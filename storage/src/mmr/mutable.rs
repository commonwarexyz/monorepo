//! An in-memory authenticatable & mutable key-value store.
//!
//! A *mutable MMR* is an authenticatable and updatable key-value store based on an MMR over all
//! updates called the *update tree*. An authenticatable bitmap, called the *active state tree*,
//! indicates which positions in the update tree correspond to the latest value of a particular key.
//! For example, if the same key K was updated at positions X, Y, and Z in that order, then the
//! authenticatable bitmap will store 0s for the bits corresponding to X and Y, and a 1 for the bit
//! corresponding to Z. The root hash of the mutable MMR is the result of hashing together the roots
//! of these two trees. A Merkle proof over this combined structure can then prove that the key K
//! currently has the value of its most recent update.

use crate::mmr::{
    bitmap::Bitmap, hasher::Hasher, iterator::leaf_pos_to_num, mem::Mmr,
    verification::Proof as MmrProof, Error,
};
use commonware_cryptography::Hasher as CHasher;
use commonware_utils::{Array, SizedSerialize};
use std::{collections::HashMap, marker::PhantomData};
use tracing::debug;

/// A proof that a particular key has a particular (currently active) value in the store.
pub struct ActiveValueProof<K: Array, V: Array, H: CHasher> {
    /// The offset of the leaf storing the active value for the key in the updates tree.
    tree_pos: u64,

    /// A proof that the record at the given offset has a certain key and value.
    updates_proof: MmrProof<H>,

    /// A proof that the record stores the currently active value for the key.
    active_state_proof: MmrProof<H>,

    /// The bitmap chunk containing the active state bit of the referenced update record.
    state_bitmap_chunk: H::Digest,

    phantom_key: PhantomData<K>,
    phantom_value: PhantomData<V>,
}

impl<K: Array, V: Array, H: CHasher> ActiveValueProof<K, V, H> {
    /// Return true if `key` currently has value `value` in the store with the given `root_hash`
    /// based on the data in this proof.
    pub fn verify(&self, hasher: &mut H, key: &K, value: &V, root_hash: &H::Digest) -> bool {
        // Reconstruct the updates tree root.
        let kv_digest = UpdateRecord::<K, V, H>::key_value_hash(hasher, key, value);
        let peak_hashes = match self.updates_proof.reconstruct_peak_hashes(
            hasher,
            &[kv_digest],
            self.tree_pos,
            self.tree_pos,
        ) {
            Ok(peak_hashes) => peak_hashes,
            Err(e) => {
                debug!("failed to reconstruct update tree root: {:?}", e);
                return false;
            }
        };
        let updates_root = {
            let mut h = Hasher::<H>::new(hasher);
            h.root_hash(self.updates_proof.size, peak_hashes.iter())
        };

        // Reconstruct the active state tree root.
        let bit_offset = leaf_pos_to_num(self.tree_pos);
        let leaf_pos = Bitmap::<H>::leaf_pos(bit_offset);
        let peak_hashes = match self.active_state_proof.reconstruct_peak_hashes(
            hasher,
            &[self.state_bitmap_chunk],
            leaf_pos,
            leaf_pos,
        ) {
            Ok(peak_hashes) => peak_hashes,
            Err(e) => {
                debug!("failed to reconstruct state tree root: {:?}", e);
                return false;
            }
        };
        let mut h = Hasher::new(hasher);
        let active_state_root = h.root_hash(self.active_state_proof.size, peak_hashes.iter());

        // Important! Make sure the bit corresponding to this key in the bitmap chunk is actually a
        // "1" (active). Otherwise it's trivial to create a proof where we'll return true for a
        // non-active value.
        let byte_offset = bit_offset as usize / 8;
        let mask = Bitmap::<H>::mask_for(bit_offset);
        if self.state_bitmap_chunk[byte_offset] & mask == 0 {
            return false;
        }

        // Derive the store's root hash from the two roots, and confirm it matches `root_hash` from
        // the caller.
        h.node_hash(0, &updates_root, &active_state_root) == *root_hash
    }
}

/// A record representing one key/value update.
struct UpdateRecord<K: Array, V: Array, H: CHasher> {
    /// The position of the leaf representing this record in the updates tree.
    tree_pos: u64,

    /// The key that was updated.
    key: K,

    /// The value the key was assigned in this update, or the delete indicator if the key was
    /// deleted.
    value: V,

    phantom: PhantomData<H>,
}

impl<K: Array, V: Array, H: CHasher> UpdateRecord<K, V, H> {
    /// Return the digest of the key value pair in this record.
    pub fn hash(&self, hasher: &mut H) -> H::Digest {
        Self::key_value_hash(hasher, &self.key, &self.value)
    }

    /// Return a digest of the `key` `value` pair.
    fn key_value_hash(hasher: &mut H, key: &K, value: &V) -> H::Digest {
        hasher.update(key);
        hasher.update(value);
        hasher.finalize()
    }
}

pub struct MutableMmr<K: Array, V: Array, H: CHasher> {
    /// MMR over digests of the UpdateRecords.
    updates: Mmr<H>,

    /// An authenticatable bitmap where a 1 indicates the corresponding update record contains the
    /// active value for its key.
    active_state: Bitmap<H>,

    /// Stores all updates made to the MMR. The index of each record in this vector is called its
    /// "location".
    records: Vec<UpdateRecord<H::Digest, V, H>>,

    /// Maps a key to to the location containing its most recent update in the records vector. A
    /// deletion is considered an update and is indicated by the delete indicator for the key value.
    snapshot: HashMap<H::Digest, usize>,

    /// A special value that indicates a key has been deleted.
    delete_indicator: V,

    phantom_key: PhantomData<K>,
}

impl<K: Array, V: Array, H: CHasher> MutableMmr<K, V, H> {
    pub fn new(hasher: &mut H, delete_indicator: V) -> Self {
        let mut s = MutableMmr {
            updates: Mmr::new(),
            active_state: Bitmap::new(),
            snapshot: HashMap::new(),
            records: Vec::new(),
            delete_indicator: delete_indicator.clone(),
            phantom_key: PhantomData,
        };

        // Add a dummy first record to reserve location 0 for future use.
        let dummy_key = H::Digest::try_from(vec![0u8; H::Digest::SERIALIZED_LEN]).unwrap();
        s.updates.add(hasher, &dummy_key);
        s.active_state.append(hasher, false);
        s.records.push(UpdateRecord {
            tree_pos: 0,
            key: dummy_key,
            value: delete_indicator,
            phantom: PhantomData,
        });

        s
    }

    /// Get the current (active) value associated with they key, or None if the key has never been
    /// updated or its last update was a delete operation.
    pub fn get(&self, key: &H::Digest) -> Option<&V> {
        let pos = self.snapshot.get(key)?;
        let record = &self.records[*pos];
        if record.value == self.delete_indicator {
            return None;
        }

        Some(&record.value)
    }

    /// Set the currently active value of `key` to `value`.`
    pub fn update(&mut self, hasher: &mut H, key: H::Digest, value: V) {
        if value == self.delete_indicator {
            panic!("collision with delete indicator");
        }
        self.update_work(hasher, key, value);
    }

    /// Mark the key as deleted, causing gets for the key to return None.
    pub fn delete(&mut self, hasher: &mut H, key: H::Digest) {
        self.update_work(hasher, key, self.delete_indicator.clone());
    }

    /// Add a new record to the store, and perform corresponding updates to the update tree, active
    /// state tree, and snapshot.
    fn update_work(&mut self, hasher: &mut H, key: H::Digest, value: V) {
        let tree_pos = self.updates.size();

        // Append the new record to the records vector.
        let record = UpdateRecord {
            tree_pos,
            key,
            value,
            phantom: PhantomData,
        };
        let record_digest = record.hash(hasher);
        let new_location = self.records.len();
        self.records.push(record);

        // Update the updates tree
        self.updates.add(hasher, &record_digest);

        // Update the active state tree.
        self.active_state.append(hasher, true);

        // Update the snapshot.
        let old_location = self.snapshot.insert(key, new_location);
        if old_location.is_none() {
            return;
        }
        let old_location = old_location.unwrap();

        // Flip the active state bit of the previous record for the key if any.
        let record = &self.records[old_location];
        assert_eq!(record.key, key);
        let bit_offset = leaf_pos_to_num(record.tree_pos);
        assert!(self.active_state.get_bit(bit_offset));
        self.active_state.set_bit(hasher, bit_offset, false);
    }

    pub fn root(&mut self, hasher: &mut H) -> H::Digest {
        let updates_root = self.updates.root(hasher);
        let active_state_root = self.active_state.root(hasher);
        let mut h = Hasher::new(hasher);
        h.node_hash(0, &updates_root, &active_state_root)
    }

    /// Return a proof of the current value of `key` in the store that can be verified against the
    /// current root. Panic if `key` has never been updated.
    ///
    /// If the key has been deleted, the proof demonstrates that the key currently has no value (or
    /// more technically, that it has the value of the delete indicator). Usage of such proofs are
    /// discouraged, as relying on them will prevent pruning deleted keys from the snapshot.
    pub async fn proof(
        &self,
        hasher: &mut H,
        key: &H::Digest,
    ) -> Result<(ActiveValueProof<K, V, H>, V), Error> {
        let location = match self.snapshot.get(key) {
            Some(location) => location,
            None => panic!("key has never been updated: {}", key),
        };
        let record = &self.records[*location];
        assert_eq!(record.key, *key);

        let updates_proof = self.updates.proof(record.tree_pos).await?;

        let bit_offset = leaf_pos_to_num(record.tree_pos);
        let (active_state_proof, state_bitmap_chunk) =
            self.active_state.proof(hasher, bit_offset).await?;

        let proof = ActiveValueProof {
            tree_pos: record.tree_pos,
            updates_proof,
            active_state_proof,
            state_bitmap_chunk,
            phantom_key: PhantomData,
            phantom_value: PhantomData,
        };

        Ok((proof, record.value.clone()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mmr::iterator::leaf_num_to_pos;
    use commonware_cryptography::{Hasher as CHasher, Sha256};
    use commonware_runtime::{deterministic::Executor, Runner};

    #[test]
    pub fn test_mutable_mmr_build() {
        let mut hasher = Sha256::new();
        let delete_indicator = <Sha256 as CHasher>::Digest::try_from(&vec![
            0u8;
            <Sha256 as CHasher>::Digest::SERIALIZED_LEN
        ])
        .unwrap();
        let mut store = MutableMmr::<
            <Sha256 as CHasher>::Digest, // key type
            <Sha256 as CHasher>::Digest, // value type
            Sha256,
        >::new(&mut hasher, delete_indicator);

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

        assert_eq!(store.records.len(), 6); // 5 updates + dummy record
        assert_eq!(store.active_state.bit_count(), store.records.len() as u64);
        assert_eq!(store.snapshot.len(), 2);

        // The MMRs should always have a size beyond the position of the last leaf.
        let last_leaf = leaf_num_to_pos(5);
        assert!(store.updates.size() > last_leaf);

        store.delete(&mut hasher, d1);
        store.delete(&mut hasher, d2);
        assert!(store.get(&d1).is_none());
        assert!(store.get(&d2).is_none());
    }

    #[test]
    #[should_panic(expected = "key has never been updated")]
    pub fn test_mutable_mmr_panic_on_proving_nonexistent_key() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let delete_indicator = <Sha256 as CHasher>::Digest::try_from(&vec![
            0u8;
            <Sha256 as CHasher>::Digest::SERIALIZED_LEN
        ])
            .unwrap();
            let mut store = MutableMmr::<
                <Sha256 as CHasher>::Digest, // key type
                <Sha256 as CHasher>::Digest, // value type
                Sha256,
            >::new(&mut hasher, delete_indicator);

            let d1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
            let d2 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
            store.update(&mut hasher, d1, d1);
            store.proof(&mut hasher, &d2).await.unwrap();
        });
    }

    #[test]
    pub fn test_mutable_mmr_data_authentication() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut hasher = Sha256::new();
            let delete_indicator = <Sha256 as CHasher>::Digest::try_from(&vec![
            0u8;
            <Sha256 as CHasher>::Digest::SERIALIZED_LEN
        ])
            .unwrap();
            let mut store = MutableMmr::<
                <Sha256 as CHasher>::Digest, // key type
                <Sha256 as CHasher>::Digest, // value type
                Sha256,
            >::new(&mut hasher, delete_indicator);

            let k1 = <Sha256 as CHasher>::Digest::try_from(&vec![1u8; 32]).unwrap();
            let k2 = <Sha256 as CHasher>::Digest::try_from(&vec![2u8; 32]).unwrap();
            let k3 = <Sha256 as CHasher>::Digest::try_from(&vec![3u8; 32]).unwrap();

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

            // Confirm we can prove delete indicators.
            store.delete(&mut hasher, k1);
            store.delete(&mut hasher, k2);

            let root_hash = store.root(&mut hasher);

            let (proof, value) = store.proof(&mut hasher, &k1).await.unwrap();
            assert_eq!(value, delete_indicator);
            assert!(proof.verify(&mut hasher, &k1, &delete_indicator, &root_hash));
            let (proof, value) = store.proof(&mut hasher, &k2).await.unwrap();
            assert_eq!(value, delete_indicator);
            assert!(proof.verify(&mut hasher, &k2, &delete_indicator, &root_hash));

            assert!(!proof.verify(&mut hasher, &k3, &delete_indicator, &root_hash));
        });
    }
}
