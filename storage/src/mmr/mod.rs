mod mem;
pub use mem::{verify_proof, verify_range_proof, InMemoryMmr};

use commonware_cryptography::{Digest, Hasher};

#[derive(Clone, Debug, PartialEq, Eq)]
/// A Proof contains the information necessary for proving the inclusion of an element, or some
/// range of elements, in the MMR.
pub struct Proof {
    size: u64, // total # of nodes in the MMR
    hashes: Vec<Digest>,
}

/// Hasher decorator the MMR uses for computing leaf, node and root hashes.
struct MmrHasher<'a, H: Hasher> {
    hasher: &'a mut H,
}

impl<'a, H: Hasher> MmrHasher<'a, H> {
    fn new(hasher: &'a mut H) -> Self {
        Self { hasher }
    }

    /// Computes the hash for a leaf given its position and the element it represents.
    fn leaf_hash(&mut self, pos: u64, element: &Digest) -> Digest {
        self.update_with_pos(pos);
        self.update_with_hash(element);
        self.finalize_reset()
    }

    /// Computes the hash for a node given its position and the hashes of its children.
    fn node_hash(&mut self, pos: u64, left_hash: &Digest, right_hash: &Digest) -> Digest {
        self.update_with_pos(pos);
        self.update_with_hash(left_hash);
        self.update_with_hash(right_hash);
        self.finalize_reset()
    }

    /// Computes the root hash for an MMR given its size and an iterator over the hashes of its
    /// peaks. The iterator should yield the peak hashes in decreasing order of their height.
    fn root_hash<'b>(&mut self, pos: u64, peak_hashes: impl Iterator<Item = &'b Digest>) -> Digest {
        self.update_with_pos(pos);
        for hash in peak_hashes {
            self.update_with_hash(hash);
        }
        self.finalize_reset()
    }

    fn update_with_pos(&mut self, pos: u64) {
        self.hasher.update(&pos.to_be_bytes());
    }
    fn update_with_hash(&mut self, hash: &Digest) {
        self.hasher.update(hash);
    }
    fn finalize_reset(&mut self) -> Digest {
        self.hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::{Digest, Hasher, Sha256};

    #[test]
    fn test_leaf_hash_sha256() {
        test_leaf_hash::<Sha256>();
    }

    #[test]
    fn test_node_hash_sha256() {
        test_node_hash::<Sha256>();
    }

    #[test]
    fn test_root_hash_sha256() {
        test_root_hash::<Sha256>();
    }

    fn test_leaf_hash<H: Hasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::MmrHasher::new(&mut hasher);
        // input hashes to use
        let hash1 = Digest::from(vec![1u8; H::len()]);
        let hash2 = Digest::from(vec![2u8; H::len()]);

        let out = mmr_hasher.leaf_hash(0, &hash1);
        assert_ne!(
            out,
            Digest::from(vec![0u8; H::len()]),
            "hash should be non-zero"
        );

        let mut out2 = mmr_hasher.leaf_hash(0, &hash1);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.leaf_hash(1, &hash1);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.leaf_hash(0, &hash2);
        assert_ne!(out, out2, "hash should change with different input hash");
    }

    fn test_node_hash<H: Hasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::MmrHasher::new(&mut hasher);
        // input hashes to use

        let hash1 = Digest::from(vec![1u8; H::len()]);
        let hash2 = Digest::from(vec![2u8; H::len()]);
        let hash3 = Digest::from(vec![3u8; H::len()]);

        let out = mmr_hasher.node_hash(0, &hash1, &hash2);
        assert_ne!(
            out,
            Digest::from(vec![0u8; H::len()]),
            "hash should be non-zero"
        );

        let mut out2 = mmr_hasher.node_hash(0, &hash1, &hash2);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.node_hash(1, &hash1, &hash2);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.node_hash(0, &hash3, &hash2);
        assert_ne!(
            out, out2,
            "hash should change with different first input hash"
        );

        out2 = mmr_hasher.node_hash(0, &hash1, &hash3);
        assert_ne!(
            out, out2,
            "hash should change with different second input hash"
        );

        out2 = mmr_hasher.node_hash(0, &hash2, &hash1);
        assert_ne!(
            out, out2,
            "hash should change when swapping order of inputs"
        );
    }

    fn test_root_hash<H: Hasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::MmrHasher::new(&mut hasher);
        // input hashes to use
        let hash1 = Digest::from(vec![1u8; H::len()]);
        let hash2 = Digest::from(vec![2u8; H::len()]);
        let hash3 = Digest::from(vec![3u8; H::len()]);
        let hash4 = Digest::from(vec![4u8; H::len()]);

        let empty_vec: Vec<Digest> = Vec::new();
        let empty_out = mmr_hasher.root_hash(0, empty_vec.iter());
        assert_ne!(
            empty_out,
            Digest::from(vec![0u8; H::len()]),
            "root hash of empty MMR should be non-zero"
        );

        let vec = [hash1.clone(), hash2.clone(), hash3.clone(), hash4.clone()];
        let out = mmr_hasher.root_hash(10, vec.iter());
        assert_ne!(
            out,
            Digest::from(vec![0u8; H::len()]),
            "root hash should be non-zero"
        );
        assert_ne!(out, empty_out, "root hash should differ from empty MMR");

        let mut out2 = mmr_hasher.root_hash(10, vec.iter());
        assert_eq!(out, out2, "root hash should be computed consistently");

        out2 = mmr_hasher.root_hash(11, vec.iter());
        assert_ne!(out, out2, "root hash should change with different position");

        let vec2 = [hash1.clone(), hash2.clone(), hash4.clone(), hash3.clone()];
        out2 = mmr_hasher.root_hash(10, vec2.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different hash order"
        );

        let vec3 = [hash1.clone(), hash2.clone(), hash3.clone()];
        out2 = mmr_hasher.root_hash(10, vec3.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different number of hashes"
        );
    }
}
