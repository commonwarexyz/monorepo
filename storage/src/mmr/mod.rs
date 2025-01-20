mod mem;
pub use mem::{verify_proof, verify_range_proof, InMemoryMMR};

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash<const N: usize>([u8; N]);

#[derive(Clone, Debug, PartialEq, Eq)]
/// A Proof contains the information necessary for proving the inclusion of an element, or some
/// range of elements, in the MMR.
pub struct Proof<const N: usize> {
    size: u64, // total # of nodes in the MMR
    hashes: Vec<Hash<N>>,
}

/// Interface the MMR uses for computing leaf, node and root hashes.
pub trait Hasher<const N: usize> {
    fn update_with_pos(&mut self, pos: u64);
    fn update_with_hash(&mut self, hash: &Hash<N>);
    fn finalize_reset(&mut self) -> Hash<N>;

    /// Computes the hash for a leaf given its position and the element it represents.
    fn leaf_hash(&mut self, pos: u64, element: &Hash<N>) -> Hash<N> {
        self.update_with_pos(pos);
        self.update_with_hash(element);
        self.finalize_reset()
    }

    /// Computes the hash for a node given its position and the hashes of its children.
    fn node_hash(&mut self, pos: u64, left_hash: &Hash<N>, right_hash: &Hash<N>) -> Hash<N> {
        self.update_with_pos(pos);
        self.update_with_hash(left_hash);
        self.update_with_hash(right_hash);
        self.finalize_reset()
    }

    /// Computes the root hash for an MMR given its size and an iterator over the hashes of its
    /// peaks. The iterator should yield the peak hashes in decreasing order of their height.
    fn root_hash<'a>(
        &mut self,
        pos: u64,
        peak_hashes: impl Iterator<Item = &'a Hash<N>>,
    ) -> Hash<N> {
        self.update_with_pos(pos);
        for hash in peak_hashes {
            self.update_with_hash(hash);
        }
        self.finalize_reset()
    }
}

pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Hasher {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
}

impl Hasher<32> for Sha256Hasher {
    fn update_with_pos(&mut self, pos: u64) {
        self.hasher.update(pos.to_be_bytes());
    }
    fn update_with_hash(&mut self, hash: &Hash<32>) {
        self.hasher.update(hash.0);
    }
    fn finalize_reset(&mut self) -> Hash<32> {
        Hash(self.hasher.finalize_reset().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_sha256() {
        let mut hasher = Sha256Hasher::new();
        test_leaf_hash::<32, Sha256Hasher>(&mut hasher);
    }

    #[test]
    fn test_node_hash_sha256() {
        let mut hasher = Sha256Hasher::new();
        test_node_hash::<32, Sha256Hasher>(&mut hasher);
    }

    #[test]
    fn test_root_hash_sha256() {
        let mut hasher = Sha256Hasher::new();
        test_root_hash::<32, Sha256Hasher>(&mut hasher);
    }

    fn test_leaf_hash<const N: usize, H: Hasher<N>>(hasher: &mut H) {
        // input hashes to use
        let hash1 = Hash([1u8; N]);
        let hash2 = Hash([2u8; N]);

        let out = hasher.leaf_hash(0, &hash1);
        assert_ne!(out.0, [0u8; N], "hash should be non-zero");

        let mut out2 = hasher.leaf_hash(0, &hash1);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = hasher.leaf_hash(1, &hash1);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = hasher.leaf_hash(0, &hash2);
        assert_ne!(out, out2, "hash should change with different input hash");
    }

    fn test_node_hash<const N: usize, H: Hasher<N>>(hasher: &mut H) {
        // input hashes to use
        let hash1 = Hash([1u8; N]);
        let hash2 = Hash([2u8; N]);
        let hash3 = Hash([3u8; N]);

        let out = hasher.node_hash(0, &hash1, &hash2);
        assert_ne!(out.0, [0u8; N], "hash should be non-zero");

        let mut out2 = hasher.node_hash(0, &hash1, &hash2);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = hasher.node_hash(1, &hash1, &hash2);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = hasher.node_hash(0, &hash3, &hash2);
        assert_ne!(
            out, out2,
            "hash should change with different first input hash"
        );

        out2 = hasher.node_hash(0, &hash1, &hash3);
        assert_ne!(
            out, out2,
            "hash should change with different second input hash"
        );

        out2 = hasher.node_hash(0, &hash2, &hash1);
        assert_ne!(
            out, out2,
            "hash should change when swapping order of inputs"
        );
    }

    fn test_root_hash<const N: usize, H: Hasher<N>>(hasher: &mut H) {
        // input hashes to use
        let hash1 = Hash([1u8; N]);
        let hash2 = Hash([2u8; N]);
        let hash3 = Hash([3u8; N]);
        let hash4 = Hash([4u8; N]);

        let empty_vec: Vec<Hash<N>> = Vec::new();
        let empty_out = hasher.root_hash(0, empty_vec.iter());
        assert_ne!(
            empty_out.0, [0u8; N],
            "root hash of empty MMR should be non-zero"
        );

        let vec = [hash1, hash2, hash3, hash4];
        let out = hasher.root_hash(10, vec.iter());
        assert_ne!(out.0, [0u8; N], "root hash should be non-zero");
        assert_ne!(out, empty_out, "root hash should differ from empty MMR");

        let mut out2 = hasher.root_hash(10, vec.iter());
        assert_eq!(out, out2, "root hash should be computed consistently");

        out2 = hasher.root_hash(11, vec.iter());
        assert_ne!(out, out2, "root hash should change with different position");

        let vec2 = [hash1, hash2, hash4, hash3];
        out2 = hasher.root_hash(10, vec2.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different hash order"
        );

        let vec3 = [hash1, hash2, hash3];
        out2 = hasher.root_hash(10, vec3.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different number of hashes"
        );
    }
}
