mod mem;
pub use mem::InMemoryMMR;

use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hash<const N: usize>([u8; N]);

/// Interface the MMR uses for hashing a leaf with its position and for generating the hash of a non-leaf node.
pub trait Hasher<const N: usize> {
    fn leaf_hash(&mut self, pos: u64, hash: &Hash<N>) -> Hash<N>;
    fn node_hash(&mut self, pos: u64, left_hash: &Hash<N>, right_hash: &Hash<N>) -> Hash<N>;
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
    fn leaf_hash(&mut self, pos: u64, hash: &Hash<32>) -> Hash<32> {
        self.hasher.update(pos.to_be_bytes());
        self.hasher.update(hash.0);
        Hash(self.hasher.finalize_reset().into())
    }

    fn node_hash(&mut self, pos: u64, left_hash: &Hash<32>, right_hash: &Hash<32>) -> Hash<32> {
        self.hasher.update(pos.to_be_bytes());
        self.hasher.update(left_hash.0);
        self.hasher.update(right_hash.0);
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
}
