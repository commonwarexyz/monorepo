//! Decorator for a cryptographic hasher that implements the MMR-specific hashing logic.
use crate::mmr::Digest;
use sha2::{Digest as Sha2Digest, Sha256 as Sha2Hasher};

/// A trait for computing the various digests of an MMR.
pub trait Hasher {
    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> Digest;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(&mut self, pos: u64, left: &Digest, right: &Digest) -> Digest;

    /// Computes the root for an MMR given its size and an iterator over the digests of its peaks in
    /// decreasing order of height.
    fn root<'a>(&mut self, size: u64, peak_digests: impl Iterator<Item = &'a Digest>) -> Digest;

    /// Compute the digest of a byte slice.
    fn digest(&mut self, data: &[u8]) -> Digest;

    /// Fork the hasher to provide equivalent functionality in another thread. This is different
    /// than [Clone::clone] because the forked hasher need not be a deep copy, and may share non-mutable
    /// state with the hasher from which it was forked.
    fn fork(&self) -> impl Hasher;
}

/// The standard SHA256 hasher to use with an MMR for computing leaf, node and root digests.
#[derive(Clone)]
pub struct Sha256 {
    hasher: Sha2Hasher,
}

impl Sha256 {
    /// Creates a new [Sha256] hasher.
    pub fn new() -> Self {
        Self {
            hasher: Sha2Hasher::new(),
        }
    }

    /// Returns a mutable reference to the underlying [Sha2Hasher].
    pub fn inner(&mut self) -> &mut Sha2Hasher {
        &mut self.hasher
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha256 {
    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> Digest {
        self.hasher.update(pos.to_be_bytes());
        self.hasher.update(element);
        self.hasher.finalize_reset().into()
    }

    fn node_digest(&mut self, pos: u64, left: &Digest, right: &Digest) -> Digest {
        self.hasher.update(pos.to_be_bytes());
        self.hasher.update(left);
        self.hasher.update(right);
        self.hasher.finalize_reset().into()
    }

    fn root<'a>(&mut self, size: u64, peak_digests: impl Iterator<Item = &'a Digest>) -> Digest {
        self.hasher.update(size.to_be_bytes());
        for digest in peak_digests {
            self.hasher.update(digest);
        }
        self.hasher.finalize_reset().into()
    }

    fn digest(&mut self, data: &[u8]) -> Digest {
        self.hasher.update(data);
        self.hasher.finalize_reset().into()
    }

    fn fork(&self) -> impl Hasher {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn test_leaf_digest() {
        let mut mmr_hasher = Sha256::new();
        // input hashes to use
        let digest1 = [1u8; 32];
        let digest2 = [2u8; 32];

        let out = mmr_hasher.leaf_digest(0, &digest1);
        assert_ne!(out, [0u8; 32], "hash should be non-zero");

        let mut out2 = mmr_hasher.leaf_digest(0, &digest1);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.leaf_digest(1, &digest1);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.leaf_digest(0, &digest2);
        assert_ne!(out, out2, "hash should change with different input digest");
    }

    #[test]
    fn test_node_digest() {
        let mut mmr_hasher = Sha256::new();
        // input hashes to use

        let d1 = [1u8; 32];
        let d2 = [2u8; 32];
        let d3 = [3u8; 32];

        let out = mmr_hasher.node_digest(0, &d1, &d2);
        assert_ne!(out, [0u8; 32], "hash should be non-zero");

        let mut out2 = mmr_hasher.node_digest(0, &d1, &d2);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.node_digest(1, &d1, &d2);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.node_digest(0, &d3, &d2);
        assert_ne!(
            out, out2,
            "hash should change with different first input hash"
        );

        out2 = mmr_hasher.node_digest(0, &d1, &d3);
        assert_ne!(
            out, out2,
            "hash should change with different second input hash"
        );

        out2 = mmr_hasher.node_digest(0, &d2, &d1);
        assert_ne!(
            out, out2,
            "hash should change when swapping order of inputs"
        );
    }

    #[test]
    fn test_root() {
        let mut mmr_hasher = Sha256::new();
        // input digests to use
        let d1 = [1u8; 32];
        let d2 = [2u8; 32];
        let d3 = [3u8; 32];
        let d4 = [4u8; 32];

        let empty_vec: Vec<Digest> = Vec::new();
        let empty_out = mmr_hasher.root(0, empty_vec.iter());
        assert_ne!(empty_out, [0u8; 32], "root of empty MMR should be non-zero");

        let digests = [d1, d2, d3, d4];
        let out = mmr_hasher.root(10, digests.iter());
        assert_ne!(out, [0u8; 32], "root should be non-zero");
        assert_ne!(out, empty_out, "root should differ from empty MMR");

        let mut out2 = mmr_hasher.root(10, digests.iter());
        assert_eq!(out, out2, "root should be computed consistently");

        out2 = mmr_hasher.root(11, digests.iter());
        assert_ne!(out, out2, "root should change with different position");

        let digests = [d1, d2, d4, d3];
        out2 = mmr_hasher.root(10, digests.iter());
        assert_ne!(out, out2, "root should change with different digest order");

        let digests = [d1, d2, d3];
        out2 = mmr_hasher.root(10, digests.iter());
        assert_ne!(
            out, out2,
            "root should change with different number of hashes"
        );
    }
}
