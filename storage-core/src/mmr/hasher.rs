//! Decorator for a cryptographic hasher that implements the MMR-specific hashing logic.

use commonware_cryptography::Hasher as CHasher;

/// A trait for computing the various digests of an MMR.
pub trait Hasher<H: CHasher>: Send + Sync {
    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> H::Digest;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(&mut self, pos: u64, left: &H::Digest, right: &H::Digest) -> H::Digest;

    /// Computes the root for an MMR given its size and an iterator over the digests of its peaks in
    /// decreasing order of height.
    fn root<'a>(
        &mut self,
        size: u64,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest;

    /// Compute the digest of a byte slice.
    fn digest(&mut self, data: &[u8]) -> H::Digest;

    /// Access the inner [CHasher] hasher.
    fn inner(&mut self) -> &mut H;

    /// Fork the hasher to provide equivalent functionality in another thread. This is different
    /// than [Clone::clone] because the forked hasher need not be a deep copy, and may share non-mutable
    /// state with the hasher from which it was forked.
    fn fork(&self) -> impl Hasher<H>;
}

/// The standard hasher to use with an MMR for computing leaf, node and root digests. Leverages no
/// external data.
pub struct Standard<H: CHasher> {
    hasher: H,
}

impl<H: CHasher> Standard<H> {
    /// Creates a new [Standard] hasher.
    pub fn new() -> Self {
        Self { hasher: H::new() }
    }

    pub fn update_with_pos(&mut self, pos: u64) {
        self.hasher.update(&pos.to_be_bytes());
    }

    pub fn update_with_digest(&mut self, digest: &H::Digest) {
        self.hasher.update(digest.as_ref());
    }

    pub fn update_with_element(&mut self, element: &[u8]) {
        self.hasher.update(element);
    }

    pub fn finalize(&mut self) -> H::Digest {
        self.hasher.finalize()
    }
}

impl<H: CHasher> Default for Standard<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Hasher<H> for Standard<H> {
    fn inner(&mut self) -> &mut H {
        &mut self.hasher
    }

    fn fork(&self) -> impl Hasher<H> {
        Standard { hasher: H::new() }
    }

    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> H::Digest {
        self.update_with_pos(pos);
        self.update_with_element(element);
        self.finalize()
    }

    fn node_digest(&mut self, pos: u64, left: &H::Digest, right: &H::Digest) -> H::Digest {
        self.update_with_pos(pos);
        self.update_with_digest(left);
        self.update_with_digest(right);
        self.finalize()
    }

    fn root<'a>(
        &mut self,
        size: u64,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.update_with_pos(size);
        for digest in peak_digests {
            self.update_with_digest(digest);
        }
        self.finalize()
    }

    fn digest(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.update(data);
        self.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use commonware_cryptography::{Hasher as CHasher, Sha256};

    #[test]
    fn test_leaf_digest_sha256() {
        test_leaf_digest::<Sha256>();
    }

    #[test]
    fn test_node_digest_sha256() {
        test_node_digest::<Sha256>();
    }

    #[test]
    fn test_root_sha256() {
        test_root::<Sha256>();
    }

    fn test_digest<H: CHasher>(value: u8) -> H::Digest {
        let mut hasher = H::new();
        hasher.update(&[value]);
        hasher.finalize()
    }

    fn test_leaf_digest<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new();
        // input hashes to use
        let digest1 = test_digest::<H>(1);
        let digest2 = test_digest::<H>(2);

        let out = mmr_hasher.leaf_digest(0, &digest1);
        assert_ne!(out, test_digest::<H>(0), "hash should be non-zero");

        let mut out2 = mmr_hasher.leaf_digest(0, &digest1);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.leaf_digest(1, &digest1);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.leaf_digest(0, &digest2);
        assert_ne!(out, out2, "hash should change with different input digest");
    }

    fn test_node_digest<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new();
        // input hashes to use

        let d1 = test_digest::<H>(1);
        let d2 = test_digest::<H>(2);
        let d3 = test_digest::<H>(3);

        let out = mmr_hasher.node_digest(0, &d1, &d2);
        assert_ne!(out, test_digest::<H>(0), "hash should be non-zero");

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

    fn test_root<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new();
        // input digests to use
        let d1 = test_digest::<H>(1);
        let d2 = test_digest::<H>(2);
        let d3 = test_digest::<H>(3);
        let d4 = test_digest::<H>(4);

        let empty_vec: Vec<H::Digest> = Vec::new();
        let empty_out = mmr_hasher.root(0, empty_vec.iter());
        assert_ne!(
            empty_out,
            test_digest::<H>(0),
            "root of empty MMR should be non-zero"
        );

        let digests = [d1, d2, d3, d4];
        let out = mmr_hasher.root(10, digests.iter());
        assert_ne!(out, test_digest::<H>(0), "root should be non-zero");
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
