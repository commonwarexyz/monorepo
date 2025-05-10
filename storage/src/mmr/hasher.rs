//! Decorator for a cryptographic hasher that implements the MMR-specific hashing logic.

use crate::mmr::{Error, Hasher, Storage};
use commonware_cryptography::Hasher as CHasher;

/// Hasher decorator the MMR uses for computing leaf, node and root hashes.
pub struct Basic<H: CHasher> {
    hasher: H,
}

impl<H: CHasher> Basic<H> {
    /// Creates a new `Basic` hasher.
    pub fn new(hasher: H) -> Self {
        Self { hasher }
    }

    pub(crate) fn update_with_pos(&mut self, pos: u64) {
        self.hasher.update(&pos.to_be_bytes());
    }

    pub(crate) fn update_with_hash(&mut self, hash: &H::Digest) {
        self.hasher.update(hash.as_ref());
    }

    pub(crate) fn update_with_element(&mut self, element: &[u8]) {
        self.hasher.update(element);
    }

    pub(crate) fn finalize_reset(&mut self) -> H::Digest {
        self.hasher.finalize()
    }
}

impl<H: CHasher> Hasher<H> for Basic<H> {
    /// Computes the hash for a leaf given its position and the element it represents.
    async fn leaf_hash(&mut self, pos: u64, element: &[u8]) -> Result<H::Digest, Error> {
        self.update_with_pos(pos);
        self.update_with_element(element);
        Ok(self.finalize_reset())
    }

    /// Computes the hash for a node given its position and the hashes of its children.
    fn node_hash(&mut self, pos: u64, left_hash: &H::Digest, right_hash: &H::Digest) -> H::Digest {
        self.update_with_pos(pos);
        self.update_with_hash(left_hash);
        self.update_with_hash(right_hash);
        self.finalize_reset()
    }

    /// Computes the root hash for an MMR given its size and an iterator over the hashes of its
    /// peaks. The iterator should yield the peak hashes in decreasing order of their height.
    fn root_hash<'b>(
        &mut self,
        pos: u64,
        peak_hashes: impl Iterator<Item = &'b H::Digest>,
    ) -> H::Digest {
        self.update_with_pos(pos);
        for hash in peak_hashes {
            self.update_with_hash(hash);
        }
        self.finalize_reset()
    }

    fn hash(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.update(data);
        self.finalize_reset()
    }
}

/// Hasher decorator the MMR uses for computing leaf, node and root hashes when
/// the tree is being grafted onto another MMR.
pub struct Grafting<H: CHasher, S: Storage<H::Digest>> {
    hasher: Basic<H>,
    height: u32,
    base_mmr: Option<Box<S>>,
}

impl<H: CHasher, S: Storage<H::Digest>> Grafting<H, S> {
    pub fn new(hasher: Basic<H>, height: u32) -> Self {
        Self {
            hasher,
            height,
            base_mmr: None,
        }
    }

    pub fn basic(&mut self) -> &mut Basic<H> {
        &mut self.hasher
    }

    pub fn graft(&mut self, base_mmr: Box<S>) {
        self.base_mmr = Some(base_mmr);
    }

    pub fn take(&mut self) -> Option<Box<S>> {
        self.base_mmr.take()
    }
}

impl<H: CHasher, S: Storage<H::Digest>> Hasher<H> for Grafting<H, S> {
    /// Computes the hash for a leaf when grafting is active. This incorporates the hash of the node
    /// from the base tree onto which this leaf is grafted.
    async fn leaf_hash(&mut self, pos: u64, element: &[u8]) -> Result<H::Digest, Error> {
        let Some(base_mmr) = &mut self.base_mmr else {
            return self.hasher.leaf_hash(pos, element).await;
        };
        let base_node_pos = pos << self.height; // TODO: This simple adjustment isn't quite right
        let base_node_hash = base_mmr.get_node(base_node_pos).await?.unwrap();
        self.hasher.update_with_pos(pos);
        self.hasher.update_with_element(element);
        self.hasher.update_with_hash(&base_node_hash);
        Ok(self.hasher.finalize_reset())
    }

    /// Computes the hash for a node given its position and the hashes of its children.
    fn node_hash(&mut self, pos: u64, left_hash: &H::Digest, right_hash: &H::Digest) -> H::Digest {
        self.hasher.node_hash(pos, left_hash, right_hash)
    }

    /// Computes the root hash for an MMR given its size and an iterator over the hashes of its
    /// peaks. The iterator should yield the peak hashes in decreasing order of their height.
    fn root_hash<'c>(
        &mut self,
        pos: u64,
        peak_hashes: impl Iterator<Item = &'c H::Digest>,
    ) -> H::Digest {
        self.hasher.root_hash(pos, peak_hashes)
    }

    fn hash(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.hash(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{Hasher as CHasher, Sha256};
    use commonware_runtime::{deterministic, Runner};

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

    fn test_digest<H: CHasher>(value: u8) -> H::Digest {
        let mut hasher = H::new();
        hasher.update(&[value]);
        hasher.finalize()
    }

    fn test_leaf_hash<H: CHasher>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr_hasher = Basic::new(H::new());
            // input hashes to use
            let hash1 = test_digest::<H>(1);
            let hash2 = test_digest::<H>(2);

            let out = mmr_hasher.leaf_hash(0, &hash1).await.unwrap();
            assert_ne!(out, test_digest::<H>(0), "hash should be non-zero");

            let mut out2 = mmr_hasher.leaf_hash(0, &hash1).await.unwrap();
            assert_eq!(out, out2, "hash should be re-computed consistently");

            out2 = mmr_hasher.leaf_hash(1, &hash1).await.unwrap();
            assert_ne!(out, out2, "hash should change with different pos");

            out2 = mmr_hasher.leaf_hash(0, &hash2).await.unwrap();
            assert_ne!(out, out2, "hash should change with different input hash");
        });
    }

    fn test_node_hash<H: CHasher>() {
        let mut mmr_hasher = Basic::new(H::new());
        // input hashes to use

        let hash1 = test_digest::<H>(1);
        let hash2 = test_digest::<H>(2);
        let hash3 = test_digest::<H>(3);

        let out = mmr_hasher.node_hash(0, &hash1, &hash2);
        assert_ne!(out, test_digest::<H>(0), "hash should be non-zero");

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

    fn test_root_hash<H: CHasher>() {
        let mut mmr_hasher = Basic::new(H::new());
        // input hashes to use
        let hash1 = test_digest::<H>(1);
        let hash2 = test_digest::<H>(2);
        let hash3 = test_digest::<H>(3);
        let hash4 = test_digest::<H>(4);

        let empty_vec: Vec<H::Digest> = Vec::new();
        let empty_out = mmr_hasher.root_hash(0, empty_vec.iter());
        assert_ne!(
            empty_out,
            test_digest::<H>(0),
            "root hash of empty MMR should be non-zero"
        );

        let vec = [hash1, hash2, hash3, hash4];
        let out = mmr_hasher.root_hash(10, vec.iter());
        assert_ne!(out, test_digest::<H>(0), "root hash should be non-zero");
        assert_ne!(out, empty_out, "root hash should differ from empty MMR");

        let mut out2 = mmr_hasher.root_hash(10, vec.iter());
        assert_eq!(out, out2, "root hash should be computed consistently");

        out2 = mmr_hasher.root_hash(11, vec.iter());
        assert_ne!(out, out2, "root hash should change with different position");

        let vec2 = [hash1, hash2, hash4, hash3];
        out2 = mmr_hasher.root_hash(10, vec2.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different hash order"
        );

        let vec3 = [hash1, hash2, hash3];
        out2 = mmr_hasher.root_hash(10, vec3.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different number of hashes"
        );
    }
}
