//! Decorator for a cryptographic hasher that implements the MMR-specific hashing logic.

use crate::mmr::{
    iterator::{leaf_num_to_pos, leaf_pos_to_num},
    Error, Storage,
};
use commonware_cryptography::Hasher as CHasher;
use std::future::Future;

/// A trait required by various MMR methods for computing hash digests.
pub trait Hasher<H: CHasher>: Send + Sync {
    /// Computes the hash for a leaf given its position and the element it represents.
    fn leaf_hash(
        &mut self,
        pos: u64,
        element: &[u8],
    ) -> impl Future<Output = Result<H::Digest, Error>> + Send;

    /// Computes the hash for a node given its position and the hashes of its children.
    fn node_hash(&mut self, pos: u64, left_hash: &H::Digest, right_hash: &H::Digest) -> H::Digest;

    /// Computes the root hash for an MMR given its size and an iterator over the hashes of its
    /// peaks. The iterator should yield the peak hashes in decreasing order of their height.
    fn root_hash<'b>(
        &mut self,
        pos: u64,
        peak_hashes: impl Iterator<Item = &'b H::Digest>,
    ) -> H::Digest;

    /// Access the underlying commonware_cryptography hasher.
    fn hash(&mut self, data: &[u8]) -> H::Digest;

    fn c_hasher(&mut self) -> &mut H;
}

/// Hasher decorator the MMR uses for computing leaf, node and root hashes.
pub struct Basic<'a, H: CHasher> {
    hasher: &'a mut H,
}

impl<'a, H: CHasher> Basic<'a, H> {
    /// Creates a new `Basic` hasher.
    pub fn new(hasher: &'a mut H) -> Self {
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

    pub(crate) fn finalize(&mut self) -> H::Digest {
        self.hasher.finalize()
    }
}

impl<H: CHasher> Hasher<H> for Basic<'_, H> {
    fn c_hasher(&mut self) -> &mut H {
        self.hasher
    }

    async fn leaf_hash(&mut self, pos: u64, element: &[u8]) -> Result<H::Digest, Error> {
        self.update_with_pos(pos);
        self.update_with_element(element);
        Ok(self.finalize())
    }

    fn node_hash(&mut self, pos: u64, left_hash: &H::Digest, right_hash: &H::Digest) -> H::Digest {
        self.update_with_pos(pos);
        self.update_with_hash(left_hash);
        self.update_with_hash(right_hash);
        self.finalize()
    }

    fn root_hash<'b>(
        &mut self,
        pos: u64,
        peak_hashes: impl Iterator<Item = &'b H::Digest>,
    ) -> H::Digest {
        self.update_with_pos(pos);
        for hash in peak_hashes {
            self.update_with_hash(hash);
        }
        self.finalize()
    }

    fn hash(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.update(data);
        self.finalize()
    }
}

/// Hasher the MMR uses for computing leaf, node and root hashes when the tree is being grafted onto
/// another MMR.  If base_mmr is `None`, it behaves like a normal `Basic` hasher, and otherwise the
/// leaf hash computation incorporates the hash of the node from the base tree onto which this leaf
/// is grafted.
pub struct Grafting<'a, H: CHasher, S: Storage<H::Digest>> {
    hasher: Basic<'a, H>,
    height: u32,
    base_mmr: &'a S,
}

impl<'a, H: CHasher, S: Storage<H::Digest>> Grafting<'a, H, S> {
    pub fn new(hasher: &'a mut H, height: u32, base_mmr: &'a S) -> Self {
        Self {
            hasher: Basic::new(hasher),
            height,
            base_mmr,
        }
    }

    /// Access the underlying Basic (non-grafting) hasher.
    pub fn basic(&mut self) -> &mut Basic<'a, H> {
        &mut self.hasher
    }

    /// Compute the position of the leaf in the base tree onto which we should graft the leaf at
    /// position `pos` in the source tree.
    ///
    /// This position is computed by walking up the MMR exactly self.height steps from the leaf.
    /// Since we don't know exactly where in the subtree this leaf falls, we map it to the
    /// right-most leaf in the subtree and walk up from there. There may be faster implementations
    /// of this.
    fn destination_pos(&self, pos: u64) -> u64 {
        let peak_leaf_num = leaf_pos_to_num(pos).unwrap();
        let chunk_size_bits = 1 << self.height;

        // The rightmost-leaf in the corresponding segment of the peak tree:
        let base_leaf_num = (peak_leaf_num * chunk_size_bits) + chunk_size_bits - 1;

        // Walking up self.height levels from the rightmost leaf involves simply adding self.height
        // to its position.
        let base_leaf_pos = leaf_num_to_pos(base_leaf_num);
        let result = base_leaf_pos + self.height as u64;
        //println!("destination_pos({})={}", pos, result);
        result
    }
}

impl<H: CHasher, S: Storage<H::Digest>> Hasher<H> for Grafting<'_, H, S> {
    async fn leaf_hash(&mut self, pos: u64, element: &[u8]) -> Result<H::Digest, Error> {
        let base_node_pos = self.destination_pos(pos);
        if base_node_pos >= self.base_mmr.size() {
            // The base tree doesn't yet have a node where we can graft this position.
            return self.hasher.leaf_hash(pos, element).await;
        }

        let base_node_hash = self.base_mmr.get_node(base_node_pos).await?.unwrap();
        self.hasher.update_with_pos(pos);
        self.hasher.update_with_element(element);
        self.hasher.update_with_hash(&base_node_hash);
        Ok(self.hasher.finalize())
    }

    fn node_hash(&mut self, pos: u64, left_hash: &H::Digest, right_hash: &H::Digest) -> H::Digest {
        self.hasher.node_hash(pos, left_hash, right_hash)
    }

    fn root_hash<'a>(
        &mut self,
        pos: u64,
        peak_hashes: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.hasher.root_hash(pos, peak_hashes)
    }

    fn hash(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.hash(data)
    }

    fn c_hasher(&mut self) -> &mut H {
        self.hasher.c_hasher()
    }
}

#[cfg(test)]
mod tests {
    use crate::mmr::{
        mem::Mmr,
        tests::{build_test_mmr, ROOTS},
    };

    use super::*;
    use commonware_cryptography::{Hasher as CHasher, Sha256};
    use commonware_runtime::{deterministic, Runner};
    use commonware_utils::hex;

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
            let mut hasher = H::new();
            let mut mmr_hasher = Basic::new(&mut hasher);
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
        let mut hasher = H::new();
        let mut mmr_hasher = Basic::new(&mut hasher);
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
        let mut hasher = H::new();
        let mut mmr_hasher = Basic::new(&mut hasher);
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

    #[test]
    fn test_hasher_grafting() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = Sha256::new();
            let mut hasher = Basic::new(&mut hasher);
            let mut base_mmr = Mmr::new();
            build_test_mmr(&mut hasher, &mut base_mmr).await;
            let root = base_mmr.root(&mut hasher);
            let expected_root = ROOTS[199];
            assert_eq!(&hex(&root), expected_root);

            {
                // Build another MMR with the same elements only using a grafting hasher, using the
                // previous mmr as the base.
                let mut hasher = Sha256::new();
                let mut hasher = Grafting::new(&mut hasher, 0, &base_mmr);

                // Since we're grafting 1-1, the destination position computation should be the identiity function.
                assert_eq!(hasher.destination_pos(0), 0);
                let rand_leaf_pos = leaf_num_to_pos(1234234);
                assert_eq!(hasher.destination_pos(rand_leaf_pos), rand_leaf_pos);

                let mut peak_mmr = Mmr::new();
                build_test_mmr(&mut hasher, &mut peak_mmr).await;
                let root = peak_mmr.root(&mut hasher);
                // Peak hash should differ from the base MMR.
                assert!(hex(&root) != expected_root);
            }

            // Try grafting at a height of 1 instead of 0, which requires we double the # of leaves in the base
            // tree to maintain the corresponding # of segments.
            let mut hasher = Sha256::new();
            let mut hasher = Basic::new(&mut hasher);
            build_test_mmr(&mut hasher, &mut base_mmr).await;
            {
                let mut hasher = Sha256::new();
                let mut hasher = Grafting::new(&mut hasher, 1, &base_mmr);

                // Confirm we're now grafting leaves to the positions of their immediate parent in
                // an MMR.
                assert_eq!(hasher.destination_pos(leaf_num_to_pos(0)), 2);
                assert_eq!(hasher.destination_pos(leaf_num_to_pos(1)), 5);
                assert_eq!(hasher.destination_pos(leaf_num_to_pos(2)), 9);
                assert_eq!(hasher.destination_pos(leaf_num_to_pos(3)), 12);
                assert_eq!(hasher.destination_pos(leaf_num_to_pos(4)), 17);

                let mut peak_mmr = Mmr::new();
                build_test_mmr(&mut hasher, &mut peak_mmr).await;
                let root = peak_mmr.root(&mut hasher);
                // Peak hash should differ from the base MMR.
                assert!(hex(&root) != expected_root);
            }

            // Height 2 grafting destination computation check.
            let mut hasher = Sha256::new();
            let hasher = Grafting::new(&mut hasher, 2, &base_mmr);
            assert_eq!(hasher.destination_pos(leaf_num_to_pos(0)), 6);
            assert_eq!(hasher.destination_pos(leaf_num_to_pos(1)), 13);

            // Height 3 grafting destination computation check.
            let mut hasher = Sha256::new();
            let hasher = Grafting::new(&mut hasher, 3, &base_mmr);
            assert_eq!(hasher.destination_pos(leaf_num_to_pos(0)), 14);
        });
    }
}
