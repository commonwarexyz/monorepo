//! Decorator for a cryptographic hasher that implements the MMR-specific hashing logic.

use crate::mmr::{
    iterator::{leaf_num_to_pos, leaf_pos_to_num},
    Error, Storage,
};
use commonware_cryptography::Hasher as CHasher;
use std::future::Future;

/// A trait for computing the various digests of an MMR.
pub trait Hasher<H: CHasher>: Send + Sync {
    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(
        &mut self,
        pos: u64,
        element: &[u8],
    ) -> impl Future<Output = Result<H::Digest, Error>> + Send;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(&mut self, pos: u64, left: &H::Digest, right: &H::Digest) -> H::Digest;

    /// Computes the root for an MMR given its size and an iterator over the digests of its peaks in
    /// decreasing order of height.
    fn root_digest<'b>(
        &mut self,
        pos: u64,
        peak_digests: impl Iterator<Item = &'b H::Digest>,
    ) -> H::Digest;

    /// Compute the digest of a byte slice.
    fn digest(&mut self, data: &[u8]) -> H::Digest;

    /// Access the inner [CHasher] hasher.
    fn inner(&mut self) -> &mut H;
}

/// The standard hasher to use with an MMR for computing leaf, node and root digests. Leverages no
/// external data.
pub struct Standard<'a, H: CHasher> {
    hasher: &'a mut H,
}

impl<'a, H: CHasher> Standard<'a, H> {
    /// Creates a new [Standard] hasher.
    pub fn new(hasher: &'a mut H) -> Self {
        Self { hasher }
    }

    pub(crate) fn update_with_pos(&mut self, pos: u64) {
        self.hasher.update(&pos.to_be_bytes());
    }

    pub(crate) fn update_with_digest(&mut self, digest: &H::Digest) {
        self.hasher.update(digest.as_ref());
    }

    pub(crate) fn update_with_element(&mut self, element: &[u8]) {
        self.hasher.update(element);
    }

    pub(crate) fn finalize(&mut self) -> H::Digest {
        self.hasher.finalize()
    }
}

impl<H: CHasher> Hasher<H> for Standard<'_, H> {
    fn inner(&mut self) -> &mut H {
        self.hasher
    }

    async fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> Result<H::Digest, Error> {
        self.update_with_pos(pos);
        self.update_with_element(element);
        Ok(self.finalize())
    }

    fn node_digest(&mut self, pos: u64, left: &H::Digest, right: &H::Digest) -> H::Digest {
        self.update_with_pos(pos);
        self.update_with_digest(left);
        self.update_with_digest(right);
        self.finalize()
    }

    fn root_digest<'b>(
        &mut self,
        pos: u64,
        peak_digests: impl Iterator<Item = &'b H::Digest>,
    ) -> H::Digest {
        self.update_with_pos(pos);
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

/// Hasher for computing leaf, node and root digests when the tree is being _grafted_ onto another
/// MMR.
///
/// ## Terminology
///
/// * **Peak Tree**: The MMR or Merkle tree that is being grafted.
/// * **Base MMR**: The MMR onto which we are grafting (cannot be a Merkle tree).
///
/// Grafting involves mapping the leaves of the peak tree to corresponding nodes in the base MMR. It
/// allows for shorter inclusion proofs over the combined trees compared to treating them as
/// independent.
///
/// One example use case is the [Current](crate::adb::current::Current) authenticated database,
/// where a MMR is built over a log of operations, and a merkle tree over a bitmap indicating the
/// activity state of each operation. If we were to treat the two trees as independent, then an
/// inclusion proof for an operation and its activity state would involve a full branch from each
/// structure. When using grafting, we can trim the branch from the base MMR at the point it "flows"
/// up into the peak tree, reducing the size of the proof by a constant factor up to 2.
///
/// For concreteness, let's assume we have a base MMR over a log of 8 operations represented by the
/// 8 leaves:
///
/// ```text
///    Height
///      3              14
///                   /    \
///                  /      \
///                 /        \
///                /          \
///      2        6            13
///             /   \        /    \
///      1     2     5      9     12
///           / \   / \    / \   /  \
///      0   0   1 3   4  7   8 10  11
/// ```
///
/// Let's assume each leaf in our peak tree corresponds to 4 leaves in the base MMR. The structure
/// of the peak tree can be obtained by chopping off the bottom log2(4)=2 levels of the base MMR
/// structure:
///
///
/// ```text
///    Height
///      1              2 (was 14)
///                   /    \
///                  /      \
///                 /        \
///                /          \
///      0        0 (was 6)    1 (was 13)
/// ```
///
/// The inverse of this procedure provides our algorithm for mapping a peak tree leaf's position to
/// a base MMR node position: take the leaf's position in the peak tree, map it to any of the
/// corresponding leaves in the base MMR, then walk up the base MMR structure exactly the number of
/// levels we removed.
///
/// In this example, leaf 0 in the peak tree corresponds to leaves \[0,1,3,4\] in the base MMR.
/// Walking up two levels from any of these base MMR leaves produces node 6 of the base MMR, which
/// is thus its grafting point. Leaf 1 in the peak tree corresponds to leaves \[7,8,10,11\] in the
/// base MMR, yielding node 13 as its grafting point.
pub struct Grafting<'a, H: CHasher, S: Storage<H::Digest>> {
    hasher: Standard<'a, H>,
    height: u32,
    base_mmr: &'a S,
}

impl<'a, H: CHasher, S: Storage<H::Digest>> Grafting<'a, H, S> {
    pub fn new(hasher: &'a mut H, height: u32, base_mmr: &'a S) -> Self {
        Self {
            hasher: Standard::new(hasher),
            height,
            base_mmr,
        }
    }

    /// Access the underlying [Standard] (non-grafting) hasher.
    pub fn standard(&mut self) -> &mut Standard<'a, H> {
        &mut self.hasher
    }

    /// Compute the position of the leaf in the base tree onto which we should graft the leaf at
    /// position `pos` in the source tree.
    ///
    /// This position is computed by walking up the MMR exactly self.height steps from the leaf.
    /// Since we don't know exactly where in the subtree this leaf falls, we map it to the
    /// right-most leaf in the subtree and walk up from there. Runtime is O(log2(n)) in the given
    /// position.
    fn destination_pos(&self, pos: u64) -> u64 {
        let peak_leaf_num = leaf_pos_to_num(pos).unwrap();
        let chunk_size_bits = 1 << self.height;

        // The rightmost-leaf in the corresponding segment of the peak tree:
        let base_leaf_num = (peak_leaf_num * chunk_size_bits) + chunk_size_bits - 1;

        // Walking up self.height levels from the rightmost leaf involves simply adding self.height
        // to its position.
        leaf_num_to_pos(base_leaf_num) + self.height as u64
    }
}

impl<H: CHasher, S: Storage<H::Digest>> Hasher<H> for Grafting<'_, H, S> {
    async fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> Result<H::Digest, Error> {
        let base_node_pos = self.destination_pos(pos);
        if base_node_pos >= self.base_mmr.size() {
            // The base tree doesn't yet have a node where we can graft this position.
            return self.hasher.leaf_digest(pos, element).await;
        }

        let base_node_digest = self.base_mmr.get_node(base_node_pos).await?.unwrap();
        self.hasher.update_with_pos(pos);
        self.hasher.update_with_element(element);
        self.hasher.update_with_digest(&base_node_digest);
        Ok(self.hasher.finalize())
    }

    fn node_digest(
        &mut self,
        pos: u64,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        self.hasher.node_digest(pos, left_digest, right_digest)
    }

    fn root_digest<'a>(
        &mut self,
        pos: u64,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.hasher.root_digest(pos, peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.digest(data)
    }

    fn inner(&mut self) -> &mut H {
        self.hasher.inner()
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
    fn test_leaf_digest_sha256() {
        test_leaf_digest::<Sha256>();
    }

    #[test]
    fn test_node_digest_sha256() {
        test_node_digest::<Sha256>();
    }

    #[test]
    fn test_root_digest_sha256() {
        test_root_digest::<Sha256>();
    }

    fn test_digest<H: CHasher>(value: u8) -> H::Digest {
        let mut hasher = H::new();
        hasher.update(&[value]);
        hasher.finalize()
    }

    fn test_leaf_digest<H: CHasher>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = H::new();
            let mut mmr_hasher = Standard::new(&mut hasher);
            // input hashes to use
            let digest1 = test_digest::<H>(1);
            let digest2 = test_digest::<H>(2);

            let out = mmr_hasher.leaf_digest(0, &digest1).await.unwrap();
            assert_ne!(out, test_digest::<H>(0), "hash should be non-zero");

            let mut out2 = mmr_hasher.leaf_digest(0, &digest1).await.unwrap();
            assert_eq!(out, out2, "hash should be re-computed consistently");

            out2 = mmr_hasher.leaf_digest(1, &digest1).await.unwrap();
            assert_ne!(out, out2, "hash should change with different pos");

            out2 = mmr_hasher.leaf_digest(0, &digest2).await.unwrap();
            assert_ne!(out, out2, "hash should change with different input digest");
        });
    }

    fn test_node_digest<H: CHasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = Standard::new(&mut hasher);
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

    fn test_root_digest<H: CHasher>() {
        let mut hasher = H::new();
        let mut mmr_hasher = Standard::new(&mut hasher);
        // input digests to use
        let d1 = test_digest::<H>(1);
        let d2 = test_digest::<H>(2);
        let d3 = test_digest::<H>(3);
        let d4 = test_digest::<H>(4);

        let empty_vec: Vec<H::Digest> = Vec::new();
        let empty_out = mmr_hasher.root_digest(0, empty_vec.iter());
        assert_ne!(
            empty_out,
            test_digest::<H>(0),
            "root of empty MMR should be non-zero"
        );

        let digests = [d1, d2, d3, d4];
        let out = mmr_hasher.root_digest(10, digests.iter());
        assert_ne!(out, test_digest::<H>(0), "root should be non-zero");
        assert_ne!(out, empty_out, "root should differ from empty MMR");

        let mut out2 = mmr_hasher.root_digest(10, digests.iter());
        assert_eq!(out, out2, "root should be computed consistently");

        out2 = mmr_hasher.root_digest(11, digests.iter());
        assert_ne!(out, out2, "root should change with different position");

        let digests = [d1, d2, d4, d3];
        out2 = mmr_hasher.root_digest(10, digests.iter());
        assert_ne!(out, out2, "root should change with different digest order");

        let digests = [d1, d2, d3];
        out2 = mmr_hasher.root_digest(10, digests.iter());
        assert_ne!(
            out, out2,
            "root should change with different number of hashes"
        );
    }

    #[test]
    fn test_hasher_grafting() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
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

                // Since we're grafting 1-1, the destination position computation should be the identity function.
                assert_eq!(hasher.destination_pos(0), 0);
                let rand_leaf_pos = leaf_num_to_pos(1234234);
                assert_eq!(hasher.destination_pos(rand_leaf_pos), rand_leaf_pos);

                let mut peak_mmr = Mmr::new();
                build_test_mmr(&mut hasher, &mut peak_mmr).await;
                let root = peak_mmr.root(&mut hasher);
                // Peak digest should differ from the base MMR.
                assert!(hex(&root) != expected_root);
            }

            // Try grafting at a height of 1 instead of 0, which requires we double the # of leaves in the base
            // tree to maintain the corresponding # of segments.
            let mut hasher = Sha256::new();
            let mut hasher = Standard::new(&mut hasher);
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
                // Peak digest should differ from the base MMR.
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
