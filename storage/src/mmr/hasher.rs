//! Decorator for a cryptographic hasher that implements the MMR-specific hashing logic.

use crate::mmr::{
    iterator::{leaf_num_to_pos, leaf_pos_to_num, pos_to_height},
    storage::Storage,
    Error,
};
use commonware_cryptography::Hasher as CHasher;
use futures::future::try_join_all;
use std::collections::HashMap;
use tracing::debug;

/// A trait for computing the various digests of an MMR.
pub trait Hasher<H: CHasher>: Send + Sync {
    /// Computes the digest for a leaf given its position and the element it represents.
    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> H::Digest;

    /// Computes the digest for a node given its position and the digests of its children.
    fn node_digest(&mut self, pos: u64, left: &H::Digest, right: &H::Digest) -> H::Digest;

    /// Computes the root for an MMR given its size and an iterator over the digests of its peaks in
    /// decreasing order of height.
    fn root_digest<'a>(
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

    fn root_digest<'a>(
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
/// One example use case is the [crate::adb::current::Current] authenticated database,
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
pub struct Grafting<'a, H: CHasher> {
    hasher: &'a mut Standard<H>,
    height: u32,

    /// Maps a leaf's position to the digest of the node on which the leaf is grafted.
    grafted_digests: HashMap<u64, H::Digest>,
}

impl<'a, H: CHasher> Grafting<'a, H> {
    pub fn new(hasher: &'a mut Standard<H>, height: u32) -> Self {
        Self {
            hasher,
            height,
            grafted_digests: HashMap::new(),
        }
    }

    /// Access the underlying [Standard] (non-grafting) hasher.
    pub fn standard(&mut self) -> &mut Standard<H> {
        self.hasher
    }

    /// Loads the grafted digests for the specified leaves into the internal map. Does not clear out
    /// any previously loaded digests. This method must be used to provide grafted digests for any
    /// leaf whose `leaf_digest` needs to be computed.
    ///
    /// # Warning
    ///
    /// Panics if any of the grafted digests are missing from the MMR.
    pub async fn load_grafted_digests(
        &mut self,
        leaves: &[u64],
        mmr: &impl Storage<H::Digest>,
    ) -> Result<(), Error> {
        let mut futures = Vec::with_capacity(leaves.len());
        for leaf_num in leaves {
            let dest_pos = self.destination_pos(leaf_num_to_pos(*leaf_num));
            let future = mmr.get_node(dest_pos);
            futures.push(future);
        }
        let join = try_join_all(futures).await?;
        for (i, digest) in join.into_iter().enumerate() {
            let Some(digest) = digest else {
                panic!("missing grafted digest for leaf {}", leaves[i]);
            };
            let leaf_pos = leaf_num_to_pos(leaves[i]);
            self.grafted_digests.insert(leaf_pos, digest);
        }

        Ok(())
    }

    /// Compute the position of the leaf in the base tree onto which we should graft the leaf at
    /// position `pos` in the source tree.
    fn destination_pos(&self, pos: u64) -> u64 {
        destination_pos(pos, self.height)
    }
}

/// A lightweight, short-lived shallow copy of a Grafting hasher that can be used in parallel
/// computations.
pub struct GraftingFork<'a, H: CHasher> {
    hasher: Standard<H>,
    height: u32,
    grafted_digests: &'a HashMap<u64, H::Digest>,
}

/// Compute the position of the node in the base tree onto which we should graft the node at
/// position `pos` in the source tree.
///
/// This algorithm performs walks down corresponding branches of the peak and base trees. When we
/// find the node in the peak tree we are looking for, we return the position of the corresponding
/// node reached in the base tree.
fn destination_pos(peak_node_pos: u64, height: u32) -> u64 {
    let leading_zeros = (peak_node_pos + 1).leading_zeros();
    let mut peak_pos = u64::MAX >> leading_zeros;
    let mut base_pos = u64::MAX >> (leading_zeros - height);
    let mut peak_height = peak_pos.trailing_ones() - 1;
    let mut base_height = peak_height + height;
    peak_pos -= 1;
    base_pos -= 1;

    while base_height >= height {
        if peak_pos == peak_node_pos {
            break;
        }

        let left_pos = peak_pos - (1 << peak_height);
        if left_pos < peak_node_pos {
            peak_pos -= 1;
            base_pos -= 1;
        } else {
            peak_pos = left_pos;
            base_pos -= 1 << base_height;
        }

        peak_height -= 1;
        base_height -= 1;
    }

    base_pos
}

/// Inverse computation of destination_pos, with an analogous implementation involving walks down
/// corresponding branches of both trees. Returns none if there is no corresponding node.
pub(super) fn source_pos(base_node_pos: u64, height: u32) -> Option<u64> {
    if pos_to_height(base_node_pos) < height {
        // Nodes below the grafting height do not have a corresponding peak tree node.
        return None;
    }

    let leading_zeros = (base_node_pos + 1).leading_zeros();
    let mut base_pos = u64::MAX >> leading_zeros;
    let mut peak_pos = u64::MAX >> (leading_zeros + height);
    let mut base_height = base_pos.trailing_ones() - 1;
    let mut peak_height = base_height - height;
    base_pos -= 1;
    peak_pos -= 1;

    while base_pos != base_node_pos {
        let left_pos = base_pos - (1 << base_height);
        if left_pos < base_node_pos {
            base_pos -= 1;
            peak_pos -= 1;
        } else {
            base_pos = left_pos;
            peak_pos -= 1 << peak_height;
        }

        base_height -= 1;
        peak_height -= 1;
    }

    Some(peak_pos)
}

impl<H: CHasher> Hasher<H> for Grafting<'_, H> {
    /// Computes the digest of a leaf in the peak_tree of a grafted MMR.
    ///
    /// # Warning
    ///
    /// Panics if the grafted_digest was not previously loaded for the leaf.
    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> H::Digest {
        let grafted_digest = self.grafted_digests.get(&pos);
        let Some(grafted_digest) = grafted_digest else {
            panic!("missing grafted digest for leaf_pos {pos}");
        };

        // We do not include position in the digest material here since the position information is
        // already captured in the grafted_digest.
        self.hasher.update_with_element(element);
        self.hasher.update_with_digest(grafted_digest);

        self.hasher.finalize()
    }

    fn fork(&self) -> impl Hasher<H> {
        GraftingFork {
            hasher: Standard::new(),
            height: self.height,
            grafted_digests: &self.grafted_digests,
        }
    }

    fn node_digest(
        &mut self,
        pos: u64,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        self.hasher
            .node_digest(self.destination_pos(pos), left_digest, right_digest)
    }

    fn root_digest<'a>(
        &mut self,
        size: u64,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.hasher
            .root_digest(self.destination_pos(size), peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.digest(data)
    }

    fn inner(&mut self) -> &mut H {
        self.hasher.inner()
    }
}

impl<H: CHasher> Hasher<H> for GraftingFork<'_, H> {
    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> H::Digest {
        let grafted_digest = self.grafted_digests.get(&pos);
        let Some(grafted_digest) = grafted_digest else {
            panic!("missing grafted digest for leaf_pos {pos}");
        };

        // We do not include position in the digest material here since the position information is
        // already captured in the base_node_digest.
        self.hasher.update_with_element(element);
        self.hasher.update_with_digest(grafted_digest);

        self.hasher.finalize()
    }

    fn fork(&self) -> impl Hasher<H> {
        GraftingFork {
            hasher: Standard::new(),
            height: self.height,
            grafted_digests: self.grafted_digests,
        }
    }

    fn node_digest(
        &mut self,
        pos: u64,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        self.hasher
            .node_digest(destination_pos(pos, self.height), left_digest, right_digest)
    }

    fn root_digest<'a>(
        &mut self,
        size: u64,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.hasher
            .root_digest(destination_pos(size, self.height), peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.digest(data)
    }

    fn inner(&mut self) -> &mut H {
        self.hasher.inner()
    }
}

/// A [Hasher] implementation to use when verifying proofs over GraftedStorage.
pub struct GraftingVerifier<'a, H: CHasher> {
    hasher: Standard<H>,
    height: u32,

    /// The required leaf elements from the peak tree that we are verifying.
    elements: Vec<&'a [u8]>,

    /// The leaf number of the first element we are verifying
    num: u64,
}

impl<'a, H: CHasher> GraftingVerifier<'a, H> {
    pub fn new(height: u32, num: u64, elements: Vec<&'a [u8]>) -> Self {
        Self {
            hasher: Standard::new(),
            height,
            elements,
            num,
        }
    }

    pub fn standard(&mut self) -> &mut Standard<H> {
        &mut self.hasher
    }
}

impl<H: CHasher> Hasher<H> for GraftingVerifier<'_, H> {
    fn leaf_digest(&mut self, pos: u64, element: &[u8]) -> H::Digest {
        self.hasher.leaf_digest(pos, element)
    }

    fn fork(&self) -> impl Hasher<H> {
        GraftingVerifier {
            hasher: Standard::new(),
            height: self.height,
            elements: self.elements.clone(),
            num: self.num,
        }
    }

    fn node_digest(
        &mut self,
        pos: u64,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        let digest = self.hasher.node_digest(pos, left_digest, right_digest);
        if pos_to_height(pos) != self.height {
            // If we're not at the grafting boundary we use the digest as-is.
            return digest;
        }

        // This base tree node corresponds to a peak-tree leaf, so we need to perform the peak-tree
        // leaf digest computation.
        let source_pos = source_pos(pos, self.height);
        let Some(source_pos) = source_pos else {
            // malformed proof input
            debug!(pos, "no grafting source pos");
            return digest;
        };
        let index = leaf_pos_to_num(source_pos);
        let Some(mut index) = index else {
            // malformed proof input
            debug!(pos = source_pos, "grafting source pos is not a leaf");
            return digest;
        };
        if index < self.num {
            // malformed proof input
            debug!(index, num = self.num, "grafting index is negative");
            return digest;
        };
        index -= self.num;
        if index >= self.elements.len() as u64 {
            // malformed proof input
            debug!(
                index,
                len = self.elements.len(),
                "grafting index is out of bounds"
            );
            return digest;
        }
        self.hasher
            .update_with_element(self.elements[index as usize]);
        self.hasher.update_with_digest(&digest);

        self.hasher.finalize()
    }

    fn root_digest<'a>(
        &mut self,
        size: u64,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.hasher.root_digest(size, peak_digests)
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
    use super::*;
    use crate::mmr::{
        iterator::leaf_num_to_pos,
        mem::Mmr,
        storage::{Grafting as GStorage, Storage},
        tests::{build_test_mmr, ROOTS},
        verification::Proof,
    };
    use commonware_cryptography::{sha256::Digest, Hasher as CHasher, Sha256};
    use commonware_macros::test_traced;
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
        });
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

    fn test_root_digest<H: CHasher>() {
        let mut mmr_hasher: Standard<H> = Standard::new();
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

    /// For a variety of grafting heights and node positions, check that destination_pos and
    /// source_pos are inverse functions.
    #[test]
    fn test_hasher_dest_source_pos_conversion() {
        for grafting_height in 1..10 {
            for pos in 0..10000 {
                let dest_pos = destination_pos(pos, grafting_height);
                let source_pos = source_pos(dest_pos, grafting_height).unwrap();
                assert_eq!(pos, source_pos);
            }
        }
    }

    #[test]
    fn test_hasher_source_dest_pos_conversion() {
        for grafting_height in 1..10 {
            for pos in 0..10000 {
                if pos_to_height(pos) < grafting_height {
                    // Base tree nodes below the grafting height do not have a corresponding peak
                    // tree node.
                    assert!(source_pos(pos, grafting_height).is_none());
                    continue;
                }
                let source_pos = source_pos(pos, grafting_height).unwrap();
                let dest_pos = destination_pos(source_pos, grafting_height);
                assert_eq!(pos, dest_pos);
            }
        }
    }

    #[test]
    fn test_hasher_grafting() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut standard: Standard<Sha256> = Standard::new();
            let mut base_mmr = Mmr::new();
            build_test_mmr(&mut standard, &mut base_mmr).await;
            let root = base_mmr.root(&mut standard);
            let expected_root = ROOTS[199];
            assert_eq!(&hex(&root), expected_root);

            let mut hasher: Grafting<Sha256> = Grafting::new(&mut standard, 0);
            hasher
                .load_grafted_digests(&(0..199).collect::<Vec<_>>(), &base_mmr)
                .await
                .unwrap();

            {
                // Build another MMR with the same elements only using a grafting hasher, using the
                // previous mmr as the base.

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
            build_test_mmr(&mut standard, &mut base_mmr).await;
            {
                let mut hasher: Grafting<Sha256> = Grafting::new(&mut standard, 1);
                hasher
                    .load_grafted_digests(&(0..199).collect::<Vec<_>>(), &base_mmr)
                    .await
                    .unwrap();

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
            let hasher: Grafting<Sha256> = Grafting::new(&mut standard, 2);
            assert_eq!(hasher.destination_pos(leaf_num_to_pos(0)), 6);
            assert_eq!(hasher.destination_pos(leaf_num_to_pos(1)), 13);

            // Height 3 grafting destination computation check.
            let hasher: Grafting<Sha256> = Grafting::new(&mut standard, 3);
            assert_eq!(hasher.destination_pos(leaf_num_to_pos(0)), 14);
        });
    }

    /// Builds a small grafted MMR, then generates & verifies proofs over it.
    #[test_traced]
    fn test_hasher_grafted_storage() {
        let executor = deterministic::Runner::default();
        const GRAFTING_HEIGHT: u32 = 1;
        executor.start(|_| async move {
            let b1 = Sha256::fill(0x01);
            let b2 = Sha256::fill(0x02);
            let b3 = Sha256::fill(0x03);
            let b4 = Sha256::fill(0x04);
            let mut standard: Standard<Sha256> = Standard::new();

            // Make a base MMR with 4 leaves.
            let mut base_mmr = Mmr::new();
            base_mmr.add(&mut standard, &b1);
            base_mmr.add(&mut standard, &b2);
            base_mmr.add(&mut standard, &b3);
            base_mmr.add(&mut standard, &b4);

            let p1 = Sha256::fill(0xF1);
            let p2 = Sha256::fill(0xF2);

            // Since we are using grafting height of 1, peak tree must have half the leaves of the base (2).
            let mut peak_tree: Mmr<Sha256> = Mmr::new();
            {
                let mut grafter = Grafting::new(&mut standard, GRAFTING_HEIGHT);
                grafter
                    .load_grafted_digests(&[0, 1], &base_mmr)
                    .await
                    .unwrap();
                peak_tree.add(&mut grafter, &p1);
                peak_tree.add(&mut grafter, &p2);
            }

            let peak_root = peak_tree.root(&mut standard);
            let base_root = base_mmr.root(&mut standard);
            assert_ne!(peak_root, base_root);

            {
                let grafted_mmr = GStorage::new(&peak_tree, &base_mmr, GRAFTING_HEIGHT);
                assert_eq!(grafted_mmr.size(), base_mmr.size());

                let grafted_storage_root = grafted_mmr.root(&mut standard).await.unwrap();
                assert_ne!(grafted_storage_root, base_root);

                // Grafted storage root uses the size of the base MMR in its digest, so it will differ
                // than the peak tree root even though these particular trees would otherwise produce
                // the same root.
                assert_ne!(grafted_storage_root, peak_root);

                // Confirm we can generate and verify an inclusion proofs for each of the 4 leafs of the grafted MMR.
                {
                    let pos = 0;
                    let proof = Proof::<Digest>::range_proof(&grafted_mmr, pos, pos)
                        .await
                        .unwrap();

                    let mut verifier =
                        GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&p1]);
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b1,
                        pos,
                        &grafted_storage_root
                    ));

                    let pos = 1;
                    let proof = Proof::<Digest>::range_proof(&grafted_mmr, pos, pos)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b2,
                        pos,
                        &grafted_storage_root
                    ));

                    let pos = 3;
                    let proof = Proof::<Digest>::range_proof(&grafted_mmr, pos, pos)
                        .await
                        .unwrap();
                    let mut verifier =
                        GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 1, vec![&p2]);
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b3,
                        pos,
                        &grafted_storage_root
                    ));

                    let pos = 4;
                    let proof = Proof::<Digest>::range_proof(&grafted_mmr, pos, pos)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        pos,
                        &grafted_storage_root
                    ));
                }

                // Confirm element inclusion proof verification fails for various manipulations of the input.
                {
                    // Valid proof of the last element.
                    let pos = 4;
                    let proof = Proof::<Digest>::range_proof(&grafted_mmr, pos, pos)
                        .await
                        .unwrap();
                    let mut verifier =
                        GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 1, vec![&p2]);
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        pos,
                        &grafted_storage_root
                    ));

                    // Proof should fail if we try to verify the wrong leaf element.
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b3,
                        pos,
                        &grafted_storage_root
                    ));

                    // Proof should fail if we use the wrong root.
                    assert!(!proof.verify_element_inclusion(&mut verifier, &b4, pos, &peak_root));

                    // Proof should fail if we use the wrong position
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        3,
                        &grafted_storage_root
                    ));

                    // Proof should fail if we inject the wrong peak element into the verifier.
                    let mut verifier =
                        GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 1, vec![&p1]);
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        pos,
                        &grafted_storage_root
                    ));

                    // Proof should fail if we give the verifier the wrong peak tree leaf number.
                    let mut verifier =
                        GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 2, vec![&p1]);
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        pos,
                        &grafted_storage_root
                    ));
                }

                // test range proving
                {
                    // Confirm we can prove the entire range.
                    let proof = Proof::<Digest>::range_proof(&grafted_mmr, 0, 4)
                        .await
                        .unwrap();
                    let range = vec![&b1, &b2, &b3, &b4];
                    let mut verifier =
                        GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&p1, &p2]);
                    assert!(proof.verify_range_inclusion(
                        &mut verifier,
                        &range,
                        0,
                        4,
                        &grafted_storage_root
                    ));

                    // Confirm same proof fails with shortened verifier range.
                    let mut verifier =
                        GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&p1]);
                    assert!(!proof.verify_range_inclusion(
                        &mut verifier,
                        &range,
                        0,
                        4,
                        &grafted_storage_root
                    ));
                }
            }

            // Add one more leaf to our base MMR, which will not have any corresponding peak tree
            // leaf since it will have no ancestors at or above the grafting height.
            let b5 = Sha256::fill(0x05);
            base_mmr.add(&mut standard, &b5);

            let grafted_mmr = GStorage::new(&peak_tree, &base_mmr, GRAFTING_HEIGHT);
            assert_eq!(grafted_mmr.size(), base_mmr.size());

            // Confirm we can generate and verify inclusion proofs for the "orphaned" leaf as well as an existing one.
            let grafted_storage_root = grafted_mmr.root(&mut standard).await.unwrap();
            let pos = 0;
            let proof = Proof::<Digest>::range_proof(&grafted_mmr, pos, pos)
                .await
                .unwrap();

            let mut verifier = GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&p1]);
            assert!(proof.verify_element_inclusion(&mut verifier, &b1, pos, &grafted_storage_root));

            let mut verifier = GraftingVerifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![]);
            let pos = 7;
            let proof = Proof::<Digest>::range_proof(&grafted_mmr, pos, pos)
                .await
                .unwrap();
            assert!(proof.verify_element_inclusion(&mut verifier, &b5, pos, &grafted_storage_root));
        });
    }
}
