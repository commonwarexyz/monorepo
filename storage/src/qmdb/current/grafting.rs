//! Verifier and Storage for _grafting_ bitmap chunks onto an operations MMR.
//!
//! ## Overview
//!
//! An MMR (the "ops MMR") is built over a log of operations, and a bitmap tracks the activity
//! status of each operation. To authenticate both structures efficiently, we combine them: each
//! complete chunk of the bitmap is hashed together with the corresponding subtree root from the ops
//! MMR to produce a single "grafted leaf" digest. These digests, along with their ancestor nodes,
//! are stored in an in-memory MMR (using grafted-space positions internally, with ops-space
//! positions in hash pre-images via [GraftedHasher]).
//!
//! This is more efficient than maintaining two independent authenticated structures. An inclusion
//! proof for an operation and its activity status only requires one branch (which embeds the bitmap
//! chunk) plus the sub-branch from the ops MMR below the grafting point, reducing proof size by up
//! to a factor of 2.
//!
//! ## Grafting height
//!
//! Each grafted leaf covers `2^h` ops MMR leaves, where `h` is the grafting height
//! (`log2(chunk_size_bits)`). For example, given an ops MMR over 8 operations with grafting height
//! 2 (chunk size = 4 bits):
//!
//! ```text
//!    Height
//!      3              14
//!                   /    \
//!                  /      \
//!                 /        \
//!                /          \
//!      2        6            13       <-- grafting height: grafted leaf positions
//!             /   \        /    \
//!      1     2     5      9     12
//!           / \   / \    / \   /  \
//!      0   0   1 3   4  7   8 10  11
//! ```
//!
//! Nodes at the grafting height (positions 6 and 13) are "grafted leaves" whose digests combine the
//! bitmap chunk with the ops subtree root: `hash(chunk || ops_subtree_root)`. Nodes above the
//! grafting height (position 14) use standard MMR hashing with ops-space positions.
//!
//! The grafted MMR is incrementally maintained via [GraftedHasher] + `DirtyMmr::merkleize` when
//! grafted leaves change.

use crate::mmr::{
    hasher::Hasher as HasherTrait, iterator::pos_to_height, mem::CleanMmr,
    storage::Storage as StorageTrait, Error, Location, Position, StandardHasher,
};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_utils::bitmap::BitMap;
use core::cmp::Ordering;
use tracing::debug;

/// Minimum number of items before switching from serial to parallel computation.
pub(super) const MIN_TO_PARALLELIZE: usize = 20;

/// Get the grafting height for a bitmap with chunk size determined by N.
pub(crate) const fn height<const N: usize>() -> u32 {
    BitMap::<N>::CHUNK_SIZE_BITS.trailing_zeros()
}

// --- Coordinate conversion ---
//
// These functions convert between three coordinate spaces:
//
// 1. **Chunk index**: Sequential index (0, 1, 2, ...) of (complete) bitmap chunks.
// 2. **Ops position**: Position in the full operations MMR.
// 3. **Grafted position**: Position in the grafted MMR, whose leaves correspond 1:1 with chunks.
//
// All conversions rely on a single MMR identity: given the leftmost leaf at position P of a
// perfect subtree, the subtree root at height h is at `P + 2^(h+1) - 2`, and conversely the
// leftmost leaf under a subtree root at position P and height h is at `P + 2 - 2^(h+1)`.

/// Convert a chunk index to the ops MMR position of the subtree root covering that chunk.
///
/// Chunk `i` covers ops leaves `[i * 2^h, (i+1) * 2^h)`. This returns the ops position
/// at the grafting height that roots that range.
///
/// Inverse of [ops_pos_to_chunk_idx].
pub(super) fn chunk_idx_to_ops_pos(chunk_idx: u64, grafting_height: u32) -> Position {
    let first_leaf_loc = Location::new_unchecked(chunk_idx << grafting_height);
    let first_leaf_pos = Position::try_from(first_leaf_loc).expect("chunk_idx_to_ops_pos overflow");
    Position::new(*first_leaf_pos + (1u64 << (grafting_height + 1)) - 2)
}

/// Convert an ops MMR position at the grafting height back to its chunk index.
///
/// Inverse of [chunk_idx_to_ops_pos].
pub(super) fn ops_pos_to_chunk_idx(ops_pos: Position, grafting_height: u32) -> u64 {
    let leftmost_leaf_pos = *ops_pos + 2 - (1u64 << (grafting_height + 1));
    let loc = Location::try_from(Position::new(leftmost_leaf_pos))
        .expect("ops_pos_to_chunk_idx: position is not a leaf");
    *loc >> grafting_height
}

/// Convert an ops MMR position (at or above the grafting height) to a grafted MMR position.
///
/// An ops node at height `ops_h` maps to a grafted node at height `ops_h - grafting_height`.
/// The conversion descends to the leftmost ops leaf, divides by 2^h to get the chunk index
/// (= grafted leaf location), then climbs back up to the grafted height.
///
/// See also [ops_pos_to_chunk_idx], which converts specifically to a chunk index (useful for
/// array indexing) rather than a grafted MMR position.
///
/// Inverse of [grafted_to_ops_pos].
///
/// # Panics
///
/// Panics if `ops_pos` is below the grafting height.
pub(super) fn ops_to_grafted_pos(ops_pos: Position, grafting_height: u32) -> Position {
    let ops_height = pos_to_height(ops_pos);
    assert!(
        ops_height >= grafting_height,
        "position height {ops_height} < grafting height {grafting_height}"
    );
    let grafted_height = ops_height - grafting_height;

    // Descend to the leftmost ops leaf, then convert to chunk index.
    let leftmost_ops_leaf_pos = *ops_pos + 2 - (1u64 << (ops_height + 1));
    let ops_leaf_loc = Location::try_from(Position::new(leftmost_ops_leaf_pos))
        .expect("leftmost leaf is not a valid leaf position");
    let chunk_idx = *ops_leaf_loc >> grafting_height;

    // Convert chunk index to grafted leaf position, then climb to grafted_height.
    let grafted_leaf_pos =
        Position::try_from(Location::new_unchecked(chunk_idx)).expect("chunk index overflow");
    Position::new(*grafted_leaf_pos + (1u64 << (grafted_height + 1)) - 2)
}

/// Convert a grafted MMR position to the corresponding ops MMR position.
///
/// Inverse of [ops_to_grafted_pos]. A grafted node at height `gh` maps to an ops node at
/// height `gh + grafting_height`.
pub(super) fn grafted_to_ops_pos(grafted_pos: Position, grafting_height: u32) -> Position {
    let grafted_height = pos_to_height(grafted_pos);

    // Descend to the leftmost grafted leaf to get the chunk index.
    let leftmost_grafted_leaf_pos = grafted_pos + 2 - (1u64 << (grafted_height + 1));
    let chunk_idx = *Location::try_from(leftmost_grafted_leaf_pos)
        .expect("leftmost leaf is not a valid leaf position");

    // Convert chunk index to ops leaf location, then climb to ops height.
    let ops_leaf_loc = chunk_idx << grafting_height;
    let ops_leaf_pos =
        Position::try_from(Location::new_unchecked(ops_leaf_loc)).expect("ops leaf loc overflow");
    let ops_height = grafted_height + grafting_height;
    Position::new(*ops_leaf_pos + (1u64 << (ops_height + 1)) - 2)
}

/// An MMR hasher adapter that converts grafted-space positions to ops-space before hashing.
///
/// Internal nodes in the grafted MMR must hash with ops-space positions so that proofs
/// generated against the grafted MMR are compatible with the ops MMR. This adapter
/// intercepts [HasherTrait::node_digest] to perform the conversion via [grafted_to_ops_pos];
/// all other methods delegate unchanged.
pub(super) struct GraftedHasher<H: HasherTrait> {
    inner: H,
    grafting_height: u32,
}

impl<H: HasherTrait> GraftedHasher<H> {
    pub(super) const fn new(inner: H, grafting_height: u32) -> Self {
        Self {
            inner,
            grafting_height,
        }
    }
}

impl<H: HasherTrait> HasherTrait for GraftedHasher<H> {
    type Digest = H::Digest;
    type Inner = H::Inner;

    fn leaf_digest(&mut self, pos: Position, element: &[u8]) -> Self::Digest {
        self.inner.leaf_digest(pos, element)
    }

    fn node_digest(
        &mut self,
        pos: Position,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        let ops_pos = grafted_to_ops_pos(pos, self.grafting_height);
        self.inner.node_digest(ops_pos, left, right)
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a Self::Digest>,
    ) -> Self::Digest {
        self.inner.root(leaves, peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> Self::Digest {
        self.inner.digest(data)
    }

    fn inner(&mut self) -> &mut Self::Inner {
        self.inner.inner()
    }

    fn fork(&self) -> impl HasherTrait<Digest = Self::Digest> {
        GraftedHasher {
            inner: self.inner.fork(),
            grafting_height: self.grafting_height,
        }
    }
}

/// A [HasherTrait] implementation used for verifying proofs over grafted [Storage].
///
/// Proof verification works by walking the tree from leaves to root, recomputing digests at each
/// node. Since a proof path crosses the grafting boundary (from ops MMR leaves up through grafted
/// peaks), two different hashing behaviors are needed depending on the node's height relative to
/// the grafting height:
///
/// - **Below or above**: standard MMR hash using ops-space positions.
/// - **At**: the children form an ops subtree root, which is combined with a bitmap chunk element
///   to reconstruct the grafted leaf digest.
pub(super) struct Verifier<'a, H: CHasher> {
    hasher: StandardHasher<H>,
    grafting_height: u32,

    /// Bitmap chunks needed for grafted leaf reconstruction at the boundary.
    chunks: Vec<&'a [u8]>,

    /// The chunk index of `chunks[0]`.
    start_chunk_index: u64,
}

impl<'a, H: CHasher> Verifier<'a, H> {
    /// Create a new Verifier.
    ///
    /// `start_chunk_index` is the chunk index corresponding to `chunks[0]`.
    pub(super) fn new(grafting_height: u32, start_chunk_index: u64, chunks: Vec<&'a [u8]>) -> Self {
        Self {
            hasher: StandardHasher::new(),
            grafting_height,
            chunks,
            start_chunk_index,
        }
    }
}

impl<H: CHasher> HasherTrait for Verifier<'_, H> {
    type Digest = H::Digest;
    type Inner = H;

    fn leaf_digest(&mut self, pos: Position, element: &[u8]) -> H::Digest {
        self.hasher.leaf_digest(pos, element)
    }

    fn fork(&self) -> impl HasherTrait<Digest = H::Digest> {
        Verifier::<H> {
            hasher: StandardHasher::new(),
            grafting_height: self.grafting_height,
            chunks: self.chunks.clone(),
            start_chunk_index: self.start_chunk_index,
        }
    }

    fn node_digest(
        &mut self,
        pos: Position,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        match pos_to_height(pos).cmp(&self.grafting_height) {
            Ordering::Less | Ordering::Greater => {
                // Below or above grafting height: standard hash with ops-space position.
                self.hasher.node_digest(pos, left_digest, right_digest)
            }
            Ordering::Equal => {
                // At grafting height: compute ops subtree root, then combine with bitmap chunk.
                let ops_subtree_root = self.hasher.node_digest(pos, left_digest, right_digest);

                let chunk_idx = ops_pos_to_chunk_idx(pos, self.grafting_height);
                let Some(local) = chunk_idx
                    .checked_sub(self.start_chunk_index)
                    .filter(|&l| l < self.chunks.len() as u64)
                    .map(|l| l as usize)
                else {
                    debug!(?pos, "chunk not available for grafted leaf");
                    return ops_subtree_root;
                };

                // grafted_leaf = hash(chunk || ops_subtree_root)
                self.hasher.inner().update(self.chunks[local]);
                self.hasher.inner().update(&ops_subtree_root);
                self.hasher.inner().finalize()
            }
        }
    }

    fn root<'a>(
        &mut self,
        leaves: Location,
        peak_digests: impl Iterator<Item = &'a H::Digest>,
    ) -> H::Digest {
        self.hasher.root(leaves, peak_digests)
    }

    fn digest(&mut self, data: &[u8]) -> H::Digest {
        self.hasher.digest(data)
    }

    fn inner(&mut self) -> &mut H {
        self.hasher.inner()
    }
}

/// A virtual [StorageTrait] that presents a grafted [CleanMmr] and ops MMR as a single combined
/// MMR.
///
/// Nodes below the grafting height are served from the ops MMR. Nodes at or above the grafting
/// height are served from the grafted MMR (with ops-to-grafted position conversion). This allows
/// standard MMR proof generation to work transparently over the combined structure.
pub(super) struct Storage<'a, D: Digest, S: StorageTrait<D>> {
    grafted_mmr: &'a CleanMmr<D>,
    grafting_height: u32,
    ops_mmr: &'a S,
}

impl<'a, D: Digest, S: StorageTrait<D>> Storage<'a, D, S> {
    /// Creates a new [Storage] instance.
    pub(super) const fn new(
        grafted_mmr: &'a CleanMmr<D>,
        grafting_height: u32,
        ops_mmr: &'a S,
    ) -> Self {
        Self {
            grafted_mmr,
            grafting_height,
            ops_mmr,
        }
    }
}

impl<D: Digest, S: StorageTrait<D>> StorageTrait<D> for Storage<'_, D, S> {
    async fn size(&self) -> Position {
        self.ops_mmr.size().await
    }

    async fn get_node(&self, pos: Position) -> Result<Option<D>, Error> {
        if pos_to_height(pos) < self.grafting_height {
            return self.ops_mmr.get_node(pos).await;
        }
        let grafted_pos = ops_to_grafted_pos(pos, self.grafting_height);
        Ok(self.grafted_mmr.get_node(grafted_pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        conformance::build_test_mmr,
        iterator::PeakIterator,
        mem::{CleanMmr, DirtyMmr},
        verification, Position, StandardHasher,
    };
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    /// Precompute grafted leaf digests and return a [CleanMmr] in grafted-space.
    ///
    /// Each grafted leaf is `hash(chunk || ops_subtree_root)` where `ops_subtree_root` is the ops
    /// MMR node at the mapped position.
    fn build_test_grafted_mmr(
        standard: &mut StandardHasher<Sha256>,
        ops_mmr: &CleanMmr<sha256::Digest>,
        chunks: &[sha256::Digest],
        grafting_height: u32,
    ) -> CleanMmr<sha256::Digest> {
        let mut dirty = DirtyMmr::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let ops_pos = chunk_idx_to_ops_pos(i as u64, grafting_height);
            let ops_subtree_root = ops_mmr
                .get_node(ops_pos)
                .expect("ops MMR missing node at mapped position");
            standard.inner().update(chunk);
            standard.inner().update(&ops_subtree_root);
            dirty.add_leaf_digest(standard.inner().finalize());
        }
        let mut grafted_hasher = GraftedHasher::new(standard.fork(), grafting_height);
        dirty.merkleize(&mut grafted_hasher, None)
    }

    #[test_traced]
    fn test_chunk_idx_to_ops_pos_roundtrip() {
        for grafting_height in 1..10 {
            for chunk_idx in 0..1000u64 {
                let ops_pos = chunk_idx_to_ops_pos(chunk_idx, grafting_height);
                assert_eq!(
                    pos_to_height(ops_pos),
                    grafting_height,
                    "chunk_idx_to_ops_pos should return a position at the grafting height"
                );
                let back = ops_pos_to_chunk_idx(ops_pos, grafting_height);
                assert_eq!(chunk_idx, back);
            }
        }
    }

    #[test_traced]
    fn test_ops_to_grafted_pos_leaves() {
        // For leaves (grafted height 0), ops_to_grafted_pos should agree with
        // ops_pos_to_chunk_idx -> Position::try_from(Location(chunk_idx)).
        for grafting_height in 1..8 {
            for chunk_idx in 0..200u64 {
                let ops_pos = chunk_idx_to_ops_pos(chunk_idx, grafting_height);
                let grafted_pos = ops_to_grafted_pos(ops_pos, grafting_height);
                let expected = *Position::try_from(Location::new_unchecked(chunk_idx)).unwrap();
                assert_eq!(
                    grafted_pos, expected,
                    "leaf mismatch: chunk_idx={chunk_idx}, gh={grafting_height}"
                );
            }
        }
    }

    #[test_traced]
    fn test_ops_grafted_roundtrip() {
        // Test roundtrip: ops -> grafted -> ops for positions at various heights.
        for grafting_height in 1..6 {
            // Build grafted leaves first, then walk up to test internal nodes.
            for chunk_idx in 0..100u64 {
                let ops_pos = chunk_idx_to_ops_pos(chunk_idx, grafting_height);
                let grafted_pos = ops_to_grafted_pos(ops_pos, grafting_height);
                let back = grafted_to_ops_pos(grafted_pos, grafting_height);
                assert_eq!(
                    ops_pos, back,
                    "leaf roundtrip failed: chunk={chunk_idx}, gh={grafting_height}"
                );
            }

            // Test internal nodes: parent of adjacent grafted leaves.
            for chunk_idx in (0..100u64).step_by(2) {
                let left_ops = chunk_idx_to_ops_pos(chunk_idx, grafting_height);
                // Parent in ops-space: left + (1 << (grafting_height + 1))
                let parent_ops = Position::new(*left_ops + (1u64 << (grafting_height + 1)));
                if pos_to_height(parent_ops) < grafting_height {
                    continue;
                }
                let grafted_pos = ops_to_grafted_pos(parent_ops, grafting_height);
                let back = grafted_to_ops_pos(grafted_pos, grafting_height);
                assert_eq!(
                    parent_ops, back,
                    "internal roundtrip failed: chunk={chunk_idx}, gh={grafting_height}"
                );
            }
        }
    }

    #[test_traced]
    fn test_ops_to_grafted_pos_known_values() {
        // Grafting height 1: each grafted leaf covers 2 ops leaves.
        // ops_pos=2 (chunk 0) -> grafted leaf 0 -> grafted pos 0
        assert_eq!(ops_to_grafted_pos(Position::new(2), 1), 0);
        // ops_pos=5 (chunk 1) -> grafted leaf 1 -> grafted pos 1
        assert_eq!(ops_to_grafted_pos(Position::new(5), 1), 1);
        // ops_pos=6 (internal, height 2) -> grafted internal at height 1 -> grafted pos 2
        assert_eq!(ops_to_grafted_pos(Position::new(6), 1), 2);
        // ops_pos=9 (chunk 2) -> grafted leaf 2 -> grafted pos 3
        assert_eq!(ops_to_grafted_pos(Position::new(9), 1), 3);
        // ops_pos=12 (chunk 3) -> grafted leaf 3 -> grafted pos 4
        assert_eq!(ops_to_grafted_pos(Position::new(12), 1), 4);
        // ops_pos=13 (internal, height 2) -> grafted internal at height 1 -> grafted pos 5
        assert_eq!(ops_to_grafted_pos(Position::new(13), 1), 5);
        // ops_pos=14 (root, height 3) -> grafted root at height 2 -> grafted pos 6
        assert_eq!(ops_to_grafted_pos(Position::new(14), 1), 6);
    }

    #[test_traced]
    fn test_grafted_leaf_computation() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 200;

            let mut standard: StandardHasher<Sha256> = StandardHasher::new();
            let mmr = CleanMmr::new(&mut standard);
            let ops_mmr = build_test_mmr(&mut standard, mmr, NUM_ELEMENTS);

            // Generate the elements that build_test_mmr uses: sha256(i.to_be_bytes()).
            let elements: Vec<_> = (0..NUM_ELEMENTS)
                .map(|i| {
                    standard.inner().update(&i.to_be_bytes());
                    standard.inner().finalize()
                })
                .collect();

            // Height 0 grafting (1:1 mapping).
            {
                assert_eq!(chunk_idx_to_ops_pos(0, 0), Position::new(0));
                assert_eq!(chunk_idx_to_ops_pos(1, 0), Position::new(1));

                let grafted = build_test_grafted_mmr(&mut standard, &ops_mmr, &elements, 0);
                let gp = ops_to_grafted_pos(chunk_idx_to_ops_pos(0, 0), 0);
                assert!(grafted.get_node(gp).is_some());
            }

            // Height 1 grafting (each grafted leaf covers 2 ops leaves).
            let ops_mmr = build_test_mmr(&mut standard, ops_mmr, NUM_ELEMENTS);
            {
                // Confirm chunk_idx_to_ops_pos mappings at height 1.
                assert_eq!(chunk_idx_to_ops_pos(0, 1), Position::new(2));
                assert_eq!(chunk_idx_to_ops_pos(1, 1), Position::new(5));
                assert_eq!(chunk_idx_to_ops_pos(2, 1), Position::new(9));
                assert_eq!(chunk_idx_to_ops_pos(3, 1), Position::new(12));
                assert_eq!(chunk_idx_to_ops_pos(4, 1), Position::new(17));

                let grafted = build_test_grafted_mmr(&mut standard, &ops_mmr, &elements, 1);
                let gp = ops_to_grafted_pos(chunk_idx_to_ops_pos(0, 1), 1);
                assert!(grafted.get_node(gp).is_some());
            }

            // Height 2 and 3 checks.
            assert_eq!(chunk_idx_to_ops_pos(0, 2), Position::new(6));
            assert_eq!(chunk_idx_to_ops_pos(1, 2), Position::new(13));
            assert_eq!(chunk_idx_to_ops_pos(0, 3), Position::new(14));
        });
    }

    #[test_traced]
    fn test_merkleize_grafted() {
        let mut standard: StandardHasher<Sha256> = StandardHasher::new();
        let grafting_height = 1u32;

        // Build ops MMR with 4 leaves.
        let mut ops_mmr = DirtyMmr::new();
        for i in 0u8..4 {
            ops_mmr.add(&mut standard, &Sha256::fill(i));
        }
        let ops_mmr = ops_mmr.merkleize(&mut standard, None);

        let c1 = Sha256::fill(0xF1);
        let c2 = Sha256::fill(0xF2);

        // Build grafted MMR with 2 leaves via DirtyMmr + GraftedHasher.
        let mut dirty = DirtyMmr::new();
        let pos0 = chunk_idx_to_ops_pos(0, grafting_height);
        let pos1 = chunk_idx_to_ops_pos(1, grafting_height);

        let sub0 = ops_mmr.get_node(pos0).unwrap();
        standard.inner().update(&c1);
        standard.inner().update(&sub0);
        dirty.add_leaf_digest(standard.inner().finalize());

        let sub1 = ops_mmr.get_node(pos1).unwrap();
        standard.inner().update(&c2);
        standard.inner().update(&sub1);
        dirty.add_leaf_digest(standard.inner().finalize());

        let mut grafted_hasher = GraftedHasher::new(standard.fork(), grafting_height);
        let grafted = dirty.merkleize(&mut grafted_hasher, None);

        // With 4 ops leaves and grafting height 1, the grafted tree has 2 leaves and 1 root.
        // All 3 nodes should be retrievable (via grafted-space positions).
        let gp0 = ops_to_grafted_pos(pos0, grafting_height);
        let gp1 = ops_to_grafted_pos(pos1, grafting_height);
        let gp_root = ops_to_grafted_pos(Position::new(6), grafting_height);
        assert!(grafted.get_node(gp0).is_some());
        assert!(grafted.get_node(gp1).is_some());
        assert!(grafted.get_node(gp_root).is_some());
    }

    /// Builds a small grafted structure, then generates and verifies proofs over it.
    #[test_traced]
    fn test_grafted_storage_proofs() {
        let executor = deterministic::Runner::default();
        const GRAFTING_HEIGHT: u32 = 1;
        executor.start(|_| async move {
            let b1 = Sha256::fill(0x01);
            let b2 = Sha256::fill(0x02);
            let b3 = Sha256::fill(0x03);
            let b4 = Sha256::fill(0x04);
            let mut standard: StandardHasher<Sha256> = StandardHasher::new();

            // Build an ops MMR with 4 leaves.
            let mut ops_mmr = DirtyMmr::new();
            ops_mmr.add(&mut standard, &b1);
            ops_mmr.add(&mut standard, &b2);
            ops_mmr.add(&mut standard, &b3);
            ops_mmr.add(&mut standard, &b4);
            let ops_mmr = ops_mmr.merkleize(&mut standard, None);

            // Bitmap chunk elements (one per grafted leaf).
            let c1 = Sha256::fill(0xF1);
            let c2 = Sha256::fill(0xF2);

            // With grafting height 1, each grafted leaf covers 2 ops leaves, so 4 ops leaves
            // yield 2 grafted leaves.
            let grafted =
                build_test_grafted_mmr(&mut standard, &ops_mmr, &[c1, c2], GRAFTING_HEIGHT);

            let ops_root = *ops_mmr.root();

            {
                let combined = Storage::new(&grafted, GRAFTING_HEIGHT, &ops_mmr);
                assert_eq!(combined.size().await, ops_mmr.size());

                // Compute the combined root by iterating ops peaks.
                let combined_root = {
                    let ops_size = ops_mmr.size();
                    let ops_leaves = Location::try_from(ops_size).unwrap();
                    let mut peaks = Vec::new();
                    for (peak_pos, peak_height) in PeakIterator::new(ops_size) {
                        if peak_height >= GRAFTING_HEIGHT {
                            let gp = ops_to_grafted_pos(peak_pos, GRAFTING_HEIGHT);
                            peaks.push(grafted.get_node(gp).unwrap());
                        } else {
                            peaks.push(combined.get_node(peak_pos).await.unwrap().unwrap());
                        }
                    }
                    standard.root(ops_leaves, peaks.iter())
                };
                assert_ne!(combined_root, ops_root);

                // Verify inclusion proofs for each of the 4 ops leaves.
                {
                    let loc = Location::new_unchecked(0);
                    let proof = verification::range_proof(&combined, loc..loc + 1)
                        .await
                        .unwrap();

                    let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b1,
                        loc,
                        &combined_root
                    ));

                    let loc = Location::new_unchecked(1);
                    let proof = verification::range_proof(&combined, loc..loc + 1)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b2,
                        loc,
                        &combined_root
                    ));

                    let loc = Location::new_unchecked(2);
                    let proof = verification::range_proof(&combined, loc..loc + 1)
                        .await
                        .unwrap();
                    let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 1, vec![&c2]);
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b3,
                        loc,
                        &combined_root
                    ));

                    let loc = Location::new_unchecked(3);
                    let proof = verification::range_proof(&combined, loc..loc + 1)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        loc,
                        &combined_root
                    ));
                }

                // Verify that manipulated inputs cause proof verification to fail.
                {
                    let loc = Location::new_unchecked(3);
                    let proof = verification::range_proof(&combined, loc..loc + 1)
                        .await
                        .unwrap();
                    let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 1, vec![&c2]);
                    assert!(proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        loc,
                        &combined_root
                    ));

                    // Wrong leaf element.
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b3,
                        loc,
                        &combined_root
                    ));

                    // Wrong root.
                    assert!(!proof.verify_element_inclusion(&mut verifier, &b4, loc, &ops_root));

                    // Wrong position.
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        loc + 1,
                        &combined_root
                    ));

                    // Wrong chunk element in the verifier.
                    let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        loc,
                        &combined_root
                    ));

                    // Wrong chunk index in the verifier.
                    let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 2, vec![&c2]);
                    assert!(!proof.verify_element_inclusion(
                        &mut verifier,
                        &b4,
                        loc,
                        &combined_root
                    ));
                }

                // Verify range proofs.
                {
                    let proof = verification::range_proof(
                        &combined,
                        Location::new_unchecked(0)..Location::new_unchecked(4),
                    )
                    .await
                    .unwrap();
                    let range = vec![&b1, &b2, &b3, &b4];
                    let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1, &c2]);
                    assert!(proof.verify_range_inclusion(
                        &mut verifier,
                        &range,
                        Location::new_unchecked(0),
                        &combined_root
                    ));

                    // Fails with incomplete chunk elements.
                    let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
                    assert!(!proof.verify_range_inclusion(
                        &mut verifier,
                        &range,
                        Location::new_unchecked(0),
                        &combined_root
                    ));
                }
            }

            // Add a 5th ops leaf that has no corresponding grafted leaf (it falls below
            // the grafting height boundary since there's no complete chunk for it yet).
            let b5 = Sha256::fill(0x05);
            let changeset = {
                let mut diff = crate::mmr::diff::DirtyDiff::new(&ops_mmr);
                diff.add(&mut standard, &b5);
                diff.merkleize(&mut standard).into_changeset()
            };
            let mut ops_mmr = ops_mmr;
            ops_mmr.apply(changeset);

            let combined = Storage::new(&grafted, GRAFTING_HEIGHT, &ops_mmr);
            assert_eq!(combined.size().await, ops_mmr.size());

            // Compute the combined root.
            let combined_root = {
                let ops_size = ops_mmr.size();
                let ops_leaves = Location::try_from(ops_size).unwrap();
                let mut peaks = Vec::new();
                for (peak_pos, peak_height) in PeakIterator::new(ops_size) {
                    if peak_height >= GRAFTING_HEIGHT {
                        let gp = ops_to_grafted_pos(peak_pos, GRAFTING_HEIGHT);
                        peaks.push(grafted.get_node(gp).unwrap());
                    } else {
                        peaks.push(combined.get_node(peak_pos).await.unwrap().unwrap());
                    }
                }
                standard.root(ops_leaves, peaks.iter())
            };

            // Verify inclusion proofs still work for both covered and uncovered ops leaves.
            let loc = Location::new_unchecked(0);
            let proof = verification::range_proof(&combined, loc..loc + 1)
                .await
                .unwrap();

            let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
            assert!(proof.verify_element_inclusion(&mut verifier, &b1, loc, &combined_root));

            let mut verifier = Verifier::<Sha256>::new(GRAFTING_HEIGHT, 0, vec![]);
            let loc = Location::new_unchecked(4);
            let proof = verification::range_proof(&combined, loc..loc + 1)
                .await
                .unwrap();
            assert!(proof.verify_element_inclusion(&mut verifier, &b5, loc, &combined_root));
        });
    }

    #[test_traced]
    fn test_grafted_mmr_basic() {
        let grafting_height = 1u32;
        let standard: StandardHasher<Sha256> = StandardHasher::new();

        // Build a grafted MMR with 2 leaves via DirtyMmr + GraftedHasher.
        let mut dirty = DirtyMmr::new();
        let d0 = Sha256::fill(0x01);
        let d1 = Sha256::fill(0x02);
        dirty.add_leaf_digest(d0);
        dirty.add_leaf_digest(d1);
        let mut grafted_hasher = GraftedHasher::new(standard.fork(), grafting_height);
        let grafted = dirty.merkleize(&mut grafted_hasher, None);

        // Check that grafted leaves are retrievable via grafted-space positions.
        let ops_pos_0 = chunk_idx_to_ops_pos(0, grafting_height);
        let ops_pos_1 = chunk_idx_to_ops_pos(1, grafting_height);
        let gp0 = ops_to_grafted_pos(ops_pos_0, grafting_height);
        let gp1 = ops_to_grafted_pos(ops_pos_1, grafting_height);
        assert_eq!(grafted.get_node(gp0), Some(d0));
        assert_eq!(grafted.get_node(gp1), Some(d1));

        // Internal node (grafted root) should also exist.
        let gp_root = ops_to_grafted_pos(Position::new(6), grafting_height);
        assert!(grafted.get_node(gp_root).is_some());

        // Non-existent position returns None.
        let gp_far = ops_to_grafted_pos(chunk_idx_to_ops_pos(5, grafting_height), grafting_height);
        assert_eq!(grafted.get_node(gp_far), None);
    }

    #[test_traced]
    fn test_grafted_mmr_with_pruning() {
        let grafting_height = 1u32;
        let standard: StandardHasher<Sha256> = StandardHasher::new();

        // Simulate pruning 4 chunks. The pruned sub-MMR has 4 grafted leaves,
        // mmr_size(4) = 7, with one peak at grafted position 6.
        let pinned_digest = Sha256::fill(0xAA);
        let grafted_pruned_to_pos = Position::try_from(Location::new_unchecked(4)).unwrap();
        assert_eq!(*grafted_pruned_to_pos, 7);

        // Build a grafted MMR from pruned components + one new leaf.
        let d4 = Sha256::fill(0xBB);
        let mut dirty =
            DirtyMmr::from_components(Vec::new(), grafted_pruned_to_pos, vec![pinned_digest]);
        dirty.add_leaf_digest(d4);
        let mut grafted_hasher = GraftedHasher::new(standard.fork(), grafting_height);
        let grafted = dirty.merkleize(&mut grafted_hasher, None);

        // The pinned peak should be at grafted position 6.
        assert_eq!(grafted.get_node(Position::new(6)), Some(pinned_digest));

        // The new leaf at chunk 4 (grafted pos 7) should be retrievable.
        let ops_pos_4 = chunk_idx_to_ops_pos(4, grafting_height);
        let gp4 = ops_to_grafted_pos(ops_pos_4, grafting_height);
        assert_eq!(grafted.get_node(gp4), Some(d4));
    }
}
