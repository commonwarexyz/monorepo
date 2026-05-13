//! Verifier and storage for grafting bitmap chunks onto an operations tree.
//!
//! ## Overview
//!
//! An operations tree is built over a log of operations, and a bitmap tracks the activity
//! status of each operation. To authenticate both structures efficiently, we combine them: each
//! _graftable_ chunk of the bitmap is hashed together with the corresponding subtree root from the
//! ops tree to produce a single "grafted leaf" digest. These digests, along with their ancestor
//! nodes, are stored in an in-memory Merkle structure (using grafted-space positions internally,
//! with ops-space positions in hash pre-images).
//!
//! A chunk is _graftable_ once its height-`G` ancestor exists in the ops tree as a single node. In
//! MMR every complete chunk is immediately graftable. MMB's delayed merges allow at most one chunk
//! per database to be bit-complete but not yet graftable ("pending").
//!
//! ```text
//!   Why MMB has a pending state, illustrated at G = 2 (chunk size = 4 leaves):
//!
//!   At ops_leaves N = 4, chunk 0's four bits are complete, so we want to graft it.
//!
//!     MMR:  N = 4 forms a perfect 4-leaf subtree, so chunk 0 has a single
//!           h=2 ancestor -- graft directly as hash(chunk_0 || h=2_root).
//!
//!     MMB:  N = 4 has no h=2 node yet. Chunk 0's leaves are split across
//!           several h<2 peaks; there is no single ops node to graft onto.
//!           The h=2 ancestor is not born until N reaches birth_chunk_0 = 5
//!           (= 3 * 2^(G-1) - 1 for MMB at G=2). Until then, chunk 0's digest
//!           is hashed directly into the canonical root; once the ancestor is
//!           born, the chunk migrates into the grafted tree.
//! ```
//!
//! This is more efficient than maintaining two independent authenticated structures. An inclusion
//! proof for an operation and its activity status only requires one branch (which embeds the bitmap
//! chunk) plus the sub-branch from the ops tree below the grafting point, reducing proof size by up
//! to a factor of 2.
//!
//! ## Grafting height
//!
//! Each grafted leaf covers `2^h` ops-tree leaves, where `h` is the grafting height
//! (`log2(chunk_size_bits)`). For example, given an ops tree over 8 operations with grafting height
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
//! grafting height (position 14) use standard hashing with ops-space positions.
//!
//! The grafted tree is incrementally maintained when grafted leaves change.

use crate::merkle::{
    self, hasher::Hasher as HasherTrait, storage::Storage as StorageTrait, Family, Graftable,
    Location, Position, Readable,
};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_utils::bitmap::BitMap;
use core::{cmp::Ordering, marker::PhantomData};
use tracing::debug;

/// Get the grafting height for a bitmap with chunk size determined by N.
pub const fn height<const N: usize>() -> u32 {
    BitMap::<N>::CHUNK_SIZE_BITS.trailing_zeros()
}

/// Return the number of bitmap chunks that have a corresponding height-G ancestor in the ops tree.
///
/// - For MMR, this is always the same as the number of complete_chunks.
/// - For MMB, this is either complete_chunks or complete_chunks - 1.
///
/// # Panics
///
/// Panics if `grafting_height == 0`.
pub fn graftable_chunks<F: Graftable>(ops_leaves: u64, grafting_height: u32) -> u64 {
    assert!(grafting_height >= 1, "grafting_height must be >= 1");
    let pos = F::subtree_root_position(Location::<F>::new(0), grafting_height);
    let birth_chunk_0 = F::peak_birth_size(pos, grafting_height);
    if ops_leaves < birth_chunk_0 {
        return 0;
    }
    let chunk_size = 1u64 << grafting_height;
    (ops_leaves - birth_chunk_0) / chunk_size + 1
}

/// Return the number of root peaks whose covered leaves end on or before `inactivity_floor`, while
/// keeping the resulting boundary aligned to a complete bitmap chunk.
///
/// Current grafted roots treat bitmap chunks as the atomic grafting unit. If the exact inactivity
/// floor falls inside a root peak or inside a multi-peak chunk group, the partially covered chunk
/// stays in the graftable region and the inactive peak count is rounded down to the latest chunk
/// boundary expressible by whole root peaks.
pub(super) fn chunk_aligned_inactive_peaks<F: Family>(
    leaves: Location<F>,
    inactivity_floor: Location<F>,
    grafting_height: u32,
) -> Result<usize, merkle::Error<F>> {
    let size = F::location_to_position(leaves);
    let chunk_size = 1u64 << grafting_height;
    let floor = *inactivity_floor;
    let mut leaf_end = 0u64;
    let mut aligned_count = 0usize;

    for (idx, (_pos, height)) in F::peaks(size).enumerate() {
        let next_leaf_end = leaf_end + (1u64 << height);
        if next_leaf_end > floor {
            break;
        }
        leaf_end = next_leaf_end;
        if leaf_end.is_multiple_of(chunk_size) {
            aligned_count = idx + 1;
        }
    }

    Ok(aligned_count)
}

// --- Coordinate conversion ---
//
// These functions convert between three coordinate spaces:
//
// 1. **Chunk index**: Sequential index (0, 1, 2, ...) of (complete) bitmap chunks.
// 2. **Ops position**: Position in the full operations tree.
// 3. **Grafted position**: Position in the grafted tree, whose leaves correspond 1:1 with chunks.
//
// All conversions rely on a single family identity: given the leftmost leaf at position P of a
// perfect subtree, the subtree root at height h is at `P + 2^(h+1) - 2`, and conversely the
// leftmost leaf under a subtree root at position P and height h is at `P + 2 - 2^(h+1)`.

/// Convert an ops-family position (at or above the grafting height) to a grafted-tree position.
///
/// An ops node at height `ops_h` maps to a grafted node at height `ops_h - grafting_height`.
/// The conversion descends to the leftmost ops leaf, divides by 2^h to get the chunk index
/// (= grafted leaf location), then climbs back up to the grafted height. The result always
/// lives in grafted-space, which is a Merkle tree over chunk indices.
///
/// # Panics
///
/// Panics if `ops_pos` is below the grafting height.
pub fn ops_to_grafted_pos<F: Graftable>(ops_pos: Position<F>, grafting_height: u32) -> Position<F> {
    let ops_height = F::pos_to_height(ops_pos);
    assert!(
        ops_height >= grafting_height,
        "position height {ops_height} < grafting height {grafting_height}"
    );
    let grafted_height = ops_height - grafting_height;

    let ops_leaf_loc = F::leftmost_leaf(ops_pos, ops_height);
    let chunk_idx = *ops_leaf_loc >> grafting_height;
    let grafted_leaf_loc = Location::<F>::new(chunk_idx);
    F::subtree_root_position(grafted_leaf_loc, grafted_height)
}

/// Convert a grafted position to the ops-family position whose subtree covers the same ops-leaf
/// range.
pub fn grafted_to_ops_pos<F: Graftable>(
    grafted_pos: Position<F>,
    grafting_height: u32,
) -> Position<F> {
    let grafted_height = F::pos_to_height(grafted_pos);
    let grafted_leaf = F::leftmost_leaf(grafted_pos, grafted_height);
    let ops_leaf_start = Location::<F>::new(*grafted_leaf << grafting_height);
    let ops_height = grafted_height + grafting_height;
    F::subtree_root_position(ops_leaf_start, ops_height)
}

/// A hasher adapter that maps grafted-structure positions to ops-structure positions.
///
/// Both the grafted structure and ops structure use the same family `F`. The grafted
/// structure's leaves correspond 1:1 with bitmap chunks. This adapter intercepts
/// [`HasherTrait::node_digest`] to convert each grafted position to the corresponding
/// ops-space position via [`Graftable::leftmost_leaf`] and [`Graftable::subtree_root_position`],
/// ensuring hash pre-images use ops-space positions for domain separation.
#[derive(Clone)]
pub(super) struct GraftedHasher<F: Graftable, H: HasherTrait<F>> {
    inner: H,
    grafting_height: u32,
    _family: PhantomData<F>,
}

impl<F: Graftable, H: HasherTrait<F>> GraftedHasher<F, H> {
    pub(super) const fn new(inner: H, grafting_height: u32) -> Self {
        Self {
            inner,
            grafting_height,
            _family: PhantomData,
        }
    }
}

impl<F: Graftable, H: HasherTrait<F>> HasherTrait<F> for GraftedHasher<F, H> {
    type Digest = H::Digest;

    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> Self::Digest {
        self.inner.hash(parts)
    }

    fn root_bagging(&self) -> merkle::Bagging {
        self.inner.root_bagging()
    }

    fn node_digest(
        &self,
        pos: Position<F>,
        left: &Self::Digest,
        right: &Self::Digest,
    ) -> Self::Digest {
        let ops_pos = grafted_to_ops_pos::<F>(pos, self.grafting_height);
        self.inner.node_digest(ops_pos, left, right)
    }
}

/// A [HasherTrait] implementation used for verifying proofs over grafted [Storage].
///
/// The ops structure uses family `F`, so this implements `HasherTrait<F>` to match the proof.
/// Proof verification walks the tree from leaves to root, recomputing digests at each node.
/// Since a proof path crosses the grafting boundary (from ops leaves up through grafted peaks),
/// two different hashing behaviors are needed depending on the node's height relative to the
/// grafting height:
///
/// - **Below or above**: standard hash using ops-space positions (`F`).
/// - **At**: the children form an ops subtree root, which is combined with a bitmap chunk element
///   to reconstruct the grafted leaf digest.
#[derive(Clone)]
pub(super) struct Verifier<'a, F: Graftable, H: CHasher> {
    hasher: merkle::hasher::Standard<H>,
    grafting_height: u32,

    /// Bitmap chunks needed for grafted leaf reconstruction at the boundary.
    chunks: Vec<&'a [u8]>,

    /// The chunk index of `chunks[0]`.
    start_chunk_index: u64,

    /// Number of chunks with a corresponding height-G ancestor in the ops tree.
    graftable_chunks: u64,

    _ops_family: PhantomData<F>,
}

impl<'a, F: Graftable, H: CHasher> Verifier<'a, F, H> {
    /// Create a new Verifier whose internal hasher uses the supplied bagging policy.
    ///
    /// `start_chunk_index` is the chunk index corresponding to `chunks[0]`.
    /// `graftable_chunks` is the number of chunks committed by the grafted tree; any chunk index
    /// in `chunks` at or beyond this boundary is treated as pending and **not** combined with
    /// the ops subtree root at the grafting height.
    pub(super) const fn new(
        grafting_height: u32,
        start_chunk_index: u64,
        chunks: Vec<&'a [u8]>,
        graftable_chunks: u64,
        bagging: merkle::Bagging,
    ) -> Self {
        Self {
            hasher: merkle::hasher::Standard::new(bagging),
            grafting_height,
            chunks,
            start_chunk_index,
            graftable_chunks,
            _ops_family: PhantomData,
        }
    }
}

impl<F: Graftable, H: CHasher> HasherTrait<F> for Verifier<'_, F, H> {
    type Digest = H::Digest;

    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> H::Digest {
        self.hasher.hash(parts)
    }

    fn root_bagging(&self) -> merkle::Bagging {
        <merkle::hasher::Standard<H> as HasherTrait<F>>::root_bagging(&self.hasher)
    }

    fn node_digest(
        &self,
        pos: merkle::Position<F>,
        left_digest: &H::Digest,
        right_digest: &H::Digest,
    ) -> H::Digest {
        match F::pos_to_height(pos).cmp(&self.grafting_height) {
            Ordering::Less | Ordering::Greater => {
                // Below or above grafting height: standard hash with ops-space position.
                self.hasher.node_digest(pos, left_digest, right_digest)
            }
            Ordering::Equal => {
                // At grafting height: compute ops subtree root, then combine with bitmap chunk.
                let ops_subtree_root = self.hasher.node_digest(pos, left_digest, right_digest);

                // Convert the F-family position to a chunk index using F's leftmost_leaf.
                let loc = F::leftmost_leaf(pos, self.grafting_height);
                let chunk_idx = *loc >> self.grafting_height;

                // Skip pending chunks. These will be incorporated in the root via the pending_chunk
                // digest field.
                if chunk_idx >= self.graftable_chunks {
                    debug!(?chunk_idx, "skipping pending chunk");
                    return ops_subtree_root;
                }

                let Some(local) = chunk_idx
                    .checked_sub(self.start_chunk_index)
                    .filter(|&l| l < self.chunks.len() as u64)
                    .map(|l| l as usize)
                else {
                    debug!(?pos, "chunk not available for grafted leaf");
                    return ops_subtree_root;
                };

                // For all-zero chunks, the grafted leaf is the ops subtree root (identity).
                // For non-zero chunks: grafted_leaf = hash(chunk || ops_subtree_root).
                let chunk = self.chunks[local];
                if chunk.iter().all(|&b| b == 0) {
                    ops_subtree_root
                } else {
                    self.hash([chunk, ops_subtree_root.as_ref()])
                }
            }
        }
    }
}

/// A virtual [StorageTrait] that presents a grafted tree and ops tree as a single combined Merkle
/// structure.
///
/// Nodes below the grafting height are served from the ops tree. Nodes at or above the grafting
/// height are served from the grafted tree (with ops-to-grafted position conversion). This allows
/// standard proof generation to work transparently over the combined structure.
///
/// Both the ops structure and the grafted structure use the same [Family] `F`. The combined storage
/// presents as `StorageTrait<F>` so that callers generic over `F` can use it transparently.
pub(super) struct Storage<
    'a,
    F: Graftable,
    D: Digest,
    G: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
    S: StorageTrait<F, Digest = D>,
    H: HasherTrait<F, Digest = D> + Clone,
> {
    grafted_tree: &'a G,
    grafting_height: u32,
    ops_tree: &'a S,
    grafted_hasher: GraftedHasher<F, H>,
    _phantom: PhantomData<(F, D)>,
}

impl<
        'a,
        F: Graftable,
        D: Digest,
        G: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
        S: StorageTrait<F, Digest = D>,
        H: HasherTrait<F, Digest = D> + Clone,
    > Storage<'a, F, D, G, S, H>
{
    /// Creates a new [Storage] instance.
    pub(super) const fn new(
        grafted_tree: &'a G,
        grafting_height: u32,
        ops_tree: &'a S,
        hasher: H,
    ) -> Self {
        Self {
            grafted_tree,
            grafting_height,
            ops_tree,
            grafted_hasher: GraftedHasher::new(hasher, grafting_height),
            _phantom: PhantomData,
        }
    }

    /// Reconstruct a grafted node that is missing from the pruned grafted tree.
    ///
    /// After pruning, only the grafted tree's pinned peaks and retained nodes are available.
    /// As the ops tree grows, delayed merges create new ops peaks that map to grafted nodes
    /// above the pinned peaks (ancestors). This function reconstructs those ancestors by
    /// recursing into their children and hashing upward until it reaches available nodes
    /// (pinned peaks or retained nodes).
    ///
    /// Recursion depth is bounded by the height difference between the queried node and the
    /// nearest available descendant (a pinned peak or retained node). In practice it remains
    /// small because the settlement guard limits how far ahead the ops tree can grow before
    /// bitmap pruning advances.
    ///
    /// Returns `None` at height 0 (a grafted leaf), since leaves encode bitmap data and
    /// cannot be recomputed from the tree structure alone. The settlement guard in
    /// [`super::db::Db::sync_boundary`] ensures this case is unreachable for pruned chunks.
    fn reconstruct_grafted_node(&self, pos: Position<F>) -> Option<D> {
        if let Some(node) = self.grafted_tree.get_node(pos) {
            return Some(node);
        }

        let height = F::pos_to_height(pos);
        if height == 0 {
            return None;
        }
        let (left, right) = F::children(pos, height);
        let left_digest = self.reconstruct_grafted_node(left)?;
        let right_digest = self.reconstruct_grafted_node(right)?;
        Some(
            self.grafted_hasher
                .node_digest(pos, &left_digest, &right_digest),
        )
    }
}

impl<
        F: Graftable,
        D: Digest,
        G: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
        S: StorageTrait<F, Digest = D>,
        H: HasherTrait<F, Digest = D> + Clone + Send + Sync,
    > StorageTrait<F> for Storage<'_, F, D, G, S, H>
{
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.ops_tree.size().await
    }

    async fn get_node(&self, pos: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        let ops_height = F::pos_to_height(pos);
        if ops_height < self.grafting_height {
            return self.ops_tree.get_node(pos).await;
        }
        let grafted_pos = ops_to_grafted_pos::<F>(pos, self.grafting_height);
        Ok(self.reconstruct_grafted_node(grafted_pos))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{conformance::build_test_mmr, Bagging::ForwardFold},
        mmb, mmr,
        mmr::{
            iterator::{pos_to_height, PeakIterator},
            mem::Mmr,
            verification, Location, Position, StandardHasher,
        },
    };
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    /// MMR has no pending state, so every supplied chunk should be treated as graftable during
    /// verification. Tests use this sentinel to avoid threading the actual chunk count through
    /// every call site.
    const ALL_CHUNKS_GRAFTABLE: u64 = u64::MAX;

    /// Count chunks of `2^G` leaves in `0..ops_leaves` that have a single covering peak at height G.
    ///
    /// Used as the oracle for `graftable_chunks` property tests.
    fn count_single_peak_chunks<F: Graftable>(ops_leaves: u64, grafting_height: u32) -> u64 {
        let chunk_size = 1u64 << grafting_height;
        let total_complete = ops_leaves / chunk_size;
        if total_complete == 0 {
            return 0;
        }
        let size = F::location_to_position(crate::merkle::Location::<F>::new(ops_leaves));
        let mut count = 0u64;
        for chunk_idx in 0..total_complete {
            // chunk has a single covering peak iff chunk_peaks returns exactly one entry.
            let mut iter = F::chunk_peaks(size, chunk_idx, grafting_height);
            let _first = iter.next();
            if iter.next().is_none() {
                count += 1;
            }
        }
        count
    }

    fn graftable_chunks_matches_oracle<F: Graftable>() {
        for grafting_height in 1u32..=8 {
            let chunk_size = 1u64 << grafting_height;
            let n_max = (chunk_size * 80).min(2000);
            for ops_leaves in 0u64..=n_max {
                let graftable = graftable_chunks::<F>(ops_leaves, grafting_height);
                let oracle = count_single_peak_chunks::<F>(ops_leaves, grafting_height);
                assert_eq!(
                    graftable, oracle,
                    "mismatch: family graftable={graftable}, oracle={oracle}, ops_leaves={ops_leaves}, G={grafting_height}"
                );

                let complete = ops_leaves / chunk_size;
                assert!(
                    graftable <= complete,
                    "graftable {graftable} exceeded complete {complete} (ops_leaves={ops_leaves}, G={grafting_height})"
                );
                assert!(
                    complete - graftable <= 1,
                    "complete-graftable gap > 1: complete={complete}, graftable={graftable}, ops_leaves={ops_leaves}, G={grafting_height}"
                );
            }
        }
    }

    #[test]
    fn test_graftable_chunks_mmr_matches_chunk_peaks() {
        graftable_chunks_matches_oracle::<mmr::Family>();
    }

    #[test]
    fn test_graftable_chunks_mmb_matches_chunk_peaks() {
        graftable_chunks_matches_oracle::<mmb::Family>();
    }

    /// MMR has no pending state: graftable_chunks always equals complete_chunks.
    #[test]
    fn test_graftable_chunks_mmr_no_pending() {
        for grafting_height in 1u32..=8 {
            let chunk_size = 1u64 << grafting_height;
            let n_max = (chunk_size * 80).min(2000);
            for ops_leaves in 0u64..=n_max {
                let graftable = graftable_chunks::<mmr::Family>(ops_leaves, grafting_height);
                let complete = ops_leaves / chunk_size;
                assert_eq!(
                    graftable, complete,
                    "MMR has unexpected pending state: ops_leaves={ops_leaves}, G={grafting_height}, graftable={graftable}, complete={complete}"
                );
            }
        }
    }

    /// Sanity check: the MMB pending window has width `2^(G-1) - 1` per chunk, strictly less than
    /// `2^G`, so at most one chunk is pending at any moment.
    #[test]
    fn test_graftable_chunks_mmb_at_most_one_pending() {
        for grafting_height in 1u32..=8 {
            let chunk_size = 1u64 << grafting_height;
            let n_max = (chunk_size * 80).min(2000);
            for ops_leaves in 0u64..=n_max {
                let graftable = graftable_chunks::<mmb::Family>(ops_leaves, grafting_height);
                let complete = ops_leaves / chunk_size;
                let pending = complete.saturating_sub(graftable);
                assert!(
                    pending <= 1,
                    "MMB has {pending} pending chunks (ops_leaves={ops_leaves}, G={grafting_height}); should be <= 1"
                );
            }
        }
    }

    #[test]
    #[should_panic(expected = "grafting_height must be >= 1")]
    fn test_graftable_chunks_rejects_height_zero() {
        let _ = graftable_chunks::<mmr::Family>(100, 0);
    }

    /// When `graftable_chunks: 0` is passed to a `Verifier`, every chunk index is treated as
    /// pending, so `node_digest` at height G returns the raw ops subtree root, never the
    /// chunk-combined digest. This is the boundary case for the graftable/pending check.
    #[test]
    fn test_verifier_graftable_chunks_zero_skips_chunk_combine() {
        const GH: u32 = 1;
        let chunk: [u8; 1] = [0xAB];
        let left = Sha256::fill(0x01);
        let right = Sha256::fill(0x02);

        // Position at h=G with chunk_idx 0; with graftable_chunks=0 the verifier must NOT
        // combine the chunk (chunk_idx >= graftable_chunks).
        let pos_at_g = mmr::Family::subtree_root_position(Location::new(0), GH);

        let standard: StandardHasher<Sha256> = StandardHasher::new(ForwardFold);
        let expected_no_combine = <StandardHasher<Sha256> as HasherTrait<mmr::Family>>::node_digest(
            &standard, pos_at_g, &left, &right,
        );

        let v = Verifier::<mmr::Family, Sha256>::new(GH, 0, vec![&chunk], 0, ForwardFold);
        let got = <Verifier<'_, mmr::Family, Sha256> as HasherTrait<mmr::Family>>::node_digest(
            &v, pos_at_g, &left, &right,
        );
        assert_eq!(
            got, expected_no_combine,
            "graftable_chunks=0 must skip chunk combination at the grafting height"
        );

        // Sanity: with graftable_chunks=1 the chunk IS combined, so the digest differs.
        let v_graftable = Verifier::<mmr::Family, Sha256>::new(GH, 0, vec![&chunk], 1, ForwardFold);
        let got_graftable =
            <Verifier<'_, mmr::Family, Sha256> as HasherTrait<mmr::Family>>::node_digest(
                &v_graftable,
                pos_at_g,
                &left,
                &right,
            );
        assert_ne!(got, got_graftable);
    }

    /// Convert an ops-tree position at the grafting height back to its chunk index.
    fn ops_pos_to_chunk_idx(ops_pos: Position, grafting_height: u32) -> u64 {
        let loc = mmr::Family::leftmost_leaf(ops_pos, grafting_height);
        *loc >> grafting_height
    }

    /// Convert a chunk index to the ops position of the subtree root.
    fn chunk_idx_to_ops_pos(chunk_idx: u64, grafting_height: u32) -> Position {
        let first_leaf_loc = Location::new(chunk_idx << grafting_height);
        mmr::Family::subtree_root_position(first_leaf_loc, grafting_height)
    }

    /// Precompute grafted leaf digests and return an MMR-based grafted test tree.
    ///
    /// Each grafted leaf is `hash(chunk || ops_subtree_root)` where `ops_subtree_root` is the ops
    /// tree node at the mapped position.
    fn build_test_grafted_mmr(
        standard: &StandardHasher<Sha256>,
        ops_mmr: &Mmr<sha256::Digest>,
        chunks: &[sha256::Digest],
        grafting_height: u32,
    ) -> Mmr<sha256::Digest> {
        let grafted_hasher =
            GraftedHasher::<mmr::Family, _>::new(standard.clone(), grafting_height);
        let mut grafted_mmr = Mmr::new();
        if !chunks.is_empty() {
            // Use a separate hasher for leaf digest computation to avoid borrow conflict
            // with grafted_hasher (which borrows standard via fork()).
            let leaf_hasher = StandardHasher::<Sha256>::new(ForwardFold);
            let batch = {
                let mut batch = grafted_mmr.new_batch();
                for (i, chunk) in chunks.iter().enumerate() {
                    let ops_pos = chunk_idx_to_ops_pos(i as u64, grafting_height);
                    let ops_subtree_root = ops_mmr
                        .get_node(ops_pos)
                        .expect("ops tree missing node at mapped position");
                    batch = batch.add_leaf_digest(
                        leaf_hasher.hash([chunk.as_ref(), ops_subtree_root.as_ref()]),
                    );
                }
                batch.merkleize(&grafted_mmr, &grafted_hasher)
            };
            grafted_mmr.apply_batch(&batch).unwrap();
        }
        grafted_mmr
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
                let expected = *Position::try_from(Location::new(chunk_idx)).unwrap();
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

            let standard: StandardHasher<Sha256> = StandardHasher::new(ForwardFold);
            let mmr = Mmr::new();
            let ops_mmr = build_test_mmr(&standard, mmr, NUM_ELEMENTS);

            // Generate the elements that build_test_mmr uses: sha256(i.to_be_bytes()).
            let elements: Vec<_> = (0..NUM_ELEMENTS)
                .map(|i| standard.digest(&i.to_be_bytes()))
                .collect();

            // Height 0 grafting (1:1 mapping).
            {
                assert_eq!(chunk_idx_to_ops_pos(0, 0), Position::new(0));
                assert_eq!(chunk_idx_to_ops_pos(1, 0), Position::new(1));

                let grafted = build_test_grafted_mmr(&standard, &ops_mmr, &elements, 0);
                let gp = ops_to_grafted_pos(chunk_idx_to_ops_pos(0, 0), 0);
                assert!(grafted.get_node(gp).is_some());
            }

            // Height 1 grafting (each grafted leaf covers 2 ops leaves).
            let ops_mmr = build_test_mmr(&standard, ops_mmr, NUM_ELEMENTS);
            {
                // Confirm chunk_idx_to_ops_pos mappings at height 1.
                assert_eq!(chunk_idx_to_ops_pos(0, 1), Position::new(2));
                assert_eq!(chunk_idx_to_ops_pos(1, 1), Position::new(5));
                assert_eq!(chunk_idx_to_ops_pos(2, 1), Position::new(9));
                assert_eq!(chunk_idx_to_ops_pos(3, 1), Position::new(12));
                assert_eq!(chunk_idx_to_ops_pos(4, 1), Position::new(17));

                let grafted = build_test_grafted_mmr(&standard, &ops_mmr, &elements, 1);
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
        let standard: StandardHasher<Sha256> = StandardHasher::new(ForwardFold);
        let grafting_height = 1u32;

        // Build ops MMR with 4 leaves.
        let mut ops_mmr = Mmr::new();
        let batch = {
            let mut batch = ops_mmr.new_batch();
            for i in 0u8..4 {
                batch = batch.add(&standard, &Sha256::fill(i));
            }
            batch.merkleize(&ops_mmr, &standard)
        };
        ops_mmr.apply_batch(&batch).unwrap();

        let c1 = Sha256::fill(0xF1);
        let c2 = Sha256::fill(0xF2);

        // Build grafted MMR with 2 leaves.
        let grafted_hasher = GraftedHasher::<mmr::Family, _>::new(standard, grafting_height);
        let mut grafted = Mmr::new();
        let pos0 = chunk_idx_to_ops_pos(0, grafting_height);
        let pos1 = chunk_idx_to_ops_pos(1, grafting_height);

        let batch = {
            let leaf_hasher = StandardHasher::<Sha256>::new(ForwardFold);
            let sub0 = ops_mmr.get_node(pos0).unwrap();
            let batch = grafted
                .new_batch()
                .add_leaf_digest(leaf_hasher.hash([c1.as_ref(), sub0.as_ref()]));

            let sub1 = ops_mmr.get_node(pos1).unwrap();
            batch
                .add_leaf_digest(leaf_hasher.hash([c2.as_ref(), sub1.as_ref()]))
                .merkleize(&grafted, &grafted_hasher)
        };
        grafted.apply_batch(&batch).unwrap();

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
            let hasher: StandardHasher<Sha256> = StandardHasher::new(ForwardFold);

            // Build an ops MMR with 4 leaves.
            let mut ops_mmr = Mmr::new();
            let batch = {
                let mut batch = ops_mmr.new_batch();
                batch = batch.add(&hasher, &b1);
                batch = batch.add(&hasher, &b2);
                batch = batch.add(&hasher, &b3);
                batch = batch.add(&hasher, &b4);
                batch.merkleize(&ops_mmr, &hasher)
            };

            ops_mmr.apply_batch(&batch).unwrap();

            // Bitmap chunk elements (one per grafted leaf).
            let c1 = Sha256::fill(0xF1);
            let c2 = Sha256::fill(0xF2);

            // With grafting height 1, each grafted leaf covers 2 ops leaves, so 4 ops leaves
            // yield 2 grafted leaves.
            let grafted = build_test_grafted_mmr(&hasher, &ops_mmr, &[c1, c2], GRAFTING_HEIGHT);

            let ops_root = ops_mmr.root(&hasher, 0).unwrap();

            {
                let combined = Storage::new(&grafted, GRAFTING_HEIGHT, &ops_mmr, hasher.clone());
                assert_eq!(combined.size().await, ops_mmr.size());

                // Compute the grafted root by iterating ops peaks.
                let grafted_root = {
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
                    hasher
                        .root(ops_leaves, 0, peaks.iter())
                        .expect("zero inactive peaks is always valid")
                };
                assert_ne!(grafted_root, ops_root);

                // Verify inclusion proofs for each of the 4 ops leaves.
                {
                    let loc = Location::new(0);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1, 0)
                        .await
                        .unwrap();

                    let verifier = Verifier::<mmr::Family, Sha256>::new(
                        GRAFTING_HEIGHT,
                        0,
                        vec![&c1],
                        ALL_CHUNKS_GRAFTABLE,
                        ForwardFold,
                    );
                    assert!(proof.verify_element_inclusion(&verifier, &b1, loc, &grafted_root));

                    let loc = Location::new(1);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1, 0)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(&verifier, &b2, loc, &grafted_root));

                    let loc = Location::new(2);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1, 0)
                        .await
                        .unwrap();
                    let verifier = Verifier::<mmr::Family, Sha256>::new(
                        GRAFTING_HEIGHT,
                        1,
                        vec![&c2],
                        ALL_CHUNKS_GRAFTABLE,
                        ForwardFold,
                    );
                    assert!(proof.verify_element_inclusion(&verifier, &b3, loc, &grafted_root));

                    let loc = Location::new(3);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1, 0)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(&verifier, &b4, loc, &grafted_root));
                }

                // Verify that manipulated inputs cause proof verification to fail.
                {
                    let loc = Location::new(3);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1, 0)
                        .await
                        .unwrap();
                    let verifier = Verifier::<mmr::Family, Sha256>::new(
                        GRAFTING_HEIGHT,
                        1,
                        vec![&c2],
                        ALL_CHUNKS_GRAFTABLE,
                        ForwardFold,
                    );
                    assert!(proof.verify_element_inclusion(&verifier, &b4, loc, &grafted_root));

                    // Wrong leaf element.
                    assert!(!proof.verify_element_inclusion(&verifier, &b3, loc, &grafted_root));

                    // Wrong root.
                    assert!(!proof.verify_element_inclusion(&verifier, &b4, loc, &ops_root));

                    // Wrong position.
                    assert!(!proof.verify_element_inclusion(
                        &verifier,
                        &b4,
                        loc + 1,
                        &grafted_root,
                    ));

                    // Wrong chunk element in the verifier.
                    let verifier = Verifier::<mmr::Family, Sha256>::new(
                        GRAFTING_HEIGHT,
                        0,
                        vec![&c1],
                        ALL_CHUNKS_GRAFTABLE,
                        ForwardFold,
                    );
                    assert!(!proof.verify_element_inclusion(&verifier, &b4, loc, &grafted_root));

                    // Wrong chunk index in the verifier.
                    let verifier = Verifier::<mmr::Family, Sha256>::new(
                        GRAFTING_HEIGHT,
                        2,
                        vec![&c2],
                        ALL_CHUNKS_GRAFTABLE,
                        ForwardFold,
                    );
                    assert!(!proof.verify_element_inclusion(&verifier, &b4, loc, &grafted_root));
                }

                // Verify range proofs.
                {
                    let proof = verification::range_proof(
                        &hasher,
                        &combined,
                        Location::new(0)..Location::new(4),
                        0,
                    )
                    .await
                    .unwrap();
                    let range = vec![&b1, &b2, &b3, &b4];
                    let verifier = Verifier::<mmr::Family, Sha256>::new(
                        GRAFTING_HEIGHT,
                        0,
                        vec![&c1, &c2],
                        ALL_CHUNKS_GRAFTABLE,
                        ForwardFold,
                    );
                    assert!(proof.verify_range_inclusion(
                        &verifier,
                        &range,
                        Location::new(0),
                        &grafted_root,
                    ));

                    // Fails with incomplete chunk elements.
                    let verifier = Verifier::<mmr::Family, Sha256>::new(
                        GRAFTING_HEIGHT,
                        0,
                        vec![&c1],
                        ALL_CHUNKS_GRAFTABLE,
                        ForwardFold,
                    );
                    assert!(!proof.verify_range_inclusion(
                        &verifier,
                        &range,
                        Location::new(0),
                        &grafted_root,
                    ));
                }
            }

            // Add a 5th ops leaf that has no corresponding grafted leaf (it falls below
            // the grafting height boundary since there's no complete chunk for it yet).
            let b5 = Sha256::fill(0x05);
            let batch = {
                let mut batch = ops_mmr.new_batch();
                batch = batch.add(&hasher, &b5);
                batch.merkleize(&ops_mmr, &hasher)
            };

            ops_mmr.apply_batch(&batch).unwrap();

            let combined = Storage::new(&grafted, GRAFTING_HEIGHT, &ops_mmr, hasher.clone());
            assert_eq!(combined.size().await, ops_mmr.size());

            // Compute the grafted root.
            let grafted_root = {
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
                hasher
                    .root(ops_leaves, 0, peaks.iter())
                    .expect("zero inactive peaks is always valid")
            };

            // Verify inclusion proofs still work for both covered and uncovered ops leaves.
            let loc = Location::new(0);
            let proof = merkle::verification::range_proof(&hasher, &combined, loc..loc + 1, 0)
                .await
                .unwrap();

            let verifier = Verifier::<mmr::Family, Sha256>::new(
                GRAFTING_HEIGHT,
                0,
                vec![&c1],
                ALL_CHUNKS_GRAFTABLE,
                ForwardFold,
            );
            assert!(proof.verify_element_inclusion(&verifier, &b1, loc, &grafted_root));

            let verifier = Verifier::<mmr::Family, Sha256>::new(
                GRAFTING_HEIGHT,
                0,
                vec![],
                ALL_CHUNKS_GRAFTABLE,
                ForwardFold,
            );
            let loc = Location::new(4);
            let proof = merkle::verification::range_proof(&hasher, &combined, loc..loc + 1, 0)
                .await
                .unwrap();
            assert!(proof.verify_element_inclusion(&verifier, &b5, loc, &grafted_root));
        });
    }

    #[test_traced]
    fn test_grafted_mmr_basic() {
        let grafting_height = 1u32;
        let standard: StandardHasher<Sha256> = StandardHasher::new(ForwardFold);

        // Build a grafted MMR with 2 leaves.
        let d0 = Sha256::fill(0x01);
        let d1 = Sha256::fill(0x02);
        let grafted_hasher = GraftedHasher::<mmr::Family, _>::new(standard, grafting_height);
        let mut grafted = Mmr::new();
        let batch = grafted
            .new_batch()
            .add_leaf_digest(d0)
            .add_leaf_digest(d1)
            .merkleize(&grafted, &grafted_hasher);
        grafted.apply_batch(&batch).unwrap();

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
        let standard: StandardHasher<Sha256> = StandardHasher::new(ForwardFold);

        // Simulate pruning 4 chunks. The pruned sub-MMR has 4 grafted leaves,
        // mmr_size(4) = 7, with one peak at grafted position 6.
        let pinned_digest = Sha256::fill(0xAA);
        let grafted_pruning_boundary = Location::new(4);
        assert_eq!(*Position::try_from(grafted_pruning_boundary).unwrap(), 7);

        // Build a grafted MMR from pruned components + one new leaf.
        let d4 = Sha256::fill(0xBB);
        let grafted_hasher = GraftedHasher::<mmr::Family, _>::new(standard, grafting_height);
        let mut grafted =
            Mmr::from_components(Vec::new(), grafted_pruning_boundary, vec![pinned_digest])
                .unwrap();
        let batch = grafted
            .new_batch()
            .add_leaf_digest(d4)
            .merkleize(&grafted, &grafted_hasher);
        grafted.apply_batch(&batch).unwrap();

        // The pinned peak should be at grafted position 6.
        assert_eq!(grafted.get_node(Position::new(6)), Some(pinned_digest));

        // The new leaf at chunk 4 (grafted pos 7) should be retrievable.
        let ops_pos_4 = chunk_idx_to_ops_pos(4, grafting_height);
        let gp4 = ops_to_grafted_pos(ops_pos_4, grafting_height);
        assert_eq!(grafted.get_node(gp4), Some(d4));
    }

    /// For every `(leaf_count, chunk_idx)` with `chunk_idx < graftable_chunks(leaf_count, G)`,
    /// the chunk has exactly one h=G peak in the ops MMB. The pending chunk (at index
    /// `graftable_chunks`, if present) is the only chunk that may have multi-peak structure;
    /// its digest is hashed directly into the canonical root rather than being folded into the
    /// grafted root.
    #[test_traced]
    fn test_graftable_chunks_always_single_peak() {
        type F = mmb::Family;
        let grafting_height = 2u32;
        let mut exercised = 0usize;

        for leaf_count in 1..=200u64 {
            let size = F::location_to_position(mmb::Location::new(leaf_count));
            let complete_chunks = leaf_count / (1u64 << grafting_height);
            let graftable_chunks =
                graftable_chunks::<F>(leaf_count, grafting_height).min(complete_chunks);
            for chunk_idx in 0..graftable_chunks {
                let count = F::chunk_peaks(size, chunk_idx, grafting_height).count();
                assert_eq!(
                    count, 1,
                    "graftable chunk {chunk_idx} has {count} peaks (leaf_count={leaf_count}, graftable={graftable_chunks}, complete={complete_chunks})"
                );
                exercised += 1;
            }
        }
        assert!(exercised > 0);
    }

    /// At every MMB size, the chunk index `complete_chunks - 1` (the most recently completed
    /// chunk) is multi-peak iff it is also the pending chunk, i.e. iff
    /// `graftable_chunks < complete_chunks`. Earlier chunks are always single-peak (graftable) and
    /// never appear in a multi-peak state.
    #[test_traced]
    fn test_only_pending_chunk_can_be_multi_peak() {
        type F = mmb::Family;
        let grafting_height = 2u32;
        let mut exercised_pending = 0usize;

        for leaf_count in 1..=200u64 {
            let size = F::location_to_position(mmb::Location::new(leaf_count));
            let complete_chunks = leaf_count / (1u64 << grafting_height);
            let graftable_chunks =
                graftable_chunks::<F>(leaf_count, grafting_height).min(complete_chunks);
            for chunk_idx in 0..complete_chunks {
                let count = F::chunk_peaks(size, chunk_idx, grafting_height).count();
                if chunk_idx < graftable_chunks {
                    assert_eq!(
                        count, 1,
                        "graftable chunk {chunk_idx} has {count} peaks (leaf_count={leaf_count})"
                    );
                } else {
                    // chunk_idx is the pending chunk; multi-peak is allowed (and expected
                    // when this branch is taken, since graftable < complete).
                    assert!(
                        count >= 1,
                        "pending chunk {chunk_idx} has {count} peaks (leaf_count={leaf_count})"
                    );
                    if count > 1 {
                        exercised_pending += 1;
                    }
                }
            }
        }

        assert!(
            exercised_pending > 0,
            "expected to exercise at least one multi-peak pending chunk"
        );
    }
}
