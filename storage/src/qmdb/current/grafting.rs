//! Verifier and storage for grafting bitmap chunks onto an operations tree.
//!
//! ## Overview
//!
//! An operations tree is built over a log of operations, and a bitmap tracks the activity
//! status of each operation. To authenticate both structures efficiently, we combine them: each
//! complete chunk of the bitmap is hashed together with the corresponding subtree root from the ops
//! tree to produce a single "grafted leaf" digest. These digests, along with their ancestor nodes,
//! are stored in an in-memory Merkle structure (using grafted-space positions internally, with ops-space
//! positions in hash pre-images via [GraftedHasher]).
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
//! The grafted tree is incrementally maintained via [GraftedHasher] when grafted leaves
//! change.

use crate::{
    merkle::{
        self, hasher::Hasher as HasherTrait, storage::Storage as StorageTrait, Family, Graftable,
        Location, Position, Readable,
    },
    qmdb::current::witness::GraftedRootWitness,
};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_utils::bitmap::BitMap;
use core::{cmp::Ordering, marker::PhantomData};
use tracing::debug;

/// Get the grafting height for a bitmap with chunk size determined by N.
pub(crate) const fn height<const N: usize>() -> u32 {
    BitMap::<N>::CHUNK_SIZE_BITS.trailing_zeros()
}

/// Folds a sequence of topological peak digests from right to left, intelligently regrouping any
/// small, disjoint MMB operational peaks into their corresponding bitmap chunks before continuing
/// the final fold.
///
/// In a standard Merkle structure, `hasher.root()` would systematically fold the `peaks` directly
/// right-to-left. By introducing a grafting layer, however, any subset of small peaks at the right
/// edge of the database that fall physically under a single `grafting_height` boundary must first
/// be logically grouped and hashed into a single "chunk ops root", and then hashed with their
/// corresponding bitmap chunk activity data.
///
/// `fold_grafted_peaks` intercepts the standard right-to-left peak fold. It buffers any
/// sub-grafting-height peaks directly into a `pending_chunk` accumulator. Once the fold passes the
/// left boundary of that chunk, it "flushes" the accumulator by hashing it with the returned
/// activity bitmap from `get_chunk`. For any trailing ops peaks that do not yet have an active,
/// complete bitmap chunk (e.g., the final `partial_chunk`), `get_chunk` returns `None` and they are
/// securely folded mathematically straight into the root without a bitmap wrap.
///
/// - `start_leaf` is the leftmost leaf covered by the first peak in `peaks` (i.e. the right-most
///   peak).
/// - `initial_acc` contains any peaks that were already folded before `start_leaf`, useful when
///   resuming a fold.
pub(super) fn fold_grafted_peaks<
    F: Family,
    D: Digest,
    H: HasherTrait<F, Digest = D>,
    C: AsRef<[u8]>,
>(
    hasher: &H,
    initial_acc: Option<D>,
    start_leaf: u64,
    peaks: impl IntoIterator<Item = (u32, D)>,
    grafting_height: u32,
    get_chunk: impl Fn(u64) -> Option<C>,
) -> Option<D> {
    let chunk_size = 1u64 << grafting_height;
    let mut acc = initial_acc;
    let mut leaf_cursor = start_leaf;
    let mut pending_chunk: Option<(u64, D, C)> = None;

    let flush = |acc: &mut Option<D>, pending: &mut Option<(u64, D, C)>| {
        if let Some((_, ops_digest, chunk)) = pending.take() {
            let grafted = if !chunk.as_ref().iter().all(|&b| b == 0) {
                hasher.hash([chunk.as_ref(), ops_digest.as_ref()])
            } else {
                ops_digest
            };
            *acc = Some(acc.map_or(grafted, |a| hasher.fold(&a, &grafted)));
        }
    };

    for (peak_height, digest) in peaks {
        let peak_start = leaf_cursor;
        leaf_cursor += 1u64 << peak_height;

        if peak_height >= grafting_height {
            flush(&mut acc, &mut pending_chunk);
            acc = Some(acc.map_or(digest, |a| hasher.fold(&a, &digest)));
            continue;
        }

        let chunk_idx = peak_start / chunk_size;
        match pending_chunk.take() {
            Some((idx, ops_digest, chunk)) if idx == chunk_idx => {
                pending_chunk = Some((idx, hasher.fold(&ops_digest, &digest), chunk));
            }
            old_chunk => {
                pending_chunk = old_chunk;
                flush(&mut acc, &mut pending_chunk);

                if let Some(chunk) = get_chunk(chunk_idx) {
                    pending_chunk = Some((chunk_idx, digest, chunk));
                } else {
                    acc = Some(acc.map_or(digest, |a| hasher.fold(&a, &digest)));
                }
            }
        }
    }

    flush(&mut acc, &mut pending_chunk);

    acc
}

/// Compute the grafted root by folding peak digests with multi-peak chunk grafting.
///
/// For MMR this produces the same result as `hasher.root(leaves, peaks)` because every chunk has a
/// single peak at the grafting height. For MMB, chunks that span multiple sub-grafting-height peaks
/// are folded together and combined with the bitmap chunk.
///
/// This custom folding process is necessary to ensure every bit of activity state from the bitmap
/// is cryptographically incorporated into the root. Because MMB structures can have "incomplete"
/// right edges, a single complete bitmap chunk block might logically cover several smaller,
/// disjoint ops peaks. `grafted_root` intercepts the standard folding process to group these
/// trailing ops peaks together by their chunk index, folds them into a single intermediate digest,
/// and then hashes them alongside their respective bitmap chunk.
///
/// `get_chunk` returns the complete bitmap chunk for a given chunk index, or `None` if the chunk is
/// not graftable (e.g. the partial trailing chunk, or a chunk outside the scope). Any un-graftable
/// partial chunks at the very end of the tree are deliberately bypassed here and folded directly,
/// so they can be securely hashed into the final canonical root in a subsequent step.
pub(super) fn grafted_root<
    F: Graftable,
    D: Digest,
    H: HasherTrait<F, Digest = D>,
    C: AsRef<[u8]>,
>(
    hasher: &H,
    leaves: merkle::Location<F>,
    peak_digests: &[D],
    grafting_height: u32,
    get_chunk: impl Fn(u64) -> Option<C>,
) -> D {
    let size = F::location_to_position(leaves);
    let mut peak_iter = peak_digests.iter();
    let acc = fold_grafted_peaks::<F, D, H, C>(
        hasher,
        None,
        0,
        F::peaks(size).map(|(_peak_pos, peak_height)| {
            let digest = *peak_iter.next().expect("peak count mismatch");
            (peak_height, digest)
        }),
        grafting_height,
        get_chunk,
    );

    // Final root = hash(leaves || acc).
    acc.map_or_else(
        || hasher.digest(&(*leaves).to_be_bytes()),
        |a| hasher.hash([(*leaves).to_be_bytes().as_slice(), a.as_ref()]),
    )
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
pub(super) fn ops_to_grafted_pos<F: Graftable>(
    ops_pos: Position<F>,
    grafting_height: u32,
) -> Position<F> {
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

/// Convert a grafted position back to the corresponding ops-family position.
pub(super) fn grafted_to_ops_pos<F: Graftable>(
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

    _ops_family: PhantomData<F>,
}

impl<'a, F: Graftable, H: CHasher> Verifier<'a, F, H> {
    /// Create a new Verifier.
    ///
    /// `start_chunk_index` is the chunk index corresponding to `chunks[0]`.
    pub(super) const fn new(
        grafting_height: u32,
        start_chunk_index: u64,
        chunks: Vec<&'a [u8]>,
    ) -> Self {
        Self {
            hasher: merkle::hasher::Standard::new(),
            grafting_height,
            chunks,
            start_chunk_index,
            _ops_family: PhantomData,
        }
    }
}

impl<F: Graftable, H: CHasher> HasherTrait<F> for Verifier<'_, F, H> {
    type Digest = H::Digest;

    fn hash<'a>(&self, parts: impl IntoIterator<Item = &'a [u8]>) -> H::Digest {
        self.hasher.hash(parts)
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

/// A virtual storage over the ops tree and grafted tree for canonical root and proof
/// reconstruction.
///
/// Below the grafting height, nodes are read directly from the ops tree. At or above the grafting
/// height, positions are mapped into grafted space. Plain grafted-tree lookup is not sufficient
/// for pruned MMB state, because delayed merges can later query grafted ancestors that were
/// compacted away. This storage fills that gap by reconstructing missing pruned grafted nodes from
/// still-materialized grafted nodes, pinned descendants, and persisted witness digests.
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
    witness: &'a GraftedRootWitness<D>,
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
        witness: &'a GraftedRootWitness<D>,
        hasher: H,
    ) -> Self {
        Self {
            grafted_tree,
            grafting_height,
            ops_tree,
            witness,
            grafted_hasher: GraftedHasher::new(hasher, grafting_height),
            _phantom: PhantomData,
        }
    }

    /// Reconstructs a grafted-space node from the materialized grafted tree plus witness state.
    ///
    /// This first prefers directly stored nodes, then exact witness entries, and finally
    /// recursively hashes child digests when only descendants are retained.
    fn reconstruct_grafted_node(&self, pos: Position<F>) -> Option<D> {
        if let Some(node) = self.grafted_tree.get_node(pos) {
            return Some(node);
        }
        if let Some(node) = self.witness.get(*pos).copied() {
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
        merkle::{
            conformance::{build_test_mem, build_test_mmr},
            mem::Mem,
        },
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
        let mut grafted_mmr = Mmr::new(&grafted_hasher);
        if !chunks.is_empty() {
            // Use a separate hasher for leaf digest computation to avoid borrow conflict
            // with grafted_hasher (which borrows standard via fork()).
            let leaf_hasher = StandardHasher::<Sha256>::new();
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

    /// Generic version of `build_test_grafted_mmr` that derives each grafted leaf from
    /// `F::chunk_peaks(...)` rather than assuming one ops node per chunk.
    fn build_test_grafted_tree_for_family<F: Graftable>(
        standard: &StandardHasher<Sha256>,
        ops: &Mem<F, sha256::Digest>,
        chunks: &[sha256::Digest],
        grafting_height: u32,
    ) -> Mem<F, sha256::Digest> {
        let grafted_hasher = GraftedHasher::<F, _>::new(standard.clone(), grafting_height);
        let mut grafted_tree = Mem::<F, _>::new(&grafted_hasher);

        if !chunks.is_empty() {
            let ops_size = ops.size();
            let leaf_hasher = StandardHasher::<Sha256>::new();
            let merkleized = {
                let mut batch = grafted_tree.new_batch();
                for (chunk_idx, chunk) in chunks.iter().enumerate() {
                    let mut chunk_ops_digest: Option<sha256::Digest> = None;
                    for (pos, _) in F::chunk_peaks(ops_size, chunk_idx as u64, grafting_height) {
                        let digest = ops.get_node(pos).expect("ops structure missing cover peak");
                        chunk_ops_digest = Some(chunk_ops_digest.map_or(digest, |acc| {
                            leaf_hasher.hash([acc.as_ref(), digest.as_ref()])
                        }));
                    }

                    let chunk_ops_digest =
                        chunk_ops_digest.expect("chunk must have at least one covering peak");
                    let leaf_digest = if chunk.as_ref().iter().all(|&b| b == 0) {
                        chunk_ops_digest
                    } else {
                        leaf_hasher.hash([chunk.as_ref(), chunk_ops_digest.as_ref()])
                    };
                    batch = batch.add_leaf_digest(leaf_digest);
                }
                batch.merkleize(&grafted_tree, &grafted_hasher)
            };
            grafted_tree.apply_batch(&merkleized).unwrap();
        }

        grafted_tree
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

            let standard: StandardHasher<Sha256> = StandardHasher::new();
            let mmr = Mmr::new(&standard);
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
        let standard: StandardHasher<Sha256> = StandardHasher::new();
        let grafting_height = 1u32;

        // Build ops MMR with 4 leaves.
        let mut ops_mmr = Mmr::new(&standard);
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
        let mut grafted = Mmr::new(&grafted_hasher);
        let pos0 = chunk_idx_to_ops_pos(0, grafting_height);
        let pos1 = chunk_idx_to_ops_pos(1, grafting_height);

        let batch = {
            let leaf_hasher = StandardHasher::<Sha256>::new();
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
            let hasher: StandardHasher<Sha256> = StandardHasher::new();

            // Build an ops MMR with 4 leaves.
            let mut ops_mmr = Mmr::new(&hasher);
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

            let ops_root = *ops_mmr.root();

            {
                let empty_witness = GraftedRootWitness::default();
                let combined = Storage::new(
                    &grafted,
                    GRAFTING_HEIGHT,
                    &ops_mmr,
                    &empty_witness,
                    hasher.clone(),
                );
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
                    hasher.root(ops_leaves, peaks.iter())
                };
                assert_ne!(grafted_root, ops_root);

                // Verify inclusion proofs for each of the 4 ops leaves.
                {
                    let loc = Location::new(0);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1)
                        .await
                        .unwrap();

                    let verifier =
                        Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
                    assert!(proof.verify_element_inclusion(&verifier, &b1, loc, &grafted_root));

                    let loc = Location::new(1);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(&verifier, &b2, loc, &grafted_root));

                    let loc = Location::new(2);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1)
                        .await
                        .unwrap();
                    let verifier =
                        Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 1, vec![&c2]);
                    assert!(proof.verify_element_inclusion(&verifier, &b3, loc, &grafted_root));

                    let loc = Location::new(3);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1)
                        .await
                        .unwrap();
                    assert!(proof.verify_element_inclusion(&verifier, &b4, loc, &grafted_root));
                }

                // Verify that manipulated inputs cause proof verification to fail.
                {
                    let loc = Location::new(3);
                    let proof = verification::range_proof(&hasher, &combined, loc..loc + 1)
                        .await
                        .unwrap();
                    let verifier =
                        Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 1, vec![&c2]);
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
                        &grafted_root
                    ));

                    // Wrong chunk element in the verifier.
                    let verifier =
                        Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
                    assert!(!proof.verify_element_inclusion(&verifier, &b4, loc, &grafted_root));

                    // Wrong chunk index in the verifier.
                    let verifier =
                        Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 2, vec![&c2]);
                    assert!(!proof.verify_element_inclusion(&verifier, &b4, loc, &grafted_root));
                }

                // Verify range proofs.
                {
                    let proof = verification::range_proof(
                        &hasher,
                        &combined,
                        Location::new(0)..Location::new(4),
                    )
                    .await
                    .unwrap();
                    let range = vec![&b1, &b2, &b3, &b4];
                    let verifier =
                        Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1, &c2]);
                    assert!(proof.verify_range_inclusion(
                        &verifier,
                        &range,
                        Location::new(0),
                        &grafted_root
                    ));

                    // Fails with incomplete chunk elements.
                    let verifier =
                        Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
                    assert!(!proof.verify_range_inclusion(
                        &verifier,
                        &range,
                        Location::new(0),
                        &grafted_root
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

            let empty_witness = GraftedRootWitness::default();
            let combined = Storage::new(
                &grafted,
                GRAFTING_HEIGHT,
                &ops_mmr,
                &empty_witness,
                hasher.clone(),
            );
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
                hasher.root(ops_leaves, peaks.iter())
            };

            // Verify inclusion proofs still work for both covered and uncovered ops leaves.
            let loc = Location::new(0);
            let proof = merkle::verification::range_proof(&hasher, &combined, loc..loc + 1)
                .await
                .unwrap();

            let verifier = Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 0, vec![&c1]);
            assert!(proof.verify_element_inclusion(&verifier, &b1, loc, &grafted_root));

            let verifier = Verifier::<mmr::Family, Sha256>::new(GRAFTING_HEIGHT, 0, vec![]);
            let loc = Location::new(4);
            let proof = merkle::verification::range_proof(&hasher, &combined, loc..loc + 1)
                .await
                .unwrap();
            assert!(proof.verify_element_inclusion(&verifier, &b5, loc, &grafted_root));
        });
    }

    #[test_traced]
    fn test_grafted_mmr_basic() {
        let grafting_height = 1u32;
        let standard: StandardHasher<Sha256> = StandardHasher::new();

        // Build a grafted MMR with 2 leaves.
        let d0 = Sha256::fill(0x01);
        let d1 = Sha256::fill(0x02);
        let grafted_hasher = GraftedHasher::<mmr::Family, _>::new(standard, grafting_height);
        let mut grafted = Mmr::new(&grafted_hasher);
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
        let standard: StandardHasher<Sha256> = StandardHasher::new();

        // Simulate pruning 4 chunks. The pruned sub-MMR has 4 grafted leaves,
        // mmr_size(4) = 7, with one peak at grafted position 6.
        let pinned_digest = Sha256::fill(0xAA);
        let grafted_pruning_boundary = Location::new(4);
        assert_eq!(*Position::try_from(grafted_pruning_boundary).unwrap(), 7);

        // Build a grafted MMR from pruned components + one new leaf.
        let d4 = Sha256::fill(0xBB);
        let grafted_hasher = GraftedHasher::<mmr::Family, _>::new(standard, grafting_height);
        let mut grafted = Mmr::from_components(
            &grafted_hasher,
            Vec::new(),
            grafted_pruning_boundary,
            vec![pinned_digest],
        )
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

    #[test_traced]
    fn test_grafted_root_mmb_regroups_multi_peak_chunks_across_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            type F = mmb::Family;

            let hasher: StandardHasher<Sha256> = StandardHasher::new();
            let grafting_height = 2u32;
            let mut exercised = 0usize;

            for leaf_count in 1..=20u64 {
                let size = F::location_to_position(mmb::Location::new(leaf_count));
                let complete_chunks = (leaf_count / (1u64 << grafting_height)) as usize;
                let has_multi_peak_chunk = (0..complete_chunks as u64)
                    .any(|chunk_idx| F::chunk_peaks(size, chunk_idx, grafting_height).count() > 1);

                if !has_multi_peak_chunk {
                    continue;
                }

                exercised += 1;
                let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(&hasher), leaf_count);
                let chunks: Vec<_> = (0..complete_chunks)
                    .map(|i| Sha256::fill(0xA0 + i as u8))
                    .collect();
                let grafted = build_test_grafted_tree_for_family::<F>(
                    &hasher,
                    &ops,
                    &chunks,
                    grafting_height,
                );
                let empty_witness = GraftedRootWitness::default();
                let combined = Storage::new(
                    &grafted,
                    grafting_height,
                    &ops,
                    &empty_witness,
                    hasher.clone(),
                );

                let leaves = merkle::Location::<F>::try_from(size).unwrap();
                let mut peaks = Vec::new();
                for (pos, _) in F::peaks(size) {
                    peaks.push(combined.get_node(pos).await.unwrap().unwrap());
                }

                let grafted_root = grafted_root::<F, _, _, _>(
                    &hasher,
                    leaves,
                    &peaks,
                    grafting_height,
                    |chunk_idx| chunks.get(chunk_idx as usize).copied(),
                );

                // A naive peak fold does not regroup sub-grafting-height peaks within a chunk.
                let naive_root = hasher.root(leaves, peaks.iter());
                assert_ne!(
                    grafted_root, naive_root,
                    "expected multi-peak regrouping to matter for leaf_count={leaf_count}"
                );
            }

            assert!(
                exercised > 0,
                "expected to find at least one multi-peak MMB chunk"
            );
        });
    }

    #[test_traced]
    fn test_grafted_leaf_digests_mmb_for_multi_peak_chunks() {
        type F = mmb::Family;

        let hasher: StandardHasher<Sha256> = StandardHasher::new();
        let grafting_height = 2u32;
        let mut exercised = 0usize;

        for leaf_count in 1..=20u64 {
            let size = F::location_to_position(mmb::Location::new(leaf_count));
            let complete_chunks = (leaf_count / (1u64 << grafting_height)) as usize;
            if complete_chunks == 0 {
                continue;
            }

            let ops = build_test_mem(&hasher, mmb::mem::Mmb::new(&hasher), leaf_count);
            let chunks: Vec<_> = (0..complete_chunks)
                .map(|i| Sha256::fill(0xC0 + i as u8))
                .collect();
            let grafted =
                build_test_grafted_tree_for_family::<F>(&hasher, &ops, &chunks, grafting_height);

            for (chunk_idx, chunk) in chunks.iter().enumerate() {
                let cover: Vec<_> =
                    F::chunk_peaks(size, chunk_idx as u64, grafting_height).collect();
                if cover.len() <= 1 {
                    continue;
                }
                exercised += 1;

                let mut iter = cover.iter();
                let &(first_pos, _) = iter.next().unwrap();
                let mut chunk_ops_digest = ops
                    .get_node(first_pos)
                    .expect("ops structure missing cover peak");
                for &(pos, _) in iter {
                    let digest = ops.get_node(pos).expect("ops structure missing cover peak");
                    chunk_ops_digest = hasher.hash([chunk_ops_digest.as_ref(), digest.as_ref()]);
                }

                let expected = hasher.hash([chunk.as_ref(), chunk_ops_digest.as_ref()]);
                let grafted_pos =
                    merkle::Position::<F>::try_from(merkle::Location::<F>::new(chunk_idx as u64))
                        .unwrap();
                let actual = grafted
                    .get_node(grafted_pos)
                    .expect("grafted structure missing chunk leaf");

                assert_eq!(
                    actual, expected,
                    "unexpected grafted leaf digest for leaf_count={leaf_count}, chunk_idx={chunk_idx}"
                );
            }
        }

        assert!(
            exercised > 0,
            "expected to exercise at least one multi-peak MMB chunk"
        );
    }
}
