//! Verifier and Storage for _grafting_ bitmap chunks onto an operations MMR.
//!
//! ## Overview
//!
//! An MMR (the "ops MMR") is built over a log of operations, and a bitmap tracks the activity
//! status of each operation. To authenticate both structures efficiently, we combine them: each
//! complete chunk of the bitmap is hashed together with the corresponding subtree root from the ops
//! MMR to produce a single "grafted leaf" digest. These digests, along with their ancestor nodes,
//! are cached in a `BTreeMap<Position, D>` keyed by **ops MMR positions**.
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
//! The `propagate_dirty` function incrementally maintains the cache above the grafting height when
//! grafted leaves change.

use crate::mmr::{
    hasher::Hasher as HasherTrait, iterator::pos_to_height, storage::Storage as StorageTrait,
    Error, Location, Position, StandardHasher,
};
use alloc::collections::{BTreeMap, BTreeSet};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_parallel::ThreadPool;
use commonware_utils::bitmap::BitMap;
use core::cmp::Ordering;
use rayon::prelude::*;
use tracing::debug;

/// Minimum number of items before switching from serial to parallel computation.
pub(super) const MIN_TO_PARALLELIZE: usize = 20;

/// Get the grafting height for a bitmap with chunk size determined by N.
pub(crate) const fn height<const N: usize>() -> u32 {
    BitMap::<N>::CHUNK_SIZE_BITS.trailing_zeros()
}

/// Given a chunk index and grafting height, returns the ops MMR position of the subtree root
/// covering that chunk's leaves.
///
/// Maps a chunk index (equivalent to a grafted leaf location) to its ops-space position.
pub(super) fn chunk_idx_to_ops_pos(chunk_idx: u64, grafting_height: u32) -> Position {
    let first_leaf_loc = Location::new_unchecked(chunk_idx << grafting_height);
    let first_leaf_pos = Position::try_from(first_leaf_loc).expect("chunk_idx_to_ops_pos overflow");
    // The subtree root covering 2^h leaves starting at first_leaf_pos is at:
    //   first_leaf_pos + 2^(h+1) - 2
    Position::new(*first_leaf_pos + (1u64 << (grafting_height + 1)) - 2)
}

/// Given an ops MMR position at the grafting height, returns the corresponding chunk index.
///
/// This is the inverse of [chunk_idx_to_ops_pos].
pub(super) fn ops_pos_to_chunk_idx(ops_pos: Position, grafting_height: u32) -> u64 {
    // The leftmost leaf position under the subtree rooted at ops_pos:
    //   ops_pos + 2 - 2^(h+1)
    // (reordered to avoid intermediate underflow)
    let leftmost_leaf_pos = *ops_pos + 2 - (1u64 << (grafting_height + 1));
    let loc = Location::try_from(Position::new(leftmost_leaf_pos))
        .expect("ops_pos_to_chunk_idx: position is not a leaf");
    *loc >> grafting_height
}

/// Propagate dirty grafted leaf positions upward through the cache, recomputing ancestor digests.
///
/// Given a set of ops positions at the grafting height whose digests have just been
/// inserted/updated in `grafted_digests`, this function walks each one up to its containing peak,
/// collects all ancestor positions that need recomputation, deduplicates them, and recomputes
/// bottom-up.
///
/// Uses **ops-space positions** in `node_digest` hash pre-images.
pub(super) fn propagate_dirty<H: CHasher>(
    grafted_digests: &mut BTreeMap<Position, H::Digest>,
    hasher: &mut StandardHasher<H>,
    dirty_positions: &[Position],
    ops_mmr_size: Position,
    pool: Option<&ThreadPool>,
) {
    // Collect all ancestor positions that need recomputation, keyed by (height, position) so
    // BTreeSet sorts by height first (bottom-up processing order).
    let mut to_recompute: BTreeSet<(u32, Position)> = BTreeSet::new();

    for &pos in dirty_positions {
        let mut current = pos;
        let mut height = pos_to_height(current);

        loop {
            // Determine parent position.
            let parent = if pos_to_height(Position::new(*current + 1)) == height + 1 {
                // current is a right child
                Position::new(*current + 1)
            } else {
                // current is a left child
                Position::new(*current + (1u64 << (height + 1)))
            };

            // Stop if the parent is outside the MMR (current is a peak).
            if parent >= ops_mmr_size {
                break;
            }

            to_recompute.insert((height + 1, parent));
            current = parent;
            height += 1;
        }
    }

    match pool {
        Some(pool) => propagate_dirty_parallel(grafted_digests, hasher, &to_recompute, pool),
        None => {
            // Serial path: process bottom-up directly (BTreeSet iterates in ascending order).
            for &(height, pos) in &to_recompute {
                let left = Position::new(*pos - (1u64 << height));
                let right = Position::new(*pos - 1);
                let left_digest = grafted_digests[&left];
                let right_digest = grafted_digests[&right];
                let digest = hasher.node_digest(pos, &left_digest, &right_digest);
                grafted_digests.insert(pos, digest);
            }
        }
    }
}

/// Parallel path for [`propagate_dirty`]: groups nodes by height level and parallelizes
/// within each level using rayon. Falls back to serial for levels with fewer than
/// [`MIN_TO_PARALLELIZE`] nodes.
fn propagate_dirty_parallel<H: CHasher>(
    grafted_digests: &mut BTreeMap<Position, H::Digest>,
    hasher: &mut StandardHasher<H>,
    to_recompute: &BTreeSet<(u32, Position)>,
    pool: &ThreadPool,
) {
    let mut level_positions: Vec<Position> = Vec::new();
    let mut current_height: Option<u32> = None;

    for &(height, pos) in to_recompute {
        if current_height != Some(height) {
            if !level_positions.is_empty() {
                process_level(
                    grafted_digests,
                    hasher,
                    pool,
                    &level_positions,
                    current_height.unwrap(),
                );
            }
            level_positions.clear();
            current_height = Some(height);
        }
        level_positions.push(pos);
    }
    if !level_positions.is_empty() {
        process_level(
            grafted_digests,
            hasher,
            pool,
            &level_positions,
            current_height.unwrap(),
        );
    }
}

/// Recompute node digests at a single height level, parallelizing if there are enough nodes.
fn process_level<H: CHasher>(
    grafted_digests: &mut BTreeMap<Position, H::Digest>,
    hasher: &mut StandardHasher<H>,
    pool: &ThreadPool,
    positions: &[Position],
    height: u32,
) {
    let shift = 1u64 << height;

    if positions.len() >= MIN_TO_PARALLELIZE {
        let computed: Vec<(Position, H::Digest)> = pool.install(|| {
            positions
                .par_iter()
                .map_init(
                    || hasher.fork(),
                    |h, &pos| {
                        let left = Position::new(*pos - shift);
                        let right = Position::new(*pos - 1);
                        let left_digest = grafted_digests[&left];
                        let right_digest = grafted_digests[&right];
                        let digest = h.node_digest(pos, &left_digest, &right_digest);
                        (pos, digest)
                    },
                )
                .collect()
        });
        for (pos, digest) in computed {
            grafted_digests.insert(pos, digest);
        }
    } else {
        for &pos in positions {
            let left = Position::new(*pos - shift);
            let right = Position::new(*pos - 1);
            let left_digest = grafted_digests[&left];
            let right_digest = grafted_digests[&right];
            let digest = hasher.node_digest(pos, &left_digest, &right_digest);
            grafted_digests.insert(pos, digest);
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

                // Map ops position -> chunk index -> local index into self.chunks.
                let chunk_idx = ops_pos_to_chunk_idx(pos, self.grafting_height);
                let Some(local) = chunk_idx.checked_sub(self.start_chunk_index) else {
                    debug!(?pos, "could not resolve chunk for grafted leaf");
                    return ops_subtree_root;
                };
                if local >= self.chunks.len() as u64 {
                    debug!(?pos, "chunk index out of range for grafted leaf");
                    return ops_subtree_root;
                }

                // grafted_leaf = hash(chunk || ops_subtree_root)
                self.hasher.inner().update(self.chunks[local as usize]);
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

/// A virtual [StorageTrait] that presents a grafted digest cache and ops MMR as a single combined
/// MMR.
///
/// Nodes below the grafting height are served from the ops MMR. Nodes at or above the grafting
/// height are served from the grafted digests cache. This allows standard MMR proof generation to
/// work transparently over the combined structure.
pub(super) struct Storage<'a, D: Digest, S: StorageTrait<D>> {
    grafted_digests: &'a BTreeMap<Position, D>,
    ops_mmr: &'a S,
    grafting_height: u32,
}

impl<'a, D: Digest, S: StorageTrait<D>> Storage<'a, D, S> {
    /// Creates a new [Storage] instance.
    pub(super) const fn new(
        grafted_digests: &'a BTreeMap<Position, D>,
        ops_mmr: &'a S,
        grafting_height: u32,
    ) -> Self {
        Self {
            grafted_digests,
            ops_mmr,
            grafting_height,
        }
    }
}

impl<D: Digest, S: StorageTrait<D>> StorageTrait<D> for Storage<'_, D, S> {
    fn size(&self) -> Position {
        self.ops_mmr.size()
    }

    async fn get_node(&self, pos: Position) -> Result<Option<D>, Error> {
        if pos_to_height(pos) < self.grafting_height {
            return self.ops_mmr.get_node(pos).await;
        }
        Ok(self.grafted_digests.get(&pos).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        conformance::build_test_mmr,
        mem::{CleanMmr, DirtyMmr},
        verification, Position, StandardHasher,
    };
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner};

    /// Precompute grafted leaf digests and return a `BTreeMap` of grafted digests (including
    /// internal nodes above the grafting height).
    ///
    /// Each grafted leaf is `hash(chunk || ops_subtree_root)` where `ops_subtree_root` is the ops
    /// MMR node at the mapped position. This matches the production pattern in
    /// [super::super::db::compute_grafted_leaf_for_chunk].
    fn precompute_grafted_digests(
        standard: &mut StandardHasher<Sha256>,
        ops_mmr: &CleanMmr<sha256::Digest>,
        chunks: &[sha256::Digest],
        grafting_height: u32,
    ) -> BTreeMap<Position, sha256::Digest> {
        let mut map = BTreeMap::new();
        let mut dirty_positions = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            let ops_pos = chunk_idx_to_ops_pos(i as u64, grafting_height);
            let ops_subtree_root = ops_mmr
                .get_node(ops_pos)
                .expect("ops MMR missing node at mapped position");

            // grafted_leaf = hash(chunk || ops_subtree_root)
            standard.inner().update(chunk);
            standard.inner().update(&ops_subtree_root);
            let digest = standard.inner().finalize();
            map.insert(ops_pos, digest);
            dirty_positions.push(ops_pos);
        }
        propagate_dirty(&mut map, standard, &dirty_positions, ops_mmr.size(), None);
        map
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

                let grafted = precompute_grafted_digests(&mut standard, &ops_mmr, &elements, 0);
                assert!(!grafted.is_empty());
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

                let grafted = precompute_grafted_digests(&mut standard, &ops_mmr, &elements, 1);
                assert!(!grafted.is_empty());
            }

            // Height 2 and 3 checks.
            assert_eq!(chunk_idx_to_ops_pos(0, 2), Position::new(6));
            assert_eq!(chunk_idx_to_ops_pos(1, 2), Position::new(13));
            assert_eq!(chunk_idx_to_ops_pos(0, 3), Position::new(14));
        });
    }

    #[test_traced]
    fn test_propagate_dirty() {
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

        // Insert two grafted leaves manually.
        let mut map = BTreeMap::new();
        let pos0 = chunk_idx_to_ops_pos(0, grafting_height);
        let pos1 = chunk_idx_to_ops_pos(1, grafting_height);

        let sub0 = ops_mmr.get_node(pos0).unwrap();
        standard.inner().update(&c1);
        standard.inner().update(&sub0);
        map.insert(pos0, standard.inner().finalize());

        let sub1 = ops_mmr.get_node(pos1).unwrap();
        standard.inner().update(&c2);
        standard.inner().update(&sub1);
        map.insert(pos1, standard.inner().finalize());

        // Propagate should add the parent node (at height grafting_height + 1).
        propagate_dirty(&mut map, &mut standard, &[pos0, pos1], ops_mmr.size(), None);

        // With 4 ops leaves and grafting height 1, the grafted tree has 2 leaves and 1 root.
        // The root position in ops space is at height 2.
        assert_eq!(map.len(), 3); // 2 leaves + 1 internal
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
                precompute_grafted_digests(&mut standard, &ops_mmr, &[c1, c2], GRAFTING_HEIGHT);

            let ops_root = *ops_mmr.root();

            {
                let combined = Storage::new(&grafted, &ops_mmr, GRAFTING_HEIGHT);
                assert_eq!(combined.size(), ops_mmr.size());

                // Compute the combined root by iterating ops peaks.
                let combined_root = {
                    use crate::mmr::iterator::PeakIterator;
                    let ops_size = ops_mmr.size();
                    let ops_leaves = Location::try_from(ops_size).unwrap();
                    let mut peaks = Vec::new();
                    for (peak_pos, peak_height) in PeakIterator::new(ops_size) {
                        if peak_height >= GRAFTING_HEIGHT {
                            peaks.push(*grafted.get(&peak_pos).unwrap());
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
            let mut ops_mmr = ops_mmr.into_dirty();
            ops_mmr.add(&mut standard, &b5);
            let ops_mmr = ops_mmr.merkleize(&mut standard, None);

            let combined = Storage::new(&grafted, &ops_mmr, GRAFTING_HEIGHT);
            assert_eq!(combined.size(), ops_mmr.size());

            // Compute the combined root.
            let combined_root = {
                use crate::mmr::iterator::PeakIterator;
                let ops_size = ops_mmr.size();
                let ops_leaves = Location::try_from(ops_size).unwrap();
                let mut peaks = Vec::new();
                for (peak_pos, peak_height) in PeakIterator::new(ops_size) {
                    if peak_height >= GRAFTING_HEIGHT {
                        peaks.push(*grafted.get(&peak_pos).unwrap());
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
}
