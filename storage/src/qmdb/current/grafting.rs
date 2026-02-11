//! Verifier and Storage for _grafting_ bitmap chunks onto an operations MMR.
//!
//! ## Overview
//!
//! An MMR (the "ops MMR") is built over a log of operations, and a bitmap tracks the activity
//! status of each operation. To authenticate both structures efficiently, we combine them: each
//! complete chunk of the bitmap is hashed together with the corresponding subtree root from the ops
//! MMR to produce a single "grafted leaf" digest. These digests, along with their ancestor nodes,
//! are cached in a [Digests] keyed by **ops MMR positions**.
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
use alloc::collections::BTreeSet;
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

/// Returns the number of nodes in an MMR with the given number of leaves.
pub(super) const fn mmr_size(leaves: u64) -> u64 {
    2 * leaves - leaves.count_ones() as u64
}

/// Convert an ops-space position (at or above the grafting height) to its grafted-space position.
///
/// Related: [ops_pos_to_chunk_idx] converts an ops position at the grafting height to a chunk
/// index (a sequential integer for array indexing). This function returns a grafted MMR position
/// (for navigating the MMR structure) and works at any height at or above the grafting height.
///
/// # Panics
///
/// Panics if `ops_pos` is below the grafting height.
pub(super) fn ops_to_grafted_pos(ops_pos: Position, grafting_height: u32) -> u64 {
    let oh = pos_to_height(ops_pos);
    assert!(
        oh >= grafting_height,
        "ops_to_grafted_pos: position height {oh} < grafting height {grafting_height}"
    );
    let gh = oh - grafting_height;

    // Find the leftmost ops-space leaf under this subtree.
    let leftmost_ops_leaf_pos = *ops_pos + 2 - (1u64 << (oh + 1));
    let ops_leaf_loc = Location::try_from(Position::new(leftmost_ops_leaf_pos))
        .expect("ops_to_grafted_pos: leftmost leaf is not a valid leaf position");

    // Convert ops leaf location to chunk index (grafted leaf location).
    let chunk_idx = *ops_leaf_loc >> grafting_height;

    // Convert chunk index to grafted-space leaf position, then climb to grafted height gh.
    let grafted_leaf_pos = Position::try_from(Location::new_unchecked(chunk_idx))
        .expect("ops_to_grafted_pos overflow");
    *grafted_leaf_pos + (1u64 << (gh + 1)) - 2
}

/// Convert a grafted-space position to its ops-space position.
///
/// Inverse of [ops_to_grafted_pos]. Maps a position in the grafted MMR (whose leaves are
/// bitmap chunks) back to the corresponding ops MMR position.
#[cfg(test)]
pub(super) fn grafted_to_ops_pos(grafted_pos: u64, grafting_height: u32) -> Position {
    let gh = pos_to_height(Position::new(grafted_pos));

    // Find the leftmost grafted-space leaf under this subtree.
    let leftmost_grafted_leaf_pos = grafted_pos + 2 - (1u64 << (gh + 1));
    let chunk_idx = *Location::try_from(Position::new(leftmost_grafted_leaf_pos))
        .expect("grafted_to_ops_pos: leftmost leaf is not a valid leaf position");

    // Convert chunk index to ops-space leaf location.
    let ops_leaf_loc = chunk_idx << grafting_height;
    let ops_leaf_pos = Position::try_from(Location::new_unchecked(ops_leaf_loc))
        .expect("grafted_to_ops_pos overflow");

    // Climb from the ops leaf to the ops height (gh + grafting_height).
    let oh = gh + grafting_height;
    Position::new(*ops_leaf_pos + (1u64 << (oh + 1)) - 2)
}

/// Stores grafted MMR digests.
/// Invariant: after construction (i.e. after [Self::update_leaves]), every slot in `nodes`
/// holds a valid digest. Internally, [Self::update_leaves] fills slots in two phases: first
/// grafted leaves (which occupy non-contiguous positions in the MMR), then internal nodes
/// (filled by [propagate_dirty]). Between phases, unfilled slots contain [Digest::EMPTY],
/// but no reads occur until construction is complete.
pub(super) struct Digests<D: Digest> {
    /// (Position, Digest) for each pruned peak.
    /// Ordered by [crate::mmr::iterator::PeakIterator] order (decreasing height).
    pinned: Vec<(u64, D)>,

    /// Unpruned grafted MMR digests, indexed by grafted-space position minus `offset`.
    /// Pre-sized via [Self::resize_for_chunks] to hold all positions in the unpruned region.
    nodes: Vec<D>,

    /// Grafted-space position of `nodes[0]`. Equals `mmr_size(pruned_chunks)`.
    /// 0 when nothing has been pruned.
    offset: u64,

    /// Height of grafted MMR leaves.
    grafting_height: u32,
}

impl<D: Digest> Digests<D> {
    /// Returns a new empty [Digests].
    pub(super) const fn new(grafting_height: u32) -> Self {
        Self {
            pinned: Vec::new(),
            nodes: Vec::new(),
            offset: 0,
            grafting_height,
        }
    }

    /// Creates a new [Digests] from pinned peaks.
    ///
    /// `pinned_peaks` are peak digests in [crate::mmr::iterator::PeakIterator]
    /// order (decreasing height).
    /// `pruned_chunks` is the number of chunks that have been pruned.
    pub(super) fn from_pinned(
        pinned_peaks: &[D],
        pruned_chunks: usize,
        grafting_height: u32,
    ) -> Self {
        let offset = mmr_size(pruned_chunks as u64);

        // Pair each pinned peak with its grafted-space position.
        let pruned_ops_leaves = pruned_chunks as u64 * (1u64 << grafting_height);
        let ops_mmr_size = Position::try_from(Location::new_unchecked(pruned_ops_leaves))
            .expect("pruned_ops_leaves overflow");
        let pinned: Vec<(u64, D)> = pinned_peaks
            .iter()
            .zip(crate::mmr::iterator::PeakIterator::new(ops_mmr_size))
            .map(|(digest, (ops_pos, _))| {
                let gp = ops_to_grafted_pos(ops_pos, grafting_height);
                (gp, *digest)
            })
            .collect();

        Self {
            pinned,
            nodes: Vec::new(),
            offset,
            grafting_height,
        }
    }

    /// Pre-size `self.nodes` to hold all grafted positions for `complete_chunks` total chunks.
    ///
    /// New slots are initialized to [Digest::EMPTY] and will be overwritten by leaf insertion
    /// and [propagate_dirty] before any reads occur.
    fn resize_for_chunks(&mut self, complete_chunks: u64) {
        let target_len = (mmr_size(complete_chunks) - self.offset) as usize;
        if target_len > self.nodes.len() {
            self.nodes.resize(target_len, D::EMPTY);
        }
    }

    /// The grafting height.
    pub(super) const fn grafting_height(&self) -> u32 {
        self.grafting_height
    }

    /// Look up a digest by ops-space (not grafted-space) position.
    pub(super) fn get(&self, pos: Position) -> Option<D> {
        let gp = ops_to_grafted_pos(pos, self.grafting_height);
        self.get_grafted(gp)
    }

    /// Insert a digest at an ops-space (not grafted-space) position.
    pub(super) fn insert(&mut self, pos: Position, digest: D) {
        let gp = ops_to_grafted_pos(pos, self.grafting_height);
        self.insert_grafted(gp, digest);
    }

    /// Look up a digest by grafted-space position.
    fn get_grafted(&self, pos: u64) -> Option<D> {
        if pos < self.offset {
            // Look in pinned peaks (linear scan over O(log P) entries).
            return self.pinned.iter().find(|(p, _)| *p == pos).map(|(_, d)| *d);
        }
        let idx = (pos - self.offset) as usize;
        self.nodes.get(idx).copied()
    }

    /// Write a digest at a grafted-space position.
    ///
    /// # Panics
    ///
    /// Panics if `pos` is beyond the pre-sized region (see [Self::update_leaves]).
    fn insert_grafted(&mut self, pos: u64, digest: D) {
        if pos < self.offset {
            // Update an existing pinned peak. During normal operation, inserts only target the
            // unpruned region (>= offset); this branch handles the edge case where a peak digest
            // is refreshed.
            let entry = self
                .pinned
                .iter_mut()
                .find(|(p, _)| *p == pos)
                .unwrap_or_else(|| {
                    panic!(
                        "insert_grafted: no pinned entry at grafted pos {pos} (offset {})",
                        self.offset
                    )
                });
            entry.1 = digest;
            return;
        }
        let idx = (pos - self.offset) as usize;
        self.nodes[idx] = digest;
    }
}

impl<D: Digest> Digests<D> {
    /// Insert grafted leaf digests and propagate ancestor nodes upward.
    ///
    /// `leaves` are `(ops_pos, digest)` pairs at the grafting height. The dense Vec is
    /// automatically resized to accommodate the current ops MMR size before insertion.
    /// After inserting all leaves, ancestor nodes are recomputed bottom-up so the cache
    /// stays consistent.
    pub(super) fn update_leaves<H: CHasher<Digest = D>>(
        &mut self,
        leaves: &[(Position, D)],
        hasher: &mut StandardHasher<H>,
        ops_mmr_size: Position,
        pool: Option<&ThreadPool>,
    ) {
        // Derive the number of complete grafted leaves from the ops MMR size.
        let ops_leaves = Location::try_from(ops_mmr_size).expect("ops_mmr_size overflow");
        let complete_chunks = *ops_leaves >> self.grafting_height;
        self.resize_for_chunks(complete_chunks);

        let dirty_positions: Vec<Position> = leaves
            .iter()
            .map(|&(pos, digest)| {
                self.insert(pos, digest);
                pos
            })
            .collect();
        propagate_dirty(self, hasher, &dirty_positions, ops_mmr_size, pool);
    }
}

/// Recompute a single internal node's digest from its children.
///
/// `pos` is the node's ops-space position and `height` is its height (above the grafting height).
/// The children are at `pos - (1 << height)` (left) and `pos - 1` (right).
fn recompute_node<H: HasherTrait>(
    grafted_digests: &Digests<H::Digest>,
    hasher: &mut H,
    pos: Position,
    height: u32,
) -> H::Digest {
    let left = Position::new(*pos - (1u64 << height));
    let right = Position::new(*pos - 1);
    let left_digest = grafted_digests.get(left).expect("missing left child");
    let right_digest = grafted_digests.get(right).expect("missing right child");
    hasher.node_digest(pos, &left_digest, &right_digest)
}

/// Propagate dirty grafted leaf positions upward through the cache, recomputing ancestor digests.
///
/// Given a set of ops positions at the grafting height whose digests have just been
/// inserted/updated in `grafted_digests`, this function walks each one up to its containing peak,
/// collects all ancestor positions that need recomputation, deduplicates them, and recomputes
/// bottom-up.
///
/// Uses **ops-space positions** in `node_digest` hash pre-images.
fn propagate_dirty<H: CHasher>(
    grafted_digests: &mut Digests<H::Digest>,
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
                let digest = recompute_node(grafted_digests, hasher, pos, height);
                grafted_digests.insert(pos, digest);
            }
        }
    }
}

/// Parallel path for [`propagate_dirty`]: groups nodes by height level and parallelizes
/// within each level using rayon. Falls back to serial for levels with fewer than
/// [`MIN_TO_PARALLELIZE`] nodes.
fn propagate_dirty_parallel<H: CHasher>(
    grafted_digests: &mut Digests<H::Digest>,
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
    grafted_digests: &mut Digests<H::Digest>,
    hasher: &mut StandardHasher<H>,
    pool: &ThreadPool,
    positions: &[Position],
    height: u32,
) {
    if positions.len() >= MIN_TO_PARALLELIZE {
        let computed: Vec<(Position, H::Digest)> = pool.install(|| {
            positions
                .par_iter()
                .map_init(
                    || hasher.fork(),
                    |h, &pos| (pos, recompute_node(grafted_digests, h, pos, height)),
                )
                .collect()
        });
        for (pos, digest) in computed {
            grafted_digests.insert(pos, digest);
        }
    } else {
        for &pos in positions {
            let digest = recompute_node(grafted_digests, hasher, pos, height);
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

    /// Resolve the local index into `self.chunks` for the ops position at the grafting height.
    ///
    /// Returns `None` if the chunk index is outside the range covered by `self.chunks`.
    fn resolve_chunk_idx(&self, pos: Position) -> Option<usize> {
        let chunk_idx = ops_pos_to_chunk_idx(pos, self.grafting_height);
        let local = chunk_idx.checked_sub(self.start_chunk_index)?;
        (local < self.chunks.len() as u64).then_some(local as usize)
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

                let Some(local) = self.resolve_chunk_idx(pos) else {
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

/// A virtual [StorageTrait] that presents a grafted digest cache and ops MMR as a single combined
/// MMR.
///
/// Nodes below the grafting height are served from the ops MMR. Nodes at or above the grafting
/// height are served from the grafted digests cache. This allows standard MMR proof generation to
/// work transparently over the combined structure.
pub(super) struct Storage<'a, D: Digest, S: StorageTrait<D>> {
    grafted_digests: &'a Digests<D>,
    ops_mmr: &'a S,
}

impl<'a, D: Digest, S: StorageTrait<D>> Storage<'a, D, S> {
    /// Creates a new [Storage] instance.
    pub(super) const fn new(grafted_digests: &'a Digests<D>, ops_mmr: &'a S) -> Self {
        Self {
            grafted_digests,
            ops_mmr,
        }
    }
}

impl<D: Digest, S: StorageTrait<D>> StorageTrait<D> for Storage<'_, D, S> {
    fn size(&self) -> Position {
        self.ops_mmr.size()
    }

    async fn get_node(&self, pos: Position) -> Result<Option<D>, Error> {
        if pos_to_height(pos) < self.grafted_digests.grafting_height() {
            return self.ops_mmr.get_node(pos).await;
        }
        Ok(self.grafted_digests.get(pos))
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

    /// Precompute grafted leaf digests and return a [Digests] containing the digests.
    ///
    /// Each grafted leaf is `hash(chunk || ops_subtree_root)` where `ops_subtree_root` is the ops
    /// MMR node at the mapped position.
    fn precompute_grafted_digests(
        standard: &mut StandardHasher<Sha256>,
        ops_mmr: &CleanMmr<sha256::Digest>,
        chunks: &[sha256::Digest],
        grafting_height: u32,
    ) -> Digests<sha256::Digest> {
        let leaves: Vec<(Position, sha256::Digest)> = chunks
            .iter()
            .enumerate()
            .map(|(i, chunk)| {
                let ops_pos = chunk_idx_to_ops_pos(i as u64, grafting_height);
                let ops_subtree_root = ops_mmr
                    .get_node(ops_pos)
                    .expect("ops MMR missing node at mapped position");
                standard.inner().update(chunk);
                standard.inner().update(&ops_subtree_root);
                (ops_pos, standard.inner().finalize())
            })
            .collect();
        let mut cache = Digests::new(grafting_height);
        cache.update_leaves(&leaves, standard, ops_mmr.size(), None);
        cache
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
    fn test_grafted_mmr_size() {
        // mmr_size(n) = 2n - popcount(n)
        assert_eq!(mmr_size(0), 0);
        assert_eq!(mmr_size(1), 1); // 2 - 1
        assert_eq!(mmr_size(2), 3); // 4 - 1
        assert_eq!(mmr_size(3), 4); // 6 - 2
        assert_eq!(mmr_size(4), 7); // 8 - 1
        assert_eq!(mmr_size(5), 8); // 10 - 2
        assert_eq!(mmr_size(8), 15); // 16 - 1

        // Cross-check: Position::try_from(Location(n)) gives the MMR position of the (n+1)-th
        // leaf, which equals mmr_size(n) for leaf count n.
        for n in 1..1000u64 {
            let expected = *Position::try_from(Location::new_unchecked(n)).unwrap();
            assert_eq!(mmr_size(n), expected, "mismatch at n={n}");
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

                let grafted = precompute_grafted_digests(&mut standard, &ops_mmr, &elements, 0);
                assert!(grafted.get(chunk_idx_to_ops_pos(0, 0)).is_some());
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
                assert!(grafted.get(chunk_idx_to_ops_pos(0, 1)).is_some());
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
        let mut cache = Digests::new(grafting_height);
        cache.resize_for_chunks(2);
        let pos0 = chunk_idx_to_ops_pos(0, grafting_height);
        let pos1 = chunk_idx_to_ops_pos(1, grafting_height);

        let sub0 = ops_mmr.get_node(pos0).unwrap();
        standard.inner().update(&c1);
        standard.inner().update(&sub0);
        cache.insert(pos0, standard.inner().finalize());

        let sub1 = ops_mmr.get_node(pos1).unwrap();
        standard.inner().update(&c2);
        standard.inner().update(&sub1);
        cache.insert(pos1, standard.inner().finalize());

        // Propagate should add the parent node (at height grafting_height + 1).
        propagate_dirty(
            &mut cache,
            &mut standard,
            &[pos0, pos1],
            ops_mmr.size(),
            None,
        );

        // With 4 ops leaves and grafting height 1, the grafted tree has 2 leaves and 1 root.
        // All 3 nodes (2 leaves + 1 internal) should be retrievable.
        assert!(cache.get(pos0).is_some());
        assert!(cache.get(pos1).is_some());
        // Parent at ops_pos = 6 (height 2 in ops space).
        assert!(cache.get(Position::new(6)).is_some());
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
                let combined = Storage::new(&grafted, &ops_mmr);
                assert_eq!(combined.size(), ops_mmr.size());

                // Compute the combined root by iterating ops peaks.
                let combined_root = {
                    use crate::mmr::iterator::PeakIterator;
                    let ops_size = ops_mmr.size();
                    let ops_leaves = Location::try_from(ops_size).unwrap();
                    let mut peaks = Vec::new();
                    for (peak_pos, peak_height) in PeakIterator::new(ops_size) {
                        if peak_height >= GRAFTING_HEIGHT {
                            peaks.push(grafted.get(peak_pos).unwrap());
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

            let combined = Storage::new(&grafted, &ops_mmr);
            assert_eq!(combined.size(), ops_mmr.size());

            // Compute the combined root.
            let combined_root = {
                use crate::mmr::iterator::PeakIterator;
                let ops_size = ops_mmr.size();
                let ops_leaves = Location::try_from(ops_size).unwrap();
                let mut peaks = Vec::new();
                for (peak_pos, peak_height) in PeakIterator::new(ops_size) {
                    if peak_height >= GRAFTING_HEIGHT {
                        peaks.push(grafted.get(peak_pos).unwrap());
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
    fn test_grafted_digests_basic() {
        let grafting_height = 1u32;
        let mut cache = Digests::<sha256::Digest>::new(grafting_height);
        // Pre-size for 2 chunks (grafted MMR has 3 nodes: 2 leaves + 1 internal).
        cache.resize_for_chunks(2);

        // Insert a grafted leaf at chunk 0 (ops pos = 2).
        let d0 = Sha256::fill(0x01);
        let ops_pos_0 = chunk_idx_to_ops_pos(0, grafting_height);
        assert_eq!(*ops_pos_0, 2);
        cache.insert(ops_pos_0, d0);
        assert_eq!(cache.get(ops_pos_0), Some(d0));

        // Insert a grafted leaf at chunk 1 (ops pos = 5).
        let d1 = Sha256::fill(0x02);
        let ops_pos_1 = chunk_idx_to_ops_pos(1, grafting_height);
        cache.insert(ops_pos_1, d1);
        assert_eq!(cache.get(ops_pos_1), Some(d1));

        // Insert an internal node (ops pos = 6, height 2 in ops space = height 1 in grafted).
        let d_internal = Sha256::fill(0x03);
        cache.insert(Position::new(6), d_internal);
        assert_eq!(cache.get(Position::new(6)), Some(d_internal));

        // Non-existent position returns None.
        assert_eq!(cache.get(chunk_idx_to_ops_pos(5, grafting_height)), None);
    }

    #[test_traced]
    fn test_grafted_digests_with_pruning() {
        let grafting_height = 1u32;

        // Simulate pruning 4 chunks. The pruned sub-MMR has 4 grafted leaves,
        // mmr_size(4) = 7, with one peak at grafted position 6.
        let pinned_digest = Sha256::fill(0xAA);
        let mut cache =
            Digests::<sha256::Digest>::from_pinned(&[pinned_digest], 4, grafting_height);

        assert_eq!(cache.offset, mmr_size(4));
        assert_eq!(cache.offset, 7);

        // The pinned peak should be at grafted position 6 (ops-space peak of 4-leaf sub-MMR).
        // For 4 grafted leaves, the peak is the root of the 4-leaf grafted sub-MMR.
        // ops_pos for this is at height 3 in ops space. For 4 chunks with gh=1:
        // chunk 0 -> ops 2, chunk 1 -> ops 5, internal -> ops 6,
        // chunk 2 -> ops 9, chunk 3 -> ops 12, internal -> ops 13, root -> ops 14.
        // With 8 ops leaves (4 chunks * 2), the MMR has size = Position::try_from(Location(8)) = 15.
        // Peak at position 14 (height 3, grafted height 2, grafted pos 6).
        assert_eq!(cache.get(Position::new(14)), Some(pinned_digest));

        // Pre-size for 5 total chunks (4 pruned + 1 unpruned).
        cache.resize_for_chunks(5);

        // Insert an unpruned node at chunk 4 (ops pos = 17, grafted pos = 7 = offset).
        let d4 = Sha256::fill(0xBB);
        let ops_pos_4 = chunk_idx_to_ops_pos(4, grafting_height);
        cache.insert(ops_pos_4, d4);
        assert_eq!(cache.get(ops_pos_4), Some(d4));

        // The unpruned node is at index 0 in the dense region.
        assert_eq!(cache.nodes[0], d4);
    }
}
