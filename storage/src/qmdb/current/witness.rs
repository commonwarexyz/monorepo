//! Extra witness data for recomputing grafted roots after pruning `current` state.
//!
//! For MMR, the pruned grafted tree's pinned nodes are enough to reopen the tree and recompute the
//! canonical grafted root. For MMB, delayed merges can later expose pruned grafted interior nodes
//! that are no longer individually materialized, so pinned nodes alone are not always enough. This
//! module persists the small extra set of grafted digests needed to bridge that gap.
//!
//! `rebuild_grafted_root_witness()` works in three steps:
//! 1. Predict which pruned grafted nodes can still become relevant as future MMB peaks.
//! 2. Walk down from the currently pinned grafted peaks, capturing the non-pinned nodes on the
//!    paths to those future targets.
//! 3. Reuse older witness entries for already-pruned nodes, and read newly-pruned nodes from the
//!    still-materialized grafted tree before compaction.
//!
//! The witness stays small because it only tracks the still-fragmentable delayed-merge frontier,
//! not every node in the pruned prefix. In practice this is logarithmic in the size of the pruned
//! prefix: once a subtree's parent has been born, that subtree can never fragment back out into
//! smaller future peaks, so witness retention follows only the still-live frontier with at most a
//! small number of target paths per height.

use crate::{
    merkle::{self, Location, Position, Readable},
    qmdb::{current::grafting, Error},
};
use commonware_cryptography::Digest;
#[cfg(test)]
use commonware_utils::bitmap::Prunable as BitMap;
use std::collections::BTreeSet;

/// Extra grafted-tree digests retained across prune/reopen for canonical root recomputation.
///
/// Ordinary pinned nodes are enough to reopen the pruned grafted `Mem`, but for MMB they are not
/// always enough to recompute the canonical grafted root after delayed merges expose pruned
/// interior nodes that are no longer individually materialized. This witness stores the small set
/// of additional grafted digests needed to bridge that gap.
///
/// Entries are kept sorted by grafted position so they can be persisted directly and queried with
/// binary search during root reconstruction.
#[derive(Clone, Debug)]
pub(super) struct GraftedRootWitness<D: Digest> {
    entries: Vec<(u64, D)>,
}

impl<D: Digest> GraftedRootWitness<D> {
    pub(super) const fn empty() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub(super) fn from_entries(mut entries: Vec<(u64, D)>) -> Self {
        entries.sort_unstable_by_key(|(pos, _)| *pos);
        Self { entries }
    }

    pub(super) fn clear(&mut self) {
        self.entries.clear();
    }

    pub(super) fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    pub(super) fn push(&mut self, pos: u64, digest: D) {
        self.entries.push((pos, digest));
    }

    pub(super) const fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn sort_by_position(&mut self) {
        self.entries.sort_unstable_by_key(|(pos, _)| *pos);
    }

    pub(super) fn persisted_entries(&self) -> &[(u64, D)] {
        &self.entries
    }

    pub(super) fn get(&self, target_pos: u64) -> Option<&D> {
        debug_assert!(self
            .entries
            .windows(2)
            .all(|window| window[0].0 < window[1].0));
        self.entries
            .binary_search_by_key(&target_pos, |(pos, _)| *pos)
            .ok()
            .map(|idx| &self.entries[idx].1)
    }
}

impl<D: Digest> Default for GraftedRootWitness<D> {
    fn default() -> Self {
        Self::empty()
    }
}

/// Maps a raw operation tree node (`ops_pos`) to the grafted position that witness planning must
/// retain for it.
///
/// If the node sits at or above the `grafting_height`, it translates directly 1:1 into a grafted
/// position. If it sits below the `grafting_height`, the entire operation subtree is aggregated
/// into a single bitmap chunk, so the target becomes the grafted leaf for that chunk.
fn witness_target_for_ops_peak<F: merkle::Graftable>(
    ops_pos: Position<F>,
    ops_height: u32,
    grafting_height: u32,
) -> Position<F> {
    if ops_height >= grafting_height {
        grafting::ops_to_grafted_pos::<F>(ops_pos, grafting_height)
    } else {
        let chunk_idx = *F::leftmost_leaf(ops_pos, ops_height) >> grafting_height;
        F::subtree_root_position(Location::<F>::new(chunk_idx), 0)
    }
}

/// Recursively predicts all future witness targets for the pruned region by calculating the
/// delayed-merge fragmentation of the grafted tree.
///
/// When an MMB database is appended to, existing peaks may disappear as they are merged into newly
/// born, taller ancestors. However, because we only preserve the interior of the grafted tree at
/// the exact moment of pruning, we must also capture the interior nodes of any currently-pinned
/// peaks that might temporarily fragment apart into their smaller children during future delayed
/// merges.
///
/// # Mathematical Rule
///
/// A child node will only ever be queried distinctly from its parent if the parent has not yet been
/// born at the current logical time (`start_leaves`). If the parent's `birth_size <= start_leaves`,
/// the parent is permanently formed and its children will never again fragment outward. Therefore,
/// we recursively descend and collect children only from parent nodes whose `birth_size >
/// start_leaves`, bounding the search to the still-fragmented portion of the pruned frontier.
fn collect_future_witness_targets<F: merkle::Graftable>(
    ops_pos: Position<F>,
    ops_height: u32,
    start_leaves: u64,
    grafting_height: u32,
    pinned_peaks: &BTreeSet<Position<F>>,
    target_positions: &mut BTreeSet<Position<F>>,
) {
    if ops_height == 0 || F::peak_birth_size(ops_pos, ops_height) <= start_leaves {
        return;
    }

    let (left, right) = F::children(ops_pos, ops_height);
    let child_height = ops_height - 1;
    for child in [left, right] {
        let target = witness_target_for_ops_peak::<F>(child, child_height, grafting_height);
        if !pinned_peaks.contains(&target) {
            target_positions.insert(target);
        }
        collect_future_witness_targets::<F>(
            child,
            child_height,
            start_leaves,
            grafting_height,
            pinned_peaks,
            target_positions,
        );
    }
}

/// Rebuilds the persisted grafted-root witness for the currently pruned prefix.
pub(super) fn rebuild_grafted_root_witness<F, D, G, const N: usize>(
    grafted_tree: &G,
    ops_size: Position<F>,
    pruned_chunks: u64,
    witness: &mut GraftedRootWitness<D>,
) -> Result<(), Error<F>>
where
    F: merkle::Graftable,
    D: Digest,
    G: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
{
    if pruned_chunks == 0 {
        witness.clear();
        return Ok(());
    }

    let grafting_height = grafting::height::<N>();
    let pruned_loc = Location::<F>::new(pruned_chunks);
    let pinned_peaks: BTreeSet<Position<F>> = F::nodes_to_pin(pruned_loc).collect();

    // Build target_positions by recursively predicting the future delayed-merge fringe. A child can
    // only ever reappear as a peak while its parent has not yet been born, so `birth(parent) >
    // start_leaves` is the exact criterion for whether we must keep descending.
    let mut target_positions = BTreeSet::new();
    let start_leaves = Location::<F>::try_from(ops_size)
        .expect("valid ops_size")
        .as_u64();
    for &grafted_pos in &pinned_peaks {
        let grafted_height = F::pos_to_height(grafted_pos);
        let ops_pos = grafting::grafted_to_ops_pos::<F>(grafted_pos, grafting_height);
        let ops_height = grafted_height + grafting_height;
        collect_future_witness_targets::<F>(
            ops_pos,
            ops_height,
            start_leaves,
            grafting_height,
            &pinned_peaks,
            &mut target_positions,
        );
    }

    let old_witness = witness.take();

    for peak_pos in &pinned_peaks {
        let peak_height = F::pos_to_height(*peak_pos);
        collect_witness_nodes_on_paths(
            grafted_tree,
            witness,
            *peak_pos,
            peak_height,
            &pinned_peaks,
            &target_positions,
            &old_witness,
        );
    }

    witness.sort_by_position();
    Ok(())
}

/// Walk from `pos` toward the target positions, capturing every non-pinned node on the path.
///
/// Only descends into subtrees that cover at least one target position. Reads newly-pruned nodes
/// from `grafted_tree`, and older nodes from `old_witness`.
fn collect_witness_nodes_on_paths<F, D, G>(
    grafted_tree: &G,
    witness: &mut GraftedRootWitness<D>,
    pos: Position<F>,
    height: u32,
    pinned_peaks: &BTreeSet<Position<F>>,
    target_positions: &BTreeSet<Position<F>>,
    old_witness: &GraftedRootWitness<D>,
) where
    F: merkle::Graftable,
    D: Digest,
    G: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
{
    // Only proceed if `pos` covers at least one target. This helper never recurses below a node
    // once that node itself is in `target_positions`, so any target still reachable from this frame
    // cannot be a strict ancestor of `pos`. In a Merkle family, subtree leaf ranges are power-of-2
    // aligned and non-overlapping, so under that recursion invariant it is enough to test whether
    // the target's leftmost leaf falls inside `pos`'s leaf range.
    let a_left = *F::leftmost_leaf(pos, height);
    let a_width = 1u64 << height;
    let covers_target = target_positions.iter().any(|&target| {
        let b_left = *F::leftmost_leaf(target, F::pos_to_height(target));
        a_left <= b_left && b_left < a_left + a_width
    });
    if !covers_target {
        return;
    }

    if !pinned_peaks.contains(&pos) {
        let digest = grafted_tree
            .get_node(pos)
            .or_else(|| old_witness.get(*pos).copied())
            .expect("witness node must exist in grafted_tree or old_witness");
        witness.push(*pos, digest);
    }

    if target_positions.contains(&pos) || height == 0 {
        return;
    }

    let (left, right) = F::children(pos, height);
    let child_height = height - 1;
    collect_witness_nodes_on_paths(
        grafted_tree,
        witness,
        left,
        child_height,
        pinned_peaks,
        target_positions,
        old_witness,
    );
    collect_witness_nodes_on_paths(
        grafted_tree,
        witness,
        right,
        child_height,
        pinned_peaks,
        target_positions,
        old_witness,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::FixedSize;
    use commonware_cryptography::sha256;

    const N: usize = sha256::Digest::SIZE;

    fn broad_target_simulation_end<F: merkle::Graftable, const N: usize>(
        pruned_chunks: u64,
    ) -> Result<u64, Error<F>> {
        let pruned_ops_leaves = pruned_chunks
            .checked_mul(BitMap::<N>::CHUNK_SIZE_BITS)
            .ok_or(Error::DataCorrupted("pruned ops leaves overflow"))?;
        if pruned_ops_leaves == 0 {
            return Ok(0);
        }

        let max_height = pruned_ops_leaves.ilog2();
        let width = 1u64
            .checked_shl(max_height)
            .ok_or(Error::DataCorrupted("witness subtree width overflow"))?;
        let leaf_start = pruned_ops_leaves
            .checked_sub(width)
            .ok_or(Error::DataCorrupted("pruned ops leaves underflow"))?;
        let pos = F::subtree_root_position(Location::<F>::new(leaf_start), max_height);
        Ok(F::peak_birth_size(pos, max_height))
    }

    fn broad_future_target_positions<F: merkle::Graftable, const N: usize>(
        pruned_chunks: u64,
        start_leaves: u64,
    ) -> Result<BTreeSet<u64>, Error<F>> {
        let pruned_ops_leaves = pruned_chunks
            .checked_mul(BitMap::<N>::CHUNK_SIZE_BITS)
            .ok_or(Error::DataCorrupted("pruned ops leaves overflow"))?;
        let pruned_loc = Location::<F>::new(pruned_chunks);
        let pinned_peaks: BTreeSet<Position<F>> = F::nodes_to_pin(pruned_loc).collect();
        let mut targets = BTreeSet::new();
        let max_sim_leaves = broad_target_simulation_end::<F, N>(pruned_chunks)?.max(start_leaves);
        let mut sim_leaves = start_leaves;

        loop {
            let sim_size = Position::try_from(Location::<F>::new(sim_leaves))?;
            for (peak_pos, peak_height) in F::peaks(sim_size) {
                let leftmost = *F::leftmost_leaf(peak_pos, peak_height);
                let width = 1u64
                    .checked_shl(peak_height)
                    .ok_or(Error::DataCorrupted("witness subtree width overflow"))?;
                let rightmost_exclusive = leftmost
                    .checked_add(width)
                    .ok_or(Error::DataCorrupted("witness subtree range overflow"))?;
                if rightmost_exclusive > pruned_ops_leaves {
                    continue;
                }
                let target = witness_target_for_ops_peak::<F>(
                    peak_pos,
                    peak_height,
                    grafting::height::<N>(),
                );
                if !pinned_peaks.contains(&target) {
                    targets.insert(*target);
                }
            }
            if sim_leaves == max_sim_leaves {
                break;
            }
            sim_leaves = sim_leaves
                .checked_add(1)
                .ok_or(Error::DataCorrupted("witness simulation overflow"))?;
        }

        Ok(targets)
    }

    /// Aligned Merkle subtrees are either fully contained or fully disjoint, so checking that the
    /// target's leftmost leaf falls within the ancestor's range is sufficient.
    fn covers_in_grafted_space<F: merkle::Graftable>(
        ancestor: Position<F>,
        target: Position<F>,
    ) -> bool {
        let ancestor_height = F::pos_to_height(ancestor);
        let ancestor_left = *F::leftmost_leaf(ancestor, ancestor_height);
        let ancestor_width = 1u64 << ancestor_height;
        let target_left = *F::leftmost_leaf(target, F::pos_to_height(target));
        ancestor_left <= target_left && target_left < ancestor_left + ancestor_width
    }

    fn is_strict_descendant_in_grafted_space<F: merkle::Graftable>(
        target: Position<F>,
        ancestor: Position<F>,
    ) -> bool {
        let target_height = F::pos_to_height(target);
        let ancestor_height = F::pos_to_height(ancestor);
        target_height < ancestor_height && covers_in_grafted_space::<F>(ancestor, target)
    }

    fn required_witness_target_positions<F: merkle::Graftable, const N: usize>(
        pruned_chunks: u64,
        start_leaves: u64,
    ) -> Result<BTreeSet<u64>, Error<F>> {
        let pruned_loc = Location::<F>::new(pruned_chunks);
        let pinned_peaks: BTreeSet<Position<F>> = F::nodes_to_pin(pruned_loc).collect();
        let broad_targets = broad_future_target_positions::<F, N>(pruned_chunks, start_leaves)?;

        Ok(broad_targets
            .into_iter()
            .filter(|&target| {
                let target = Position::<F>::new(target);
                pinned_peaks
                    .iter()
                    .copied()
                    .any(|pinned| is_strict_descendant_in_grafted_space::<F>(target, pinned))
            })
            .collect())
    }

    fn recursive_target_positions<F: merkle::Graftable, const N: usize>(
        pruned_chunks: u64,
        start_leaves: u64,
    ) -> BTreeSet<u64> {
        let pruned_loc = Location::<F>::new(pruned_chunks);
        let pinned_peaks: BTreeSet<Position<F>> = F::nodes_to_pin(pruned_loc).collect();
        let mut targets = BTreeSet::new();
        let grafting_height = grafting::height::<N>();
        for &grafted_pos in &pinned_peaks {
            let grafted_height = F::pos_to_height(grafted_pos);
            let ops_pos = grafting::grafted_to_ops_pos::<F>(grafted_pos, grafting_height);
            collect_future_witness_targets::<F>(
                ops_pos,
                grafted_height + grafting_height,
                start_leaves,
                grafting_height,
                &pinned_peaks,
                &mut targets,
            );
        }
        targets.into_iter().map(|pos| *pos).collect()
    }

    fn assert_recursive_targets_match_required_targets<F: merkle::Graftable, const N: usize>() {
        let interesting_offsets = [
            0u64, 1, 2, 3, 7, 15, 31, 63, 127, 128, 129, 255, 256, 257, 383, 511, 512, 513, 767,
            1023,
        ];

        for pruned_chunks in 1..=8u64 {
            let pruned_ops_leaves = pruned_chunks * BitMap::<N>::CHUNK_SIZE_BITS;
            for offset in interesting_offsets {
                let start_leaves = pruned_ops_leaves + offset;
                let recursive = recursive_target_positions::<F, N>(pruned_chunks, start_leaves);
                let required =
                    required_witness_target_positions::<F, N>(pruned_chunks, start_leaves)
                        .unwrap_or_else(|err| {
                            panic!(
                                "required target generation failed: pruned_chunks={pruned_chunks}, start_leaves={start_leaves}, err={err:?}"
                            )
                        });
                assert_eq!(
                    recursive, required,
                    "required target mismatch: pruned_chunks={pruned_chunks}, start_leaves={start_leaves}"
                );
            }
        }
    }

    #[test]
    fn recursive_witness_targets_match_required_targets_mmb() {
        assert_recursive_targets_match_required_targets::<crate::merkle::mmb::Family, N>();
    }

    #[test]
    fn recursive_witness_targets_match_required_targets_mmr() {
        assert_recursive_targets_match_required_targets::<crate::merkle::mmr::Family, N>();
    }

    #[test]
    fn simulated_ghost_ancestor_is_not_witness_required() {
        let pruned_chunks = 4u64;
        let start_leaves = 1024u64;

        let broad = broad_future_target_positions::<crate::merkle::mmb::Family, N>(
            pruned_chunks,
            start_leaves,
        )
        .expect("broad future targets");
        let required = required_witness_target_positions::<crate::merkle::mmb::Family, N>(
            pruned_chunks,
            start_leaves,
        )
        .expect("required witness targets");
        let recursive = recursive_target_positions::<crate::merkle::mmb::Family, N>(
            pruned_chunks,
            start_leaves,
        );

        assert!(
            broad.contains(&7),
            "broad future target set should include the ghost ancestor"
        );
        assert!(
            !required.contains(&7),
            "ghost ancestor should not be witness-required"
        );
        assert_eq!(recursive, required);
    }
}
