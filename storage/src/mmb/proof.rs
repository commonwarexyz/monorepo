//! Defines the inclusion [Proof] structure for MMBs, and functions for determining which node
//! digests are required for range and multi-element proofs, and for reconstructing the root
//! digest from a proof.

use super::{
    hasher::Hasher,
    iterator::{child_steps, peak_birth_step, step_to_pos, PeakIterator},
    Error, Location, Position,
};
pub use crate::merkle::proof::{ReconstructionError, MAX_PROOF_DIGESTS_PER_ELEMENT};
use alloc::{collections::BTreeSet, vec::Vec};
use commonware_cryptography::Digest;
use core::ops::Range;

/// MMB inclusion proof. Type alias for `merkle::Proof<Mmb, D>`.
pub type Proof<D> = crate::merkle::Proof<super::Mmb, D>;

/// Collect the positions of sibling nodes required for reconstructing a peak digest, in the
/// same left-first DFS order that [`reconstruct_peak_from_range`] consumes them.
///
/// At each node: if the subtree is entirely outside the range, its root position is emitted
/// (it will be provided as a sibling digest). If it's a leaf in the range, nothing is emitted.
/// Otherwise, recurse left then right.
fn collect_siblings_dfs(
    step: u64,
    height: u32,
    leaf_start: u64,
    range: &Range<u64>,
    positions: &mut Vec<Position>,
) {
    let leaves_in_node = 1u64 << height;
    let leaf_end = leaf_start + leaves_in_node;

    if leaf_end <= range.start || leaf_start >= range.end {
        positions.push(step_to_pos(step, height == 0));
        return;
    }
    if height == 0 {
        return;
    }

    let (left_step, right_step) = child_steps(step, height);
    let mid = leaf_start + (1u64 << (height - 1));
    collect_siblings_dfs(left_step, height - 1, leaf_start, range, positions);
    collect_siblings_dfs(right_step, height - 1, mid, range, positions);
}

/// A blueprint for building a range proof. The positions are split into two groups so that the
/// proof generator cannot accidentally fetch a raw digest where a folded accumulator is needed.
pub(crate) struct ProofBlueprint {
    /// Peak positions that precede the range (oldest-to-newest). The proof generator must fetch
    /// each digest and left-fold them starting from `Hash(leaves)` to produce a single proof
    /// digest. Empty when the range starts in the oldest peak.
    pub fold_prefix: Vec<Position>,

    /// Positions whose raw digests are fetched directly: after-peak digests followed by sibling
    /// nodes in left-first DFS order.
    pub fetch_nodes: Vec<Position>,
}

/// Return the blueprint for building a range proof for the specified range of elements in an
/// MMB with the given number of leaves.
///
/// The blueprint's `fold_prefix` and `fetch_nodes` together produce digests in the layout
/// expected by [`Proof::reconstruct_root`]:
///   `[ folded_prefix? | after_peak_oldest | ... | after_peak_newest | siblings... ]`
///
/// # Errors
///
/// Returns [Error::Empty] if the range is empty.
/// Returns [Error::LocationOverflow] if a location in `range` > [crate::mmb::MAX_LOCATION].
/// Returns [Error::RangeOutOfBounds] if the last element in `range` >= `leaves`.
pub(crate) fn nodes_required_for_range_proof(
    leaves: Location,
    range: Range<Location>,
) -> Result<ProofBlueprint, Error> {
    if range.is_empty() {
        return Err(Error::Empty);
    }
    let end_minus_one = range
        .end
        .checked_sub(1)
        .expect("can't underflow because range is non-empty");
    if end_minus_one >= leaves {
        return Err(Error::RangeOutOfBounds(range.end));
    }

    let start_loc = range.start.as_u64();
    let end_loc = range.end.as_u64(); // exclusive
    let n = leaves.as_u64();
    let size = Position::try_from(leaves)?;

    // Single-pass peak walk: classify each peak and collect range-containing peaks.
    // PeakIterator yields newest-to-oldest, so before/after vecs are in that order.
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut range_peaks = Vec::new();
    let mut end_leaf_cursor = n;
    for (peak_pos, height) in PeakIterator::new(size) {
        let leaves_in_peak = 1u64 << height;
        let leaf_start = end_leaf_cursor - leaves_in_peak;

        if leaf_start >= end_loc {
            after.push(peak_pos);
        } else if end_leaf_cursor <= start_loc {
            before.push(peak_pos);
        } else {
            let step = peak_birth_step(end_leaf_cursor - 1, height);
            range_peaks.push((step, height, leaf_start));
        }
        end_leaf_cursor = leaf_start;
    }

    // Reverse all from newest-to-oldest to oldest-to-newest.
    before.reverse();
    after.reverse();
    range_peaks.reverse();

    // Collect sibling positions in DFS order for each range-containing peak.
    let leaf_range = start_loc..end_loc;
    let mut fetch_nodes = Vec::new();
    for &peak_pos in &after {
        fetch_nodes.push(peak_pos);
    }
    for &(step, height, leaf_start) in &range_peaks {
        collect_siblings_dfs(step, height, leaf_start, &leaf_range, &mut fetch_nodes);
    }

    Ok(ProofBlueprint {
        fold_prefix: before,
        fetch_nodes,
    })
}

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`.
///
/// # Errors
///
/// Returns [Error::Empty] if locations is empty.
/// Returns [Error::LocationOverflow] if any location > [crate::mmb::MAX_LOCATION].
/// Returns [Error::RangeOutOfBounds] if any location >= `leaves`.
#[allow(dead_code)]
pub(crate) fn nodes_required_for_multi_proof(
    leaves: Location,
    locations: &[Location],
) -> Result<BTreeSet<Position>, Error> {
    if locations.is_empty() {
        return Err(Error::Empty);
    }
    // TODO: This walks all peaks per location (O(N * log K)). A single peak walk
    // collecting all locations would be O(N + log K).
    locations.iter().try_fold(BTreeSet::new(), |mut acc, loc| {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(*loc));
        }
        // `loc` is valid so it won't overflow from +1
        let bp = nodes_required_for_range_proof(leaves, *loc..*loc + 1)?;
        acc.extend(bp.fold_prefix);
        acc.extend(bp.fetch_nodes);
        Ok(acc)
    })
}

/// Build a range proof from a node-fetching closure.
///
/// This handles the folded-prefix computation internally so callers cannot accidentally
/// store raw peak digests where a fold is expected.
///
/// # Errors
///
/// Returns [Error::Empty] if the range is empty.
/// Returns [Error::LocationOverflow] if a location in `range` > [crate::mmb::MAX_LOCATION].
/// Returns [Error::RangeOutOfBounds] if the last element in `range` >= `leaves`.
/// Returns [Error::MissingNode] if any required node is not available via `get_node`.
pub(crate) fn build_range_proof<D, H>(
    hasher: &mut H,
    leaves: Location,
    range: Range<Location>,
    get_node: impl Fn(Position) -> Option<D>,
) -> Result<Proof<D>, Error>
where
    D: Digest,
    H: Hasher<super::Mmb, Digest = D>,
{
    let bp = nodes_required_for_range_proof(leaves, range)?;

    let mut digests = Vec::new();

    // Fold preceding peaks into a single accumulator digest.
    if !bp.fold_prefix.is_empty() {
        let mut acc = hasher.digest(&leaves.as_u64().to_be_bytes());
        for &peak_pos in &bp.fold_prefix {
            let peak_d = get_node(peak_pos).ok_or(Error::MissingNode(peak_pos))?;
            acc = hasher.fold_peak(&acc, &peak_d);
        }
        digests.push(acc);
    }

    // Fetch raw digests for after-peaks and siblings.
    for &pos in &bp.fetch_nodes {
        digests.push(get_node(pos).ok_or(Error::MissingNode(pos))?);
    }

    Ok(Proof { leaves, digests })
}

/// Reconstruct a peak digest from elements within a range and sibling digests for subtrees
/// outside the range.
///
/// Descends through the peak tree using `child_steps` / `step_to_pos`. At each node:
/// - If the node is a leaf in the range: hash the next element.
/// - If the node's subtree is entirely outside the range: consume a sibling digest.
/// - Otherwise: recurse into children and compute the node digest.
fn reconstruct_peak_from_range<'a, D, H, E, S>(
    hasher: &mut H,
    step: u64,
    height: u32,
    leaf_start: u64,
    range: Range<u64>,
    elements: &mut E,
    siblings: &mut S,
) -> Result<D, ReconstructionError>
where
    D: Digest,
    H: Hasher<super::Mmb, Digest = D>,
    E: Iterator,
    E::Item: AsRef<[u8]>,
    S: Iterator<Item = &'a D>,
{
    let leaves_in_node = 1u64 << height;
    let leaf_end = leaf_start + leaves_in_node;

    // Entirely outside the range: consume a sibling digest.
    if leaf_end <= range.start || leaf_start >= range.end {
        return siblings
            .next()
            .copied()
            .ok_or(ReconstructionError::MissingDigests);
    }

    // Leaf in range: hash the next element.
    if height == 0 {
        let elem = elements
            .next()
            .ok_or(ReconstructionError::MissingElements)?;
        let pos = step_to_pos(step, true);
        return Ok(hasher.leaf_digest(pos, elem.as_ref()));
    }

    // Recurse into children.
    let (left_step, right_step) = child_steps(step, height);
    let mid = leaf_start + (1u64 << (height - 1));

    let left_d = reconstruct_peak_from_range(
        hasher,
        left_step,
        height - 1,
        leaf_start,
        range.clone(),
        elements,
        siblings,
    )?;
    let right_d = reconstruct_peak_from_range(
        hasher,
        right_step,
        height - 1,
        mid,
        range,
        elements,
        siblings,
    )?;

    let pos = step_to_pos(step, false);
    Ok(hasher.node_digest(pos, &left_d, &right_d))
}

impl<D: Digest> Proof<D> {
    /// Reconstruct the root digest from this proof and the given elements.
    ///
    /// The proof must have been built with the folded-peak layout:
    /// `[folded_prefix? | after_peak_oldest | ... | after_peak_newest | siblings...]`.
    ///
    /// `elements` are the leaf values for the range `start_loc..start_loc + elements.len()`.
    ///
    /// # Errors
    ///
    /// Returns [ReconstructionError] if the proof digests or elements are inconsistent.
    pub fn reconstruct_root<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<super::Mmb, Digest = D>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            if start_loc == 0 {
                return Ok(hasher.digest(&self.leaves.as_u64().to_be_bytes()));
            }
            return Err(ReconstructionError::MissingElements);
        }

        let end_loc = start_loc + elements.len() as u64;
        let start_u64 = start_loc.as_u64();
        let end_u64 = end_loc.as_u64();

        // Single-pass peak walk: classify and collect range-containing peaks.
        let size = Position::try_from(self.leaves).map_err(|_| ReconstructionError::InvalidSize)?;
        let n = self.leaves.as_u64();
        let mut num_before = 0usize;
        let mut num_after = 0usize;
        let mut range_peaks = Vec::new();
        let mut end_leaf_cursor = n;
        for (_peak_pos, height) in PeakIterator::new(size) {
            let leaves_in_peak = 1u64 << height;
            let leaf_start = end_leaf_cursor - leaves_in_peak;

            if leaf_start >= end_u64 {
                num_after += 1;
            } else if end_leaf_cursor <= start_u64 {
                num_before += 1;
            } else {
                let step = peak_birth_step(end_leaf_cursor - 1, height);
                range_peaks.push((step, height, leaf_start));
            }
            end_leaf_cursor = leaf_start;
        }
        // PeakIterator yields newest-to-oldest; reverse for oldest-to-newest fold order.
        range_peaks.reverse();

        // Slice boundaries into self.digests:
        //   [folded_prefix? | after_peaks... | siblings...]
        let prefix_count = usize::from(num_before > 0);
        let sibling_start = prefix_count + num_after;
        if self.digests.len() < sibling_start {
            return Err(ReconstructionError::MissingDigests);
        }
        let after_digests = &self.digests[prefix_count..sibling_start];
        let mut sibling_iter = self.digests[sibling_start..].iter();

        // Start the accumulator from the folded prefix or Hash(leaves).
        let mut acc = if num_before > 0 {
            self.digests[0]
        } else {
            hasher.digest(&self.leaves.as_u64().to_be_bytes())
        };

        // Fold range-containing peaks (reconstructed from elements + siblings).
        let mut elem_iter = elements.iter();
        for &(step, height, leaf_start) in &range_peaks {
            let peak_d = reconstruct_peak_from_range(
                hasher,
                step,
                height,
                leaf_start,
                start_u64..end_u64,
                &mut elem_iter,
                &mut sibling_iter,
            )?;
            acc = hasher.fold_peak(&acc, &peak_d);
        }

        if elem_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }
        if sibling_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }

        // Fold after-peak digests (oldest-to-newest).
        for after_d in after_digests {
            acc = hasher.fold_peak(&acc, after_d);
        }

        Ok(acc)
    }

    /// Verify that the given elements are included at `start_loc` in the MMB with the given root.
    pub fn verify_range_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<super::Mmb, Digest = D>,
        E: AsRef<[u8]>,
    {
        self.reconstruct_root(hasher, elements, start_loc)
            .map(|r| r == *root)
            .unwrap_or(false)
    }

    /// Verify that a single element is included at `loc` in the MMB with the given root.
    pub fn verify_element_inclusion<H>(
        &self,
        hasher: &mut H,
        element: &[u8],
        loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<super::Mmb, Digest = D>,
    {
        self.verify_range_inclusion(hasher, &[element], loc, root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmb::{
        hasher::Standard,
        mem::{CleanMmb, DirtyMmb},
    };
    use commonware_cryptography::Sha256;

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Sha256>;

    fn build_mmb(n: u64) -> CleanMmb<D> {
        let mut hasher = H::new();
        let mut mmb = DirtyMmb::new();
        for i in 0..n {
            mmb.add(&mut hasher, &i.to_be_bytes());
        }
        mmb.merkleize(&mut hasher, None)
    }

    fn build_proof(hasher: &mut H, mmb: &CleanMmb<D>, range: core::ops::Range<u64>) -> Proof<D> {
        let loc_range = Location::new(range.start)..Location::new(range.end);
        mmb.range_proof(hasher, loc_range).unwrap()
    }

    /// Collect all positions referenced by a blueprint.
    fn all_positions(bp: &ProofBlueprint) -> Vec<Position> {
        let mut out = Vec::new();
        out.extend(&bp.fold_prefix);
        out.extend(&bp.fetch_nodes);
        out
    }

    #[test]
    fn test_single_element_proof_positions() {
        for n in 1u64..=64 {
            let mmb = build_mmb(n);
            let leaves = mmb.leaves();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp = nodes_required_for_range_proof(leaves, loc..loc + 1).unwrap();
                let positions = all_positions(&bp);
                for &pos in &positions {
                    assert!(
                        pos < mmb.size(),
                        "n={n}, loc={loc}: pos {pos} >= size {}",
                        mmb.size()
                    );
                }
                // Should not contain the element's own leaf position.
                let leaf_pos = Position::try_from(loc).unwrap();
                assert!(
                    !positions.contains(&leaf_pos),
                    "n={n}, loc={loc}: should not contain leaf pos {leaf_pos}"
                );
            }
        }
    }

    #[test]
    fn test_single_element_proof_reconstruction() {
        for n in 1u64..=64 {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            for loc_idx in 0..n {
                let proof = build_proof(&mut hasher, &mmb, loc_idx..loc_idx + 1);
                let elements = [loc_idx.to_be_bytes()];
                let start_loc = Location::new(loc_idx);

                let reconstructed = proof
                    .reconstruct_root(&mut hasher, &elements, start_loc)
                    .unwrap_or_else(|e| panic!("n={n}, loc={loc_idx}: reconstruct failed: {e}"));
                assert_eq!(reconstructed, root, "n={n}, loc={loc_idx}: root mismatch");
            }
        }
    }

    #[test]
    fn test_range_proof_reconstruction() {
        for n in 2u64..=32 {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            let ranges: Vec<(u64, u64)> = vec![
                (0, n),
                (0, 1),
                (n - 1, n),
                (0, n.min(3)),
                (n.saturating_sub(3), n),
            ];

            for (start, end) in ranges {
                if start >= end || end > n {
                    continue;
                }
                let proof = build_proof(&mut hasher, &mmb, start..end);
                let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();
                let start_loc = Location::new(start);

                let reconstructed = proof
                    .reconstruct_root(&mut hasher, &elements, start_loc)
                    .unwrap_or_else(|e| {
                        panic!("n={n}, range={start}..{end}: reconstruct failed: {e}")
                    });
                assert_eq!(
                    reconstructed, root,
                    "n={n}, range={start}..{end}: root mismatch"
                );
            }
        }
    }

    #[test]
    fn test_verify_element_inclusion() {
        for n in 1u64..=32 {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            for loc_idx in 0..n {
                let proof = build_proof(&mut hasher, &mmb, loc_idx..loc_idx + 1);
                let loc = Location::new(loc_idx);

                assert!(
                    proof
                        .verify_element_inclusion(&mut hasher, &loc_idx.to_be_bytes(), loc, &root,),
                    "n={n}, loc={loc_idx}: verification failed"
                );

                // Wrong element should fail.
                assert!(
                    !proof.verify_element_inclusion(
                        &mut hasher,
                        &(loc_idx + 1000).to_be_bytes(),
                        loc,
                        &root,
                    ),
                    "n={n}, loc={loc_idx}: wrong element should not verify"
                );
            }
        }
    }

    #[test]
    fn test_folded_proof_size() {
        // Verify that proofs with the folded-prefix optimization have fewer digests than
        // the total number of peaks + siblings (i.e. the fold saves digests).
        for n in 4u64..=64 {
            let mmb = build_mmb(n);
            let leaves = mmb.leaves();

            // Prove the last element: all other peaks are preceding and should fold into one.
            let loc = n - 1;
            let bp = nodes_required_for_range_proof(leaves, Location::new(loc)..Location::new(n))
                .unwrap();

            if bp.fold_prefix.len() > 1 {
                // With folding, the proof has 1 digest for the folded prefix instead of N.
                // folded_digests = 1 (folded) + fetch_nodes.len()
                // unfolded_digests = fold_prefix.len() + fetch_nodes.len()
                let folded_total = 1 + bp.fetch_nodes.len();
                let unfolded_total = bp.fold_prefix.len() + bp.fetch_nodes.len();
                assert!(
                    folded_total < unfolded_total,
                    "n={n}: folded ({folded_total}) should be less than unfolded ({unfolded_total})"
                );
            }
        }
    }

    #[test]
    fn test_range_in_oldest_peak() {
        // Range in the oldest peak: no preceding peaks, so no folded prefix.
        for n in 2u64..=32 {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            // The oldest peak covers the first elements.
            let proof = build_proof(&mut hasher, &mmb, 0..1);
            let elements = [0u64.to_be_bytes()];
            let reconstructed = proof
                .reconstruct_root(&mut hasher, &elements, Location::new(0))
                .unwrap();
            assert_eq!(reconstructed, root, "n={n}: oldest peak range failed");
        }
    }

    #[test]
    fn test_range_in_newest_peak() {
        // Range in the newest peak: all other peaks are preceding.
        for n in 2u64..=32 {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            let loc = n - 1;
            let proof = build_proof(&mut hasher, &mmb, loc..n);
            let elements = [loc.to_be_bytes()];
            let reconstructed = proof
                .reconstruct_root(&mut hasher, &elements, Location::new(loc))
                .unwrap();
            assert_eq!(reconstructed, root, "n={n}: newest peak range failed");
        }
    }

    #[test]
    fn test_full_range() {
        // Full range proof: all elements provided, no siblings needed.
        for n in 1u64..=32 {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            let proof = build_proof(&mut hasher, &mmb, 0..n);
            let elements: Vec<_> = (0..n).map(|i| i.to_be_bytes()).collect();
            let reconstructed = proof
                .reconstruct_root(&mut hasher, &elements, Location::new(0))
                .unwrap();
            assert_eq!(reconstructed, root, "n={n}: full range failed");

            // Full range should have 0 digests (no siblings, no folded prefix, no after-peaks).
            assert_eq!(
                proof.digests.len(),
                0,
                "n={n}: full range proof should have 0 digests"
            );
        }
    }

    #[test]
    fn test_no_duplicate_positions() {
        for n in 1u64..=64 {
            let mmb = build_mmb(n);
            let leaves = mmb.leaves();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp = nodes_required_for_range_proof(leaves, loc..loc + 1).unwrap();
                let positions = all_positions(&bp);
                let set: BTreeSet<_> = positions.iter().copied().collect();
                assert_eq!(
                    positions.len(),
                    set.len(),
                    "n={n}, loc={loc}: duplicate positions"
                );
            }
        }
    }

    #[test]
    fn test_multi_proof() {
        for n in 2u64..=32 {
            let mmb = build_mmb(n);
            let leaves = mmb.leaves();

            let locs = [Location::new(0)];
            let result = nodes_required_for_multi_proof(leaves, &locs);
            assert!(result.is_ok(), "n={n}: {result:?}");

            if n >= 3 {
                let locs = [Location::new(0), Location::new(n - 1)];
                let result = nodes_required_for_multi_proof(leaves, &locs);
                assert!(result.is_ok(), "n={n}: {result:?}");

                let union = result.unwrap();
                for loc in &locs {
                    let single = nodes_required_for_range_proof(leaves, *loc..*loc + 1).unwrap();
                    let positions = all_positions(&single);
                    for pos in &positions {
                        assert!(union.contains(pos), "n={n}: missing {pos} for loc={loc}");
                    }
                }
            }
        }
    }

    #[test]
    fn test_last_element_proof_size_is_two() {
        // Build a large MMB, then grow it in increments, each time proving the last element. The
        // folded-prefix optimization means the proof should always be small: at most 1 folded
        // prefix + 0 after-peaks + at most one sibling in the containing tree.
        let mut hasher = H::new();
        let mut mmb = DirtyMmb::new();
        for i in 0u64..1000 {
            mmb.add(&mut hasher, &i.to_be_bytes());
        }
        let mut n = 1000u64;

        while n <= 5000 {
            let clean = mmb.merkleize(&mut hasher, None);
            let leaves = clean.leaves();
            let root = *clean.root();

            let loc = n - 1;
            let bp = nodes_required_for_range_proof(leaves, Location::new(loc)..Location::new(n))
                .unwrap();

            // The newest peak has height 0 (N odd) or 1 (N even), so at most 1 sibling. All
            // preceding peaks fold into 1 digest. After-peaks is 0 (nothing newer). So the proof
            // has at most 2 digests: 1 folded prefix + 1 sibling.
            let total_digests = usize::from(!bp.fold_prefix.is_empty()) + bp.fetch_nodes.len();
            assert!(
                total_digests <= 2,
                "n={n}: expected <= 2 digests, got {total_digests} (fold_prefix={}, fetch_nodes={})",
                bp.fold_prefix.len(),
                bp.fetch_nodes.len(),
            );

            // Verify the proof actually works.
            let proof = build_proof(&mut hasher, &clean, loc..n);
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    &loc.to_be_bytes(),
                    Location::new(loc),
                    &root,
                ),
                "n={n}: verification failed"
            );

            // Convert back to dirty and grow by 100 elements.
            mmb = clean.into_dirty();
            for i in n..n + 100 {
                mmb.add(&mut hasher, &i.to_be_bytes());
            }
            n += 100;
        }
    }

    #[test]
    fn test_proof_after_pruning() {
        // Build a large MMB, then prune 10 leaves at a time. After each prune, verify
        // that we can generate and verify a proof for every retained element.
        let mut hasher = H::new();
        let mut mmb = DirtyMmb::new();
        let n = 1000u64;
        for i in 0..n {
            mmb.add(&mut hasher, &i.to_be_bytes());
        }
        let mut mmb = mmb.merkleize(&mut hasher, None);
        let root = *mmb.root();

        let mut pruned_locs = 0u64;
        while pruned_locs + 50 < n {
            // Prune 50 more leaves.
            let prune_loc = pruned_locs + 50;
            let prune_pos = Position::try_from(Location::new(prune_loc)).unwrap();
            mmb.prune_to_pos(prune_pos).unwrap();
            pruned_locs = prune_loc;

            // Root must be unchanged after pruning.
            assert_eq!(
                *mmb.root(),
                root,
                "root changed after pruning to loc {prune_loc}"
            );

            // Verify proof for every retained element.
            for loc_idx in pruned_locs..n {
                let loc = Location::new(loc_idx);
                let proof = mmb
                    .range_proof(&mut hasher, loc..loc + 1)
                    .unwrap_or_else(|e| {
                        panic!("pruned_to={pruned_locs}, loc={loc_idx}: proof gen failed: {e}")
                    });
                assert!(
                    proof
                        .verify_element_inclusion(&mut hasher, &loc_idx.to_be_bytes(), loc, &root,),
                    "pruned_to={pruned_locs}, loc={loc_idx}: verification failed"
                );
            }
        }
    }

    #[test]
    fn test_every_element_contributes_to_root() {
        // For a range proof, flipping any single element must cause verification to fail.
        // This confirms every element is consumed and hashed during reconstruction.
        for n in [8u64, 13, 20, 32] {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            // Test a range that spans at least 2 peaks for thorough coverage.
            let start = 1;
            let end = n - 1;
            let proof = build_proof(&mut hasher, &mmb, start..end);
            let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();

            // Valid elements verify.
            assert!(
                proof.verify_range_inclusion(&mut hasher, &elements, Location::new(start), &root),
                "n={n}: valid range should verify"
            );

            // Flipping one byte in each element must cause failure.
            for flip_idx in 0..elements.len() {
                let mut tampered = elements.clone();
                tampered[flip_idx][0] ^= 0xFF;
                assert!(
                    !proof.verify_range_inclusion(
                        &mut hasher,
                        &tampered,
                        Location::new(start),
                        &root,
                    ),
                    "n={n}: tampered element at index {flip_idx} should not verify"
                );
            }
        }
    }

    #[test]
    fn test_tampered_proof_digests_rejected() {
        // Flipping any bit in any proof digest must cause verification to fail.
        for n in [8u64, 13, 20, 32] {
            let mmb = build_mmb(n);
            let mut hasher = H::new();
            let root = *mmb.root();

            // Single-element proof.
            for loc_idx in [0, n / 2, n - 1] {
                let proof = build_proof(&mut hasher, &mmb, loc_idx..loc_idx + 1);
                let element = loc_idx.to_be_bytes();
                let loc = Location::new(loc_idx);

                // Valid proof verifies.
                assert!(proof.verify_element_inclusion(&mut hasher, &element, loc, &root));

                // Flip one bit in each digest.
                for digest_idx in 0..proof.digests.len() {
                    let mut tampered = proof.clone();
                    tampered.digests[digest_idx].0[0] ^= 1;
                    assert!(
                        !tampered.verify_element_inclusion(&mut hasher, &element, loc, &root),
                        "n={n}, loc={loc_idx}: tampered digest[{digest_idx}] should not verify"
                    );
                }
            }
        }
    }

    #[test]
    fn test_element_count_mismatch_rejected() {
        let mmb = build_mmb(10);
        let mut hasher = H::new();
        let root = *mmb.root();

        let proof = build_proof(&mut hasher, &mmb, 3..4);

        // Wrong element count never verifies against the real root.
        let too_many: Vec<_> = (3u64..6).map(|i| i.to_be_bytes()).collect();
        assert!(!proof.verify_range_inclusion(&mut hasher, &too_many, Location::new(3), &root,));

        // Zero elements is rejected outright.
        let result = proof.reconstruct_root(&mut hasher, &[] as &[[u8; 8]], Location::new(3));
        assert!(matches!(result, Err(ReconstructionError::MissingElements)));
    }

    #[test]
    fn test_empty_proof_verifies_empty_tree() {
        let mut hasher = H::new();
        let mmb = CleanMmb::new(&mut hasher);
        let root = *mmb.root();
        let proof = Proof::<D>::default();

        // Empty proof should verify against the empty MMB root.
        assert!(proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[&[u8]],
            Location::new(0),
            &root,
        ));

        // Non-zero start_loc with empty elements should fail.
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[&[u8]],
            Location::new(1),
            &root,
        ));

        // Empty proof should not verify against a non-empty MMB root.
        let non_empty_mmb = build_mmb(5);
        let non_empty_root = *non_empty_mmb.root();
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[&[u8]],
            Location::new(0),
            &non_empty_root,
        ));
    }

    #[test]
    fn test_error_cases() {
        let mmb = build_mmb(10);
        let leaves = mmb.leaves();

        // Empty range.
        let result = nodes_required_for_range_proof(leaves, Location::new(3)..Location::new(3));
        assert!(matches!(result, Err(Error::Empty)));

        // Out of bounds.
        let result = nodes_required_for_range_proof(leaves, Location::new(0)..Location::new(11));
        assert!(matches!(result, Err(Error::RangeOutOfBounds(_))));

        // Empty locations.
        let result = nodes_required_for_multi_proof(leaves, &[]);
        assert!(matches!(result, Err(Error::Empty)));
    }
}
