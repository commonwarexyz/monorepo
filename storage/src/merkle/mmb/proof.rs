//! MMB-specific proof construction and verification.
//!
//! Provides functions for building and verifying inclusion proofs against MMB root digests.

use crate::merkle::{
    hasher::Hasher,
    mmb::{
        iterator::{birthed_node_pos, child_leaves, peak_birth_leaf, PeakIterator},
        Error, Family, Location, Position,
    },
    proof::{Proof, ReconstructionError},
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// The maximum number of digests in a proof per element being proven.
///
/// An MMB with 62 peaks requires at most 61 path siblings + 61 peak digests = 122 digests
/// for the left-most leaf in the oldest peak.
pub const MAX_PROOF_DIGESTS_PER_ELEMENT: usize = 122;

impl<D: Digest> Proof<Family, D> {
    /// Return true if this proof proves that `element` appears at location `loc` within the MMB
    /// with root digest `root`.
    pub fn verify_element_inclusion<H>(
        &self,
        hasher: &mut H,
        element: &[u8],
        loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<Family = Family, Digest = D>,
    {
        self.verify_range_inclusion(hasher, &[element], loc, root)
    }

    /// Return true if this proof proves that the `elements` appear consecutively starting at
    /// location `start_loc` within the MMB with root digest `root`.
    pub fn verify_range_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<Family = Family, Digest = D>,
        E: AsRef<[u8]>,
    {
        match self.reconstruct_root(hasher, elements, start_loc) {
            Ok(reconstructed_root) => *root == reconstructed_root,
            Err(_error) => {
                #[cfg(feature = "std")]
                tracing::debug!(error = ?_error, "invalid proof input");
                false
            }
        }
    }

    /// Return true if this proof proves that the elements at the specified locations are included
    /// in the MMB with root digest `root`. A malformed proof will return false.
    ///
    /// The order of the elements does not affect the output.
    pub fn verify_multi_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[(E, Location)],
        root: &D,
    ) -> bool
    where
        H: Hasher<Family = Family, Digest = D>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            return self.leaves == Location::new(0)
                && *root == hasher.root(Location::new(0), core::iter::empty());
        }

        let mut node_positions = BTreeSet::new();
        let mut blueprints = BTreeMap::new();

        for (_, loc) in elements {
            if !loc.is_valid() {
                return false;
            }
            let Ok(bp) = blueprint(self.leaves, *loc..*loc + 1) else {
                return false;
            };
            for &pos in &bp.fold_prefix {
                node_positions.insert(pos);
            }
            for &pos in &bp.fetch_nodes {
                node_positions.insert(pos);
            }
            blueprints.insert(*loc, bp);
        }

        if node_positions.len() != self.digests.len() {
            return false;
        }

        let node_digests: BTreeMap<Position, D> = node_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, digest)| (pos, *digest))
            .collect();

        for (element, loc) in elements {
            let bp = &blueprints[loc];

            let mut digests = Vec::with_capacity(
                if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len(),
            );
            if !bp.fold_prefix.is_empty() {
                let mut acc = *node_digests
                    .get(&bp.fold_prefix[0])
                    .expect("must exist by construction");
                for &pos in &bp.fold_prefix[1..] {
                    let d = node_digests.get(&pos).expect("must exist by construction");
                    acc = hasher.fold(&acc, d);
                }
                digests.push(acc);
            }
            for &pos in &bp.fetch_nodes {
                let d = node_digests.get(&pos).expect("must exist by construction");
                digests.push(*d);
            }
            let proof = Self {
                leaves: self.leaves,
                digests,
            };

            if !proof.verify_element_inclusion(hasher, element.as_ref(), *loc, root) {
                return false;
            }
        }

        true
    }

    /// Reconstruct the root digest from this proof and the given elements.
    ///
    /// `elements` are the leaf values for the range `start_loc..start_loc + elements.len()`.
    pub fn reconstruct_root<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<Family = Family, Digest = D>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            if start_loc == 0 {
                return if self.digests.is_empty() {
                    Ok(hasher.digest(&self.leaves.to_be_bytes()))
                } else {
                    Err(ReconstructionError::ExtraDigests)
                };
            }
            return Err(ReconstructionError::MissingElements);
        }

        let end_loc = start_loc
            .checked_add(elements.len() as u64)
            .ok_or(ReconstructionError::InvalidEndLoc)?;

        // Classify peaks: before range, after range, or containing range elements.
        let size = Position::try_from(self.leaves).map_err(|_| ReconstructionError::InvalidSize)?;
        let mut num_before = 0usize;
        let mut num_after = 0usize;
        let mut range_peaks = Vec::new();
        let mut end_leaf_cursor = self.leaves;
        for (_peak_pos, height) in PeakIterator::new(size) {
            let leaves_in_peak = 1u64 << height;
            let leaf_start = end_leaf_cursor - leaves_in_peak;

            if leaf_start >= end_loc {
                num_after += 1;
            } else if end_leaf_cursor <= start_loc {
                num_before += 1;
            } else {
                let birth_leaf = peak_birth_leaf(end_leaf_cursor - 1, height);
                range_peaks.push((birth_leaf, height, leaf_start));
            }
            end_leaf_cursor = leaf_start;
        }
        // PeakIterator yields newest-to-oldest; reverse for oldest-to-newest fold order.
        range_peaks.reverse();

        // Slice self.digests: [folded_prefix? | after_peaks... | siblings...]
        let prefix_count = usize::from(num_before > 0);
        let sibling_start = prefix_count + num_after;
        if self.digests.len() < sibling_start {
            return Err(ReconstructionError::MissingDigests);
        }
        let after_digests = &self.digests[prefix_count..sibling_start];
        let mut sibling_iter = self.digests[sibling_start..].iter();

        // Fold all peaks into an accumulator (without the leaf count, which is hashed in at the
        // end to prevent malleability via the `leaves` field).
        let mut acc: Option<D> = if num_before > 0 {
            Some(self.digests[0])
        } else {
            None
        };

        // Fold range-containing peaks (reconstructed from elements + siblings).
        let mut elem_iter = elements.iter();
        for &(birth_leaf, height, leaf_start) in &range_peaks {
            let peak_d = reconstruct_peak_from_range(
                hasher,
                birth_leaf,
                height,
                leaf_start,
                start_loc..end_loc,
                &mut elem_iter,
                &mut sibling_iter,
            )?;
            acc = Some(acc.map_or(peak_d, |a| hasher.fold(&a, &peak_d)));
        }

        if elem_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }
        if sibling_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }

        // Fold after-peak digests in oldest-to-newest order (matching the proof layout).
        for after_d in after_digests.iter() {
            acc = Some(acc.map_or(*after_d, |a| hasher.fold(&a, after_d)));
        }

        // Hash the leaf count into the final result.
        Ok(if let Some(peaks_acc) = acc {
            hasher.hash([self.leaves.to_be_bytes().as_slice(), peaks_acc.as_ref()])
        } else {
            hasher.digest(&self.leaves.to_be_bytes())
        })
    }
}

/// Collect the positions of sibling nodes required for reconstructing a peak digest, in the
/// same left-first DFS order that [`reconstruct_peak_from_range`] consumes them.
///
/// At each node: if the subtree is entirely outside the range, its root position is emitted.
/// If it's a leaf in the range, nothing is emitted. Otherwise, recurse left then right.
fn collect_siblings_dfs(
    birth_leaf: Location,
    height: u32,
    leaf_start: Location,
    range: &Range<Location>,
    positions: &mut Vec<Position>,
) {
    let leaves_in_node = 1u64 << height;
    let leaf_end = leaf_start + leaves_in_node;

    if leaf_end <= range.start || leaf_start >= range.end {
        positions.push(birthed_node_pos(birth_leaf, height == 0));
        return;
    }
    if height == 0 {
        return;
    }

    let (left_leaf, right_leaf) = child_leaves(birth_leaf, height);
    let mid = leaf_start + (1u64 << (height - 1));
    collect_siblings_dfs(left_leaf, height - 1, leaf_start, range, positions);
    collect_siblings_dfs(right_leaf, height - 1, mid, range, positions);
}

/// Blueprint for a range proof, separating fold-prefix peaks from nodes that must be fetched.
pub(crate) struct Blueprint {
    /// Peak positions that precede the proven range (to be folded into a single accumulator).
    pub fold_prefix: Vec<Position>,
    /// Node positions to include in the proof: after-peaks followed by DFS siblings.
    pub fetch_nodes: Vec<Position>,
}

/// Return a blueprint for building a range proof over the specified range.
///
/// # Errors
///
/// - Returns [Error::Empty] if the range is empty.
/// - Returns [Error::LocationOverflow] if a location exceeds the valid range.
/// - Returns [Error::RangeOutOfBounds] if the range end exceeds `leaves`.
#[allow(dead_code)]
pub(crate) fn blueprint(leaves: Location, range: Range<Location>) -> Result<Blueprint, Error> {
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

    let size = Position::try_from(leaves)?;
    let n = leaves;

    // Single-pass peak walk: classify each peak.
    // PeakIterator yields newest-to-oldest.
    let mut before = Vec::new();
    let mut after = Vec::new();
    let mut range_peaks = Vec::new();
    let mut end_leaf_cursor = n;
    for (peak_pos, height) in PeakIterator::new(size) {
        let leaves_in_peak = 1u64 << height;
        let leaf_start = end_leaf_cursor - leaves_in_peak;

        if leaf_start >= range.end {
            after.push(peak_pos);
        } else if end_leaf_cursor <= range.start {
            before.push(peak_pos);
        } else {
            let birth_leaf = peak_birth_leaf(end_leaf_cursor - 1, height);
            range_peaks.push((birth_leaf, height, leaf_start));
        }
        end_leaf_cursor = leaf_start;
    }

    // Reverse all from newest-to-oldest to oldest-to-newest.
    before.reverse();
    after.reverse();
    range_peaks.reverse();

    // Build fetch_nodes: after-peaks first, then DFS siblings for each range peak.
    let mut fetch_nodes = Vec::new();
    for &peak_pos in &after {
        fetch_nodes.push(peak_pos);
    }
    for &(birth_leaf, height, leaf_start) in &range_peaks {
        collect_siblings_dfs(birth_leaf, height, leaf_start, &range, &mut fetch_nodes);
    }

    Ok(Blueprint {
        fold_prefix: before,
        fetch_nodes,
    })
}

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`.
///
/// # Errors
///
/// - Returns [Error::Empty] if locations is empty.
/// - Returns [Error::LocationOverflow] if any location exceeds the valid range.
/// - Returns [Error::RangeOutOfBounds] if any location >= `leaves`.
#[allow(dead_code)]
pub(crate) fn nodes_required_for_multi_proof(
    leaves: Location,
    locations: &[Location],
) -> Result<BTreeSet<Position>, Error> {
    if locations.is_empty() {
        return Err(Error::Empty);
    }
    locations.iter().try_fold(BTreeSet::new(), |mut acc, loc| {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(*loc));
        }
        let bp = blueprint(leaves, *loc..*loc + 1)?;
        acc.extend(bp.fold_prefix);
        acc.extend(bp.fetch_nodes);
        Ok(acc)
    })
}

/// Build a range proof from a node-fetching closure.
///
/// # Errors
///
/// - Returns [Error::Empty] if the range is empty.
/// - Returns [Error::LocationOverflow] if a location exceeds the valid range.
/// - Returns [Error::RangeOutOfBounds] if the range end exceeds `leaves`.
/// - Returns [Error::ElementPruned] if any required node is not available via `get_node`.
#[allow(dead_code)]
pub(crate) fn build_range_proof<D, H>(
    hasher: &mut H,
    leaves: Location,
    range: Range<Location>,
    get_node: impl Fn(Position) -> Option<D>,
) -> Result<Proof<Family, D>, Error>
where
    D: Digest,
    H: Hasher<Family = Family, Digest = D>,
{
    let bp = blueprint(leaves, range)?;

    let mut digests =
        Vec::with_capacity(if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len());

    // Fold prefix peaks into a single accumulator (without the leaf count, which is always
    // hashed into the final root independently).
    if !bp.fold_prefix.is_empty() {
        let mut acc = get_node(bp.fold_prefix[0]).ok_or(Error::ElementPruned(bp.fold_prefix[0]))?;
        for &pos in &bp.fold_prefix[1..] {
            let d = get_node(pos).ok_or(Error::ElementPruned(pos))?;
            acc = hasher.fold(&acc, &d);
        }
        digests.push(acc);
    }

    // Append after-peak and sibling digests.
    for &pos in &bp.fetch_nodes {
        digests.push(get_node(pos).ok_or(Error::ElementPruned(pos))?);
    }

    Ok(Proof { leaves, digests })
}

/// Reconstruct a peak digest from elements within a range and sibling digests for subtrees
/// outside the range.
///
/// Descends through the peak tree using `child_leaves` / `birthed_node_pos`. At each node:
/// - If the node is a leaf in the range: hash the next element.
/// - If the node's subtree is entirely outside the range: consume a sibling digest.
/// - Otherwise: recurse into children and compute the node digest.
fn reconstruct_peak_from_range<'a, D, H, E, S>(
    hasher: &mut H,
    birth_leaf: Location,
    height: u32,
    leaf_start: Location,
    range: Range<Location>,
    elements: &mut E,
    siblings: &mut S,
) -> Result<D, ReconstructionError>
where
    D: Digest,
    H: Hasher<Family = Family, Digest = D>,
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
        let pos = birthed_node_pos(birth_leaf, true);
        return Ok(hasher.leaf_digest(pos, elem.as_ref()));
    }

    // Recurse into children.
    let (left_leaf, right_leaf) = child_leaves(birth_leaf, height);
    let mid = leaf_start + (1u64 << (height - 1));

    let left_d = reconstruct_peak_from_range(
        hasher,
        left_leaf,
        height - 1,
        leaf_start,
        range.clone(),
        elements,
        siblings,
    )?;
    let right_d = reconstruct_peak_from_range(
        hasher,
        right_leaf,
        height - 1,
        mid,
        range,
        elements,
        siblings,
    )?;

    let pos = birthed_node_pos(birth_leaf, false);
    Ok(hasher.node_digest(pos, &left_d, &right_d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        hasher::Standard,
        mmb::{iterator::leaf_pos, mem::Mmb, Family},
    };
    use alloc::vec;
    use commonware_cryptography::Sha256;

    type D = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type H = Standard<Family, Sha256>;

    /// Build an in-memory MMB with `n` elements (element i = i.to_be_bytes()).
    fn make_mmb(n: u64) -> (H, Mmb<D>) {
        let mut hasher = H::new();
        let mut mmb = Mmb::new(&mut hasher);
        let changeset = {
            let mut batch = mmb.new_batch();
            for i in 0..n {
                batch.add(&mut hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mut hasher).finalize()
        };
        mmb.apply(changeset).unwrap();
        (hasher, mmb)
    }

    #[test]
    fn test_blueprint_errors() {
        let leaves = Location::new(10);

        // Empty range.
        assert!(matches!(
            blueprint(leaves, Location::new(3)..Location::new(3)),
            Err(Error::Empty)
        ));

        // Out of bounds.
        assert!(matches!(
            blueprint(leaves, Location::new(0)..Location::new(11)),
            Err(Error::RangeOutOfBounds(_))
        ));

        // Empty locations for multi-proof.
        assert!(matches!(
            nodes_required_for_multi_proof(leaves, &[]),
            Err(Error::Empty)
        ));
    }

    #[test]
    fn test_single_element_proof_positions() {
        for n in 1u64..=64 {
            let (_, mmb) = make_mmb(n);
            let leaves = mmb.leaves();
            let size = mmb.size();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp = blueprint(leaves, loc..loc + 1).unwrap();
                let mut positions: Vec<Position> = Vec::new();
                positions.extend(&bp.fold_prefix);
                positions.extend(&bp.fetch_nodes);

                for &pos in &positions {
                    assert!(pos < size, "n={n}, loc={loc}: pos {pos} >= size {size}");
                }
                // Should not contain the element's own leaf position.
                let lp = leaf_pos(loc);
                assert!(
                    !positions.contains(&lp),
                    "n={n}, loc={loc}: should not contain leaf pos {lp}"
                );
            }
        }
    }

    #[test]
    fn test_no_duplicate_positions() {
        for n in 1u64..=64 {
            let (_, mmb) = make_mmb(n);
            let leaves = mmb.leaves();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp = blueprint(leaves, loc..loc + 1).unwrap();
                let mut positions: Vec<Position> = Vec::new();
                positions.extend(&bp.fold_prefix);
                positions.extend(&bp.fetch_nodes);
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
    fn test_single_element_proof_reconstruction() {
        for n in 1u64..=64 {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            for loc_idx in 0..n {
                let proof = mmb
                    .proof(&mut hasher, Location::new(loc_idx))
                    .unwrap_or_else(|e| panic!("n={n}, loc={loc_idx}: build failed: {e:?}"));

                let elements = [loc_idx.to_be_bytes()];
                let start_loc = Location::new(loc_idx);

                let reconstructed = proof
                    .reconstruct_root(&mut hasher, &elements, start_loc)
                    .unwrap_or_else(|e| panic!("n={n}, loc={loc_idx}: reconstruct failed: {e:?}"));
                assert_eq!(reconstructed, root, "n={n}, loc={loc_idx}: root mismatch");
            }
        }
    }

    #[test]
    fn test_range_proof_reconstruction() {
        for n in 2u64..=32 {
            let (mut hasher, mmb) = make_mmb(n);
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
                let proof = mmb
                    .range_proof(&mut hasher, Location::new(start)..Location::new(end))
                    .unwrap_or_else(|e| panic!("n={n}, range={start}..{end}: build failed: {e:?}"));
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
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            for loc_idx in 0..n {
                let proof = mmb.proof(&mut hasher, Location::new(loc_idx)).unwrap();
                let loc = Location::new(loc_idx);

                assert!(
                    proof.verify_element_inclusion(&mut hasher, &loc_idx.to_be_bytes(), loc, &root),
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
    fn test_full_range() {
        for n in 1u64..=32 {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            let proof = mmb
                .range_proof(&mut hasher, Location::new(0)..Location::new(n))
                .unwrap();
            let elements: Vec<_> = (0..n).map(|i| i.to_be_bytes()).collect();
            let reconstructed = proof
                .reconstruct_root(&mut hasher, &elements, Location::new(0))
                .unwrap();
            assert_eq!(reconstructed, root, "n={n}: full range failed");

            // Full range should have 0 digests.
            assert_eq!(
                proof.digests.len(),
                0,
                "n={n}: full range proof should have 0 digests"
            );
        }
    }

    #[test]
    fn test_empty_proof_verifies_empty_tree() {
        let mut hasher = H::new();
        let mmb = Mmb::<D>::new(&mut hasher);
        let root = *mmb.root();
        let proof = Proof::<Family, D>::default();

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
    }

    #[test]
    fn test_every_element_contributes_to_root() {
        for n in [8u64, 13, 20, 32] {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            let start = 1;
            let end = n - 1;
            let proof = mmb
                .range_proof(&mut hasher, Location::new(start)..Location::new(end))
                .unwrap();
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
    fn test_multi_proof_generation_and_verify() {
        let (mut hasher, mmb) = make_mmb(20);
        let root = *mmb.root();

        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes =
            nodes_required_for_multi_proof(mmb.leaves(), locations).expect("valid locations");
        let digests = nodes
            .into_iter()
            .map(|pos| mmb.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mmb.leaves(),
            digests,
        };

        // Verify the proof.
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (0u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &root
        ));

        // Different order should also verify.
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (10u64.to_be_bytes(), Location::new(10)),
                (5u64.to_be_bytes(), Location::new(5)),
                (0u64.to_be_bytes(), Location::new(0)),
            ],
            &root
        ));

        // Wrong elements should fail.
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (99u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &root
        ));

        // Wrong root should fail.
        let wrong_root = hasher.digest(b"wrong");
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (0u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &wrong_root
        ));

        // Empty multi-proof on empty tree.
        let mut hasher2 = H::new();
        let empty_mmb = Mmb::new(&mut hasher2);
        let empty_proof: Proof<Family, D> = Proof::default();
        assert!(empty_proof.verify_multi_inclusion(
            &mut hasher2,
            &[] as &[([u8; 8], Location)],
            empty_mmb.root()
        ));
    }

    #[test]
    fn test_last_element_proof_size_is_two() {
        // An MMB property is that the most recent item always has a small proof
        // (at most 2 digests). Verify this holds as the tree grows.
        let mut hasher = H::new();
        let (_, mut mmb) = make_mmb(1000);
        let mut n = 1000u64;

        while n <= 5000 {
            let leaves = mmb.leaves();
            let root = *mmb.root();

            let loc = n - 1;
            let bp =
                blueprint(leaves, Location::new(loc)..Location::new(n)).unwrap();

            let total_digests =
                usize::from(!bp.fold_prefix.is_empty()) + bp.fetch_nodes.len();
            assert!(
                total_digests <= 2,
                "n={n}: expected <= 2 digests, got {total_digests} \
                 (fold_prefix={}, fetch_nodes={})",
                bp.fold_prefix.len(),
                bp.fetch_nodes.len(),
            );

            // Verify the proof actually works.
            let proof = mmb
                .proof(&mut hasher, Location::new(loc))
                .unwrap();
            assert!(
                proof.verify_element_inclusion(
                    &mut hasher,
                    &loc.to_be_bytes(),
                    Location::new(loc),
                    &root,
                ),
                "n={n}: verification failed"
            );

            // Grow by 100 elements.
            let changeset = {
                let mut batch = mmb.new_batch();
                for i in n..n + 100 {
                    batch.add(&mut hasher, &i.to_be_bytes());
                }
                batch.merkleize(&mut hasher).finalize()
            };
            mmb.apply(changeset).unwrap();
            n += 100;
        }
    }

    #[test]
    fn test_tampered_proof_digests_rejected() {
        for n in [8u64, 13, 20, 32] {
            let (mut hasher, mmb) = make_mmb(n);
            let root = *mmb.root();

            for loc_idx in [0, n / 2, n - 1] {
                let proof = mmb.proof(&mut hasher, Location::new(loc_idx)).unwrap();
                let element = loc_idx.to_be_bytes();
                let loc = Location::new(loc_idx);

                assert!(proof.verify_element_inclusion(&mut hasher, &element, loc, &root));

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
}
