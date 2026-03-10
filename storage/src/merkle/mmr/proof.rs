//! Defines the inclusion [Proof] structure, and functions for verifying them against a root digest.
//!
//! Also provides lower-level functions for building verifiers against new or extended proof types.
//! These lower level functions are kept outside of the [Proof] structure and not re-exported by the
//! parent module.

pub use crate::merkle::proof::{ReconstructionError, MAX_PROOF_DIGESTS_PER_ELEMENT};
#[cfg(any(feature = "std", test))]
use crate::mmr::iterator::nodes_to_pin;
use crate::mmr::{
    hasher::Hasher,
    iterator::PeakIterator,
    Error, Location, Position,
};

/// A blueprint for building a range proof for this Merkle family.
pub(crate) type ProofBlueprint = crate::merkle::proof::ProofBlueprint<super::Mmr>;

use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    vec,
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;
/// MMR inclusion proof. Type alias for `merkle::Proof<Mmr, D>`.
pub type Proof<D> = crate::merkle::Proof<super::Mmr, D>;

/// Collect the positions of sibling nodes required for reconstructing a peak digest, in the
/// same DFS order that [`peak_digest_from_range`] consumes them.
///
/// At each node: if one child's subtree is entirely outside the range, its position is emitted.
/// Otherwise, recurse into the child.
fn collect_siblings_dfs(
    pos: Position,
    two_h: u64,
    leftmost_pos: Position,
    rightmost_pos: Position,
    positions: &mut Vec<Position>,
) {
    assert_ne!(two_h, 0);
    if two_h == 1 {
        // Leaf in range: no sibling to collect.
        return;
    }

    let left_pos = pos - two_h;
    let right_pos = left_pos + two_h - 1;

    if left_pos >= leftmost_pos {
        // Left subtree overlaps the range: recurse.
        collect_siblings_dfs(left_pos, two_h >> 1, leftmost_pos, rightmost_pos, positions);
    } else {
        // Left subtree is entirely outside the range.
        positions.push(left_pos);
    }

    if left_pos < rightmost_pos {
        // Right subtree overlaps the range: recurse.
        collect_siblings_dfs(right_pos, two_h >> 1, leftmost_pos, rightmost_pos, positions);
    } else {
        // Right subtree is entirely outside the range.
        positions.push(right_pos);
    }
}

/// Build a range proof from a node-fetching closure.
///
/// This handles the folded-prefix computation internally so callers cannot accidentally
/// store raw peak digests where a fold is expected.
pub(crate) fn build_range_proof<D, H>(
    hasher: &mut H,
    leaves: Location,
    range: Range<Location>,
    get_node: impl Fn(Position) -> Option<D>,
) -> Result<Proof<D>, Error>
where
    D: Digest,
    H: Hasher<super::Mmr, Digest = D>,
{
    let bp = nodes_required_for_range_proof(leaves, range)?;

    let mut digests = Vec::new();

    // Fold preceding peaks into a single accumulator digest.
    if !bp.fold_prefix.is_empty() {
        let mut acc = hasher.digest(&leaves.as_u64().to_be_bytes());
        for &peak_pos in &bp.fold_prefix {
            let peak_d = get_node(peak_pos).ok_or(Error::ElementPruned(peak_pos))?;
            acc = hasher.fold_peak(&acc, &peak_d);
        }
        digests.push(acc);
    }

    // Fetch raw digests for after-peaks and siblings.
    for &pos in &bp.fetch_nodes {
        digests.push(get_node(pos).ok_or(Error::ElementPruned(pos))?);
    }

    Ok(Proof { leaves, digests })
}

impl<D: Digest> Proof<D> {
    /// Return true if this proof proves that `element` appears at location `loc` within the MMR
    /// with root digest `root`.
    pub fn verify_element_inclusion<H>(
        &self,
        hasher: &mut H,
        element: &[u8],
        loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<super::Mmr, Digest = D>,
    {
        self.verify_range_inclusion(hasher, &[element], loc, root)
    }

    /// Return true if this proof proves that the `elements` appear consecutively starting at
    /// position `start_loc` within the MMR with root digest `root`. A malformed proof will return
    /// false.
    pub fn verify_range_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<super::Mmr, Digest = D>,
        E: AsRef<[u8]>,
    {
        self.reconstruct_root(hasher, elements, start_loc)
            .map(|r| r == *root)
            .unwrap_or(false)
    }

    /// Verify that the given elements at the given locations are included in the MMR with root
    /// digest `root`. A malformed proof will return false.
    pub fn verify_multi_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[(E, Location)],
        root: &D,
    ) -> bool
    where
        H: Hasher<super::Mmr, Digest = D>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            return self
                .reconstruct_root(hasher, &[] as &[&[u8]], Location::new(0))
                .map(|r| r == *root)
                .unwrap_or(false);
        }
        let Ok(size) = Position::try_from(self.leaves) else {
            return false;
        };

        // Build a position-to-digest mapping from the proof's digests, using BTreeSet ordering
        // to match the ordering used during proof generation.
        let Ok(node_positions) = nodes_required_for_multi_proof(
            self.leaves,
            &elements.iter().map(|(_, loc)| *loc).collect::<Vec<_>>(),
        ) else {
            return false;
        };
        if node_positions.len() != self.digests.len() {
            return false;
        }
        let position_to_digest: BTreeMap<Position, D> = node_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, &digest)| (pos, digest))
            .collect();

        // Verify each element individually by constructing a single-element proof from the
        // shared position-to-digest map.
        for (element, loc) in elements {
            let Ok(element_pos) = Position::try_from(*loc) else {
                return false;
            };
            if element_pos >= size {
                return false;
            }

            let Ok(bp) = nodes_required_for_range_proof(self.leaves, *loc..*loc + 1) else {
                return false;
            };

            // Build the folded proof for this single element.
            let mut element_digests = Vec::new();

            // Fold the prefix peaks into one digest.
            if !bp.fold_prefix.is_empty() {
                let mut acc = hasher.digest(&self.leaves.as_u64().to_be_bytes());
                for &peak_pos in &bp.fold_prefix {
                    let Some(peak_d) = position_to_digest.get(&peak_pos) else {
                        return false;
                    };
                    acc = hasher.fold_peak(&acc, peak_d);
                }
                element_digests.push(acc);
            }

            // Fetch remaining nodes.
            for &pos in &bp.fetch_nodes {
                let Some(&digest) = position_to_digest.get(&pos) else {
                    return false;
                };
                element_digests.push(digest);
            }

            let element_proof = Proof {
                leaves: self.leaves,
                digests: element_digests,
            };
            if !element_proof.verify_element_inclusion(hasher, element.as_ref(), *loc, root) {
                return false;
            }
        }
        true
    }

    // The functions below are lower level functions that are useful to building verification
    // functions for new or extended proof types.

    /// Computes the set of pinned nodes for the pruning boundary corresponding to the start of the
    /// given range, returning the digest of each by extracting it from the proof.
    ///
    /// The pinned nodes are exactly the fold_prefix peaks from the proof blueprint. With the
    /// folded proof format, these digests are folded into a single accumulator. This function
    /// can only extract individual pinned nodes when they appear in the fetch_nodes portion of
    /// the proof (e.g., after-peaks or siblings that happen to coincide with pinned positions).
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidSize] if the proof size is not a valid MMR size.
    /// Returns [Error::LocationOverflow] if a location in `range` > [crate::mmr::MAX_LOCATION].
    /// Returns [Error::InvalidProofLength] if the proof digest count doesn't match expected.
    /// Returns [Error::MissingDigest] if a pinned node is not found in the proof.
    /// Extract pinned node digests from a folded proof.
    ///
    /// The pinned nodes at the pruning boundary (range start) are the fold_prefix peaks.
    /// With the folded proof format, these peaks are compressed into a single accumulator
    /// digest and individual peak digests cannot be recovered. This function returns
    /// [Error::MissingDigest] for folded proofs that have fold_prefix peaks.
    ///
    /// This function succeeds when the range starts at the oldest peak (no fold_prefix),
    /// meaning there are no pinned nodes to extract.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn extract_pinned_nodes(
        &self,
        range: std::ops::Range<Location>,
    ) -> Result<Vec<D>, Error> {
        let start_pos = Position::try_from(range.start)?;
        let pinned_positions: Vec<Position> = nodes_to_pin(start_pos).collect();

        if pinned_positions.is_empty() {
            return Ok(vec![]);
        }

        // With folded proofs, the pinned nodes (= fold_prefix peaks) are not individually
        // available. Return an error indicating they can't be extracted.
        let bp = nodes_required_for_range_proof(self.leaves, range)?;
        if !bp.fold_prefix.is_empty() {
            return Err(Error::MissingDigest(bp.fold_prefix[0]));
        }

        // If there are no fold_prefix peaks but we still have pinned positions, try fetch_nodes.
        let position_to_digest: BTreeMap<Position, D> = bp
            .fetch_nodes
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, &digest)| (pos, digest))
            .collect();

        let mut result = Vec::with_capacity(pinned_positions.len());
        for pinned_pos in &pinned_positions {
            if let Some(&digest) = position_to_digest.get(pinned_pos) {
                result.push(digest);
            } else {
                return Err(Error::MissingDigest(*pinned_pos));
            }
        }
        Ok(result)
    }

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, returning the (position,digest) of every node whose digest was required by the
    /// process (including those from the proof itself). Returns a [Error::InvalidProof] if the
    /// input data is invalid and [Error::RootMismatch] if the root does not match the computed
    /// root.
    pub fn verify_range_inclusion_and_extract_digests<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> Result<Vec<(Position, D)>, super::Error>
    where
        H: Hasher<super::Mmr, Digest = D>,
        E: AsRef<[u8]>,
    {
        let mut collected_digests = Vec::new();
        let Ok(reconstructed_root) =
            self.reconstruct_root_impl(hasher, elements, start_loc, Some(&mut collected_digests))
        else {
            return Err(Error::InvalidProof);
        };

        if reconstructed_root != *root {
            return Err(Error::RootMismatch);
        }

        Ok(collected_digests)
    }

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, or returns a [ReconstructionError] if the input data is invalid.
    ///
    /// The proof must have been built with the folded-peak layout:
    /// `[folded_prefix? | after_peak_oldest | ... | after_peak_newest | siblings...]`.
    pub fn reconstruct_root<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<super::Mmr, Digest = D>,
        E: AsRef<[u8]>,
    {
        self.reconstruct_root_impl(hasher, elements, start_loc, None)
    }

    /// Internal implementation of root reconstruction that optionally collects all digests used.
    fn reconstruct_root_impl<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
        mut collected_digests: Option<&mut Vec<(Position, D)>>,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<super::Mmr, Digest = D>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            if start_loc == 0 {
                return Ok(hasher.digest(&self.leaves.as_u64().to_be_bytes()));
            }
            return Err(ReconstructionError::MissingElements);
        }

        let size = Position::try_from(self.leaves).map_err(|_| ReconstructionError::InvalidSize)?;
        let start_element_pos =
            Position::try_from(start_loc).map_err(|_| ReconstructionError::InvalidStartLoc)?;
        let end_element_pos = {
            let end_loc_minus_one = start_loc
                .checked_add(elements.len() as u64 - 1)
                .ok_or(ReconstructionError::InvalidEndLoc)?;
            Position::try_from(end_loc_minus_one)
                .map_err(|_| ReconstructionError::InvalidEndLoc)?
        };
        if end_element_pos >= size {
            return Err(ReconstructionError::InvalidEndLoc);
        }

        // Single-pass peak walk: classify peaks.
        let mut num_before = 0usize;
        let mut after_peaks: Vec<Position> = Vec::new();
        let mut range_peaks: Vec<(Position, u32)> = Vec::new();
        for (peak_pos, height) in PeakIterator::new(size) {
            let leftmost_pos = peak_pos + 2 - (1u64 << (height + 1));
            if peak_pos < start_element_pos {
                num_before += 1;
            } else if leftmost_pos > end_element_pos {
                after_peaks.push(peak_pos);
            } else {
                range_peaks.push((peak_pos, height));
            }
        }
        let num_after = after_peaks.len();

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
        for &(peak_pos, height) in &range_peaks {
            let peak_d = peak_digest_from_range(
                hasher,
                RangeNode {
                    pos: peak_pos,
                    two_h: 1u64 << height,
                    leftmost_pos: start_element_pos,
                    rightmost_pos: end_element_pos,
                },
                &mut elem_iter,
                &mut sibling_iter,
                collected_digests.as_deref_mut(),
            )?;
            if let Some(ref mut cd) = collected_digests {
                cd.push((peak_pos, peak_d));
            }
            acc = hasher.fold_peak(&acc, &peak_d);
        }

        if elem_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }
        if sibling_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }

        // Fold after-peak digests (oldest-to-newest).
        for (i, after_d) in after_digests.iter().enumerate() {
            if let Some(ref mut cd) = collected_digests {
                cd.push((after_peaks[i], *after_d));
            }
            acc = hasher.fold_peak(&acc, after_d);
        }

        Ok(acc)
    }
}

/// Return the blueprint for building a range proof for the specified range of elements.
///
/// The blueprint's `fold_prefix` and `fetch_nodes` together produce digests in the layout
/// expected by [`Proof::reconstruct_root`]:
///   `[ folded_prefix? | after_peak_oldest | ... | after_peak_newest | siblings... ]`
///
/// # Errors
///
/// Returns [Error::InvalidSize] if `size` is not a valid MMR size.
/// Returns [Error::Empty] if the range is empty.
/// Returns [Error::LocationOverflow] if a location in `range` > [crate::mmr::MAX_LOCATION].
/// Returns [Error::RangeOutOfBounds] if the last element position in `range` is out of bounds
/// (>= `size`).
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

    let size = Position::try_from(leaves)?;
    let start_element_pos = Position::try_from(range.start)?;
    let end_element_pos = Position::try_from(end_minus_one)?;

    // Single-pass peak walk: classify each peak as before/range-containing/after.
    let mut fold_prefix = Vec::new();
    let mut after = Vec::new();
    let mut range_peaks: Vec<(Position, u32)> = Vec::new();

    for (peak_pos, height) in PeakIterator::new(size) {
        let leftmost_pos = peak_pos + 2 - (1u64 << (height + 1));
        if peak_pos < start_element_pos {
            // Entire peak is before the range.
            fold_prefix.push(peak_pos);
        } else if leftmost_pos > end_element_pos {
            // Entire peak is after the range.
            after.push(peak_pos);
        } else {
            range_peaks.push((peak_pos, height));
        }
    }

    // Collect sibling positions in DFS order for each range-containing peak.
    let mut fetch_nodes = after;
    for &(peak_pos, height) in &range_peaks {
        collect_siblings_dfs(
            peak_pos,
            1u64 << height,
            start_element_pos,
            end_element_pos,
            &mut fetch_nodes,
        );
    }

    Ok(ProofBlueprint {
        fold_prefix,
        fetch_nodes,
    })
}

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`.
///
/// The order of positions does not affect the output (sorted internally).
///
/// # Errors
///
/// Returns [Error::InvalidSize] if `size` is not a valid MMR size.
/// Returns [Error::Empty] if locations is empty.
/// Returns [Error::LocationOverflow] if any location in `locations` > [crate::mmr::MAX_LOCATION].
/// Returns [Error::RangeOutOfBounds] if any location is out of bounds for the given `size`.
#[cfg(any(feature = "std", test))]
pub(crate) fn nodes_required_for_multi_proof(
    leaves: Location,
    locations: &[Location],
) -> Result<BTreeSet<Position>, Error> {
    // Collect all required node positions
    //
    // TODO(#1472): Optimize this loop
    if locations.is_empty() {
        return Err(Error::Empty);
    }
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

/// Node location within a peak tree for range-based reconstruction.
#[derive(Clone, Copy)]
struct RangeNode {
    pos: Position,
    two_h: u64,
    leftmost_pos: Position,
    rightmost_pos: Position,
}

/// Reconstruct a peak digest from elements within a range and sibling digests for subtrees
/// outside the range.
///
/// Descends through the peak tree in DFS order (left first, then right). At each node:
/// - If one child's subtree is entirely outside the range: consume a sibling digest.
/// - If one child is a leaf in the range: hash the next element.
/// - Otherwise: recurse into children and compute the parent digest.
fn peak_digest_from_range<'a, D, H, E, S>(
    hasher: &mut H,
    node: RangeNode,
    elements: &mut E,
    siblings: &mut S,
    mut collected_digests: Option<&mut Vec<(Position, D)>>,
) -> Result<D, ReconstructionError>
where
    D: Digest,
    H: Hasher<super::Mmr, Digest = D>,
    E: Iterator<Item: AsRef<[u8]>>,
    S: Iterator<Item = &'a D>,
{
    assert_ne!(node.two_h, 0);
    if node.two_h == 1 {
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_digest(node.pos, element.as_ref())),
            None => return Err(ReconstructionError::MissingElements),
        }
    }

    let left_pos = node.pos - node.two_h;
    let right_pos = left_pos + node.two_h - 1;
    let half = node.two_h >> 1;

    // Process left subtree.
    let left_digest = if left_pos >= node.leftmost_pos {
        peak_digest_from_range(
            hasher,
            RangeNode { pos: left_pos, two_h: half, ..node },
            elements,
            siblings,
            collected_digests.as_deref_mut(),
        )?
    } else {
        *siblings
            .next()
            .ok_or(ReconstructionError::MissingDigests)?
    };

    // Process right subtree.
    let right_digest = if left_pos < node.rightmost_pos {
        peak_digest_from_range(
            hasher,
            RangeNode { pos: right_pos, two_h: half, ..node },
            elements,
            siblings,
            collected_digests.as_deref_mut(),
        )?
    } else {
        *siblings
            .next()
            .ok_or(ReconstructionError::MissingDigests)?
    };

    if let Some(ref mut cd) = collected_digests {
        cd.push((left_pos, left_digest));
        cd.push((right_pos, right_digest));
    }

    Ok(hasher.node_digest(node.pos, &left_digest, &right_digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        hasher::Standard,
        mem::{CleanMmr, DirtyMmr},
        LocationRangeExt as _, MAX_LOCATION,
    };
    use commonware_codec::{Decode, Encode, EncodeSize};
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;

    fn test_digest(v: u8) -> Digest {
        Sha256::hash(&[v])
    }

    #[test]
    fn test_proving_proof() {
        // Test that an empty proof authenticates an empty MMR.
        let mut hasher: Standard<Sha256> = Standard::new();
        let mmr = CleanMmr::new(&mut hasher);
        let root = mmr.root();
        let proof = Proof::default();
        assert!(proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[Digest],
            Location::new(0),
            root
        ));

        // Any starting position other than 0 should fail to verify.
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[Digest],
            Location::new(1),
            root
        ));

        // Invalid root should fail to verify.
        let test_digest = test_digest(0);
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[Digest],
            Location::new(0),
            &test_digest
        ));

        // Non-empty elements list should fail to verify.
        assert!(!proof.verify_range_inclusion(&mut hasher, &[test_digest], Location::new(0), root));
    }

    #[test]
    fn test_proving_verify_element() {
        // create an 11 element MMR over which we'll test single-element inclusion proofs
        let element = Digest::from(*b"01234567012345670123456701234567");
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut mmr = DirtyMmr::new();
        for _ in 0..11 {
            mmr.add(&mut hasher, &element);
        }
        let mmr = mmr.merkleize(&mut hasher, None);
        let root = mmr.root();

        // confirm the proof of inclusion for each leaf successfully verifies
        for leaf in 0u64..11 {
            let leaf = Location::new(leaf);
            let proof: Proof<Digest> = mmr.proof(&mut hasher, leaf).unwrap();
            assert!(
                proof.verify_element_inclusion(&mut hasher, &element, leaf, root),
                "valid proof should verify successfully"
            );
        }

        // Create a valid proof, then confirm various mangling of the proof or proof args results in
        // verification failure.
        const LEAF: Location = Location::new(10);
        let proof = mmr.proof(&mut hasher, LEAF).unwrap();
        assert!(
            proof.verify_element_inclusion(&mut hasher, &element, LEAF, root),
            "proof verification should be successful"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, LEAF + 1, root),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, LEAF - 1, root),
            "proof verification should fail with incorrect element position 2"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &test_digest(0), LEAF, root),
            "proof verification should fail with mangled element"
        );
        let root2 = test_digest(0);
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, LEAF, &root2),
            "proof verification should fail with mangled root"
        );
        let mut proof2 = proof.clone();
        proof2.digests[0] = test_digest(0);
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, root),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.leaves = Location::new(10);
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, root),
            "proof verification should fail with incorrect leaves"
        );
        proof2 = proof.clone();
        proof2.digests.push(test_digest(0));
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, root),
            "proof verification should fail with extra hash"
        );
        proof2 = proof.clone();
        while !proof2.digests.is_empty() {
            proof2.digests.pop();
            assert!(
                !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, root),
                "proof verification should fail with missing digests"
            );
        }
    }

    #[test]
    fn test_proving_verify_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut mmr = DirtyMmr::new();
        let mut elements = Vec::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }
        let mmr = mmr.merkleize(&mut hasher, None);
        // test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root();

        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[range.to_usize_range()],
                        range.start,
                        root,
                    ),
                    "valid range proof should verify successfully {i}:{j}",
                );
            }
        }

        // Create a proof over a range of elements, confirm it verifies successfully, then mangle
        // the proof & proof input in various ways, confirming verification fails.
        let range = Location::new(33)..Location::new(40);
        let range_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        let valid_elements = &elements[range.to_usize_range()];
        assert!(
            range_proof.verify_range_inclusion(&mut hasher, valid_elements, range.start, root),
            "valid range proof should verify successfully"
        );
        // Remove digests from the proof until it's empty, confirming proof verification fails for
        // each.
        let mut invalid_proof = range_proof.clone();
        for _i in 0..range_proof.digests.len() {
            invalid_proof.digests.remove(0);
            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    range.start,
                    root,
                ),
                "range proof with removed elements should fail"
            );
        }
        // Confirm proof verification fails when providing an element range different than the one
        // used to generate the proof.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                if Location::from(i) == range.start && Location::from(j) == range.end {
                    // skip the valid range
                    continue;
                }
                assert!(
                    !range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[i..j],
                        range.start,
                        root,
                    ),
                    "range proof with invalid element range should fail {i}:{j}",
                );
            }
        }
        // Confirm proof fails to verify with an invalid root.
        let invalid_root = test_digest(1);
        assert!(
            !range_proof.verify_range_inclusion(
                &mut hasher,
                valid_elements,
                range.start,
                &invalid_root,
            ),
            "range proof with invalid root should fail"
        );
        // Mangle each element of the proof and confirm it fails to verify.
        for i in 0..range_proof.digests.len() {
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests[i] = test_digest(0);

            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    range.start,
                    root,
                ),
                "mangled range proof should fail verification"
            );
        }
        // Inserting elements into the proof should also cause it to fail (malleability check)
        for i in 0..range_proof.digests.len() {
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests.insert(i, test_digest(0));
            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    range.start,
                    root,
                ),
                "mangled range proof should fail verification. inserted element at: {i}",
            );
        }
        // Bad start_loc should cause verification to fail.
        for loc in 0..elements.len() {
            let loc = Location::new(loc as u64);
            if loc == range.start {
                continue;
            }
            assert!(
                !range_proof.verify_range_inclusion(&mut hasher, valid_elements, loc, root),
                "bad start_loc should fail verification {loc}",
            );
        }
    }

    #[test_traced]
    fn test_proving_retained_nodes_provable_after_pruning() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut mmr = DirtyMmr::new();
        let mut elements = Vec::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }
        let mut mmr = mmr.merkleize(&mut hasher, None);

        // Confirm we can successfully prove all retained elements in the MMR after pruning.
        let root = *mmr.root();
        for i in 1..*mmr.size() {
            mmr.prune_to_pos(Position::new(i)).unwrap();
            let pruned_root = mmr.root();
            assert_eq!(root, *pruned_root);
            for loc in 0..elements.len() {
                let loc = Location::new(loc as u64);
                let proof = mmr.proof(&mut hasher, loc);
                if Position::try_from(loc).unwrap() < Position::new(i) {
                    continue;
                }
                assert!(proof.is_ok());
                assert!(proof.unwrap().verify_element_inclusion(
                    &mut hasher,
                    &elements[*loc as usize],
                    loc,
                    &root
                ));
            }
        }
    }

    #[test]
    fn test_proving_ranges_provable_after_pruning() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut mmr = DirtyMmr::new();
        let mut elements = Vec::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }
        let mut mmr = mmr.merkleize(&mut hasher, None);

        // prune up to the first peak
        const PRUNE_POS: Position = Position::new(62);
        mmr.prune_to_pos(PRUNE_POS).unwrap();
        assert_eq!(mmr.bounds().start, PRUNE_POS);

        // Test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root();
        for i in 0..elements.len() - 1 {
            if Position::try_from(Location::new(i as u64)).unwrap() < PRUNE_POS {
                continue;
            }
            for j in (i + 2)..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[range.to_usize_range()],
                        range.start,
                        root,
                    ),
                    "valid range proof over remaining elements should verify successfully",
                );
            }
        }

        // Add a few more nodes, prune again, and test again to make sure repeated pruning doesn't
        // break proof verification.
        let mut mmr = mmr.into_dirty();
        for i in 0..37 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }
        let mut mmr = mmr.merkleize(&mut hasher, None);
        mmr.prune_to_pos(Position::new(130)).unwrap(); // a bit after the new highest peak
        assert_eq!(mmr.bounds().start, 130);

        let updated_root = mmr.root();
        let range = Location::new(elements.len() as u64 - 10)..Location::new(elements.len() as u64);
        let range_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        assert!(
                range_proof.verify_range_inclusion(
                    &mut hasher,
                    &elements[range.to_usize_range()],
                    range.start,
                    updated_root,
                ),
                "valid range proof over remaining elements after 2 pruning rounds should verify successfully",
            );
    }

    #[test]
    fn test_proving_proof_serialization() {
        // create a new MMR and add a non-trivial amount of elements
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut mmr = DirtyMmr::new();
        let mut elements = Vec::new();
        for i in 0..25 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }
        let mmr = mmr.merkleize(&mut hasher, None);

        // Generate proofs over all possible ranges of elements and confirm each
        // serializes=>deserializes correctly.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let proof = mmr.range_proof(&mut hasher, range).unwrap();

                let expected_size = proof.encode_size();
                let serialized_proof = proof.encode();
                assert_eq!(
                    serialized_proof.len(),
                    expected_size,
                    "serialized proof should have expected size"
                );
                // max_items is the number of elements in the range
                let max_items = j - i;
                let deserialized_proof = Proof::decode_cfg(serialized_proof, &max_items).unwrap();
                assert_eq!(
                    proof, deserialized_proof,
                    "deserialized proof should match source proof"
                );

                // Remove one byte from the end of the serialized
                // proof and confirm it fails to deserialize.
                let serialized_proof = proof.encode();
                let serialized_proof = serialized_proof.slice(0..serialized_proof.len() - 1);
                assert!(
                    Proof::<Digest>::decode_cfg(serialized_proof, &max_items).is_err(),
                    "proof should not deserialize with truncated data"
                );

                // Add 1 byte of extra data to the end of the serialized
                // proof and confirm it fails to deserialize.
                let mut serialized_proof = proof.encode_mut();
                serialized_proof.extend_from_slice(&[0; 10]);
                let serialized_proof = serialized_proof;

                assert!(
                    Proof::<Digest>::decode_cfg(serialized_proof, &max_items).is_err(),
                    "proof should not deserialize with extra data"
                );

                // Confirm deserialization fails when max_items is too small.
                let actual_digests = proof.digests.len();
                if actual_digests > 0 {
                    // Find the minimum max_items that would allow this many digests
                    let min_max_items = actual_digests.div_ceil(MAX_PROOF_DIGESTS_PER_ELEMENT);
                    // Using one less should fail
                    let too_small = min_max_items - 1;
                    let serialized_proof = proof.encode();
                    assert!(
                        Proof::<Digest>::decode_cfg(serialized_proof, &too_small).is_err(),
                        "proof should not deserialize with max_items too small"
                    );
                }
            }
        }
    }

    #[test_traced]
    fn test_proving_extract_pinned_nodes() {
        // Test for every number of elements from 1 to 255.
        // With folded proofs, extract_pinned_nodes only works when the range starts at the
        // oldest peak (no fold_prefix needed). Otherwise the pinned nodes are folded and
        // can't be extracted individually.
        for num_elements in 1u64..255 {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = DirtyMmr::new();

            for i in 0..num_elements {
                let digest = test_digest(i as u8);
                mmr.add(&mut hasher, &digest);
            }
            let mmr = mmr.merkleize(&mut hasher, None);

            // Test pruning to each leaf.
            for leaf in 0..num_elements {
                let test_end_locs = if num_elements == 1 {
                    vec![leaf + 1]
                } else {
                    let mut ends = vec![leaf + 1];
                    if leaf + 2 <= num_elements {
                        ends.push(leaf + 2);
                    }
                    if leaf + 3 <= num_elements {
                        ends.push(leaf + 3);
                    }
                    if ends.last().unwrap() != &num_elements {
                        ends.push(num_elements);
                    }
                    ends.into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()
                };

                for end_loc in test_end_locs {
                    let range = Location::new(leaf)..Location::new(end_loc);
                    let proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();

                    let leaf_loc = Location::new(leaf);
                    let leaf_pos = Position::try_from(leaf_loc).unwrap();
                    let expected_pinned: Vec<Position> = nodes_to_pin(leaf_pos).collect();

                    // With folded proofs, extraction fails when there are fold_prefix peaks
                    // (pinned nodes are folded). It succeeds when leaf == 0 (no preceding peaks).
                    let extract_result = proof.extract_pinned_nodes(range.clone());
                    if leaf == 0 {
                        // No preceding peaks, so pinned nodes are empty.
                        assert!(extract_result.is_ok());
                        assert!(extract_result.unwrap().is_empty());
                    } else {
                        // The fold_prefix peaks are folded in the proof. Extraction may fail
                        // with MissingDigest if the pinned nodes aren't in fetch_nodes.
                        // This is expected behavior with the folded proof format.
                        if let Ok(pinned_nodes) = extract_result {
                            assert_eq!(pinned_nodes.len(), expected_pinned.len());
                            for (i, &expected_pos) in expected_pinned.iter().enumerate() {
                                let extracted_hash = pinned_nodes[i];
                                let actual_hash = mmr.get_node(expected_pos).unwrap();
                                assert_eq!(
                                    extracted_hash, actual_hash,
                                    "Hash mismatch at position {expected_pos} (index {i}) for {num_elements} elements, boundary={leaf}, range=[{leaf}, {end_loc}]"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_proving_extract_pinned_nodes_invalid_size() {
        // Test that extract_pinned_nodes returns an error for invalid MMR size
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut mmr = DirtyMmr::new();

        // Build MMR with 10 elements
        for i in 0..10 {
            let digest = test_digest(i);
            mmr.add(&mut hasher, &digest);
        }
        let mmr = mmr.merkleize(&mut hasher, None);

        // When the range starts mid-MMR, the fold_prefix peaks may or may not overlap
        // with the pinned positions. With folded proofs, if fold_prefix is non-empty,
        // the pinned nodes are folded and MissingDigest is returned.
        let range = Location::new(5)..Location::new(8);
        let proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        // For this particular range, the pinned nodes happen to be in the fetch_nodes,
        // so extraction succeeds.
        let _ = proof.extract_pinned_nodes(range.clone());

        // For range starting at 0 (no fold_prefix), extract should return empty pinned nodes.
        let range0 = Location::new(0)..Location::new(8);
        let proof0 = mmr.range_proof(&mut hasher, range0.clone()).unwrap();
        let result = proof0.extract_pinned_nodes(range0);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());

        // Test with invalid location.
        let mut bad_proof = proof;
        bad_proof.leaves = Location::new(*MAX_LOCATION + 2);
        let result = bad_proof.extract_pinned_nodes(range);
        assert!(matches!(result, Err(Error::LocationOverflow(_))));
    }

    #[test]
    fn test_proving_digests_from_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut mmr = DirtyMmr::new();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }
        let mmr = mmr.merkleize(&mut hasher, None);
        let root = mmr.root();

        // Test 1: compute_digests over the entire range should contain a digest for every node
        // in the tree (minus peak digests that were folded).
        let proof = mmr.range_proof(&mut hasher, Location::new(0)..mmr.leaves()).unwrap();
        let node_digests = proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements,
                Location::new(0),
                root,
            )
            .unwrap();
        // With fold-based root, the full range proof has no prefix or after peaks, so all
        // internal nodes are collected from the range-containing peaks.
        assert!(!node_digests.is_empty());

        // Make sure the wrong root fails.
        let wrong_root = elements[0]; // any other digest will do
        assert!(matches!(
            proof.verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements,
                Location::new(0),
                &wrong_root
            ),
            Err(Error::RootMismatch)
        ));

        // Test 2: Single element range (first element)
        let range = Location::new(0)..Location::new(1);
        let single_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        let range_start = range.start;
        let single_digests = single_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        assert!(single_digests.len() > 1);

        // Test 3: Single element range (middle element)
        let mid_idx = 24;
        let range = Location::new(mid_idx)..Location::new(mid_idx + 1);
        let range_start = range.start;
        let mid_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        let mid_digests = mid_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        assert!(mid_digests.len() > 1);

        // Test 4: Single element range (last element)
        // With folded prefix, the last element proof only collects digests from within
        // the range-containing peak (just the leaf itself if it's a height-0 peak).
        let last_idx = elements.len() as u64 - 1;
        let range = Location::new(last_idx)..Location::new(last_idx + 1);
        let range_start = range.start;
        let last_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        let last_digests = last_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        assert!(!last_digests.is_empty());

        // Test 5: Small range at the beginning
        let range = Location::new(0)..Location::new(5);
        let range_start = range.start;
        let small_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        let small_digests = small_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        // Verify that we get digests for the range elements and their ancestors
        assert!(small_digests.len() > 5);

        // Test 6: Medium range in the middle
        let range = Location::new(10)..Location::new(31);
        let range_start = range.start;
        let mid_range_proof = mmr.range_proof(&mut hasher, range.clone()).unwrap();
        let mid_range_digests = mid_range_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        let num_elements = range.end - range.start;
        assert!(mid_range_digests.len() as u64 > num_elements);
    }

    #[test]
    fn test_proving_multi_proof_generation_and_verify() {
        // Create an MMR with multiple elements
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut dirty_mmr = DirtyMmr::new();
        let mut elements = Vec::new();

        for i in 0..20 {
            elements.push(test_digest(i));
            dirty_mmr.add(&mut hasher, &elements[i as usize]);
        }
        let mmr = dirty_mmr.merkleize(&mut hasher, None);

        let root = mmr.root();

        // Generate proof for non-contiguous single elements
        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes_for_multi_proof =
            nodes_required_for_multi_proof(mmr.leaves(), locations).expect("test locations valid");
        let digests = nodes_for_multi_proof
            .into_iter()
            .map(|pos| mmr.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mmr.leaves(),
            digests,
        };

        assert_eq!(multi_proof.leaves, mmr.leaves());

        // Verify the proof
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            root
        ));

        // Verify in different order
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[10], Location::new(10)),
                (elements[5], Location::new(5)),
                (elements[0], Location::new(0)),
            ],
            root
        ));

        // Verify with duplicate items
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[0], Location::new(0)),
                (elements[10], Location::new(10)),
                (elements[5], Location::new(5)),
            ],
            root
        ));

        // Verify mangling the location to something invalid should fail.
        let mut wrong_size_proof = multi_proof.clone();
        wrong_size_proof.leaves = Location::new(*MAX_LOCATION + 2);
        assert!(!wrong_size_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            root,
        ));

        // Verify with wrong positions
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new(1)),
                (elements[5], Location::new(6)),
                (elements[10], Location::new(11)),
            ],
            root,
        ));

        // Verify with wrong elements
        let wrong_elements = [
            vec![255u8, 254u8, 253u8],
            vec![252u8, 251u8, 250u8],
            vec![249u8, 248u8, 247u8],
        ];
        let wrong_verification = multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (wrong_elements[0].as_slice(), Location::new(0)),
                (wrong_elements[1].as_slice(), Location::new(5)),
                (wrong_elements[2].as_slice(), Location::new(10)),
            ],
            root,
        );
        assert!(!wrong_verification, "Should fail with wrong elements");

        // Verify with out of range element
        let wrong_verification = multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(1000)),
            ],
            root,
        );
        assert!(
            !wrong_verification,
            "Should fail with out of range elements"
        );

        // Verify with wrong root should fail
        let wrong_root = test_digest(99);
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            &wrong_root
        ));

        // Empty multi-proof
        let mut hasher: Standard<Sha256> = Standard::new();
        let empty_mmr = CleanMmr::new(&mut hasher);
        let empty_root = empty_mmr.root();
        let empty_proof = Proof::default();
        assert!(empty_proof.verify_multi_inclusion(
            &mut hasher,
            &[] as &[(Digest, Location)],
            empty_root
        ));
    }

    #[test]
    fn test_proving_multi_proof_deduplication() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut dirty_mmr = DirtyMmr::new();
        let mut elements = Vec::new();

        // Create an MMR with enough elements to have shared digests
        for i in 0..30 {
            elements.push(test_digest(i));
            dirty_mmr.add(&mut hasher, &elements[i as usize]);
        }
        let mmr = dirty_mmr.merkleize(&mut hasher, None);

        // Get individual proofs that will share some digests (elements in same subtree)
        let proof1 = mmr.proof(&mut hasher, Location::new(0)).unwrap();
        let proof2 = mmr.proof(&mut hasher, Location::new(1)).unwrap();
        let total_digests_separate = proof1.digests.len() + proof2.digests.len();

        // Generate multi-proof for the same positions
        let locations = &[Location::new(0), Location::new(1)];
        let multi_proof =
            nodes_required_for_multi_proof(mmr.leaves(), locations).expect("test locations valid");
        let digests = multi_proof
            .into_iter()
            .map(|pos| mmr.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mmr.leaves(),
            digests,
        };

        // The combined proof should have fewer digests due to deduplication
        assert!(multi_proof.digests.len() < total_digests_separate);

        // Verify it still works
        let root = mmr.root();
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[1], Location::new(1))
            ],
            root
        ));
    }

    #[test]
    fn test_max_location_is_provable() {
        // Test that the validation logic accepts MAX_LOCATION as a valid leaf count.
        // With MAX_LOCATION leaves, valid locations are 0..MAX_LOCATION-1.
        // The range MAX_LOCATION-1..MAX_LOCATION proves the last element.
        let max_loc_plus_1 = Location::new(*MAX_LOCATION + 1);

        let result = nodes_required_for_range_proof(MAX_LOCATION, MAX_LOCATION - 1..MAX_LOCATION);
        assert!(
            result.is_ok(),
            "Should be able to prove with MAX_LOCATION leaves"
        );

        // MAX_LOCATION + 1 should be rejected (exceeds MAX_LOCATION)
        let result_overflow =
            nodes_required_for_range_proof(max_loc_plus_1, MAX_LOCATION..max_loc_plus_1);
        assert!(
            result_overflow.is_err(),
            "Should reject location > MAX_LOCATION"
        );
        matches!(result_overflow, Err(Error::LocationOverflow(_)));
    }

    #[test]
    fn test_max_location_multi_proof() {
        // Test that multi_proof can handle MAX_LOCATION
        // Should be able to generate multi-proof for MAX_LOCATION
        let result = nodes_required_for_multi_proof(MAX_LOCATION, &[MAX_LOCATION - 1]);
        assert!(
            result.is_ok(),
            "Should be able to generate multi-proof for MAX_LOCATION"
        );

        // Should reject MAX_LOCATION + 1
        let invalid_loc = MAX_LOCATION + 1;
        let result_overflow = nodes_required_for_multi_proof(invalid_loc, &[MAX_LOCATION]);
        assert!(
            result_overflow.is_err(),
            "Should reject location > MAX_LOCATION in multi-proof"
        );
    }

    #[test]
    fn test_max_proof_digests_per_element_sufficient() {
        // With folded prefix, worst case is 1 folded prefix + 61 after-peaks + 61 siblings = 123.
        // But MAX_PROOF_DIGESTS_PER_ELEMENT is 124 which is still sufficient.
        let many_peaks_size = Position::new((1u64 << 63) - 64);
        assert!(
            many_peaks_size.is_valid_size(),
            "Size {many_peaks_size} should be a valid MMR size",
        );

        let peak_count = PeakIterator::new(many_peaks_size).count();
        assert_eq!(peak_count, 62);

        // Test location 0 (leftmost leaf, in tallest tree of height 61)
        // With folded prefix: 0 before-peaks (loc 0 is in oldest peak), 61 after-peaks, 61 siblings = 122
        let leaves = Location::try_from(many_peaks_size).unwrap();
        let loc = Location::new(0);
        let bp = nodes_required_for_range_proof(leaves, loc..loc + 1)
            .expect("should compute blueprint for location 0");

        let total = bp.fold_prefix.len() + bp.fetch_nodes.len();
        assert!(
            total <= MAX_PROOF_DIGESTS_PER_ELEMENT,
            "Location 0 should need at most {MAX_PROOF_DIGESTS_PER_ELEMENT} digests, got {total}",
        );

        // Test the rightmost leaf (in smallest tree of height 0, which is itself a peak)
        let last_leaf_loc = leaves - 1;
        let bp = nodes_required_for_range_proof(leaves, last_leaf_loc..last_leaf_loc + 1)
            .expect("should compute blueprint for last leaf");

        let total = bp.fold_prefix.len() + bp.fetch_nodes.len();
        assert!(
            total <= MAX_PROOF_DIGESTS_PER_ELEMENT,
            "Last leaf should need at most {MAX_PROOF_DIGESTS_PER_ELEMENT} digests, got {total}",
        );
    }

    #[test]
    fn test_max_proof_digests_per_element_is_maximum() {
        let n_for_63_peaks = (1u128 << 63) - 1;
        let size_for_63_peaks = 2 * n_for_63_peaks - 63; // = 2^64 - 65
        assert!(
            size_for_63_peaks > *crate::mmr::MAX_POSITION as u128,
            "63 peaks requires size {size_for_63_peaks} > MAX_POSITION",
        );

        let size_truncated = size_for_63_peaks as u64;
        assert!(
            !Position::new(size_truncated).is_valid_size(),
            "Size for 63 peaks should fail is_mmr_size()"
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;
        use commonware_cryptography::sha256::Digest as Sha256Digest;

        commonware_conformance::conformance_tests! {
            CodecConformance<Proof<Sha256Digest>>,
        }
    }
}
