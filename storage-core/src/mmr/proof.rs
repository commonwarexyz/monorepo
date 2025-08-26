//! Defines the inclusion [Proof] structure, functions for generating them from an MMR, and
//! functions for verifying them against a root digest.
//!
//! ## Historical Proof Generation
//!
//! This module provides both current and historical proof generation capabilities:
//! - [Proof::range_proof] generates proofs against the current MMR state
//! - [Proof::historical_range_proof] generates proofs against historical MMR states
//!
//! Historical proofs are essential for sync operations where we need to prove elements against a
//! past state of the MMR rather than its current state.

use crate::mmr::{
    iterator::{leaf_num_to_pos, leaf_pos_to_num, PathIterator, PeakIterator},
    Digest, Error, Hasher, Mmr,
};
use alloc::{collections::BTreeMap, vec::Vec};

/// Errors that can occur when reconstructing a digest from a proof due to invalid input.
#[derive(Error, Debug)]
pub enum ReconstructionError {
    #[error("missing digests in proof")]
    MissingDigests,
    #[error("extra digests in proof")]
    ExtraDigests,
    #[error("start position is not a leaf")]
    InvalidStartPos,
    #[error("end position exceeds MMR size")]
    InvalidEndPos,
    #[error("missing elements")]
    MissingElements,
}

/// Contains the information necessary for proving the inclusion of an element, or some range of
/// elements, in the MMR from its root digest.
///
/// The `digests` vector contains:
///
/// 1: the digests of each peak corresponding to a mountain containing no elements from the element
/// range being proven in decreasing order of height, followed by:
///
/// 2: the nodes in the remaining mountains necessary for reconstructing their peak digests from the
/// elements within the range, ordered by the position of their parent.
#[derive(Clone, Debug, Eq)]
pub struct Proof {
    /// The total number of nodes in the MMR.
    pub size: u64,
    /// The digests necessary for proving the inclusion of an element, or range of elements, in the
    /// MMR.
    pub digests: Vec<Digest>,
}

impl PartialEq for Proof {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.digests == other.digests
    }
}

impl Default for Proof {
    /// Create an empty proof. The empty proof will verify only against the root digest of an empty
    /// (`size == 0`) MMR.
    fn default() -> Self {
        Self {
            size: 0,
            digests: Vec::new(),
        }
    }
}

impl Proof {
    /// Return true if `proof` proves that `element` appears at position `element_pos` within the
    /// MMR with root digest `root`.
    pub fn verify_element_inclusion<H>(
        &self,
        hasher: &mut H,
        element: &[u8],
        element_pos: u64,
        root: &Digest,
    ) -> bool
    where
        H: Hasher,
    {
        self.verify_range_inclusion(hasher, &[element], element_pos, root)
    }

    /// Return true if `proof` proves that the `elements` appear consecutively starting at position
    /// `start_element_pos` within the MMR with root digest `root`.
    pub fn verify_range_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_element_pos: u64,
        root: &Digest,
    ) -> bool
    where
        H: Hasher,
        E: AsRef<[u8]>,
    {
        match self.reconstruct_root(hasher, elements, start_element_pos) {
            Ok(reconstructed_root) => *root == reconstructed_root,
            Err(_) => false,
        }
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
        start_element_pos: u64,
        root: &Digest,
    ) -> Result<Vec<(u64, Digest)>, Error>
    where
        H: Hasher,
        E: AsRef<[u8]>,
    {
        let mut collected_digests = Vec::new();
        let Ok(peak_digests) = self.reconstruct_peak_digests(
            hasher,
            elements,
            start_element_pos,
            Some(&mut collected_digests),
        ) else {
            return Err(Error::InvalidProof);
        };

        if hasher.root(self.size, peak_digests.iter()) != *root {
            return Err(Error::RootMismatch);
        }

        Ok(collected_digests)
    }

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, or returns a [ReconstructionError] if the input data is invalid.
    fn reconstruct_root<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_element_pos: u64,
    ) -> Result<Digest, ReconstructionError>
    where
        H: Hasher,
        E: AsRef<[u8]>,
    {
        let peak_digests =
            self.reconstruct_peak_digests(hasher, elements, start_element_pos, None)?;

        Ok(hasher.root(self.size, peak_digests.iter()))
    }

    /// Reconstruct the peak digests of the MMR that produced this proof, returning
    /// [ReconstructionError] if the input data is invalid.  If collected_digests is Some, then all
    /// node digests used in the process will be added to the wrapped vector.
    fn reconstruct_peak_digests<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_element_pos: u64,
        mut collected_digests: Option<&mut Vec<(u64, Digest)>>,
    ) -> Result<Vec<Digest>, ReconstructionError>
    where
        H: Hasher,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            if start_element_pos == 0 {
                return Ok(Vec::new());
            }
            return Err(ReconstructionError::MissingElements);
        }
        let Some(start_leaf) = leaf_pos_to_num(start_element_pos) else {
            return Err(ReconstructionError::InvalidStartPos);
        };
        let end_element_pos = if elements.len() == 1 {
            start_element_pos
        } else {
            leaf_num_to_pos(start_leaf + elements.len() as u64 - 1)
        };
        if end_element_pos >= self.size {
            return Err(ReconstructionError::InvalidEndPos);
        }

        let mut proof_digests_iter = self.digests.iter();
        let mut siblings_iter = self.digests.iter().rev();

        // Include peak digests only for trees that have no elements from the range, and keep track
        // of the starting and ending trees of those that do contain some.
        let mut peak_digests: Vec<Digest> = Vec::new();
        let mut proof_digests_used = 0;
        let mut elements_iter = elements.iter();
        for (peak_pos, height) in PeakIterator::new(self.size) {
            let leftmost_pos = peak_pos + 2 - (1 << (height + 1));
            if peak_pos >= start_element_pos && leftmost_pos <= end_element_pos {
                let hash = peak_digest_from_range(
                    hasher,
                    RangeInfo {
                        pos: peak_pos,
                        two_h: 1 << height,
                        leftmost_pos: start_element_pos,
                        rightmost_pos: end_element_pos,
                    },
                    &mut elements_iter,
                    &mut siblings_iter,
                    collected_digests.as_deref_mut(),
                )?;
                peak_digests.push(hash);
                if let Some(ref mut collected_digests) = collected_digests {
                    collected_digests.push((peak_pos, hash));
                }
            } else if let Some(hash) = proof_digests_iter.next() {
                proof_digests_used += 1;
                peak_digests.push(*hash);
                if let Some(ref mut collected_digests) = collected_digests {
                    collected_digests.push((peak_pos, *hash));
                }
            } else {
                return Err(ReconstructionError::MissingDigests);
            }
        }

        if elements_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }
        if let Some(next_sibling) = siblings_iter.next() {
            if proof_digests_used == 0 || *next_sibling != self.digests[proof_digests_used - 1] {
                return Err(ReconstructionError::ExtraDigests);
            }
        }

        Ok(peak_digests)
    }

    /// Return the list of pruned (pos < `start_pos`) node positions that are still required for
    /// proving any retained node.
    ///
    /// This set consists of every pruned node that is either (1) a peak, or (2) has no descendent
    /// in the retained section, but its immediate parent does. (A node meeting condition (2) can be
    /// shown to always be the left-child of its parent.)
    ///
    /// This set of nodes does not change with the MMR's size, only the pruning boundary. For a
    /// given pruning boundary that happens to be a valid MMR size, one can prove that this set is
    /// exactly the set of peaks for an MMR whose size equals the pruning boundary. If the pruning
    /// boundary is not a valid MMR size, then the set corresponds to the peaks of the largest MMR
    /// whose size is less than the pruning boundary.
    pub fn nodes_to_pin(start_pos: u64) -> impl Iterator<Item = u64> {
        PeakIterator::new(PeakIterator::to_nearest_size(start_pos)).map(|(pos, _)| pos)
    }

    /// Return the list of node positions required by the range proof for the specified range of
    /// elements, inclusive of both endpoints.
    pub fn nodes_required_for_range_proof(
        size: u64,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Vec<u64> {
        let mut positions = Vec::new();

        // Find the mountains that contain no elements from the range. The peaks of these mountains
        // are required to prove the range, so they are added to the result.
        let mut start_tree_with_element = (u64::MAX, 0);
        let mut end_tree_with_element = (u64::MAX, 0);
        let mut peak_iterator = PeakIterator::new(size);
        while let Some(peak) = peak_iterator.next() {
            if start_tree_with_element.0 == u64::MAX && peak.0 >= start_element_pos {
                // Found the first tree to contain an element in the range
                start_tree_with_element = peak;
                if peak.0 >= end_element_pos {
                    // Start and end tree are the same
                    end_tree_with_element = peak;
                    continue;
                }
                for peak in peak_iterator.by_ref() {
                    if peak.0 >= end_element_pos {
                        // Found the last tree to contain an element in the range
                        end_tree_with_element = peak;
                        break;
                    }
                }
            } else {
                // Tree is outside the range, its peak is thus required.
                positions.push(peak.0);
            }
        }
        assert!(start_tree_with_element.0 != u64::MAX);
        assert!(end_tree_with_element.0 != u64::MAX);

        // Include the positions of any left-siblings of each node on the path from peak to
        // leftmost-leaf, and right-siblings for the path from peak to rightmost-leaf. These are
        // added in order of decreasing parent position.
        let left_path_iter = PathIterator::new(
            start_element_pos,
            start_tree_with_element.0,
            start_tree_with_element.1,
        );

        let mut siblings = Vec::new();
        if start_element_pos == end_element_pos {
            // For the (common) case of a single element range, the right and left path are the
            // same so no need to process each independently.
            siblings.extend(left_path_iter);
        } else {
            let right_path_iter = PathIterator::new(
                end_element_pos,
                end_tree_with_element.0,
                end_tree_with_element.1,
            );
            // filter the right path for right siblings only
            siblings.extend(right_path_iter.filter(|(parent_pos, pos)| *parent_pos == *pos + 1));
            // filter the left path for left siblings only
            siblings.extend(left_path_iter.filter(|(parent_pos, pos)| *parent_pos != *pos + 1));

            // If the range spans more than one tree, then the digests must already be in the correct
            // order. Otherwise, we enforce the desired order through sorting.
            if start_tree_with_element.0 == end_tree_with_element.0 {
                siblings.sort_by(|a, b| b.0.cmp(&a.0));
            }
        }
        positions.extend(siblings.into_iter().map(|(_, pos)| pos));
        positions
    }

    /// Return an inclusion proof for the specified range of elements, inclusive of both endpoints.
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    pub fn range_proof(
        mmr: &Mmr,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof, Error> {
        Self::historical_range_proof(mmr, mmr.size(), start_element_pos, end_element_pos)
    }

    /// Analogous to range_proof but for a previous database state.
    /// Specifically, the state when the MMR had `size` elements.
    pub fn historical_range_proof(
        mmr: &Mmr,
        size: u64,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof, Error> {
        assert!(start_element_pos <= end_element_pos);
        assert!(start_element_pos < mmr.size());
        assert!(end_element_pos < mmr.size());

        let mut digests: Vec<Digest> = Vec::new();
        let positions =
            Self::nodes_required_for_range_proof(size, start_element_pos, end_element_pos);
        let hash_results = positions.iter().map(|pos| mmr.get_node(*pos));

        for (i, hash_result) in hash_results.into_iter().enumerate() {
            match hash_result {
                Some(hash) => digests.push(hash),
                None => return Err(Error::ElementPruned(positions[i])),
            };
        }

        Ok(Proof { size, digests })
    }

    /// Extract the hashes of all nodes that should be pinned at the given pruning boundary
    /// from a proof that proves a range starting at that boundary.
    ///
    /// # Arguments
    /// * `start_element_pos` - Start of the proven range (must equal pruning_boundary)
    /// * `end_element_pos` - End of the proven range
    ///
    /// # Returns
    /// A Vec of digest values for all nodes in `nodes_to_pin(pruning_boundary)`,
    /// in the same order as returned by `nodes_to_pin` (decreasing height order)
    pub fn extract_pinned_nodes(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Vec<Digest>, Error> {
        // Get the positions of all nodes that should be pinned.
        let pinned_positions: Vec<u64> = Self::nodes_to_pin(start_element_pos).collect();

        // Get all positions required for the proof.
        let required_positions =
            Self::nodes_required_for_range_proof(self.size, start_element_pos, end_element_pos);
        if required_positions.len() != self.digests.len() {
            return Err(Error::InvalidProofLength);
        }

        // Happy path: we can extract the pinned nodes directly from the proof.
        // This happens when the `end_element_pos` is the last element in the MMR.
        if pinned_positions
            == required_positions[required_positions.len() - pinned_positions.len()..]
        {
            return Ok(self.digests[required_positions.len() - pinned_positions.len()..].to_vec());
        }

        // Create a mapping from position to digest.
        let position_to_digest: BTreeMap<u64, Digest> = required_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, &digest)| (pos, digest))
            .collect();

        // Extract the pinned nodes in the same order as nodes_to_pin.
        let mut result = Vec::with_capacity(pinned_positions.len());
        for pinned_pos in pinned_positions {
            let Some(&digest) = position_to_digest.get(&pinned_pos) else {
                return Err(Error::MissingDigest(pinned_pos));
            };
            result.push(digest);
        }
        Ok(result)
    }
}

/// Information about the current range of nodes being traversed.
struct RangeInfo {
    pos: u64,           // current node position in the tree
    two_h: u64,         // 2^height of the current node
    leftmost_pos: u64,  // leftmost leaf in the tree to be traversed
    rightmost_pos: u64, // rightmost leaf in the tree to be traversed
}

fn peak_digest_from_range<'a, H, E, S>(
    hasher: &mut H,
    range_info: RangeInfo,
    elements: &mut E,
    sibling_digests: &mut S,
    mut collected_digests: Option<&mut Vec<(u64, Digest)>>,
) -> Result<Digest, ReconstructionError>
where
    H: Hasher,
    E: Iterator<Item: AsRef<[u8]>>,
    S: Iterator<Item = &'a Digest>,
{
    assert_ne!(range_info.two_h, 0);
    if range_info.two_h == 1 {
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_digest(range_info.pos, element.as_ref())),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }

    let mut left_digest: Option<Digest> = None;
    let mut right_digest: Option<Digest> = None;

    let left_pos = range_info.pos - range_info.two_h;
    let right_pos = left_pos + range_info.two_h - 1;
    if left_pos >= range_info.leftmost_pos {
        // Descend left
        let digest = peak_digest_from_range(
            hasher,
            RangeInfo {
                pos: left_pos,
                two_h: range_info.two_h >> 1,
                leftmost_pos: range_info.leftmost_pos,
                rightmost_pos: range_info.rightmost_pos,
            },
            elements,
            sibling_digests,
            collected_digests.as_deref_mut(),
        )?;
        left_digest = Some(digest);
    }
    if left_pos < range_info.rightmost_pos {
        // Descend right
        let digest = peak_digest_from_range(
            hasher,
            RangeInfo {
                pos: right_pos,
                two_h: range_info.two_h >> 1,
                leftmost_pos: range_info.leftmost_pos,
                rightmost_pos: range_info.rightmost_pos,
            },
            elements,
            sibling_digests,
            collected_digests.as_deref_mut(),
        )?;
        right_digest = Some(digest);
    }

    if left_digest.is_none() {
        match sibling_digests.next() {
            Some(hash) => left_digest = Some(*hash),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }
    if right_digest.is_none() {
        match sibling_digests.next() {
            Some(hash) => right_digest = Some(*hash),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }

    if let Some(ref mut collected_digests) = collected_digests {
        collected_digests.push((left_pos, left_digest.unwrap()));
        collected_digests.push((right_pos, right_digest.unwrap()));
    }

    Ok(hasher.node_digest(
        range_info.pos,
        &left_digest.unwrap(),
        &right_digest.unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{hasher::Sha256, iterator::nodes_to_pin, Mmr};
    use alloc::{collections::btree_set::BTreeSet, vec};

    fn test_digest(v: u8) -> Digest {
        [v; 32]
    }

    #[test]
    fn test_proving_empty_proof() {
        // Test that an empty proof authenticates an empty MMR.
        let mmr = Mmr::new();
        let mut hasher: Sha256 = Sha256::new();
        let root = mmr.root(&mut hasher);
        let proof = Proof::default();
        assert!(proof.verify_range_inclusion(&mut hasher, &[] as &[Digest], 0, &root));

        // Any starting position other than 0 should fail to verify.
        assert!(!proof.verify_range_inclusion(&mut hasher, &[] as &[Digest], 1, &root));

        // Invalid root should fail to verify.
        let test_digest = test_digest(0);
        assert!(!proof.verify_range_inclusion(&mut hasher, &[] as &[Digest], 0, &test_digest));

        // Non-empty elements list should fail to verify.
        assert!(!proof.verify_range_inclusion(&mut hasher, &[test_digest], 0, &root));
    }

    #[test]
    fn test_proving_verify_element() {
        // create an 11 element MMR over which we'll test single-element inclusion proofs
        let mut mmr = Mmr::new();
        let element = Digest::from(*b"01234567012345670123456701234567");
        let mut leaves: Vec<u64> = Vec::new();
        let mut hasher: Sha256 = Sha256::new();
        for _ in 0..11 {
            leaves.push(mmr.add(&mut hasher, &element));
        }

        let root = mmr.root(&mut hasher);

        // confirm the proof of inclusion for each leaf successfully verifies
        for leaf in leaves.iter().by_ref() {
            let proof: Proof = mmr.proof(*leaf).unwrap();
            assert!(
                proof.verify_element_inclusion(&mut hasher, &element, *leaf, &root),
                "valid proof should verify successfully"
            );
        }

        // confirm mangling the proof or proof args results in failed validation
        const POS: u64 = 18;
        let proof = mmr.proof(POS).unwrap();
        assert!(
            proof.verify_element_inclusion(&mut hasher, &element, POS, &root),
            "proof verification should be successful"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, POS + 1, &root),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, POS - 1, &root),
            "proof verification should fail with incorrect element position 2"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &test_digest(0), POS, &root),
            "proof verification should fail with mangled element"
        );
        let root2 = test_digest(0);
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, POS, &root2),
            "proof verification should fail with mangled root"
        );
        let mut proof2 = proof.clone();
        proof2.digests[0] = test_digest(0);
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.size = 10;
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root),
            "proof verification should fail with incorrect size"
        );
        proof2 = proof.clone();
        proof2.digests.push(test_digest(0));
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root),
            "proof verification should fail with extra hash"
        );
        proof2 = proof.clone();
        while !proof2.digests.is_empty() {
            proof2.digests.pop();
            assert!(
                !proof2.verify_element_inclusion(&mut hasher, &element, 7, &root),
                "proof verification should fail with missing digests"
            );
        }
        proof2 = proof.clone();
        proof2.digests.clear();
        const PEAK_COUNT: usize = 3;
        proof2
            .digests
            .extend(proof.digests[0..PEAK_COUNT - 1].iter().cloned());
        // sneak in an extra hash that won't be used in the computation and make sure it's
        // detected
        proof2.digests.push(test_digest(0));
        proof2
            .digests
            .extend(proof.digests[PEAK_COUNT - 1..].iter().cloned());
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, POS, &root),
            "proof verification should fail with extra hash even if it's unused by the computation"
        );
    }

    #[test]
    fn test_proving_verify_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();
        let mut hasher: Sha256 = Sha256::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }
        // test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root(&mut hasher);

        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let start_pos = element_positions[i];
                let end_pos = element_positions[j];
                let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[i..j + 1],
                        start_pos,
                        &root,
                    ),
                    "valid range proof should verify successfully {i}:{j}",
                );
            }
        }

        // create a test range for which we will mangle data and confirm the proof fails
        let start_index = 33;
        let end_index = 39;
        let start_pos = element_positions[start_index];
        let end_pos = element_positions[end_index];
        let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
        let valid_elements = &elements[start_index..end_index + 1];
        assert!(
            range_proof.verify_range_inclusion(&mut hasher, valid_elements, start_pos, &root),
            "valid range proof should verify successfully"
        );
        let mut invalid_proof = range_proof.clone();
        for _i in 0..range_proof.digests.len() {
            invalid_proof.digests.remove(0);
            assert!(
                !range_proof.verify_range_inclusion(
                    &mut hasher,
                    &[] as &[Digest],
                    start_pos,
                    &root,
                ),
                "range proof with removed elements should fail"
            );
        }
        // confirm proof fails with invalid element digests
        for i in 0..elements.len() {
            for j in i..elements.len() {
                if i == start_index && j == end_index {
                    // skip the valid range
                    continue;
                }
                assert!(
                    !range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[i..j + 1],
                        start_pos,
                        &root,
                    ),
                    "range proof with invalid elements should fail {i}:{j}",
                );
            }
        }
        // confirm proof fails with invalid root
        let invalid_root = test_digest(1);
        assert!(
            !range_proof.verify_range_inclusion(
                &mut hasher,
                valid_elements,
                start_pos,
                &invalid_root,
            ),
            "range proof with invalid root should fail"
        );
        // mangle the proof and confirm it fails
        let mut invalid_proof = range_proof.clone();
        invalid_proof.digests[1] = test_digest(0);
        assert!(
            !invalid_proof.verify_range_inclusion(&mut hasher, valid_elements, start_pos, &root,),
            "mangled range proof should fail verification"
        );
        // inserting elements into the proof should also cause it to fail (malleability check)
        for i in 0..range_proof.digests.len() {
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests.insert(i, test_digest(0));
            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    start_pos,
                    &root,
                ),
                "mangled range proof should fail verification. inserted element at: {i}",
            );
        }
        // removing proof elements should cause verification to fail
        let mut invalid_proof = range_proof.clone();
        for _ in 0..range_proof.digests.len() {
            invalid_proof.digests.remove(0);
            assert!(
                !invalid_proof.verify_range_inclusion(
                    &mut hasher,
                    valid_elements,
                    start_pos,
                    &root,
                ),
                "shortened range proof should fail verification"
            );
        }
        // bad element range should cause verification to fail
        for (i, _) in elements.iter().enumerate() {
            for (j, _) in elements.iter().enumerate() {
                let start_pos2 = element_positions[i];
                if start_pos2 == start_pos {
                    continue;
                }
                assert!(
                    !range_proof.verify_range_inclusion(
                        &mut hasher,
                        valid_elements,
                        start_pos2,
                        &root,
                    ),
                    "bad element range should fail verification {i}:{j}",
                );
            }
        }
    }

    #[test]
    fn test_verification_retained_nodes_provable_after_pruning() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();
        let mut hasher: Sha256 = Sha256::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }

        // Confirm we can successfully prove all retained elements in the MMR after pruning.
        let root = mmr.root(&mut hasher);
        for i in 1..mmr.size() {
            mmr.prune_to_pos(i);
            let pruned_root = mmr.root(&mut hasher);
            assert_eq!(root, pruned_root);
            for (j, pos) in element_positions.iter().enumerate() {
                let proof = mmr.proof(*pos);
                if *pos < i {
                    assert!(proof.is_err());
                } else {
                    assert!(proof.is_ok());
                    assert!(proof.unwrap().verify_element_inclusion(
                        &mut hasher,
                        &elements[j],
                        *pos,
                        &root
                    ));
                }
            }
        }
    }

    #[test]
    fn test_verification_ranges_provable_after_pruning() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();
        let mut hasher: Sha256 = Sha256::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }

        // prune up to the first peak
        mmr.prune_to_pos(62);
        assert_eq!(mmr.oldest_retained_pos().unwrap(), 62);
        for i in 0..elements.len() {
            if element_positions[i] > 62 {
                elements = elements[i..elements.len()].to_vec();
                element_positions = element_positions[i..element_positions.len()].to_vec();
                break;
            }
        }

        // test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root(&mut hasher);
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let start_pos = element_positions[i];
                let end_pos = element_positions[j];
                let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[i..j + 1],
                        start_pos,
                        &root,
                    ),
                    "valid range proof over remaining elements should verify successfully",
                );
            }
        }

        // add a few more nodes, prune again, and test again to make sure repeated pruning works
        for i in 0..37 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }
        mmr.prune_to_pos(130); // a bit after the new highest peak
        assert_eq!(mmr.oldest_retained_pos().unwrap(), 130);

        let updated_root = mmr.root(&mut hasher);
        for i in 0..elements.len() {
            if element_positions[i] >= 130 {
                elements = elements[i..elements.len()].to_vec();
                element_positions = element_positions[i..element_positions.len()].to_vec();
                break;
            }
        }
        let start_pos = element_positions[0];
        let end_pos = *element_positions.last().unwrap();
        let range_proof = mmr.range_proof(start_pos, end_pos).unwrap();
        assert!(
                range_proof.verify_range_inclusion(
                    &mut hasher,
                    &elements,
                        start_pos,
                    &updated_root,
                ),
                "valid range proof over remaining elements after 2 pruning rounds should verify successfully",
            );
    }

    #[test]
    fn test_extract_pinned_nodes() {
        // Test for every number of elements from 1 to 255
        for num_elements in 1u8..255 {
            // Build MMR with the specified number of elements
            let mut mmr = Mmr::new();
            let mut hasher: Sha256 = Sha256::new();
            let mut element_positions = Vec::new();
            for i in 0..num_elements {
                let digest = test_digest(i);
                element_positions.push(mmr.add(&mut hasher, &digest));
            }

            // Test every valid pruning boundary (each element position)
            for &start_pos in &element_positions {
                // Test with a few different end positions to get good coverage
                let test_end_positions = if element_positions.len() == 1 {
                    // Single element case
                    vec![start_pos]
                } else {
                    // Multi-element case: test with various end positions
                    let mut ends = vec![start_pos]; // Single element proof

                    // Add a few more end positions if available
                    let start_idx = element_positions
                        .iter()
                        .position(|&pos| pos == start_pos)
                        .unwrap();
                    if start_idx + 1 < element_positions.len() {
                        ends.push(element_positions[start_idx + 1]);
                    }
                    if start_idx + 2 < element_positions.len() {
                        ends.push(element_positions[start_idx + 2]);
                    }
                    // Always test with the last element if different
                    if *element_positions.last().unwrap() != start_pos {
                        ends.push(*element_positions.last().unwrap());
                    }

                    ends.into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()
                };

                for end_pos in test_end_positions {
                    // Generate proof for the range
                    let proof_result = mmr.range_proof(start_pos, end_pos);
                    let proof = proof_result.unwrap();

                    // Extract pinned nodes
                    let extract_result = proof.extract_pinned_nodes(start_pos, end_pos);
                    assert!(
                            extract_result.is_ok(),
                            "Failed to extract pinned nodes for {num_elements} elements, boundary={start_pos}, range=[{start_pos}, {end_pos}]"
                        );

                    let pinned_nodes = extract_result.unwrap();
                    let expected_pinned: Vec<u64> = nodes_to_pin(start_pos).collect();

                    // Verify count matches expected
                    assert_eq!(
                            pinned_nodes.len(),
                            expected_pinned.len(),
                            "Pinned node count mismatch for {num_elements} elements, boundary={start_pos}, range=[{start_pos}, {end_pos}]"
                        );

                    // Verify extracted hashes match actual node values
                    // The pinned_nodes Vec is in the same order as expected_pinned
                    for (i, &expected_pos) in expected_pinned.iter().enumerate() {
                        let extracted_hash = pinned_nodes[i];
                        let actual_hash = mmr.get_node(expected_pos).unwrap();
                        assert_eq!(
                                extracted_hash, actual_hash,
                                "Hash mismatch at position {expected_pos} (index {i}) for {num_elements} elements, boundary={start_pos}, range=[{start_pos}, {end_pos}]"
                            );
                    }
                }
            }
        }
    }

    #[test]
    fn test_historical_range_proof_basic() {
        // Create an MMR with 5 elements
        let mut mmr = Mmr::new();
        let mut hasher: Sha256 = Sha256::new();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();
        for i in 0..5 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }
        let current_size = mmr.size();
        let current_root = mmr.root(&mut hasher);

        {
            // Historical proof should match regular proof at current size
            let historical_proof = Proof::historical_range_proof(
                &mmr,
                current_size,
                element_positions[0],
                element_positions[2],
            )
            .unwrap();
            let regular_proof = mmr
                .range_proof(element_positions[0], element_positions[2])
                .unwrap();

            assert_eq!(historical_proof.size, current_size);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert!(historical_proof.verify_range_inclusion(
                &mut hasher,
                &elements[0..3],
                element_positions[0],
                &current_root
            ));
        }

        {
            // Historical proof should match regular proof at historical size
            let mut ref_mmr = Mmr::new();
            for elt in elements.iter().take(3) {
                ref_mmr.add(&mut hasher, elt);
            }
            let ref_size = ref_mmr.size();
            let ref_root = ref_mmr.root(&mut hasher);
            let ref_proof = Proof::historical_range_proof(
                &mmr,
                ref_size,
                element_positions[0],
                element_positions[2],
            )
            .unwrap();
            let historical_proof = Proof::historical_range_proof(
                &mmr,
                ref_size,
                element_positions[0],
                element_positions[2],
            )
            .unwrap();

            assert_eq!(ref_proof.size, ref_size);
            assert_eq!(ref_proof.digests, historical_proof.digests);
            assert!(ref_proof.verify_range_inclusion(
                &mut hasher,
                &elements[0..3],
                element_positions[0],
                &ref_root
            ));
        }
    }

    #[test]
    fn test_historical_range_proof_large() {
        // Simulate a sync scenario: server has 1000 operations, client syncs 600-799
        let mut server_mmr = Mmr::new();
        let mut hasher: Sha256 = Sha256::new();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();

        // Add 1000 elements to server
        for i in 0..1000 {
            elements.push(test_digest((i % 256) as u8));
            element_positions.push(server_mmr.add(&mut hasher, elements.last().unwrap()));
        }

        // Want operations 600-799
        let start_loc = 600;
        let end_loc = 799;

        // Create historical MMR state as it would have been after end_loc elements
        let mut ref_mmr = Mmr::new();
        for elt in elements.iter().take(end_loc + 1) {
            ref_mmr.add(&mut hasher, elt);
        }
        let ref_size = ref_mmr.size();
        let ref_root = ref_mmr.root(&mut hasher);

        // Generate proof at historical position
        let historical_proof = Proof::historical_range_proof(
            &server_mmr,
            ref_size,
            element_positions[start_loc],
            element_positions[end_loc],
        )
        .unwrap();

        assert_eq!(historical_proof.size, ref_size);

        // Verify the sync proof
        assert!(historical_proof.verify_range_inclusion(
            &mut hasher,
            &elements[start_loc..=end_loc],
            element_positions[start_loc],
            &ref_root // Compare to historical root
        ));
    }

    #[test]
    fn test_historical_range_proof_singleton() {
        let mut mmr = Mmr::new();
        let mut single_hasher: Sha256 = Sha256::new();
        let element = test_digest(0);
        mmr.add(&mut single_hasher, &element);
        let single_historical_size = mmr.size();
        let single_root = mmr.root(&mut single_hasher);

        let single_element_proof =
            Proof::historical_range_proof(&mmr, single_historical_size, 0, 0).unwrap();

        assert!(single_element_proof.verify_range_inclusion(
            &mut single_hasher,
            &[element],
            0,
            &single_root
        ));
    }

    #[test]
    fn test_verification_digests_from_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();
        let mut hasher: Sha256 = Sha256::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }
        let root = mmr.root(&mut hasher);

        // Test 1: compute_digests over the entire range should contain a digest for every node
        // in the tree, plus one extra for the root.
        let proof = mmr.range_proof(0, mmr.size() - 1).unwrap();
        let mut node_digests = proof
            .verify_range_inclusion_and_extract_digests(&mut hasher, &elements, 0, &root)
            .unwrap();
        assert_eq!(node_digests.len(), mmr.size() as usize);
        node_digests.sort_by_key(|(pos, _)| *pos);
        for (i, (pos, d)) in node_digests.into_iter().enumerate() {
            assert_eq!(pos, i as u64);
            assert_eq!(mmr.get_node(pos).unwrap(), d);
        }
        // Make sure the wrong root fails.
        let wrong_root = elements[0]; // any other digest will do
        assert!(matches!(
            proof.verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements,
                0,
                &wrong_root
            ),
            Err(Error::RootMismatch)
        ));

        // Test 2: Single element range (first element)
        let single_proof = mmr
            .range_proof(element_positions[0], element_positions[0])
            .unwrap();
        let single_digests = single_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[0..1],
                element_positions[0],
                &root,
            )
            .unwrap();
        assert!(single_digests.len() > 1);

        // Test 3: Single element range (middle element)
        let mid_idx = 24;
        let mid_proof = mmr
            .range_proof(element_positions[mid_idx], element_positions[mid_idx])
            .unwrap();
        let mid_digests = mid_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[mid_idx..mid_idx + 1],
                element_positions[mid_idx],
                &root,
            )
            .unwrap();
        assert!(mid_digests.len() > 1);

        // Test 4: Single element range (last element)
        let last_idx = elements.len() - 1;
        let last_proof = mmr
            .range_proof(element_positions[last_idx], element_positions[last_idx])
            .unwrap();
        let last_digests = last_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[last_idx..],
                element_positions[last_idx],
                &root,
            )
            .unwrap();
        assert!(last_digests.len() > 1);

        // Test 5: Small range at the beginning
        let small_proof = mmr
            .range_proof(element_positions[0], element_positions[4])
            .unwrap();
        let small_digests = small_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[0..5],
                element_positions[0],
                &root,
            )
            .unwrap();
        // Verify that we get digests for the range elements and their ancestors
        assert!(small_digests.len() > 5);

        // Test 6: Medium range in the middle
        let mid_start = 10;
        let mid_end = 30;
        let mid_range_proof = mmr
            .range_proof(element_positions[mid_start], element_positions[mid_end])
            .unwrap();
        let mid_range_digests = mid_range_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[mid_start..mid_end + 1],
                element_positions[mid_start],
                &root,
            )
            .unwrap();
        let num_elements = mid_end - mid_start + 1;
        assert!(mid_range_digests.len() > num_elements);
    }
}
