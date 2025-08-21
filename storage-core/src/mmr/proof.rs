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
use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    vec::Vec,
};

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

    /// Return an inclusion proof for the specified positions. This is analogous to range_proof
    /// but supports non-contiguous positions.
    ///
    /// The order of positions does not affect the output (sorted internally).
    pub fn multi_proof(mmr: &Mmr, positions: &[u64]) -> Result<Proof, Error> {
        // If there are no positions, return an empty proof
        if positions.is_empty() {
            return Ok(Proof {
                size: mmr.size(),
                digests: Vec::new(),
            });
        }

        // Collect all required node positions
        //
        // TODO(#1472): Optimize this loop
        let size = mmr.size();
        let node_positions: BTreeSet<_> = positions
            .iter()
            .flat_map(|pos| Self::nodes_required_for_range_proof(size, *pos, *pos))
            .collect();

        let results = node_positions
            .into_iter()
            .map(|pos| (pos, mmr.get_node(pos)));

        // Build the proof, returning error with correct position on pruned nodes
        let mut digests = Vec::with_capacity(results.len());
        for (pos, digest) in results.into_iter() {
            match digest {
                Some(digest) => digests.push(digest),
                None => return Err(Error::ElementPruned(pos)),
            }
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
