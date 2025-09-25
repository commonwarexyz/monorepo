//! Defines the inclusion [Proof] structure, and functions for verifying them against a root digest.
//!
//! Also provides lower-level functions for building verifiers against new or extended proof types.
//! These lower level functions are kept outside of the [Proof] structure and not re-exported by the
//! parent module.

use crate::mmr::{
    hasher::Hasher,
    iterator::{leaf_loc_to_pos, nodes_to_pin, PathIterator, PeakIterator},
    Error,
};
use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    vec,
    vec::Vec,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::{Digest, Hasher as CHasher};
use core::ops::Range;
#[cfg(feature = "std")]
use tracing::debug;

/// Errors that can occur when reconstructing a digest from a proof due to invalid input.
#[derive(Error, Debug)]
pub enum ReconstructionError {
    #[error("missing digests in proof")]
    MissingDigests,
    #[error("extra digests in proof")]
    ExtraDigests,
    #[error("end location is out of bounds")]
    InvalidEndLoc,
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
pub struct Proof<D: Digest> {
    /// The total number of nodes in the MMR for MMR proofs, though other authenticated data
    /// structures may override the meaning of this field. For example the authenticated
    /// [crate::mmr::bitmap::Bitmap] stores the number of bits in the bitmap within this field.
    pub size: u64,
    /// The digests necessary for proving the inclusion of an element, or range of elements, in the
    /// MMR.
    pub digests: Vec<D>,
}

impl<D: Digest> PartialEq for Proof<D> {
    fn eq(&self, other: &Self) -> bool {
        self.size == other.size && self.digests == other.digests
    }
}

impl<D: Digest> EncodeSize for Proof<D> {
    fn encode_size(&self) -> usize {
        UInt(self.size).encode_size() + self.digests.encode_size()
    }
}

impl<D: Digest> Write for Proof<D> {
    fn write(&self, buf: &mut impl BufMut) {
        // Write the number of nodes in the MMR as a varint
        UInt(self.size).write(buf);

        // Write the digests
        self.digests.write(buf);
    }
}

impl<D: Digest> Read for Proof<D> {
    /// The maximum number of digests in the proof.
    type Cfg = usize;

    fn read_cfg(buf: &mut impl Buf, max_len: &Self::Cfg) -> Result<Self, commonware_codec::Error> {
        // Read the number of nodes in the MMR
        let size = UInt::<u64>::read(buf)?.into();

        // Read the digests
        let range = ..=max_len;
        let digests = Vec::<D>::read_range(buf, range)?;
        Ok(Proof { size, digests })
    }
}

impl<D: Digest> Default for Proof<D> {
    /// Create an empty proof. The empty proof will verify only against the root digest of an empty
    /// (`size == 0`) MMR.
    fn default() -> Self {
        Self {
            size: 0,
            digests: vec![],
        }
    }
}

impl<D: Digest> Proof<D> {
    /// Return true if this proof proves that `element` appears at location `loc` within the MMR
    /// with root digest `root`.
    pub fn verify_element_inclusion<I, H>(
        &self,
        hasher: &mut H,
        element: &[u8],
        loc: u64,
        root: &D,
    ) -> bool
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
    {
        self.verify_range_inclusion(hasher, &[element], loc, root)
    }

    /// Return true if this proof proves that the `elements` appear consecutively starting at
    /// position `start_loc` within the MMR with root digest `root`.
    pub fn verify_range_inclusion<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: u64,
        root: &D,
    ) -> bool
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
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
    /// in the MMR with the root digest `root`.
    ///
    /// The order of the elements does not affect the output.
    pub fn verify_multi_inclusion<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[(E, u64)],
        root: &D,
    ) -> bool
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        // Empty proof is valid for an empty MMR
        if elements.is_empty() {
            return self.size == 0 && *root == hasher.root(0, core::iter::empty());
        }

        // Single pass to collect all required positions with deduplication
        let mut node_positions = BTreeSet::new();
        let mut nodes_required = BTreeMap::new();
        for (_, loc) in elements {
            let required = nodes_required_for_range_proof(self.size, *loc..(*loc + 1));
            for req_pos in &required {
                node_positions.insert(*req_pos);
            }
            nodes_required.insert(*loc, required);
        }

        // Verify we have the exact number of digests needed
        if node_positions.len() != self.digests.len() {
            return false;
        }

        // Build position to digest mapping once
        let node_digests: BTreeMap<u64, D> = node_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, digest)| (pos, *digest))
            .collect();

        // Verify each element by reconstructing its path
        for (element, loc) in elements {
            // Get required positions for this element
            let required = &nodes_required[loc];

            // Build proof with required digests
            let mut digests = Vec::with_capacity(required.len());
            for req_pos in required {
                // There must exist a digest for each required position (by
                // construction of `node_digests`)
                let digest = node_digests
                    .get(req_pos)
                    .expect("missing digest for required position");
                digests.push(*digest);
            }
            let proof = Proof {
                size: self.size,
                digests,
            };

            // Verify the proof
            if !proof.verify_element_inclusion(hasher, element.as_ref(), *loc, root) {
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
    /// # Arguments
    /// * `range` - The start and end locations of the proven range, where start is also used as the
    ///   pruning boundary.
    ///
    /// # Returns
    /// A Vec of digests for all nodes in `nodes_to_pin(pruning_boundary)`, in the same order as
    /// returned by `nodes_to_pin` (decreasing height order)
    pub(crate) fn extract_pinned_nodes(
        &self,
        range: std::ops::Range<u64>,
    ) -> Result<Vec<D>, Error> {
        // Get the positions of all nodes that should be pinned.
        let start_pos = leaf_loc_to_pos(range.start);
        let pinned_positions: Vec<u64> = nodes_to_pin(start_pos).collect();

        // Get all positions required for the proof.
        let required_positions = nodes_required_for_range_proof(self.size, range);
        if required_positions.len() != self.digests.len() {
            #[cfg(feature = "std")]
            debug!(
                digests_len = self.digests.len(),
                required_positions_len = required_positions.len(),
                "Proof digest count doesn't match required positions",
            );
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
        let position_to_digest: BTreeMap<u64, D> = required_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, &digest)| (pos, digest))
            .collect();

        // Extract the pinned nodes in the same order as nodes_to_pin.
        let mut result = Vec::with_capacity(pinned_positions.len());
        for pinned_pos in pinned_positions {
            let Some(&digest) = position_to_digest.get(&pinned_pos) else {
                #[cfg(feature = "std")]
                debug!(pinned_pos, "Pinned node not found in proof");
                return Err(Error::MissingDigest(pinned_pos));
            };
            result.push(digest);
        }
        Ok(result)
    }

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, returning the (position,digest) of every node whose digest was required by the
    /// process (including those from the proof itself). Returns a [Error::InvalidProof] if the
    /// input data is invalid and [Error::RootMismatch] if the root does not match the computed
    /// root.
    pub fn verify_range_inclusion_and_extract_digests<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: u64,
        root: &I::Digest,
    ) -> Result<Vec<(u64, D)>, super::Error>
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        let mut collected_digests = Vec::new();
        let Ok(peak_digests) = self.reconstruct_peak_digests(
            hasher,
            elements,
            start_loc,
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
    pub fn reconstruct_root<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: u64,
    ) -> Result<I::Digest, ReconstructionError>
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        let peak_digests = self.reconstruct_peak_digests(hasher, elements, start_loc, None)?;

        Ok(hasher.root(self.size, peak_digests.iter()))
    }

    /// Reconstruct the peak digests of the MMR that produced this proof, returning
    /// [ReconstructionError] if the input data is invalid.  If collected_digests is Some, then all
    /// node digests used in the process will be added to the wrapped vector.
    pub fn reconstruct_peak_digests<I, H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: u64,
        mut collected_digests: Option<&mut Vec<(u64, I::Digest)>>,
    ) -> Result<Vec<D>, ReconstructionError>
    where
        I: CHasher<Digest = D>,
        H: Hasher<I>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            if start_loc == 0 {
                return Ok(vec![]);
            }
            return Err(ReconstructionError::MissingElements);
        }
        let start_element_pos = leaf_loc_to_pos(start_loc);
        let end_element_pos = if elements.len() == 1 {
            start_element_pos
        } else {
            leaf_loc_to_pos(start_loc + elements.len() as u64 - 1)
        };
        if end_element_pos >= self.size {
            return Err(ReconstructionError::InvalidEndLoc);
        }

        let mut proof_digests_iter = self.digests.iter();
        let mut siblings_iter = self.digests.iter().rev();

        // Include peak digests only for trees that have no elements from the range, and keep track
        // of the starting and ending trees of those that do contain some.
        let mut peak_digests: Vec<D> = Vec::new();
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
}

/// Return the list of node positions required by the range proof for the specified range of
/// elements.
///
/// # Panics
///
/// Panics if the range is invalid for an MMR of the provided `size`.
pub(crate) fn nodes_required_for_range_proof(size: u64, range: Range<u64>) -> Vec<u64> {
    let mut positions = Vec::new();
    if range.is_empty() {
        return positions;
    }

    let start_element_pos = leaf_loc_to_pos(range.start);
    let end_element_pos = leaf_loc_to_pos(range.end - 1);
    assert!(end_element_pos < size, "range is out of bounds");

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

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`.
///
/// The order of positions does not affect the output (sorted internally).
pub(crate) fn nodes_required_for_multi_proof(size: u64, locations: &[u64]) -> BTreeSet<u64> {
    // Collect all required node positions
    //
    // TODO(#1472): Optimize this loop
    locations
        .iter()
        .flat_map(|loc| nodes_required_for_range_proof(size, *loc..(*loc + 1)))
        .collect()
}

/// Information about the current range of nodes being traversed.
struct RangeInfo {
    pos: u64,           // current node position in the tree
    two_h: u64,         // 2^height of the current node
    leftmost_pos: u64,  // leftmost leaf in the tree to be traversed
    rightmost_pos: u64, // rightmost leaf in the tree to be traversed
}

fn peak_digest_from_range<'a, I, H, E, S>(
    hasher: &mut H,
    range_info: RangeInfo,
    elements: &mut E,
    sibling_digests: &mut S,
    mut collected_digests: Option<&mut Vec<(u64, I::Digest)>>,
) -> Result<I::Digest, ReconstructionError>
where
    I: CHasher,
    H: Hasher<I>,
    E: Iterator<Item: AsRef<[u8]>>,
    S: Iterator<Item = &'a I::Digest>,
{
    assert_ne!(range_info.two_h, 0);
    if range_info.two_h == 1 {
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_digest(range_info.pos, element.as_ref())),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }

    let mut left_digest: Option<I::Digest> = None;
    let mut right_digest: Option<I::Digest> = None;

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
        collected_digests.push((
            left_pos,
            left_digest.expect("left_digest guaranteed to be Some after checks above"),
        ));
        collected_digests.push((
            right_pos,
            right_digest.expect("right_digest guaranteed to be Some after checks above"),
        ));
    }

    Ok(hasher.node_digest(
        range_info.pos,
        &left_digest.expect("left_digest guaranteed to be Some after checks above"),
        &right_digest.expect("right_digest guaranteed to be Some after checks above"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{hasher::Standard, mem::Mmr};
    use bytes::Bytes;
    use commonware_codec::{Decode, Encode};
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;

    fn test_digest(v: u8) -> Digest {
        Sha256::hash(&[v])
    }

    #[test]
    fn test_proving_proof() {
        // Test that an empty proof authenticates an empty MMR.
        let mmr = Mmr::new();
        let mut hasher: Standard<Sha256> = Standard::new();
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
        let mut hasher: Standard<Sha256> = Standard::new();
        for _ in 0..11 {
            mmr.add(&mut hasher, &element);
        }

        let root = mmr.root(&mut hasher);

        // confirm the proof of inclusion for each leaf successfully verifies
        for leaf in 0u64..11 {
            let proof: Proof<Digest> = mmr.proof(leaf).unwrap();
            assert!(
                proof.verify_element_inclusion(&mut hasher, &element, leaf, &root),
                "valid proof should verify successfully"
            );
        }

        // confirm mangling the proof or proof args results in failed validation
        const LEAF: u64 = 10;
        let proof = mmr.proof(LEAF).unwrap();
        assert!(
            proof.verify_element_inclusion(&mut hasher, &element, LEAF, &root),
            "proof verification should be successful"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, LEAF + 1, &root),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &element, LEAF - 1, &root),
            "proof verification should fail with incorrect element position 2"
        );
        assert!(
            !proof.verify_element_inclusion(&mut hasher, &test_digest(0), LEAF, &root),
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
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, &root),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.size = 10;
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, &root),
            "proof verification should fail with incorrect size"
        );
        proof2 = proof.clone();
        proof2.digests.push(test_digest(0));
        assert!(
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, &root),
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
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, &root),
            "proof verification should fail with extra hash even if it's unused by the computation"
        );
    }

    #[test]
    fn test_proving_verify_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }
        // test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root(&mut hasher);

        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = i as u64..j as u64;
                let range_proof = mmr.range_proof(range.clone()).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[range.start as usize..range.end as usize],
                        range.start,
                        &root,
                    ),
                    "valid range proof should verify successfully {i}:{j}",
                );
            }
        }

        // Create a proof over a range of elements, confirm it verifies successfully, then mangle
        // the proof & proof input in various ways, confirming verification fails.
        let range = 33..40;
        let range_proof = mmr.range_proof(range.clone()).unwrap();
        let valid_elements = &elements[range.start as usize..range.end as usize];
        assert!(
            range_proof.verify_range_inclusion(&mut hasher, valid_elements, range.start, &root),
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
                    &root,
                ),
                "range proof with removed elements should fail"
            );
        }
        // Confirm proof verification fails when providing an element range different than the one
        // used to generate the proof.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                if i == range.start as usize && j == range.end as usize {
                    // skip the valid range
                    continue;
                }
                assert!(
                    !range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[i..j],
                        range.start,
                        &root,
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
                    &root,
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
                    &root,
                ),
                "mangled range proof should fail verification. inserted element at: {i}",
            );
        }
        // Bad start_loc should cause verification to fail.
        for loc in 0..elements.len() as u64 {
            if loc == range.start {
                continue;
            }
            assert!(
                !range_proof.verify_range_inclusion(&mut hasher, valid_elements, loc, &root),
                "bad start_loc should fail verification {loc}",
            );
        }
    }

    #[test_traced]
    fn test_proving_retained_nodes_provable_after_pruning() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }

        // Confirm we can successfully prove all retained elements in the MMR after pruning.
        let root = mmr.root(&mut hasher);
        for i in 1..mmr.size() {
            mmr.prune_to_pos(i);
            let pruned_root = mmr.root(&mut hasher);
            assert_eq!(root, pruned_root);
            for loc in 0..elements.len() as u64 {
                let proof = mmr.proof(loc);
                if leaf_loc_to_pos(loc) < i {
                    continue;
                }
                assert!(proof.is_ok());
                assert!(proof.unwrap().verify_element_inclusion(
                    &mut hasher,
                    &elements[loc as usize],
                    loc,
                    &root
                ));
            }
        }
    }

    #[test]
    fn test_proving_ranges_provable_after_pruning() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }

        // prune up to the first peak
        const PRUNE_POS: u64 = 62;
        mmr.prune_to_pos(PRUNE_POS);
        assert_eq!(mmr.oldest_retained_pos().unwrap(), PRUNE_POS);

        // Test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root(&mut hasher);
        for i in 0..elements.len() - 1 {
            if leaf_loc_to_pos(i as u64) < PRUNE_POS {
                continue;
            }
            for j in (i + 2)..elements.len() {
                let range = i as u64..j as u64;
                let range_proof = mmr.range_proof(range.clone()).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &mut hasher,
                        &elements[range.start as usize..range.end as usize],
                        range.start,
                        &root,
                    ),
                    "valid range proof over remaining elements should verify successfully",
                );
            }
        }

        // Add a few more nodes, prune again, and test again to make sure repeated pruning doesn't
        // break proof verification.
        for i in 0..37 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }
        mmr.prune_to_pos(130); // a bit after the new highest peak
        assert_eq!(mmr.oldest_retained_pos().unwrap(), 130);

        let updated_root = mmr.root(&mut hasher);
        let range = elements.len() as u64 - 10..elements.len() as u64;
        let range_proof = mmr.range_proof(range.clone()).unwrap();
        assert!(
                range_proof.verify_range_inclusion(
                    &mut hasher,
                    &elements[range.start as usize..range.end as usize],
                    range.start,
                    &updated_root,
                ),
                "valid range proof over remaining elements after 2 pruning rounds should verify successfully",
            );
    }

    #[test]
    fn test_proving_proof_serialization() {
        // create a new MMR and add a non-trivial amount of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        for i in 0..25 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, elements.last().unwrap());
        }

        // Generate proofs over all possible ranges of elements and confirm each
        // serializes=>deserializes correctly.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = i as u64..j as u64;
                let proof = mmr.range_proof(range.clone()).unwrap();

                let expected_size = proof.encode_size();
                let serialized_proof = proof.encode().freeze();
                assert_eq!(
                    serialized_proof.len(),
                    expected_size,
                    "serialized proof should have expected size"
                );
                let max_digests = proof.digests.len();
                let deserialized_proof = Proof::decode_cfg(serialized_proof, &max_digests).unwrap();
                assert_eq!(
                    proof, deserialized_proof,
                    "deserialized proof should match source proof"
                );

                // Remove one byte from the end of the serialized
                // proof and confirm it fails to deserialize.
                let serialized_proof = proof.encode().freeze();
                let serialized_proof: Bytes = serialized_proof.slice(0..serialized_proof.len() - 1);
                assert!(
                    Proof::<Digest>::decode_cfg(serialized_proof, &max_digests).is_err(),
                    "proof should not deserialize with truncated data"
                );

                // Add 1 byte of extra data to the end of the serialized
                // proof and confirm it fails to deserialize.
                let mut serialized_proof = proof.encode();
                serialized_proof.extend_from_slice(&[0; 10]);
                let serialized_proof = serialized_proof.freeze();

                assert!(
                    Proof::<Digest>::decode_cfg(serialized_proof, &max_digests).is_err(),
                    "proof should not deserialize with extra data"
                );

                // Confirm deserialization fails when max length is exceeded.
                if max_digests > 0 {
                    let serialized_proof = proof.encode().freeze();
                    assert!(
                        Proof::<Digest>::decode_cfg(serialized_proof, &(max_digests - 1)).is_err(),
                        "proof should not deserialize with max length exceeded"
                    );
                }
            }
        }
    }

    #[test_traced]
    fn test_proving_extract_pinned_nodes() {
        // Test for every number of elements from 1 to 255
        for num_elements in 1u64..255 {
            // Build MMR with the specified number of elements
            let mut mmr = Mmr::new();
            let mut hasher: Standard<Sha256> = Standard::new();

            for i in 0..num_elements {
                let digest = test_digest(i as u8);
                mmr.add(&mut hasher, &digest);
            }

            // Test pruning to each leaf.
            for leaf in 0..num_elements {
                // Test with a few different end positions to get good coverage
                let test_end_locs = if num_elements == 1 {
                    // Single element case
                    vec![leaf + 1]
                } else {
                    // Multi-element case: test with various end positions
                    let mut ends = vec![leaf + 1]; // Single element proof

                    // Add a few more end positions if available
                    if leaf + 2 <= num_elements {
                        ends.push(leaf + 2);
                    }
                    if leaf + 3 <= num_elements {
                        ends.push(leaf + 3);
                    }
                    // Always test with the last element if different
                    if ends.last().unwrap() != &num_elements {
                        ends.push(num_elements);
                    }

                    ends.into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect()
                };

                for end_loc in test_end_locs {
                    // Generate proof for the range
                    let range = leaf..end_loc;
                    let proof_result = mmr.range_proof(range.clone());
                    let proof = proof_result.unwrap();

                    // Extract pinned nodes
                    let extract_result = proof.extract_pinned_nodes(range.clone());
                    assert!(
                            extract_result.is_ok(),
                            "Failed to extract pinned nodes for {num_elements} elements, boundary={leaf}, range={}..{}", range.start, range.end
                        );

                    let pinned_nodes = extract_result.unwrap();
                    let expected_pinned: Vec<u64> = nodes_to_pin(leaf_loc_to_pos(leaf)).collect();

                    // Verify count matches expected
                    assert_eq!(
                            pinned_nodes.len(),
                            expected_pinned.len(),
                            "Pinned node count mismatch for {num_elements} elements, boundary={leaf}, range=[{leaf}, {end_loc}]"
                        );

                    // Verify extracted hashes match actual node values
                    // The pinned_nodes Vec is in the same order as expected_pinned
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

    #[test]
    fn test_proving_digests_from_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let mut mmr = Mmr::default();
        let mut elements = Vec::new();
        let mut element_positions = Vec::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        for i in 0..49 {
            elements.push(test_digest(i));
            element_positions.push(mmr.add(&mut hasher, elements.last().unwrap()));
        }
        let root = mmr.root(&mut hasher);

        // Test 1: compute_digests over the entire range should contain a digest for every node
        // in the tree.
        let proof = mmr.range_proof(0..mmr.leaves()).unwrap();
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
        let range = 0..1;
        let single_proof = mmr.range_proof(range.clone()).unwrap();
        let single_digests = single_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.start as usize..range.end as usize],
                range.start,
                &root,
            )
            .unwrap();
        assert!(single_digests.len() > 1);

        // Test 3: Single element range (middle element)
        let mid_idx = 24;
        let range = mid_idx..mid_idx + 1;
        let mid_proof = mmr.range_proof(range.clone()).unwrap();
        let mid_digests = mid_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.start as usize..range.end as usize],
                range.start,
                &root,
            )
            .unwrap();
        assert!(mid_digests.len() > 1);

        // Test 4: Single element range (last element)
        let last_idx = elements.len() - 1;
        let range = last_idx as u64..last_idx as u64 + 1;
        let last_proof = mmr.range_proof(range.clone()).unwrap();
        let last_digests = last_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.start as usize..range.end as usize],
                range.start,
                &root,
            )
            .unwrap();
        assert!(last_digests.len() > 1);

        // Test 5: Small range at the beginning
        let range = 0..5;
        let small_proof = mmr.range_proof(range.clone()).unwrap();
        let small_digests = small_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.start as usize..range.end as usize],
                range.start,
                &root,
            )
            .unwrap();
        // Verify that we get digests for the range elements and their ancestors
        assert!(small_digests.len() > 5);

        // Test 6: Medium range in the middle
        let range = 10..31;
        let mid_range_proof = mmr.range_proof(range.clone()).unwrap();
        let mid_range_digests = mid_range_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.start as usize..range.end as usize],
                range.start,
                &root,
            )
            .unwrap();
        let num_elements = range.end - range.start;
        assert!(mid_range_digests.len() > num_elements as usize);
    }

    #[test]
    fn test_proving_multi_proof_generation_and_verify() {
        // Create an MMR with multiple elements
        let mut mmr = Mmr::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut elements = Vec::new();

        for i in 0..20 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, &elements[i as usize]);
        }

        let root = mmr.root(&mut hasher);

        // Generate proof for non-contiguous single elements
        let nodes_for_multi_proof = nodes_required_for_multi_proof(mmr.size(), &[0, 5, 10]);
        let digests = nodes_for_multi_proof
            .into_iter()
            .map(|pos| mmr.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            size: mmr.size(),
            digests,
        };

        assert_eq!(multi_proof.size, mmr.size());

        // Verify the proof
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[(elements[0], 0), (elements[5], 5), (elements[10], 10),],
            &root
        ));

        // Verify in different order
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[(elements[10], 10), (elements[5], 5), (elements[0], 0),],
            &root
        ));

        // Verify with duplicate items
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], 0),
                (elements[0], 0),
                (elements[10], 10),
                (elements[5], 5),
            ],
            &root
        ));

        // Verify with wrong positions
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[(elements[0], 1), (elements[5], 6), (elements[10], 11),],
            &root,
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
                (wrong_elements[0].as_slice(), 0),
                (wrong_elements[1].as_slice(), 5),
                (wrong_elements[2].as_slice(), 10),
            ],
            &root,
        );
        assert!(!wrong_verification, "Should fail with wrong elements");

        // Verify with wrong root should fail
        let wrong_root = test_digest(99);
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[(elements[0], 0), (elements[5], 5), (elements[10], 10),],
            &wrong_root
        ));

        // Empty multi-proof
        let empty_multi = nodes_required_for_multi_proof(0, &[]);
        assert_eq!(empty_multi.len(), 0);
        assert!(empty_multi.is_empty());

        let empty_mmr = Mmr::new();
        let empty_root = empty_mmr.root(&mut hasher);
        let empty_proof = Proof {
            size: 0,
            digests: vec![],
        };
        assert!(empty_proof.verify_multi_inclusion(
            &mut hasher,
            &[] as &[(Digest, u64)],
            &empty_root
        ));
    }

    #[test]
    fn test_proving_multi_proof_deduplication() {
        let mut mmr = Mmr::new();
        let mut hasher: Standard<Sha256> = Standard::new();
        let mut elements = Vec::new();

        // Create an MMR with enough elements to have shared digests
        for i in 0..30 {
            elements.push(test_digest(i));
            mmr.add(&mut hasher, &elements[i as usize]);
        }

        // Get individual proofs that will share some digests (elements in same subtree)
        let proof1 = mmr.proof(0).unwrap();
        let proof2 = mmr.proof(1).unwrap();
        let total_digests_separate = proof1.digests.len() + proof2.digests.len();

        // Generate multi-proof for the same positions
        let multi_proof = nodes_required_for_multi_proof(mmr.size(), &[0, 1]);
        let digests = multi_proof
            .into_iter()
            .map(|pos| mmr.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            size: mmr.size(),
            digests,
        };

        // The combined proof should have fewer digests due to deduplication
        assert!(multi_proof.digests.len() < total_digests_separate);

        // Verify it still works
        let root = mmr.root(&mut hasher);
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[(elements[0], 0), (elements[1], 1)],
            &root
        ));
    }
}
