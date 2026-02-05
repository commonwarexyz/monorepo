//! Defines the inclusion [Proof] structure, and functions for verifying them against a root digest.
//!
//! Also provides lower-level functions for building verifiers against new or extended proof types.
//! These lower level functions are kept outside of the [Proof] structure and not re-exported by the
//! parent module.

#[cfg(any(feature = "std", test))]
use crate::mmr::iterator::nodes_to_pin;
use crate::mmr::{
    hasher::Hasher,
    iterator::{PathIterator, PeakIterator},
    Error, Location, Position,
};
use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    vec,
    vec::Vec,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;
use core::{cmp::Reverse, ops::Range};
#[cfg(feature = "std")]
use tracing::debug;

/// The maximum number of digests in a proof per element being proven.
///
/// This accounts for the worst case proof size, in an MMR with 62 peaks. The
/// left-most leaf in such a tree requires 122 digests, for 61 path siblings
/// and 61 peak digests.
pub const MAX_PROOF_DIGESTS_PER_ELEMENT: usize = 122;

/// Errors that can occur when reconstructing a digest from a proof due to invalid input.
#[derive(Error, Debug)]
pub enum ReconstructionError {
    #[error("missing digests in proof")]
    MissingDigests,
    #[error("extra digests in proof")]
    ExtraDigests,
    #[error("start location is out of bounds")]
    InvalidStartLoc,
    #[error("end location is out of bounds")]
    InvalidEndLoc,
    #[error("missing elements")]
    MissingElements,
    #[error("invalid size")]
    InvalidSize,
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
    /// The total number of leaves in the MMR for MMR proofs, though other authenticated data
    /// structures may override the meaning of this field. For example, the authenticated
    /// [crate::AuthenticatedBitMap] stores the number of bits in the bitmap within this field.
    pub leaves: Location,
    /// The digests necessary for proving the inclusion of an element, or range of elements, in the
    /// MMR.
    pub digests: Vec<D>,
}

impl<D: Digest> PartialEq for Proof<D> {
    fn eq(&self, other: &Self) -> bool {
        self.leaves == other.leaves && self.digests == other.digests
    }
}

impl<D: Digest> EncodeSize for Proof<D> {
    fn encode_size(&self) -> usize {
        self.leaves.encode_size() + self.digests.encode_size()
    }
}

impl<D: Digest> Write for Proof<D> {
    fn write(&self, buf: &mut impl BufMut) {
        // Write the number of leaves in the MMR
        self.leaves.write(buf);

        // Write the digests
        self.digests.write(buf);
    }
}

impl<D: Digest> Read for Proof<D> {
    /// The maximum number of items being proven.
    ///
    /// The upper bound on digests is derived as `max_items * MAX_PROOF_DIGESTS_PER_ELEMENT`.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_items: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        // Read the number of nodes in the MMR
        let leaves = Location::read(buf)?;

        // Read the digests
        let max_digests = max_items.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT);
        let digests = Vec::<D>::read_range(buf, ..=max_digests)?;

        Ok(Self { leaves, digests })
    }
}

impl<D: Digest> Default for Proof<D> {
    /// Create an empty proof. The empty proof will verify only against the root digest of an empty
    /// (`leaves == 0`) MMR.
    fn default() -> Self {
        Self {
            leaves: Location::new_unchecked(0),
            digests: vec![],
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<D: Digest> arbitrary::Arbitrary<'_> for Proof<D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            leaves: u.arbitrary()?,
            digests: u.arbitrary()?,
        })
    }
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
        H: Hasher<Digest = D>,
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
        H: Hasher<Digest = D>,
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
    /// in the MMR with the root digest `root`. A malformed proof will return false.
    ///
    /// The order of the elements does not affect the output.
    pub fn verify_multi_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[(E, Location)],
        root: &D,
    ) -> bool
    where
        H: Hasher<Digest = D>,
        E: AsRef<[u8]>,
    {
        // Empty proof is valid for an empty MMR
        if elements.is_empty() {
            return self.leaves == Location::new_unchecked(0)
                && *root == hasher.root(Location::new_unchecked(0), core::iter::empty());
        }

        // Single pass to collect all required positions with deduplication
        let mut node_positions = BTreeSet::new();
        let mut nodes_required = BTreeMap::new();

        for (_, loc) in elements {
            if !loc.is_valid() {
                return false;
            }
            // `loc` is valid so it won't overflow from +1
            let Ok(required) = nodes_required_for_range_proof(self.leaves, *loc..*loc + 1) else {
                return false;
            };
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
        let node_digests: BTreeMap<Position, D> = node_positions
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
                    .expect("must exist by construction of node_digests");
                digests.push(*digest);
            }
            let proof = Self {
                leaves: self.leaves,
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
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidSize] if the proof size is not a valid MMR size.
    /// Returns [Error::LocationOverflow] if a location in `range` > [crate::mmr::MAX_LOCATION].
    /// Returns [Error::InvalidProofLength] if the proof digest count doesn't match the required
    /// positions count.
    /// Returns [Error::MissingDigest] if a pinned node is not found in the proof.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn extract_pinned_nodes(
        &self,
        range: std::ops::Range<Location>,
    ) -> Result<Vec<D>, Error> {
        // Get the positions of all nodes that should be pinned.
        let start_pos = Position::try_from(range.start)?;
        let pinned_positions: Vec<Position> = nodes_to_pin(start_pos).collect();

        // Get all positions required for the proof.
        let required_positions = nodes_required_for_range_proof(self.leaves, range)?;

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
        let position_to_digest: BTreeMap<Position, D> = required_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, &digest)| (pos, digest))
            .collect();

        // Extract the pinned nodes in the same order as nodes_to_pin.
        let mut result = Vec::with_capacity(pinned_positions.len());
        for pinned_pos in pinned_positions {
            let Some(&digest) = position_to_digest.get(&pinned_pos) else {
                #[cfg(feature = "std")]
                debug!(?pinned_pos, "Pinned node not found in proof");
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
    pub fn verify_range_inclusion_and_extract_digests<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> Result<Vec<(Position, D)>, super::Error>
    where
        H: Hasher<Digest = D>,
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

        if hasher.root(self.leaves, peak_digests.iter()) != *root {
            return Err(Error::RootMismatch);
        }

        Ok(collected_digests)
    }

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, or returns a [ReconstructionError] if the input data is invalid.
    pub fn reconstruct_root<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<Digest = D>,
        E: AsRef<[u8]>,
    {
        let peak_digests = self.reconstruct_peak_digests(hasher, elements, start_loc, None)?;

        Ok(hasher.root(self.leaves, peak_digests.iter()))
    }

    /// Reconstruct the peak digests of the MMR that produced this proof, returning
    /// [ReconstructionError] if the input data is invalid.  If collected_digests is Some, then all
    /// node digests used in the process will be added to the wrapped vector.
    pub fn reconstruct_peak_digests<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location,
        mut collected_digests: Option<&mut Vec<(Position, D)>>,
    ) -> Result<Vec<D>, ReconstructionError>
    where
        H: Hasher<Digest = D>,
        E: AsRef<[u8]>,
    {
        if elements.is_empty() {
            if start_loc == 0 {
                return Ok(vec![]);
            }
            return Err(ReconstructionError::MissingElements);
        }
        let size = Position::try_from(self.leaves).map_err(|_| ReconstructionError::InvalidSize)?;
        let start_element_pos =
            Position::try_from(start_loc).map_err(|_| ReconstructionError::InvalidStartLoc)?;
        let end_element_pos = if elements.len() == 1 {
            start_element_pos
        } else {
            let end_loc = start_loc
                .checked_add(elements.len() as u64 - 1)
                .ok_or(ReconstructionError::InvalidEndLoc)?;
            Position::try_from(end_loc).map_err(|_| ReconstructionError::InvalidEndLoc)?
        };
        if end_element_pos >= size {
            return Err(ReconstructionError::InvalidEndLoc);
        }

        let mut proof_digests_iter = self.digests.iter();
        let mut siblings_iter = self.digests.iter().rev();

        // Include peak digests only for trees that have no elements from the range, and keep track
        // of the starting and ending trees of those that do contain some.
        let mut peak_digests: Vec<D> = Vec::new();
        let mut proof_digests_used = 0;
        let mut elements_iter = elements.iter();
        for (peak_pos, height) in PeakIterator::new(size) {
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
) -> Result<Vec<Position>, Error> {
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

    // Find the mountains that contain no elements from the range. The peaks of these mountains
    // are required to prove the range, so they are added to the result.
    let mut start_tree_with_element: Option<(Position, u32)> = None;
    let mut end_tree_with_element: Option<(Position, u32)> = None;
    let mut positions = Vec::new();
    let size = Position::try_from(leaves)?;
    let start_element_pos = Position::try_from(range.start)?;
    let end_element_pos = Position::try_from(end_minus_one)?;

    let mut peak_iterator = PeakIterator::new(size);
    while let Some(peak) = peak_iterator.next() {
        if start_tree_with_element.is_none() && peak.0 >= start_element_pos {
            // Found the first tree to contain an element in the range
            start_tree_with_element = Some(peak);
            if peak.0 >= end_element_pos {
                // Start and end tree are the same
                end_tree_with_element = Some(peak);
                continue;
            }
            for peak in peak_iterator.by_ref() {
                if peak.0 >= end_element_pos {
                    // Found the last tree to contain an element in the range
                    end_tree_with_element = Some(peak);
                    break;
                }
            }
        } else {
            // Tree is outside the range, its peak is thus required.
            positions.push(peak.0);
        }
    }

    // We checked above that all range elements are in this MMR, so some mountain must contain
    // the first and last elements in the range.
    let (start_tree_peak, start_tree_height) =
        start_tree_with_element.expect("start_tree_with_element is Some");
    let (end_tree_peak, end_tree_height) =
        end_tree_with_element.expect("end_tree_with_element is Some");

    // Include the positions of any left-siblings of each node on the path from peak to
    // leftmost-leaf, and right-siblings for the path from peak to rightmost-leaf. These are
    // added in order of decreasing parent position.
    let left_path_iter = PathIterator::new(start_element_pos, start_tree_peak, start_tree_height);

    let mut siblings = Vec::new();
    if start_element_pos == end_element_pos {
        // For the (common) case of a single element range, the right and left path are the
        // same so no need to process each independently.
        siblings.extend(left_path_iter);
    } else {
        let right_path_iter = PathIterator::new(end_element_pos, end_tree_peak, end_tree_height);
        // filter the right path for right siblings only
        siblings.extend(right_path_iter.filter(|(parent_pos, pos)| *parent_pos == *pos + 1));
        // filter the left path for left siblings only
        siblings.extend(left_path_iter.filter(|(parent_pos, pos)| *parent_pos != *pos + 1));

        // If the range spans more than one tree, then the digests must already be in the correct
        // order. Otherwise, we enforce the desired order through sorting.
        if start_tree_peak == end_tree_peak {
            siblings.sort_by_key(|a| Reverse(a.0));
        }
    }
    positions.extend(siblings.into_iter().map(|(_, pos)| pos));

    Ok(positions)
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
        let positions = nodes_required_for_range_proof(leaves, *loc..*loc + 1)?;
        acc.extend(positions);

        Ok(acc)
    })
}

/// Information about the current range of nodes being traversed.
struct RangeInfo {
    pos: Position,           // current node position in the tree
    two_h: u64,              // 2^height of the current node
    leftmost_pos: Position,  // leftmost leaf in the tree to be traversed
    rightmost_pos: Position, // rightmost leaf in the tree to be traversed
}

fn peak_digest_from_range<'a, D, H, E, S>(
    hasher: &mut H,
    range_info: RangeInfo,
    elements: &mut E,
    sibling_digests: &mut S,
    mut collected_digests: Option<&mut Vec<(Position, D)>>,
) -> Result<D, ReconstructionError>
where
    D: Digest,
    H: Hasher<Digest = D>,
    E: Iterator<Item: AsRef<[u8]>>,
    S: Iterator<Item = &'a D>,
{
    assert_ne!(range_info.two_h, 0);
    if range_info.two_h == 1 {
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_digest(range_info.pos, element.as_ref())),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }

    let mut left_digest: Option<D> = None;
    let mut right_digest: Option<D> = None;

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
    use crate::mmr::{
        hasher::Standard,
        location::LocationRangeExt as _,
        mem::{CleanMmr, DirtyMmr},
        MAX_LOCATION,
    };
    use commonware_codec::{Decode, Encode};
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
            Location::new_unchecked(0),
            root
        ));

        // Any starting position other than 0 should fail to verify.
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[Digest],
            Location::new_unchecked(1),
            root
        ));

        // Invalid root should fail to verify.
        let test_digest = test_digest(0);
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[] as &[Digest],
            Location::new_unchecked(0),
            &test_digest
        ));

        // Non-empty elements list should fail to verify.
        assert!(!proof.verify_range_inclusion(
            &mut hasher,
            &[test_digest],
            Location::new_unchecked(0),
            root
        ));
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
            let leaf = Location::new_unchecked(leaf);
            let proof: Proof<Digest> = mmr.proof(leaf).unwrap();
            assert!(
                proof.verify_element_inclusion(&mut hasher, &element, leaf, root),
                "valid proof should verify successfully"
            );
        }

        // Create a valid proof, then confirm various mangling of the proof or proof args results in
        // verification failure.
        const LEAF: Location = Location::new_unchecked(10);
        let proof = mmr.proof(LEAF).unwrap();
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
        proof2.leaves = Location::new_unchecked(10);
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
            !proof2.verify_element_inclusion(&mut hasher, &element, LEAF, root),
            "proof verification should fail with extra hash even if it's unused by the computation"
        );
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
                let range = Location::new_unchecked(i as u64)..Location::new_unchecked(j as u64);
                let range_proof = mmr.range_proof(range.clone()).unwrap();
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
        let range = Location::new_unchecked(33)..Location::new_unchecked(40);
        let range_proof = mmr.range_proof(range.clone()).unwrap();
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
            let loc = Location::new_unchecked(loc as u64);
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
            mmr.prune_to_pos(Position::new(i));
            let pruned_root = mmr.root();
            assert_eq!(root, *pruned_root);
            for loc in 0..elements.len() {
                let loc = Location::new_unchecked(loc as u64);
                let proof = mmr.proof(loc);
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
        mmr.prune_to_pos(PRUNE_POS);
        assert_eq!(mmr.bounds().start, PRUNE_POS);

        // Test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root();
        for i in 0..elements.len() - 1 {
            if Position::try_from(Location::new_unchecked(i as u64)).unwrap() < PRUNE_POS {
                continue;
            }
            for j in (i + 2)..elements.len() {
                let range = Location::new_unchecked(i as u64)..Location::new_unchecked(j as u64);
                let range_proof = mmr.range_proof(range.clone()).unwrap();
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
        mmr.prune_to_pos(Position::new(130)); // a bit after the new highest peak
        assert_eq!(mmr.bounds().start, 130);

        let updated_root = mmr.root();
        let range = Location::new_unchecked(elements.len() as u64 - 10)
            ..Location::new_unchecked(elements.len() as u64);
        let range_proof = mmr.range_proof(range.clone()).unwrap();
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
                let range = Location::new_unchecked(i as u64)..Location::new_unchecked(j as u64);
                let proof = mmr.range_proof(range).unwrap();

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
        // Test for every number of elements from 1 to 255
        for num_elements in 1u64..255 {
            // Build MMR with the specified number of elements
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = DirtyMmr::new();

            for i in 0..num_elements {
                let digest = test_digest(i as u8);
                mmr.add(&mut hasher, &digest);
            }
            let mmr = mmr.merkleize(&mut hasher, None);

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
                    let range = Location::new_unchecked(leaf)..Location::new_unchecked(end_loc);
                    let proof_result = mmr.range_proof(range.clone());
                    let proof = proof_result.unwrap();

                    // Extract pinned nodes
                    let extract_result = proof.extract_pinned_nodes(range.clone());
                    assert!(
                            extract_result.is_ok(),
                            "Failed to extract pinned nodes for {num_elements} elements, boundary={leaf}, range={}..{}", range.start, range.end
                        );

                    let pinned_nodes = extract_result.unwrap();
                    let leaf_loc = Location::new_unchecked(leaf);
                    let leaf_pos = Position::try_from(leaf_loc).unwrap();
                    let expected_pinned: Vec<Position> = nodes_to_pin(leaf_pos).collect();

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

        // Generate a valid proof
        let range = Location::new_unchecked(5)..Location::new_unchecked(8);
        let mut proof = mmr.range_proof(range.clone()).unwrap();

        // Verify the proof works with valid size
        assert!(proof.extract_pinned_nodes(range.clone()).is_ok());

        // Test with invalid location.
        proof.leaves = Location::new_unchecked(MAX_LOCATION + 2);
        let result = proof.extract_pinned_nodes(range);
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
        // in the tree.
        let proof = mmr
            .range_proof(Location::new_unchecked(0)..mmr.leaves())
            .unwrap();
        let mut node_digests = proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements,
                Location::new_unchecked(0),
                root,
            )
            .unwrap();
        assert_eq!(node_digests.len() as u64, mmr.size());
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
                Location::new_unchecked(0),
                &wrong_root
            ),
            Err(Error::RootMismatch)
        ));

        // Test 2: Single element range (first element)
        let range = Location::new_unchecked(0)..Location::new_unchecked(1);
        let single_proof = mmr.range_proof(range.clone()).unwrap();
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
        let range = Location::new_unchecked(mid_idx)..Location::new_unchecked(mid_idx + 1);
        let range_start = range.start;
        let mid_proof = mmr.range_proof(range.clone()).unwrap();
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
        let last_idx = elements.len() as u64 - 1;
        let range = Location::new_unchecked(last_idx)..Location::new_unchecked(last_idx + 1);
        let range_start = range.start;
        let last_proof = mmr.range_proof(range.clone()).unwrap();
        let last_digests = last_proof
            .verify_range_inclusion_and_extract_digests(
                &mut hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        assert!(last_digests.len() > 1);

        // Test 5: Small range at the beginning
        let range = Location::new_unchecked(0)..Location::new_unchecked(5);
        let range_start = range.start;
        let small_proof = mmr.range_proof(range.clone()).unwrap();
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
        let range = Location::new_unchecked(10)..Location::new_unchecked(31);
        let range_start = range.start;
        let mid_range_proof = mmr.range_proof(range.clone()).unwrap();
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
        let locations = &[
            Location::new_unchecked(0),
            Location::new_unchecked(5),
            Location::new_unchecked(10),
        ];
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
                (elements[0], Location::new_unchecked(0)),
                (elements[5], Location::new_unchecked(5)),
                (elements[10], Location::new_unchecked(10)),
            ],
            root
        ));

        // Verify in different order
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[10], Location::new_unchecked(10)),
                (elements[5], Location::new_unchecked(5)),
                (elements[0], Location::new_unchecked(0)),
            ],
            root
        ));

        // Verify with duplicate items
        assert!(multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new_unchecked(0)),
                (elements[0], Location::new_unchecked(0)),
                (elements[10], Location::new_unchecked(10)),
                (elements[5], Location::new_unchecked(5)),
            ],
            root
        ));

        // Verify mangling the location to something invalid should fail.
        let mut wrong_size_proof = multi_proof.clone();
        wrong_size_proof.leaves = Location::new_unchecked(MAX_LOCATION + 2);
        assert!(!wrong_size_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new_unchecked(0)),
                (elements[5], Location::new_unchecked(5)),
                (elements[10], Location::new_unchecked(10)),
            ],
            root,
        ));

        // Verify with wrong positions
        assert!(!multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new_unchecked(1)),
                (elements[5], Location::new_unchecked(6)),
                (elements[10], Location::new_unchecked(11)),
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
                (wrong_elements[0].as_slice(), Location::new_unchecked(0)),
                (wrong_elements[1].as_slice(), Location::new_unchecked(5)),
                (wrong_elements[2].as_slice(), Location::new_unchecked(10)),
            ],
            root,
        );
        assert!(!wrong_verification, "Should fail with wrong elements");

        // Verify with out of range element
        let wrong_verification = multi_proof.verify_multi_inclusion(
            &mut hasher,
            &[
                (elements[0], Location::new_unchecked(0)),
                (elements[5], Location::new_unchecked(5)),
                (elements[10], Location::new_unchecked(1000)),
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
                (elements[0], Location::new_unchecked(0)),
                (elements[5], Location::new_unchecked(5)),
                (elements[10], Location::new_unchecked(10)),
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
        let proof1 = mmr.proof(Location::new_unchecked(0)).unwrap();
        let proof2 = mmr.proof(Location::new_unchecked(1)).unwrap();
        let total_digests_separate = proof1.digests.len() + proof2.digests.len();

        // Generate multi-proof for the same positions
        let locations = &[Location::new_unchecked(0), Location::new_unchecked(1)];
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
                (elements[0], Location::new_unchecked(0)),
                (elements[1], Location::new_unchecked(1))
            ],
            root
        ));
    }

    #[test]
    fn test_max_location_is_provable() {
        // Test that the validation logic accepts MAX_LOCATION as a valid location
        // We use the maximum valid MMR size (2^63 - 1) which can hold up to 2^62 leaves
        let max_loc = Location::new_unchecked(MAX_LOCATION);
        let max_loc_plus_1 = Location::new_unchecked(MAX_LOCATION + 1);

        // MAX_LOCATION should be accepted by the validation logic
        // (The range MAX_LOCATION..MAX_LOCATION+1 proves a single element at MAX_LOCATION)
        let result = nodes_required_for_range_proof(max_loc, max_loc - 1..max_loc);

        // This should succeed - MAX_LOCATION is a valid location
        assert!(result.is_ok(), "Should be able to prove MAX_LOCATION");

        // MAX_LOCATION + 1 should be rejected (exceeds MAX_LOCATION)
        let result_overflow =
            nodes_required_for_range_proof(max_loc_plus_1, max_loc..max_loc_plus_1);
        assert!(
            result_overflow.is_err(),
            "Should reject location > MAX_LOCATION"
        );
        matches!(result_overflow, Err(Error::LocationOverflow(_)));
    }

    #[test]
    fn test_max_location_multi_proof() {
        // Test that multi_proof can handle MAX_LOCATION
        let max_loc = Location::new_unchecked(MAX_LOCATION);

        // Should be able to generate multi-proof for MAX_LOCATION
        let result = nodes_required_for_multi_proof(max_loc, &[max_loc - 1]);
        assert!(
            result.is_ok(),
            "Should be able to generate multi-proof for MAX_LOCATION"
        );

        // Should reject MAX_LOCATION + 1
        let invalid_loc = max_loc + 1;
        let result_overflow = nodes_required_for_multi_proof(invalid_loc, &[max_loc]);
        assert!(
            result_overflow.is_err(),
            "Should reject location > MAX_LOCATION in multi-proof"
        );
    }

    #[test]
    fn test_max_proof_digests_per_element_sufficient() {
        // Verify that MAX_PROOF_DIGESTS_PER_ELEMENT (122) is sufficient for any single-element
        // proof in the largest valid MMR.
        //
        // MMR sizes follow: mmr_size(N) = 2*N - popcount(N) where N = leaf count.
        // The number of peaks equals popcount(N).
        //
        // To maximize peaks, we want N with maximum popcount. N = 2^62 - 1 has 62 one-bits:
        //   N = 0x3FFFFFFFFFFFFFFF = 2^0 + 2^1 + ... + 2^61
        //
        // This gives us 62 perfect binary trees with leaf counts 2^0, 2^1, ..., 2^61
        // and corresponding heights 0, 1, ..., 61.
        //
        // mmr_size(2^62 - 1) = 2*(2^62 - 1) - 62 = 2^63 - 2 - 62 = 2^63 - 64
        //
        // For a single-element proof in a tree of height h:
        //   - Path siblings from leaf to peak: h digests
        //   - Other peaks (not containing the element): (62 - 1) = 61 digests
        //   - Total: h + 61 digests
        //
        // Worst case: element in tallest tree (h = 61)
        //   - Path siblings: 61
        //   - Other peaks: 61
        //   - Total: 61 + 61 = 122 digests

        const NUM_PEAKS: usize = 62;
        const MAX_TREE_HEIGHT: usize = 61;
        const EXPECTED_WORST_CASE: usize = MAX_TREE_HEIGHT + (NUM_PEAKS - 1);

        let many_peaks_size = Position::new((1u64 << 63) - 64);
        assert!(
            many_peaks_size.is_mmr_size(),
            "Size {many_peaks_size} should be a valid MMR size",
        );

        let peak_count = PeakIterator::new(many_peaks_size).count();
        assert_eq!(peak_count, NUM_PEAKS);

        // Verify the peak heights are 61, 60, ..., 1, 0 (from left to right)
        let peaks: Vec<_> = PeakIterator::new(many_peaks_size).collect();
        for (i, &(_pos, height)) in peaks.iter().enumerate() {
            let expected_height = (NUM_PEAKS - 1 - i) as u32;
            assert_eq!(
                height, expected_height,
                "Peak {i} should have height {expected_height}, got {height}",
            );
        }

        // Test location 0 (leftmost leaf, in tallest tree of height 61)
        // Expected: 61 path siblings + 61 other peaks = 122 digests
        let leaves = Location::try_from(many_peaks_size).unwrap();
        let loc = Location::new_unchecked(0);
        let positions = nodes_required_for_range_proof(leaves, loc..loc + 1)
            .expect("should compute positions for location 0");

        assert_eq!(
            positions.len(),
            EXPECTED_WORST_CASE,
            "Location 0 proof should require exactly {EXPECTED_WORST_CASE} digests (61 path + 61 peaks)",
        );

        // Test the rightmost leaf (in smallest tree of height 0, which is itself a peak)
        // Expected: 0 path siblings + 61 other peaks = 61 digests
        let last_leaf_loc = leaves - 1;
        let positions = nodes_required_for_range_proof(leaves, last_leaf_loc..last_leaf_loc + 1)
            .expect("should compute positions for last leaf");

        let expected_last_leaf = NUM_PEAKS - 1;
        assert_eq!(
            positions.len(),
            expected_last_leaf,
            "Last leaf proof should require exactly {expected_last_leaf} digests (0 path + 61 peaks)",
        );
    }

    #[test]
    fn test_max_proof_digests_per_element_is_maximum() {
        // For K peaks, the worst-case proof needs: (max_tree_height) + (K - 1) digests
        // With K peaks of heights K-1, K-2, ..., 0, this is (K-1) + (K-1) = 2*(K-1)
        //
        // To get K peaks, leaf count N must have exactly K bits set.
        // MMR size = 2*N - popcount(N) = 2*N - K
        //
        // For 63 peaks: N = 2^63 - 1 (63 bits set), size = 2*(2^63 - 1) - 63 = 2^64 - 65
        // This exceeds MAX_POSITION, so is_mmr_size() returns false.

        let n_for_63_peaks = (1u128 << 63) - 1;
        let size_for_63_peaks = 2 * n_for_63_peaks - 63; // = 2^64 - 65
        assert!(
            size_for_63_peaks > *crate::mmr::MAX_POSITION as u128,
            "63 peaks requires size {size_for_63_peaks} > MAX_POSITION",
        );

        let size_truncated = size_for_63_peaks as u64;
        assert!(
            !Position::new(size_truncated).is_mmr_size(),
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
