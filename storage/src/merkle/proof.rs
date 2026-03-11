//! Defines the inclusion [Proof] structure, and functions for verifying them against a root digest.
//!
//! Also provides lower-level functions for building verifiers against new or extended proof types.
//! These lower level functions are kept outside of the [Proof] structure and not re-exported by the
//! parent module.

use crate::{
    merkle::hasher::Hasher,
    mmr::{
        self,
        iterator::{nodes_to_pin, PeakIterator},
        Error, Location, Position,
    },
};
use alloc::{
    collections::{btree_map::BTreeMap, btree_set::BTreeSet},
    vec,
    vec::Vec,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;
use core::ops::Range;

/// The maximum number of digests in a proof per element being proven.
///
/// This accounts for the worst case proof size, in an MMR with 62 peaks. The
/// left-most leaf in such a tree requires 122 digests, for 61 path siblings
/// and 61 peak digests.
pub const MAX_PROOF_DIGESTS_PER_ELEMENT: usize = 122;

/// Errors that can occur when reconstructing a digest from a proof due to invalid input.
#[derive(thiserror::Error, Debug)]
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
/// The `digests` vector uses a fold-based layout:
///
/// 1. If there are peaks entirely before the proven range (fold prefix), the first digest is
///    a single accumulator produced by folding those peaks: `fold(fold(..., peak0), peak1)`.
///    If there are no such peaks, this entry is absent.
///
/// 2. The digests of peaks entirely after the proven range, in peak iteration order.
///
/// 3. The sibling digests needed to reconstruct each range-peak digest from the proven elements,
///    in depth-first (forward consumption) order for each range peak.
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
            leaves: Location::new(0),
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
        hasher: &H,
        element: &[u8],
        loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<Family = mmr::Family, Digest = D>,
    {
        self.verify_range_inclusion(hasher, &[element], loc, root)
    }

    /// Return true if this proof proves that the `elements` appear consecutively starting at
    /// position `start_loc` within the MMR with root digest `root`. A malformed proof will return
    /// false.
    pub fn verify_range_inclusion<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> bool
    where
        H: Hasher<Family = mmr::Family, Digest = D>,
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
        hasher: &H,
        elements: &[(E, Location)],
        root: &D,
    ) -> bool
    where
        H: Hasher<Family = mmr::Family, Digest = D>,
        E: AsRef<[u8]>,
    {
        // Empty proof is valid for an empty MMR
        if elements.is_empty() {
            return self.leaves == Location::new(0)
                && *root == hasher.root(Location::new(0), core::iter::empty());
        }

        // Collect all required positions with deduplication, and blueprints per element.
        let mut node_positions = BTreeSet::new();
        let mut blueprints = BTreeMap::new();

        for (_, loc) in elements {
            if !loc.is_valid() {
                return false;
            }
            // `loc` is valid so it won't overflow from +1
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

        // Verify each element by constructing its sub-proof in fold-based format
        for (element, loc) in elements {
            let bp = &blueprints[loc];

            // Build the sub-proof: [fold_acc? | fetch_nodes...]
            let mut digests = Vec::with_capacity(
                if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len(),
            );
            if !bp.fold_prefix.is_empty() {
                // Fold prefix peaks into accumulator (without the leaf count).
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

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, returning the (position,digest) of every node whose digest was required by the
    /// process (including those from the proof itself). Returns a [Error::InvalidProof] if the
    /// input data is invalid and [Error::RootMismatch] if the root does not match the computed
    /// root.
    pub fn verify_range_inclusion_and_extract_digests<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location,
        root: &D,
    ) -> Result<Vec<(Position, D)>, Error>
    where
        H: Hasher<Family = mmr::Family, Digest = D>,
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

    /// Verify that both the proof and the pinned nodes are valid with respect to `root`.
    ///
    /// The `pinned_nodes` are the peak digests of the sub-MMR at `start_loc`, in the order returned
    /// by `nodes_to_pin`. Each pinned node is either:
    ///
    /// - A peak of the full MMR that precedes the proven range (fold-prefix peak). These are
    ///   verified by refolding them and comparing against the proof's fold-prefix accumulator.
    /// - A sibling node within a range peak's reconstruction. These are verified against the
    ///   digests extracted during proof verification.
    ///
    /// Returns `true` only if the proof reconstructs to `root` and every pinned node digest is
    /// accounted for. When `start_loc` is 0, `pinned_nodes` must be empty.
    pub fn verify_proof_and_pinned_nodes<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location,
        pinned_nodes: &[D],
        root: &D,
    ) -> bool
    where
        H: Hasher<Family = mmr::Family, Digest = D>,
        E: AsRef<[u8]>,
    {
        // Verify the proof and extract all node digests used in the reconstruction.
        let collected = match self
            .verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)
        {
            Ok(c) => c,
            Err(_) => return false,
        };

        if elements.is_empty() {
            return pinned_nodes.is_empty();
        }

        let Ok(start_pos) = Position::try_from(start_loc) else {
            return false;
        };

        let pinned_positions: Vec<Position> = nodes_to_pin(start_pos).collect();
        if pinned_positions.len() != pinned_nodes.len() {
            return false;
        }

        let Ok(bp) = start_loc
            .checked_add(elements.len() as u64)
            .ok_or(Error::LocationOverflow(start_loc))
            .and_then(|end_loc| blueprint(self.leaves, start_loc..end_loc))
        else {
            return false;
        };

        // Combine pinned positions and digests into a map for fast lookup.
        let mut pinned_map: BTreeMap<Position, D> = pinned_positions
            .into_iter()
            .zip(pinned_nodes.iter().copied())
            .collect();

        // Verify fold-prefix pinned nodes by recomputing the accumulator (without the leaf
        // count, which is hashed into the final root independently).
        if !bp.fold_prefix.is_empty() {
            if self.digests.is_empty() {
                return false;
            }
            let Some(first) = pinned_map.remove(&bp.fold_prefix[0]) else {
                return false;
            };
            let mut acc = first;
            for pos in &bp.fold_prefix[1..] {
                let Some(digest) = pinned_map.remove(pos) else {
                    return false;
                };
                acc = hasher.fold(&acc, &digest);
            }
            if acc != self.digests[0] {
                return false;
            }
        }

        // Verify remaining pinned nodes (siblings) against the extracted digests.
        let extracted: BTreeMap<Position, D> = collected.into_iter().collect();
        for (pos, digest) in pinned_map {
            if extracted.get(&pos) != Some(&digest) {
                return false;
            }
        }

        true
    }

    /// Reconstructs the root digest of the MMR from the digests in the proof and the provided range
    /// of elements, or returns a [ReconstructionError] if the input data is invalid.
    pub fn reconstruct_root<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<Family = mmr::Family, Digest = D>,
        E: AsRef<[u8]>,
    {
        self.reconstruct_root_impl(hasher, elements, start_loc, None)
    }

    /// Core implementation for reconstructing the MMR root from a proof. Uses the fold-based proof
    /// layout: `[folded_prefix? | after_peaks... | siblings_dfs...]`.
    ///
    /// If `collected_digests` is Some, all node digests encountered during reconstruction are
    /// appended to the wrapped vector.
    fn reconstruct_root_impl<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location,
        mut collected_digests: Option<&mut Vec<(Position, D)>>,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<Family = mmr::Family, Digest = D>,
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

        // Classify peaks.
        let mut before_count = 0usize;
        let mut after_peaks: Vec<Position> = Vec::new();
        let mut range_peaks: Vec<(Position, u32)> = Vec::new();

        for (peak_pos, height) in PeakIterator::new(size) {
            let leftmost_pos = peak_pos + 2 - (1u64 << (height + 1));
            if peak_pos < start_element_pos {
                before_count += 1;
            } else if leftmost_pos > end_element_pos {
                after_peaks.push(peak_pos);
            } else {
                range_peaks.push((peak_pos, height));
            }
        }

        // Slice self.digests into [folded_prefix? | after_peaks... | siblings...]
        let has_prefix = before_count > 0;
        let prefix_digests = if has_prefix { 1 } else { 0 };
        let expected_min = prefix_digests + after_peaks.len();
        if self.digests.len() < expected_min {
            return Err(ReconstructionError::MissingDigests);
        }

        let after_start = prefix_digests;
        let after_end = after_start + after_peaks.len();
        let siblings = &self.digests[after_end..];

        // Fold all peaks into an accumulator (without the leaf count, which is hashed in at the
        // end to prevent malleability via the `leaves` field).
        let mut acc: Option<D> = if has_prefix {
            Some(self.digests[0])
        } else {
            None
        };

        // Reconstruct each range peak and fold into acc.
        let mut sibling_cursor = 0usize;
        let mut elements_iter = elements.iter();
        for &(peak_pos, height) in &range_peaks {
            let peak_digest = peak_digest_from_range(
                hasher,
                RangeInfo {
                    pos: peak_pos,
                    two_h: 1 << height,
                    leftmost_pos: start_element_pos,
                    rightmost_pos: end_element_pos,
                },
                &mut elements_iter,
                siblings,
                &mut sibling_cursor,
                collected_digests.as_deref_mut(),
            )?;
            if let Some(ref mut cd) = collected_digests {
                cd.push((peak_pos, peak_digest));
            }
            acc = Some(acc.map_or(peak_digest, |a| hasher.fold(&a, &peak_digest)));
        }

        // Fold after-peak digests.
        for (i, &after_peak_pos) in after_peaks.iter().enumerate() {
            let digest = self.digests[after_start + i];
            if let Some(ref mut cd) = collected_digests {
                cd.push((after_peak_pos, digest));
            }
            acc = Some(acc.map_or(digest, |a| hasher.fold(&a, &digest)));
        }

        // Verify all elements were consumed.
        if elements_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }

        // Verify all siblings were consumed.
        if sibling_cursor != siblings.len() {
            return Err(ReconstructionError::ExtraDigests);
        }

        // Hash the leaf count into the final result.
        Ok(acc.map_or_else(
            || hasher.digest(&self.leaves.to_be_bytes()),
            |peaks_acc| hasher.hash([self.leaves.to_be_bytes().as_slice(), peaks_acc.as_ref()]),
        ))
    }
}

/// Blueprint for a range proof, separating fold-prefix peaks from nodes that must be fetched.
pub(crate) struct Blueprint {
    /// Peak positions that precede the proven range (to be folded into a single accumulator).
    pub fold_prefix: Vec<Position>,
    /// Node positions to include in the proof: after-peaks followed by DFS siblings.
    pub fetch_nodes: Vec<Position>,
}

/// Collect sibling positions needed to reconstruct a peak digest from a range of elements, in DFS
/// (forward consumption) order. This mirrors the traversal of `peak_digest_from_range`.
fn collect_siblings_dfs(
    pos: Position,
    two_h: u64,
    leftmost_pos: Position,
    rightmost_pos: Position,
    out: &mut Vec<Position>,
) {
    if two_h == 1 {
        return;
    }

    let left_pos = pos - two_h;
    let right_pos = left_pos + two_h - 1;
    let descend_left = left_pos >= leftmost_pos;
    let descend_right = left_pos < rightmost_pos;

    if !descend_left {
        out.push(left_pos);
    } else {
        collect_siblings_dfs(left_pos, two_h >> 1, leftmost_pos, rightmost_pos, out);
    }

    if !descend_right {
        out.push(right_pos);
    } else {
        collect_siblings_dfs(right_pos, two_h >> 1, leftmost_pos, rightmost_pos, out);
    }
}

/// Return a blueprint containing the digests required to generate a proof over the specified range
/// of elements.
///
/// # Errors
///
/// - Returns [Error::InvalidSize] if `size` is not a valid MMR size.
/// - Returns [Error::Empty] if the range is empty.
/// - Returns [Error::LocationOverflow] if a location in `range` >
/// [crate::merkle::Family::MAX_LOCATION].
/// - Returns [Error::RangeOutOfBounds] if the last element position in `range` is out of bounds (>=
/// `size`).
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
    let start_element_pos = Position::try_from(range.start)?;
    let end_element_pos = Position::try_from(end_minus_one)?;

    let mut fold_prefix = Vec::new();
    let mut after_peaks = Vec::new();
    let mut range_peaks: Vec<(Position, u32)> = Vec::new();

    for (peak_pos, height) in PeakIterator::new(size) {
        let leftmost_pos = peak_pos + 2 - (1u64 << (height + 1));
        if peak_pos < start_element_pos {
            fold_prefix.push(peak_pos);
        } else if leftmost_pos > end_element_pos {
            after_peaks.push(peak_pos);
        } else {
            range_peaks.push((peak_pos, height));
        }
    }

    assert!(
        !range_peaks.is_empty(),
        "at least one peak must contain range elements"
    );

    // Build fetch_nodes: after_peaks first, then DFS siblings for each range peak.
    let mut fetch_nodes = after_peaks;
    for &(peak_pos, height) in &range_peaks {
        collect_siblings_dfs(
            peak_pos,
            1 << height,
            start_element_pos,
            end_element_pos,
            &mut fetch_nodes,
        );
    }

    Ok(Blueprint {
        fold_prefix,
        fetch_nodes,
    })
}

/// Build a range proof using the fold-based layout.
///
/// The prover folds prefix peak digests into a single accumulator. The resulting proof contains:
/// `[fold_acc? | after_peaks... | siblings_dfs...]`
///
/// `get_node` returns the digest for a given position, or `None` if pruned.
pub(crate) fn build_range_proof<D, H>(
    hasher: &H,
    leaves: Location,
    range: Range<Location>,
    get_node: impl Fn(Position) -> Option<D>,
) -> Result<Proof<D>, Error>
where
    D: Digest,
    H: Hasher<Family = mmr::Family, Digest = D>,
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

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`.
///
/// The order of positions does not affect the output (sorted internally).
///
/// # Errors
///
/// - Returns [Error::InvalidSize] if `size` is not a valid MMR size.
/// - Returns [Error::Empty] if locations is empty.
/// - Returns [Error::LocationOverflow] if any location in `locations` >
/// [crate::merkle::Family::MAX_LOCATION].
/// - Returns [Error::RangeOutOfBounds] if any location is out of bounds for the given `size`.
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
        let bp = blueprint(leaves, *loc..*loc + 1)?;
        acc.extend(bp.fold_prefix);
        acc.extend(bp.fetch_nodes);

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

/// Reconstruct the peak digest from a DFS traversal over the range of elements and siblings.
/// Siblings are consumed in forward order from `siblings[*cursor..]`.
fn peak_digest_from_range<D, H, E>(
    hasher: &H,
    range_info: RangeInfo,
    elements: &mut E,
    siblings: &[D],
    cursor: &mut usize,
    mut collected_digests: Option<&mut Vec<(Position, D)>>,
) -> Result<D, ReconstructionError>
where
    D: Digest,
    H: Hasher<Family = mmr::Family, Digest = D>,
    E: Iterator<Item: AsRef<[u8]>>,
{
    assert_ne!(range_info.two_h, 0);
    if range_info.two_h == 1 {
        match elements.next() {
            Some(element) => return Ok(hasher.leaf_digest(range_info.pos, element.as_ref())),
            None => return Err(ReconstructionError::MissingDigests),
        }
    }

    let left_pos = range_info.pos - range_info.two_h;
    let right_pos = left_pos + range_info.two_h - 1;
    let descend_left = left_pos >= range_info.leftmost_pos;
    let descend_right = left_pos < range_info.rightmost_pos;

    // Read siblings and descend in the same order as collect_siblings_dfs.
    let left_digest = if descend_left {
        peak_digest_from_range(
            hasher,
            RangeInfo {
                pos: left_pos,
                two_h: range_info.two_h >> 1,
                leftmost_pos: range_info.leftmost_pos,
                rightmost_pos: range_info.rightmost_pos,
            },
            elements,
            siblings,
            cursor,
            collected_digests.as_deref_mut(),
        )?
    } else {
        if *cursor >= siblings.len() {
            return Err(ReconstructionError::MissingDigests);
        }
        let d = siblings[*cursor];
        *cursor += 1;
        d
    };

    let right_digest = if descend_right {
        peak_digest_from_range(
            hasher,
            RangeInfo {
                pos: right_pos,
                two_h: range_info.two_h >> 1,
                leftmost_pos: range_info.leftmost_pos,
                rightmost_pos: range_info.rightmost_pos,
            },
            elements,
            siblings,
            cursor,
            collected_digests.as_deref_mut(),
        )?
    } else {
        if *cursor >= siblings.len() {
            return Err(ReconstructionError::MissingDigests);
        }
        let d = siblings[*cursor];
        *cursor += 1;
        d
    };

    if let Some(ref mut cd) = collected_digests {
        cd.push((left_pos, left_digest));
        cd.push((right_pos, right_digest));
    }

    Ok(hasher.node_digest(range_info.pos, &left_digest, &right_digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        location::LocationRangeExt as _,
        mmr,
        mmr::{mem::Mmr, StandardHasher as Standard},
        Family,
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
        let hasher: Standard<Sha256> = Standard::new();
        let mmr = Mmr::new(&hasher);
        let root = mmr.root();
        let proof = Proof::default();
        assert!(proof.verify_range_inclusion(&hasher, &[] as &[Digest], Location::new(0), root));

        // Any starting position other than 0 should fail to verify.
        assert!(!proof.verify_range_inclusion(&hasher, &[] as &[Digest], Location::new(1), root));

        // Invalid root should fail to verify.
        let test_digest = test_digest(0);
        assert!(!proof.verify_range_inclusion(
            &hasher,
            &[] as &[Digest],
            Location::new(0),
            &test_digest
        ));

        // Non-empty elements list should fail to verify.
        assert!(!proof.verify_range_inclusion(&hasher, &[test_digest], Location::new(0), root));
    }

    #[test]
    fn test_proving_verify_element() {
        // create an 11 element MMR over which we'll test single-element inclusion proofs
        let element = Digest::from(*b"01234567012345670123456701234567");
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let changeset = {
            let mut batch = mmr.new_batch();
            for _ in 0..11 {
                batch = batch.add(&hasher, &element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        let root = mmr.root();

        // confirm the proof of inclusion for each leaf successfully verifies
        for leaf in 0u64..11 {
            let leaf = Location::new(leaf);
            let proof: Proof<Digest> = mmr.proof(&hasher, leaf).unwrap();
            assert!(
                proof.verify_element_inclusion(&hasher, &element, leaf, root),
                "valid proof should verify successfully"
            );
        }

        // Create a valid proof, then confirm various mangling of the proof or proof args results in
        // verification failure.
        const LEAF: Location = Location::new(10);
        let proof = mmr.proof(&hasher, LEAF).unwrap();
        assert!(
            proof.verify_element_inclusion(&hasher, &element, LEAF, root),
            "proof verification should be successful"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, LEAF + 1, root),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, LEAF - 1, root),
            "proof verification should fail with incorrect element position 2"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &test_digest(0), LEAF, root),
            "proof verification should fail with mangled element"
        );
        let root2 = test_digest(0);
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, LEAF, &root2),
            "proof verification should fail with mangled root"
        );
        let mut proof2 = proof.clone();
        proof2.digests[0] = test_digest(0);
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, LEAF, root),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.leaves = Location::new(10);
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, LEAF, root),
            "proof verification should fail with incorrect leaves"
        );
        proof2 = proof.clone();
        proof2.digests.push(test_digest(0));
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, LEAF, root),
            "proof verification should fail with extra hash"
        );
        proof2 = proof.clone();
        while !proof2.digests.is_empty() {
            proof2.digests.pop();
            assert!(
                !proof2.verify_element_inclusion(&hasher, &element, LEAF, root),
                "proof verification should fail with missing digests"
            );
        }
        // Inserting an extra digest in the middle should cause verification failure.
        if proof.digests.len() >= 2 {
            proof2 = proof.clone();
            proof2.digests.clear();
            proof2.digests.extend(proof.digests[0..1].iter().cloned());
            proof2.digests.push(test_digest(0));
            proof2.digests.extend(proof.digests[1..].iter().cloned());
            assert!(
                !proof2.verify_element_inclusion(&hasher, &element, LEAF, root),
                "proof verification should fail with extra hash even if it's unused by the computation"
            );
        }
    }

    #[test]
    fn test_proving_verify_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let elements: Vec<_> = (0..49).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        // test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root();

        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &hasher,
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
        let range_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
        let valid_elements = &elements[range.to_usize_range()];
        assert!(
            range_proof.verify_range_inclusion(&hasher, valid_elements, range.start, root),
            "valid range proof should verify successfully"
        );
        // Remove digests from the proof until it's empty, confirming proof verification fails for
        // each.
        let mut invalid_proof = range_proof.clone();
        for _i in 0..range_proof.digests.len() {
            invalid_proof.digests.remove(0);
            assert!(
                !invalid_proof.verify_range_inclusion(&hasher, valid_elements, range.start, root,),
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
                        &hasher,
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
                &hasher,
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
                !invalid_proof.verify_range_inclusion(&hasher, valid_elements, range.start, root,),
                "mangled range proof should fail verification"
            );
        }
        // Inserting elements into the proof should also cause it to fail (malleability check)
        for i in 0..range_proof.digests.len() {
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests.insert(i, test_digest(0));
            assert!(
                !invalid_proof.verify_range_inclusion(&hasher, valid_elements, range.start, root,),
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
                !range_proof.verify_range_inclusion(&hasher, valid_elements, loc, root),
                "bad start_loc should fail verification {loc}",
            );
        }
    }

    #[test_traced]
    fn test_proving_retained_nodes_provable_after_pruning() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let elements: Vec<_> = (0..49).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();

        // Confirm we can successfully prove all retained elements in the MMR after pruning.
        let root = *mmr.root();
        for prune_leaf in 1..*mmr.leaves() {
            let prune_loc = Location::new(prune_leaf);
            mmr.prune(prune_loc).unwrap();
            let pruned_root = mmr.root();
            assert_eq!(root, *pruned_root);
            for loc in 0..elements.len() {
                let loc = Location::new(loc as u64);
                let proof = mmr.proof(&hasher, loc);
                if loc < prune_loc {
                    continue;
                }
                assert!(proof.is_ok());
                assert!(proof.unwrap().verify_element_inclusion(
                    &hasher,
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
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let mut elements: Vec<_> = (0..49).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();

        // prune up to the first peak
        const PRUNE_LOC: Location = Location::new(32);
        mmr.prune(PRUNE_LOC).unwrap();
        assert_eq!(mmr.bounds().start, PRUNE_LOC);

        // Test range proofs over all possible ranges of at least 2 elements
        let root = mmr.root();
        for i in 0..elements.len() - 1 {
            if Location::new(i as u64) < PRUNE_LOC {
                continue;
            }
            for j in (i + 2)..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &hasher,
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
        let new_elements: Vec<_> = (0..37).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &new_elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        elements.extend(new_elements);
        mmr.prune(Location::new(66)).unwrap(); // a bit after the new highest peak
        assert_eq!(mmr.bounds().start, Location::new(66));

        let updated_root = mmr.root();
        let range = Location::new(elements.len() as u64 - 10)..Location::new(elements.len() as u64);
        let range_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
        assert!(
                range_proof.verify_range_inclusion(
                    &hasher,
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
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let elements: Vec<_> = (0..25).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();

        // Generate proofs over all possible ranges of elements and confirm each
        // serializes=>deserializes correctly.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let proof = mmr.range_proof(&hasher, range).unwrap();

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

    // TODO: Add tests for extract_pinned_nodes once the method is implemented.

    #[test]
    fn test_proving_digests_from_range() {
        // create a new MMR and add a non-trivial amount (49) of elements
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let elements: Vec<_> = (0..49).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        let root = mmr.root();

        // Test 1: compute_digests over the entire range should contain a digest for every node
        // in the tree.
        let proof = mmr
            .range_proof(&hasher, Location::new(0)..mmr.leaves())
            .unwrap();
        let mut node_digests = proof
            .verify_range_inclusion_and_extract_digests(&hasher, &elements, Location::new(0), root)
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
                &hasher,
                &elements,
                Location::new(0),
                &wrong_root
            ),
            Err(Error::RootMismatch)
        ));

        // Test 2: Single element range (first element)
        let range = Location::new(0)..Location::new(1);
        let single_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
        let range_start = range.start;
        let single_digests = single_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
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
        let mid_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
        let mid_digests = mid_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        assert!(mid_digests.len() > 1);

        // Test 4: Single element range (last element)
        let last_idx = elements.len() as u64 - 1;
        let range = Location::new(last_idx)..Location::new(last_idx + 1);
        let range_start = range.start;
        let last_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
        let last_digests = last_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
                &elements[range.to_usize_range()],
                range_start,
                root,
            )
            .unwrap();
        assert!(!last_digests.is_empty());

        // Test 5: Small range at the beginning
        let range = Location::new(0)..Location::new(5);
        let range_start = range.start;
        let small_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
        let small_digests = small_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
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
        let mid_range_proof = mmr.range_proof(&hasher, range.clone()).unwrap();
        let mid_range_digests = mid_range_proof
            .verify_range_inclusion_and_extract_digests(
                &hasher,
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
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let elements: Vec<_> = (0..20).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();

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
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            root
        ));

        // Verify in different order
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[10], Location::new(10)),
                (elements[5], Location::new(5)),
                (elements[0], Location::new(0)),
            ],
            root
        ));

        // Verify with duplicate items
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
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
        wrong_size_proof.leaves = Location::new(*<mmr::Family as Family>::MAX_LOCATION + 2);
        assert!(!wrong_size_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            root,
        ));

        // Verify with wrong positions
        assert!(!multi_proof.verify_multi_inclusion(
            &hasher,
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
            &hasher,
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
            &hasher,
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
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            &wrong_root
        ));

        // Empty multi-proof
        let hasher: Standard<Sha256> = Standard::new();
        let empty_mmr = Mmr::new(&hasher);
        let empty_root = empty_mmr.root();
        let empty_proof = Proof::default();
        assert!(empty_proof.verify_multi_inclusion(
            &hasher,
            &[] as &[(Digest, Location)],
            empty_root
        ));
    }

    #[test]
    fn test_proving_multi_proof_deduplication() {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        // Create an MMR with enough elements to have shared digests
        let elements: Vec<_> = (0..30).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();

        // Get individual proofs that will share some digests (elements in same subtree)
        let proof1 = mmr.proof(&hasher, Location::new(0)).unwrap();
        let proof2 = mmr.proof(&hasher, Location::new(1)).unwrap();
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
            &hasher,
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
        let max_loc = <mmr::Family as Family>::MAX_LOCATION;
        let max_loc_plus_1 = Location::new(*max_loc + 1);

        let result = blueprint(max_loc, max_loc - 1..max_loc);
        assert!(
            result.is_ok(),
            "Should be able to prove with MAX_LOCATION leaves"
        );

        // MAX_LOCATION + 1 should be rejected (exceeds MAX_LOCATION)
        let result_overflow = blueprint(max_loc_plus_1, max_loc..max_loc_plus_1);
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
        let max_loc = <mmr::Family as Family>::MAX_LOCATION;
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
            many_peaks_size.is_valid_size(),
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
        let loc = Location::new(0);
        let bp = blueprint(leaves, loc..loc + 1).expect("should compute blueprint for location 0");
        let total_nodes = bp.fold_prefix.len() + bp.fetch_nodes.len();

        assert_eq!(
            total_nodes,
            EXPECTED_WORST_CASE,
            "Location 0 proof should require exactly {EXPECTED_WORST_CASE} digests (61 path + 61 peaks)",
        );

        // Test the rightmost leaf (in smallest tree of height 0, which is itself a peak)
        // Expected: 0 path siblings + 61 other peaks = 61 digests
        let last_leaf_loc = leaves - 1;
        let bp = blueprint(leaves, last_leaf_loc..last_leaf_loc + 1)
            .expect("should compute blueprint for last leaf");
        let total_nodes = bp.fold_prefix.len() + bp.fetch_nodes.len();

        let expected_last_leaf = NUM_PEAKS - 1;
        assert_eq!(
            total_nodes,
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
        // This exceeds MAX_POSITION, so is_valid_size() returns false.

        let n_for_63_peaks = (1u128 << 63) - 1;
        let size_for_63_peaks = 2 * n_for_63_peaks - 63; // = 2^64 - 65
        assert!(
            size_for_63_peaks > *<mmr::Family as Family>::MAX_POSITION as u128,
            "63 peaks requires size {size_for_63_peaks} > MAX_POSITION",
        );

        let size_truncated = size_for_63_peaks as u64;
        assert!(
            !Position::new(size_truncated).is_valid_size(),
            "Size for 63 peaks should fail is_valid_size()"
        );
    }

    /// Regression test: pinned nodes that are sibling digests (not fold-prefix peaks) must be
    /// verified against the extracted proof digests. A 3-leaf MMR with start_loc=1 has a pinned
    /// node at position 0 (L0) which is a sibling within the range peak, not a fold-prefix peak.
    #[test]
    fn test_verify_proof_and_pinned_nodes_sibling_case() {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        let elements: Vec<Digest> = (0..3).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for e in &elements {
                batch = batch.add(&hasher, e);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        let root = mmr.root();

        // Proof for range [1, 3) — fold prefix is empty, pinned node at position 0 is a sibling.
        let start_loc = Location::new(1);
        let proof = mmr
            .range_proof(&hasher, start_loc..Location::new(3))
            .unwrap();

        let pinned: Vec<Digest> = mmr
            .nodes_to_pin(Position::try_from(start_loc).unwrap())
            .into_values()
            .collect();
        assert_eq!(pinned.len(), 1, "should have exactly one pinned node");

        // Correct pinned nodes must verify.
        assert!(
            proof.verify_proof_and_pinned_nodes(&hasher, &elements[1..], start_loc, &pinned, root,),
            "valid pinned nodes should verify"
        );

        // Wrong pinned digest must fail.
        let bad_pinned = vec![test_digest(99)];
        assert!(
            !proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[1..],
                start_loc,
                &bad_pinned,
                root,
            ),
            "wrong pinned digest should fail"
        );

        // Extra pinned node must fail.
        let extra_pinned = vec![pinned[0], test_digest(42)];
        assert!(
            !proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[1..],
                start_loc,
                &extra_pinned,
                root,
            ),
            "extra pinned node should fail"
        );

        // Empty pinned nodes must fail (start_loc > 0 requires at least one).
        assert!(
            !proof.verify_proof_and_pinned_nodes(&hasher, &elements[1..], start_loc, &[], root,),
            "missing pinned nodes should fail"
        );
    }

    /// Test verify_proof_and_pinned_nodes when pinned nodes ARE fold-prefix peaks.
    #[test]
    fn test_verify_proof_and_pinned_nodes_fold_prefix_case() {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);
        // 10-leaf MMR: peaks at positions covering [0-7] and [8-9].
        // start_loc=8 puts the first peak entirely in the fold prefix.
        let elements: Vec<Digest> = (0..10).map(test_digest).collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for e in &elements {
                batch = batch.add(&hasher, e);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        let root = mmr.root();

        let start_loc = Location::new(8);
        let proof = mmr
            .range_proof(&hasher, start_loc..Location::new(10))
            .unwrap();

        let pinned: Vec<Digest> = mmr
            .nodes_to_pin(Position::try_from(start_loc).unwrap())
            .into_values()
            .collect();
        assert_eq!(pinned.len(), 1, "should have one fold-prefix peak");

        assert!(
            proof.verify_proof_and_pinned_nodes(&hasher, &elements[8..], start_loc, &pinned, root,),
            "valid fold-prefix pinned nodes should verify"
        );

        // Wrong digest must fail.
        assert!(
            !proof.verify_proof_and_pinned_nodes(
                &hasher,
                &elements[8..],
                start_loc,
                &[test_digest(99)],
                root,
            ),
            "wrong fold-prefix digest should fail"
        );
    }

    /// Regression test: mutating only the `leaves` field in a proof must invalidate it.
    /// Before the fix, when a fold prefix existed, the leaf count was baked into the
    /// pre-folded accumulator but not independently checked during verification, so a
    /// different `leaves` value with a compatible peak structure would still verify.
    #[test]
    fn test_proof_leaves_malleability() {
        let hasher: Standard<Sha256> = Standard::new();
        let mut mmr = Mmr::new(&hasher);

        // 252 leaves. Leaf 240 sits in a peak preceded by 4 prefix peaks.
        let elements: Vec<Digest> = (0..252u16)
            .map(|i| Sha256::hash(&i.to_be_bytes()))
            .collect();
        let changeset = {
            let mut batch = mmr.new_batch();
            for e in &elements {
                batch = batch.add(&hasher, e);
            }
            batch.merkleize(&hasher).finalize()
        };
        mmr.apply(changeset).unwrap();
        let root = mmr.root();

        let loc = Location::new(240);
        let proof = mmr.proof(&hasher, loc).unwrap();
        assert!(proof.verify_element_inclusion(&hasher, &elements[240], loc, root));

        // Tamper with the leaves field (249 has the same peak layout for leaf 240).
        let mut tampered = proof.clone();
        tampered.leaves = Location::new(249);
        assert_ne!(tampered, proof);
        assert!(
            !tampered.verify_element_inclusion(&hasher, &elements[240], loc, root),
            "proof with tampered leaves field must not verify"
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
