//! Defines the generic inclusion [Proof] structure for Merkle-family data structures.
//!
//! The [Proof] struct is parameterized by a [`Family`] marker and a [`Digest`] type. Each Merkle
//! family (MMR, MMB, etc.) reuses the shared verification and reconstruction logic in this module,
//! while retaining any family-specific proof helpers in its submodule.

use crate::merkle::{hasher::Hasher, Error, Family, Location, Position};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;
use core::ops::Range;

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
/// elements, in a Merkle-family data structure from its root digest.
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
pub struct Proof<F: Family, D: Digest> {
    /// The total number of leaves in the data structure. For MMR proofs, this is the number of
    /// leaves in the MMR, though other authenticated data structures may override the meaning of
    /// this field. For example, the authenticated [crate::AuthenticatedBitMap] stores the number
    /// of bits in the bitmap within this field.
    pub leaves: Location<F>,
    /// The digests necessary for proving inclusion.
    pub digests: Vec<D>,
}

impl<F: Family, D: Digest> PartialEq for Proof<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.leaves == other.leaves && self.digests == other.digests
    }
}

impl<F: Family, D: Digest> EncodeSize for Proof<F, D> {
    fn encode_size(&self) -> usize {
        self.leaves.encode_size() + self.digests.encode_size()
    }
}

impl<F: Family, D: Digest> Write for Proof<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.leaves.write(buf);
        self.digests.write(buf);
    }
}

impl<F: Family, D: Digest> commonware_codec::Read for Proof<F, D> {
    /// The maximum number of digests in the proof.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_digests: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let leaves = Location::<F>::read(buf)?;
        let digests = Vec::<D>::read_range(buf, ..=*max_digests)?;
        Ok(Self { leaves, digests })
    }
}

impl<F: Family, D: Digest> Default for Proof<F, D> {
    /// Create an empty proof. The empty proof will verify only against the root digest of an empty
    /// (`leaves == 0`) data structure.
    fn default() -> Self {
        Self {
            leaves: Location::new(0),
            digests: vec![],
        }
    }
}

impl<F: Family, D: Digest> Proof<F, D> {
    /// Return true if this proof proves that `element` appears at location `loc` within the
    /// structure with root digest `root`.
    pub fn verify_element_inclusion<H>(
        &self,
        hasher: &H,
        element: &[u8],
        loc: Location<F>,
        root: &D,
    ) -> bool
    where
        H: Hasher<F, Digest = D>,
    {
        self.verify_range_inclusion(hasher, &[element], loc, root)
    }

    /// Return true if this proof proves that the `elements` appear consecutively starting at
    /// `start_loc` within the structure with root digest `root`.
    pub fn verify_range_inclusion<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
        root: &D,
    ) -> bool
    where
        H: Hasher<F, Digest = D>,
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
    /// in the structure with root digest `root`. A malformed proof will return false.
    ///
    /// The order of the elements does not affect the output.
    pub fn verify_multi_inclusion<H, E>(
        &self,
        hasher: &H,
        elements: &[(E, Location<F>)],
        root: &D,
    ) -> bool
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        // Empty proof is valid only for an empty tree with no extra digest data.
        if elements.is_empty() {
            return self.digests.is_empty()
                && self.leaves == Location::new(0)
                && *root == hasher.root(Location::new(0), core::iter::empty());
        }

        // Collect all required positions with deduplication, and blueprints per element.
        let mut node_positions = BTreeSet::new();
        let mut blueprints = BTreeMap::new();

        for (_, loc) in elements {
            if !loc.is_valid_index() {
                return false;
            }
            // `loc` is valid so it won't overflow from +1
            let Ok(bp) = Blueprint::new(self.leaves, *loc..*loc + 1) else {
                return false;
            };
            node_positions.extend(bp.fold_prefix.iter().map(|s| s.pos));
            node_positions.extend(&bp.fetch_nodes);
            blueprints.insert(*loc, bp);
        }

        // Verify we have the exact number of digests needed
        if node_positions.len() != self.digests.len() {
            return false;
        }

        // Build position to digest mapping once
        let node_digests: BTreeMap<Position<F>, D> = node_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, digest)| (pos, *digest))
            .collect();

        // Verify each element by constructing its sub-proof in fold-based format
        for (element, loc) in elements {
            let bp = &blueprints[loc];

            let mut digests = Vec::with_capacity(
                if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len(),
            );
            if let Some((first_sub, rest)) = bp.fold_prefix.split_first() {
                let first = *node_digests
                    .get(&first_sub.pos)
                    .expect("must exist by construction");
                let acc = rest.iter().fold(first, |acc, sub| {
                    let d = node_digests
                        .get(&sub.pos)
                        .expect("must exist by construction");
                    hasher.fold(&acc, d)
                });
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

    /// Reconstruct the root digest from this proof and the given consecutive elements,
    /// or return a `ReconstructionError` if the input data is invalid.
    pub fn reconstruct_root<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        self.reconstruct_root_collecting(hasher, elements, start_loc, None)
    }

    /// Reconstructs the root digest from the digests in the proof and the provided range
    /// of elements, returning the (position,digest) of every node whose digest was required by the
    /// process (including those from the proof itself). Returns [Error::InvalidProof] if the
    /// input data is invalid and [Error::RootMismatch] if the root does not match the computed
    /// root.
    pub fn verify_range_inclusion_and_extract_digests<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
        root: &D,
    ) -> Result<Vec<(Position<F>, D)>, Error<F>>
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        let mut collected_digests = Vec::new();
        let Ok(reconstructed_root) = self.reconstruct_root_collecting(
            hasher,
            elements,
            start_loc,
            Some(&mut collected_digests),
        ) else {
            return Err(Error::InvalidProof);
        };

        if reconstructed_root != *root {
            return Err(Error::RootMismatch);
        }

        Ok(collected_digests)
    }

    /// Verify that both the proof and the pinned nodes are valid with respect to `root`.
    ///
    /// The `pinned_nodes` are the peak digests of the sub-structure at `start_loc`, in the order
    /// returned by `Family::nodes_to_pin`. The proof authenticates the prefix `[0, start_loc)` via:
    ///
    /// - fold-prefix peaks of the larger tree, and
    /// - sibling subtrees inside the first range peak that lie wholly before `start_loc`.
    ///
    /// When the larger tree has merged smaller subtrees into a bigger parent, the pins sit below
    /// these authenticated subtrees. The verifier hashes pairs of pins up to each authenticated
    /// subtree's root and compares against the proof.
    ///
    /// For example, in MMB at `leaves=5, start_loc=4`, the proof describes `[0, 4)` as one
    /// height-2 subtree `p7`, while the pins cover the same leaves as two height-1 subtrees
    /// `p2`, `p5`:
    ///
    /// ```text
    ///     proof authenticates:         pins contain:
    ///
    ///             p7
    ///           /    \
    ///          p2    p5                p2         p5
    ///         / \    / \              / \        / \
    ///        L0 L1  L2 L3            L0 L1      L2 L3
    /// ```
    ///
    /// The verifier walks down from `p7` via `F::children`, pulls the pins for `p2` and `p5`, and
    /// hashes them back up (`node_digest(p7, pin[p2], pin[p5])`) to compare against the `p7`
    /// digest the proof authenticates.
    ///
    /// Returns `true` only if the proof reconstructs to `root` and every pinned node digest is
    /// accounted for. When `start_loc` is 0, `pinned_nodes` must be empty.
    pub fn verify_proof_and_pinned_nodes<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
        pinned_nodes: &[D],
        root: &D,
    ) -> bool
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        self.try_verify_proof_and_pinned_nodes(hasher, elements, start_loc, pinned_nodes, root)
            .is_some()
    }

    /// Fallible implementation of [`verify_proof_and_pinned_nodes`](Self::verify_proof_and_pinned_nodes).
    ///
    /// Returns `Some(())` if the proof and pins are consistent with `root`, `None` otherwise. The
    /// `Option` return lets the body use `?` on each fallible step; the public wrapper converts to
    /// `bool` via `.is_some()`.
    fn try_verify_proof_and_pinned_nodes<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
        pinned_nodes: &[D],
        root: &D,
    ) -> Option<()>
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        let collected = self
            .verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)
            .ok()?;

        if elements.is_empty() {
            return pinned_nodes.is_empty().then_some(());
        }

        if !start_loc.is_valid() || start_loc > self.leaves {
            return None;
        }

        let pinned_positions: Vec<_> = F::nodes_to_pin(start_loc).collect();
        if pinned_positions.len() != pinned_nodes.len() {
            return None;
        }

        let end_loc = start_loc.checked_add(elements.len() as u64)?;
        let bp = Blueprint::new(self.leaves, start_loc..end_loc).ok()?;

        let mut pinned_map: BTreeMap<Position<F>, D> = pinned_positions
            .into_iter()
            .zip(pinned_nodes.iter().copied())
            .collect();

        // Fold-prefix peaks of the larger tree may have merged several pins together. Reconstruct
        // each peak's digest by hashing the pins beneath it up to the peak, then compare the
        // folded accumulator against the one the proof carries.
        if let Some((first_sub, rest)) = bp.fold_prefix.split_first() {
            let &expected = self.digests.first()?;
            let mut acc = first_sub.reconstruct_from_pins(hasher, &mut pinned_map)?;
            for sub in rest {
                let d = sub.reconstruct_from_pins(hasher, &mut pinned_map)?;
                acc = hasher.fold(&acc, &d);
            }
            if acc != expected {
                return None;
            }
        }

        // Sibling subtrees inside the first range peak that lie wholly before `start_loc` are
        // authenticated directly by the proof (their digests appear in `extracted`). Rebuild each
        // from the pins and compare.
        let extracted: BTreeMap<Position<F>, D> = collected.into_iter().collect();
        for sibling in bp.prefix_siblings() {
            let &expected = extracted.get(&sibling.pos)?;
            let d = sibling.reconstruct_from_pins(hasher, &mut pinned_map)?;
            if d != expected {
                return None;
            }
        }

        // Every pin must have been consumed by one of the two reconstructions above.
        pinned_map.is_empty().then_some(())
    }

    /// Like [`reconstruct_root`](Self::reconstruct_root), but if `collected` is `Some`, every
    /// `(position, digest)` pair encountered during reconstruction is appended.
    pub(crate) fn reconstruct_root_collecting<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
        mut collected: Option<&mut Vec<(Position<F>, D)>>,
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<F, Digest = D>,
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
        if !start_loc.is_valid_index() {
            return Err(ReconstructionError::InvalidStartLoc);
        }
        let end_loc = start_loc
            .checked_add(elements.len() as u64)
            .ok_or(ReconstructionError::InvalidEndLoc)?;
        if end_loc > self.leaves {
            return Err(ReconstructionError::InvalidEndLoc);
        }
        let range = start_loc..end_loc;

        let bp =
            Blueprint::new(self.leaves, range).map_err(|_| ReconstructionError::InvalidSize)?;

        // Slice self.digests into [folded_prefix? | after_peaks... | siblings...]
        let prefix_digests = usize::from(!bp.fold_prefix.is_empty());
        let expected_min = prefix_digests + bp.fetch_nodes.len();
        if self.digests.len() < expected_min {
            return Err(ReconstructionError::MissingDigests);
        }

        // Blueprint's fetch_nodes contains after_peaks then the DFS sibling digests. We need to
        // know how many after_peaks there are to skip over them.
        let after_start = prefix_digests;
        let after_peaks_count = bp.after_peaks.len();
        let after_end = after_start + after_peaks_count;
        let siblings = &self.digests[after_end..];

        // Collect all peak digests to provide to hasher.root().
        let mut peak_digests = Vec::new();
        if !bp.fold_prefix.is_empty() {
            peak_digests.push(self.digests[0]);
        }

        let mut sibling_cursor = 0usize;
        let mut elements_iter = elements.iter();
        for peak in &bp.range_peaks {
            let peak_digest = peak.reconstruct_digest(
                hasher,
                &bp.range,
                &mut elements_iter,
                siblings,
                &mut sibling_cursor,
                collected.as_deref_mut(),
            )?;
            if let Some(ref mut cd) = collected {
                cd.push((peak.pos, peak_digest));
            }
            peak_digests.push(peak_digest);
        }

        for (i, &after_peak_pos) in bp.after_peaks.iter().enumerate() {
            let digest = self.digests[after_start + i];
            if let Some(ref mut cd) = collected {
                cd.push((after_peak_pos, digest));
            }
            peak_digests.push(digest);
        }

        // Verify all elements were consumed.
        if elements_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }

        // Verify all siblings were consumed.
        if sibling_cursor != siblings.len() {
            return Err(ReconstructionError::ExtraDigests);
        }

        Ok(hasher.root(self.leaves, peak_digests.iter()))
    }
}

/// A perfect binary subtree within a peak, identified by its root position, height,
/// and the first leaf location it covers.
#[derive(Copy, Clone)]
pub(crate) struct Subtree<F: Family> {
    /// Position of the subtree root node.
    pub pos: Position<F>,
    pub height: u32,
    pub leaf_start: Location<F>,
}

impl<F: Family> Subtree<F> {
    fn leaf_end(&self) -> Location<F> {
        self.leaf_start + (1u64 << self.height)
    }

    /// True if this subtree's leaves lie wholly before `range.start`.
    fn is_before(&self, range: &Range<Location<F>>) -> bool {
        self.leaf_end() <= range.start
    }

    /// True if this subtree's leaves lie wholly outside `range` (either before it or after it).
    fn is_outside(&self, range: &Range<Location<F>>) -> bool {
        self.is_before(range) || self.leaf_start >= range.end
    }

    fn children(&self) -> (Self, Self) {
        let (left_pos, right_pos) = F::children(self.pos, self.height);
        let child_height = self.height - 1;
        let mid = self.leaf_start + (1u64 << child_height);
        (
            Self {
                pos: left_pos,
                height: child_height,
                leaf_start: self.leaf_start,
            },
            Self {
                pos: right_pos,
                height: child_height,
                leaf_start: mid,
            },
        )
    }

    /// Collect sibling positions needed to reconstruct this subtree digest from a range of
    /// elements, in left-first DFS order.
    ///
    /// At each node: if the subtree is entirely outside the range, its root position is emitted. If
    /// it's a leaf in the range, nothing is emitted. Otherwise, recurse into children.
    fn collect_siblings(&self, range: &Range<Location<F>>, out: &mut Vec<Position<F>>) {
        if self.is_outside(range) {
            out.push(self.pos);
            return;
        }

        if self.height > 0 {
            let (left, right) = self.children();
            left.collect_siblings(range, out);
            right.collect_siblings(range, out);
        }
    }

    /// Collect sibling subtrees that lie wholly before the proven range, in the same
    /// left-first DFS order as [`collect_siblings`](Self::collect_siblings).
    ///
    /// Only `range.start` is consulted: the `range.end` side doesn't matter for prefix
    /// siblings. Pruning on `range.start` also keeps the traversal O(height) per peak —
    /// pruning only by `range.end` would recurse into both children whenever a subtree
    /// sits entirely inside the proven range, costing O(2^height) per such peak.
    fn collect_prefix_siblings(&self, range: &Range<Location<F>>, out: &mut Vec<Self>) {
        if self.is_before(range) {
            out.push(*self);
            return;
        }

        if self.leaf_start >= range.start {
            return;
        }

        if self.height > 0 {
            let (left, right) = self.children();
            left.collect_prefix_siblings(range, out);
            right.collect_prefix_siblings(range, out);
        }
    }

    /// Reconstruct this subtree's digest from a set of finer-grained pinned positions, consuming
    /// each pin as it is used.
    ///
    /// Walks down via [`Self::children`] until each recursion hits a pin, then hashes back up with
    /// [`Hasher::node_digest`] for position-keyed domain separation. Returns `None` if any required
    /// pin is missing.
    ///
    /// On failure, `pinned_map` may have been partially consumed. Callers are expected to return
    /// immediately without inspecting it further.
    fn reconstruct_from_pins<D, H>(
        &self,
        hasher: &H,
        pinned_map: &mut BTreeMap<Position<F>, D>,
    ) -> Option<D>
    where
        D: Digest,
        H: Hasher<F, Digest = D>,
    {
        if let Some(d) = pinned_map.remove(&self.pos) {
            return Some(d);
        }
        if self.height == 0 {
            return None;
        }
        let (left, right) = self.children();
        let left_d = left.reconstruct_from_pins(hasher, pinned_map)?;
        let right_d = right.reconstruct_from_pins(hasher, pinned_map)?;
        Some(hasher.node_digest(self.pos, &left_d, &right_d))
    }

    /// Reconstruct the digest of this subtree from a range of elements and sibling digests,
    /// consuming both in left-first DFS order.
    ///
    /// At each node:
    /// - If the subtree is entirely outside the range: consume a sibling digest.
    /// - If it's a leaf in the range: hash the next element.
    /// - Otherwise: recurse into children via [`Family::children`] and compute the node digest.
    ///
    /// If `collected` is `Some`, every child `(position, digest)` pair encountered during
    /// reconstruction is appended to the vector.
    fn reconstruct_digest<D, H, E>(
        &self,
        hasher: &H,
        range: &Range<Location<F>>,
        elements: &mut E,
        siblings: &[D],
        cursor: &mut usize,
        mut collected: Option<&mut Vec<(Position<F>, D)>>,
    ) -> Result<D, ReconstructionError>
    where
        D: Digest,
        H: Hasher<F, Digest = D>,
        E: Iterator<Item: AsRef<[u8]>>,
    {
        // Entirely outside the range: consume a sibling digest.
        if self.is_outside(range) {
            let Some(digest) = siblings.get(*cursor).copied() else {
                return Err(ReconstructionError::MissingDigests);
            };
            *cursor += 1;
            return Ok(digest);
        }

        // Leaf in range: hash the next element.
        if self.height == 0 {
            let elem = elements
                .next()
                .ok_or(ReconstructionError::MissingElements)?;
            return Ok(hasher.leaf_digest(self.pos, elem.as_ref()));
        }

        // Recurse into children.
        let (left, right) = self.children();
        let left_d = left.reconstruct_digest(
            hasher,
            range,
            elements,
            siblings,
            cursor,
            collected.as_deref_mut(),
        )?;
        let right_d = right.reconstruct_digest(
            hasher,
            range,
            elements,
            siblings,
            cursor,
            collected.as_deref_mut(),
        )?;

        if let Some(ref mut cd) = collected {
            cd.push((left.pos, left_d));
            cd.push((right.pos, right_d));
        }

        Ok(hasher.node_digest(self.pos, &left_d, &right_d))
    }
}

/// Blueprint for a range proof, separating fold-prefix peaks from nodes that must be fetched.
pub(crate) struct Blueprint<F: Family> {
    /// Total number of leaves in the structure this blueprint was built for.
    leaves: Location<F>,
    /// The location range this blueprint was built for.
    pub range: Range<Location<F>>,
    /// Peaks that precede the proven range (to be folded into a single accumulator).
    pub fold_prefix: Vec<Subtree<F>>,
    /// Peak positions entirely after the proven range.
    pub after_peaks: Vec<Position<F>>,
    /// The peaks that overlap the proven range.
    pub range_peaks: Vec<Subtree<F>>,
    /// Node positions to include in the proof: after-peaks followed by DFS siblings.
    pub fetch_nodes: Vec<Position<F>>,
}

impl<F: Family> Blueprint<F> {
    /// Efficiently compute just the fold prefix for a given starting location.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn fold_prefix(
        leaves: Location<F>,
        start_loc: Location<F>,
    ) -> Result<Vec<Position<F>>, super::Error<F>> {
        let size = Position::<F>::try_from(leaves)?;
        let mut fold_prefix = Vec::new();
        let mut leaf_cursor = Location::new(0);

        for (peak_pos, height) in F::peaks(size) {
            let leaf_end = leaf_cursor + (1u64 << height);
            if leaf_end <= start_loc {
                fold_prefix.push(peak_pos);
            } else {
                break;
            }
            leaf_cursor = leaf_end;
        }

        Ok(fold_prefix)
    }

    /// Return a blueprint for building a range proof over the given leaf `range` in a
    /// structure with `leaves` total leaves.
    pub(crate) fn new(
        leaves: Location<F>,
        range: Range<Location<F>>,
    ) -> Result<Self, super::Error<F>> {
        if range.is_empty() {
            return Err(super::Error::Empty);
        }
        let end_minus_one = range
            .end
            .checked_sub(1)
            .expect("can't underflow because range is non-empty");
        if end_minus_one >= leaves {
            return Err(super::Error::RangeOutOfBounds(range.end));
        }

        let size = Position::try_from(leaves)?;

        let mut fold_prefix = Vec::new();
        let mut after_peaks = Vec::new();
        let mut range_peaks = Vec::new();
        let mut leaf_cursor = Location::new(0);

        for (peak_pos, height) in F::peaks(size) {
            let leaf_start = leaf_cursor;
            let leaf_end = leaf_start + (1u64 << height);

            if leaf_end <= range.start {
                fold_prefix.push(Subtree {
                    pos: peak_pos,
                    height,
                    leaf_start,
                });
            } else if leaf_start >= range.end {
                after_peaks.push(peak_pos);
            } else {
                range_peaks.push(Subtree {
                    pos: peak_pos,
                    height,
                    leaf_start,
                });
            }
            leaf_cursor = leaf_end;
        }

        assert!(
            !range_peaks.is_empty(),
            "at least one peak must contain range elements"
        );

        let mut fetch_nodes = after_peaks.clone();
        for peak in &range_peaks {
            peak.collect_siblings(&range, &mut fetch_nodes);
        }

        Ok(Self {
            leaves,
            range,
            fold_prefix,
            after_peaks,
            range_peaks,
            fetch_nodes,
        })
    }

    /// Sibling subtrees of the first range peak that lie wholly before `self.range.start`.
    ///
    /// Only the first range peak can contain such siblings; later range peaks are entirely at or
    /// after `range.start` by this blueprint's classification.
    pub(crate) fn prefix_siblings(&self) -> Vec<Subtree<F>> {
        let mut out = Vec::new();
        if let Some(peak) = self.range_peaks.first() {
            peak.collect_prefix_siblings(&self.range, &mut out);
        }
        out
    }

    /// Build a range proof from this blueprint and a node-fetching closure.
    ///
    /// The prover folds prefix peak digests into a single accumulator. The resulting proof
    /// contains: `[fold_acc? | after_peaks... | siblings_dfs...]`.
    ///
    /// Returns an error via `element_pruned` if `get_node` returns `None` for any required
    /// position.
    pub(crate) fn build_proof<D, H, E>(
        self,
        hasher: &H,
        get_node: impl Fn(Position<F>) -> Option<D>,
        element_pruned: impl Fn(Position<F>) -> E,
    ) -> Result<Proof<F, D>, E>
    where
        D: Digest,
        H: Hasher<F, Digest = D>,
    {
        let mut digests = Vec::with_capacity(
            if self.fold_prefix.is_empty() { 0 } else { 1 } + self.fetch_nodes.len(),
        );

        if let Some((first_sub, rest)) = self.fold_prefix.split_first() {
            let first = get_node(first_sub.pos).ok_or_else(|| element_pruned(first_sub.pos))?;
            let acc = rest.iter().try_fold(first, |acc, sub| {
                let d = get_node(sub.pos).ok_or_else(|| element_pruned(sub.pos))?;
                Ok(hasher.fold(&acc, &d))
            })?;
            digests.push(acc);
        }

        for &pos in &self.fetch_nodes {
            digests.push(get_node(pos).ok_or_else(|| element_pruned(pos))?);
        }

        Ok(Proof {
            leaves: self.leaves,
            digests,
        })
    }
}

/// The maximum number of digests in a proof per element being proven.
///
/// This accounts for the worst case proof size, in an MMR/MMB with 62 peaks. The
/// left-most leaf in such a tree requires 122 digests, for 61 path siblings
/// and 61 peak digests.
pub const MAX_PROOF_DIGESTS_PER_ELEMENT: usize = 122;

/// Build a range proof from a node-fetching closure. This is the generic implementation
/// shared by all Merkle families. The `element_pruned` closure is called when `get_node`
/// returns `None` for a required position.
pub(crate) fn build_range_proof<F, D, H, E>(
    hasher: &H,
    leaves: Location<F>,
    range: Range<Location<F>>,
    get_node: impl Fn(Position<F>) -> Option<D>,
    element_pruned: impl Fn(Position<F>) -> E,
) -> Result<Proof<F, D>, E>
where
    F: Family,
    D: Digest,
    H: Hasher<F, Digest = D>,
    E: From<super::Error<F>>,
{
    Blueprint::new(leaves, range)?.build_proof(hasher, get_node, element_pruned)
}

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`. This is the generic implementation
/// shared by all Merkle families.
#[cfg(any(feature = "std", test))]
pub(crate) fn nodes_required_for_multi_proof<F: Family>(
    leaves: Location<F>,
    locations: &[Location<F>],
) -> Result<BTreeSet<Position<F>>, super::Error<F>> {
    if locations.is_empty() {
        return Err(super::Error::Empty);
    }
    locations.iter().try_fold(BTreeSet::new(), |mut acc, loc| {
        if !loc.is_valid_index() {
            return Err(super::Error::LocationOverflow(*loc));
        }
        let bp = Blueprint::new(leaves, *loc..*loc + 1)?;
        acc.extend(bp.fold_prefix.into_iter().map(|s| s.pos));
        acc.extend(bp.fetch_nodes);
        Ok(acc)
    })
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for Proof<F, D>
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        hasher::Standard,
        mem::Mem,
        mmb, mmr,
        proof::{nodes_required_for_multi_proof, Blueprint, Proof},
        Family, Location, LocationRangeExt as _,
    };
    use alloc::vec;
    use commonware_codec::{Decode, Encode, EncodeSize};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn test_digest(v: u8) -> D {
        <Sha256 as commonware_cryptography::Hasher>::hash(&[v])
    }

    /// Build an in-memory Merkle structure with `n` elements (element i = i.to_be_bytes()).
    fn build_raw<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new(hasher);
        let batch = {
            let mut batch = mem.new_batch();
            for i in 0..n {
                batch = batch.add(hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mem, hasher)
        };
        mem.apply_batch(&batch).unwrap();
        mem
    }

    fn empty_proof<F: Family>() {
        // Test that an empty proof authenticates an empty structure.
        let hasher = H::new();
        let mem = Mem::<F, D>::new(&hasher);
        let root = mem.root();
        let proof: Proof<F, D> = Proof::default();
        assert!(proof.verify_range_inclusion(&hasher, &[] as &[D], Location::new(0), root));

        // Any starting position other than 0 should fail to verify.
        assert!(!proof.verify_range_inclusion(&hasher, &[] as &[D], Location::new(1), root));

        // Invalid root should fail to verify.
        let td = test_digest(0);
        assert!(!proof.verify_range_inclusion(&hasher, &[] as &[D], Location::new(0), &td));

        // Non-empty elements list should fail to verify.
        assert!(!proof.verify_range_inclusion(&hasher, &[td], Location::new(0), root));
    }

    fn verify_element<F: Family>() {
        // Create an 11 element structure and test single-element inclusion proofs.
        let element = D::from(*b"01234567012345670123456701234567");
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let batch = {
            let mut batch = mem.new_batch();
            for _ in 0..11 {
                batch = batch.add(&hasher, &element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
        let root = mem.root();

        // Confirm the proof of inclusion for each leaf verifies.
        for leaf in 0u64..11 {
            let leaf = Location::new(leaf);
            let proof: Proof<F, D> = mem.proof(&hasher, leaf).unwrap();
            assert!(
                proof.verify_element_inclusion(&hasher, &element, leaf, root),
                "valid proof should verify successfully"
            );
        }

        // Create a valid proof, then confirm various mangling of the proof or proof args results in
        // verification failure.
        let leaf = Location::<F>::new(10);
        let proof = mem.proof(&hasher, leaf).unwrap();
        assert!(
            proof.verify_element_inclusion(&hasher, &element, leaf, root),
            "proof verification should be successful"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, leaf + 1, root),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, leaf - 1, root),
            "proof verification should fail with incorrect element position 2"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &test_digest(0), leaf, root),
            "proof verification should fail with mangled element"
        );
        let root2 = test_digest(0);
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, leaf, &root2),
            "proof verification should fail with mangled root"
        );
        let mut proof2 = proof.clone();
        proof2.digests[0] = test_digest(0);
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, leaf, root),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.leaves = Location::new(10);
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, leaf, root),
            "proof verification should fail with incorrect leaves"
        );
        proof2 = proof.clone();
        proof2.digests.push(test_digest(0));
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, leaf, root),
            "proof verification should fail with extra hash"
        );
        proof2 = proof.clone();
        while !proof2.digests.is_empty() {
            proof2.digests.pop();
            assert!(
                !proof2.verify_element_inclusion(&hasher, &element, leaf, root),
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
                !proof2.verify_element_inclusion(&hasher, &element, leaf, root),
                "proof verification should fail with extra hash even if it's unused by the computation"
            );
        }
    }

    fn verify_range<F: Family>() {
        // Create a structure and add 49 elements.
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let elements: Vec<_> = (0..49).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
        let root = mem.root();

        // Test range proofs over all possible ranges of at least 2 elements.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mem.range_proof(&hasher, range.clone()).unwrap();
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

        // Create a proof over a range, confirm it verifies, then mangle it in various ways.
        let range = Location::new(33)..Location::new(40);
        let range_proof = mem.range_proof(&hasher, range.clone()).unwrap();
        let valid_elements = &elements[range.to_usize_range()];
        assert!(
            range_proof.verify_range_inclusion(&hasher, valid_elements, range.start, root),
            "valid range proof should verify successfully"
        );
        // Remove digests from the proof until it's empty.
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
                if Location::<F>::from(i) == range.start && Location::<F>::from(j) == range.end {
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

    fn retained_nodes_provable_after_pruning<F: Family>() {
        // Create a structure and add 49 elements.
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let elements: Vec<_> = (0..49).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        // Confirm we can successfully prove all retained elements after pruning.
        let root = *mem.root();
        for prune_leaf in 1..*mem.leaves() {
            let prune_loc = Location::new(prune_leaf);
            mem.prune(prune_loc).unwrap();
            let pruned_root = mem.root();
            assert_eq!(root, *pruned_root);
            for loc in 0..elements.len() {
                let loc = Location::new(loc as u64);
                let proof = mem.proof(&hasher, loc);
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

    fn ranges_provable_after_pruning<F: Family>() {
        // Create a structure and add 49 elements.
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let mut elements: Vec<_> = (0..49).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        // Prune up to the first peak.
        let prune_loc = Location::<F>::new(32);
        mem.prune(prune_loc).unwrap();
        assert_eq!(mem.bounds().start, prune_loc);

        // Test range proofs over all possible ranges of at least 2 elements
        let root = mem.root();
        for i in 0..elements.len() - 1 {
            if Location::<F>::new(i as u64) < prune_loc {
                continue;
            }
            for j in (i + 2)..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mem.range_proof(&hasher, range.clone()).unwrap();
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

        // Add more nodes, prune again, and test again.
        let new_elements: Vec<_> = (0..37).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &new_elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
        elements.extend(new_elements);
        mem.prune(Location::new(66)).unwrap();
        assert_eq!(mem.bounds().start, Location::new(66));

        let updated_root = mem.root();
        let range = Location::new(elements.len() as u64 - 10)..Location::new(elements.len() as u64);
        let range_proof = mem.range_proof(&hasher, range.clone()).unwrap();
        assert!(
            range_proof.verify_range_inclusion(
                &hasher,
                &elements[range.to_usize_range()],
                range.start,
                updated_root,
            ),
            "valid range proof over remaining elements after 2 pruning rounds should verify",
        );
    }

    fn proof_serialization<F: Family>() {
        // Create a structure and add 25 elements.
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let elements: Vec<_> = (0..25).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        // Generate proofs over all possible ranges of elements and confirm each
        // serializes=>deserializes correctly.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let proof = mem.range_proof(&hasher, range).unwrap();

                let expected_size = proof.encode_size();
                let serialized_proof = proof.encode();
                assert_eq!(
                    serialized_proof.len(),
                    expected_size,
                    "serialized proof should have expected size"
                );
                let max_digests = proof.digests.len();
                let deserialized_proof =
                    Proof::<F, D>::decode_cfg(serialized_proof, &max_digests).unwrap();
                assert_eq!(
                    proof, deserialized_proof,
                    "deserialized proof should match source proof"
                );

                // Remove one byte from the end and confirm it fails to deserialize.
                let serialized_proof = proof.encode();
                let serialized_proof = serialized_proof.slice(0..serialized_proof.len() - 1);
                assert!(
                    Proof::<F, D>::decode_cfg(serialized_proof, &max_digests).is_err(),
                    "proof should not deserialize with truncated data"
                );

                // Add extra data and confirm it fails to deserialize.
                let mut serialized_proof = proof.encode_mut();
                serialized_proof.extend_from_slice(&[0; 10]);
                let serialized_proof = serialized_proof;
                assert!(
                    Proof::<F, D>::decode_cfg(serialized_proof, &max_digests).is_err(),
                    "proof should not deserialize with extra data"
                );

                // Confirm deserialization fails when max_digests is too small.
                let actual_digests = proof.digests.len();
                if actual_digests > 0 {
                    let too_small = actual_digests - 1;
                    let serialized_proof = proof.encode();
                    assert!(
                        Proof::<F, D>::decode_cfg(serialized_proof, &too_small).is_err(),
                        "proof should not deserialize with max_digests too small"
                    );
                }
            }
        }
    }

    fn multi_proof_generation_and_verify<F: Family>() {
        // Create a structure with 20 elements.
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let elements: Vec<_> = (0..20).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        let root = mem.root();

        // Generate proof for non-contiguous single elements.
        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes_for_multi_proof =
            nodes_required_for_multi_proof(mem.leaves(), locations).expect("test locations valid");
        let digests = nodes_for_multi_proof
            .into_iter()
            .map(|pos| mem.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mem.leaves(),
            digests,
        };

        assert_eq!(multi_proof.leaves, mem.leaves());

        // Verify the proof.
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            root
        ));

        // Verify in different order.
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[10], Location::new(10)),
                (elements[5], Location::new(5)),
                (elements[0], Location::new(0)),
            ],
            root
        ));

        // Verify with duplicate items.
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
        wrong_size_proof.leaves = Location::new(*F::MAX_LEAVES + 2);
        assert!(!wrong_size_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            root,
        ));

        // Verify with wrong positions.
        assert!(!multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(1)),
                (elements[5], Location::new(6)),
                (elements[10], Location::new(11)),
            ],
            root,
        ));

        // Verify with wrong elements.
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

        // Verify with out of range element.
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

        // Verify with wrong root should fail.
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

        // Empty multi-proof.
        let hasher = H::new();
        let empty_mem = Mem::<F, D>::new(&hasher);
        let empty_root = empty_mem.root();
        let empty_proof: Proof<F, D> = Proof::default();
        assert!(empty_proof.verify_multi_inclusion(
            &hasher,
            &[] as &[(D, Location<F>)],
            empty_root
        ));

        // Malformed empty proof with extra digests must be rejected.
        let malformed_proof: Proof<F, D> = Proof {
            leaves: Location::new(0),
            digests: vec![test_digest(0)],
        };
        assert!(!malformed_proof.verify_multi_inclusion(
            &hasher,
            &[] as &[(D, Location<F>)],
            empty_root
        ));
    }

    fn multi_proof_deduplication<F: Family>() {
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let elements: Vec<_> = (0..30).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        // Get individual proofs that will share some digests (elements in same subtree).
        let proof1 = mem.proof(&hasher, Location::new(0)).unwrap();
        let proof2 = mem.proof(&hasher, Location::new(1)).unwrap();
        let total_digests_separate = proof1.digests.len() + proof2.digests.len();

        // Generate multi-proof for the same positions.
        let locations = &[Location::new(0), Location::new(1)];
        let multi_proof_nodes =
            nodes_required_for_multi_proof(mem.leaves(), locations).expect("test locations valid");
        let digests = multi_proof_nodes
            .into_iter()
            .map(|pos| mem.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mem.leaves(),
            digests,
        };

        // The combined proof should have fewer digests due to deduplication.
        assert!(multi_proof.digests.len() < total_digests_separate);

        // Verify it still works.
        let root = mem.root();
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[1], Location::new(1))
            ],
            root
        ));
    }

    fn proof_leaves_malleability<F: Family>() {
        let hasher = H::new();
        let mut mem = Mem::<F, D>::new(&hasher);

        // 252 leaves. Leaf 240 sits in a peak preceded by prefix peaks.
        let elements: Vec<D> = (0..252u16)
            .map(|i| <Sha256 as commonware_cryptography::Hasher>::hash(&i.to_be_bytes()))
            .collect();
        let batch = {
            let mut batch = mem.new_batch();
            for e in &elements {
                batch = batch.add(&hasher, e);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
        let root = mem.root();

        let loc = Location::new(240);
        let proof = mem.proof(&hasher, loc).unwrap();
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

    fn blueprint_errors<F: Family>() {
        let leaves = Location::<F>::new(10);

        // Empty range.
        assert!(matches!(
            Blueprint::<F>::new(leaves, Location::new(3)..Location::new(3)),
            Err(crate::merkle::Error::Empty)
        ));

        // Out of bounds.
        assert!(matches!(
            Blueprint::<F>::new(leaves, Location::new(0)..Location::new(11)),
            Err(crate::merkle::Error::RangeOutOfBounds(_))
        ));

        // Empty locations for multi-proof.
        assert!(matches!(
            nodes_required_for_multi_proof::<F>(leaves, &[]),
            Err(crate::merkle::Error::Empty)
        ));
    }

    fn single_element_proof_reconstruction<F: Family>() {
        for n in 1u64..=64 {
            let hasher = H::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

            for loc_idx in 0..n {
                let proof = mem
                    .proof(&hasher, Location::new(loc_idx))
                    .unwrap_or_else(|e| panic!("n={n}, loc={loc_idx}: build failed: {e:?}"));

                let elements = [loc_idx.to_be_bytes()];
                let start_loc = Location::new(loc_idx);

                let reconstructed = proof
                    .reconstruct_root(&hasher, &elements, start_loc)
                    .unwrap_or_else(|e| panic!("n={n}, loc={loc_idx}: reconstruct failed: {e:?}"));
                assert_eq!(reconstructed, root, "n={n}, loc={loc_idx}: root mismatch");
            }
        }
    }

    fn range_proof_reconstruction<F: Family>() {
        for n in 2u64..=32 {
            let hasher = H::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

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
                let proof = mem
                    .range_proof(&hasher, Location::new(start)..Location::new(end))
                    .unwrap_or_else(|e| panic!("n={n}, range={start}..{end}: build failed: {e:?}"));
                let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();
                let start_loc = Location::new(start);

                let reconstructed = proof
                    .reconstruct_root(&hasher, &elements, start_loc)
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

    fn verify_element_inclusion<F: Family>() {
        for n in 1u64..=32 {
            let hasher = H::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

            for loc_idx in 0..n {
                let proof = mem.proof(&hasher, Location::new(loc_idx)).unwrap();
                let loc = Location::new(loc_idx);

                assert!(
                    proof.verify_element_inclusion(&hasher, &loc_idx.to_be_bytes(), loc, &root),
                    "n={n}, loc={loc_idx}: verification failed"
                );

                // Wrong element should fail.
                assert!(
                    !proof.verify_element_inclusion(
                        &hasher,
                        &(loc_idx + 1000).to_be_bytes(),
                        loc,
                        &root,
                    ),
                    "n={n}, loc={loc_idx}: wrong element should not verify"
                );
            }
        }
    }

    fn full_range<F: Family>() {
        for n in 1u64..=32 {
            let hasher = H::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

            let proof = mem
                .range_proof(&hasher, Location::new(0)..Location::new(n))
                .unwrap();
            let elements: Vec<_> = (0..n).map(|i| i.to_be_bytes()).collect();
            let reconstructed = proof
                .reconstruct_root(&hasher, &elements, Location::new(0))
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

    fn empty_proof_verifies_empty_tree<F: Family>() {
        let hasher = H::new();
        let mem = Mem::<F, D>::new(&hasher);
        let root = *mem.root();
        let proof = Proof::<F, D>::default();

        // Empty proof should verify against the empty root.
        assert!(proof.verify_range_inclusion(&hasher, &[] as &[&[u8]], Location::new(0), &root,));

        // Non-zero start_loc with empty elements should fail.
        assert!(!proof.verify_range_inclusion(&hasher, &[] as &[&[u8]], Location::new(1), &root,));
    }

    fn every_element_contributes_to_root<F: Family>() {
        for n in [8u64, 13, 20, 32] {
            let hasher = H::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

            let start = 1;
            let end = n - 1;
            let proof = mem
                .range_proof(&hasher, Location::new(start)..Location::new(end))
                .unwrap();
            let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();

            // Valid elements verify.
            assert!(
                proof.verify_range_inclusion(&hasher, &elements, Location::new(start), &root),
                "n={n}: valid range should verify"
            );

            // Flipping one byte in each element must cause failure.
            for flip_idx in 0..elements.len() {
                let mut tampered = elements.clone();
                tampered[flip_idx][0] ^= 0xFF;
                assert!(
                    !proof.verify_range_inclusion(&hasher, &tampered, Location::new(start), &root,),
                    "n={n}: tampered element at index {flip_idx} should not verify"
                );
            }
        }
    }

    fn multi_proof_generation_and_verify_raw<F: Family>() {
        let hasher = H::new();
        let mem = build_raw::<F>(&hasher, 20);
        let root = *mem.root();

        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes =
            nodes_required_for_multi_proof(mem.leaves(), locations).expect("valid locations");
        let digests = nodes
            .into_iter()
            .map(|pos| mem.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mem.leaves(),
            digests,
        };

        // Verify the proof.
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (0u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &root
        ));

        // Different order should also verify.
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (10u64.to_be_bytes(), Location::new(10)),
                (5u64.to_be_bytes(), Location::new(5)),
                (0u64.to_be_bytes(), Location::new(0)),
            ],
            &root
        ));

        // Wrong elements should fail.
        assert!(!multi_proof.verify_multi_inclusion(
            &hasher,
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
            &hasher,
            &[
                (0u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &wrong_root
        ));

        // Empty multi-proof on empty tree.
        let hasher2 = H::new();
        let empty_mem = Mem::<F, D>::new(&hasher2);
        let empty_proof: Proof<F, D> = Proof::default();
        assert!(empty_proof.verify_multi_inclusion(
            &hasher2,
            &[] as &[([u8; 8], Location<F>)],
            empty_mem.root()
        ));

        // Malformed empty proof with extra digests must be rejected.
        let malformed_proof: Proof<F, D> = Proof {
            leaves: Location::new(0),
            digests: vec![test_digest(0)],
        };
        assert!(!malformed_proof.verify_multi_inclusion(
            &hasher2,
            &[] as &[([u8; 8], Location<F>)],
            empty_mem.root()
        ));
    }

    fn tampered_proof_digests_rejected<F: Family>() {
        for n in [8u64, 13, 20, 32] {
            let hasher = H::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

            for loc_idx in [0, n / 2, n - 1] {
                let proof = mem.proof(&hasher, Location::new(loc_idx)).unwrap();
                let element = loc_idx.to_be_bytes();
                let loc = Location::new(loc_idx);

                assert!(proof.verify_element_inclusion(&hasher, &element, loc, &root));

                for digest_idx in 0..proof.digests.len() {
                    let mut tampered = proof.clone();
                    tampered.digests[digest_idx].0[0] ^= 1;
                    assert!(
                        !tampered.verify_element_inclusion(&hasher, &element, loc, &root),
                        "n={n}, loc={loc_idx}: tampered digest[{digest_idx}] should not verify"
                    );
                }
            }
        }
    }

    fn no_duplicate_positions<F: Family>() {
        use alloc::collections::BTreeSet;
        for n in 1u64..=64 {
            let hasher = H::new();
            let mem = build_raw::<F>(&hasher, n);
            let leaves = mem.leaves();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp = Blueprint::<F>::new(leaves, loc..loc + 1).unwrap();
                let mut positions: Vec<Position<F>> = Vec::new();
                positions.extend(bp.fold_prefix.iter().map(|s| s.pos));
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

    /// `verify_proof_and_pinned_nodes` must accept pinned nodes at
    /// `F::nodes_to_pin(start_loc)` positions for any `(leaves, start_loc)` pair.
    ///
    /// `nodes_to_pin(L)` returns the peaks of the tree at size L (the peaks you'd
    /// pin if you pruned to L). `fold_prefix(N, L)` returns the peaks of the size-N
    /// tree that lie entirely before leaf L. These can disagree when the larger tree
    /// has merged smaller peaks into larger subtrees. The verifier must handle this
    /// for both families.
    fn verify_proof_and_pinned_nodes_across_sizes<F: Family>() {
        // Sweep (leaves, start) pairs. Larger trees with start far from a peak
        // boundary are more likely to produce pinned positions that don't appear
        // as siblings in the proof walk.
        let cases: &[(u64, u64)] = &[
            // First delayed-merge birth-boundary case: the larger tree exposes a
            // fold-prefix peak that did not exist yet at `start`.
            (5, 4),
            (10, 3),
            (20, 5),
            (50, 10),
            (100, 10),
            (100, 30),
            (200, 50),
            (500, 100),
            (1000, 100),
            (1000, 300),
            (2000, 500),
        ];

        let hasher = H::new();
        for &(n, start) in cases {
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

            let pinned: Vec<D> = F::nodes_to_pin(Location::<F>::new(start))
                .map(|pos| mem.get_node(pos).unwrap())
                .collect();

            let proof = mem
                .range_proof(
                    &hasher,
                    Location::<F>::new(start)..Location::<F>::new(start + 1),
                )
                .unwrap();

            assert!(
                proof.verify_proof_and_pinned_nodes(
                    &hasher,
                    &[start.to_be_bytes()],
                    Location::<F>::new(start),
                    &pinned,
                    &root,
                ),
                "verify_proof_and_pinned_nodes failed: leaves={n}, start={start}"
            );
        }
    }

    // ---------------------------------------------------------------------------
    // MMR tests
    // ---------------------------------------------------------------------------

    #[test]
    fn mmr_empty_proof() {
        empty_proof::<mmr::Family>();
    }
    #[test]
    fn mmr_verify_element() {
        verify_element::<mmr::Family>();
    }
    #[test]
    fn mmr_verify_range() {
        verify_range::<mmr::Family>();
    }
    #[test_traced]
    fn mmr_retained_nodes_provable_after_pruning() {
        retained_nodes_provable_after_pruning::<mmr::Family>();
    }
    #[test]
    fn mmr_ranges_provable_after_pruning() {
        ranges_provable_after_pruning::<mmr::Family>();
    }
    #[test]
    fn mmr_proof_serialization() {
        proof_serialization::<mmr::Family>();
    }
    #[test]
    fn mmr_multi_proof_generation_and_verify() {
        multi_proof_generation_and_verify::<mmr::Family>();
    }
    #[test]
    fn mmr_multi_proof_deduplication() {
        multi_proof_deduplication::<mmr::Family>();
    }
    #[test]
    fn mmr_proof_leaves_malleability() {
        proof_leaves_malleability::<mmr::Family>();
    }
    #[test]
    fn mmr_blueprint_errors() {
        blueprint_errors::<mmr::Family>();
    }
    #[test]
    fn mmr_single_element_proof_reconstruction() {
        single_element_proof_reconstruction::<mmr::Family>();
    }
    #[test]
    fn mmr_range_proof_reconstruction() {
        range_proof_reconstruction::<mmr::Family>();
    }
    #[test]
    fn mmr_verify_element_inclusion() {
        verify_element_inclusion::<mmr::Family>();
    }
    #[test]
    fn mmr_full_range() {
        full_range::<mmr::Family>();
    }
    #[test]
    fn mmr_empty_proof_verifies_empty_tree() {
        empty_proof_verifies_empty_tree::<mmr::Family>();
    }
    #[test]
    fn mmr_every_element_contributes_to_root() {
        every_element_contributes_to_root::<mmr::Family>();
    }
    #[test]
    fn mmr_multi_proof_generation_and_verify_raw() {
        multi_proof_generation_and_verify_raw::<mmr::Family>();
    }
    #[test]
    fn mmr_tampered_proof_digests_rejected() {
        tampered_proof_digests_rejected::<mmr::Family>();
    }
    #[test]
    fn mmr_no_duplicate_positions() {
        no_duplicate_positions::<mmr::Family>();
    }
    #[test]
    fn mmr_verify_proof_and_pinned_nodes_across_sizes() {
        verify_proof_and_pinned_nodes_across_sizes::<mmr::Family>();
    }

    // ---------------------------------------------------------------------------
    // MMB tests
    // ---------------------------------------------------------------------------

    #[test]
    fn mmb_empty_proof() {
        empty_proof::<mmb::Family>();
    }
    #[test]
    fn mmb_verify_element() {
        verify_element::<mmb::Family>();
    }
    #[test]
    fn mmb_verify_range() {
        verify_range::<mmb::Family>();
    }
    #[test_traced]
    fn mmb_retained_nodes_provable_after_pruning() {
        retained_nodes_provable_after_pruning::<mmb::Family>();
    }
    #[test]
    fn mmb_ranges_provable_after_pruning() {
        ranges_provable_after_pruning::<mmb::Family>();
    }
    #[test]
    fn mmb_proof_serialization() {
        proof_serialization::<mmb::Family>();
    }
    #[test]
    fn mmb_multi_proof_generation_and_verify() {
        multi_proof_generation_and_verify::<mmb::Family>();
    }
    #[test]
    fn mmb_multi_proof_deduplication() {
        multi_proof_deduplication::<mmb::Family>();
    }
    #[test]
    fn mmb_proof_leaves_malleability() {
        proof_leaves_malleability::<mmb::Family>();
    }
    #[test]
    fn mmb_blueprint_errors() {
        blueprint_errors::<mmb::Family>();
    }
    #[test]
    fn mmb_single_element_proof_reconstruction() {
        single_element_proof_reconstruction::<mmb::Family>();
    }
    #[test]
    fn mmb_range_proof_reconstruction() {
        range_proof_reconstruction::<mmb::Family>();
    }
    #[test]
    fn mmb_verify_element_inclusion() {
        verify_element_inclusion::<mmb::Family>();
    }
    #[test]
    fn mmb_full_range() {
        full_range::<mmb::Family>();
    }
    #[test]
    fn mmb_empty_proof_verifies_empty_tree() {
        empty_proof_verifies_empty_tree::<mmb::Family>();
    }
    #[test]
    fn mmb_every_element_contributes_to_root() {
        every_element_contributes_to_root::<mmb::Family>();
    }
    #[test]
    fn mmb_multi_proof_generation_and_verify_raw() {
        multi_proof_generation_and_verify_raw::<mmb::Family>();
    }
    #[test]
    fn mmb_tampered_proof_digests_rejected() {
        tampered_proof_digests_rejected::<mmb::Family>();
    }
    #[test]
    fn mmb_no_duplicate_positions() {
        no_duplicate_positions::<mmb::Family>();
    }
    #[test]
    fn mmb_verify_proof_and_pinned_nodes_across_sizes() {
        verify_proof_and_pinned_nodes_across_sizes::<mmb::Family>();
    }
}
