//! Defines the generic inclusion [Proof] structure for Merkle-family data structures.
//!
//! The [Proof] struct is parameterized by a [`Family`] marker and a [`Digest`] type. Each Merkle
//! family (MMR, MMB, etc.) reuses the shared verification and reconstruction logic in this module,
//! while retaining any family-specific proof helpers in its submodule.

use crate::merkle::{Bagging, Error, Family, Location, Position, hasher::Hasher};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, ReadExt, ReadRangeExt, Write, varint::UInt};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Contains the information necessary for proving the inclusion of an element, or some range of
/// elements, in a Merkle-family data structure from its root digest.
///
/// For range proofs, the `digests` vector uses a fold-based layout:
///
/// 1. If there are folded peaks entirely before the proven range, the first digest is a single
///    accumulator produced by folding those peaks: `fold(fold(..., peak0), peak1)`. If there are
///    no such peaks, this entry is absent.
///
/// 2. The digests of any non-folded peaks entirely before the proven range, in peak iteration
///    order.
///
/// 3. For `ForwardFold`, the digests of peaks entirely after the proven range, in peak iteration
///    order. For `BackwardFold`, inactive after-peaks are still listed individually, while active
///    after-peaks are collapsed into one optional suffix accumulator.
///
/// 4. The sibling digests needed to reconstruct each range-peak digest from the proven elements,
///    in depth-first (forward consumption) order for each range peak.
///
/// Multi-proofs use a different, position-keyed layout: `digests` contains the node digests at
/// [multi_proof_positions], in that order. This may include active suffix peaks that a single
/// `BackwardFold` range proof would collapse into a synthetic suffix accumulator.
#[derive(Clone, Debug, Eq)]
pub struct Proof<F: Family, D: Digest> {
    /// The total number of leaves in the data structure. For MMR proofs, this is the number of
    /// leaves in the MMR, though other authenticated data structures may override the meaning of
    /// this field. For example, the authenticated [crate::AuthenticatedBitMap] stores the number
    /// of bits in the bitmap within this field.
    pub leaves: Location<F>,
    /// The number of inactive peaks in the structure when this proof was generated.
    pub inactive_peaks: usize,
    /// The digests necessary for proving inclusion.
    pub digests: Vec<D>,
}

impl<F: Family, D: Digest> PartialEq for Proof<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.leaves == other.leaves
            && self.inactive_peaks == other.inactive_peaks
            && self.digests == other.digests
    }
}

impl<F: Family, D: Digest> EncodeSize for Proof<F, D> {
    fn encode_size(&self) -> usize {
        self.leaves.encode_size()
            + UInt(self.inactive_peaks as u64).encode_size()
            + self.digests.encode_size()
    }
}

impl<F: Family, D: Digest> Write for Proof<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.leaves.write(buf);
        UInt(self.inactive_peaks as u64).write(buf);
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
        let inactive_peaks = usize::try_from(UInt::<u64>::read(buf)?.0).map_err(|_| {
            commonware_codec::Error::Invalid("Proof", "inactive_peaks exceeds usize")
        })?;
        let digests = Vec::<D>::read_range(buf, ..=*max_digests)?;
        Ok(Self {
            leaves,
            inactive_peaks,
            digests,
        })
    }
}

impl<F: Family, D: Digest> Default for Proof<F, D> {
    /// Create an empty proof. The empty proof will verify only against the root digest of an empty
    /// (`leaves == 0`) data structure.
    fn default() -> Self {
        Self {
            leaves: Location::new(0),
            inactive_peaks: 0,
            digests: vec![],
        }
    }
}

impl<F: Family, D: Digest> Proof<F, D> {
    /// Return true if this proof proves that `element` appears at location `loc` within the
    /// structure with root digest `root`, using the bagging carried by `hasher`.
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

    /// Return true if this proof verifies against the supplied root, using the bagging carried by
    /// `hasher`.
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
        self.reconstruct_root_inner(hasher, elements, start_loc, None)
            .is_ok_and(|reconstructed_root| reconstructed_root == *root)
    }

    /// Returns true if this proof's `inactive_peaks` field matches the canonical value derived
    /// from `size` and `inactivity_floor`.
    pub fn matches_canonical_inactive_peaks(
        &self,
        size: Location<F>,
        inactivity_floor: Location<F>,
    ) -> bool {
        self.inactive_peaks == F::inactive_peaks(size, inactivity_floor)
    }

    /// Verify a position-keyed multi-proof using the bagging carried by `hasher`.
    ///
    /// Locations must be strictly ascending. Returns `false` if any location is out of range,
    /// repeats the previous one, or precedes it.
    ///
    /// Multi-proofs keep every witness tied to a concrete node position, so this path may include
    /// extra backward-bagged suffix peaks that range proofs can collapse into a suffix accumulator.
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
                && self.inactive_peaks == 0
                && *root
                    == hasher
                        .root(Location::new(0), 0, core::iter::empty())
                        .expect("zero inactive peaks is always valid");
        }

        // The proof must hold exactly one digest for each position in `positions`, in the same
        // order. Computing `positions` also rejects invalid locations.
        let locations: Vec<_> = elements.iter().map(|(_, loc)| *loc).collect();
        let Ok(positions) = multi_proof_positions(self.leaves, &locations) else {
            return false;
        };
        if positions.len() != self.digests.len() {
            return false;
        }
        let witness = |pos: Position<F>| {
            positions
                .binary_search(&pos)
                .ok()
                .map(|index| self.digests[index])
        };

        // Compute the digest of each peak that holds selected elements, and take the other peaks'
        // digests from the proof. If a peak holds only some of the selected elements, its digest is
        // also in the proof and must equal the computed one.
        let Ok(size) = Position::try_from(self.leaves) else {
            return false;
        };
        let mut peaks = Vec::new();
        let mut remaining = elements;
        let mut leaf_start = Location::new(0);
        for (pos, height) in F::peaks(size) {
            let peak = Subtree {
                pos,
                height,
                leaf_start,
            };
            leaf_start = peak.leaf_end();
            let (selected, rest) =
                remaining.split_at(remaining.partition_point(|(_, loc)| *loc < leaf_start));
            remaining = rest;
            let digest = if selected.is_empty() {
                witness(pos)
            } else {
                peak.reconstruct_multi(hasher, selected, &witness)
                    .filter(|digest| {
                        selected.len() == elements.len() || witness(pos) == Some(*digest)
                    })
            };
            let Some(digest) = digest else {
                return false;
            };
            peaks.push(digest);
        }
        hasher
            .root(self.leaves, self.inactive_peaks, peaks.iter())
            .is_ok_and(|reconstructed| reconstructed == *root)
    }

    /// Reconstruct the root digest from this proof and the given consecutive elements using
    /// the bagging carried by `hasher`, or return [`Error::InvalidProof`] if the input data is
    /// invalid.
    pub fn reconstruct_root<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
    ) -> Result<D, Error<F>>
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        self.reconstruct_root_inner(hasher, elements, start_loc, None)
    }

    /// Verify this proof against `root` and extract all authenticated digests.
    ///
    /// Reconstructs the root from the proof and provided elements and returns every
    /// `(position, digest)` pair required by that reconstruction, including the proof's own
    /// digests. Returns [`Error::InvalidProof`] if the input data is malformed and
    /// [`Error::RootMismatch`] if the reconstructed root does not match `root`.
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
        let reconstructed_root =
            self.reconstruct_root_inner(hasher, elements, start_loc, Some(&mut collected_digests))?;

        if reconstructed_root != *root {
            return Err(Error::RootMismatch);
        }

        Ok(collected_digests)
    }

    /// Verify this proof and the pinned nodes against `root`.
    ///
    /// The proof's `inactive_peaks` field commits to the split boundary; peak bagging is selected
    /// by `hasher`.
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
        let bagging = hasher.root_bagging();
        let collected = self
            .verify_range_inclusion_and_extract_digests(hasher, elements, start_loc, root)
            .ok()?;

        if elements.is_empty() {
            return pinned_nodes.is_empty().then_some(());
        }

        if !start_loc.is_valid() || start_loc > self.leaves {
            return None;
        }

        let end_loc = start_loc.checked_add(elements.len() as u64)?;
        let bp = Blueprint::new(
            self.leaves,
            self.inactive_peaks,
            bagging,
            start_loc..end_loc,
        )
        .ok()?;

        // Pair each pinned position with its digest, rejecting a count mismatch in either direction.
        let mut pinned_map = BTreeMap::new();
        let mut pinned_digests = pinned_nodes.iter();
        for pos in F::nodes_to_pin(start_loc) {
            pinned_map.insert(pos, *pinned_digests.next()?);
        }
        if pinned_digests.next().is_some() {
            return None;
        }

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

        let extracted: BTreeMap<Position<F>, D> = collected.into_iter().collect();

        // Verify prefix active peaks that were not folded.
        for sub in &bp.prefix_active_peaks {
            let &expected = extracted.get(&sub.pos)?;
            let d = sub.reconstruct_from_pins(hasher, &mut pinned_map)?;
            if d != expected {
                return None;
            }
        }

        // Sibling subtrees inside the first range peak that lie wholly before `start_loc` are
        // authenticated directly by the proof (their digests appear in `extracted`). Rebuild each
        // from the pins and compare.
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

    /// Reconstruct a root from range-proof digests and optionally collect authenticated nodes.
    ///
    /// Reads the bagging policy from `hasher`. When `collected` is supplied, the verifier records
    /// the intermediate node digests it authenticates while reconstructing the range.
    pub(crate) fn reconstruct_root_inner<H, E>(
        &self,
        hasher: &H,
        elements: &[E],
        start_loc: Location<F>,
        collected: Option<&mut Vec<(Position<F>, D)>>,
    ) -> Result<D, Error<F>>
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        let bagging = hasher.root_bagging();
        let mut collected = collected;
        if elements.is_empty() {
            // Only the empty proof of an empty structure proves no elements.
            if start_loc != 0
                || self.inactive_peaks != 0
                || self.leaves != Location::new(0)
                || !self.digests.is_empty()
            {
                return Err(Error::InvalidProof);
            }
            return Ok(hasher
                .root(self.leaves, 0, core::iter::empty())
                .expect("zero inactive peaks is always valid"));
        }
        if !start_loc.is_valid_index() {
            return Err(Error::InvalidProof);
        }
        let end_loc = start_loc
            .checked_add(elements.len() as u64)
            .ok_or(Error::InvalidProof)?;
        if end_loc > self.leaves {
            return Err(Error::InvalidProof);
        }
        let range = start_loc..end_loc;

        let bp = Blueprint::new(self.leaves, self.inactive_peaks, bagging, range)
            .map_err(|_| Error::InvalidProof)?;

        let proof_digests = bp.split_proof_digests(&self.digests)?;

        // Collect all peak digests to provide to hasher.root().
        let mut peak_digests = Vec::new();
        if let Some(&digest) = proof_digests.fold_prefix {
            peak_digests.push(digest);
        }
        for (sub, &digest) in bp
            .prefix_active_peaks
            .iter()
            .zip(proof_digests.prefix_active_peaks)
        {
            peak_digests.push(digest);
            if let Some(ref mut cd) = collected {
                cd.push((sub.pos, digest));
            }
        }

        let mut sibling_cursor = 0usize;
        let mut elements_iter = elements.iter();
        for peak in &bp.range_peaks {
            let peak_digest = peak.reconstruct_digest(
                hasher,
                &bp.range,
                &mut elements_iter,
                proof_digests.siblings,
                &mut sibling_cursor,
                collected.as_deref_mut(),
            )?;
            if let Some(ref mut cd) = collected {
                cd.push((peak.pos, peak_digest));
            }
            peak_digests.push(peak_digest);
        }

        for (&after_peak_pos, &digest) in bp.after_peaks.iter().zip(proof_digests.after_peaks) {
            if let Some(ref mut cd) = collected {
                cd.push((after_peak_pos, digest));
            }
            peak_digests.push(digest);
        }
        if let Some(&digest) = proof_digests.suffix_acc {
            peak_digests.push(digest);
        }

        // Verify all elements were consumed.
        if elements_iter.next().is_some() {
            return Err(Error::InvalidProof);
        }

        // Verify all siblings were consumed.
        if sibling_cursor != proof_digests.siblings.len() {
            return Err(Error::InvalidProof);
        }

        hasher
            .root_with_folded_peaks(
                self.leaves,
                bp.inactive_peaks_after_prefix_fold(self.inactive_peaks),
                self.inactive_peaks,
                peak_digests.iter(),
            )
            .ok_or(Error::InvalidProof)
    }
}

/// A perfect binary subtree within a peak, identified by its root position, height,
/// and the first leaf location it covers.
#[derive(Copy, Clone, Debug)]
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

    /// True if this subtree's leaves lie wholly inside `range`.
    fn is_inside(&self, range: &Range<Location<F>>) -> bool {
        self.leaf_start >= range.start && self.leaf_end() <= range.end
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
    /// Emits outside subtrees and skips fully covered subtrees.
    fn collect_siblings(&self, range: &Range<Location<F>>, out: &mut Vec<Position<F>>) {
        if self.is_outside(range) {
            out.push(self.pos);
            return;
        }

        if self.is_inside(range) {
            return;
        }

        if self.height > 0 {
            let (left, right) = self.children();
            left.collect_siblings(range, out);
            right.collect_siblings(range, out);
        }
    }

    /// Append the position of each sibling along the paths from the leaves at `locations` up to
    /// this subtree's root, once and in postorder. `locations` must be strictly ascending and
    /// within this subtree.
    fn collect_multi_siblings(&self, locations: &[Location<F>], out: &mut Vec<Position<F>>) {
        if self.height == 0 {
            return;
        }
        let (left, right) = self.children();
        let (left_locations, right_locations) =
            locations.split_at(locations.partition_point(|loc| *loc < right.leaf_start));
        if !left_locations.is_empty() {
            left.collect_multi_siblings(left_locations, out);
        }
        if !right_locations.is_empty() {
            out.push(left.pos);
            right.collect_multi_siblings(right_locations, out);
        }
        if !left_locations.is_empty() {
            out.push(right.pos);
        }
    }

    /// Compute the digest of this subtree's root from its selected `elements` and the proof digests
    /// that `witness` looks up by position. `elements` must be in strictly ascending location
    /// order. Returns `None` if a needed digest is missing or does not match the computed one.
    fn reconstruct_multi<H, E>(
        &self,
        hasher: &H,
        elements: &[(E, Location<F>)],
        witness: &impl Fn(Position<F>) -> Option<H::Digest>,
    ) -> Option<H::Digest>
    where
        H: Hasher<F>,
        E: AsRef<[u8]>,
    {
        if self.height == 0 {
            let [(element, _)] = elements else {
                return None;
            };
            return Some(hasher.leaf_digest(self.pos, element.as_ref()));
        }

        // A child's digest comes from the proof if it holds no selected elements, and is computed
        // otherwise. If both children hold selected elements, their digests are also in the proof
        // and must equal the computed ones.
        let (left, right) = self.children();
        let (left_elements, right_elements) =
            elements.split_at(elements.partition_point(|(_, loc)| *loc < right.leaf_start));
        let child = |node: Self, selected: &[(E, Location<F>)], sibling_selected: bool| {
            if selected.is_empty() {
                return witness(node.pos);
            }
            let digest = node.reconstruct_multi(hasher, selected, witness)?;
            if sibling_selected && witness(node.pos)? != digest {
                return None;
            }
            Some(digest)
        };
        let left_digest = child(left, left_elements, !right_elements.is_empty())?;
        let right_digest = child(right, right_elements, !left_elements.is_empty())?;
        Some(hasher.node_digest(self.pos, &left_digest, &right_digest))
    }

    /// Collect sibling subtrees that lie wholly before the proven range, in the same
    /// left-first DFS order as [`collect_siblings`](Self::collect_siblings).
    ///
    /// Only `range.start` is consulted because the `range.end` side cannot affect prefix siblings.
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
    fn reconstruct_from_pins<H: Hasher<F>>(
        &self,
        hasher: &H,
        pinned_map: &mut BTreeMap<Position<F>, H::Digest>,
    ) -> Option<H::Digest> {
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
    fn reconstruct_digest<H, E>(
        &self,
        hasher: &H,
        range: &Range<Location<F>>,
        elements: &mut E,
        siblings: &[H::Digest],
        cursor: &mut usize,
        mut collected: Option<&mut Vec<(Position<F>, H::Digest)>>,
    ) -> Result<H::Digest, Error<F>>
    where
        H: Hasher<F>,
        E: Iterator<Item: AsRef<[u8]>>,
    {
        // Entirely outside the range: consume a sibling digest.
        if self.is_outside(range) {
            let Some(digest) = siblings.get(*cursor).copied() else {
                return Err(Error::InvalidProof);
            };
            *cursor += 1;
            return Ok(digest);
        }

        // Leaf in range: hash the next element.
        if self.height == 0 {
            let elem = elements.next().ok_or(Error::InvalidProof)?;
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

/// The plan of a range proof: the peaks of the structure partitioned around the proven range,
/// with the path siblings the proof reads from the peaks it overlaps.
///
/// [Self::positions] is everything the proof reads from the structure, so a storage adapter can
/// fetch the digests in one batch and then [Self::build] the proof from memory. The read set does
/// not depend on the bagging policy or the inactive-peak boundary: every peak outside the range
/// is read, whether the proof lists it or folds it into an accumulator, and every peak overlapping
/// the range is rebuilt from its path siblings. Those two parameters only shape the proof's
/// layout, which [Self::build] applies.
#[derive(Debug)]
pub struct RangePlan<F: Family> {
    /// Total number of leaves in the structure.
    leaves: Location<F>,
    /// The proven range.
    range: Range<Location<F>>,
    /// Peaks entirely before the range, in peak order.
    before: Vec<Subtree<F>>,
    /// Peaks overlapping the range, in peak order; never empty.
    overlapping: Vec<Subtree<F>>,
    /// Peak positions entirely after the range, in peak order.
    after: Vec<Position<F>>,
    /// Path siblings of the overlapping peaks, in left-first DFS order.
    siblings: Vec<Position<F>>,
}

impl<F: Family> RangePlan<F> {
    /// Plan a proof of `range` over a structure of `leaves` leaves.
    ///
    /// # Errors
    ///
    /// Returns [super::Error::Empty] for an empty range, [super::Error::RangeOutOfBounds] for a
    /// range that ends beyond `leaves`, and [super::Error::LocationOverflow] if `leaves` exceeds
    /// [Family::MAX_LEAVES].
    pub fn new(leaves: Location<F>, range: Range<Location<F>>) -> Result<Self, super::Error<F>> {
        if range.is_empty() {
            return Err(super::Error::Empty);
        }
        if range.end > leaves {
            return Err(super::Error::RangeOutOfBounds(range.end));
        }
        let size = Position::try_from(leaves)?;

        // Peaks cover consecutive leaf spans in iteration order. A peak wholly outside the range
        // enters the proof as one digest; a peak overlapping it is rebuilt from the proven
        // elements and the siblings of their path, so only those siblings are read.
        let mut before = Vec::new();
        let mut overlapping = Vec::new();
        let mut after = Vec::new();
        let mut leaf_start = Location::new(0);
        for (pos, height) in F::peaks(size) {
            let peak = Subtree {
                pos,
                height,
                leaf_start,
            };
            leaf_start = peak.leaf_end();
            if peak.is_before(&range) {
                before.push(peak);
            } else if peak.leaf_start >= range.end {
                after.push(pos);
            } else {
                overlapping.push(peak);
            }
        }
        assert!(
            !overlapping.is_empty(),
            "at least one peak must contain range elements"
        );

        // Siblings are kept in left-first DFS order because the verifier replays the same walk
        // to rebuild each overlapping peak.
        let mut siblings = Vec::new();
        for peak in &overlapping {
            peak.collect_siblings(&range, &mut siblings);
        }
        Ok(Self {
            leaves,
            range,
            before,
            overlapping,
            after,
            siblings,
        })
    }

    /// Total number of leaves in the structure this plan was built for.
    pub const fn leaves(&self) -> Location<F> {
        self.leaves
    }

    /// Every position the proof reads, in no particular order.
    fn reads(&self) -> impl Iterator<Item = Position<F>> + '_ {
        self.before
            .iter()
            .map(|peak| peak.pos)
            .chain(self.after.iter().copied())
            .chain(self.siblings.iter().copied())
    }

    /// Every position the proof reads, in strictly increasing order, as a batched storage read
    /// requires.
    pub fn positions(&self) -> Vec<Position<F>> {
        // Peaks outside the range and path siblings cover disjoint leaf spans, so their positions
        // are distinct and sorting makes them strictly increasing.
        let mut positions: Vec<_> = self.reads().collect();
        positions.sort_unstable();
        positions
    }

    /// Build the proof from the digests at [Self::positions], read through `get_node`.
    ///
    /// The proof commits to `inactive_peaks`; the bagging policy is read from `hasher`.
    ///
    /// # Errors
    ///
    /// Returns [super::Error::InvalidProof] if `inactive_peaks` exceeds the number of peaks and
    /// [super::Error::ElementPruned] for the first required position `get_node` cannot supply.
    pub fn build<H: Hasher<F>>(
        self,
        hasher: &H,
        inactive_peaks: usize,
        get_node: impl Fn(Position<F>) -> Option<H::Digest>,
    ) -> Result<Proof<F, H::Digest>, super::Error<F>> {
        Blueprint::from_plan(self, inactive_peaks, hasher.root_bagging())?.build_proof(
            hasher,
            inactive_peaks,
            get_node,
        )
    }
}

/// The plan of a proof of one element: a [RangePlan] over `location..location + 1`, which is what
/// a proof of a single element reads.
#[derive(Debug)]
pub struct ElementPlan<F: Family>(RangePlan<F>);

impl<F: Family> ElementPlan<F> {
    /// Plan a proof of the element at `location` in a structure of `leaves` leaves.
    ///
    /// # Errors
    ///
    /// Returns [super::Error::LocationOverflow] if `location` is not a valid index or `leaves`
    /// exceeds [Family::MAX_LEAVES], and [super::Error::RangeOutOfBounds] if `location` is at or
    /// beyond `leaves`.
    pub fn new(leaves: Location<F>, location: Location<F>) -> Result<Self, super::Error<F>> {
        let end = location
            .checked_add(1)
            .ok_or(super::Error::LocationOverflow(location))?;
        Ok(Self(RangePlan::new(leaves, location..end)?))
    }

    /// The proven element's location.
    pub const fn location(&self) -> Location<F> {
        self.0.range.start
    }

    /// Every position the proof reads, in strictly increasing order, as a batched storage read
    /// requires.
    pub fn positions(&self) -> Vec<Position<F>> {
        self.0.positions()
    }
}

/// The same plan as a range plan over `location..location + 1`.
impl<F: Family> From<ElementPlan<F>> for RangePlan<F> {
    fn from(plan: ElementPlan<F>) -> Self {
        plan.0
    }
}

/// Bagging-specific layout of a range proof: the peaks of a [RangePlan] separated into fold-prefix
/// peaks, individually listed peaks, and suffix peaks, plus the path siblings to fetch.
pub(crate) struct Blueprint<F: Family> {
    /// Total number of leaves in the structure this blueprint was built for.
    leaves: Location<F>,
    /// The location range this blueprint was built for.
    range: Range<Location<F>>,
    /// Peaks that precede the proven range (to be folded into a single accumulator).
    pub(crate) fold_prefix: Vec<Subtree<F>>,
    prefix_active_peaks: Vec<Subtree<F>>,
    /// Peak positions entirely after the proven range.
    after_peaks: Vec<Position<F>>,
    /// Active peak positions after the proven range that are collapsed into one suffix accumulator.
    suffix_peaks: Vec<Position<F>>,
    /// The peaks that overlap the proven range.
    range_peaks: Vec<Subtree<F>>,
    /// Path siblings of the overlapping peaks, in left-first DFS order.
    pub(crate) siblings: Vec<Position<F>>,
}

pub(crate) struct ProofDigestLayout<'a, D> {
    pub(crate) fold_prefix: Option<&'a D>,
    pub(crate) prefix_active_peaks: &'a [D],
    pub(crate) after_peaks: &'a [D],
    pub(crate) suffix_acc: Option<&'a D>,
    pub(crate) siblings: &'a [D],
}

impl<F: Family> Blueprint<F> {
    /// Build a range-proof blueprint for a caller-supplied bagging policy.
    pub(crate) fn new(
        leaves: Location<F>,
        inactive_peaks: usize,
        bagging: Bagging,
        range: Range<Location<F>>,
    ) -> Result<Self, super::Error<F>> {
        Self::from_plan(RangePlan::new(leaves, range)?, inactive_peaks, bagging)
    }

    /// Lay out the proof of `plan` for a caller-supplied bagging policy.
    ///
    /// Forward bagging folds peaks before the range into one prefix accumulator. Backward bagging
    /// also collapses active peaks after the range into one suffix accumulator while leaving inactive
    /// after-peaks position-keyed.
    pub(crate) fn from_plan(
        plan: RangePlan<F>,
        inactive_peaks: usize,
        bagging: Bagging,
    ) -> Result<Self, super::Error<F>> {
        let RangePlan {
            leaves,
            range,
            before,
            overlapping,
            after,
            siblings,
        } = plan;

        // `inactive_peaks` is a global boundary over the tree's peaks, not just the peaks before
        // this range. It may point into or beyond the proven range; reconstruction then folds the
        // same global boundary and the final root comparison rejects non-canonical proofs.
        if inactive_peaks > before.len() + overlapping.len() + after.len() {
            return Err(super::Error::InvalidProof);
        }

        // Peaks before the range fold into one prefix accumulator when they are inactive or the
        // bagging is forward. Under backward bagging the active ones are folded only after the
        // overlapping peaks, so they cannot be combined ahead of time and stay individual.
        let first_after = before.len() + overlapping.len();
        let fold_count = match bagging {
            Bagging::ForwardFold => before.len(),
            Bagging::BackwardFold => inactive_peaks.min(before.len()),
        };
        let mut fold_prefix = before;
        let prefix_active_peaks = fold_prefix.split_off(fold_count);

        // Backward bagging starts its fold at the newest peak, so the active peaks after the
        // range collapse into one suffix accumulator. The inactive boundary indexes the global
        // peak order, so the after-peaks continue the count past the prefix and overlapping peaks.
        let individual_count = match bagging {
            Bagging::ForwardFold => after.len(),
            Bagging::BackwardFold => inactive_peaks.saturating_sub(first_after).min(after.len()),
        };
        let mut after_peaks = after;
        let suffix_peaks = after_peaks.split_off(individual_count);

        Ok(Self {
            leaves,
            range,
            fold_prefix,
            prefix_active_peaks,
            after_peaks,
            suffix_peaks,
            range_peaks: overlapping,
            siblings,
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

    /// Peak positions listed individually in the proof, in layout order.
    pub(crate) fn individual_positions(&self) -> impl Iterator<Item = Position<F>> + '_ {
        self.prefix_active_peaks
            .iter()
            .map(|peak| peak.pos)
            .chain(self.after_peaks.iter().copied())
    }

    /// Return active after-peaks that are collapsed into a backward-folded suffix accumulator.
    #[cfg(feature = "std")]
    pub(crate) fn suffix_peaks(&self) -> Option<&[Position<F>]> {
        (!self.suffix_peaks.is_empty()).then_some(&self.suffix_peaks)
    }

    /// Split a proof's digest vector according to this blueprint's range-proof layout, in the
    /// order [Self::build_proof] emits it.
    pub(crate) fn split_proof_digests<'a, D>(
        &self,
        digests: &'a [D],
    ) -> Result<ProofDigestLayout<'a, D>, Error<F>> {
        let fold_count = usize::from(!self.fold_prefix.is_empty());
        let suffix_count = usize::from(!self.suffix_peaks.is_empty());
        let prefix_start = fold_count;
        let after_start = prefix_start + self.prefix_active_peaks.len();
        let suffix_start = after_start + self.after_peaks.len();
        let suffix_end = suffix_start + suffix_count;
        let required = suffix_end + self.siblings.len();
        if digests.len() != required {
            return Err(Error::InvalidProof);
        }

        Ok(ProofDigestLayout {
            fold_prefix: (!self.fold_prefix.is_empty()).then(|| &digests[0]),
            prefix_active_peaks: &digests[prefix_start..after_start],
            after_peaks: &digests[after_start..suffix_start],
            suffix_acc: (!self.suffix_peaks.is_empty()).then(|| &digests[suffix_start]),
            siblings: &digests[suffix_end..],
        })
    }

    /// Map the original `inactive_peaks` count to the count for the reconstructed peak list,
    /// where `fold_prefix.len()` peaks have been collapsed into one leading accumulator entry.
    ///
    /// The accumulator counts as 1 inactive peak; any inactive peaks beyond `fold_prefix.len()`
    /// remain unfolded after it. Under `ForwardFold` the accumulator may absorb active peaks too
    /// (`fold_prefix.len() > inactive_peaks`); `saturating_sub` clamps and the result is 1.
    const fn inactive_peaks_after_prefix_fold(&self, inactive_peaks: usize) -> usize {
        if self.fold_prefix.is_empty() {
            return inactive_peaks;
        }
        inactive_peaks.saturating_sub(self.fold_prefix.len()) + 1
    }

    /// Build a range proof from this blueprint and a node-fetching closure.
    ///
    /// The prover folds prefix peak digests into a single accumulator. The resulting proof
    /// contains:
    /// `[fold_acc? | prefix_active_peaks... | after_peaks... | suffix_acc? | siblings_dfs...]`.
    ///
    /// Returns [super::Error::ElementPruned] for the first required position `get_node` cannot
    /// supply.
    pub(crate) fn build_proof<H: Hasher<F>>(
        &self,
        hasher: &H,
        inactive_peaks: usize,
        get_node: impl Fn(Position<F>) -> Option<H::Digest>,
    ) -> Result<Proof<F, H::Digest>, super::Error<F>> {
        let node = |pos: Position<F>| get_node(pos).ok_or(super::Error::ElementPruned(pos));
        let mut digests = Vec::with_capacity(
            if self.fold_prefix.is_empty() { 0 } else { 1 }
                + self.prefix_active_peaks.len()
                + self.after_peaks.len()
                + self.siblings.len()
                + usize::from(!self.suffix_peaks.is_empty()),
        );

        // Peaks before the range that fold collapse into one leading accumulator.
        if let Some((first_sub, rest)) = self.fold_prefix.split_first() {
            let acc = rest.iter().try_fold(node(first_sub.pos)?, |acc, sub| {
                node(sub.pos).map(|d| hasher.fold(&acc, &d))
            })?;
            digests.push(acc);
        }

        // Individually listed peaks follow: active prefix peaks, then explicit after-peaks.
        for pos in self.individual_positions() {
            digests.push(node(pos)?);
        }

        // Active after-peaks under backward bagging collapse into one suffix accumulator.
        if let Some((last_pos, rest)) = self.suffix_peaks.split_last() {
            let acc = rest.iter().rev().try_fold(node(*last_pos)?, |acc, &pos| {
                node(pos).map(|d| hasher.fold(&d, &acc))
            })?;
            digests.push(acc);
        }

        // DFS path siblings of the overlapping peaks close the proof.
        for &pos in &self.siblings {
            digests.push(node(pos)?);
        }

        Ok(Proof {
            leaves: self.leaves,
            inactive_peaks,
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

/// Positions a multi-proof over strictly ascending `locations` reads from a structure of `leaves`
/// leaves, in strictly increasing order: the union of each location's [ElementPlan::positions], so
/// it does not depend on bagging or inactive peaks either. A multi-proof is these digests in this
/// order.
///
/// # Errors
///
/// Returns [super::Error::Empty] if `locations` is empty. Otherwise, returns the error of the
/// first invalid location in input order: the error of [ElementPlan::new],
/// [super::Error::DuplicateLocation] if it repeats the previous location, or
/// [super::Error::UnsortedLocation] if it precedes it.
pub fn multi_proof_positions<F: Family>(
    leaves: Location<F>,
    locations: &[Location<F>],
) -> Result<Vec<Position<F>>, super::Error<F>> {
    // Check the locations in input order so the first invalid one determines the error.
    let Some((&first, rest)) = locations.split_first() else {
        return Err(super::Error::Empty);
    };
    let check_bounds = |loc: Location<F>| -> Result<(), super::Error<F>> {
        let end = loc
            .checked_add(1)
            .ok_or(super::Error::LocationOverflow(loc))?;
        if end > leaves {
            return Err(super::Error::RangeOutOfBounds(end));
        }
        Ok(())
    };
    check_bounds(first)?;
    let size = Position::try_from(leaves)?;
    let mut previous = first;
    for &loc in rest {
        if loc == previous {
            return Err(super::Error::DuplicateLocation(loc));
        }
        if loc < previous {
            return Err(super::Error::UnsortedLocation(loc));
        }
        check_bounds(loc)?;
        previous = loc;
    }

    // A single-element proof reads the other peaks and the siblings along the path from its leaf to
    // its peak. The union over all selected leaves is every peak that does not hold all of them,
    // plus the siblings along each leaf's path. The walk emits each position once.
    let mut positions = Vec::new();
    let mut remaining = locations;
    let mut leaf_start = Location::new(0);
    for (pos, height) in F::peaks(size) {
        let peak = Subtree {
            pos,
            height,
            leaf_start,
        };
        leaf_start = peak.leaf_end();
        let (selected, rest) =
            remaining.split_at(remaining.partition_point(|loc| *loc < leaf_start));
        remaining = rest;
        if !selected.is_empty() {
            peak.collect_multi_siblings(selected, &mut positions);
        }
        if selected.len() != locations.len() {
            positions.push(pos);
        }
    }

    // The walk emits positions in postorder. An MMR numbers its nodes in that order, but an MMB can
    // append a parent after leaves to its right, so its positions need sorting.
    positions.sort_unstable();
    Ok(positions)
}

#[cfg(feature = "arbitrary")]
impl<F: Family, D: Digest> arbitrary::Arbitrary<'_> for Proof<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            leaves: u.arbitrary()?,
            inactive_peaks: u.arbitrary()?,
            digests: u.arbitrary()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{
        Bagging::{BackwardFold, ForwardFold},
        Family, Location, LocationRangeExt as _,
        hasher::Standard,
        mem::Mem,
        mmb, mmr,
        proof::{Blueprint, Proof, multi_proof_positions},
    };
    use alloc::{collections::BTreeSet, vec};
    use commonware_codec::{Decode, Encode, EncodeSize};
    use commonware_cryptography::{Sha256, sha256};
    use commonware_macros::test_traced;
    use commonware_utils::test_rng;
    use rand::RngExt as _;

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn check_range_plan<F: Family>() {
        for leaves in 1..=24u64 {
            let peaks = F::peaks(Position::try_from(Location::<F>::new(leaves)).unwrap()).count();
            for start in 0..leaves {
                for end in start + 1..=leaves {
                    let range = Location::<F>::new(start)..Location::new(end);
                    let plan = RangePlan::new(Location::new(leaves), range.clone()).unwrap();
                    let positions = plan.positions();
                    assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
                    for bagging in [ForwardFold, BackwardFold] {
                        let hasher = H::new(bagging);
                        for inactive_peaks in 0..=peaks {
                            let reads = core::cell::RefCell::new(Vec::new());
                            RangePlan::new(Location::new(leaves), range.clone())
                                .unwrap()
                                .build(&hasher, inactive_peaks, |pos| {
                                    reads.borrow_mut().push(pos);
                                    Some(test_digest(0))
                                })
                                .unwrap();
                            let mut read = reads.into_inner();
                            read.sort_unstable();
                            assert_eq!(
                                read, positions,
                                "leaves={leaves} range={start}..{end} bagging={bagging:?} inactive_peaks={inactive_peaks}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn range_plan_positions_independent_of_bagging_and_inactive_peaks() {
        check_range_plan::<mmr::Family>();
        check_range_plan::<mmb::Family>();
    }

    #[test]
    fn range_plan_rejects_invalid_inputs() {
        type F = mmr::Family;
        let leaves = Location::<F>::new(8);
        assert!(matches!(
            RangePlan::new(leaves, leaves..leaves + 1),
            Err(Error::RangeOutOfBounds(_))
        ));
        assert!(matches!(
            RangePlan::new(leaves, Location::new(3)..Location::new(3)),
            Err(Error::Empty)
        ));
        for leaves in [
            Location::<F>::new(*F::MAX_LEAVES + 1),
            Location::new(u64::MAX),
        ] {
            assert!(matches!(
                RangePlan::new(leaves, Location::new(0)..Location::new(1)),
                Err(Error::LocationOverflow(_))
            ));
        }
    }

    #[test]
    fn multi_proof_positions_reject_invalid_inputs() {
        type F = mmr::Family;
        let leaves = Location::<F>::new(8);
        assert!(matches!(
            multi_proof_positions(leaves, &[Location::new(2), leaves]),
            Err(Error::RangeOutOfBounds(_))
        ));
        assert!(matches!(
            multi_proof_positions::<F>(leaves, &[]),
            Err(Error::Empty)
        ));
        assert!(matches!(
            multi_proof_positions(leaves, &[Location::new(u64::MAX)]),
            Err(Error::LocationOverflow(_))
        ));
    }

    #[test]
    fn multi_proofs_report_first_invalid_location() {
        fn check<F: Family>() {
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, 4);
            let leaves = mem.leaves();
            let root = plain_root(&mem, &hasher);
            let location = Location::<F>::new;

            // A proof of every leaf, so verification can fail only on the supplied locations.
            let all: Vec<_> = (0..4).map(location).collect();
            let proof = Proof {
                leaves,
                inactive_peaks: 0,
                digests: multi_proof_positions(leaves, &all)
                    .unwrap()
                    .into_iter()
                    .map(|pos| mem.get_node(pos).unwrap())
                    .collect(),
            };
            let elements: Vec<_> = all.iter().map(|loc| (loc.to_be_bytes(), *loc)).collect();
            assert!(proof.verify_multi_inclusion(&hasher, &elements, &root));

            // Each location is checked against the previous one in input order, so the error names
            // the first out-of-range, repeated, or descending location even when a later location
            // sorts before it. An out-of-range location reports the end of its one-element range.
            let cases = [
                (vec![], Error::Empty),
                (vec![0, 0, 4], Error::DuplicateLocation(location(0))),
                (vec![4, 0, 0], Error::RangeOutOfBounds(location(5))),
                (vec![3, 4], Error::RangeOutOfBounds(location(5))),
                (vec![2, 1], Error::UnsortedLocation(location(1))),
                (vec![3, 1, 1, 3], Error::UnsortedLocation(location(1))),
                (vec![1, 3, 3, 1], Error::DuplicateLocation(location(3))),
                (vec![0, 1, 2, 3, 0, 4], Error::UnsortedLocation(location(0))),
                (vec![0, 1, 2, 3, 4, 0], Error::RangeOutOfBounds(location(5))),
            ];
            for (locations, expected) in cases {
                let locations: Vec<_> = locations.into_iter().map(location).collect();
                assert_eq!(
                    format!("{:?}", multi_proof_positions(leaves, &locations).err()),
                    format!("{:?}", Some(&expected)),
                    "multi_proof_positions({locations:?}) must report the first invalid location"
                );

                // Verification rejects the same location lists.
                let elements: Vec<_> = locations
                    .iter()
                    .map(|loc| (loc.to_be_bytes(), *loc))
                    .collect();
                assert!(
                    !proof.verify_multi_inclusion(&hasher, &elements, &root),
                    "verify_multi_inclusion({locations:?}) must fail"
                );
            }
        }
        check::<mmr::Family>();
        check::<mmb::Family>();
    }

    /// Reference implementation of `multi_proof_positions` that returns the union of each
    /// location's [ElementPlan::positions]. It fails on an empty list or on the first invalid
    /// location in input order.
    fn union_of_element_positions<F: Family>(
        leaves: Location<F>,
        locations: &[Location<F>],
    ) -> Result<Vec<Position<F>>, Error<F>> {
        if locations.is_empty() {
            return Err(Error::Empty);
        }
        let mut union = BTreeSet::new();
        for (i, &loc) in locations.iter().enumerate() {
            if i > 0 && loc == locations[i - 1] {
                return Err(Error::DuplicateLocation(loc));
            }
            if i > 0 && loc < locations[i - 1] {
                return Err(Error::UnsortedLocation(loc));
            }
            union.extend(ElementPlan::new(leaves, loc)?.positions());
        }
        Ok(union.into_iter().collect())
    }

    #[test]
    fn multi_proof_positions_match_union_of_element_positions() {
        fn check<F: Family>(leaves: u64, locations: &[u64]) {
            let leaves = Location::<F>::new(leaves);
            let locations: Vec<_> = locations.iter().copied().map(Location::new).collect();
            assert_eq!(
                format!("{:?}", multi_proof_positions(leaves, &locations)),
                format!("{:?}", union_of_element_positions(leaves, &locations)),
                "leaves={leaves} locations={locations:?} must match the union of element positions"
            );
        }

        fn check_family<F: Family>() {
            // In trees of up to 10 leaves, check every nonempty selection. In trees of up to 64
            // leaves, check every single leaf, every pair, every whole peak, and all leaves.
            for leaves in 1..=64u64 {
                if leaves <= 10 {
                    for mask in 1..1u64 << leaves {
                        let selection: Vec<_> =
                            (0..leaves).filter(|loc| mask & (1 << loc) != 0).collect();
                        check::<F>(leaves, &selection);
                    }
                }
                for first in 0..leaves {
                    check::<F>(leaves, &[first]);
                    for second in first + 1..leaves {
                        check::<F>(leaves, &[first, second]);
                    }
                }
                check::<F>(leaves, &(0..leaves).collect::<Vec<_>>());
                let size = Position::try_from(Location::<F>::new(leaves)).unwrap();
                let mut start = 0;
                for (_, height) in F::peaks(size) {
                    let end = start + (1u64 << height);
                    check::<F>(leaves, &(start..end).collect::<Vec<_>>());
                    start = end;
                }
            }

            // Check random selections in trees of up to 2^20 leaves.
            let mut rng = test_rng();
            for _ in 0..256 {
                let leaves = rng.random_range(1..=1u64 << 20);
                let mut selection: Vec<_> = (0..rng.random_range(1..=64))
                    .map(|_| rng.random_range(0..leaves))
                    .collect();
                selection.sort_unstable();
                selection.dedup();
                check::<F>(leaves, &selection);
            }

            // Empty and invalid inputs must fail with the reference's error.
            let max = *F::MAX_LEAVES;
            for (leaves, selection) in [
                (8, vec![]),
                (8, vec![8]),
                (8, vec![2, 8, 1]),
                (8, vec![3, 3]),
                (8, vec![3, 1, 9]),
                (8, vec![u64::MAX]),
                (max, vec![max - 1, max]),
                (max + 1, vec![0, 0]),
                (max + 1, vec![u64::MAX]),
                (u64::MAX, vec![u64::MAX - 1]),
            ] {
                check::<F>(leaves, &selection);
            }
        }
        check_family::<mmr::Family>();
        check_family::<mmb::Family>();
    }

    #[test]
    fn multi_proofs_bind_every_digest_and_element() {
        fn check<F: Family>() {
            for leaves in [1u64, 2, 3, 7, 8, 11, 31, 64] {
                let mem = build_raw::<F>(&H::new(ForwardFold), leaves);
                let peaks = F::peaks(Position::try_from(mem.leaves()).unwrap()).count();

                // Test single leaves and multi-leaf selections, since a proof of two or more leaves
                // holds digests that verification also computes.
                let mut selections = vec![vec![0], vec![leaves - 1], (0..leaves).collect()];
                if leaves > 1 {
                    selections.push(vec![0, 1]);
                    selections.push(vec![0, leaves - 1]);
                    selections.push((0..leaves).step_by(2).collect());
                }
                for bagging in [ForwardFold, BackwardFold] {
                    let hasher = H::new(bagging);
                    for inactive_peaks in 0..=peaks {
                        let root = mem.root(&hasher, inactive_peaks).unwrap();
                        for selection in &selections {
                            // The tree's digests at the planned positions must form a valid proof.
                            let locations: Vec<_> =
                                selection.iter().copied().map(Location::<F>::new).collect();
                            let proof = Proof {
                                leaves: mem.leaves(),
                                inactive_peaks,
                                digests: multi_proof_positions(mem.leaves(), &locations)
                                    .unwrap()
                                    .into_iter()
                                    .map(|pos| mem.get_node(pos).unwrap())
                                    .collect(),
                            };
                            let elements: Vec<_> = locations
                                .iter()
                                .map(|loc| (loc.to_be_bytes(), *loc))
                                .collect();
                            assert!(
                                proof.verify_multi_inclusion(&hasher, &elements, &root),
                                "leaves={leaves} selection={selection:?} must verify"
                            );

                            // Changing any one digest or element must make verification fail.
                            for i in 0..proof.digests.len() {
                                let mut tampered = proof.clone();
                                tampered.digests[i].0[0] ^= 1;
                                assert!(
                                    !tampered.verify_multi_inclusion(&hasher, &elements, &root),
                                    "leaves={leaves} selection={selection:?} must reject a changed digest {i}"
                                );
                            }
                            for i in 0..elements.len() {
                                let mut tampered = elements.clone();
                                tampered[i].0[0] ^= 1;
                                assert!(
                                    !proof.verify_multi_inclusion(&hasher, &tampered, &root),
                                    "leaves={leaves} selection={selection:?} must reject a changed element {i}"
                                );
                            }
                        }
                    }
                }
            }
        }
        check::<mmr::Family>();
        check::<mmb::Family>();
    }

    #[test]
    fn element_plan_rejects_invalid_inputs() {
        type F = mmr::Family;
        let leaves = Location::<F>::new(8);
        assert!(matches!(
            ElementPlan::new(leaves, leaves),
            Err(Error::RangeOutOfBounds(_))
        ));
        for location in [F::MAX_LEAVES, Location::new(u64::MAX)] {
            assert!(matches!(
                ElementPlan::new(leaves, location),
                Err(Error::LocationOverflow(_))
            ));
        }
    }

    #[test]
    fn range_plan_build_reports_the_first_missing_node_and_rejects_before_reading() {
        type F = mmr::Family;
        let hasher = H::new(BackwardFold);
        let mem = build_raw::<F>(&hasher, 11);
        let plan = || RangePlan::new(mem.leaves(), Location::new(3)..Location::new(5)).unwrap();
        let positions = plan().positions();
        let missing = positions[1];
        let reads = core::cell::RefCell::new(Vec::new());
        let get_node = |pos: Position<F>| {
            reads.borrow_mut().push(pos);
            (pos != missing).then(|| mem.get_node(pos)).flatten()
        };
        assert!(matches!(
            plan().build(&hasher, 0, get_node),
            Err(Error::ElementPruned(pos)) if pos == missing
        ));
        reads.borrow_mut().clear();
        let peaks = F::peaks(mem.size()).count();
        assert!(matches!(
            plan().build(&hasher, peaks + 1, get_node),
            Err(Error::InvalidProof)
        ));
        assert!(
            reads.borrow().is_empty(),
            "an invalid inactive boundary must not read nodes"
        );
    }

    fn test_digest(v: u8) -> D {
        <Sha256 as commonware_cryptography::Hasher>::hash(&[&[v]])
    }

    /// Build an in-memory Merkle structure with `n` elements (element i = i.to_be_bytes()).
    fn build_raw<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new();
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

    fn build_inactive_prefix<F: Family>(hasher: &H, n: u64, inactive_peaks: usize) -> Mem<F, D> {
        let mut mem = Mem::new();
        let batch = {
            let mut batch = mem.new_batch();
            for i in 0..n {
                batch = batch.add(hasher, &i.to_be_bytes());
            }
            let batch = batch.merkleize(&mem, hasher);
            batch.root(&mem, hasher, inactive_peaks).unwrap();
            batch
        };
        mem.apply_batch(&batch).unwrap();
        mem
    }

    fn plain_root<F: Family>(mem: &Mem<F, D>, hasher: &H) -> D {
        mem.root(hasher, 0).unwrap()
    }

    fn split_root<F: Family>(mem: &Mem<F, D>, inactive_peaks: usize) -> D {
        let backward_hasher: H = Standard::new(BackwardFold);
        mem.root(&backward_hasher, inactive_peaks).unwrap()
    }

    /// Hasher tuned for `bagging` so callers can mix forward/backward and full/split policies.
    fn hasher_for_bagging(bagging: Bagging) -> H {
        Standard::new(bagging)
    }

    fn push_unique_shape(shapes: &mut Vec<(Bagging, usize)>, shape: (Bagging, usize)) {
        if !shapes.contains(&shape) {
            shapes.push(shape);
        }
    }

    fn supported_root_shapes<F: Family>(leaves: Location<F>) -> Vec<(Bagging, usize)> {
        let peak_count = F::peaks(F::location_to_position(leaves)).count();
        let mut shapes = Vec::new();

        push_unique_shape(&mut shapes, (Bagging::ForwardFold, 0));
        push_unique_shape(&mut shapes, (Bagging::BackwardFold, 0));
        for inactive_peaks in 0..=peak_count {
            push_unique_shape(&mut shapes, (Bagging::ForwardFold, inactive_peaks));
            push_unique_shape(&mut shapes, (Bagging::BackwardFold, inactive_peaks));
        }

        shapes
    }

    fn inactive_leaf_floor<F: Family>(leaves: Location<F>, inactive_peaks: usize) -> u64 {
        F::peaks(F::location_to_position(leaves))
            .take(inactive_peaks)
            .map(|(_, height)| 1u64 << height)
            .sum()
    }

    fn active_start_for_shape<F: Family>(
        leaves: Location<F>,
        inactive_peaks: usize,
        width: u64,
    ) -> Location<F> {
        let start = inactive_leaf_floor::<F>(leaves, inactive_peaks);
        if start + width <= *leaves {
            return Location::new(start);
        }
        leaves - width
    }

    fn range_proofs_verify_for_supported_root_shapes<F: Family>() {
        let mem = build_raw::<F>(&H::new(ForwardFold), 123);
        let leaves = mem.leaves();

        for (bagging, inactive_peaks) in supported_root_shapes::<F>(leaves) {
            let hasher = hasher_for_bagging(bagging);
            let range_start = active_start_for_shape::<F>(leaves, inactive_peaks, 3);
            let range = range_start..range_start + 3;
            let root = mem.root(&hasher, inactive_peaks).unwrap();
            let elements: Vec<_> = (*range.start..*range.end)
                .map(|i| i.to_be_bytes())
                .collect();
            let proof: Proof<F, D> = RangePlan::new(leaves, range.clone())
                .unwrap()
                .build(&hasher, inactive_peaks, |pos| mem.get_node(pos))
                .unwrap();

            assert_eq!(proof.inactive_peaks, inactive_peaks);
            assert!(
                proof.verify_range_inclusion(&hasher, &elements, range.start, &root),
                "range proof should verify for ({bagging:?}, {inactive_peaks})",
            );

            let mut tampered_boundary = proof.clone();
            tampered_boundary.inactive_peaks = if inactive_peaks == 0 { 1 } else { 0 };
            assert!(
                !tampered_boundary.verify_range_inclusion(&hasher, &elements, range.start, &root),
                "inactive_peaks mutation should fail for ({bagging:?}, {inactive_peaks})",
            );

            if !proof.digests.is_empty() {
                let mut tampered_digest = proof.clone();
                tampered_digest.digests[0].0[0] ^= 1;
                assert!(
                    !tampered_digest
                        .verify_range_inclusion(&hasher, &elements, range.start, &root,),
                    "digest mutation should fail for ({bagging:?}, {inactive_peaks})",
                );
            }
        }
    }

    fn multi_proofs_verify_for_supported_root_shapes<F: Family>() {
        let mem = build_raw::<F>(&H::new(ForwardFold), 123);
        let leaves = mem.leaves();

        for (bagging, inactive_peaks) in supported_root_shapes::<F>(leaves) {
            let hasher = hasher_for_bagging(bagging);
            let first = active_start_for_shape::<F>(leaves, inactive_peaks, 12);
            let locations = [first, first + 5, first + 11];
            let nodes = multi_proof_positions(leaves, &locations).expect("test locations valid");
            let proof = Proof {
                leaves,
                inactive_peaks,
                digests: nodes
                    .into_iter()
                    .map(|pos| mem.get_node(pos).unwrap())
                    .collect(),
            };
            let root = mem.root(&hasher, inactive_peaks).unwrap();
            let elements: Vec<_> = locations
                .iter()
                .map(|loc| ((*loc).to_be_bytes(), *loc))
                .collect();

            assert!(
                proof.verify_multi_inclusion(&hasher, &elements, &root),
                "multi-proof should verify for ({bagging:?}, {inactive_peaks})",
            );

            // Locations must be strictly ascending, so a repeated location fails whether or not
            // its element matches, and genuine elements fail in descending order.
            let mut duplicated = elements.clone();
            duplicated.push(elements[elements.len() - 1]);
            assert!(!proof.verify_multi_inclusion(&hasher, &duplicated, &root));
            duplicated.last_mut().unwrap().0[0] ^= 1;
            assert!(!proof.verify_multi_inclusion(&hasher, &duplicated, &root));
            let mut descending = elements.clone();
            descending.reverse();
            assert!(!proof.verify_multi_inclusion(&hasher, &descending, &root));

            let mut tampered_boundary = proof.clone();
            tampered_boundary.inactive_peaks = if inactive_peaks == 0 { 1 } else { 0 };
            assert!(
                !tampered_boundary.verify_multi_inclusion(&hasher, &elements, &root),
                "inactive_peaks mutation should fail for ({bagging:?}, {inactive_peaks})",
            );

            if !proof.digests.is_empty() {
                let mut tampered_digest = proof.clone();
                tampered_digest.digests[0].0[0] ^= 1;
                assert!(
                    !tampered_digest.verify_multi_inclusion(&hasher, &elements, &root),
                    "digest mutation should fail for ({bagging:?}, {inactive_peaks})",
                );
            }
        }
    }

    fn backward_fold_proof_optimization_inner(inactive_peaks: usize) {
        let hasher: H = Standard::new(BackwardFold);
        let mem = build_inactive_prefix::<mmb::Family>(&hasher, 123, inactive_peaks);
        let leaves = mem.leaves();
        let root = split_root(&mem, inactive_peaks);

        let mut selected = None;
        for loc in 0..*leaves {
            let range = Location::new(loc)..Location::new(loc + 1);
            let optimized =
                Blueprint::new(leaves, inactive_peaks, Bagging::BackwardFold, range.clone())
                    .unwrap();
            if optimized.suffix_peaks.len() > 1 {
                selected = Some((range, optimized));
                break;
            }
        }
        let (range, optimized) = selected.expect("test tree should expose a multi-peak suffix");

        let suffix_len = optimized.suffix_peaks.len();
        let position_keyed_len = usize::from(!optimized.fold_prefix.is_empty())
            + optimized.prefix_active_peaks.len()
            + optimized.after_peaks.len()
            + optimized.siblings.len()
            + suffix_len;
        let suffix_idx = usize::from(!optimized.fold_prefix.is_empty())
            + optimized.prefix_active_peaks.len()
            + optimized.after_peaks.len();
        let proof = optimized
            .build_proof(&hasher, inactive_peaks, |pos| mem.get_node(pos))
            .unwrap();

        assert_eq!(position_keyed_len - proof.digests.len(), suffix_len - 1);
        assert!(proof.verify_range_inclusion(
            &hasher,
            &[range.start.to_be_bytes()],
            range.start,
            &root,
        ));

        let mut tampered = proof;
        tampered.digests[suffix_idx].0[0] ^= 1;
        assert!(!tampered.verify_range_inclusion(
            &hasher,
            &[range.start.to_be_bytes()],
            range.start,
            &root,
        ));
    }

    #[test]
    fn full_backward_root_proves_like_split_zero() {
        let hasher: H = Standard::new(BackwardFold);
        let mem = build_raw::<mmb::Family>(&hasher, 123);
        let range = Location::new(2)..Location::new(3);

        let generated: Proof<mmb::Family, D> = RangePlan::new(mem.leaves(), range.clone())
            .unwrap()
            .build(&hasher, 0, |pos| mem.get_node(pos))
            .unwrap();

        let full_backward_root = mem.root(&hasher, 0).unwrap();
        assert!(generated.verify_range_inclusion(
            &hasher,
            &[range.start.to_be_bytes()],
            range.start,
            &full_backward_root,
        ));

        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes = multi_proof_positions(mem.leaves(), locations).expect("valid locations");
        let multi_proof = Proof {
            leaves: mem.leaves(),
            inactive_peaks: 0,
            digests: nodes
                .into_iter()
                .map(|pos| mem.get_node(pos).unwrap())
                .collect(),
        };
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (0u64.to_be_bytes(), Location::new(0)),
                (5u64.to_be_bytes(), Location::new(5)),
                (10u64.to_be_bytes(), Location::new(10)),
            ],
            &full_backward_root,
        ));

        // A zero inactive boundary is byte-identical to the corresponding full root.
        let split_root_value = mem.root(&hasher, 0).unwrap();
        assert_eq!(full_backward_root, split_root_value);
        let split_proof: Proof<mmb::Family, D> = RangePlan::new(mem.leaves(), range.clone())
            .unwrap()
            .build(&hasher, 0, |pos| mem.get_node(pos))
            .unwrap();
        assert!(split_proof.verify_range_inclusion(
            &hasher,
            &[range.start.to_be_bytes()],
            range.start,
            &split_root_value,
        ));
    }

    /// Insert the roots of `n` elements of family `F` under every bagging policy and inactive
    /// boundary into `roots`. Panics if any root is already present.
    fn insert_roots<F: Family>(n: u64, roots: &mut BTreeMap<D, (&'static str, Bagging, usize)>) {
        let mem = build_raw::<F>(&H::new(ForwardFold), n);
        let peaks = F::peaks(mem.size()).count();
        for bagging in [ForwardFold, BackwardFold] {
            for inactive_peaks in 0..=peaks {
                let root = mem.root(&H::new(bagging), inactive_peaks).unwrap();
                let config = (core::any::type_name::<F>(), bagging, inactive_peaks);
                if let Some(other) = roots.insert(root, config) {
                    panic!("n={n}: {config:?} and {other:?} must have distinct roots");
                }
            }
        }
    }

    #[test]
    fn roots_commit_family_and_bagging() {
        // For a fixed leaf count, roots must distinguish the family, bagging policy,
        // and inactive boundary, including when the tree is empty.
        for n in 0..=64 {
            let mut roots = BTreeMap::new();
            insert_roots::<mmr::Family>(n, &mut roots);
            insert_roots::<mmb::Family>(n, &mut roots);
        }
    }

    /// Whether `proof`, re-typed for family `V`, verifies `elements` from `start` against `root`
    /// under `bagging`.
    fn verifies_under<F: Family, V: Family>(
        proof: &Proof<F, D>,
        bagging: Bagging,
        elements: &[[u8; 8]],
        start: u64,
        root: &D,
    ) -> bool {
        let proof = Proof::<V, D> {
            leaves: Location::new(*proof.leaves),
            inactive_peaks: proof.inactive_peaks,
            digests: proof.digests.clone(),
        };
        proof.verify_range_inclusion(&H::new(bagging), elements, Location::new(start), root)
    }

    /// Check that every single-element proof over `n` elements of family `F`, at every inactive
    /// boundary, verifies only under `F` and the bagging policy that produced it, and never under
    /// family `G`.
    fn check_proof_binding<F: Family, G: Family>(n: u64) {
        let mem = build_raw::<F>(&H::new(ForwardFold), n);
        let peaks = F::peaks(mem.size()).count();
        let configs = [ForwardFold, BackwardFold]
            .into_iter()
            .flat_map(|bagging| (0..=peaks).map(move |inactive| (bagging, inactive)));
        for (bagging, inactive) in configs {
            let hasher = H::new(bagging);
            let root = mem.root(&hasher, inactive).unwrap();
            for loc in 0..n {
                let proof = mem.proof(&hasher, Location::new(loc), inactive).unwrap();
                let element = [loc.to_be_bytes()];
                for verifier in [ForwardFold, BackwardFold] {
                    assert_eq!(
                        verifies_under::<F, F>(&proof, verifier, &element, loc, &root),
                        verifier == bagging,
                        "n={n} loc={loc} inactive={inactive} prover={bagging:?} verifier={verifier:?}"
                    );
                    assert!(
                        !verifies_under::<F, G>(&proof, verifier, &element, loc, &root),
                        "n={n} loc={loc} inactive={inactive} prover={bagging:?} verifier={verifier:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn proofs_verify_only_under_their_family_and_bagging() {
        for n in 1..=32 {
            check_proof_binding::<mmr::Family, mmb::Family>(n);
            check_proof_binding::<mmb::Family, mmr::Family>(n);
        }
    }

    /// Check that the empty proof verifies the empty root of family `F` only under `F` and the
    /// bagging policy that produced it, and never under family `G`.
    fn check_empty_proof_binding<F: Family, G: Family>() {
        let mem = Mem::<F, D>::new();
        let proof = Proof::<F, D>::default();
        for bagging in [ForwardFold, BackwardFold] {
            let root = mem.root(&H::new(bagging), 0).unwrap();
            for verifier in [ForwardFold, BackwardFold] {
                assert_eq!(
                    verifies_under::<F, F>(&proof, verifier, &[], 0, &root),
                    verifier == bagging,
                    "prover={bagging:?} verifier={verifier:?}"
                );
                assert!(
                    !verifies_under::<F, G>(&proof, verifier, &[], 0, &root),
                    "prover={bagging:?} verifier={verifier:?}"
                );
            }
        }
    }

    #[test]
    fn empty_proofs_verify_only_under_their_family_and_bagging() {
        check_empty_proof_binding::<mmr::Family, mmb::Family>();
        check_empty_proof_binding::<mmb::Family, mmr::Family>();
    }

    #[test]
    fn mmb_verifier_rejects_mmr_root() {
        // With 2^k - 1 elements, both families have k peaks, and the newest MMR peak is the leaf at
        // the newest MMB peak's position. An MMB proof of that leaf can therefore carry the older
        // MMR peaks from the MMR proof.
        let hasher = H::new(BackwardFold);
        for k in 1..=10 {
            // The honest MMR proof of the newest leaf verifies against the MMR root.
            let n = (1u64 << k) - 1;
            let mmr = build_raw::<mmr::Family>(&hasher, n);
            let root = mmr.root(&hasher, 0).unwrap();
            let loc = n - 1;
            let element = loc.to_be_bytes();
            let proof = mmr.proof(&hasher, Location::new(loc), 0).unwrap();
            assert!(proof.verify_element_inclusion(&hasher, &element, Location::new(loc), &root));

            // Reinterpreted as an MMB proof, it reconstructs the root that the MMB hasher computes
            // over the MMR's peaks. Only the family tag separates that root from the MMR root, so
            // the forged proof fails against the MMR root.
            let forged = Proof::<mmb::Family, D> {
                leaves: Location::new(n),
                inactive_peaks: 0,
                digests: proof.digests,
            };
            let peaks: Vec<D> = mmr
                .peak_iterator()
                .map(|(pos, _)| mmr.get_node(pos).unwrap())
                .collect();
            let mmb_root =
                <H as Hasher<mmb::Family>>::root(&hasher, Location::new(n), 0, peaks.iter())
                    .unwrap();
            assert_eq!(
                forged
                    .reconstruct_root(&hasher, &[element], Location::new(loc))
                    .unwrap(),
                mmb_root,
                "k={k}"
            );
            assert!(
                !forged.verify_element_inclusion(&hasher, &element, Location::new(loc), &root),
                "k={k}"
            );
        }
    }

    #[test]
    fn mmb_verifier_rejects_mmr_internal_node_as_element() {
        // With 76 leaves, MMB location 73 is position 140, and its parent 141 is the fifth of six
        // MMB peaks. In the MMR, position 140 is the parent of 136 and 139, and 141 is the second
        // of three peaks. An MMB leaf at position 140 holding the 64-byte element `d136 || d139`
        // therefore has the digest of MMR node 140. The MMR never contained that element because
        // every inserted element is eight bytes.
        let hasher = H::new(ForwardFold);
        let mmr = build_raw::<mmr::Family>(&hasher, 76);
        let root = mmr.root(&hasher, 0).unwrap();
        let digest = |pos| mmr.get_node(Position::new(pos)).unwrap();
        let mut element = digest(136).as_ref().to_vec();
        element.extend_from_slice(digest(139).as_ref());

        // A forward MMB proof of location 73 holds the folded prefix of the first four MMB peaks,
        // the sixth peak, and the sibling of position 140. MMR peaks 126 and 148 and MMR node 133,
        // the other child of 141, fill those slots.
        let forged = Proof::<mmb::Family, D> {
            leaves: Location::new(76),
            inactive_peaks: 0,
            digests: vec![digest(126), digest(148), digest(133)],
        };

        // The forged proof reconstructs the root that the MMB hasher computes over the MMR's peaks.
        // Only the family tag separates that root from the MMR root, so the forged proof fails
        // against the MMR root.
        let peaks: Vec<D> = mmr
            .peak_iterator()
            .map(|(pos, _)| mmr.get_node(pos).unwrap())
            .collect();
        let mmb_root =
            <H as Hasher<mmb::Family>>::root(&hasher, Location::new(76), 0, peaks.iter()).unwrap();
        assert_eq!(
            forged
                .reconstruct_root(&hasher, &[element.as_slice()], Location::new(73))
                .unwrap(),
            mmb_root
        );
        assert!(!forged.verify_element_inclusion(&hasher, &element, Location::new(73), &root));
    }

    fn empty_proof<F: Family>() {
        // Test that an empty proof authenticates an empty structure.
        let hasher = H::new(ForwardFold);
        let mem = Mem::<F, D>::new();
        let root = plain_root(&mem, &hasher);
        let proof: Proof<F, D> = Proof::default();
        let empty_range: &[D] = &[];
        let empty_multi: &[(D, Location<F>)] = &[];
        assert!(proof.verify_range_inclusion(&hasher, empty_range, Location::new(0), &root));
        assert!(proof.verify_multi_inclusion(&hasher, empty_multi, &root));

        let mut inactive_proof = proof.clone();
        inactive_proof.inactive_peaks = 1;
        assert!(!inactive_proof.verify_range_inclusion(
            &hasher,
            empty_range,
            Location::new(0),
            &root,
        ));
        assert!(!inactive_proof.verify_multi_inclusion(&hasher, empty_multi, &root));
        assert!(matches!(
            inactive_proof.reconstruct_root(&hasher, empty_range, Location::new(0)),
            Err(Error::InvalidProof)
        ));

        // Any starting position other than 0 should fail to verify.
        assert!(!proof.verify_range_inclusion(&hasher, empty_range, Location::new(1), &root));

        // Invalid root should fail to verify.
        let td = test_digest(0);
        assert!(!proof.verify_range_inclusion(&hasher, empty_range, Location::new(0), &td));

        // Non-empty elements list should fail to verify.
        assert!(!proof.verify_range_inclusion(&hasher, &[td], Location::new(0), &root));
    }

    fn verify_element<F: Family>() {
        // Create an 11 element structure and test single-element inclusion proofs.
        let element = D::from(*b"01234567012345670123456701234567");
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();
        let batch = {
            let mut batch = mem.new_batch();
            for _ in 0..11 {
                batch = batch.add(&hasher, &element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
        let root = plain_root(&mem, &hasher);

        // Confirm the proof of inclusion for each leaf verifies.
        for leaf in 0u64..11 {
            let leaf = Location::new(leaf);
            let proof: Proof<F, D> = mem.proof(&hasher, leaf, 0).unwrap();
            assert!(
                proof.verify_element_inclusion(&hasher, &element, leaf, &root),
                "valid proof should verify successfully"
            );
        }

        // Create a valid proof, then confirm various mangling of the proof or proof args results in
        // verification failure.
        let leaf = Location::<F>::new(10);
        let proof = mem.proof(&hasher, leaf, 0).unwrap();
        assert!(
            proof.verify_element_inclusion(&hasher, &element, leaf, &root),
            "proof verification should be successful"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, leaf + 1, &root),
            "proof verification should fail with incorrect element position"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &element, leaf - 1, &root),
            "proof verification should fail with incorrect element position 2"
        );
        assert!(
            !proof.verify_element_inclusion(&hasher, &test_digest(0), leaf, &root),
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
            !proof2.verify_element_inclusion(&hasher, &element, leaf, &root),
            "proof verification should fail with mangled proof hash"
        );
        proof2 = proof.clone();
        proof2.leaves = Location::new(10);
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, leaf, &root),
            "proof verification should fail with incorrect leaves"
        );
        proof2 = proof.clone();
        proof2.digests.push(test_digest(0));
        assert!(
            !proof2.verify_element_inclusion(&hasher, &element, leaf, &root),
            "proof verification should fail with extra hash"
        );
        proof2 = proof.clone();
        while !proof2.digests.is_empty() {
            proof2.digests.pop();
            assert!(
                !proof2.verify_element_inclusion(&hasher, &element, leaf, &root),
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
                !proof2.verify_element_inclusion(&hasher, &element, leaf, &root),
                "proof verification should fail with extra hash even if it's unused by the computation"
            );
        }
    }

    fn verify_range<F: Family>() {
        // Create a structure and add 49 elements.
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();
        let elements: Vec<_> = (0..49).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
        let root = plain_root(&mem, &hasher);

        // Test range proofs over all possible ranges of at least 2 elements.
        for i in 0..elements.len() {
            for j in i + 1..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mem.range_proof(&hasher, range.clone(), 0).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &hasher,
                        &elements[range.to_usize_range()],
                        range.start,
                        &root
                    ),
                    "valid range proof should verify successfully {i}:{j}",
                );
            }
        }

        // Create a proof over a range, confirm it verifies, then mangle it in various ways.
        let range = Location::new(33)..Location::new(40);
        let range_proof = mem.range_proof(&hasher, range.clone(), 0).unwrap();
        let valid_elements = &elements[range.to_usize_range()];
        assert!(
            range_proof.verify_range_inclusion(&hasher, valid_elements, range.start, &root),
            "valid range proof should verify successfully"
        );
        let mut invalid_proof = range_proof.clone();
        invalid_proof.inactive_peaks = 1;
        assert!(
            !invalid_proof.verify_range_inclusion(&hasher, valid_elements, range.start, &root),
            "plain range proof with inactive peaks must fail verification"
        );
        // Remove digests from the proof until it's empty.
        let mut invalid_proof = range_proof.clone();
        for _i in 0..range_proof.digests.len() {
            invalid_proof.digests.remove(0);
            assert!(
                !invalid_proof.verify_range_inclusion(&hasher, valid_elements, range.start, &root),
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
                        &root
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
                &invalid_root
            ),
            "range proof with invalid root should fail"
        );
        // Mangle each element of the proof and confirm it fails to verify.
        for i in 0..range_proof.digests.len() {
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests[i] = test_digest(0);
            assert!(
                !invalid_proof.verify_range_inclusion(&hasher, valid_elements, range.start, &root),
                "mangled range proof should fail verification"
            );
        }
        // Inserting elements into the proof should also cause it to fail (malleability check)
        for i in 0..range_proof.digests.len() {
            let mut invalid_proof = range_proof.clone();
            invalid_proof.digests.insert(i, test_digest(0));
            assert!(
                !invalid_proof.verify_range_inclusion(&hasher, valid_elements, range.start, &root),
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
                !range_proof.verify_range_inclusion(&hasher, valid_elements, loc, &root),
                "bad start_loc should fail verification {loc}",
            );
        }
    }

    fn retained_nodes_provable_after_pruning<F: Family>() {
        // Create a structure and add 49 elements.
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();
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
        let root = plain_root(&mem, &hasher);
        for prune_leaf in 1..*mem.leaves() {
            let prune_loc = Location::new(prune_leaf);
            mem.prune(prune_loc).unwrap();
            let pruned_root = plain_root(&mem, &hasher);
            assert_eq!(root, pruned_root);
            for loc in 0..elements.len() {
                let loc = Location::new(loc as u64);
                let proof = mem.proof(&hasher, loc, 0);
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
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();
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
        let root = plain_root(&mem, &hasher);
        for i in 0..elements.len() - 1 {
            if Location::<F>::new(i as u64) < prune_loc {
                continue;
            }
            for j in (i + 2)..elements.len() {
                let range = Location::new(i as u64)..Location::new(j as u64);
                let range_proof = mem.range_proof(&hasher, range.clone(), 0).unwrap();
                assert!(
                    range_proof.verify_range_inclusion(
                        &hasher,
                        &elements[range.to_usize_range()],
                        range.start,
                        &root
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

        let updated_root = plain_root(&mem, &hasher);
        let range = Location::new(elements.len() as u64 - 10)..Location::new(elements.len() as u64);
        let range_proof = mem.range_proof(&hasher, range.clone(), 0).unwrap();
        assert!(
            range_proof.verify_range_inclusion(
                &hasher,
                &elements[range.to_usize_range()],
                range.start,
                &updated_root
            ),
            "valid range proof over remaining elements after 2 pruning rounds should verify",
        );
    }

    fn proof_serialization<F: Family>() {
        // Create a structure and add 25 elements.
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();
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
                let proof = mem.range_proof(&hasher, range, 0).unwrap();

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
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();
        let elements: Vec<_> = (0..20).map(test_digest).collect();
        let batch = {
            let mut batch = mem.new_batch();
            for element in &elements {
                batch = batch.add(&hasher, element);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        let root = plain_root(&mem, &hasher);

        // Generate proof for non-contiguous single elements.
        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes_for_multi_proof =
            multi_proof_positions(mem.leaves(), locations).expect("test locations valid");
        let digests = nodes_for_multi_proof
            .into_iter()
            .map(|pos| mem.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mem.leaves(),
            inactive_peaks: 0,
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
            &root
        ));

        // Elements in descending location order fail.
        assert!(!multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[10], Location::new(10)),
                (elements[5], Location::new(5)),
                (elements[0], Location::new(0)),
            ],
            &root
        ));

        let mut invalid_proof = multi_proof.clone();
        invalid_proof.inactive_peaks = 1;
        assert!(!invalid_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            &root
        ));

        // A repeated location fails.
        assert!(!multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            &root
        ));

        // Verify mangling the location to something invalid should fail.
        let mut wrong_size_proof = multi_proof.clone();
        wrong_size_proof.leaves = F::MAX_LEAVES + 2;
        assert!(!wrong_size_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[5], Location::new(5)),
                (elements[10], Location::new(10)),
            ],
            &root
        ));

        // Verify with wrong positions.
        assert!(!multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(1)),
                (elements[5], Location::new(6)),
                (elements[10], Location::new(11)),
            ],
            &root
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
            &root,
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
            &root,
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
        let hasher = H::new(ForwardFold);
        let empty_mem = Mem::<F, D>::new();
        let empty_root = plain_root(&empty_mem, &hasher);
        let empty_proof: Proof<F, D> = Proof::default();
        let empty_multi: &[(D, Location<F>)] = &[];
        assert!(empty_proof.verify_multi_inclusion(&hasher, empty_multi, &empty_root));

        // Malformed empty proof with extra digests must be rejected.
        let malformed_proof: Proof<F, D> = Proof {
            leaves: Location::new(0),
            inactive_peaks: 0,
            digests: vec![test_digest(0)],
        };
        assert!(!malformed_proof.verify_multi_inclusion(&hasher, empty_multi, &empty_root));
    }

    fn multi_proof_deduplication<F: Family>() {
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();
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
        let proof1 = mem.proof(&hasher, Location::new(0), 0).unwrap();
        let proof2 = mem.proof(&hasher, Location::new(1), 0).unwrap();
        let total_digests_separate = proof1.digests.len() + proof2.digests.len();

        // Generate multi-proof for the same positions.
        let locations = &[Location::new(0), Location::new(1)];
        let multi_proof_nodes =
            multi_proof_positions(mem.leaves(), locations).expect("test locations valid");
        let digests = multi_proof_nodes
            .into_iter()
            .map(|pos| mem.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mem.leaves(),
            inactive_peaks: 0,
            digests,
        };

        // The combined proof should have fewer digests due to deduplication.
        assert!(multi_proof.digests.len() < total_digests_separate);

        // Verify it still works.
        let root = plain_root(&mem, &hasher);
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[1], Location::new(1))
            ],
            &root
        ));
    }

    fn proof_leaves_malleability<F: Family>() {
        let hasher = H::new(ForwardFold);
        let mut mem = Mem::<F, D>::new();

        // 252 leaves. Leaf 240 sits in a peak preceded by prefix peaks.
        let elements: Vec<D> = (0..252u16)
            .map(|i| <Sha256 as commonware_cryptography::Hasher>::hash(&[&i.to_be_bytes()]))
            .collect();
        let batch = {
            let mut batch = mem.new_batch();
            for e in &elements {
                batch = batch.add(&hasher, e);
            }
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();
        let root = plain_root(&mem, &hasher);

        let loc = Location::new(240);
        let proof = mem.proof(&hasher, loc, 0).unwrap();
        assert!(proof.verify_element_inclusion(&hasher, &elements[240], loc, &root));

        // Tamper with the leaves field (249 has the same peak layout for leaf 240).
        let mut tampered = proof.clone();
        tampered.leaves = Location::new(249);
        assert_ne!(tampered, proof);
        assert!(
            !tampered.verify_element_inclusion(&hasher, &elements[240], loc, &root),
            "proof with tampered leaves field must not verify"
        );

        let mut tampered = proof.clone();
        tampered.inactive_peaks = 1;
        assert_ne!(tampered, proof);
        assert!(
            !tampered.verify_element_inclusion(&hasher, &elements[240], loc, &root),
            "proof with tampered inactive_peaks must not verify"
        );
    }

    fn blueprint_errors<F: Family>() {
        let leaves = Location::<F>::new(10);

        // Empty range.
        assert!(matches!(
            Blueprint::<F>::new(
                leaves,
                0,
                Bagging::ForwardFold,
                Location::new(3)..Location::new(3)
            ),
            Err(crate::merkle::Error::Empty)
        ));

        // Out of bounds.
        assert!(matches!(
            Blueprint::<F>::new(
                leaves,
                0,
                Bagging::ForwardFold,
                Location::new(0)..Location::new(11)
            ),
            Err(crate::merkle::Error::RangeOutOfBounds(_))
        ));

        // Inactive prefix cannot exceed the number of peaks.
        let peak_count = F::peaks(Position::try_from(leaves).unwrap()).count();
        assert!(matches!(
            Blueprint::<F>::new(
                leaves,
                peak_count + 1,
                Bagging::ForwardFold,
                Location::new(0)..Location::new(1)
            ),
            Err(crate::merkle::Error::InvalidProof)
        ));

        // Empty locations for multi-proof.
        assert!(matches!(
            multi_proof_positions::<F>(leaves, &[]),
            Err(crate::merkle::Error::Empty)
        ));
    }

    fn single_element_proof_reconstruction<F: Family>() {
        for n in 1u64..=64 {
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

            for loc_idx in 0..n {
                let proof = mem
                    .proof(&hasher, Location::new(loc_idx), 0)
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
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

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
                    .range_proof(&hasher, Location::new(start)..Location::new(end), 0)
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
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

            for loc_idx in 0..n {
                let proof = mem.proof(&hasher, Location::new(loc_idx), 0).unwrap();
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
                        &root
                    ),
                    "n={n}, loc={loc_idx}: wrong element should not verify"
                );
            }
        }
    }

    fn full_range<F: Family>() {
        for n in 1u64..=32 {
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

            let proof = mem
                .range_proof(&hasher, Location::new(0)..Location::new(n), 0)
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
        let hasher = H::new(ForwardFold);
        let mem = Mem::<F, D>::new();
        let root = plain_root(&mem, &hasher);
        let proof = Proof::<F, D>::default();

        // Empty proof should verify against the empty root.
        assert!(proof.verify_range_inclusion(&hasher, &[] as &[&[u8]], Location::new(0), &root));

        let mut inactive_proof = proof.clone();
        inactive_proof.inactive_peaks = 1;
        assert!(!inactive_proof.verify_range_inclusion(
            &hasher,
            &[] as &[&[u8]],
            Location::new(0),
            &root
        ));
        assert!(!inactive_proof.verify_multi_inclusion(
            &hasher,
            &[] as &[(&[u8], Location<F>)],
            &root
        ));

        // Non-zero start_loc with empty elements should fail.
        assert!(!proof.verify_range_inclusion(&hasher, &[] as &[&[u8]], Location::new(1), &root));
    }

    fn every_element_contributes_to_root<F: Family>() {
        for n in [8u64, 13, 20, 32] {
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

            let start = 1;
            let end = n - 1;
            let proof = mem
                .range_proof(&hasher, Location::new(start)..Location::new(end), 0)
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
                    !proof.verify_range_inclusion(&hasher, &tampered, Location::new(start), &root),
                    "n={n}: tampered element at index {flip_idx} should not verify"
                );
            }
        }
    }

    fn multi_proof_generation_and_verify_raw<F: Family>() {
        let hasher = H::new(ForwardFold);
        let mem = build_raw::<F>(&hasher, 20);
        let root = plain_root(&mem, &hasher);

        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes = multi_proof_positions(mem.leaves(), locations).expect("valid locations");
        let digests = nodes
            .into_iter()
            .map(|pos| mem.get_node(pos).unwrap())
            .collect();
        let multi_proof = Proof {
            leaves: mem.leaves(),
            inactive_peaks: 0,
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

        // Elements in descending location order fail.
        assert!(!multi_proof.verify_multi_inclusion(
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
        let hasher2 = H::new(ForwardFold);
        let empty_mem = Mem::<F, D>::new();
        let empty_proof: Proof<F, D> = Proof::default();
        assert!(empty_proof.verify_multi_inclusion(
            &hasher2,
            &[] as &[([u8; 8], Location<F>)],
            &plain_root(&empty_mem, &hasher2)
        ));

        // Malformed empty proof with extra digests must be rejected.
        let malformed_proof: Proof<F, D> = Proof {
            leaves: Location::new(0),
            inactive_peaks: 0,
            digests: vec![test_digest(0)],
        };
        assert!(!malformed_proof.verify_multi_inclusion(
            &hasher2,
            &[] as &[([u8; 8], Location<F>)],
            &plain_root(&empty_mem, &hasher2)
        ));
    }

    fn tampered_proof_digests_rejected<F: Family>() {
        for n in [8u64, 13, 20, 32] {
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

            for loc_idx in [0, n / 2, n - 1] {
                let proof = mem.proof(&hasher, Location::new(loc_idx), 0).unwrap();
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
        for n in 1u64..=64 {
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let leaves = mem.leaves();
            for loc in 0..n {
                let loc = Location::new(loc);
                let positions = ElementPlan::new(leaves, loc).unwrap().positions();
                let set: BTreeSet<_> = positions.iter().copied().collect();
                assert_eq!(
                    positions.len(),
                    set.len(),
                    "n={n}, loc={loc}: duplicate positions"
                );
            }
        }
    }

    fn full_peak_range_blueprint_does_not_descend<F: Family>() {
        let leaves = Location::new(1u64 << 40);
        let range = Location::new(0)..leaves;

        let bp = Blueprint::<F>::new(leaves, 0, Bagging::ForwardFold, range).unwrap();

        assert!(
            bp.range_peaks.iter().any(|peak| peak.height >= 39),
            "test must include a large fully covered peak"
        );
        assert!(
            bp.siblings.is_empty(),
            "full-range proofs should not fetch per-peak siblings"
        );
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

        let hasher = H::new(ForwardFold);
        for &(n, start) in cases {
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

            let pinned: Vec<D> = F::nodes_to_pin(Location::<F>::new(start))
                .map(|pos| mem.get_node(pos).unwrap())
                .collect();

            let proof = mem
                .range_proof(
                    &hasher,
                    Location::<F>::new(start)..Location::<F>::new(start + 1),
                    0,
                )
                .unwrap();

            assert!(
                proof.verify_proof_and_pinned_nodes(
                    &hasher,
                    &[start.to_be_bytes()],
                    Location::<F>::new(start),
                    &pinned,
                    &root
                ),
                "verify_proof_and_pinned_nodes failed: leaves={n}, start={start}"
            );
        }
    }

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
    fn mmr_range_proofs_verify_for_supported_root_shapes() {
        range_proofs_verify_for_supported_root_shapes::<mmr::Family>();
    }
    #[test]
    fn mmr_multi_proofs_verify_for_supported_root_shapes() {
        multi_proofs_verify_for_supported_root_shapes::<mmr::Family>();
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
    fn mmr_full_peak_range_blueprint_does_not_descend() {
        full_peak_range_blueprint_does_not_descend::<mmr::Family>();
    }
    #[test]
    fn mmr_verify_proof_and_pinned_nodes_across_sizes() {
        verify_proof_and_pinned_nodes_across_sizes::<mmr::Family>();
    }

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
    fn mmb_range_proofs_verify_for_supported_root_shapes() {
        range_proofs_verify_for_supported_root_shapes::<mmb::Family>();
    }
    #[test]
    fn mmb_multi_proofs_verify_for_supported_root_shapes() {
        multi_proofs_verify_for_supported_root_shapes::<mmb::Family>();
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
    fn mmb_backward_fold_range_proof_collapses_active_suffix() {
        backward_fold_proof_optimization_inner(0);
    }
    #[test]
    fn mmb_backward_fold_range_proof_keeps_inactive_after_peaks_individual() {
        backward_fold_proof_optimization_inner(2);
    }
    #[test]
    fn mmb_no_duplicate_positions() {
        no_duplicate_positions::<mmb::Family>();
    }
    #[test]
    fn mmb_full_peak_range_blueprint_does_not_descend() {
        full_peak_range_blueprint_does_not_descend::<mmb::Family>();
    }
    #[test]
    fn mmb_verify_proof_and_pinned_nodes_across_sizes() {
        verify_proof_and_pinned_nodes_across_sizes::<mmb::Family>();
    }
}
