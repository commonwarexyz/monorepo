//! Defines the generic inclusion [Proof] structure for Merkle-family data structures.
//!
//! The [Proof] struct is parameterized by a [`Family`] marker and a [`Digest`] type. Each Merkle
//! family (MMR, MMB, etc.) reuses the shared verification and reconstruction logic in this module,
//! while retaining any family-specific proof helpers in its submodule.

use crate::merkle::{hasher::Hasher, Bagging, Error, Family, Location, Position};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Errors that can occur when reconstructing a digest from a proof due to invalid input.
#[derive(thiserror::Error, Debug)]
pub enum ReconstructionError {
    #[error("invalid proof")]
    InvalidProof,
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
/// Multi-proofs use a different, position-keyed layout: `digests` contains the sorted set of node
/// digests required by the requested `inactive_peaks` and bagging policy. For `BackwardFold`, this
/// may include active suffix peaks that a single range proof could collapse into a synthetic suffix
/// accumulator.
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
        match self.reconstruct_root_inner(hasher, elements, start_loc, None) {
            Ok(reconstructed_root) => *root == reconstructed_root,
            Err(_error) => {
                #[cfg(feature = "std")]
                tracing::debug!(error = ?_error, "invalid proof input");
                false
            }
        }
    }

    /// Returns true if this proof's `inactive_peaks` field matches the canonical value derived
    /// from `size` and `inactivity_floor`.
    pub fn matches_canonical_inactive_peaks(
        &self,
        size: Position<F>,
        inactivity_floor: Location<F>,
    ) -> bool {
        self.inactive_peaks == F::inactive_peaks(size, inactivity_floor)
    }

    /// Verify a position-keyed multi-proof using the bagging carried by `hasher`.
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
        let bagging = hasher.root_bagging();
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

        // Collect all required positions with deduplication, and blueprints per element.
        let mut node_positions = BTreeSet::new();
        let mut blueprints = BTreeMap::new();

        for (_, loc) in elements {
            if !loc.is_valid_index() {
                return false;
            }
            // `loc` is valid so it won't overflow from +1
            let Ok(bp) = Blueprint::new(self.leaves, self.inactive_peaks, bagging, *loc..*loc + 1)
            else {
                return false;
            };
            node_positions.extend(bp.fold_prefix.iter().map(|s| s.pos));
            node_positions.extend(&bp.fetch_nodes);
            if let Some(suffix_peaks) = bp.suffix_peaks() {
                node_positions.extend(suffix_peaks);
            }
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

            let suffix_count = usize::from(bp.suffix_peaks().is_some());
            let mut digests = Vec::with_capacity(
                if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len() + suffix_count,
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
            let prefix_active_count = bp.prefix_active_count();
            let after_count = bp.after_peaks_count();
            for &pos in &bp.fetch_nodes[..prefix_active_count + after_count] {
                let d = node_digests.get(&pos).expect("must exist by construction");
                digests.push(*d);
            }
            if let Some(suffix_peaks) = bp.suffix_peaks() {
                let (last_pos, rest_pos) = suffix_peaks
                    .split_last()
                    .expect("suffix_peaks is non-empty when returned");
                let mut acc = *node_digests
                    .get(last_pos)
                    .expect("must exist by construction");
                for pos in rest_pos.iter().rev() {
                    let d = node_digests.get(pos).expect("must exist by construction");
                    acc = hasher.fold(d, &acc);
                }
                digests.push(acc);
            }
            for &pos in &bp.fetch_nodes[prefix_active_count + after_count..] {
                let d = node_digests.get(&pos).expect("must exist by construction");
                digests.push(*d);
            }
            let proof = Self {
                leaves: self.leaves,
                inactive_peaks: self.inactive_peaks,
                digests,
            };

            match proof.reconstruct_root_inner(hasher, &[element.as_ref()], *loc, None) {
                Ok(reconstructed_root) if &reconstructed_root == root => {}
                Ok(_) | Err(_) => return false,
            }
        }

        true
    }

    /// Reconstruct the root digest from this proof and the given consecutive elements using
    /// the bagging carried by `hasher`, or return a `ReconstructionError` if the input data is
    /// invalid.
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
        let Ok(reconstructed_root) =
            self.reconstruct_root_inner(hasher, elements, start_loc, Some(&mut collected_digests))
        else {
            return Err(Error::InvalidProof);
        };

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

        let pinned_positions: Vec<_> = F::nodes_to_pin(start_loc).collect();
        if pinned_positions.len() != pinned_nodes.len() {
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
    ) -> Result<D, ReconstructionError>
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        let bagging = hasher.root_bagging();
        let mut collected = collected;
        if elements.is_empty() {
            if start_loc == 0 {
                if self.inactive_peaks != 0 {
                    return Err(ReconstructionError::InvalidProof);
                }
                if self.leaves != Location::new(0) {
                    return Err(ReconstructionError::MissingElements);
                }
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

        let bp = Blueprint::new(self.leaves, self.inactive_peaks, bagging, range)
            .map_err(|_| ReconstructionError::InvalidSize)?;

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
            return Err(ReconstructionError::ExtraDigests);
        }

        // Verify all siblings were consumed.
        if sibling_cursor != proof_digests.siblings.len() {
            return Err(ReconstructionError::ExtraDigests);
        }

        hasher
            .root_with_folded_peaks(
                self.leaves,
                bp.inactive_peaks_after_prefix_fold(self.inactive_peaks),
                self.inactive_peaks,
                peak_digests.iter(),
            )
            .ok_or(ReconstructionError::InvalidProof)
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

/// Return the peaks of a tree of `leaves` that overlap `range`, validating both the range and the
/// declared `inactive_peaks` boundary.
///
/// The returned subtrees are bagging-independent: `Blueprint::new`'s prefix/suffix accumulator
/// layout depends on bagging, but the per-peak partition of the proven range does not.
///
/// Blueprint for a range proof, separating fold-prefix peaks from nodes that must be fetched.
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
    /// Node positions to include in the proof: after-peaks followed by DFS siblings.
    pub(crate) fetch_nodes: Vec<Position<F>>,
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
    ///
    /// Forward bagging folds peaks before the range into one prefix accumulator. Backward bagging
    /// also collapses active peaks after the range into one suffix accumulator while leaving inactive
    /// after-peaks position-keyed.
    pub(crate) fn new(
        leaves: Location<F>,
        inactive_peaks: usize,
        bagging: Bagging,
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
        let mut prefix_active_peaks = Vec::new();
        let mut after_peaks = Vec::new();
        let mut suffix_peaks = Vec::new();
        let mut range_peaks = Vec::new();
        let mut leaf_cursor = Location::new(0);

        let mut peak_index = 0;
        for (peak_pos, height) in F::peaks(size) {
            let leaf_start = leaf_cursor;
            let leaf_end = leaf_start + (1u64 << height);

            if leaf_end <= range.start {
                if peak_index < inactive_peaks || bagging == Bagging::ForwardFold {
                    fold_prefix.push(Subtree {
                        pos: peak_pos,
                        height,
                        leaf_start,
                    });
                } else {
                    prefix_active_peaks.push(Subtree {
                        pos: peak_pos,
                        height,
                        leaf_start,
                    });
                }
            } else if leaf_start >= range.end {
                if bagging == Bagging::BackwardFold && peak_index >= inactive_peaks {
                    suffix_peaks.push(peak_pos);
                } else {
                    after_peaks.push(peak_pos);
                }
            } else {
                range_peaks.push(Subtree {
                    pos: peak_pos,
                    height,
                    leaf_start,
                });
            }
            leaf_cursor = leaf_end;
            peak_index += 1;
        }
        // `inactive_peaks` is a global boundary over the tree's peaks, not just the peaks before
        // this range. It may point into or beyond the proven range; reconstruction then folds the
        // same global boundary and the final root comparison rejects non-canonical proofs.
        if inactive_peaks > peak_index {
            return Err(super::Error::InvalidProof);
        }

        assert!(
            !range_peaks.is_empty(),
            "at least one peak must contain range elements"
        );

        let mut fetch_nodes: Vec<_> = prefix_active_peaks.iter().map(|s| s.pos).collect();
        fetch_nodes.extend_from_slice(&after_peaks);
        for peak in &range_peaks {
            peak.collect_siblings(&range, &mut fetch_nodes);
        }

        Ok(Self {
            leaves,
            range,
            fold_prefix,
            prefix_active_peaks,
            after_peaks,
            suffix_peaks,
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

    /// Return the number of active prefix peak digests stored before after-peak digests.
    pub(crate) const fn prefix_active_count(&self) -> usize {
        self.prefix_active_peaks.len()
    }

    /// Return the number of non-collapsed after-peak digests in the proof layout.
    pub(crate) const fn after_peaks_count(&self) -> usize {
        self.after_peaks.len()
    }

    /// Return active after-peaks that are collapsed into a backward-folded suffix accumulator.
    pub(crate) fn suffix_peaks(&self) -> Option<&[Position<F>]> {
        (!self.suffix_peaks.is_empty()).then_some(&self.suffix_peaks)
    }

    /// Split a proof's digest vector according to this blueprint's range-proof layout.
    pub(crate) fn split_proof_digests<'a, D>(
        &self,
        digests: &'a [D],
    ) -> Result<ProofDigestLayout<'a, D>, ReconstructionError> {
        let fold_count = usize::from(!self.fold_prefix.is_empty());
        let suffix_count = usize::from(!self.suffix_peaks.is_empty());
        let required = fold_count + self.fetch_nodes.len() + suffix_count;
        if digests.len() < required {
            return Err(ReconstructionError::MissingDigests);
        }
        if digests.len() > required {
            return Err(ReconstructionError::ExtraDigests);
        }

        let prefix_start = fold_count;
        let after_start = prefix_start + self.prefix_active_peaks.len();
        let siblings_start = after_start + self.after_peaks.len();
        let suffix_start = siblings_start;
        let suffix_end = suffix_start + suffix_count;

        Ok(ProofDigestLayout {
            fold_prefix: (!self.fold_prefix.is_empty()).then(|| &digests[0]),
            prefix_active_peaks: &digests[prefix_start..after_start],
            after_peaks: &digests[after_start..siblings_start],
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
    /// Returns an error via `element_pruned` if `get_node` returns `None` for any required
    /// position.
    pub(crate) fn build_proof<D, H, E>(
        self,
        hasher: &H,
        inactive_peaks: usize,
        get_node: impl Fn(Position<F>) -> Option<D>,
        element_pruned: impl Fn(Position<F>) -> E,
    ) -> Result<Proof<F, D>, E>
    where
        D: Digest,
        H: Hasher<F, Digest = D>,
    {
        let mut digests = Vec::with_capacity(
            if self.fold_prefix.is_empty() { 0 } else { 1 }
                + self.fetch_nodes.len()
                + usize::from(!self.suffix_peaks.is_empty()),
        );

        if let Some((first_sub, rest)) = self.fold_prefix.split_first() {
            let first = get_node(first_sub.pos).ok_or_else(|| element_pruned(first_sub.pos))?;
            let acc = rest.iter().try_fold(first, |acc, sub| {
                let d = get_node(sub.pos).ok_or_else(|| element_pruned(sub.pos))?;
                Ok(hasher.fold(&acc, &d))
            })?;
            digests.push(acc);
        }

        for sub in &self.prefix_active_peaks {
            digests.push(get_node(sub.pos).ok_or_else(|| element_pruned(sub.pos))?);
        }
        for &pos in &self.after_peaks {
            digests.push(get_node(pos).ok_or_else(|| element_pruned(pos))?);
        }
        if let Some((last_pos, rest)) = self.suffix_peaks.split_last() {
            let last = get_node(*last_pos).ok_or_else(|| element_pruned(*last_pos))?;
            let acc = rest.iter().rev().try_fold(last, |acc, &pos| {
                let d = get_node(pos).ok_or_else(|| element_pruned(pos))?;
                Ok(hasher.fold(&d, &acc))
            })?;
            digests.push(acc);
        }

        let sibling_start = self.prefix_active_peaks.len() + self.after_peaks.len();
        for &pos in &self.fetch_nodes[sibling_start..] {
            digests.push(get_node(pos).ok_or_else(|| element_pruned(pos))?);
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

/// Build a range proof from a node-fetching closure. The bagging policy is read from `hasher`.
/// This is the generic implementation shared by all Merkle families. The `element_pruned` closure
/// is called when `get_node` returns `None` for a required position.
pub(crate) fn build_range_proof<F, D, H, E>(
    hasher: &H,
    leaves: Location<F>,
    inactive_peaks: usize,
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
    Blueprint::new(leaves, inactive_peaks, hasher.root_bagging(), range)?.build_proof(
        hasher,
        inactive_peaks,
        get_node,
        element_pruned,
    )
}

/// Returns the positions of the minimal set of nodes whose digests are required to prove the
/// inclusion of the elements at the specified `locations`, using the provided root bagging.
#[cfg(any(feature = "std", test))]
pub(crate) fn nodes_required_for_multi_proof<F: Family>(
    leaves: Location<F>,
    inactive_peaks: usize,
    bagging: Bagging,
    locations: &[Location<F>],
) -> Result<BTreeSet<Position<F>>, super::Error<F>> {
    if locations.is_empty() {
        return Err(super::Error::Empty);
    }
    locations.iter().try_fold(BTreeSet::new(), |mut acc, loc| {
        if !loc.is_valid_index() {
            return Err(super::Error::LocationOverflow(*loc));
        }
        let bp = Blueprint::new(leaves, inactive_peaks, bagging, *loc..*loc + 1)?;
        if let Some(suffix_peaks) = bp.suffix_peaks() {
            acc.extend(suffix_peaks);
        }
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
            inactive_peaks: u.arbitrary()?,
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
        Bagging::{BackwardFold, ForwardFold},
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
        Location::new(*leaves - width)
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
            let proof: Proof<F, D> = build_range_proof(
                &hasher,
                leaves,
                inactive_peaks,
                range.clone(),
                |pos| mem.get_node(pos),
                Error::ElementPruned,
            )
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
            let nodes = nodes_required_for_multi_proof(leaves, inactive_peaks, bagging, &locations)
                .expect("test locations valid");
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
            + optimized.fetch_nodes.len()
            + suffix_len;
        let suffix_idx = usize::from(!optimized.fold_prefix.is_empty())
            + optimized.prefix_active_peaks.len()
            + optimized.after_peaks.len();
        let proof = optimized
            .build_proof(
                &hasher,
                inactive_peaks,
                |pos| mem.get_node(pos),
                Error::ElementPruned,
            )
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

        let generated: Result<Proof<mmb::Family, D>, Error<mmb::Family>> = build_range_proof(
            &hasher,
            mem.leaves(),
            0,
            range.clone(),
            |pos| mem.get_node(pos),
            Error::ElementPruned,
        );
        let generated = generated.unwrap();

        let full_backward_root = mem.root(&hasher, 0).unwrap();
        assert!(generated.verify_range_inclusion(
            &hasher,
            &[range.start.to_be_bytes()],
            range.start,
            &full_backward_root,
        ));

        let locations = &[Location::new(0), Location::new(5), Location::new(10)];
        let nodes =
            nodes_required_for_multi_proof(mem.leaves(), 0, Bagging::BackwardFold, locations)
                .expect("valid locations");
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
        let split_proof: Result<Proof<mmb::Family, D>, Error<mmb::Family>> = build_range_proof(
            &hasher,
            mem.leaves(),
            0,
            range.clone(),
            |pos| mem.get_node(pos),
            Error::ElementPruned,
        );
        let split_proof = split_proof.unwrap();
        assert!(split_proof.verify_range_inclusion(
            &hasher,
            &[range.start.to_be_bytes()],
            range.start,
            &split_root_value,
        ));
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
            Err(ReconstructionError::InvalidProof)
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
            nodes_required_for_multi_proof(mem.leaves(), 0, Bagging::ForwardFold, locations)
                .expect("test locations valid");
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

        // Verify in different order.
        assert!(multi_proof.verify_multi_inclusion(
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

        // Verify with duplicate items.
        assert!(multi_proof.verify_multi_inclusion(
            &hasher,
            &[
                (elements[0], Location::new(0)),
                (elements[0], Location::new(0)),
                (elements[10], Location::new(10)),
                (elements[5], Location::new(5)),
            ],
            &root
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
            nodes_required_for_multi_proof(mem.leaves(), 0, Bagging::ForwardFold, locations)
                .expect("test locations valid");
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
            nodes_required_for_multi_proof::<F>(leaves, 0, Bagging::ForwardFold, &[]),
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
        let nodes =
            nodes_required_for_multi_proof(mem.leaves(), 0, Bagging::ForwardFold, locations)
                .expect("valid locations");
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
        use alloc::collections::BTreeSet;
        for n in 1u64..=64 {
            let hasher = H::new(ForwardFold);
            let mem = build_raw::<F>(&hasher, n);
            let leaves = mem.leaves();
            for loc in 0..n {
                let loc = Location::new(loc);
                let bp =
                    Blueprint::<F>::new(leaves, 0, Bagging::ForwardFold, loc..loc + 1).unwrap();
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

    fn full_peak_range_blueprint_does_not_descend<F: Family>() {
        let leaves = Location::new(1u64 << 40);
        let range = Location::new(0)..leaves;

        let bp = Blueprint::<F>::new(leaves, 0, Bagging::ForwardFold, range).unwrap();

        assert!(
            bp.range_peaks.iter().any(|peak| peak.height >= 39),
            "test must include a large fully covered peak"
        );
        assert!(
            bp.fetch_nodes.is_empty(),
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
