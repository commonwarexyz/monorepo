//! Defines the generic inclusion [Proof] structure for Merkle-family data structures.
//!
//! The [Proof] struct is parameterized by a [`Family`] marker and a [`Digest`] type. Each Merkle
//! family (MMR, MMB, etc.) reuses the shared verification and reconstruction logic in this module,
//! while retaining any family-specific proof helpers in its submodule.

use crate::merkle::{hasher::Hasher, Family, Location, Position};
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

    /// Return true if this proof proves that the elements at the specified locations are
    /// included in the structure with root digest `root`. A malformed proof will return false.
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
            let Ok(bp) = Blueprint::new(self.leaves, *loc..*loc + 1) else {
                return false;
            };
            node_positions.extend(&bp.fold_prefix);
            node_positions.extend(&bp.fetch_nodes);
            blueprints.insert(*loc, bp);
        }

        if node_positions.len() != self.digests.len() {
            return false;
        }

        let node_digests: BTreeMap<Position<F>, D> = node_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, digest)| (pos, *digest))
            .collect();

        for (element, loc) in elements {
            let bp = &blueprints[loc];

            let mut digests = Vec::with_capacity(
                if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len(),
            );
            if let Some((&first_pos, rest)) = bp.fold_prefix.split_first() {
                let first = *node_digests
                    .get(&first_pos)
                    .expect("must exist by construction");
                let acc = rest.iter().fold(first, |acc, &pos| {
                    let d = node_digests.get(&pos).expect("must exist by construction");
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

    /// Like [`reconstruct_root`](Self::reconstruct_root), but if `collected` is `Some`,
    /// every `(position, digest)` pair encountered during reconstruction is appended.
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
        if !start_loc.is_valid() {
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

        // Slice self.digests: [folded_prefix? | after_peaks... | siblings...]
        let prefix_digests = usize::from(!bp.fold_prefix.is_empty());
        let expected_min = prefix_digests + bp.fetch_nodes.len();
        if self.digests.len() < expected_min {
            return Err(ReconstructionError::MissingDigests);
        }

        let after_start = prefix_digests;
        // Blueprint's fetch_nodes contains after_peaks then the DFS sibling digests
        // We need to know how many after_peaks there are to skip over them
        let after_peaks_count = bp.after_peaks.len();
        let after_end = after_start + after_peaks_count;
        let siblings = &self.digests[after_end..];

        let mut acc: Option<D> = if prefix_digests == 1 {
            Some(self.digests[0])
        } else {
            None
        };

        let mut sibling_cursor = 0usize;
        let mut elements_iter = elements.iter();
        for peak in &bp.range_peaks {
            let peak_digest = reconstruct_peak_from_range(
                hasher,
                Subtree {
                    pos: peak.pos,
                    height: peak.height,
                    leaf_start: peak.leaf_start,
                },
                &bp.range,
                &mut elements_iter,
                siblings,
                &mut sibling_cursor,
                collected.as_deref_mut(),
            )?;
            if let Some(ref mut cd) = collected {
                cd.push((peak.pos, peak_digest));
            }
            acc = Some(acc.map_or(peak_digest, |a| hasher.fold(&a, &peak_digest)));
        }

        for (i, &after_peak_pos) in bp.after_peaks.iter().enumerate() {
            let digest = self.digests[after_start + i];
            if let Some(ref mut cd) = collected {
                cd.push((after_peak_pos, digest));
            }
            acc = Some(acc.map_or(digest, |a| hasher.fold(&a, &digest)));
        }

        if elements_iter.next().is_some() {
            return Err(ReconstructionError::ExtraDigests);
        }
        if sibling_cursor != siblings.len() {
            return Err(ReconstructionError::ExtraDigests);
        }

        Ok(if let Some(peaks_acc) = acc {
            hasher.hash([self.leaves.to_be_bytes().as_slice(), peaks_acc.as_ref()])
        } else {
            hasher.digest(&self.leaves.to_be_bytes())
        })
    }
}

/// A perfect binary subtree within a peak, identified by its root position, height,
/// and the first leaf location it covers.
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
}

/// Blueprint for a range proof, separating fold-prefix peaks from nodes that must be fetched.
pub(crate) struct Blueprint<F: Family> {
    /// Total number of leaves in the structure this blueprint was built for.
    leaves: Location<F>,
    /// The location range this blueprint was built for.
    pub range: Range<Location<F>>,
    /// Peak positions that precede the proven range (to be folded into a single accumulator).
    pub fold_prefix: Vec<Position<F>>,
    /// Peak positions entirely after the proven range.
    pub after_peaks: Vec<Position<F>>,
    /// The peaks that overlap the proven range.
    pub range_peaks: Vec<Subtree<F>>,
    /// Node positions to include in the proof: after-peaks followed by DFS siblings.
    pub fetch_nodes: Vec<Position<F>>,
}

impl<F: Family> Blueprint<F> {
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
                fold_prefix.push(peak_pos);
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
            collect_siblings_dfs(
                Subtree {
                    pos: peak.pos,
                    height: peak.height,
                    leaf_start: peak.leaf_start,
                },
                &range,
                &mut fetch_nodes,
            );
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

    /// Build a range proof from this blueprint and a node-fetching closure.
    ///
    /// The prover folds prefix peak digests into a single accumulator. The resulting proof
    /// contains: `[fold_acc? | after_peaks... | siblings_dfs...]`.
    ///
    /// Returns an error via `element_pruned` if `get_node` returns `None` for any required
    /// position.
    pub(crate) fn build_proof<D, H, E>(
        self,
        hasher: &mut H,
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

        if let Some((&first_pos, rest)) = self.fold_prefix.split_first() {
            let first = get_node(first_pos).ok_or_else(|| element_pruned(first_pos))?;
            let acc = rest.iter().try_fold(first, |acc, &pos| {
                let d = get_node(pos).ok_or_else(|| element_pruned(pos))?;
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
pub(crate) fn nodes_required_for_multi_proof<F: Family>(
    leaves: Location<F>,
    locations: &[Location<F>],
) -> Result<BTreeSet<Position<F>>, super::Error<F>> {
    if locations.is_empty() {
        return Err(super::Error::Empty);
    }
    locations.iter().try_fold(BTreeSet::new(), |mut acc, loc| {
        if !loc.is_valid() {
            return Err(super::Error::LocationOverflow(*loc));
        }
        let bp = Blueprint::new(leaves, *loc..*loc + 1)?;
        acc.extend(bp.fold_prefix);
        acc.extend(bp.fetch_nodes);
        Ok(acc)
    })
}

/// Collect sibling positions needed to reconstruct a peak digest from a range of
/// elements, in left-first DFS order. This mirrors the traversal order of
/// [`reconstruct_peak_from_range`].
///
/// At each node: if the subtree is entirely outside the range, its root position is
/// emitted. If it's a leaf in the range, nothing is emitted. Otherwise, recurse into
/// children via [`Family::children`].
pub(crate) fn collect_siblings_dfs<F: Family>(
    node: Subtree<F>,
    range: &Range<Location<F>>,
    out: &mut Vec<Position<F>>,
) {
    if node.leaf_end() <= range.start || node.leaf_start >= range.end {
        out.push(node.pos);
        return;
    }

    if node.height > 0 {
        let (left, right) = node.children();
        collect_siblings_dfs::<F>(left, range, out);
        collect_siblings_dfs::<F>(right, range, out);
    }
}

/// Reconstruct the digest of a peak subtree from a range of elements and sibling
/// digests, consuming both in left-first DFS order matching [`collect_siblings_dfs`].
///
/// At each node:
/// - If the subtree is entirely outside the range: consume a sibling digest.
/// - If it's a leaf in the range: hash the next element.
/// - Otherwise: recurse into children via [`Family::children`] and compute the node
///   digest.
///
/// If `collected` is `Some`, every child `(position, digest)` pair encountered during
/// reconstruction is appended to the vector.
pub(crate) fn reconstruct_peak_from_range<F, D, H, E>(
    hasher: &H,
    node: Subtree<F>,
    range: &Range<Location<F>>,
    elements: &mut E,
    siblings: &[D],
    cursor: &mut usize,
    mut collected: Option<&mut Vec<(Position<F>, D)>>,
) -> Result<D, ReconstructionError>
where
    F: Family,
    D: Digest,
    H: Hasher<F, Digest = D>,
    E: Iterator<Item: AsRef<[u8]>>,
{
    // Entirely outside the range: consume a sibling digest.
    if node.leaf_end() <= range.start || node.leaf_start >= range.end {
        let Some(digest) = siblings.get(*cursor).copied() else {
            return Err(ReconstructionError::MissingDigests);
        };
        *cursor += 1;
        return Ok(digest);
    }

    // Leaf in range: hash the next element.
    if node.height == 0 {
        let elem = elements
            .next()
            .ok_or(ReconstructionError::MissingElements)?;
        return Ok(hasher.leaf_digest(node.pos, elem.as_ref()));
    }

    // Recurse into children.
    let (left, right) = node.children();
    let left_pos = left.pos;
    let right_pos = right.pos;

    let left_d = reconstruct_peak_from_range::<F, D, H, E>(
        hasher,
        left,
        range,
        elements,
        siblings,
        cursor,
        collected.as_deref_mut(),
    )?;
    let right_d = reconstruct_peak_from_range::<F, D, H, E>(
        hasher,
        right,
        range,
        elements,
        siblings,
        cursor,
        collected.as_deref_mut(),
    )?;

    if let Some(ref mut cd) = collected {
        cd.push((left_pos, left_d));
        cd.push((right_pos, right_d));
    }

    Ok(hasher.node_digest(node.pos, &left_d, &right_d))
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
