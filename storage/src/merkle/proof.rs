//! Defines the generic inclusion [Proof] structure for Merkle-family data structures.
//!
//! The [Proof] struct is parameterized by a [`Family`] marker and a [`Digest`] type. Each Merkle
//! family (MMR, MMB, etc.) provides its own verification and construction logic in its submodule.

use crate::merkle::{hasher::Hasher, mem, Family, Location, Position};
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

// --- Shared verification methods ---

impl<F: Family, D: Digest> Proof<F, D> {
    /// Return true if this proof proves that `element` appears at location `loc` within the
    /// structure with root digest `root`.
    pub fn verify_element_inclusion<H>(
        &self,
        hasher: &mut H,
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
    /// location `start_loc` within the structure with root digest `root`.
    pub fn verify_range_inclusion<H, E>(
        &self,
        hasher: &mut H,
        elements: &[E],
        start_loc: Location<F>,
        root: &D,
    ) -> bool
    where
        H: Hasher<F, Digest = D>,
        E: AsRef<[u8]>,
    {
        match F::reconstruct_root(hasher, self.leaves, &self.digests, elements, start_loc) {
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
        hasher: &mut H,
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

        // Collect all required positions with deduplication, and blueprints per element.
        let mut node_positions = BTreeSet::new();
        let mut blueprints = BTreeMap::new();

        for (_, loc) in elements {
            if !loc.is_valid() {
                return false;
            }
            let Ok(bp) = F::proof_blueprint(self.leaves, *loc..*loc + 1) else {
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

        if node_positions.len() != self.digests.len() {
            return false;
        }

        // Build position to digest mapping.
        let node_digests: BTreeMap<Position<F>, D> = node_positions
            .iter()
            .zip(self.digests.iter())
            .map(|(&pos, digest)| (pos, *digest))
            .collect();

        // Verify each element by constructing its sub-proof.
        for (element, loc) in elements {
            let bp = &blueprints[loc];

            let mut digests = Vec::with_capacity(
                if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len(),
            );
            if !bp.fold_prefix.is_empty() {
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
}

// --- Shared proof construction ---

/// Build a range proof from a node-fetching closure.
///
/// Uses `F::proof_blueprint` to determine which nodes are needed, then fetches their digests
/// via `get_node`.
pub(crate) fn build_range_proof<F, D>(
    hasher: &mut impl Hasher<F, Digest = D>,
    leaves: Location<F>,
    range: Range<Location<F>>,
    get_node: impl Fn(Position<F>) -> Option<D>,
) -> Result<Proof<F, D>, mem::Error<F>>
where
    F: Family,
    D: Digest,
{
    let bp = F::proof_blueprint(leaves, range)?;

    let mut digests =
        Vec::with_capacity(if bp.fold_prefix.is_empty() { 0 } else { 1 } + bp.fetch_nodes.len());

    // Fold prefix peaks into a single accumulator.
    if !bp.fold_prefix.is_empty() {
        let mut acc =
            get_node(bp.fold_prefix[0]).ok_or(mem::Error::ElementPruned(bp.fold_prefix[0]))?;
        for &pos in &bp.fold_prefix[1..] {
            let d = get_node(pos).ok_or(mem::Error::ElementPruned(pos))?;
            acc = hasher.fold(&acc, &d);
        }
        digests.push(acc);
    }

    // Append after-peak and sibling digests.
    for &pos in &bp.fetch_nodes {
        digests.push(get_node(pos).ok_or(mem::Error::ElementPruned(pos))?);
    }

    Ok(Proof { leaves, digests })
}
