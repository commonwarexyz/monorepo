//! Defines the generic inclusion [Proof] structure for Merkle-family data structures.
//!
//! The [Proof] struct is parameterized by a [`Family`] marker and a [`Digest`] type. Each Merkle
//! family (MMR, MMB, etc.) provides its own verification and construction logic in its submodule.

use crate::merkle::{Family, Location};
use alloc::{vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;

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
