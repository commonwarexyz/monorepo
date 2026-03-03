//! Shared [Proof] structure for Merkle-family data structures (MMR, MMB).

use super::MerkleFamily;
use alloc::{vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Read, ReadExt, ReadRangeExt, Write};
use commonware_cryptography::Digest;
use thiserror::Error;

use super::Location;

/// The maximum number of digests in a proof per element being proven.
///
/// This accounts for the worst case proof size across all Merkle families. An MMB with 62 peaks
/// requires 62 path siblings + 62 peak digests = 124 digests for the left-most leaf.
pub const MAX_PROOF_DIGESTS_PER_ELEMENT: usize = 124;

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
/// elements, in a Merkle-family data structure from its root digest.
///
/// The `digests` vector contains:
///
/// 1: the digests of each peak corresponding to a mountain containing no elements from the element
/// range being proven in decreasing order of height, followed by:
///
/// 2: the nodes in the remaining mountains necessary for reconstructing their peak digests from the
/// elements within the range, ordered by the position of their parent.
pub struct Proof<F: MerkleFamily, D: Digest> {
    /// The total number of leaves in the data structure. Other authenticated data structures may
    /// override the meaning of this field. For example, the authenticated [crate::AuthenticatedBitMap]
    /// stores the number of bits in the bitmap within this field.
    pub leaves: Location<F>,
    /// The digests necessary for proving the inclusion of an element, or range of elements.
    pub digests: Vec<D>,
}

impl<F: MerkleFamily, D: Digest> PartialEq for Proof<F, D> {
    fn eq(&self, other: &Self) -> bool {
        self.leaves == other.leaves && self.digests == other.digests
    }
}

impl<F: MerkleFamily, D: Digest> Eq for Proof<F, D> {}

impl<F: MerkleFamily, D: Digest> Clone for Proof<F, D> {
    fn clone(&self) -> Self {
        Self {
            leaves: self.leaves,
            digests: self.digests.clone(),
        }
    }
}

impl<F: MerkleFamily, D: Digest> core::fmt::Debug for Proof<F, D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Proof")
            .field("leaves", &self.leaves)
            .field("digests", &self.digests)
            .finish()
    }
}

impl<F: MerkleFamily, D: Digest> Default for Proof<F, D> {
    /// Create an empty proof. The empty proof will verify only against the root digest of an empty
    /// (`leaves == 0`) data structure.
    fn default() -> Self {
        Self {
            leaves: Location::new(0),
            digests: vec![],
        }
    }
}

impl<F: MerkleFamily, D: Digest> EncodeSize for Proof<F, D> {
    fn encode_size(&self) -> usize {
        self.leaves.encode_size() + self.digests.encode_size()
    }
}

impl<F: MerkleFamily, D: Digest> Write for Proof<F, D> {
    fn write(&self, buf: &mut impl BufMut) {
        self.leaves.write(buf);
        self.digests.write(buf);
    }
}

impl<F: MerkleFamily, D: Digest> Read for Proof<F, D> {
    /// The maximum number of items being proven.
    ///
    /// The upper bound on digests is derived as `max_items * MAX_PROOF_DIGESTS_PER_ELEMENT`.
    type Cfg = usize;

    fn read_cfg(
        buf: &mut impl Buf,
        max_items: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let leaves = Location::<F>::read(buf)?;
        let max_digests = max_items.saturating_mul(MAX_PROOF_DIGESTS_PER_ELEMENT);
        let digests = Vec::<D>::read_range(buf, ..=max_digests)?;
        Ok(Self { leaves, digests })
    }
}

#[cfg(feature = "arbitrary")]
impl<F: MerkleFamily, D: Digest> arbitrary::Arbitrary<'_> for Proof<F, D>
where
    D: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let leaves: Location<F> = u.arbitrary()?;
        let digests: Vec<D> = u.arbitrary()?;
        Ok(Self { leaves, digests })
    }
}

