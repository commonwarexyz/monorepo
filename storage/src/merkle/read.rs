//! Shared read-only trait for merkleized data structures.

use crate::merkle::{hasher::Hasher, proof::Proof, Family, Location, Position};
use alloc::sync::Arc;
use commonware_cryptography::Digest;
use core::ops::Range;

/// Read-only interface for a merkleized data structure.
pub trait Readable: Send + Sync {
    /// The Merkle family implemented by this structure.
    type Family: Family;

    /// The digest type used by this structure.
    type Digest: Digest;

    /// The error type returned by proof construction.
    type Error;

    /// Total number of nodes (retained + pruned).
    fn size(&self) -> Position<Self::Family>;

    /// Digest of the node at `pos`, or `None` if pruned / out of bounds.
    fn get_node(&self, pos: Position<Self::Family>) -> Option<Self::Digest>;

    /// Leaf location up to which pruning has been performed, or 0 if never pruned.
    fn pruning_boundary(&self) -> Location<Self::Family>;

    /// Inclusion proof for the element at `loc`.
    fn proof(
        &self,
        hasher: &impl Hasher<Self::Family, Digest = Self::Digest>,
        loc: Location<Self::Family>,
    ) -> Result<Proof<Self::Family, Self::Digest>, Self::Error>;

    /// Inclusion proof for all elements in `range`.
    fn range_proof(
        &self,
        hasher: &impl Hasher<Self::Family, Digest = Self::Digest>,
        range: Range<Location<Self::Family>>,
    ) -> Result<Proof<Self::Family, Self::Digest>, Self::Error>;

    /// Total number of leaves.
    fn leaves(&self) -> Location<Self::Family> {
        Location::try_from(self.size()).expect("invalid merkle size")
    }

    /// `[start, end)` range of retained leaf locations.
    fn bounds(&self) -> Range<Location<Self::Family>> {
        self.pruning_boundary()..self.leaves()
    }
}

impl<T: Readable> Readable for Arc<T> {
    type Family = T::Family;
    type Digest = T::Digest;
    type Error = T::Error;

    fn size(&self) -> Position<Self::Family> {
        (**self).size()
    }

    fn get_node(&self, pos: Position<Self::Family>) -> Option<Self::Digest> {
        (**self).get_node(pos)
    }

    fn pruning_boundary(&self) -> Location<Self::Family> {
        (**self).pruning_boundary()
    }

    fn proof(
        &self,
        hasher: &impl Hasher<Self::Family, Digest = Self::Digest>,
        loc: Location<Self::Family>,
    ) -> Result<Proof<Self::Family, Self::Digest>, Self::Error> {
        (**self).proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &impl Hasher<Self::Family, Digest = Self::Digest>,
        range: Range<Location<Self::Family>>,
    ) -> Result<Proof<Self::Family, Self::Digest>, Self::Error> {
        (**self).range_proof(hasher, range)
    }
}
