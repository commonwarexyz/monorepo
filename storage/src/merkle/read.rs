//! Shared read-only trait for merkleized data structures.

use crate::merkle::{hasher::Hasher, proof::Proof, Family, Location, Position};
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

    /// Iterator over `(peak_position, height)` for this structure's family.
    type PeakIterator: Iterator<Item = (Position<Self::Family>, u32)>;

    /// Total number of nodes (retained + pruned).
    fn size(&self) -> Position<Self::Family>;

    /// Digest of the node at `pos`, or `None` if pruned / out of bounds.
    fn get_node(&self, pos: Position<Self::Family>) -> Option<Self::Digest>;

    /// Root digest of the structure.
    fn root(&self) -> Self::Digest;

    /// Items before this position have been pruned.
    fn pruned_to_pos(&self) -> Position<Self::Family>;

    /// Iterator over the current peaks.
    fn peak_iterator(&self) -> Self::PeakIterator;

    /// Inclusion proof for the element at `loc`.
    fn proof(
        &self,
        hasher: &mut impl Hasher<Self::Family, Digest = Self::Digest>,
        loc: Location<Self::Family>,
    ) -> Result<Proof<Self::Family, Self::Digest>, Self::Error>;

    /// Inclusion proof for all elements in `range`.
    fn range_proof(
        &self,
        hasher: &mut impl Hasher<Self::Family, Digest = Self::Digest>,
        range: Range<Location<Self::Family>>,
    ) -> Result<Proof<Self::Family, Self::Digest>, Self::Error>;

    /// Total number of leaves.
    fn leaves(&self) -> Location<Self::Family> {
        Location::try_from(self.size()).expect("invalid merkle size")
    }

    /// `[start, end)` range of retained node positions.
    fn bounds(&self) -> Range<Position<Self::Family>> {
        self.pruned_to_pos()..self.size()
    }
}
