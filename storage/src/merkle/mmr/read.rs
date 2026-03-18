//! Read-only trait for merkleized MMRs.
//!
//! [`Readable`] provides an interface for reading from a merkleized MMR.

use crate::mmr::{hasher::Hasher, iterator::PeakIterator, proof, Error, Location, Position, Proof};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Read-only interface for a merkleized MMR.
pub trait Readable: Send + Sync {
    /// The digest type used by this MMR.
    type Digest: Digest;

    /// Total number of nodes (retained + pruned).
    fn size(&self) -> Position;

    /// Digest of the node at `pos`, or `None` if pruned / out of bounds.
    fn get_node(&self, pos: Position) -> Option<Self::Digest>;

    /// Root digest of the MMR.
    fn root(&self) -> Self::Digest;

    /// Items before this position have been pruned.
    fn pruned_to_pos(&self) -> Position;

    /// Total number of leaves.
    fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmr size")
    }

    /// Iterator over (peak_position, height) in decreasing height order.
    fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// [start, end) range of retained node positions.
    fn bounds(&self) -> Range<Position> {
        self.pruned_to_pos()..self.size()
    }

    /// Inclusion proof for the element at `loc`.
    fn proof(
        &self,
        hasher: &impl Hasher<Digest = Self::Digest>,
        loc: Location,
    ) -> Result<Proof<Self::Digest>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(loc) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    /// Inclusion proof for all elements in `range`.
    fn range_proof(
        &self,
        hasher: &impl Hasher<Digest = Self::Digest>,
        range: Range<Location>,
    ) -> Result<Proof<Self::Digest>, Error> {
        let leaves = self.leaves();
        proof::build_range_proof(hasher, leaves, range, |pos| self.get_node(pos))
    }
}
