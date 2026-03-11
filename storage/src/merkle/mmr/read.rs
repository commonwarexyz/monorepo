//! Read-only trait for merkleized MMRs.
//!
//! [`Readable`] provides an interface for reading from a merkleized MMR.
//!
//! [`BatchChainInfo`] is used to walk chains of batches.

use crate::mmr::{iterator::PeakIterator, proof, Error, Location, Position, Proof};
use alloc::{collections::BTreeMap, vec::Vec};
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
    fn proof(&self, loc: Location) -> Result<Proof<Self::Digest>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(loc) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    /// Inclusion proof for all elements in `range`.
    fn range_proof(&self, range: Range<Location>) -> Result<Proof<Self::Digest>, Error> {
        let leaves = self.leaves();
        let positions = proof::nodes_required_for_range_proof(leaves, range)?;
        let digests = positions
            .into_iter()
            .map(|pos| self.get_node(pos).ok_or(Error::ElementPruned(pos)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Proof { leaves, digests })
    }
}

/// Information needed to flatten a chain of batches into a single [`super::batch::Changeset`].
pub trait BatchChainInfo: Send + Sync {
    /// The digest type used by this MMR.
    type Digest: Digest;

    /// Number of nodes in the original MMR that the batch chain was forked
    /// from. This is constant through the entire chain.
    fn base_size(&self) -> Position;

    /// Collect all overwrites that target nodes in the original MMR
    /// (i.e. positions < `base_size()`), walking from the deepest
    /// ancestor to the current batch. Later batches overwrite earlier ones.
    fn collect_overwrites(&self, into: &mut BTreeMap<Position, Self::Digest>);
}
