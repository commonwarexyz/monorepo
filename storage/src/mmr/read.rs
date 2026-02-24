//! Read-only trait for merkleized MMRs.
//!
//! [`MmrRead`] provides a synchronous, `no_std`-compatible interface for
//! reading from any merkleized MMR. It is implemented by [`super::mem::CleanMmr`]
//! (base) and [`super::diff::CleanDiff`] (diff layer).
//!
//! [`ChainInfo`] is a `pub(crate)` trait used internally by changeset
//! flattening to traverse stacked diff chains.

use crate::mmr::{iterator::PeakIterator, proof, Error, Location, Position, Proof};
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Read-only interface for a merkleized MMR.
///
/// Generic code uses `P: MmrRead<D>` for static dispatch.
pub trait MmrRead<D: Digest>: Send + Sync {
    /// Total number of nodes (retained + pruned).
    fn size(&self) -> Position;

    /// Digest of the node at `pos`, or `None` if pruned / out of bounds.
    fn get_node(&self, pos: Position) -> Option<D>;

    /// Root digest of the MMR.
    fn root(&self) -> &D;

    /// Pruning boundary (highest pruned position, or 0).
    fn pruned_to_pos(&self) -> Position;

    // --- Derived defaults ---

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

    /// Position of the last leaf, or `None` if empty.
    fn last_leaf_pos(&self) -> Option<Position> {
        if self.size() == 0 {
            return None;
        }
        Some(PeakIterator::last_leaf_pos(self.size()))
    }

    /// Inclusion proof for the element at `loc`.
    fn proof(&self, loc: Location) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(loc) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    /// Inclusion proof for all elements in `range`.
    fn range_proof(&self, range: Range<Location>) -> Result<Proof<D>, Error> {
        let leaves = self.leaves();
        let positions = proof::nodes_required_for_range_proof(leaves, range)?;
        let digests = positions
            .into_iter()
            .map(|pos| self.get_node(pos).ok_or(Error::ElementPruned(pos)))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Proof { leaves, digests })
    }
}

/// Trait for traversing stacked diff chains during changeset flattening.
///
/// `into_changeset` must produce a changeset relative to the ultimate base
/// MMR, not just the immediate parent. These methods let `CleanDiff` recurse
/// through the parent chain to collect the necessary information.
///
/// `CleanMmr` implements the trivial base-case (size = self, no overwrites).
/// `CleanDiff` overrides to recurse through parents.
pub trait ChainInfo<D: Digest> {
    /// Size of the ultimate base MMR in this diff chain.
    fn base_size(&self) -> Position;

    /// Base nodes still visible after all pops in the chain.
    fn base_visible(&self) -> Position;

    /// Accumulate overwrites at positions < `base_size()` from the chain.
    fn collect_chain_overwrites(&self, into: &mut BTreeMap<Position, D>);
}
