//! Shared read-only trait for merkleized data structures.

use crate::merkle::{Family, Location, Position};
use alloc::sync::Arc;
use commonware_cryptography::Digest;
use core::ops::Range;

/// Read-only interface for a merkleized data structure.
///
/// This trait covers structural reads (size, leaves, retained nodes, pruning boundary). Proof
/// construction is intentionally *not* part of the trait: every concrete implementation exposes
/// inherent `proof` / `range_proof` methods that take an explicit `inactive_peaks` count and read
/// the bagging policy from the supplied [`crate::merkle::hasher::Hasher`], so callers cannot
/// accidentally pair a split-spec root with a forward-fold proof from the same state.
pub trait Readable: Send + Sync {
    /// The Merkle family implemented by this structure.
    type Family: Family;

    /// The digest type used by this structure.
    type Digest: Digest;

    /// The error type returned by structural reads.
    type Error;

    /// Total number of nodes (retained + pruned).
    fn size(&self) -> Position<Self::Family>;

    /// Digest of the node at `pos`, or `None` if pruned / out of bounds.
    fn get_node(&self, pos: Position<Self::Family>) -> Option<Self::Digest>;

    /// Leaf location up to which pruning has been performed, or 0 if never pruned.
    fn pruning_boundary(&self) -> Location<Self::Family>;

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
}
