//! Shared read-only trait for merkleized data structures.

use crate::merkle::{Family, Position};
use alloc::sync::Arc;
use commonware_cryptography::Digest;

/// Read-only interface for a merkleized data structure.
///
/// Synchronous node resolution over whatever this view holds: `get_node` serves only what it
/// can resolve without I/O and reports everything else as absent. Proof construction stays on
/// concrete types because it depends on caller-selected bagging.
pub trait Readable: Send + Sync {
    /// The Merkle family implemented by this structure.
    type Family: Family;

    /// The digest type used by this structure.
    type Digest: Digest;

    /// Total number of nodes (retained + pruned).
    fn size(&self) -> Position<Self::Family>;

    /// Digest of the node at `pos`, or `None` if this structure cannot serve it.
    fn get_node(&self, pos: Position<Self::Family>) -> Option<Self::Digest>;
}

impl<T: Readable> Readable for Arc<T> {
    type Family = T::Family;
    type Digest = T::Digest;

    fn size(&self) -> Position<Self::Family> {
        (**self).size()
    }

    fn get_node(&self, pos: Position<Self::Family>) -> Option<Self::Digest> {
        (**self).get_node(pos)
    }
}
