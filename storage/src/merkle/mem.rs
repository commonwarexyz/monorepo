//! Shared traits and types for in-memory Merkle-family data structures.
//!
//! Defines the [`CleanMem`] and [`DirtyMem`] traits that abstract over the
//! in-memory MMR and MMB types, allowing the journaled implementation to be
//! generic over the Merkle family.

use super::{hasher::Hasher, Location, MerkleFamily, Position};
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_cryptography::Digest;
use core::ops::Range;

cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use commonware_parallel::ThreadPool;
    } else {
        /// Placeholder for no_std builds where parallelism is unavailable.
        pub struct ThreadPool;
    }
}

/// Configuration for initializing an in-memory Merkle structure.
pub struct Config<F: MerkleFamily, D: Digest> {
    /// The retained nodes.
    pub nodes: Vec<D>,

    /// The highest position for which this structure has been pruned, or 0 if never pruned.
    pub pruned_to_pos: Position<F>,

    /// The pinned nodes, in the order expected by `MerkleFamily::nodes_to_pin`.
    pub pinned_nodes: Vec<D>,
}

/// An in-memory Merkle structure in the Clean (merkleized) state.
pub trait CleanMem<F: MerkleFamily, D: Digest>: Sized + Send + Sync {
    /// The corresponding Dirty type.
    type Dirty: DirtyMem<F, D, Clean = Self>;

    /// Return the total number of nodes, irrespective of pruning.
    fn size(&self) -> Position<F>;

    /// Return the total number of leaves.
    fn leaves(&self) -> Location<F>;

    /// Returns [start, end) where `start` is the oldest retained position.
    fn bounds(&self) -> Range<Position<F>>;

    /// Return the node digest at `pos`, or `None` if not stored.
    fn get_node(&self, pos: Position<F>) -> Option<D>;

    /// Return the node digest at `pos`, panicking if not available.
    fn get_node_unchecked(&self, pos: Position<F>) -> &D;

    /// Add extra pinned nodes.
    fn add_pinned_nodes(&mut self, pinned: BTreeMap<Position<F>, D>);

    /// Prune all nodes before `pos`, pinning those required for proofs.
    fn prune_to_pos(&mut self, pos: Position<F>) -> Result<(), super::Error<F>>;

    /// Prune all nodes, retaining only pinned nodes.
    fn prune_all(&mut self);

    /// Return the root digest.
    fn root(&self) -> &D;

    /// Convert to the Dirty state.
    fn into_dirty(self) -> Self::Dirty;

    /// Initialize from a config, merkleizing immediately.
    fn init(
        config: Config<F, D>,
        hasher: &mut impl Hasher<F, Digest = D>,
    ) -> Result<Self, super::Error<F>>;

    /// Return the pinned nodes. Test-only.
    #[cfg(test)]
    fn pinned_nodes(&self) -> BTreeMap<Position<F>, D>;
}

/// An in-memory Merkle structure in the Dirty (unmerkleized) state.
pub trait DirtyMem<F: MerkleFamily, D: Digest>: Sized + Send + Sync + From<Self::Clean> {
    /// The corresponding Clean type.
    type Clean: CleanMem<F, D, Dirty = Self>;

    /// Return the total number of nodes, irrespective of pruning.
    fn size(&self) -> Position<F>;

    /// Return the total number of leaves.
    fn leaves(&self) -> Location<F>;

    /// Returns [start, end) where `start` is the oldest retained position.
    fn bounds(&self) -> Range<Position<F>>;

    /// Return the node digest at `pos`, panicking if not available.
    fn get_node_unchecked(&self, pos: Position<F>) -> &D;

    /// Add extra pinned nodes.
    fn add_pinned_nodes(&mut self, pinned: BTreeMap<Position<F>, D>);

    /// Add an element and return its leaf position.
    fn add(&mut self, hasher: &mut impl Hasher<F, Digest = D>, element: &[u8]) -> Position<F>;

    /// Add a pre-computed leaf digest and return its position.
    fn add_leaf_digest(&mut self, digest: D) -> Position<F>;

    /// Pop the most recent leaf, returning the new size.
    fn pop(&mut self) -> Result<Position<F>, super::Error<F>>;

    /// Compute all pending digests and the root, converting to Clean state.
    fn merkleize(
        self,
        hasher: &mut impl Hasher<F, Digest = D>,
        pool: Option<ThreadPool>,
    ) -> Self::Clean;

    /// Reconstruct from raw components.
    fn from_components(nodes: Vec<D>, pruned_to_pos: Position<F>, pinned: Vec<D>) -> Self;
}
