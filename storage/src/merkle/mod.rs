//! Shared types for Merkle-family data structures (MMR, MMB).
//!
//! This module provides generic `Position<F>` and `Location<F>` types parameterized by a
//! [`Family`] marker trait. Each Merkle family (e.g. MMR, MMB) implements the trait with
//! its own constants and conversion formulas, while the shared arithmetic, codec, and comparison
//! logic lives here.

pub mod batch;
#[cfg(test)]
pub(crate) mod conformance;
pub mod hasher;
#[cfg(feature = "std")]
mod persisted;
#[cfg(feature = "std")]
pub use persisted::{compact, full};
mod location;
pub mod mem;
pub mod mmb;
pub mod mmr;
pub(super) mod path;
mod position;
mod proof;
mod read;
#[cfg(feature = "std")]
pub mod storage;
#[cfg(feature = "std")]
pub mod verification;

use alloc::vec::Vec;
use core::fmt::Debug;
pub use location::{Location, LocationRangeExt};
pub use position::Position;
pub use proof::Proof;
pub use read::Readable;
use thiserror::Error;

/// Marker trait for Merkle-family data structures.
///
/// Provides the per-family constants and conversion functions that differentiate
/// MMR from MMB (or other future Merkle structures).
pub trait Family: Copy + Clone + Debug + Default + Send + Sync + 'static {
    /// Maximum valid node count / size.
    const MAX_NODES: Position<Self>;

    /// Maximum valid leaf count.
    const MAX_LEAVES: Location<Self>;

    /// Convert a leaf location to its node position, or equivalently, convert a leaf count to the
    /// corresponding total node count (size).
    ///
    /// The public, guaranteed domain is `loc <= MAX_LEAVES`. Some implementations may also accept
    /// slightly larger temporary values for internal probing (for example, when checking the next
    /// size boundary), but callers must not rely on that behavior.
    fn location_to_position(loc: Location<Self>) -> Position<Self>;

    /// Convert a node position to its leaf location, or `None` if the position is not a leaf.
    /// Equivalently, convert a total node count (size) to the corresponding leaf count, returning
    /// `None` if the size is not valid.
    ///
    /// The caller guarantees `pos <= MAX_NODES`.
    fn position_to_location(pos: Position<Self>) -> Option<Location<Self>>;

    /// Whether `size` is a valid tree size for this Merkle structure.
    fn is_valid_size(size: Position<Self>) -> bool;

    /// Returns the largest valid size that is no greater than `size`.
    fn to_nearest_size(size: Position<Self>) -> Position<Self>;

    /// Return the peaks of a structure with the given `size` as `(position, height)` pairs
    /// in canonical oldest-to-newest order (suitable for
    /// [`Hasher::root`](crate::merkle::hasher::Hasher::root)).
    fn peaks(size: Position<Self>) -> impl Iterator<Item = (Position<Self>, u32)> + Send;

    /// Compute positions of nodes that must be pinned when pruning to `prune_loc`.
    ///
    /// Pinned nodes are the minimal set of pruned digests required to continue growing the
    /// structure and recomputing its root after pruning. The default implementation returns the
    /// peaks of the sub-structure at `prune_loc`, which is sufficient for both root computation and
    /// re-merkleization of retained leaves. Implementations may override this if their family
    /// requires a different canonical pinned-node set for the pruning boundary.
    ///
    /// # Panics
    ///
    /// Implementations panic if `prune_loc` is invalid (i.e., exceeds
    /// [`MAX_LEAVES`](Self::MAX_LEAVES)). Callers must validate inputs before calling.
    fn nodes_to_pin(prune_loc: Location<Self>) -> impl Iterator<Item = Position<Self>> + Send {
        let prune_pos = Self::location_to_position(prune_loc);
        Self::peaks(prune_pos)
            .filter(move |&(pos, _)| pos < prune_pos)
            .map(|(pos, _)| pos)
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Return the positions of the left and right children of the node at `pos` with the
    /// given `height`. The caller guarantees `height > 0` (leaves have no children).
    fn children(pos: Position<Self>, height: u32) -> (Position<Self>, Position<Self>);

    /// Return the heights of the internal nodes that lie between `size_for(N)` and
    /// `size_for(N+1)`, where `N` is the given leaf count. These are the nodes created
    /// when the `N`-th leaf is appended.
    fn parent_heights(leaves: Location<Self>) -> impl Iterator<Item = u32>;

    /// Return the height of the node at `pos`.
    ///
    /// # Panics
    ///
    /// Implementations may panic if `pos` does not correspond to a node that exists in some valid
    /// instance of this family (i.e., it is not a position that would appear in a structure of any
    /// size).
    fn pos_to_height(pos: Position<Self>) -> u32;
}

/// Extension of [`Family`] with methods needed for grafting bitmap chunks onto a Merkle structure.
/// Grafting combines an activity bitmap with an ops Merkle structure by hashing bitmap chunks
/// together with ops subtree roots. These methods provide the coordinate conversions and
/// chunk-to-peak mappings required by that process.
pub trait Graftable: Family {
    /// Return the nodes that collectively cover the leaf range of a bitmap chunk in a structure of
    /// the given `size`.
    ///
    /// A chunk at index `chunk_idx` with grafting height `grafting_height` covers leaves
    /// `[chunk_idx << grafting_height, (chunk_idx + 1) << grafting_height)`. The returned nodes
    /// partition that range: each node's leaf range is entirely within the chunk, and together they
    /// cover it exactly.
    ///
    /// Results are returned in oldest-to-newest (left-to-right) order.
    ///
    /// # Panics
    ///
    /// Panics if `size` is not a valid size or if the chunk's leaf range exceeds the structure's
    /// leaf count.
    fn chunk_peaks(
        size: Position<Self>,
        chunk_idx: u64,
        grafting_height: u32,
    ) -> impl Iterator<Item = (Position<Self>, u32)> + Send;

    /// Return the deterministic position of the node at `height` whose leftmost leaf is at
    /// `leaf_start`.
    ///
    /// For some families, this position corresponds to a node that physically exists in any
    /// structure containing those leaves. For others (e.g. MMB with delayed merging), it may be a
    /// "virtual" position that no actual node occupies, but is still deterministic and unique for
    /// the given leaf range and height.
    ///
    /// Used by grafting to map grafted-structure positions to ops-structure positions for domain
    /// separation in hash pre-images.
    ///
    /// # Panics
    ///
    /// Panics if `height` is excessively large (e.g., `>= 63`), or if the resulting position
    /// computation overflows the bounds of the underlying numeric types.
    fn subtree_root_position(leaf_start: Location<Self>, height: u32) -> Position<Self>;

    /// Return the location of the leftmost leaf covered by the node at `pos` with `height`. For a
    /// leaf (height 0), returns its own location.
    ///
    /// # Panics
    ///
    /// Panics if `height` is excessively large (e.g., `>= 63`), or if an invalid combination of
    /// `pos` and `height` results in arithmetic underflow/overflow.
    fn leftmost_leaf(pos: Position<Self>, height: u32) -> Location<Self>;

    /// Return the minimum leaf count at which the node at `pos` with `height` exists in the
    /// structure.
    ///
    /// For families without delayed merging (e.g. MMR), a node exists as soon as all leaves
    /// in its span have been appended. For families with delayed merging (e.g. MMB), the
    /// node is created some number of leaf insertions _after_ its last leaf, so the birth
    /// size is larger. The MMB override accounts for this delay.
    ///
    /// This is used by the grafted-tree pruning logic to determine when a chunk-pair's
    /// parent has been born in the ops tree, which controls when it is safe to prune the
    /// pair's individual grafted leaves.
    ///
    /// # Panics
    ///
    /// Panics if `height` is excessively large (e.g., `>= 63`), or if arithmetic overflows.
    fn peak_birth_size(pos: Position<Self>, height: u32) -> u64 {
        let leftmost = *Self::leftmost_leaf(pos, height);
        let width = 1u64.checked_shl(height).expect("height excessively large");
        leftmost.checked_add(width).expect("birth size overflow")
    }
}

/// Errors that can occur when interacting with a Merkle-family data structure.
#[derive(Debug, Error)]
pub enum Error<F: Family> {
    /// The position does not correspond to a leaf node.
    #[error("{0} is not a leaf")]
    NonLeaf(Position<F>),

    /// The position exceeds the valid range.
    #[error("{0} > MAX_NODES")]
    PositionOverflow(Position<F>),

    /// The location exceeds the valid range.
    #[error("{0} > MAX_LEAVES")]
    LocationOverflow(Location<F>),

    /// The range is empty but must contain at least one element.
    #[error("range is empty")]
    Empty,

    /// The end of a range is out of bounds.
    #[error("range end out of bounds: {0}")]
    RangeOutOfBounds(Location<F>),

    /// The requested size is invalid.
    #[error("invalid size: {0}")]
    InvalidSize(u64),

    /// A requested leaf location exceeds the current leaf count.
    #[error("leaf location out of bounds: {0}")]
    LeafOutOfBounds(Location<F>),

    /// A required node was not available (e.g. pruned).
    #[error("element pruned: {0}")]
    ElementPruned(Position<F>),

    /// The provided pinned node list does not match the expected pruning boundary.
    #[error("invalid pinned nodes")]
    InvalidPinnedNodes,

    /// Structure has diverged incompatibly from the batch's ancestor chain.
    #[error("stale batch: base size {expected}, current size {actual}")]
    StaleBatch {
        /// The base size when the batch chain was forked.
        expected: Position<F>,
        /// The current structure size.
        actual: Position<F>,
    },

    /// An ancestor batch was dropped before this batch was applied, causing
    /// data loss. All ancestors must be kept alive until descendants are applied.
    #[error("ancestor dropped: expected size {expected}, actual size {actual}")]
    AncestorDropped {
        /// The expected size after applying all ancestors + this batch.
        expected: Position<F>,
        /// The actual size (less than expected due to missing ancestor data).
        actual: Position<F>,
    },

    /// The proof is invalid.
    #[error("invalid proof")]
    InvalidProof,

    /// The root does not match the computed root.
    #[error("root mismatch")]
    RootMismatch,

    /// A required digest is missing.
    #[error("missing digest: {0}")]
    MissingDigest(Position<F>),

    /// A metadata error occurred.
    #[cfg(feature = "std")]
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),

    /// A journal error occurred.
    #[cfg(feature = "std")]
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),

    /// A runtime error occurred.
    #[cfg(feature = "std")]
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),

    /// A required node is missing.
    #[error("missing node: {0}")]
    MissingNode(Position<F>),

    /// Data is corrupted.
    #[error("data corrupted: {0}")]
    DataCorrupted(&'static str),

    /// A required grafted leaf digest is missing.
    #[error("missing grafted leaf digest: {0}")]
    MissingGraftedLeaf(Position<F>),

    /// Bit offset is out of bounds.
    #[error("bit offset {0} out of bounds (size: {1})")]
    BitOutOfBounds(u64, u64),

    /// Rewind was attempted but no prior committed state is available.
    #[error("rewind beyond history")]
    RewindBeyondHistory,
}
