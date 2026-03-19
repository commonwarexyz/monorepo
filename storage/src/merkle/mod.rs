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
mod location;
pub mod mem;
pub mod mmb;
pub mod mmr;
pub(super) mod path;
mod position;
mod proof;
mod read;

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
pub trait Family: Copy + Clone + Debug + Send + Sync + 'static {
    /// Maximum valid `Position` value (the largest valid node count / size).
    const MAX_POSITION: Position<Self>;

    /// Maximum valid `Location` value (the largest valid leaf count).
    const MAX_LOCATION: Location<Self>;

    /// Convert a leaf location to its node position, or equivalently, convert a leaf count to the
    /// corresponding total node count (size).
    ///
    /// Valid for any `loc` whose result does not overflow `u64`. Callers that stay within
    /// `loc <= MAX_LOCATION` are always safe; values slightly above may also be valid
    /// (e.g., for probing the next size boundary).
    fn location_to_position(loc: Location<Self>) -> Position<Self>;

    /// Convert a node position to its leaf location, or `None` if the position is not a leaf.
    /// Equivalently, convert a total node count (size) to the corresponding leaf count, returning
    /// `None` if the size is not valid.
    ///
    /// The caller guarantees `pos <= MAX_POSITION`.
    fn position_to_location(pos: Position<Self>) -> Option<Location<Self>>;

    /// Whether `size` is a valid tree size for this Merkle structure.
    fn is_valid_size(size: Position<Self>) -> bool;

    /// Returns the largest valid size that is no greater than `size`.
    fn to_nearest_size(size: Position<Self>) -> Position<Self>;

    /// Return the peaks of a structure with the given `size` as `(position, height)` pairs
    /// in canonical oldest-to-newest order (suitable for
    /// [`Hasher::root`](crate::merkle::hasher::Hasher::root)).
    fn peaks(size: Position<Self>) -> impl Iterator<Item = (Position<Self>, u32)>;

    /// Compute positions of nodes that must be pinned when pruning to `prune_pos`
    /// in a structure of the given `size`.
    fn nodes_to_pin(size: Position<Self>, prune_pos: Position<Self>) -> Vec<Position<Self>>;

    /// Return the positions of the left and right children of the node at `pos` with the
    /// given `height`. The caller guarantees `height > 0` (leaves have no children).
    fn children(pos: Position<Self>, height: u32) -> (Position<Self>, Position<Self>);

    /// Return the heights of the internal nodes that lie between `size_for(N)` and
    /// `size_for(N+1)`, where `N` is the leaf count for the given `size`. These are
    /// the nodes created when the `N`-th leaf is appended.
    fn parent_heights(size: Position<Self>) -> impl Iterator<Item = u32>;
}

/// Errors that can occur when interacting with a Merkle-family data structure.
#[derive(Debug, Error)]
pub enum Error<F: Family> {
    /// The position does not correspond to a leaf node.
    #[error("{0} is not a leaf")]
    NonLeaf(Position<F>),

    /// The position exceeds the valid range.
    #[error("{0} > MAX_POSITION")]
    PositionOverflow(Position<F>),

    /// The location exceeds the valid range.
    #[error("{0} > MAX_LOCATION")]
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

    /// Changeset was created against a different state.
    #[error("stale changeset: expected size {expected}, actual {actual}")]
    StaleChangeset {
        /// The size the changeset was built against.
        expected: Position<F>,
        /// The current size.
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
}
