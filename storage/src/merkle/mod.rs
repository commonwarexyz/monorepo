//! Shared types for Merkle-family data structures (MMR, MMB).
//!
//! This module provides generic `Position<F>` and `Location<F>` types parameterized by a
//! [`Family`] marker trait. Each Merkle family (e.g. MMR, MMB) implements the trait with
//! its own constants and conversion formulas, while the shared arithmetic, codec, and comparison
//! logic lives here.

pub mod batch;
pub mod hasher;
mod location;
pub mod mem;
pub mod mmb;
pub mod mmr;
mod position;
mod proof;
mod read;

use alloc::vec::Vec;
use commonware_cryptography::Digest;
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

    /// Convert a leaf location (0-based leaf index) to its node position.
    ///
    /// The caller guarantees `loc <= MAX_LOCATION`.
    fn location_to_position(loc: Location<Self>) -> Position<Self>;

    /// Convert a node position to its leaf location, or `None` if the position is not a leaf.
    ///
    /// The caller guarantees `pos <= MAX_POSITION`.
    fn position_to_location(pos: Position<Self>) -> Option<Location<Self>>;

    /// Whether `size` is a valid tree size for this Merkle structure.
    fn is_valid_size(size: Position<Self>) -> bool;

    /// Returns the largest valid size that is no greater than `size`.
    fn to_nearest_size(size: Position<Self>) -> Position<Self>;

    /// Compute positions of nodes that must be pinned when pruning to `prune_pos`
    /// in a structure of the given `size`.
    fn nodes_to_pin(size: Position<Self>, prune_pos: Position<Self>) -> Vec<Position<Self>>;

    /// Return the positions of the left and right children of the node at `pos` with the
    /// given `height`. The caller guarantees `height > 0` (leaves have no children).
    fn children(pos: Position<Self>, height: u32) -> (Position<Self>, Position<Self>);

    // --- Peak iteration ---

    /// Iterator over `(peak_position, height)` pairs.
    type PeakIterator: Iterator<Item = (Position<Self>, u32)>;

    /// Iterate peaks for the given size.
    fn peak_iterator(size: Position<Self>) -> Self::PeakIterator;

    /// Peaks in oldest-to-newest order for root fold computation.
    /// Default: same as `peak_iterator` (correct for MMR whose iterator already yields in fold
    /// order).
    fn peaks_fold_order(size: Position<Self>) -> Vec<(Position<Self>, u32)> {
        Self::peak_iterator(size).collect()
    }

    // --- Append support ---

    /// Heights of internal nodes created when appending a leaf to a structure of the given
    /// `size`. After appending the leaf at position `size`, each internal node is appended
    /// sequentially at `size + 1`, `size + 2`, etc.
    fn merge_heights_on_append(size: Position<Self>) -> Vec<u32>;

    // --- Dirty path support ---

    /// Ancestors of the leaf at `loc` up to its peak root, bottom-up.
    /// Returns `(parent_position, height)` pairs, starting from the leaf's immediate parent.
    fn leaf_ancestors(loc: Location<Self>, size: Position<Self>) -> Vec<(Position<Self>, u32)>;

    // --- Proof support ---

    /// Compute the proof blueprint for a leaf range: which peaks are before, after, or contain
    /// the range, and which sibling nodes are needed for reconstruction.
    fn proof_blueprint(
        leaves: Location<Self>,
        range: core::ops::Range<Location<Self>>,
    ) -> Result<mem::Blueprint<Self>, mem::Error<Self>>;

    /// Reconstruct the root digest from proof data and elements.
    ///
    /// This is the family-specific algorithm that rebuilds the root from a fold-based proof layout.
    /// MMR and MMB have fundamentally different tree traversal strategies for reconstruction.
    fn reconstruct_root<D: Digest, H: hasher::Hasher<Self, Digest = D>, E: AsRef<[u8]>>(
        hasher: &mut H,
        proof_leaves: Location<Self>,
        proof_digests: &[D],
        elements: &[E],
        start_loc: Location<Self>,
    ) -> Result<D, proof::ReconstructionError>;
}

/// Errors from converting between `Position` and `Location`.
#[derive(Debug, Clone, Copy, Error)]
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
}

impl<F: Family> PartialEq for Error<F> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NonLeaf(a), Self::NonLeaf(b)) => a == b,
            (Self::PositionOverflow(a), Self::PositionOverflow(b)) => a == b,
            (Self::LocationOverflow(a), Self::LocationOverflow(b)) => a == b,
            _ => false,
        }
    }
}

impl<F: Family> Eq for Error<F> {}
