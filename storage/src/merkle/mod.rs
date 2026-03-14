//! Shared types for Merkle-family data structures (MMR, MMB).
//!
//! This module provides generic `Position<F>` and `Location<F>` types parameterized by a
//! [`Family`] marker trait. Each Merkle family (e.g. MMR, MMB) implements the trait with
//! its own constants and conversion formulas, while the shared arithmetic, codec, and comparison
//! logic lives here.

pub mod hasher;
mod location;
pub mod mmb;
pub mod mmr;
mod position;
mod proof;

use alloc::vec::Vec;
use location::Location;
pub use location::LocationRangeExt;
use position::Position;
use thiserror::Error;

/// Marker trait for Merkle-family data structures.
///
/// Provides the per-family constants and conversion functions that differentiate
/// MMR from MMB (or other future Merkle structures).
pub trait Family: Copy + Clone + Send + Sync + 'static {
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
