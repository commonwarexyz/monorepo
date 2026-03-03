//! Shared types for Merkle-family data structures (MMR, MMB).
//!
//! This module provides generic [`Position<F>`] and [`Location<F>`] types parameterized by a
//! [`MerkleFamily`] marker trait. Each Merkle family (e.g. MMR, MMB) implements the trait with
//! its own constants and conversion formulas, while the shared arithmetic, codec, and comparison
//! logic lives here.

pub mod location;
pub mod position;
pub mod proof;

use core::fmt;
pub use location::{Location, LocationRangeExt};
pub use position::Position;
pub use proof::Proof;

/// Marker trait for Merkle-family data structures.
///
/// Provides the per-family constants and conversion functions that differentiate
/// MMR from MMB (or other future Merkle structures).
pub trait MerkleFamily: Copy + Clone + Send + Sync + 'static {
    /// Maximum valid [Position] value (the largest valid node count / size).
    const MAX_POSITION: u64;

    /// Maximum valid [Location] value (the largest valid leaf count).
    const MAX_LOCATION: u64;

    /// Convert a leaf location (0-based leaf index) to its node position.
    ///
    /// The caller guarantees `loc <= MAX_LOCATION`.
    fn location_to_position(loc: u64) -> u64;

    /// Convert a node position to its leaf location, or `None` if the position is not a leaf.
    ///
    /// The caller guarantees `pos <= MAX_POSITION`.
    fn position_to_location(pos: u64) -> Option<u64>;

    /// Whether `size` is a valid tree size for this Merkle structure.
    fn is_valid_size(size: u64) -> bool;
}

/// Error returned when converting a [Position] to a [Location] fails.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum PositionConversionError<F: MerkleFamily> {
    /// The position does not correspond to a leaf node.
    NonLeaf(Position<F>),
    /// The position exceeds the valid range.
    Overflow(Position<F>),
}

impl<F: MerkleFamily> fmt::Debug for PositionConversionError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLeaf(p) => f.debug_tuple("NonLeaf").field(p).finish(),
            Self::Overflow(p) => f.debug_tuple("Overflow").field(p).finish(),
        }
    }
}

impl<F: MerkleFamily> fmt::Display for PositionConversionError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonLeaf(pos) => write!(f, "{pos} is not a leaf"),
            Self::Overflow(pos) => write!(f, "{pos} > MAX_POSITION"),
        }
    }
}

/// Error returned when converting a [Location] to a [Position] fails.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum LocationConversionError<F: MerkleFamily> {
    /// The location exceeds the valid range.
    Overflow(Location<F>),
}

impl<F: MerkleFamily> fmt::Debug for LocationConversionError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow(l) => f.debug_tuple("Overflow").field(l).finish(),
        }
    }
}

impl<F: MerkleFamily> fmt::Display for LocationConversionError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow(loc) => write!(f, "{loc} > MAX_LOCATION"),
        }
    }
}
