//! Shared types for Merkle-family data structures (MMR, MMB).
//!
//! This module provides generic [`Position<F>`] and [`Location<F>`] types parameterized by a
//! [`MerkleFamily`] marker trait. Each Merkle family (e.g. MMR, MMB) implements the trait with
//! its own constants and conversion formulas, while the shared arithmetic, codec, and comparison
//! logic lives here.

pub mod hasher;
pub mod location;
pub mod mmr;
pub mod position;
pub mod proof;

#[cfg(feature = "std")]
pub mod journaled;
pub mod mem;
#[cfg(feature = "std")]
pub mod storage;

use alloc::vec::Vec;
use core::fmt;
pub use location::{Location, LocationRangeExt};
pub use position::Position;
pub use proof::Proof;
use thiserror::Error;

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

    /// Returns the largest valid size that is no greater than `size`.
    fn to_nearest_size(size: u64) -> u64;

    /// Compute positions of nodes that must be pinned when pruning to `prune_pos`
    /// in a structure of the given `size`.
    fn nodes_to_pin(size: u64, prune_pos: u64) -> Vec<u64>;
}

/// Errors that can occur when interacting with a Merkle-family data structure.
#[derive(Error, Debug)]
pub enum Error<F: MerkleFamily> {
    #[cfg(feature = "std")]
    #[error("metadata error: {0}")]
    Metadata(#[from] crate::metadata::Error),
    #[cfg(feature = "std")]
    #[error("journal error: {0}")]
    Journal(#[from] crate::journal::Error),
    #[cfg(feature = "std")]
    #[error("runtime error: {0}")]
    Runtime(#[from] commonware_runtime::Error),
    #[error("missing node: {0}")]
    MissingNode(Position<F>),
    #[error("invalid proof")]
    InvalidProof,
    #[error("root mismatch")]
    RootMismatch,
    #[error("element pruned: {0}")]
    ElementPruned(Position<F>),
    #[error("position is not a leaf: {0}")]
    PositionNotLeaf(Position<F>),
    #[error("invalid position: {0}")]
    InvalidPosition(Position<F>),
    #[error("missing digest: {0}")]
    MissingDigest(Position<F>),
    #[error("missing grafted leaf digest: {0}")]
    MissingGraftedLeaf(Position<F>),
    #[error("invalid proof length")]
    InvalidProofLength,
    #[error("invalid size: {0}")]
    InvalidSize(u64),
    #[error("empty")]
    Empty,
    #[error("pruned chunks causes u64 overflow")]
    PrunedChunksOverflow,
    #[error("location {0} > MAX_LOCATION")]
    LocationOverflow(Location<F>),
    #[error("range out of bounds: end location {0} exceeds size")]
    RangeOutOfBounds(Location<F>),
    #[error("requires merkleization for requested size")]
    Unmerkleized,
    #[error("leaf location out of bounds: {0}")]
    LeafOutOfBounds(Location<F>),
    #[error("bit offset {0} out of bounds (size: {1})")]
    BitOutOfBounds(u64, u64),
    #[error("invalid pinned nodes")]
    InvalidPinnedNodes,
    #[error("data corrupted: {0}")]
    DataCorrupted(&'static str),
}

impl<F: MerkleFamily> From<PositionConversionError<F>> for Error<F> {
    fn from(err: PositionConversionError<F>) -> Self {
        match err {
            PositionConversionError::NonLeaf(pos) => Self::PositionNotLeaf(pos),
            PositionConversionError::Overflow(pos) => Self::InvalidPosition(pos),
        }
    }
}

impl<F: MerkleFamily> From<LocationConversionError<F>> for Error<F> {
    fn from(err: LocationConversionError<F>) -> Self {
        match err {
            LocationConversionError::Overflow(loc) => Self::LocationOverflow(loc),
        }
    }
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
