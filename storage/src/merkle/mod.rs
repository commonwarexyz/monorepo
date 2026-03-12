//! Merkle data structures for authenticated storage.

pub mod location;
pub mod mmr;
pub mod position;
pub mod proof;

pub use location::{Location, LocationRangeExt, MAX_LOCATION};
pub use position::{Position, MAX_POSITION};
use thiserror::Error;

/// Errors from converting between [Position] and [Location].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Error)]
pub enum Error {
    /// The position does not correspond to a leaf node.
    #[error("{0} is not a leaf")]
    NonLeaf(Position),

    /// The position exceeds the valid range.
    #[error("{0} > MAX_POSITION")]
    PositionOverflow(Position),

    /// The location exceeds the valid range.
    #[error("{0} > MAX_LOCATION")]
    LocationOverflow(Location),
}
