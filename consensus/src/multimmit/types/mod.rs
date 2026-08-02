//! Canonical Multimmit protocol objects.

mod activity;
#[cfg(feature = "arbitrary")]
mod arbitrary;
mod block;
mod certificate;
mod genesis;
mod history;
mod primitives;
mod tally;
mod vote;

pub use crate::types::Height;
pub use activity::*;
pub use block::*;
pub use certificate::*;
pub use genesis::*;
pub use history::*;
pub use primitives::*;
pub use tally::*;
pub use vote::*;

/// An error encountered while constructing a Multimmit protocol object.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// A value belongs to another epoch or configuration.
    #[error("epoch or configuration mismatch")]
    Context,
    /// A chain identifier or chain ordering is invalid.
    #[error("invalid chain")]
    Chain,
    /// An ordinary signed block used the synthetic genesis height.
    #[error("height zero is reserved for synthetic genesis")]
    GenesisHeight,
    /// A bounded sequence has the wrong length.
    #[error("invalid {0} length")]
    Length(&'static str),
    /// A view-zero value was used where a live view is required.
    #[error("view zero is reserved for genesis")]
    GenesisView,
    /// Participants are duplicated, unordered, out of range, or have the wrong cardinality.
    #[error("invalid participant set")]
    Participants,
    /// A compact transcript is not the canonical representation of its expanded messages.
    #[error("non-canonical transcript")]
    Transcript,
    /// A certificate does not satisfy its structural quorum predicate.
    #[error("invalid certificate quorum")]
    Quorum,
    /// A proposal or extension path exceeds the representable chain height.
    #[error("chain height overflow")]
    HeightOverflow,
    /// An application body does not match the commitment in its producer header.
    #[error("application body does not match the producer header")]
    Commitment,
}
