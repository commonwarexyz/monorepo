//! Multimmit protocol objects and their canonical encodings.
//!
//! # Producer chains
//!
//! A [`TransactionBlockHeader`] names one producer-chain coordinate (its [`Context`]) and
//! commits to the digest of an application body. The chain's producer signs it as a
//! [`SignedTransactionBlock`], and a [`TransactionBlock`] pairs a header with its body. Every
//! chain starts from a synthetic genesis object of its epoch ([`EpochGenesis`]).
//!
//! # Votes
//!
//! A [`VoteContent`] is what a validator signs in a view: an [`Endorsement`] (the tip it
//! endorses on every chain and the chains it declares final), an optional leader-block digest, and
//! whether the vote is final. A validator sends its growing content as [`VoteUpdate`]s carrying
//! only the [`ChainChange`]s since one of its two previous updates.
//!
//! # Leader chain and certificates
//!
//! A [`LeaderBlock`] names the previous view's V-QC and that V-QC chain's tips-history
//! commitment; the scheduled leader signs it as a [`SignedLeaderBlock`]. A [`Vqc`] records exactly
//! `n - f` final votes of one view in a [`FinalTally`] with the [`ResolutionPath`]s that
//! interpret tips above its base. An [`Lqc`] records exactly `n - f` votes for one leader block in
//! a [`VoteTally`]; with the [`HistoryRecord`] opening its leader's commitment it certifies
//! finalized tips.
//!
//! ```text
//! TransactionBlockHeader -> SignedTransactionBlock
//! Endorsement -> VoteContent -> VoteUpdate (ChainChange)
//! LeaderBlock -> SignedLeaderBlock
//! VoteContent x (n - f) -> Vqc (FinalTally, ResolutionPath) | Lqc (VoteTally) + HistoryRecord
//! ```

mod activity;
#[cfg(feature = "arbitrary")]
mod arbitrary;
mod artifact;
mod block;
mod bounds;
mod certificate;
mod codec;
mod floor;
mod frontier;
mod genesis;
mod history;
mod primitives;
mod proof;
mod tally;
mod vote;

pub use activity::*;
#[cfg(feature = "arbitrary")]
pub(crate) use arbitrary::codec_config as arbitrary_codec_config;
pub use artifact::{Artifact, ArtifactId};
pub use block::*;
pub use certificate::*;
pub use codec::{CodecConfig, CodecConfigError, DEFAULT_DELTA_MAX, DEFAULT_MAX_VQC_BYTES, Window};
pub use floor::Floor;
pub use frontier::{Frontier, FrontierError};
pub use genesis::*;
pub use history::*;
pub use primitives::*;
pub use proof::ViewProof;
pub use tally::*;
pub use vote::*;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) use {
    artifact::{ArtifactBatch, ArtifactKind, each_artifact},
    bounds::EncodedBounds,
};

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
    /// A per-chain vector does not carry exactly one entry per producer chain.
    #[error("wrong number of chain entries")]
    ChainCount,
    /// A set of declared chains does not range over the epoch's chains.
    #[error("declared chain set does not match the chain count")]
    Declared,
    /// A path or payload list exceeds the epoch's window bounds.
    #[error("path exceeds the window bounds")]
    Window,
    /// A vote update's sequence number is zero.
    #[error("vote update sequence numbers start at one")]
    Sequence,
    /// An encoded object exceeds its byte ceiling.
    #[error("object exceeds its byte ceiling")]
    Size,
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
    /// A path exceeds the representable chain height.
    #[error("chain height overflow")]
    HeightOverflow,
    /// An application body does not match the commitment in its producer header.
    #[error("application body does not match the producer header")]
    Commitment,
}
