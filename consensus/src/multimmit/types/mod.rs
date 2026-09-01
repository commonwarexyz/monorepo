//! Multimmit protocol objects and their canonical encodings.
//!
//! # Producer chains
//!
//! A [`TransactionBlockHeader`] names one producer-chain position (its [`Context`]) and commits
//! to the digest of an application body. The chain's producer signs it as a
//! [`SignedTransactionBlock`]; validators holding the body sign it with a threshold share as a
//! [`DaVote`], and `n-2f` votes recover a [`DaCertificate`]. A [`TransactionBlock`] pairs a header
//! with its body.
//!
//! # Leader chain
//!
//! A [`LeaderBlock`] carries one [`ChainProposal`] per producer chain, each extending an
//! [`Anchor`]: a safe tip or a DA certificate. The scheduled leader signs it as a
//! [`SignedLeaderBlock`].
//!
//! # Votes and certificates
//!
//! A [`VoteBody`] casts a [`Ballot`] (a leader digest plus one position and one extension per
//! chain) in a round and is signed as a [`Vote`]; a [`NoVote`] abstains instead. Either is a
//! [`ViewMessage`]. A [`Vqc`] aggregates `n-f..=n` view messages and an [`Lqc`] exactly `n-f`
//! votes for one leader; both store their votes compactly in a [`Tally`]. `2f+1` [`Nullify`]
//! shares for a round recover a [`Nullification`].
//!
//! ```text
//! TransactionBlockHeader -> SignedTransactionBlock
//!                        -> DaVote -> DaCertificate
//! LeaderBlock(ChainProposal(Anchor)) -> SignedLeaderBlock
//! VoteBody(Ballot) -> Vote | NoVote -> ViewMessage -> Vqc | Lqc (Tally)
//! Round -> Nullify -> Nullification
//! ```

mod activity;
#[cfg(feature = "arbitrary")]
mod arbitrary;
mod artifact;
mod block;
mod bounds;
mod certificate;
mod codec;
#[cfg(all(test, feature = "arbitrary"))]
mod conformance;
mod finality;
mod frontier;
mod genesis;
mod history;
mod primitives;
mod proof;
mod tally;
mod vote;

pub use activity::*;
pub use artifact::{Artifact, ArtifactId};
pub use block::*;
pub use certificate::*;
pub use codec::{CodecConfig, CodecConfigError, PathLimits};
pub use finality::{FinalityFact, FinalityId, PoolSummary};
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
    /// A chain proposal carries more payloads than the pipeline depth.
    #[error("proposal exceeds the pipeline depth")]
    ProposalLength,
    /// A vote path does not fit its proposal: a position lies beyond the pipeline depth or the
    /// proposal's tip, or the position plus its extension overflows the chain height.
    #[error("vote position exceeds its proposal")]
    Position,
    /// A vote extension carries more payloads than the extension bound.
    #[error("vote extension exceeds the extension bound")]
    ExtensionLength,
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
