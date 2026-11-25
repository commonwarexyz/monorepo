//! Pure extraction and ordering algebra shared by the machine, marshal, and scheme.
//!
//! Callers provide already-authenticated protocol objects, and the algebra deterministically
//! reconstructs the block paths those objects describe. [`validate`] checks and derives
//! certificate transcripts, hashing canonical encodings under a namespace. Nothing here holds
//! protocol state, touches storage, or performs runtime work.

mod path;
mod tips;
mod validate;

#[cfg(any(test, feature = "mocks"))]
pub(crate) mod fuzz;
#[cfg(any(test, feature = "mocks"))]
mod reference;

use crate::multimmit::types::ChainId;
pub(crate) use tips::{FinalTips, PoolExtractor, Tips, VqcExtraction};
pub(crate) use validate::{
    CertificateDerivations, DerivedVqc, ValidatedLqc, ValidatedVqc, ValidatedVqcParts,
    VerifiedVote, validate_lqc, validate_vqc, validate_vqc_votes, validate_vqc_with_votes,
    vote_evidence,
};

/// A malformed or insufficient input to the extraction algebra.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    /// A chain identifier did not name an input chain.
    #[error("chain {0} is outside the configured chain set")]
    Chain(ChainId),
    /// A leader block failed structural validation for the configured epoch.
    #[error("leader block is invalid for the configured epoch")]
    Leader,
    /// A vote did not describe a valid path through its leader proposal.
    #[error("vote does not describe a valid proposal-relative path")]
    Vote,
    /// A signer is outside the configured committee.
    #[error("signer is outside the configured committee")]
    Signer,
    /// Per-chain values were not one per chain in ascending chain order.
    #[error("per-chain values are not in canonical chain order")]
    ChainOrder,
    /// The supplied votes did not satisfy the extraction quorum.
    #[error("insufficient or duplicate votes for extraction")]
    Quorum,
    /// Reconstructing a block path would overflow the chain height.
    #[error("block path height overflow")]
    HeightOverflow,
    /// Two retained paths assigned different parents to one block reference.
    #[error("conflicting ancestry for one block reference")]
    ConflictingAncestry,
}

#[cfg(test)]
mod tests;
