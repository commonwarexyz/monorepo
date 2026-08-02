//! Pure extraction and ordering algebra.
//!
//! This module contains no protocol state, cryptography, storage, or runtime work. Callers provide
//! already-authenticated protocol objects, and the algebra deterministically reconstructs the
//! block paths those objects describe.

mod path;
mod tips;

use crate::multimmit::{
    config::CodecConfig,
    types::{ChainId, LeaderBlock, Lqc, VoteBody, Vqc},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::Participant;
pub(crate) use path::{ProposalPaths, VotePaths};
pub(crate) use tips::{FinalTips, PoolExtractor, Tips, VqcExtraction};

pub(crate) fn validate_vqc<H, V, D>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
) -> Result<(), Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    VqcExtraction::new::<H, V>(certificate, config).map(drop)
}

pub(crate) fn validate_lqc<H, V, D>(
    certificate: &Lqc<V, D>,
    config: CodecConfig,
) -> Result<(), Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    FinalTips::from_lqc::<H, V>(certificate, config).map(drop)
}

pub(crate) fn validate_vqc_votes<'a, H, V, D>(
    leader: &LeaderBlock<V, D>,
    votes: impl IntoIterator<Item = (Participant, &'a VoteBody<D>)>,
    config: CodecConfig,
) -> Result<(), Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest + 'a,
{
    let prepared = tips::PreparedVotes::new::<H, V, _>(leader, votes, config)?;
    if prepared.len() < config.designation_quorum() {
        return Err(Error::Quorum);
    }
    prepared.ancestry().map(drop)
}

/// A malformed or insufficient input to the extraction algebra.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Error {
    /// A chain identifier did not name an input chain.
    #[error("chain {0} is outside the configured chain set")]
    Chain(ChainId),
    /// A vote did not describe a valid path through its leader proposal.
    #[error("vote does not describe a valid proposal-relative path")]
    Vote,
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
#[path = "../tests/algebra.rs"]
mod tests;
