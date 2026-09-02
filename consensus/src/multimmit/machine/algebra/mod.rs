//! Pure extraction and ordering algebra.
//!
//! This module contains no protocol state, cryptography, storage, or runtime work. Callers provide
//! already-authenticated protocol objects, and the algebra deterministically reconstructs the
//! block paths those objects describe.

mod path;
mod tips;

use crate::multimmit::{
    config::CodecConfig,
    types::{CertificateId, ChainId, LeaderBlock, Lqc, VoteBody, Vqc},
};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::Participant;
pub(crate) use path::{ProposalPaths, VotePaths};
pub(crate) use tips::{FinalTips, PoolExtractor, Tips, VqcExtraction};

/// Namespace of the digest by which the finality pool identifies one signer's vote body.
const FINALITY_VOTE_NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_FINALITY_VOTE";

/// Digest by which the finality pool identifies one signer's vote body.
pub(crate) fn vote_evidence<H, D>(signer: Participant, body: &VoteBody<D>) -> D
where
    H: Hasher<Digest = D>,
    D: Digest,
{
    let signer = u64::from(signer.get()).to_be_bytes();
    let body = body.encode();
    H::hash(&[FINALITY_VOTE_NAMESPACE, &signer, body.as_ref()])
}

/// One vote a certificate transcript attests, with the evidence digest the finality pool
/// indexes it by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedVote<D: Digest> {
    pub(crate) signer: Participant,
    pub(crate) body: VoteBody<D>,
    pub(crate) evidence: D,
}

impl<D: Digest> VerifiedVote<D> {
    pub(crate) fn new<H: Hasher<Digest = D>>(signer: Participant, body: VoteBody<D>) -> Self {
        let evidence = vote_evidence::<H, D>(signer, &body);
        Self {
            signer,
            body,
            evidence,
        }
    }
}


/// Expensive deterministic outputs derived while validating one exact V-QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedVqc<D: Digest> {
    id: CertificateId<D>,
    leader: D,
    canonical: Bytes,
    tips: Tips<D>,
    votes: Vec<VerifiedVote<D>>,
}

impl<D: Digest> ValidatedVqc<D> {
    pub(crate) const fn id(&self) -> CertificateId<D> {
        self.id
    }

    pub(crate) const fn leader(&self) -> D {
        self.leader
    }

    pub(crate) fn into_parts(self) -> (CertificateId<D>, Bytes, Tips<D>) {
        (self.id, self.canonical, self.tips)
    }

    /// Takes the attested votes: transcript signers first, then conflicting votes.
    pub(crate) fn take_votes(&mut self) -> Vec<VerifiedVote<D>> {
        core::mem::take(&mut self.votes)
    }

    /// Bytes charged against the completion lane. The attested votes are excluded: the finality
    /// pool allocates them either way, and they are bounded by the certificate's own encoding.
    pub(crate) fn owned_bytes(&self) -> Option<usize> {
        self.canonical.len().checked_add(self.tips.owned_bytes()?)
    }
}

/// Expensive deterministic outputs derived while validating one exact L-QC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ValidatedLqc<D: Digest> {
    leader: D,
    tips: FinalTips<D>,
    votes: Vec<VerifiedVote<D>>,
}

impl<D: Digest> ValidatedLqc<D> {
    pub(crate) fn into_parts(self) -> (D, FinalTips<D>, Vec<VerifiedVote<D>>) {
        (self.leader, self.tips, self.votes)
    }

    /// Bytes charged against the completion lane; the attested votes are excluded as for
    /// [`ValidatedVqc::owned_bytes`].
    pub(crate) fn owned_bytes(&self) -> Option<usize> {
        self.tips.owned_bytes()
    }
}

/// Validates one exact V-QC and derives its ordering data without finality vote evidence.
pub(crate) fn validate_vqc<H, V, D>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
) -> Result<ValidatedVqc<D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    validate_vqc_inner::<H, V, D>(certificate, config, false)
}

/// Validates one exact V-QC and additionally derives every attested vote with its finality
/// evidence, so the finality pool can observe the certificate without rebuilding or hashing.
pub(crate) fn validate_vqc_with_votes<H, V, D>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
) -> Result<ValidatedVqc<D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    validate_vqc_inner::<H, V, D>(certificate, config, true)
}

fn validate_vqc_inner<H, V, D>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
    with_votes: bool,
) -> Result<ValidatedVqc<D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let canonical = certificate.encode();
    let id = CertificateId::new(H::hash(&[canonical.as_ref()]));
    let leader = certificate.leader().digest::<H>();
    let tally = certificate.tally();
    let mut expanded = Vec::with_capacity(tally.signers().count());
    for signer in tally.signers().iter() {
        let body = tally
            .vote_with_leader_digest(certificate.leader(), leader, signer, config)
            .map_err(|_| Error::Vote)?;
        expanded.push((signer, body));
    }
    let (tips, _) = VqcExtraction::from_votes::<H, V>(
        certificate.leader(),
        leader,
        expanded.iter().map(|(signer, body)| (*signer, body)),
        config,
    )?
    .into_parts();
    let mut votes = Vec::new();
    if with_votes {
        votes.reserve(expanded.len() + certificate.conflicting_votes().len());
        votes.extend(
            expanded
                .into_iter()
                .map(|(signer, body)| VerifiedVote::new::<H>(signer, body)),
        );
        for conflict in certificate.conflicting_votes() {
            let body = conflict
                .vote_body(certificate.leader().round(), config)
                .map_err(|_| Error::Vote)?;
            votes.push(VerifiedVote::new::<H>(conflict.signer(), body));
        }
    }
    Ok(ValidatedVqc {
        id,
        leader,
        canonical,
        tips,
        votes,
    })
}

pub(crate) fn validate_lqc<H, V, D>(
    certificate: &Lqc<V, D>,
    config: CodecConfig,
) -> Result<ValidatedLqc<D>, Error>
where
    H: Hasher<Digest = D>,
    V: Variant,
    D: Digest,
{
    let leader = certificate.leader();
    let leader_digest = leader.digest::<H>();
    let tally = certificate.tally();
    let mut expanded = Vec::with_capacity(tally.signers().count());
    for signer in tally.signers().iter() {
        let body = tally
            .vote_with_leader_digest(leader, leader_digest, signer, config)
            .map_err(|_| Error::Vote)?;
        expanded.push((signer, body));
    }
    let tips = FinalTips::from_pool::<H, V, _>(
        leader,
        expanded.iter().map(|(signer, body)| (*signer, body)),
        config,
    )?;
    let votes = expanded
        .into_iter()
        .map(|(signer, body)| VerifiedVote::new::<H>(signer, body))
        .collect();
    Ok(ValidatedLqc {
        leader: leader_digest,
        tips,
        votes,
    })
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
