//! Reconstruction of the ordinary subjects a V-QC or L-QC aggregates.

use super::{Error, batch::CertificateVotes};
use crate::multimmit::{
    scheme::{OrdinarySubject, Scheme},
    types::{CodecConfig, DigestedLeader, LeaderBlock, Tally, Vqc},
};
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::Participant;

/// One signed subject of an aggregate transcript.
pub(super) struct Entry {
    pub(super) signer: Participant,
    pub(super) subject: OrdinarySubject,
}

/// The signed subjects of a V-QC or L-QC in ascending signer order, the order its aggregate is
/// formed in, and the vote bodies they expand to.
pub(super) struct Transcript<D: Digest> {
    pub(super) entries: Vec<Entry>,
    pub(super) votes: CertificateVotes<D>,
}

/// Reconstructs the designated votes of a tally, in ascending signer order.
pub(super) fn tally_transcript<S, D, H>(
    leader: &LeaderBlock<S, D>,
    tally: &Tally<D>,
    config: CodecConfig,
) -> Result<Transcript<D>, Error>
where
    S: Scheme,
    D: Digest,
    H: Hasher<Digest = D>,
{
    let leader = DigestedLeader::new::<H>(leader);
    let mut votes = CertificateVotes {
        leader: leader.digest(),
        designated: Vec::with_capacity(tally.signers().count()),
        conflicting: Vec::new(),
    };
    let mut entries = Vec::with_capacity(config.view_quorum());
    for signer in tally.signers().iter() {
        let body = tally.vote(leader, signer, config)?;
        entries.push(Entry {
            signer,
            subject: OrdinarySubject::vote(&body),
        });
        votes.designated.push((signer, body));
    }
    Ok(Transcript { entries, votes })
}

/// Reconstructs every signed view message of a V-QC, in ascending signer order.
pub(super) fn vqc_transcript<S, D, H>(
    certificate: &Vqc<S, D>,
    config: CodecConfig,
) -> Result<Transcript<D>, Error>
where
    S: Scheme,
    D: Digest,
    H: Hasher<Digest = D>,
{
    let leader = certificate.leader();
    let Transcript {
        mut entries,
        mut votes,
    } = tally_transcript::<S, D, H>(leader, certificate.tally(), config)?;
    let leader_digest = votes.leader;
    for signer in certificate.novoters().iter() {
        entries.push(Entry {
            signer,
            subject: OrdinarySubject::novote(leader.round()),
        });
    }
    for vote in certificate.conflicting_votes() {
        if vote.leader() == leader_digest {
            return Err(Error::Transcript);
        }
        let body = vote.vote_body(leader.round())?;
        entries.push(Entry {
            signer: vote.signer(),
            subject: OrdinarySubject::vote(&body),
        });
        votes.conflicting.push((vote.signer(), body));
    }
    entries.sort_by_key(|entry| entry.signer);
    if !(config.view_quorum()..=config.vqc_max_messages()).contains(&entries.len())
        || entries
            .windows(2)
            .any(|pair| pair[0].signer == pair[1].signer)
    {
        return Err(Error::Transcript);
    }
    Ok(Transcript { entries, votes })
}
