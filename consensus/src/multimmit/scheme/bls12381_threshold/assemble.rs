//! Certificate assembly and transcript reconstruction.

#[cfg(not(target_arch = "wasm32"))]
use super::DaRecoveryError;
use super::{
    Error, Scheme,
    batch::CertificateVotes,
    claims::{TranscriptEntry, decoded, partial},
};
use crate::{
    Epochable,
    multimmit::{
        scheme::{Namespace, Subject},
        types::{
            CodecConfig, ConflictingVote, DaCertificate, DaVote, DigestedLeader, LeaderBlock, Lqc,
            Nullification, Nullify, Tally, ThresholdShare, ViewMessage, Vote, Vqc,
        },
    },
    types::Attributable as _,
};
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    bls12381::{
        certificate::threshold as certificate_threshold,
        primitives::{
            ops::{self, aggregate, threshold},
            sharing::Sharing,
            variant::Variant,
        },
    },
    certificate::{Signers, Subject as _},
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
#[cfg(not(target_arch = "wasm32"))]
use commonware_utils::Participant;
use commonware_utils::non_empty;
use std::collections::HashSet;

/// Whether assembly verifies each input signature before combining them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureVerification {
    /// Verify every input signature individually.
    Checked,
    /// Skip the per-input checks.
    ///
    /// Threshold recovery (DA certificates and nullifications) still checks the recovered
    /// signature against the group identity with one pairing, so DA shares that passed only the
    /// structural precheck are safe to recover. Aggregation (V-QCs and L-QCs) runs no
    /// pairing at all, so its inputs must already be verified.
    Preverified,
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Recovers a DA certificate from exactly `n-2f` shares for one header, verifying each share.
    pub fn assemble_da_certificate<D: Digest>(
        &self,
        votes: &[DaVote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<V, D>, Error> {
        self.assemble_da_certificate_with(votes, SignatureVerification::Checked, strategy)
    }

    mocks_pub! {
        /// Recovers a DA certificate from exactly `n-2f` shares for one header.
        fn assemble_da_certificate_with<D: Digest>(
            &self,
            votes: &[DaVote<V, D>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<DaCertificate<V, D>, Error> {
            if votes.len() != self.codec_config().da_quorum() {
                return Err(Error::Quorum);
            }
            let header = votes[0].header().clone();
            self.ensure_chain(header.chain())?;
            self.ensure_epoch(header.epoch())?;
            if votes.iter().any(|vote| vote.header() != &header) {
                return Err(Error::Transcript);
            }

            let da = self
                .material
                .da_sharing()
                .ok_or(Error::SharingUnavailable)?;
            let subject = Subject::da_vote(&header);
            let certificate = recover(
                da,
                votes.iter().map(DaVote::share),
                subject.namespace(&self.namespace),
                &subject.message(),
                verification,
                strategy,
            )?;
            Ok(DaCertificate::new(header, certificate))
        }
    }

    /// Recovers a DA certificate from shares that passed only [`Self::precheck_da_vote`].
    ///
    /// Interpolation is checked once against the group identity, which is a complete authority
    /// over the shares it consumed: a quorum recovers the group signature exactly when every
    /// share is the correct evaluation of the group polynomial. The honest case therefore costs
    /// one pairing check for the whole quorum. A failed check proves some share is invalid, and
    /// only then does the attribution pass verify the shares against their partial public keys
    /// to name the signers responsible.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn assemble_da_certificate_optimistic<D: Digest>(
        &self,
        votes: &[DaVote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<V, D>, DaRecoveryError> {
        let error = match self.assemble_da_certificate_with(
            votes,
            SignatureVerification::Preverified,
            strategy,
        ) {
            Ok(certificate) => return Ok(certificate),
            Err(error) => error,
        };
        if error != Error::Signature {
            return Err(error.into());
        }
        // An empty attribution means every share verifies alone while the quorum does not, which
        // no share can cause. Report the recovery failure instead of blaming an honest signer.
        match self.invalid_da_shares(votes, strategy)? {
            invalid if invalid.is_empty() => Err(Error::Signature.into()),
            invalid => Err(DaRecoveryError::InvalidShares(invalid)),
        }
    }

    /// Names the signers whose data-availability shares fail against their partial public keys.
    ///
    /// Checking each share separately keeps the answer independent of any random weights, so the
    /// same quorum always attributes the same signers. The pass is bounded by the quorum and only
    /// runs behind a failed group check, which already proves a share is invalid.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn invalid_da_shares<D: Digest>(
        &self,
        votes: &[DaVote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<Vec<Participant>, Error> {
        let sharing = self
            .material
            .da_sharing()
            .ok_or(Error::SharingUnavailable)?;
        let header = votes.first().ok_or(Error::Quorum)?.header();
        let subject = Subject::da_vote(header);
        let namespace = subject.namespace(&self.namespace);
        let message = subject.message();
        let partials = votes
            .iter()
            .map(|vote| partial(vote.share()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(strategy
            .map_collect_vec(&partials, |partial| {
                threshold::verify_message(sharing, namespace, &message, partial)
                    .is_err()
                    .then_some(partial.index)
            })
            .into_iter()
            .flatten()
            .collect())
    }

    /// Recovers a nullification from exactly `2f+1` shares for one round, verifying each share.
    pub fn assemble_nullification(
        &self,
        shares: &[Nullify<V>],
        strategy: &impl Strategy,
    ) -> Result<Nullification<V>, Error> {
        self.assemble_nullification_with(shares, SignatureVerification::Checked, strategy)
    }

    mocks_pub! {
        /// Recovers a nullification from exactly `2f+1` shares for one round.
        fn assemble_nullification_with(
            &self,
            shares: &[Nullify<V>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<Nullification<V>, Error> {
            if shares.len() != self.codec_config().nullification_quorum() {
                return Err(Error::Quorum);
            }
            let round = shares[0].round();
            self.ensure_epoch(round.epoch())?;
            if shares.iter().any(|share| share.round() != round) {
                return Err(Error::Transcript);
            }

            let nullification = self
                .material
                .nullification_sharing()
                .ok_or(Error::SharingUnavailable)?;
            let subject = Subject::Nullify(round);
            let certificate = recover(
                nullification,
                shares.iter().map(Nullify::share),
                subject.namespace(&self.namespace),
                &subject.message(),
                verification,
                strategy,
            )?;
            Ok(Nullification::new(round, certificate)?)
        }
    }

    /// Assembles a V-QC from `n-f..=n` complete view messages, verifying each signature.
    pub fn assemble_vqc<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        messages: &[ViewMessage<V, D>],
        strategy: &impl Strategy,
    ) -> Result<Vqc<V, D>, Error> {
        self.assemble_vqc_with::<H, D>(leader, messages, SignatureVerification::Checked, strategy)
    }

    mocks_pub! {
        /// Assembles a V-QC from `n-f..=n` complete view messages.
        fn assemble_vqc_with<H: Hasher<Digest = D>, D: Digest>(
            &self,
            leader: LeaderBlock<V, D>,
            messages: &[ViewMessage<V, D>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<Vqc<V, D>, Error> {
            self.ensure_leader(&leader)?;
            let codec = self.codec_config();
            if !(codec.view_quorum()..=codec.vqc_max_messages()).contains(&messages.len()) {
                return Err(Error::Quorum);
            }

            let digested = DigestedLeader::new::<H>(&leader);
            let mut target = Vec::new();
            let mut conflicting = Vec::new();
            let mut novoters = Vec::new();
            let mut transcript = Vec::with_capacity(messages.len());
            let mut signatures = Vec::with_capacity(messages.len());

            for message in messages {
                match message {
                    ViewMessage::Vote(vote) => {
                        self.ensure_vote_body(vote.body())?;
                        if vote.body().round() != leader.round() {
                            return Err(Error::Transcript);
                        }
                        let signature = decoded(vote.attestation())?;
                        let subject = Subject::vote(vote.body());
                        transcript.push(TranscriptEntry {
                            signer: vote.signer(),
                            namespace: subject.namespace(&self.namespace),
                            message: subject.message(),
                        });
                        signatures.push(signature);

                        if vote.body().leader() == digested.digest() {
                            if !vote.body().valid_for(digested) {
                                return Err(Error::Transcript);
                            }
                            target.push((vote.signer(), vote.body().clone()));
                        } else {
                            conflicting.push(ConflictingVote::new(
                                vote.signer(),
                                vote.body().ballot().clone(),
                                self.codec_config(),
                            )?);
                        }
                    }
                    ViewMessage::NoVote(novote) => {
                        if novote.round() != leader.round() {
                            return Err(Error::Transcript);
                        }
                        let signature = decoded(novote.attestation())?;
                        let subject = Subject::NoVote(novote.round());
                        transcript.push(TranscriptEntry {
                            signer: novote.signer(),
                            namespace: subject.namespace(&self.namespace),
                            message: subject.message(),
                        });
                        signatures.push(signature);
                        novoters.push(novote.signer());
                    }
                }
            }
            if target.len() < self.codec_config().designation_quorum() {
                return Err(Error::Quorum);
            }

            let signature = self.aggregate(&transcript, &signatures, verification, strategy)?;
            conflicting.sort_by_key(ConflictingVote::signer);
            novoters.sort_unstable();
            let tally = Tally::from_votes(digested, target, self.codec_config())?;
            let novoters = Signers::try_from((self.participants.keys(), novoters))
                .map_err(|_| Error::Transcript)?;
            Ok(Vqc::new(
                leader,
                tally,
                novoters,
                conflicting,
                signature,
                self.codec_config(),
            )?)
        }
    }

    /// Assembles an L-QC from exactly `n-f` ordinary votes for one leader, verifying each
    /// signature.
    pub fn assemble_lqc<H: Hasher<Digest = D>, D: Digest>(
        &self,
        leader: LeaderBlock<V, D>,
        votes: &[Vote<V, D>],
        strategy: &impl Strategy,
    ) -> Result<Lqc<V, D>, Error> {
        self.assemble_lqc_with::<H, D>(leader, votes, SignatureVerification::Checked, strategy)
    }

    mocks_pub! {
        /// Assembles an L-QC from exactly `n-f` ordinary votes for one leader.
        fn assemble_lqc_with<H: Hasher<Digest = D>, D: Digest>(
            &self,
            leader: LeaderBlock<V, D>,
            votes: &[Vote<V, D>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<Lqc<V, D>, Error> {
            self.ensure_leader(&leader)?;
            if votes.len() != self.codec_config().view_quorum() {
                return Err(Error::Quorum);
            }

            let digested = DigestedLeader::new::<H>(&leader);
            let mut tally_votes = Vec::with_capacity(votes.len());
            let mut transcript = Vec::with_capacity(votes.len());
            let mut signatures = Vec::with_capacity(votes.len());
            for vote in votes {
                self.ensure_vote_body(vote.body())?;
                if !vote.body().valid_for(digested) {
                    return Err(Error::Transcript);
                }
                tally_votes.push((vote.signer(), vote.body().clone()));
                let subject = Subject::vote(vote.body());
                transcript.push(TranscriptEntry {
                    signer: vote.signer(),
                    namespace: subject.namespace(&self.namespace),
                    message: subject.message(),
                });
                signatures.push(decoded(vote.attestation())?);
            }

            let signature = self.aggregate(&transcript, &signatures, verification, strategy)?;
            let tally = Tally::from_votes(digested, tally_votes, self.codec_config())?;
            Ok(Lqc::new(leader, tally, signature, self.codec_config())?)
        }
    }

    /// Combines `signatures` into the aggregate over `transcript`, verifying each first when
    /// `verification` is [`SignatureVerification::Checked`].
    fn aggregate(
        &self,
        transcript: &[TranscriptEntry<'_>],
        signatures: &[V::Signature],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<aggregate::Signature<V>, Error> {
        if transcript.len() != signatures.len() {
            return Err(Error::Transcript);
        }
        let mut publics = HashSet::with_capacity(transcript.len());
        let entries = transcript
            .iter()
            .zip(signatures)
            .map(|(entry, signature)| {
                let public = self.public(entry.signer).ok_or(Error::Transcript)?;
                if public == &V::Public::zero() || !publics.insert(*public) {
                    return Err(Error::Signature);
                }
                Ok((public, entry.namespace, entry.message.as_ref(), signature))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        if entries.is_empty() {
            return Err(Error::Signature);
        }
        if verification == SignatureVerification::Checked {
            strategy
                .try_map_collect_vec(&entries, |(public, namespace, message, signature)| {
                    ops::verify_message::<V>(public, namespace, message, signature)
                })
                .map_err(|_| Error::Signature)?;
        }
        let signature = aggregate::combine_signatures::<V, _>(non_empty![@signatures.iter()]);
        (signature.inner() != &V::Signature::zero())
            .then_some(signature)
            .ok_or(Error::Signature)
    }
}

/// Interpolates the threshold signature over `shares`, verifying each share first when
/// `verification` is [`SignatureVerification::Checked`] and the recovered signature otherwise.
fn recover<'a, V: Variant>(
    sharing: &Sharing<V>,
    shares: impl IntoIterator<Item = &'a ThresholdShare<V>>,
    namespace: &[u8],
    message: &[u8],
    verification: SignatureVerification,
    strategy: &impl Strategy,
) -> Result<certificate_threshold::Certificate<V>, Error> {
    let partials = shares
        .into_iter()
        .map(partial)
        .collect::<Result<Vec<_>, _>>()?;
    if verification == SignatureVerification::Checked {
        strategy
            .try_map_collect_vec(&partials, |share| {
                threshold::verify_message(sharing, namespace, message, share)
            })
            .map_err(|_| Error::Signature)?;
    }
    let signature =
        threshold::recover(sharing, &partials, strategy).map_err(|_| Error::Signature)?;
    if signature == V::Signature::zero()
        || verification == SignatureVerification::Preverified
            && ops::verify_message::<V>(sharing.public(), namespace, message, &signature).is_err()
    {
        return Err(Error::Signature);
    }
    Ok(certificate_threshold::Certificate::new(signature))
}

/// A certificate's reconstructed signed messages and the vote bodies they carry.
pub(super) struct Transcript<'a, D: Digest> {
    /// Every signed message, in signer order.
    pub(super) entries: Vec<TranscriptEntry<'a>>,
    /// The expanded vote bodies.
    pub(super) votes: CertificateVotes<D>,
}

/// Reconstructs the signed vote of every tally signer for `leader`.
pub(super) fn tally_transcript<'a, V, D, H>(
    leader: &LeaderBlock<V, D>,
    tally: &Tally<D>,
    config: CodecConfig,
    namespace: &'a Namespace,
) -> Result<Transcript<'a, D>, Error>
where
    V: Variant,
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
        let subject = Subject::vote(&body);
        entries.push(TranscriptEntry {
            signer,
            namespace: subject.namespace(namespace),
            message: subject.message(),
        });
        votes.designated.push((signer, body));
    }
    Ok(Transcript { entries, votes })
}

/// Reconstructs every signed view message of a V-QC, in signer order.
pub(super) fn vqc_transcript<'a, V, D, H>(
    certificate: &Vqc<V, D>,
    config: CodecConfig,
    namespace: &'a Namespace,
) -> Result<Transcript<'a, D>, Error>
where
    V: Variant,
    D: Digest,
    H: Hasher<Digest = D>,
{
    let leader = certificate.leader();
    let Transcript {
        entries: mut transcript,
        mut votes,
    } = tally_transcript::<V, D, H>(leader, certificate.tally(), config, namespace)?;
    let leader_digest = votes.leader;
    for signer in certificate.novoters().iter() {
        let subject = Subject::NoVote(leader.round());
        transcript.push(TranscriptEntry {
            signer,
            namespace: subject.namespace(namespace),
            message: subject.message(),
        });
    }
    for vote in certificate.conflicting_votes() {
        if vote.leader() == leader_digest {
            return Err(Error::Transcript);
        }
        let body = vote.vote_body(leader.round())?;
        let subject = Subject::vote(&body);
        transcript.push(TranscriptEntry {
            signer: vote.signer(),
            namespace: subject.namespace(namespace),
            message: subject.message(),
        });
        votes.conflicting.push((vote.signer(), body));
    }
    transcript.sort_by_key(|entry| entry.signer);
    if !(config.view_quorum()..=config.vqc_max_messages()).contains(&transcript.len())
        || transcript
            .windows(2)
            .any(|pair| pair[0].signer == pair[1].signer)
    {
        return Err(Error::Transcript);
    }
    Ok(Transcript {
        entries: transcript,
        votes,
    })
}
