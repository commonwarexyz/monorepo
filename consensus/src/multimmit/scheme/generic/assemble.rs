//! Assembly of data-availability certificates, nullifications, V-QCs, and L-QCs.

#[cfg(not(target_arch = "wasm32"))]
use super::DaRecoveryError;
use super::{Error, Generic};
use crate::{
    Epochable,
    multimmit::{
        scheme::{AggregateOf, DaSubject, NullifySubject, OrdinarySubject, RoleDigest, Scheme},
        types::{
            ConflictingVote, DaCertificate, DaVote, DigestedLeader, LeaderBlock, Lqc,
            Nullification, Nullify, Tally, ViewMessage, Vote, Vqc,
        },
    },
    types::Attributable as _,
};
use commonware_cryptography::{
    Digest, Hasher,
    certificate::{self, Aggregator as _, AssemblyError, Attestation, Item, Signers},
};
use commonware_parallel::Strategy;
#[cfg(not(target_arch = "wasm32"))]
use commonware_utils::Participant;
use commonware_utils::iter::NonEmpty;
use rand_core::CryptoRng;

/// Whether assembly verifies each input signature or trusts that the caller already has.
///
/// [`Self::Preverified`] is for inputs already verified individually or batch-verified upstream.
/// A data-availability certificate or nullification assembled from preverified attestations is
/// still verified once before it is returned, because a certificate formed from attestations
/// that verify individually need not verify itself. Aggregation (V-QCs and L-QCs) runs no
/// verification at all in that mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureVerification {
    /// Verify every input signature before assembling.
    Checked,
    /// Trust that every input signature was verified.
    Preverified,
}

impl<S: Scheme> Generic<S> {
    /// Assembles a data-availability certificate from exactly a DA quorum of votes for one
    /// header, verifying each vote.
    pub fn assemble_da_certificate<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<S, D>, Error> {
        self.assemble_da_certificate_with(rng, votes, SignatureVerification::Checked, strategy)
    }

    mocks_pub! {
        /// Assembles a data-availability certificate from exactly a DA quorum of votes for one
        /// header.
        fn assemble_da_certificate_with<R: CryptoRng, D: Digest>(
            &self,
            rng: &mut R,
            votes: &[DaVote<S, D>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<DaCertificate<S, D>, Error> {
            self.assemble_da(
                rng,
                votes,
                self.codec_config().da_quorum(),
                verification,
                strategy,
            )
        }
    }

    /// Assembles a payment chain's receipt from exactly [`Self::receipt_quorum`] votes for one
    /// header, verifying each vote.
    ///
    /// Fails with [`Error::Receipts`] when the suite's DA certificates do not reveal their
    /// signers.
    pub fn assemble_receipt<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<S, D>, Error> {
        self.assemble_receipt_with(rng, votes, SignatureVerification::Checked, strategy)
    }

    fn assemble_receipt_with<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<S, D>, Error> {
        if !<S::Da as certificate::Scheme>::is_attributable() {
            return Err(Error::Receipts);
        }
        let receipt = self.assemble_da(rng, votes, self.receipt_quorum(), verification, strategy)?;
        if !self.is_receipt(receipt.certificate()) {
            return Err(Error::Receipt);
        }
        Ok(receipt)
    }

    /// Assembles a data-availability certificate from exactly `quorum` votes for one header.
    fn assemble_da<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        quorum: usize,
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<S, D>, Error> {
        if !self.attestations {
            return Err(Error::SharingUnavailable);
        }
        if votes.len() != quorum {
            return Err(Error::Quorum);
        }
        let header = votes[0].header().clone();
        self.ensure_chain(header.chain())?;
        self.ensure_epoch(header.epoch())?;
        if votes.iter().any(|vote| vote.header() != &header) {
            return Err(Error::Transcript);
        }
        let certificate = assemble_role(
            &self.da,
            rng,
            DaSubject::new(&header),
            votes.iter().map(DaVote::attestation),
            verification,
            strategy,
        )?;
        Ok(DaCertificate::new(header, certificate))
    }

    /// Assembles a data-availability certificate from votes that were not verified, attributing
    /// invalid votes when the certificate does not verify.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn assemble_da_certificate_optimistic<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<S, D>, DaRecoveryError> {
        let assembled = self.assemble_da_certificate_with(
            rng,
            votes,
            SignatureVerification::Preverified,
            strategy,
        );
        self.attribute_da_failure(rng, votes, assembled, strategy)
    }

    /// Assembles a payment chain's receipt from votes that were not verified, attributing
    /// invalid votes when the receipt does not verify.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn assemble_receipt_optimistic<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<S, D>, DaRecoveryError> {
        let assembled =
            self.assemble_receipt_with(rng, votes, SignatureVerification::Preverified, strategy);
        self.attribute_da_failure(rng, votes, assembled, strategy)
    }

    /// Returns an optimistic DA assembly's certificate, or attributes its signature failure to
    /// the votes that fail on their own.
    #[cfg(not(target_arch = "wasm32"))]
    fn attribute_da_failure<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        assembled: Result<DaCertificate<S, D>, Error>,
        strategy: &impl Strategy,
    ) -> Result<DaCertificate<S, D>, DaRecoveryError> {
        let error = match assembled {
            Ok(certificate) => return Ok(certificate),
            Err(error) => error,
        };
        if error != Error::Signature {
            return Err(error.into());
        }
        // An empty attribution means every attestation verifies alone while the certificate
        // does not, which no attestation can cause. Report the failure instead of blaming an
        // honest signer.
        match self.invalid_da_votes(rng, votes, strategy)? {
            invalid if invalid.is_empty() => Err(Error::Signature.into()),
            invalid => Err(DaRecoveryError::InvalidShares(invalid)),
        }
    }

    /// Returns the signers of the votes that fail verification on their own.
    #[cfg(not(target_arch = "wasm32"))]
    pub(super) fn invalid_da_votes<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[DaVote<S, D>],
        strategy: &impl Strategy,
    ) -> Result<Vec<Participant>, Error> {
        if !self.attestations {
            return Err(Error::SharingUnavailable);
        }
        let header = votes.first().ok_or(Error::Quorum)?.header();
        let verification = certificate::Scheme::verify_attestations::<_, RoleDigest, _>(
            &self.da,
            rng,
            DaSubject::new(header),
            votes
                .iter()
                .map(|vote| vote.attestation().clone())
                .collect::<Vec<_>>(),
            strategy,
        );
        Ok(verification.invalid)
    }

    /// Assembles a nullification from exactly `2f + 1` nullify shares for one round, verifying
    /// each share.
    pub fn assemble_nullification<R: CryptoRng>(
        &self,
        rng: &mut R,
        shares: &[Nullify<S>],
        strategy: &impl Strategy,
    ) -> Result<Nullification<S>, Error> {
        self.assemble_nullification_with(rng, shares, SignatureVerification::Checked, strategy)
    }

    mocks_pub! {
        /// Assembles a nullification from exactly `2f + 1` nullify shares for one round.
        fn assemble_nullification_with<R: CryptoRng>(
            &self,
            rng: &mut R,
            shares: &[Nullify<S>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<Nullification<S>, Error> {
            if !self.attestations {
                return Err(Error::SharingUnavailable);
            }
            if shares.len() != self.codec_config().nullification_quorum() {
                return Err(Error::Quorum);
            }
            let round = shares[0].round();
            self.ensure_epoch(round.epoch())?;
            if shares.iter().any(|share| share.round() != round) {
                return Err(Error::Transcript);
            }
            let certificate = assemble_role(
                &self.nullify,
                rng,
                NullifySubject::new(round),
                shares.iter().map(Nullify::attestation),
                verification,
                strategy,
            )?;
            Ok(Nullification::new(round, certificate)?)
        }
    }

    /// Assembles a V-QC from `n-f..=n` complete view messages, verifying each signature.
    pub fn assemble_vqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        leader: LeaderBlock<S, D>,
        messages: &[ViewMessage<S, D>],
        strategy: &impl Strategy,
    ) -> Result<Vqc<S, D>, Error> {
        self.assemble_vqc_with::<R, H, D>(
            rng,
            leader,
            messages,
            SignatureVerification::Checked,
            strategy,
        )
    }

    mocks_pub! {
        /// Assembles a V-QC from `n-f..=n` complete view messages.
        fn assemble_vqc_with<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
            &self,
            rng: &mut R,
            leader: LeaderBlock<S, D>,
            messages: &[ViewMessage<S, D>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<Vqc<S, D>, Error> {
            self.ensure_leader(&leader)?;
            let codec = self.codec_config();
            if !(codec.view_quorum()..=codec.vqc_max_messages()).contains(&messages.len()) {
                return Err(Error::Quorum);
            }

            let digested = DigestedLeader::new::<H>(&leader);
            let mut target = Vec::new();
            let mut conflicting = Vec::new();
            let mut novoters = Vec::new();
            let mut signed = Vec::with_capacity(messages.len());
            for message in messages {
                match message {
                    ViewMessage::Vote(vote) => {
                        self.ensure_vote_body(vote.body())?;
                        if vote.body().round() != leader.round() {
                            return Err(Error::Transcript);
                        }
                        signed.push((OrdinarySubject::vote(vote.body()), vote.attestation()));
                        if vote.body().leader() == digested.digest() {
                            if !vote.body().valid_for(digested) {
                                return Err(Error::Transcript);
                            }
                            target.push((vote.signer(), vote.body().clone()));
                        } else {
                            conflicting.push(ConflictingVote::new(
                                vote.signer(),
                                vote.body().ballot().clone(),
                                codec,
                            )?);
                        }
                    }
                    ViewMessage::NoVote(novote) => {
                        if novote.round() != leader.round() {
                            return Err(Error::Transcript);
                        }
                        signed.push((OrdinarySubject::novote(novote.round()), novote.attestation()));
                        novoters.push(novote.signer());
                    }
                }
            }
            if target.len() < codec.designation_quorum() {
                return Err(Error::Quorum);
            }

            let aggregate = self.aggregate(rng, signed, verification, strategy)?;
            conflicting.sort_by_key(ConflictingVote::signer);
            novoters.sort_unstable();
            let tally = Tally::from_votes(digested, target, codec)?;
            let novoters = Signers::try_from((self.participants(), novoters))
                .map_err(|_| Error::Transcript)?;
            Ok(Vqc::new(leader, tally, novoters, conflicting, aggregate, codec)?)
        }
    }

    /// Assembles an L-QC from exactly `n-f` votes for one leader, verifying each signature.
    pub fn assemble_lqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        leader: LeaderBlock<S, D>,
        votes: &[Vote<S, D>],
        strategy: &impl Strategy,
    ) -> Result<Lqc<S, D>, Error> {
        self.assemble_lqc_with::<R, H, D>(
            rng,
            leader,
            votes,
            SignatureVerification::Checked,
            strategy,
        )
    }

    mocks_pub! {
        /// Assembles an L-QC from exactly `n-f` votes for one leader.
        fn assemble_lqc_with<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
            &self,
            rng: &mut R,
            leader: LeaderBlock<S, D>,
            votes: &[Vote<S, D>],
            verification: SignatureVerification,
            strategy: &impl Strategy,
        ) -> Result<Lqc<S, D>, Error> {
            self.ensure_leader(&leader)?;
            let codec = self.codec_config();
            if votes.len() != codec.view_quorum() {
                return Err(Error::Quorum);
            }

            let digested = DigestedLeader::new::<H>(&leader);
            let mut tally_votes = Vec::with_capacity(votes.len());
            let mut signed = Vec::with_capacity(votes.len());
            for vote in votes {
                self.ensure_vote_body(vote.body())?;
                if !vote.body().valid_for(digested) {
                    return Err(Error::Transcript);
                }
                tally_votes.push((vote.signer(), vote.body().clone()));
                signed.push((OrdinarySubject::vote(vote.body()), vote.attestation()));
            }

            let aggregate = self.aggregate(rng, signed, verification, strategy)?;
            let tally = Tally::from_votes(digested, tally_votes, codec)?;
            Ok(Lqc::new(leader, tally, aggregate, codec)?)
        }
    }

    /// Aggregates ordinary attestations over their subjects in ascending signer order, the order
    /// a certificate transcript reconstructs them in.
    fn aggregate<R: CryptoRng>(
        &self,
        rng: &mut R,
        mut signed: Vec<(OrdinarySubject, &Attestation<S::Ordinary>)>,
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<AggregateOf<S>, Error> {
        signed.sort_by_key(|(_, attestation)| attestation.signer);
        if verification == SignatureVerification::Checked {
            let items = signed
                .iter()
                .map(|(subject, attestation)| Item::Attestation {
                    subject: subject.clone(),
                    attestation: *attestation,
                })
                .collect::<Vec<_>>();
            if !self
                .ordinary
                .verify_aggregates::<_, RoleDigest>(rng, &items, strategy)
                .into_iter()
                .all(core::convert::identity)
            {
                return Err(Error::Signature);
            }
        }
        let attestations = NonEmpty::try_new(signed.iter().map(|(_, attestation)| *attestation))
            .ok_or(Error::Quorum)?;
        self.ordinary
            .aggregate(attestations)
            .map_err(assembly_error)
    }
}

/// Maps an assembly failure to the Multimmit error it represents.
const fn assembly_error(error: AssemblyError) -> Error {
    match error {
        AssemblyError::UnknownSigner { .. } => Error::Transcript,
        _ => Error::Signature,
    }
}

/// Assembles a role certificate over one subject, verifying the attestations first or the
/// certificate after.
fn assemble_role<'a, R, T, G>(
    role: &R,
    rng: &mut G,
    subject: T,
    attestations: impl Iterator<Item = &'a Attestation<R>>,
    verification: SignatureVerification,
    strategy: &impl Strategy,
) -> Result<R::Certificate, Error>
where
    R: for<'s> certificate::Scheme<Subject<'s, RoleDigest> = T>,
    T: Clone,
    G: CryptoRng,
{
    let attestations = attestations.cloned().collect::<Vec<_>>();
    if verification == SignatureVerification::Checked {
        let verification = role.verify_attestations::<_, RoleDigest, _>(
            rng,
            subject.clone(),
            attestations.clone(),
            strategy,
        );
        if !verification.invalid.is_empty() {
            return Err(Error::Signature);
        }
    }
    let attestations = NonEmpty::try_new(attestations.into_iter()).ok_or(Error::Quorum)?;
    let certificate = role
        .assemble(attestations, strategy)
        .map_err(assembly_error)?;
    if verification == SignatureVerification::Preverified
        && !role.verify_certificate::<_, RoleDigest>(rng, subject, &certificate, strategy)
    {
        return Err(Error::Signature);
    }
    Ok(certificate)
}
