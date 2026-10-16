//! Certificate assembly from attested vote contents.

use super::{Contents, Error, Scheme, claims::nonzero};
use crate::{
    Epochable,
    multimmit::types::{
        Attestation, CertificateId, FinalTally, LeaderBlock, Lqc, ResolutionPath, VoteContent,
        VoteTally, Vqc,
    },
    types::Attributable as _,
};
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    bls12381::primitives::{ops::aggregate, variant::Variant},
};
use commonware_parallel::Strategy;
use commonware_utils::non_empty;
use rand_core::CryptoRng;

/// Whether assembly verifies the aggregate it produces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureVerification {
    /// Verify the assembled aggregate against every recorded content before returning it.
    Checked,
    /// Skip verification: every input attestation was already verified over its content.
    Preverified,
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Assembles a V-QC extending `parent` from exactly `n - f` final votes of one view and the
    /// resolution paths of their tips above the base.
    ///
    /// Assembly checks the transcript shape and the signature; whether the paths resolve every
    /// tip above the base depends on the parent chain and is checked when the V-QC is admitted.
    pub fn assemble_vqc<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        parent: CertificateId<D>,
        votes: &[(VoteContent<D>, Attestation<V>)],
        paths: Vec<ResolutionPath<D>>,
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<Vqc<V, D>, Error> {
        let round = votes.first().ok_or(Error::Transcript)?.0.round();
        let (contents, signature) = self.aggregate(rng, votes, verification, strategy)?;
        let tally = FinalTally::from_contents(contents, paths, self.codec_config())?;
        Ok(Vqc::new(
            round,
            parent,
            tally,
            signature,
            self.codec_config(),
        )?)
    }

    /// Assembles an L-QC for `leader` from exactly `n - f` votes for it, final or not.
    pub fn assemble_lqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        leader: LeaderBlock<D>,
        votes: &[(VoteContent<D>, Attestation<V>)],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<Lqc<V, D>, Error> {
        self.ensure_epoch(leader.epoch())?;
        if votes
            .iter()
            .any(|(content, _)| content.round() != leader.round())
        {
            return Err(Error::Transcript);
        }
        let (contents, signature) = self.aggregate(rng, votes, verification, strategy)?;
        let tally = VoteTally::from_contents(leader.digest::<H>(), contents, self.codec_config())?;
        Ok(Lqc::new(leader, tally, signature))
    }

    /// Sums the attestations of `votes` into one aggregate over their contents, verifying it when
    /// `verification` is [`SignatureVerification::Checked`].
    fn aggregate<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        votes: &[(VoteContent<D>, Attestation<V>)],
        verification: SignatureVerification,
        strategy: &impl Strategy,
    ) -> Result<(Contents<D>, aggregate::Signature<V>), Error> {
        let signatures = votes
            .iter()
            .map(|(_, attestation)| {
                attestation
                    .signature()
                    .and_then(nonzero)
                    .ok_or(Error::Signature)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if signatures.is_empty() {
            return Err(Error::Transcript);
        }
        let signature = aggregate::combine_signatures::<V, _>(non_empty![@signatures.iter()]);
        let contents: Vec<_> = votes
            .iter()
            .map(|(content, attestation)| (attestation.signer(), content.clone()))
            .collect();
        if contents
            .iter()
            .any(|(signer, content)| !self.content_fits(content) || self.public(*signer).is_none())
        {
            return Err(Error::Transcript);
        }
        if verification == SignatureVerification::Checked
            && !self.verify_tally(rng, &contents, &signature, strategy)
        {
            return Err(Error::Signature);
        }
        Ok((contents, signature))
    }
}
