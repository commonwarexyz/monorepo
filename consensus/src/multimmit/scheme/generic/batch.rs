//! Batch verification of mixed artifacts with per-artifact attribution.

use super::{
    Generic,
    checks::{Checks, aggregate_check},
    transcript::{Transcript, tally_transcript, vqc_transcript},
};
use crate::{
    Epochable,
    multimmit::{
        scheme::{AggregateOf, Scheme, Verified},
        types::{Artifact, Lqc, VoteBody, Vqc},
    },
};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use rand_core::CryptoRng;

/// The expanded vote bodies of a verified V-QC or L-QC.
pub(crate) struct CertificateVotes<D: Digest> {
    /// The leader digest the designated votes support.
    pub(crate) leader: D,
    /// The votes for the certified leader, in signer order.
    pub(crate) designated: Vec<(Participant, VoteBody<D>)>,
    /// The votes for other leaders, in signer order.
    pub(crate) conflicting: Vec<(Participant, VoteBody<D>)>,
}

/// The checks of one artifact, and the vote bodies of a V-QC or L-QC.
pub(super) struct ArtifactChecks<'k, S: Scheme, D: Digest> {
    pub(super) checks: Checks<'k, S>,
    votes: Option<CertificateVotes<D>>,
}

impl<'k, S: Scheme, D: Digest> ArtifactChecks<'k, S, D> {
    const fn without_votes(checks: Checks<'k, S>) -> Self {
        Self {
            checks,
            votes: None,
        }
    }
}

impl<S: Scheme> Generic<S> {
    /// Verifies a batch of artifacts, returning one verdict per artifact.
    ///
    /// `known` holds, per artifact, messages the node already verified (see [`Verified`]). A
    /// known message can only make verification cheaper: a forged or mismatched one fails its
    /// artifact or is ignored, and never passes an invalid artifact.
    pub fn verify_artifacts<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        artifacts: &[&Artifact<S, D>],
        known: &[&[Verified<'_, S, D>]],
        strategy: &impl Strategy,
    ) -> Vec<bool> {
        self.verify_artifacts_expanded::<R, H, D>(rng, artifacts, known, strategy)
            .into_iter()
            .map(|result| result.is_ok())
            .collect()
    }

    /// Verifies a batch of artifacts, returning the expanded votes of each verified V-QC and
    /// L-QC.
    pub(crate) fn verify_artifacts_expanded<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        artifacts: &[&Artifact<S, D>],
        known: &[&[Verified<'_, S, D>]],
        strategy: &impl Strategy,
    ) -> Vec<Result<Option<CertificateVotes<D>>, ()>> {
        // Structural checks and check extraction run per artifact; message construction and
        // transcript reconstruction dominate, so they parallelize.
        let inputs = artifacts
            .iter()
            .enumerate()
            .map(|(index, artifact)| (*artifact, known.get(index).copied().unwrap_or(&[])))
            .collect::<Vec<_>>();
        let extracted: Vec<_> = strategy.map_collect_vec(&inputs, |(artifact, known)| {
            self.artifact_checks::<H, D>(artifact, known)
        });
        let (checks, votes): (Vec<_>, Vec<_>) = extracted
            .into_iter()
            .map(|extracted| match extracted {
                Some(ArtifactChecks { checks, votes }) => (Some(checks), votes),
                None => (None, None),
            })
            .unzip();
        let valid = self.verify_checks(rng, &checks, strategy);
        valid
            .into_iter()
            .zip(votes)
            .map(|(valid, votes)| if valid { Ok(votes) } else { Err(()) })
            .collect()
    }

    fn artifact_checks<'k, H: Hasher<Digest = D>, D: Digest>(
        &self,
        artifact: &'k Artifact<S, D>,
        known: &[Verified<'k, S, D>],
    ) -> Option<ArtifactChecks<'k, S, D>> {
        let checks = match artifact {
            Artifact::TransactionBlock(block) => self.transaction_block_checks(block)?,
            Artifact::DaVote(vote) => self.da_vote_checks(vote)?,
            Artifact::DaCertificate(certificate) => self.da_certificate_checks(certificate)?,
            Artifact::LeaderBlock(block) => self.leader_block_checks(block, known)?,
            Artifact::Vote(vote) => self.vote_checks(vote)?,
            Artifact::NoVote(novote) => self.novote_checks(novote)?,
            Artifact::Nullify(nullify) => self.nullify_checks(nullify)?,
            Artifact::Nullification(certificate) => self.nullification_checks(certificate)?,
            Artifact::Vqc(certificate) => return self.vqc_checks::<H, D>(certificate, known),
            Artifact::Lqc(certificate) => return self.lqc_checks::<H, D>(certificate, known),
        };
        Some(ArtifactChecks::without_votes(checks))
    }

    /// Builds the checks for a V-QC after its structural checks.
    pub(super) fn vqc_checks<'k, H: Hasher<Digest = D>, D: Digest>(
        &self,
        certificate: &'k Vqc<S, D>,
        known: &[Verified<'k, S, D>],
    ) -> Option<ArtifactChecks<'k, S, D>> {
        if self.ensure_epoch(certificate.epoch()).is_err()
            || certificate.validate(self.codec_config()).is_err()
            || self
                .distinct_chain_limits()
                .is_some_and(|limits| certificate.leader().validate_chain_limits(limits).is_err())
        {
            return None;
        }
        let transcript = vqc_transcript::<S, D, H>(certificate, self.codec_config()).ok()?;
        self.certificate_checks(transcript, certificate.signature(), known)
    }

    /// Builds the checks for an L-QC after its structural checks.
    pub(super) fn lqc_checks<'k, H: Hasher<Digest = D>, D: Digest>(
        &self,
        certificate: &'k Lqc<S, D>,
        known: &[Verified<'k, S, D>],
    ) -> Option<ArtifactChecks<'k, S, D>> {
        if self.ensure_epoch(certificate.epoch()).is_err()
            || certificate.validate(self.codec_config()).is_err()
            || self
                .distinct_chain_limits()
                .is_some_and(|limits| certificate.leader().validate_chain_limits(limits).is_err())
        {
            return None;
        }
        let transcript = tally_transcript::<S, D, H>(
            certificate.leader(),
            certificate.tally(),
            self.codec_config(),
        )
        .ok()?;
        self.certificate_checks(transcript, certificate.signature(), known)
    }

    fn certificate_checks<'k, D: Digest>(
        &self,
        transcript: Transcript<D>,
        aggregate: &'k AggregateOf<S>,
        known: &[Verified<'k, S, D>],
    ) -> Option<ArtifactChecks<'k, S, D>> {
        // Designated bodies are rebuilt under this epoch's codec, but conflicting ballots are kept
        // as decoded, so they are held to the chain limits even when every chain shares them.
        let chain_limits = self.parameters.chain_limits();
        let designated = self
            .distinct_chain_limits()
            .map_or(&[][..], |_| &transcript.votes.designated[..]);
        if designated
            .iter()
            .chain(&transcript.votes.conflicting)
            .any(|(_, body)| body.validate_chain_limits(chain_limits).is_err())
        {
            return None;
        }
        let Transcript { entries, votes } = transcript;
        let checks = Checks {
            ordinary: vec![aggregate_check(entries, aggregate, known)],
            ..Checks::default()
        };
        Some(ArtifactChecks {
            checks,
            votes: Some(votes),
        })
    }
}
