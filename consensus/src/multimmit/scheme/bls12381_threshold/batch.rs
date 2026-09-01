//! Batch verification of heterogeneous artifacts, discharging known messages.

use super::{
    Scheme,
    assemble::{Transcript, tally_transcript, vqc_transcript},
    claims::{Claim, OwnedTerm, TranscriptEntry, decoded},
};
use crate::{
    Epochable,
    multimmit::{
        scheme::{Subject, Verified},
        types::{Artifact, Lqc, VoteBody, Vqc},
    },
    types::Attributable as _,
};
use bytes::Bytes;
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    bls12381::primitives::{
        ops::{aggregate, batch},
        variant::Variant,
    },
    certificate::Subject as _,
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use rand_core::CryptoRng;
use std::collections::{HashMap, HashSet};

/// The expanded vote bodies of a verified V-QC or L-QC.
///
/// Novotes carry no vote body and are not included.
pub(crate) struct CertificateVotes<D: Digest> {
    /// Digest of the certificate's designated leader block.
    pub(crate) leader: D,
    /// Votes for the designated leader, which contribute to safe tips.
    pub(crate) designated: Vec<(Participant, VoteBody<D>)>,
    /// Votes for other leader blocks in the same view, retained as finality evidence.
    pub(crate) conflicting: Vec<(Participant, VoteBody<D>)>,
}

/// One artifact's pairing claims, plus the expanded votes when it is a certificate.
pub(super) struct ArtifactClaims<'a, V: Variant, D: Digest> {
    pub(super) claims: Vec<Claim<'a, V>>,
    votes: Option<CertificateVotes<D>>,
}

impl<'a, V: Variant, D: Digest> ArtifactClaims<'a, V, D> {
    const fn without_votes(claims: Vec<Claim<'a, V>>) -> Self {
        Self {
            claims,
            votes: None,
        }
    }
}

/// A known message's signature and the term it signs, keyed by signer.
struct KnownTerm<'a, V: Variant> {
    namespace: &'a [u8],
    message: Bytes,
    signature: V::Signature,
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Verifies a heterogeneous artifact batch and returns one verdict per input item.
    ///
    /// Items are independent: an invalid artifact cannot poison a valid neighbor. `known[i]`
    /// lists messages the caller already verified that accompany `artifacts[i]`; missing entries
    /// mean nothing is known. A certificate transcript term is discharged when a known message
    /// from the same signer reproduces it exactly, and a leader-block anchor is discharged when
    /// the identical DA certificate is known. A forged or mismatched known message can only fail
    /// an artifact, never pass one.
    ///
    /// Every artifact decomposes into pairing claims, and the whole batch is checked as one
    /// randomly scaled pairing product costing one pairing per distinct message instead of one
    /// per signature. On failure, bisection isolates the invalid artifacts; an invalid
    /// signature is attributable evidence of misbehavior, so the optimistic path is the
    /// common case.
    pub fn verify_artifacts<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        artifacts: &[&Artifact<V, D>],
        known: &[&[Verified<'_, V, D>]],
        strategy: &impl Strategy,
    ) -> Vec<bool> {
        self.verify_artifacts_expanded::<R, H, D>(rng, artifacts, known, strategy)
            .into_iter()
            .map(|result| result.is_ok())
            .collect()
    }

    /// Returns reconstructed certificate votes only for authenticated artifacts, in input order.
    pub(crate) fn verify_artifacts_expanded<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        artifacts: &[&Artifact<V, D>],
        known: &[&[Verified<'_, V, D>]],
        strategy: &impl Strategy,
    ) -> Vec<Result<Option<CertificateVotes<D>>, ()>> {
        // Structural checks and claim extraction run per artifact; message construction and
        // transcript reconstruction dominate, so they parallelize.
        let inputs = artifacts
            .iter()
            .enumerate()
            .map(|(index, artifact)| (artifact, known.get(index).copied().unwrap_or(&[])))
            .collect::<Vec<_>>();
        let mut claims: Vec<_> = strategy.map_collect_vec(&inputs, |(artifact, known)| {
            self.artifact_claims::<H, D>(artifact, known)
        });

        let claim_count = claims
            .iter()
            .filter_map(Option::as_ref)
            .map(|artifact| artifact.claims.len())
            .sum();
        let mut owners = Vec::with_capacity(claim_count);
        let mut batched = Vec::with_capacity(claim_count);
        for (index, set) in claims.iter().enumerate() {
            let Some(set) = set else {
                continue;
            };
            for claim in &set.claims {
                owners.push(index);
                batched.push(claim.as_batch());
            }
        }
        for invalid in batch::verify_claims(rng, &batched, strategy) {
            claims[owners[invalid]] = None;
        }
        claims
            .into_iter()
            .map(|claims| claims.map(|artifact| artifact.votes).ok_or(()))
            .collect()
    }

    /// Decomposes one artifact into its pairing claims, running every structural check.
    ///
    /// Returns `None` when the artifact fails a non-cryptographic check; otherwise the
    /// artifact is valid exactly when every returned claim's pairing product holds.
    fn artifact_claims<'a, H: Hasher<Digest = D>, D: Digest>(
        &'a self,
        artifact: &Artifact<V, D>,
        known: &[Verified<'_, V, D>],
    ) -> Option<ArtifactClaims<'a, V, D>> {
        let claims = match artifact {
            Artifact::TransactionBlock(block) => vec![self.transaction_block_claim(block)?],
            Artifact::DaVote(vote) => vec![self.da_vote_claim(vote)?],
            Artifact::DaCertificate(certificate) => vec![self.da_certificate_claim(certificate)?],
            Artifact::LeaderBlock(block) => self.leader_block_claims(block, known)?,
            Artifact::Vote(vote) => vec![self.vote_claim(vote)?],
            Artifact::NoVote(novote) => vec![self.novote_claim(novote)?],
            Artifact::Nullify(nullify) => vec![self.nullify_claim(nullify)?],
            Artifact::Nullification(certificate) => {
                vec![self.nullification_claim(certificate)?]
            }
            Artifact::Vqc(certificate) => return self.vqc_claims::<H, D>(certificate, known),
            Artifact::Lqc(certificate) => return self.lqc_claims::<H, D>(certificate, known),
        };
        Some(ArtifactClaims::without_votes(claims))
    }

    /// Builds the claims for a V-QC after its structural checks.
    pub(super) fn vqc_claims<'a, H: Hasher<Digest = D>, D: Digest>(
        &'a self,
        certificate: &Vqc<V, D>,
        known: &[Verified<'_, V, D>],
    ) -> Option<ArtifactClaims<'a, V, D>> {
        if self.ensure_epoch(certificate.epoch()).is_err()
            || certificate.validate(self.codec_config()).is_err()
        {
            return None;
        }
        let transcript =
            vqc_transcript::<V, D, H>(certificate, self.codec_config(), &self.namespace).ok()?;
        self.certificate_claims(transcript, certificate.signature()?, known)
    }

    /// Builds the claims for an L-QC after its structural checks.
    pub(super) fn lqc_claims<'a, H: Hasher<Digest = D>, D: Digest>(
        &'a self,
        certificate: &Lqc<V, D>,
        known: &[Verified<'_, V, D>],
    ) -> Option<ArtifactClaims<'a, V, D>> {
        if self.ensure_epoch(certificate.epoch()).is_err()
            || certificate.validate(self.codec_config()).is_err()
        {
            return None;
        }
        let transcript = tally_transcript::<V, D, H>(
            certificate.leader(),
            certificate.tally(),
            self.codec_config(),
            &self.namespace,
        )
        .ok()?;
        self.certificate_claims(transcript, certificate.signature()?, known)
    }

    /// Builds the claims for a certificate from its reconstructed transcript and aggregate.
    fn certificate_claims<'a, D: Digest>(
        &'a self,
        transcript: Transcript<'a, D>,
        signature: &aggregate::Signature<V>,
        known: &[Verified<'_, V, D>],
    ) -> Option<ArtifactClaims<'a, V, D>> {
        Some(ArtifactClaims {
            claims: self.reduced_aggregate_claim(&transcript.entries, signature, known)?,
            votes: Some(transcript.votes),
        })
    }

    /// Builds the pairing claims for an aggregate transcript after discharging every term whose
    /// signature is known from a locally verified message.
    ///
    /// BLS signatures are unique per key and message, so a valid aggregate over the transcript
    /// must contain exactly the known signature for every discharged term. Subtracting those
    /// leaves an aggregate over the remaining terms alone; an empty remainder must then equal the
    /// identity. Returns no claims when everything was discharged and the remainder holds.
    fn reduced_aggregate_claim<'a, D: Digest>(
        &'a self,
        transcript: &[TranscriptEntry<'a>],
        signature: &aggregate::Signature<V>,
        known: &[Verified<'_, V, D>],
    ) -> Option<Vec<Claim<'a, V>>> {
        if known.is_empty() {
            return self
                .aggregate_claim(transcript, signature)
                .map(|claim| vec![claim]);
        }
        if transcript.is_empty() || signature.inner() == &V::Signature::zero() {
            return None;
        }
        let mut discharged: HashMap<Participant, KnownTerm<'_, V>> =
            HashMap::with_capacity(known.len());
        for message in known {
            let (signer, subject, attestation) = match message {
                Verified::Vote(vote) => (
                    vote.signer(),
                    Subject::vote(vote.body()),
                    vote.attestation(),
                ),
                Verified::NoVote(vote) => (
                    vote.signer(),
                    Subject::NoVote(vote.round()),
                    vote.attestation(),
                ),
                // Certificates discharge leader-block anchors, never aggregate transcripts.
                Verified::DaCertificate(_) => continue,
            };
            let Ok(signature) = decoded(attestation) else {
                continue;
            };
            discharged.insert(
                signer,
                KnownTerm {
                    namespace: subject.namespace(&self.namespace),
                    message: subject.message(),
                    signature,
                },
            );
        }
        let mut publics = HashSet::with_capacity(transcript.len());
        let mut remainder = *signature.inner();
        let mut terms = Vec::with_capacity(transcript.len());
        for entry in transcript {
            let public = self.public(entry.signer)?;
            if !publics.insert(*public) {
                return None;
            }
            match discharged.get(&entry.signer) {
                Some(known)
                    if known.namespace == entry.namespace && known.message == entry.message =>
                {
                    remainder -= &known.signature;
                }
                _ => terms.push(OwnedTerm {
                    public: *public,
                    namespace: entry.namespace,
                    message: entry.message.clone(),
                }),
            }
        }
        if terms.is_empty() {
            return (remainder == V::Signature::zero()).then(Vec::new);
        }
        Some(vec![Claim::aggregate(remainder, terms)])
    }
}
