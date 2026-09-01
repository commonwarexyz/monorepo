//! Pairing claims and the individual verifiers built on them.
//!
//! A claim builder runs every structural check of its artifact, so the artifact is valid exactly
//! when each returned claim's pairing product holds. Individual verifiers check those claims one
//! by one; batch verification checks many artifacts' claims together.

use super::{Error, Scheme};
use crate::{
    Epochable, Viewable,
    multimmit::{
        scheme::{Subject, Verified},
        types::{
            Anchor, Attestation, CertificateId, DaCertificate, DaVote, Lqc, NoVote, Nullification,
            Nullify, SignedLeaderBlock, SignedTransactionBlock, ThresholdShare, Vote, Vqc,
        },
    },
    types::Attributable as _,
};
use bytes::Bytes;
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    bls12381::{
        certificate::threshold as certificate_threshold,
        primitives::{
            ops::{self, aggregate, batch},
            sharing::Sharing,
            variant::{PartialSignature, Variant},
        },
    },
    certificate::Subject as _,
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use core::convert::identity;
use rand_core::CryptoRng;
use std::collections::HashSet;

/// One signer's message in an aggregate transcript.
pub(super) struct TranscriptEntry<'a> {
    pub(super) signer: Participant,
    pub(super) namespace: &'a [u8],
    pub(super) message: Bytes,
}

/// One message covered by a claim, owned until the claim is borrowed as a [`batch::Claim`].
pub(super) struct OwnedTerm<'a, V: Variant> {
    pub(super) public: V::Public,
    pub(super) namespace: &'a [u8],
    pub(super) message: Bytes,
}

/// The terms a [`Claim`] covers.
enum Terms<'a, V: Variant> {
    /// An ordinary signature or threshold material over one message.
    One(OwnedTerm<'a, V>),
    /// An aggregate transcript.
    Many(Vec<OwnedTerm<'a, V>>),
}

impl<'a, V: Variant> Terms<'a, V> {
    fn as_slice(&self) -> &[OwnedTerm<'a, V>] {
        match self {
            Self::One(term) => core::slice::from_ref(term),
            Self::Many(terms) => terms,
        }
    }
}

/// One pairing claim extracted from an artifact: `signature` covers every term.
pub(super) struct Claim<'a, V: Variant> {
    signature: V::Signature,
    terms: Terms<'a, V>,
}

impl<'a, V: Variant> Claim<'a, V> {
    const fn single(
        signature: V::Signature,
        public: V::Public,
        namespace: &'a [u8],
        message: Bytes,
    ) -> Self {
        Self {
            signature,
            terms: Terms::One(OwnedTerm {
                public,
                namespace,
                message,
            }),
        }
    }

    /// Creates the claim that `signature` aggregates signatures over every term.
    pub(super) const fn aggregate(signature: V::Signature, terms: Vec<OwnedTerm<'a, V>>) -> Self {
        Self {
            signature,
            terms: Terms::Many(terms),
        }
    }

    /// Checks a single-term claim with one pairing product.
    ///
    /// Returns false for an aggregate claim, even one left with a single term; aggregates are
    /// checked with [`verify_claims`].
    pub(super) fn verify(&self) -> bool {
        let Terms::One(term) = &self.terms else {
            return false;
        };
        ops::verify_message::<V>(&term.public, term.namespace, &term.message, &self.signature)
            .is_ok()
    }

    /// Borrows this claim as a [`batch::Claim`].
    pub(super) fn as_batch(&self) -> batch::Claim<'_, V> {
        batch::Claim {
            signature: self.signature,
            terms: self
                .terms
                .as_slice()
                .iter()
                .map(|term| batch::Term {
                    public: term.public,
                    namespace: term.namespace,
                    message: &term.message,
                })
                .collect(),
        }
    }
}

/// Returns whether every claim holds, checked as one randomly scaled batch.
pub(super) fn verify_claims<R: CryptoRng, V: Variant>(
    rng: &mut R,
    claims: &[Claim<'_, V>],
    strategy: &impl Strategy,
) -> bool {
    let batched = claims.iter().map(Claim::as_batch).collect::<Vec<_>>();
    batch::verify_claims(rng, &batched, strategy).is_empty()
}

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Verifies a producer's transaction-block attestation.
    pub fn verify_transaction_block<D: Digest>(
        &self,
        block: &SignedTransactionBlock<V, D>,
    ) -> bool {
        self.transaction_block_claim(block)
            .is_some_and(|claim| claim.verify())
    }

    /// Verifies one data-availability threshold share.
    pub fn verify_da_vote<D: Digest>(&self, vote: &DaVote<V, D>) -> bool {
        self.da_vote_claim(vote).is_some_and(|claim| claim.verify())
    }

    /// Runs every non-cryptographic check on one data-availability share.
    ///
    /// The share's own pairing is deliberately left unchecked: its only use is threshold
    /// recovery, and [`Self::assemble_da_certificate_optimistic`] checks the whole quorum with
    /// one pairing and attributes the shares individually only when that check fails.
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn precheck_da_vote<D: Digest>(&self, vote: &DaVote<V, D>) -> bool {
        self.da_vote_claim(vote).is_some()
    }

    /// Verifies the scheduled leader's signature and every embedded DA certificate.
    pub fn verify_leader_block<D: Digest>(
        &self,
        block: &SignedLeaderBlock<V, D>,
        strategy: &impl Strategy,
    ) -> bool {
        let Some(claims) = self.leader_block_claims(block, &[]) else {
            return false;
        };
        strategy
            .map_collect_vec(&claims, Claim::verify)
            .into_iter()
            .all(identity)
    }

    /// Verifies a complete consensus vote.
    pub fn verify_vote<D: Digest>(&self, vote: &Vote<V, D>) -> bool {
        self.vote_claim(vote).is_some_and(|claim| claim.verify())
    }

    /// Verifies an attributed abstention.
    pub fn verify_novote(&self, novote: &NoVote<V>) -> bool {
        self.novote_claim(novote)
            .is_some_and(|claim| claim.verify())
    }

    /// Verifies one nullification threshold share.
    pub fn verify_nullify(&self, nullify: &Nullify<V>) -> bool {
        self.nullify_claim(nullify)
            .is_some_and(|claim| claim.verify())
    }

    /// Verifies a recovered data-availability certificate.
    pub fn verify_da_certificate<D: Digest>(&self, certificate: &DaCertificate<V, D>) -> bool {
        self.da_certificate_claim(certificate)
            .is_some_and(|claim| claim.verify())
    }

    /// Verifies a recovered nullification certificate.
    pub fn verify_nullification(&self, certificate: &Nullification<V>) -> bool {
        self.nullification_claim(certificate)
            .is_some_and(|claim| claim.verify())
    }

    /// Verifies every ordinary signature represented by a V-QC's compact transcript.
    pub fn verify_vqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &Vqc<V, D>,
        strategy: &impl Strategy,
    ) -> Option<CertificateId<D>> {
        let claims = self.vqc_claims::<H, D>(certificate, &[])?;
        verify_claims(rng, &claims.claims, strategy).then(|| certificate.id::<H>())
    }

    /// Verifies every ordinary vote signature represented by an L-QC's tally.
    pub fn verify_lqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &Lqc<V, D>,
        strategy: &impl Strategy,
    ) -> Option<CertificateId<D>> {
        let claims = self.lqc_claims::<H, D>(certificate, &[])?;
        verify_claims(rng, &claims.claims, strategy).then(|| certificate.id::<H>())
    }

    /// Builds the claim for a producer's attestation, checking chain ownership.
    pub(super) fn transaction_block_claim<D: Digest>(
        &self,
        block: &SignedTransactionBlock<V, D>,
    ) -> Option<Claim<'_, V>> {
        if self.producer(block.header().chain()).ok()? != block.signer() {
            return None;
        }
        self.attestation_claim(
            Subject::transaction_block(block.header()),
            block.attestation(),
        )
    }

    /// Builds the claim for one data-availability share, running its structural checks.
    pub(super) fn da_vote_claim<D: Digest>(&self, vote: &DaVote<V, D>) -> Option<Claim<'_, V>> {
        if !self.chain_in_range(vote.header().chain()) {
            return None;
        }
        let sharing = self.material.da_sharing()?;
        self.share_claim(sharing, Subject::da_vote(vote.header()), vote.share())
    }

    /// Builds the claims for a leader block: the scheduled leader's attestation plus every
    /// embedded DA certificate not already held in `known`.
    ///
    /// An anchor the node already holds needs no pairing; anything else, including a different
    /// certificate for the same header, is verified in full.
    pub(super) fn leader_block_claims<D: Digest>(
        &self,
        block: &SignedLeaderBlock<V, D>,
        known: &[Verified<'_, V, D>],
    ) -> Option<Vec<Claim<'_, V>>> {
        if self.ensure_leader(block.block()).is_err()
            || block.signer() != self.parameters.leader(block.view())
        {
            return None;
        }
        let mut claims = vec![
            self.attestation_claim(Subject::leader_block(block.block()), block.attestation())?,
        ];
        for proposal in block.block().proposals() {
            let Anchor::Certificate(certificate) = proposal.anchor() else {
                continue;
            };
            if known.iter().any(
                |message| matches!(message, Verified::DaCertificate(held) if *held == certificate),
            ) {
                continue;
            }
            claims.push(self.da_certificate_claim(certificate)?);
        }
        Some(claims)
    }

    /// Builds the claim for one consensus vote, checking its body against the codec limits.
    pub(super) fn vote_claim<D: Digest>(&self, vote: &Vote<V, D>) -> Option<Claim<'_, V>> {
        self.ensure_vote_body(vote.body()).ok()?;
        self.attestation_claim(Subject::vote(vote.body()), vote.attestation())
    }

    /// Builds the claim for one abstention.
    pub(super) fn novote_claim(&self, novote: &NoVote<V>) -> Option<Claim<'_, V>> {
        self.attestation_claim(Subject::NoVote(novote.round()), novote.attestation())
    }

    /// Builds the claim for one nullification share.
    pub(super) fn nullify_claim(&self, nullify: &Nullify<V>) -> Option<Claim<'_, V>> {
        let sharing = self.material.nullification_sharing()?;
        self.share_claim(sharing, Subject::Nullify(nullify.round()), nullify.share())
    }

    /// Builds the claim for one recovered nullification.
    pub(super) fn nullification_claim(
        &self,
        certificate: &Nullification<V>,
    ) -> Option<Claim<'_, V>> {
        self.ensure_epoch(certificate.epoch()).ok()?;
        self.recovered_claim(
            self.material.nullification_identity(),
            Subject::Nullify(certificate.round()),
            certificate.certificate(),
        )
    }

    /// Builds the claim for one data-availability certificate, including its header checks.
    pub(super) fn da_certificate_claim<D: Digest>(
        &self,
        certificate: &DaCertificate<V, D>,
    ) -> Option<Claim<'_, V>> {
        let header = certificate.header();
        if !self.chain_in_range(header.chain()) || self.ensure_epoch(header.epoch()).is_err() {
            return None;
        }
        self.recovered_claim(
            self.material.da_identity(),
            Subject::da_vote(header),
            certificate.certificate(),
        )
    }

    /// Builds the claim for one attributed ordinary signature.
    fn attestation_claim(
        &self,
        subject: Subject,
        attestation: &Attestation<V>,
    ) -> Option<Claim<'_, V>> {
        self.ensure_epoch(subject.epoch()).ok()?;
        let public = self.public(attestation.signer())?;
        let signature = decoded(attestation).ok()?;
        Some(Claim::single(
            signature,
            *public,
            subject.namespace(&self.namespace),
            subject.message(),
        ))
    }

    /// Builds the claim for one threshold share, against its partial public key.
    fn share_claim(
        &self,
        sharing: &Sharing<V>,
        subject: Subject,
        share: &ThresholdShare<V>,
    ) -> Option<Claim<'_, V>> {
        self.ensure_epoch(subject.epoch()).ok()?;
        let partial = partial(share).ok()?;
        let public = sharing.partial_public(partial.index).ok()?;
        Some(Claim::single(
            partial.value,
            public,
            subject.namespace(&self.namespace),
            subject.message(),
        ))
    }

    /// Builds the claim for one recovered threshold certificate, against a group identity.
    fn recovered_claim(
        &self,
        identity: &V::Public,
        subject: Subject,
        certificate: &certificate_threshold::Certificate<V>,
    ) -> Option<Claim<'_, V>> {
        let signature = certificate.get()?;
        if signature == &V::Signature::zero() {
            return None;
        }
        Some(Claim::single(
            *signature,
            *identity,
            subject.namespace(&self.namespace),
            subject.message(),
        ))
    }

    /// Builds the atomic claim for one aggregate transcript (a V-QC or L-QC).
    ///
    /// The transcript must be non-empty, every signer must resolve to a distinct public key, and
    /// the signature must be non-zero. These checks run on untrusted certificates before any
    /// pairing.
    pub(super) fn aggregate_claim<'a>(
        &'a self,
        transcript: &[TranscriptEntry<'a>],
        signature: &aggregate::Signature<V>,
    ) -> Option<Claim<'a, V>> {
        if transcript.is_empty() || signature.inner() == &V::Signature::zero() {
            return None;
        }
        let mut publics = HashSet::with_capacity(transcript.len());
        let terms = transcript
            .iter()
            .map(|entry| {
                let public = self.public(entry.signer)?;
                publics.insert(*public).then(|| OwnedTerm {
                    public: *public,
                    namespace: entry.namespace,
                    message: entry.message.clone(),
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Claim::aggregate(*signature.inner(), terms))
    }
}

/// Decodes a signature and rejects a malformed or zero group element.
fn nonzero_signature<V: Variant>(signature: &Lazy<V::Signature>) -> Result<V::Signature, Error> {
    match signature.get() {
        Some(signature) if signature != &V::Signature::zero() => Ok(*signature),
        _ => Err(Error::Signature),
    }
}

/// Decodes an attestation's signature, rejecting a malformed or zero element.
pub(super) fn decoded<V: Variant>(attestation: &Attestation<V>) -> Result<V::Signature, Error> {
    nonzero_signature::<V>(attestation.lazy_signature())
}

/// Decodes a threshold share, rejecting a malformed or zero element.
pub(super) fn partial<V: Variant>(share: &ThresholdShare<V>) -> Result<PartialSignature<V>, Error> {
    Ok(PartialSignature {
        index: share.signer(),
        value: nonzero_signature::<V>(share.lazy_signature())?,
    })
}
