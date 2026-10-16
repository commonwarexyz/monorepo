//! Pairing claims and the individual verifiers built on them.
//!
//! A claim builder runs every structural check of its item, so the item is valid exactly when the
//! returned claim's pairing product holds. Individual verifiers check one claim; batch
//! verification checks many items' claims together.

use super::{Contents, Scheme};
use crate::{
    Epochable, Viewable as _,
    multimmit::{
        scheme::Subject,
        types::{Attestation, Lqc, SignedLeaderBlock, SignedTransactionBlock, VoteContent, Vqc},
    },
    types::{Attributable as _, Epoch},
};
use bytes::Bytes;
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Digest, Hasher, PublicKey,
    bls12381::primitives::{
        ops::{self, aggregate, batch},
        variant::Variant,
    },
    certificate::{Signers, Subject as _},
};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_utils::Participant;
use rand_core::CryptoRng;
use std::collections::HashMap;

/// One signer's public key and the namespaced message it signed.
struct Term<'a, V: Variant> {
    public: V::Public,
    namespace: &'a [u8],
    message: Bytes,
}

/// One pairing claim extracted from an item: `signature` covers every term.
///
/// An ordinary signature has one term. A certificate has one term per signer, and terms of
/// signers that signed the same content share one encoded message, which batch verification
/// groups into a single pairing.
pub(super) struct Claim<'a, V: Variant> {
    signature: V::Signature,
    terms: Vec<Term<'a, V>>,
}

impl<V: Variant> Claim<'_, V> {
    /// Checks an ordinary-signature claim with one pairing product.
    ///
    /// Returns false for a claim with more than one term; those are checked with
    /// [`Self::verify_aggregate`].
    fn verify_single(&self) -> bool {
        let [term] = self.terms.as_slice() else {
            return false;
        };
        ops::verify_message::<V>(&term.public, term.namespace, &term.message, &self.signature)
            .is_ok()
    }

    /// Checks a claim of any size, grouping terms that share a message into one pairing.
    fn verify_aggregate<R: CryptoRng>(&self, rng: &mut R, strategy: &impl Strategy) -> bool {
        batch::verify_claims(rng, &[self.as_batch()], strategy).is_empty()
    }

    /// Borrows this claim as a [`batch::Claim`].
    pub(super) fn as_batch(&self) -> batch::Claim<'_, V> {
        batch::Claim {
            signature: self.signature,
            terms: self
                .terms
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

impl<P: PublicKey, V: Variant> Scheme<P, V> {
    /// Verifies a producer's transaction-block attestation.
    pub fn verify_transaction_block<D: Digest>(
        &self,
        block: &SignedTransactionBlock<V, D>,
    ) -> bool {
        self.transaction_block_claim(block)
            .is_some_and(|claim| claim.verify_single())
    }

    /// Verifies the scheduled leader's leader-block attestation.
    pub fn verify_leader_block<D: Digest>(&self, block: &SignedLeaderBlock<V, D>) -> bool {
        self.leader_block_claim(block)
            .is_some_and(|claim| claim.verify_single())
    }

    /// Verifies one signer's attestation over a vote content.
    ///
    /// A [`VoteUpdate`](crate::multimmit::types::VoteUpdate) is verified by rebuilding its content
    /// and passing it with the update's attestation.
    pub fn verify_vote<D: Digest>(
        &self,
        content: &VoteContent<D>,
        attestation: &Attestation<V>,
    ) -> bool {
        self.vote_claim(content, attestation)
            .is_some_and(|claim| claim.verify_single())
    }

    /// Verifies that `signature` aggregates each signer's signature over its paired content.
    ///
    /// Signers must be distinct. Signers that signed identical contents share one pairing.
    pub fn verify_tally<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        contents: &[(Participant, VoteContent<D>)],
        signature: &aggregate::Signature<V>,
        strategy: &impl Strategy,
    ) -> bool {
        self.tally_claim(contents, signature)
            .is_some_and(|claim| claim.verify_aggregate(rng, strategy))
    }

    /// Verifies a V-QC's aggregate over the final votes its tally records.
    ///
    /// The well-formedness of the tally against its parent chain is checked separately.
    pub fn verify_vqc<R: CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &Vqc<V, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.vqc_claim(certificate)
            .is_some_and(|(claim, _)| claim.verify_aggregate(rng, strategy))
    }

    /// Verifies an L-QC's aggregate over the votes for its leader block its tally records.
    pub fn verify_lqc<R: CryptoRng, H: Hasher<Digest = D>, D: Digest>(
        &self,
        rng: &mut R,
        certificate: &Lqc<V, D>,
        strategy: &impl Strategy,
    ) -> bool {
        self.lqc_claim::<H, D>(certificate)
            .is_some_and(|(claim, _)| claim.verify_aggregate(rng, strategy))
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

    /// Builds the claim for a leader block, checking the leader schedule.
    pub(super) fn leader_block_claim<D: Digest>(
        &self,
        block: &SignedLeaderBlock<V, D>,
    ) -> Option<Claim<'_, V>> {
        if block.signer() != self.parameters.leader(block.view()) {
            return None;
        }
        self.attestation_claim(Subject::leader_block(block.block()), block.attestation())
    }

    /// Builds the claim for one attested vote content.
    pub(super) fn vote_claim<D: Digest>(
        &self,
        content: &VoteContent<D>,
        attestation: &Attestation<V>,
    ) -> Option<Claim<'_, V>> {
        if !self.content_fits(content) {
            return None;
        }
        self.attestation_claim(Subject::vote(content), attestation)
    }

    /// Builds the claim for a V-QC and returns it with the rebuilt final votes.
    pub(super) fn vqc_claim<D: Digest>(
        &self,
        certificate: &Vqc<V, D>,
    ) -> Option<(Claim<'_, V>, Contents<D>)> {
        self.certificate_claim(
            certificate.epoch(),
            certificate.tally().signers(),
            certificate.signature(),
            || certificate.contents(),
        )
    }

    /// Builds the claim for an L-QC and returns it with the rebuilt votes.
    pub(super) fn lqc_claim<H: Hasher<Digest = D>, D: Digest>(
        &self,
        certificate: &Lqc<V, D>,
    ) -> Option<(Claim<'_, V>, Contents<D>)> {
        self.certificate_claim(
            certificate.epoch(),
            certificate.tally().signers(),
            certificate.signature(),
            || certificate.contents::<H>(),
        )
    }

    /// Builds the claim for a certificate of `epoch` whose tally records `signers`, rebuilding
    /// its contents only once the epoch, quorum, and signature have passed their checks.
    fn certificate_claim<D: Digest>(
        &self,
        epoch: Epoch,
        signers: &Signers,
        signature: Option<&aggregate::Signature<V>>,
        contents: impl FnOnce() -> Contents<D>,
    ) -> Option<(Claim<'_, V>, Contents<D>)> {
        self.ensure_epoch(epoch).ok()?;
        if !self.quorum_fits(signers) {
            return None;
        }
        let signature = signature?;
        let contents = contents();
        let claim = self.tally_claim(&contents, signature)?;
        Some((claim, contents))
    }

    /// Builds the aggregate claim that `signature` covers every signer's content.
    ///
    /// Each distinct content is encoded once and shared by the terms of its signers. Repeated
    /// signers are rejected by the batch verifier, which refuses repeated public keys.
    pub(super) fn tally_claim<D: Digest>(
        &self,
        contents: &[(Participant, VoteContent<D>)],
        signature: &aggregate::Signature<V>,
    ) -> Option<Claim<'_, V>> {
        let signature = nonzero(signature.inner())?;
        if contents.is_empty() {
            return None;
        }
        let mut messages = HashMap::<&VoteContent<D>, Bytes>::new();
        let terms = contents
            .iter()
            .map(|(signer, content)| {
                if !self.content_fits(content) {
                    return None;
                }
                let message = messages
                    .entry(content)
                    .or_insert_with(|| content.encode())
                    .clone();
                Some(Term {
                    public: *self.public(*signer)?,
                    namespace: &self.namespace.vote,
                    message,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Claim { signature, terms })
    }

    /// Builds the claim for one attributed ordinary signature.
    fn attestation_claim(
        &self,
        subject: Subject,
        attestation: &Attestation<V>,
    ) -> Option<Claim<'_, V>> {
        self.ensure_epoch(subject.epoch()).ok()?;
        let public = *self.public(attestation.signer())?;
        let signature = nonzero(attestation.signature()?)?;
        Some(Claim {
            signature,
            terms: vec![Term {
                public,
                namespace: subject.namespace(&self.namespace),
                message: subject.message(),
            }],
        })
    }

    /// Returns whether `content` belongs to this epoch and names one tip per chain.
    pub(super) fn content_fits<D: Digest>(&self, content: &VoteContent<D>) -> bool {
        content.epoch() == self.parameters.epoch()
            && content.tips().len() == self.codec_config().chains()
    }

    /// Returns whether `signers` is an `n - f` subset of this committee.
    fn quorum_fits(&self, signers: &Signers) -> bool {
        let codec = self.codec_config();
        signers.len() == codec.participants() && signers.count() == codec.view_quorum()
    }
}

/// Returns `signature` unless it is the identity element.
pub(super) fn nonzero<S: Additive + Copy>(signature: &S) -> Option<S> {
    (signature != &S::zero()).then_some(*signature)
}
