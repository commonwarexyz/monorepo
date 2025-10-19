//! Signing-scheme abstraction and implementations used by `simplex`.
//!
//! The [`Scheme`] trait defines the cryptographic surface consumed by the core consensus engine:
//! how votes are signed and verified, how quorum certificates are assembled/checked, and whether
//! additional randomness is exposed for leader rotation. Two concrete schemes are provided:
//!
//! * [`bls12381_threshold`] – aggregated threshold signatures that also expose per-view randomness.
//! * [`ed25519`] – quorum signatures collected into a vector.

pub mod bls12381_threshold;
pub mod ed25519;

use crate::{
    simplex::types::{Vote, VoteContext, VoteVerification},
    types::Round,
};
use commonware_codec::{Codec, CodecFixed, Encode, Read};
use commonware_cryptography::Digest;
use commonware_utils::union;
use rand::{CryptoRng, Rng};
use std::{collections::BTreeSet, fmt::Debug, hash::Hash};

/// Cryptographic surface required by `simplex`.
///
/// A `Scheme` produces validator votes, validates them (individually or in batches), assembles
/// quorum certificates, checks recovered certificates and, when available, derives a randomness
/// seed for leader rotation. Implementations may override the provided defaults to take advantage
/// of scheme-specific batching strategies.
pub trait Scheme: Clone + Debug + Send + Sync + 'static {
    /// Vote signature emitted by individual validators.
    type Signature: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + CodecFixed<Cfg = ()>;
    /// Quorum certificate recovered from a set of votes.
    type Certificate: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Codec;
    /// Randomness seed derived from a certificate, if the scheme supports it.
    type Seed: Clone + Encode + Send;

    /// Converts the scheme into a pure verifier.
    ///
    /// The returned instance should return `false` from `can_sign()`.
    fn into_verifier(self) -> Self;

    /// Signs a vote for the given context using the supplied namespace for domain separation.
    /// Returns `None` if the scheme cannot sign (e.g. it's a verifier-only instance).
    fn sign_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
    ) -> Option<Vote<Self>>;

    /// Verifies a single vote against the participant material managed by the scheme.
    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        vote: &Vote<Self>,
    ) -> bool;

    /// Batch-verifies votes and separates valid messages from the voter indices that failed
    /// verification.
    ///
    /// Callers must not include duplicate votes from the same signer.
    fn verify_votes<R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        votes: I,
    ) -> VoteVerification<Self>
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Vote<Self>>,
    {
        let mut invalid = BTreeSet::new();

        let verified = votes.into_iter().filter_map(|vote| {
            if self.verify_vote(namespace, context, &vote) {
                Some(vote)
            } else {
                invalid.insert(vote.signer);
                None
            }
        });

        VoteVerification::new(verified.collect(), invalid.into_iter().collect())
    }

    /// Aggregates a quorum of votes into a certificate, returning `None` if the quorum is not met.
    ///
    /// Callers must not include duplicate votes from the same signer.
    fn assemble_certificate<I>(&self, votes: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Vote<Self>>;

    /// Verifies a certificate that was recovered or received from the network.
    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        certificate: &Self::Certificate,
    ) -> bool;

    /// Verifies a stream of certificates, returning `false` at the first failure.
    fn verify_certificates<'a, R, D, I>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        certificates: I,
    ) -> bool
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: Iterator<Item = (VoteContext<'a, D>, &'a Self::Certificate)>,
    {
        for (context, certificate) in certificates {
            if !self.verify_certificate(rng, namespace, context, certificate) {
                return false;
            }
        }

        true
    }

    /// Extracts randomness seed, if provided by the scheme, derived from the certificate
    /// for the given round.
    fn seed(&self, round: Round, certificate: &Self::Certificate) -> Option<Self::Seed>;

    /// Encoding configuration for bounded-size certificate decoding used in network payloads.
    fn certificate_codec_config(&self) -> <Self::Certificate as Read>::Cfg;

    /// Encoding configuration that allows unbounded certificate decoding.
    ///
    /// Only use this when decoding data from trusted local storage, it must not be exposed to
    /// adversarial inputs or network payloads.
    fn certificate_codec_config_unbounded() -> <Self::Certificate as Read>::Cfg;
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
const SEED_SUFFIX: &[u8] = b"_SEED";
const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";
const FINALIZE_SUFFIX: &[u8] = b"_FINALIZE";

/// Creates a namespace for seed messages by appending the SEED_SUFFIX
/// The seed is used for leader election and randomness generation
#[inline]
pub(crate) fn seed_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, SEED_SUFFIX)
}

/// Creates a namespace for notarize messages by appending the NOTARIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn notarize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NOTARIZE_SUFFIX)
}

/// Creates a namespace for nullify messages by appending the NULLIFY_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn nullify_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, NULLIFY_SUFFIX)
}

/// Creates a namespace for finalize messages by appending the FINALIZE_SUFFIX
/// Domain separation prevents cross-protocol attacks
#[inline]
pub(crate) fn finalize_namespace(namespace: &[u8]) -> Vec<u8> {
    union(namespace, FINALIZE_SUFFIX)
}

/// Produces the vote namespace and message bytes for a given vote context.
///
/// Returns the final namespace (with the context-specific suffix) and the
/// serialized message to sign or verify.
#[inline]
pub(crate) fn vote_namespace_and_message<D: Digest>(
    namespace: &[u8],
    context: VoteContext<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    match context {
        VoteContext::Notarize { proposal } => {
            (notarize_namespace(namespace), proposal.encode().to_vec())
        }
        VoteContext::Nullify { round } => (nullify_namespace(namespace), round.encode().to_vec()),
        VoteContext::Finalize { proposal } => {
            (finalize_namespace(namespace), proposal.encode().to_vec())
        }
    }
}

/// Produces the seed namespace and message bytes for a given vote context.
///
/// Returns the final namespace (with the seed suffix) and the serialized
/// message to sign or verify.
#[inline]
pub(crate) fn seed_namespace_and_message<D: Digest>(
    namespace: &[u8],
    context: VoteContext<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    (
        seed_namespace(namespace),
        match context {
            VoteContext::Notarize { proposal } | VoteContext::Finalize { proposal } => {
                proposal.round.encode().to_vec()
            }
            VoteContext::Nullify { round } => round.encode().to_vec(),
        },
    )
}
