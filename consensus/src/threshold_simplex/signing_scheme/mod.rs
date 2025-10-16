//! This module exposes the domain-separation helpers plus concrete
//! [`SigningScheme`] implementations: one backed by BLS12-381 threshold
//! signatures and one backed by Ed25519 quorum signatures.

pub mod bls12381_threshold;
pub mod ed25519;

use crate::threshold_simplex::types::{Vote, VoteContext, VoteVerification};
use commonware_codec::{Codec, CodecFixed, Encode, Read};
use commonware_cryptography::Digest;
use commonware_utils::union;
use rand::{CryptoRng, Rng};
use std::{collections::BTreeSet, fmt::Debug, hash::Hash};

/// Cryptographic surface required by `threshold_simplex`.
///
/// A `SigningScheme` produces validator votes, validates them (individually or in
/// batches), assembles quorum certificates, checks recovered certificates and, when
/// available, derives a randomness seed for leader rotation. Implementations may override
/// the provided defaults to take advantage of scheme-specific batching strategies.
pub trait SigningScheme: Clone + Debug + Send + Sync + 'static {
    type Signature: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + CodecFixed<Cfg = ()>;
    type Certificate: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Codec;

    type Seed: Clone + Encode + Send;

    /// Converts the scheme into a pure verifier.
    ///
    /// The returned instance should return `false` from `can_sign()`.
    fn into_verifier(self) -> Self;

    /// Returns `true` if this instance holds the secrets required to author votes.
    fn can_sign(&self) -> bool;

    /// Signs a vote for the given context using the supplied namespace for domain separation.
    fn sign_vote<D: Digest>(&self, namespace: &[u8], context: VoteContext<'_, D>) -> Vote<Self>;

    /// Verifies a single vote against the participant material managed by the scheme.
    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        context: VoteContext<'_, D>,
        vote: &Vote<Self>,
    ) -> bool;

    /// Batch-verifies votes and separates valid messages from the indices that failed verification.
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
    /// `certificate` carries a previously recovered certificate for the same proposal (in
    /// a different context), when available. Schemes such as threshold BLS can reuse part
    /// of that certificate (e.g. the seed signature from a notarization) when assembling
    /// a finalization certificate, while most other schemes may simply ignore it.
    ///
    /// Callers must not include duplicate votes from the same signer.
    fn assemble_certificate<I>(
        &self,
        votes: I,
        certificate: Option<Self::Certificate>,
    ) -> Option<Self::Certificate>
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

    /// Extracts randomness seed derived from the certificate, if provided by the scheme.
    fn seed(&self, certificate: &Self::Certificate) -> Option<Self::Seed>;

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
