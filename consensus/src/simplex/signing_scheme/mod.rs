//! Signing scheme implementations for `simplex`.
//!
//! # Attributable Schemes and Liveness/Fault Evidence
//!
//! Signing schemes differ in whether per-validator activities can be used as evidence of either
//! liveness or of committing a fault:
//!
//! - **Attributable Schemes** ([`ed25519`], [`bls12381_multisig`]): Individual signatures can be presented
//!   to some third party as evidence of either liveness or of committing a fault. Certificates contain signer
//!   indices alongside individual signatures, enabling secure per-validator activity tracking and
//!   conflict detection.
//!
//! - **Non-Attributable schemes** ([`bls12381_threshold`]): Individual signatures cannot be presented
//!   to some third party as evidence of either liveness or of committing a fault because they can be forged
//!   by other players (often after some quorum of partial signatures are collected). With [`bls12381_threshold`],
//!   possession of any `t` valid partial signatures can be used to forge a partial signature for any other player.
//!   Because peer connections are authenticated, evidence can be used locally (as it must be sent by said participant)
//!   but can't be used by an external observer.
//!
//! The [`Scheme::is_attributable()`] method signals whether evidence can be safely
//! exposed. For applications only interested in collecting evidence for liveness/faults, use [`reporter::AttributableReporter`]
//! which automatically handles filtering and verification based on scheme (hiding votes/proofs that are not attributable). If
//! full observability is desired, process all messages passed through the [`crate::Reporter`] interface.

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;
pub mod utils;

cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
      pub mod reporter;
    }
}

use crate::{
    simplex::types::{Signature, SignatureVerification, Subject},
    types::Round,
};
use commonware_codec::{Codec, CodecFixed, Encode, Read};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::{ordered::Set, union};
use rand::{CryptoRng, Rng};
use std::{collections::BTreeSet, fmt::Debug, hash::Hash};

/// Cryptographic surface required by `simplex`.
///
/// A `Scheme` produces validator votes, validates them (individually or in batches), assembles
/// quorum certificates, checks recovered certificates and, when available, derives a randomness
/// seed for leader rotation. Implementations may override the provided defaults to take advantage
/// of scheme-specific batching strategies.
///
/// # Identity Keys vs Consensus Keys
///
/// A participant may supply both an identity key and a consensus key. The identity key
/// is used for assigning a unique order to the committee and authenticating connections whereas the consensus key
/// is used for actually signing and verifying votes/certificates.
///
/// This flexibility is supported because some cryptographic schemes are only performant when used in batch verification
/// (like [bls12381_multisig]) and/or are refreshed frequently (like [bls12381_threshold]). Refer to [ed25519]
/// for an example of a scheme that uses the same key for both purposes.
pub trait Scheme: Clone + Debug + Send + Sync + 'static {
    /// Public key type for participant identity used to order and index the committee.
    type PublicKey: PublicKey;
    /// Vote signature emitted by individual validators.
    type Signature: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + CodecFixed<Cfg = ()>;
    /// Quorum certificate recovered from a set of votes.
    type Certificate: Clone + Debug + PartialEq + Eq + Hash + Send + Sync + Codec;
    /// Randomness seed derived from a certificate, if the scheme supports it.
    type Seed: Clone + Encode + Send;

    /// Returns the index of "self" in the participant set, if available.
    /// Returns `None` if the scheme is a verifier-only instance.
    fn me(&self) -> Option<u32>;

    /// Returns the ordered set of participant public identity keys managed by the scheme.
    fn participants(&self) -> &Set<Self::PublicKey>;

    /// Signs a vote for the given context using the supplied namespace for domain separation.
    /// Returns `None` if the scheme cannot sign (e.g. it's a verifier-only instance).
    fn sign_vote<D: Digest>(
        &self,
        namespace: &[u8],
        subject: Subject<'_, D>,
    ) -> Option<Signature<Self>>;

    /// Verifies a single vote against the participant material managed by the scheme.
    fn verify_vote<D: Digest>(
        &self,
        namespace: &[u8],
        subject: Subject<'_, D>,
        signature: &Signature<Self>,
    ) -> bool;

    /// Batch-verifies votes and separates valid messages from the voter indices that failed
    /// verification.
    ///
    /// Callers must not include duplicate votes from the same signer.
    fn verify_votes<R, D, I>(
        &self,
        _rng: &mut R,
        namespace: &[u8],
        subject: Subject<'_, D>,
        signatures: I,
    ) -> SignatureVerification<Self>
    where
        R: Rng + CryptoRng,
        D: Digest,
        I: IntoIterator<Item = Signature<Self>>,
    {
        let mut invalid = BTreeSet::new();

        let verified = signatures.into_iter().filter_map(|sig| {
            if self.verify_vote(namespace, subject, &sig) {
                Some(sig)
            } else {
                invalid.insert(sig.signer);
                None
            }
        });

        SignatureVerification::new(verified.collect(), invalid.into_iter().collect())
    }

    /// Aggregates a quorum of votes into a certificate, returning `None` if the quorum is not met.
    ///
    /// Callers must not include duplicate votes from the same signer.
    fn assemble_certificate<I>(&self, signatures: I) -> Option<Self::Certificate>
    where
        I: IntoIterator<Item = Signature<Self>>;

    /// Verifies a certificate that was recovered or received from the network.
    fn verify_certificate<R: Rng + CryptoRng, D: Digest>(
        &self,
        rng: &mut R,
        namespace: &[u8],
        subject: Subject<'_, D>,
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
        I: Iterator<Item = (Subject<'a, D>, &'a Self::Certificate)>,
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

    /// Returns whether per-validator fault evidence can be safely exposed.
    ///
    /// Schemes where individual signatures can be safely reported as fault evidence should
    /// return `true`.
    ///
    /// This is used by [`reporter::AttributableReporter`] to safely expose consensus
    /// activities.
    fn is_attributable(&self) -> bool;

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
    subject: Subject<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    match subject {
        Subject::Notarize { proposal } => {
            (notarize_namespace(namespace), proposal.encode().to_vec())
        }
        Subject::Nullify { round } => (nullify_namespace(namespace), round.encode().to_vec()),
        Subject::Finalize { proposal } => {
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
    subject: Subject<'_, D>,
) -> (Vec<u8>, Vec<u8>) {
    (
        seed_namespace(namespace),
        match subject {
            Subject::Notarize { proposal } | Subject::Finalize { proposal } => {
                proposal.round.encode().to_vec()
            }
            Subject::Nullify { round } => round.encode().to_vec(),
        },
    )
}
