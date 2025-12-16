//! Signing scheme implementations for `simplex`.
//!
//! # Attributable Schemes and Fault Evidence
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
//! The [`certificate::Scheme::is_attributable()`] method signals whether evidence can be safely
//! exposed. For applications only interested in collecting evidence for liveness/faults, use [`reporter::AttributableReporter`]
//! which automatically handles filtering and verification based on scheme (hiding votes/proofs that are not attributable). If
//! full observability is desired, process all messages passed through the [`crate::Reporter`] interface.

use crate::{simplex::types::Subject, types::Round};
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{certificate, Digest};
use commonware_utils::union;

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;

#[cfg(not(target_arch = "wasm32"))]
pub mod reporter;

impl<'a, D: Digest> certificate::Subject for Subject<'a, D> {
    fn namespace_and_message(&self, namespace: &[u8]) -> (Bytes, Bytes) {
        vote_namespace_and_message(namespace, self)
    }
}

/// Extension trait for schemes that can derive randomness from certificates.
///
/// Some signing schemes (like [`bls12381_threshold`]) produce certificates that contain
/// embedded randomness which can be extracted and used for leader election or other
/// protocol-level randomness requirements. This trait provides a uniform interface for
/// extracting that randomness when available.
///
/// Schemes that do not support embedded randomness (like [`ed25519`] and [`bls12381_multisig`])
/// implement this trait but return `None` from [`SeededScheme::seed`].
pub trait SeededScheme: certificate::Scheme {
    /// Randomness seed derived from a certificate, if the scheme supports it.
    type Seed: Clone + Encode + Send;

    /// Extracts randomness seed, if provided by the scheme, derived from the certificate
    /// for the given round.
    fn seed(&self, round: Round, certificate: &Self::Certificate) -> Option<Self::Seed>;
}

/// Marker trait for signing schemes compatible with `simplex`.
///
/// This trait binds a [`certificate::Scheme`] to the [`Subject`] subject type
/// used by the simplex protocol. It is automatically implemented for any scheme
/// whose subject type matches `Subject<'a, D>`.
pub trait Scheme<D: Digest>: for<'a> SeededScheme<Subject<'a, D> = Subject<'a, D>> {}

impl<D: Digest, S> Scheme<D> for S where S: for<'a> SeededScheme<Subject<'a, D> = Subject<'a, D>> {}

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
    subject: &Subject<'_, D>,
) -> (Bytes, Bytes) {
    match subject {
        Subject::Notarize { proposal } => (
            notarize_namespace(namespace).into(),
            proposal.encode().freeze(),
        ),
        Subject::Nullify { round } => {
            (nullify_namespace(namespace).into(), round.encode().freeze())
        }
        Subject::Finalize { proposal } => (
            finalize_namespace(namespace).into(),
            proposal.encode().freeze(),
        ),
    }
}

/// Produces the seed namespace and message bytes for a given vote context.
///
/// Returns the final namespace (with the seed suffix) and the serialized
/// message to sign or verify.
#[inline]
pub(crate) fn seed_namespace_and_message<D: Digest>(
    namespace: &[u8],
    subject: &Subject<'_, D>,
) -> (Bytes, Bytes) {
    (
        seed_namespace(namespace).into(),
        match subject {
            Subject::Notarize { proposal } | Subject::Finalize { proposal } => {
                proposal.round.encode().freeze()
            }
            Subject::Nullify { round } => round.encode().freeze(),
        },
    )
}
