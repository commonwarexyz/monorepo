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

// cfg_if::cfg_if! {
//     if #[cfg(not(target_arch = "wasm32"))] {
//       pub mod reporter;
//     }
// }

use crate::{
    signing_scheme::{Context, Scheme},
    simplex::types::VoteContext,
    types::Round,
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use commonware_utils::union;

impl<'a, D: Digest> Context for VoteContext<'a, D> {
    fn namespace_and_message(&self, namespace: &[u8]) -> (Vec<u8>, Vec<u8>) {
        vote_namespace_and_message(namespace, self)
    }
}

pub trait SeededScheme: Scheme {
    /// Randomness seed derived from a certificate, if the scheme supports it.
    type Seed: Clone + Encode + Send;

    /// Extracts randomness seed, if provided by the scheme, derived from the certificate
    /// for the given round.
    fn seed(&self, round: Round, certificate: &Self::Certificate) -> Option<Self::Seed>;
}

pub trait SimplexScheme<D: Digest>:
    for<'a> SeededScheme<Context<'a, D> = VoteContext<'a, D>>
{
}

impl<D: Digest, S> SimplexScheme<D> for S where
    S: for<'a> SeededScheme<Context<'a, D> = VoteContext<'a, D>>
{
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
    context: &VoteContext<D>,
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
    context: &VoteContext<D>,
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
