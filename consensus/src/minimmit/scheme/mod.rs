//! Signing scheme implementations for `minimmit`.
//!
//! # Attributable Schemes and Fault Evidence
//!
//! Signing schemes differ in whether per-validator activities can be used as evidence of either
//! liveness or of committing a fault:
//!
//! - **Attributable Schemes** ([`ed25519`], [`bls12381_multisig`], [`secp256r1`]): Individual signatures can be
//!   presented to some third party as evidence of either liveness or of committing a fault. Certificates contain signer
//!   indices alongside individual signatures, enabling secure per-validator activity tracking and conflict detection.
//!
//! - **Non-Attributable schemes** ([`bls12381_threshold`]): Individual signatures cannot be presented
//!   to some third party as evidence of either liveness or of committing a fault because they can be forged
//!   by other players (often after some quorum of partial signatures are collected). With [`bls12381_threshold`],
//!   possession of any `t` valid partial signatures can be used to forge a partial signature for any other player.
//!   Because peer connections are authenticated, evidence can be used locally (as it must be sent by said participant)
//!   but can't be used by an external observer.
//!
//! The [`certificate::Scheme::is_attributable()`] associated function signals whether evidence can be safely
//! exposed.

use crate::minimmit::types::Subject;
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{certificate, Digest};
use commonware_utils::union;

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;
pub mod reporter;
pub mod secp256r1;

/// Pre-computed namespaces for minimmit voting subjects.
///
/// This struct holds the pre-computed namespace bytes for each vote type.
/// Unlike simplex, minimmit has no finalize namespace since finalization
/// occurs at L notarize votes.
#[derive(Clone, Debug)]
pub struct Namespace {
    /// Namespace for notarize votes/certificates.
    pub notarize: Vec<u8>,
    /// Namespace for nullify votes/certificates.
    pub nullify: Vec<u8>,
    /// Namespace for seed signatures (used by threshold schemes).
    pub seed: Vec<u8>,
}

impl Namespace {
    /// Creates a new Namespace from a base namespace.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            notarize: notarize_namespace(namespace),
            nullify: nullify_namespace(namespace),
            seed: seed_namespace(namespace),
        }
    }
}

impl certificate::Namespace for Namespace {
    fn derive(namespace: &[u8]) -> Self {
        Self::new(namespace)
    }
}

impl<'a, D: Digest> certificate::Subject for Subject<'a, D> {
    type Namespace = Namespace;

    fn namespace<'b>(&self, derived: &'b Self::Namespace) -> &'b [u8] {
        match self {
            Self::Notarize { .. } => &derived.notarize,
            Self::Nullify { .. } => &derived.nullify,
        }
    }

    fn message(&self) -> Bytes {
        match self {
            Self::Notarize { proposal } => proposal.encode().freeze(),
            Self::Nullify { round } => round.encode().freeze(),
        }
    }
}

/// Marker trait for signing schemes compatible with `minimmit`.
///
/// This trait binds a [`certificate::Scheme`] to the [`Subject`] subject type
/// used by the minimmit protocol. It is automatically implemented for any scheme
/// whose subject type matches `Subject<'a, D>`.
pub trait Scheme<D: Digest>: for<'a> certificate::Scheme<Subject<'a, D> = Subject<'a, D>> {}

impl<D: Digest, S> Scheme<D> for S where
    S: for<'a> certificate::Scheme<Subject<'a, D> = Subject<'a, D>>
{
}

// Constants for domain separation in signature verification
// These are used to prevent cross-protocol attacks and message-type confusion
const SEED_SUFFIX: &[u8] = b"_SEED";
const NOTARIZE_SUFFIX: &[u8] = b"_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_NULLIFY";

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
