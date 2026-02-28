//! Signing scheme implementations for `minimmit`.
//!
//! # Attributable Schemes and Fault Evidence
//!
//! Signing schemes differ in whether per-validator activities can be used as evidence of either
//! liveness or of committing a fault. See [`crate::simplex::scheme`] for details on attributable
//! vs non-attributable schemes.

use crate::minimmit::types::Subject;
use bytes::Bytes;
use commonware_codec::Encode;
use commonware_cryptography::{certificate, Digest};
use commonware_utils::union;

pub mod bls12381_multisig;
pub mod bls12381_threshold;
pub mod ed25519;
pub mod secp256r1;

/// Pre-computed namespaces for minimmit voting subjects.
///
/// This struct holds the pre-computed namespace bytes for each vote type.
/// Unlike Simplex, Minimmit has no finalize namespace since finalization
/// uses the same notarize votes (just with a higher threshold).
///
/// Unlike Simplex, Minimmit does not use seed signatures for VRF-based leader
/// election. The BLS threshold scheme uses aggregated signatures for M-quorum
/// and threshold recovery for L-quorum, prioritizing security over random election.
#[derive(Clone, Debug)]
pub struct Namespace {
    /// Namespace for notarize votes/certificates.
    pub notarize: Vec<u8>,
    /// Namespace for nullify votes/certificates.
    pub nullify: Vec<u8>,
}

impl Namespace {
    /// Creates a new Namespace from a base namespace.
    pub fn new(namespace: &[u8]) -> Self {
        Self {
            notarize: notarize_namespace(namespace),
            nullify: nullify_namespace(namespace),
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
            Self::Notarize { proposal } => proposal.encode(),
            Self::Nullify { round } => round.encode(),
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
const NOTARIZE_SUFFIX: &[u8] = b"_MINIMMIT_NOTARIZE";
const NULLIFY_SUFFIX: &[u8] = b"_MINIMMIT_NULLIFY";

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_namespace_creation() {
        let ns = Namespace::new(b"test");
        assert_eq!(ns.notarize, b"test_MINIMMIT_NOTARIZE");
        assert_eq!(ns.nullify, b"test_MINIMMIT_NULLIFY");
    }

    #[test]
    fn test_namespace_domain_separation() {
        // Ensure minimmit namespaces don't collide with simplex
        let minimmit_ns = Namespace::new(b"app");
        let simplex_ns = crate::simplex::scheme::Namespace::new(b"app");

        assert_ne!(minimmit_ns.notarize, simplex_ns.notarize);
        assert_ne!(minimmit_ns.nullify, simplex_ns.nullify);
    }
}
