//! Core BLS12-381 signature primitives.
//!
//! This module provides the fundamental building blocks for BLS signatures:
//! key generation, message hashing, signing, verification, and proof of possession.

use super::super::{
    group::{self, Scalar, DST},
    variant::Variant,
    Error,
};
#[cfg(not(feature = "std"))]
use alloc::{borrow::Cow, vec::Vec};
use commonware_codec::Encode;
use commonware_math::algebra::{CryptoGroup, HashToGroup, Random};
use commonware_utils::union_unique;
#[cfg(feature = "std")]
use std::borrow::Cow;

/// Computes the public key from the private key.
pub fn compute_public<V: Variant>(private: &Scalar) -> V::Public {
    V::Public::generator() * private
}

/// Returns a new keypair derived from the provided randomness.
pub fn keypair<R: rand_core::CryptoRngCore, V: Variant>(
    rng: &mut R,
) -> (group::Private, V::Public) {
    let private = group::Private::random(rng);
    let public = compute_public::<V>(&private);
    (private, public)
}

/// Hashes the provided message with the domain separation tag (DST) to
/// the curve.
pub fn hash_message<V: Variant>(dst: DST, message: &[u8]) -> V::Signature {
    V::Signature::hash_to_group(dst, message)
}

/// Hashes the provided message with the domain separation tag (DST) and namespace to
/// the curve.
pub fn hash_message_namespace<V: Variant>(
    dst: DST,
    namespace: &[u8],
    message: &[u8],
) -> V::Signature {
    V::Signature::hash_to_group(dst, &union_unique(namespace, message))
}

/// Signs the provided message with the private key.
pub fn sign<V: Variant>(private: &Scalar, dst: DST, message: &[u8]) -> V::Signature {
    hash_message::<V>(dst, message) * private
}

/// Verifies the signature with the provided public key.
pub fn verify<V: Variant>(
    public: &V::Public,
    dst: DST,
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    // Create hashed message `hm`
    let hm = hash_message::<V>(dst, message);

    // Verify the signature
    V::verify(public, &hm, signature)
}

/// Signs the provided message with the private key.
///
/// # Determinism
///
/// Signatures produced by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn sign_message<V: Variant>(
    private: &group::Private,
    namespace: Option<&[u8]>,
    message: &[u8],
) -> V::Signature {
    let payload = namespace.map_or(Cow::Borrowed(message), |namespace| {
        Cow::Owned(union_unique(namespace, message))
    });
    sign::<V>(private, V::MESSAGE, &payload)
}

/// Verifies the signature with the provided public key.
///
/// # Warning
///
/// This function assumes a group check was already performed on
/// `public` and `signature`.
pub fn verify_message<V: Variant>(
    public: &V::Public,
    namespace: Option<&[u8]>,
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    let payload = namespace.map_or(Cow::Borrowed(message), |namespace| {
        Cow::Owned(union_unique(namespace, message))
    });
    verify::<V>(public, V::MESSAGE, &payload, signature)
}

// =============================================================================
// PROOF OF POSSESSION
// Proof of Possession is used to prove that a party controls the private key
// corresponding to a public key. This prevents rogue key attacks in aggregate
// signature schemes.
// =============================================================================

/// Generates a proof of possession for the private key.
pub fn sign_proof_of_possession<V: Variant>(private: &group::Private) -> V::Signature {
    // Get public key
    let public = compute_public::<V>(private);

    // Sign the public key
    sign::<V>(private, V::PROOF_OF_POSSESSION, &public.encode())
}

/// Verifies a proof of possession for the provided public key.
pub fn verify_proof_of_possession<V: Variant>(
    public: &V::Public,
    signature: &V::Signature,
) -> Result<(), Error> {
    verify::<V>(public, V::PROOF_OF_POSSESSION, &public.encode(), signature)
}
