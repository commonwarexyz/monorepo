//! Anonymous credentials via threshold blind BLS signatures.
//!
//! This module implements anonymous credentials using threshold blind BLS signatures
//! based on the Boldyreva scheme (PKC 2003). A threshold signing group (e.g.,
//! validators) can issue credentials bound to a message without learning what the
//! message is. The resulting credential is a standard BLS signature verifiable with
//! [`ops::verify_message`](super::primitives::ops::verify_message).
//!
//! # Protocol
//!
//! 1. The user calls [`blind`] to hash a message to the curve and multiply by a
//!    random scalar `r`, producing a blinded point. Validators cannot recover the
//!    message from this.
//! 2. Each validator calls [`sign_blinded`] with their threshold share, producing a
//!    [`PartialSignature`]. The user (or anyone) can check each partial with
//!    [`verify_blinded`].
//! 3. The user collects enough partials and recovers the threshold signature using
//!    [`threshold::recover`](super::primitives::ops::threshold::recover).
//! 4. The user calls [`unblind`] to remove the blinding factor, yielding a standard
//!    BLS signature over the message.
//! 5. Anyone can verify the credential with
//!    [`ops::verify_message`](super::primitives::ops::verify_message) using the group
//!    public key, the namespace, and the message.
//!
//! # Security
//!
//! - **Blindness**: Validators see only uniformly random group elements during signing.
//!   They learn nothing about the message.
//! - **Binding**: The credential is a standard BLS signature over the message. It is
//!   invalid for any other message.
//! - **Unlinkability**: The same message blinded with different factors produces identical
//!   unblinded signatures but distinct blinded points. Issuance sessions cannot be
//!   correlated with redemption.
//! - **Public verifiability**: Anyone with the group public key can verify the credential
//!   via [`ops::verify_message`](super::primitives::ops::verify_message). No validator
//!   interaction is needed at redemption.
//!
//! # Key Separation
//!
//! The threshold key used for credential issuance **must not** be reused for any
//! other signing purpose (e.g., consensus certificates, regular message signing).
//!
//! In a blind signature scheme, validators sign an arbitrary group element without
//! knowing what it represents. A malicious requester could construct a blinded point
//! that, when unblinded, yields a valid signature in a different domain (e.g., a
//! consensus certificate). No cryptographic mechanism within the blind signing
//! protocol can prevent this -- it is fundamental to the blindness property.
//!
//! The standard mitigation (used by Privacy Pass, RFC 9576) is to dedicate a
//! separate key to credential issuance. A signature produced by the credential key
//! is then useless in any other context because no other protocol verifies against
//! that key.
//!
//! # Concurrent Session Limitation
//!
//! This scheme is vulnerable to Wagner's generalized birthday attack when many concurrent
//! blind signing sessions are permitted. The attack complexity for `l` concurrent sessions
//! is `O(l * p^(1 / (1 + floor(log2(l)))))` where `p` is the BLS12-381 scalar field
//! order (~2^255).
//!
//! Approximate security levels:
//!
//! - 1 concurrent session: ~2^128
//! - 2-3 concurrent sessions: ~2^85
//! - 4-7 concurrent sessions: ~2^64
//! - 128+ concurrent sessions: ~2^32 (insecure)
//!
//! **The application layer must limit concurrent blind signing sessions per user.**
//!
//! This is a fundamental property of publicly-verifiable algebraic blind signatures.
//! Schemes that resist this attack (e.g., VOPRF from Privacy Pass) do so by adding
//! a final hash that destroys public verifiability.
//!
//! # Example
//!
//! ```rust
//! use commonware_cryptography::bls12381::{
//!     credentials,
//!     primitives::{
//!         ops,
//!         ops::threshold,
//!         variant::MinSig,
//!         sharing::Mode,
//!     },
//!     dkg,
//! };
//! use commonware_utils::{NZU32, N3f1};
//! use commonware_parallel::Sequential;
//! use rand::rngs::OsRng;
//!
//! // Setup: DKG to create threshold key shares
//! let n = NZU32!(5);
//! let (sharing, shares) = dkg::deal_anonymous::<MinSig, N3f1>(&mut OsRng, Mode::default(), n);
//!
//! // User: blind a message
//! let namespace = b"my_app";
//! let message = b"payload_to_sign_anonymously";
//! let (blinding_factor, blinded) = credentials::blind::<_, MinSig>(&mut OsRng, namespace, message);
//!
//! // Validators: sign the blinded point
//! let partials: Vec<_> = shares.iter().map(|s| credentials::sign_blinded::<MinSig>(s, &blinded)).collect();
//!
//! // Validators (or user): verify each partial
//! for p in &partials {
//!     credentials::verify_blinded::<MinSig>(&sharing, &blinded, p).expect("valid partial");
//! }
//!
//! // User: recover threshold signature and unblind
//! let blinded_sig = threshold::recover::<MinSig, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
//! let credential = credentials::unblind::<MinSig>(&blinding_factor, &blinded_sig);
//!
//! // Anyone: verify the credential using standard BLS verification
//! ops::verify_message::<MinSig>(sharing.public(), namespace, message, &credential)
//!     .expect("credential should be valid");
//! ```
//!
//! # References
//!
//! - Boldyreva, "Threshold Signatures, Multisignatures and Blind Signatures Based on
//!   the Gap-Diffie-Hellman-Group Signature Scheme" (PKC 2003)
//! - Benhamouda et al., "One-More Discrete Logarithm Assumption" (EUROCRYPT 2021)
//! - Jarecki and Nazarian, "Adaptively Secure Threshold Blind BLS Signatures"
//!   (ASIACRYPT 2025)

use super::primitives::{
    group::{Scalar, Share},
    ops::hash_with_namespace,
    sharing::Sharing,
    variant::{PartialSignature, Variant},
    Error,
};
use commonware_math::algebra::{Field, Random};
use rand_core::CryptoRngCore;

/// Blinds a message for anonymous threshold signing.
///
/// Hashes the message to the signature curve and multiplies by a random scalar,
/// producing a blinded point that hides the message from validators.
///
/// Returns `(blinding_factor, blinded_point)`. The blinding factor must be kept
/// secret (it implements [`ZeroizeOnDrop`](zeroize::ZeroizeOnDrop)) and passed to
/// [`unblind`] after threshold recovery.
pub fn blind<R: CryptoRngCore, V: Variant>(
    rng: &mut R,
    namespace: &[u8],
    message: &[u8],
) -> (Scalar, V::Signature) {
    let h = hash_with_namespace::<V>(V::MESSAGE, namespace, message);
    let r = Scalar::random(rng);
    let blinded = h * &r;
    (r, blinded)
}

/// Signs a blinded point with a threshold share.
///
/// Each validator calls this with their [`Share`] and the blinded point received
/// from the user. The resulting [`PartialSignature`] can be verified with
/// [`verify_blinded`] before being sent back to the user.
pub fn sign_blinded<V: Variant>(share: &Share, blinded: &V::Signature) -> PartialSignature<V> {
    let sig = share.private.expose(|scalar| *blinded * scalar);
    PartialSignature {
        value: sig,
        index: share.index,
    }
}

/// Verifies a partial blind signature against the public polynomial.
///
/// Checks that the partial signature was produced using the correct threshold
/// share for the given blinded point. This confirms the signer used their
/// legitimate share without learning the underlying message.
pub fn verify_blinded<V: Variant>(
    sharing: &Sharing<V>,
    blinded: &V::Signature,
    partial: &PartialSignature<V>,
) -> Result<(), Error> {
    let pk = sharing.partial_public(partial.index)?;
    V::verify(&pk, blinded, &partial.value)
}

/// Removes the blinding factor from a recovered threshold signature.
///
/// After recovering the threshold signature from partial blind signatures
/// (via [`threshold::recover`](super::primitives::ops::threshold::recover)),
/// the user calls this to obtain a standard BLS signature over the original
/// message. The result can be verified with
/// [`ops::verify_message`](super::primitives::ops::verify_message).
///
/// # Panics
///
/// The blinding factor must be non-zero. This is guaranteed when using the
/// output of [`blind`], since [`Scalar::random`](Random::random) never
/// returns zero.
pub fn unblind<V: Variant>(blinding_factor: &Scalar, blinded_sig: &V::Signature) -> V::Signature {
    let r_inv = blinding_factor.inv();
    *blinded_sig * &r_inv
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{
        dkg,
        primitives::{
            group::Private,
            ops::{self, threshold},
            variant::{MinPk, MinSig},
        },
    };
    use commonware_math::algebra::Random;
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, test_rng_seeded, Faults, N3f1, NZU32};

    fn round_trip<V: Variant>() {
        let mut rng = test_rng();
        let n = NZU32!(5);
        let (sharing, shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), n);

        let namespace = b"test";
        let message = b"deadbeef01234567";

        // Client blinds
        let (blinding_factor, blinded) = blind::<_, V>(&mut rng, namespace, message);

        // Each signer produces and verifies a partial
        let partials: Vec<_> = shares
            .iter()
            .map(|s| {
                let partial = sign_blinded::<V>(s, &blinded);
                verify_blinded::<V>(&sharing, &blinded, &partial).expect("partial should be valid");
                partial
            })
            .collect();

        // Recover threshold signature and unblind
        let blinded_sig =
            threshold::recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        let credential = unblind::<V>(&blinding_factor, &blinded_sig);

        // Verify with standard BLS verification
        ops::verify_message::<V>(sharing.public(), namespace, message, &credential)
            .expect("credential should be valid");
    }

    #[test]
    fn test_round_trip() {
        round_trip::<MinPk>();
        round_trip::<MinSig>();
    }

    fn unlinkability<V: Variant>() {
        let mut rng1 = test_rng();
        let mut rng2 = test_rng_seeded(1);
        let n = NZU32!(5);
        let (sharing, shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng1, Default::default(), n);

        let namespace = b"test";
        let message = b"same_message_both_times";

        // Blind the same message with two different factors
        let (bf1, blinded1) = blind::<_, V>(&mut rng1, namespace, message);
        let (bf2, blinded2) = blind::<_, V>(&mut rng2, namespace, message);

        // Blinded points must differ (different random factors)
        assert_ne!(blinded1, blinded2, "blinded points should differ");

        // Sign and recover for both
        let partials1: Vec<_> = shares
            .iter()
            .map(|s| sign_blinded::<V>(s, &blinded1))
            .collect();
        let partials2: Vec<_> = shares
            .iter()
            .map(|s| sign_blinded::<V>(s, &blinded2))
            .collect();

        let sig1 = threshold::recover::<V, _, N3f1>(&sharing, &partials1, &Sequential).unwrap();
        let sig2 = threshold::recover::<V, _, N3f1>(&sharing, &partials2, &Sequential).unwrap();

        // Unblind both
        let cred1 = unblind::<V>(&bf1, &sig1);
        let cred2 = unblind::<V>(&bf2, &sig2);

        // Unblinded signatures must be identical (same message, same key)
        assert_eq!(cred1, cred2, "unblinded credentials should be identical");

        // Both must verify
        ops::verify_message::<V>(sharing.public(), namespace, message, &cred1)
            .expect("credential 1 should be valid");
        ops::verify_message::<V>(sharing.public(), namespace, message, &cred2)
            .expect("credential 2 should be valid");
    }

    #[test]
    fn test_unlinkability() {
        unlinkability::<MinPk>();
        unlinkability::<MinSig>();
    }

    fn wrong_message<V: Variant>() {
        let mut rng = test_rng();
        let n = NZU32!(5);
        let (sharing, shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), n);

        let namespace = b"test";
        let message = b"correct_message";
        let wrong = b"wrong_message";

        let (bf, blinded) = blind::<_, V>(&mut rng, namespace, message);
        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_blinded::<V>(s, &blinded))
            .collect();
        let blinded_sig =
            threshold::recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        let credential = unblind::<V>(&bf, &blinded_sig);

        // Must fail with wrong message
        assert!(
            ops::verify_message::<V>(sharing.public(), namespace, wrong, &credential).is_err(),
            "verification with wrong message should fail"
        );

        // Must succeed with correct message
        ops::verify_message::<V>(sharing.public(), namespace, message, &credential)
            .expect("verification with correct message should succeed");
    }

    #[test]
    fn test_wrong_message() {
        wrong_message::<MinPk>();
        wrong_message::<MinSig>();
    }

    fn wrong_namespace<V: Variant>() {
        let mut rng = test_rng();
        let n = NZU32!(5);
        let (sharing, shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), n);

        let namespace = b"correct_ns";
        let message = b"some_message";

        let (bf, blinded) = blind::<_, V>(&mut rng, namespace, message);
        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_blinded::<V>(s, &blinded))
            .collect();
        let blinded_sig =
            threshold::recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        let credential = unblind::<V>(&bf, &blinded_sig);

        assert!(
            ops::verify_message::<V>(sharing.public(), b"wrong_ns", message, &credential).is_err(),
            "verification with wrong namespace should fail"
        );
    }

    #[test]
    fn test_wrong_namespace() {
        wrong_namespace::<MinPk>();
        wrong_namespace::<MinSig>();
    }

    fn wrong_key<V: Variant>() {
        let mut rng1 = test_rng();
        let mut rng2 = test_rng_seeded(1);
        let n = NZU32!(5);
        let (sharing1, shares1) = dkg::deal_anonymous::<V, N3f1>(&mut rng1, Default::default(), n);
        let (sharing2, _) = dkg::deal_anonymous::<V, N3f1>(&mut rng2, Default::default(), n);

        let namespace = b"test";
        let message = b"some_message";

        let (bf, blinded) = blind::<_, V>(&mut rng1, namespace, message);
        let partials: Vec<_> = shares1
            .iter()
            .map(|s| sign_blinded::<V>(s, &blinded))
            .collect();
        let blinded_sig =
            threshold::recover::<V, _, N3f1>(&sharing1, &partials, &Sequential).unwrap();
        let credential = unblind::<V>(&bf, &blinded_sig);

        // Must fail with wrong public key
        assert!(
            ops::verify_message::<V>(sharing2.public(), namespace, message, &credential).is_err(),
            "verification with wrong key should fail"
        );

        // Must succeed with correct public key
        ops::verify_message::<V>(sharing1.public(), namespace, message, &credential)
            .expect("verification with correct key should succeed");
    }

    #[test]
    fn test_wrong_key() {
        wrong_key::<MinPk>();
        wrong_key::<MinSig>();
    }

    fn partial_threshold<V: Variant>() {
        let mut rng = test_rng();
        let n = NZU32!(6);
        let t = N3f1::quorum(6) as usize;
        let (sharing, shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), n);

        let namespace = b"test";
        let message = b"threshold_test";

        let (bf, blinded) = blind::<_, V>(&mut rng, namespace, message);

        // Get all partial signatures
        let all_partials: Vec<_> = shares
            .iter()
            .map(|s| sign_blinded::<V>(s, &blinded))
            .collect();

        // Recover from first t partials
        let subset1: Vec<_> = all_partials.iter().take(t).collect();
        let sig1 = threshold::recover::<V, _, N3f1>(&sharing, subset1, &Sequential).unwrap();

        // Recover from last t partials
        let subset2: Vec<_> = all_partials.iter().skip(all_partials.len() - t).collect();
        let sig2 = threshold::recover::<V, _, N3f1>(&sharing, subset2, &Sequential).unwrap();

        // Both must produce the same unblinded credential
        let cred1 = unblind::<V>(&bf, &sig1);
        let cred2 = unblind::<V>(&bf, &sig2);
        assert_eq!(
            cred1, cred2,
            "different subsets should produce same credential"
        );

        // Both must verify
        ops::verify_message::<V>(sharing.public(), namespace, message, &cred1)
            .expect("credential from subset 1 should be valid");
        ops::verify_message::<V>(sharing.public(), namespace, message, &cred2)
            .expect("credential from subset 2 should be valid");
    }

    #[test]
    fn test_partial_threshold() {
        partial_threshold::<MinPk>();
        partial_threshold::<MinSig>();
    }

    fn invalid_partial<V: Variant>() {
        let mut rng = test_rng();
        let n = NZU32!(5);
        let (sharing, mut shares) = dkg::deal_anonymous::<V, N3f1>(&mut rng, Default::default(), n);

        let namespace = b"test";
        let message = b"invalid_partial_test";

        let (bf, blinded) = blind::<_, V>(&mut rng, namespace, message);

        // Corrupt one share
        shares[2].private = Private::random(&mut rng);

        let partials: Vec<_> = shares
            .iter()
            .map(|s| sign_blinded::<V>(s, &blinded))
            .collect();

        // verify_blinded must reject the corrupted partial
        assert!(
            verify_blinded::<V>(&sharing, &blinded, &partials[0]).is_ok(),
            "valid partial should pass"
        );
        assert!(
            verify_blinded::<V>(&sharing, &blinded, &partials[2]).is_err(),
            "corrupted partial should fail"
        );

        // Recovery using all partials (including corrupted) should produce
        // an invalid credential
        let blinded_sig =
            threshold::recover::<V, _, N3f1>(&sharing, &partials, &Sequential).unwrap();
        let credential = unblind::<V>(&bf, &blinded_sig);

        assert!(
            ops::verify_message::<V>(sharing.public(), namespace, message, &credential).is_err(),
            "credential from corrupted partials should be invalid"
        );
    }

    #[test]
    fn test_invalid_partial() {
        invalid_partial::<MinPk>();
        invalid_partial::<MinSig>();
    }
}
