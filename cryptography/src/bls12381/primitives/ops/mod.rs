//! Digital signatures over the BLS12-381 curve.
//!
//! This module provides BLS12-381 signature operations:
//!
//! - Core primitives (keypair generation, signing, verification, proof of possession)
//! - [`aggregate`]: Aggregation of public keys and signatures
//! - [`batch`]: Batch verification ensuring each individual signature is valid
//! - [`threshold`]: Threshold signature operations
//!
//! # Domain Separation Tag (DST)
//!
//! All signatures use the `POP` (Proof of Possession) scheme during signing. For Proof-of-Possession (POP) signatures,
//! the domain separation tag is `BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. For signatures over other messages, the
//! domain separation tag is `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`. You can read more about DSTs [here](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2).
//!
//! # Batch vs Aggregate Verification
//!
//! Use [`batch`] when you need to ensure each individual signature is valid. Use [`aggregate`]
//! when you only need to verify that the aggregate is valid (more efficient, but an attacker
//! could redistribute signature components between signers while keeping the aggregate unchanged).
//! Batch verification uses random scalar weights internally to prevent this attack.

pub mod aggregate;
pub mod batch;
pub mod threshold;

use super::{
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

/// Hashes a message with an optional namespace to the signature curve.
pub fn hash_message_with_namespace<V: Variant>(
    namespace: Option<&[u8]>,
    message: &[u8],
) -> V::Signature {
    namespace.map_or_else(
        || hash_message::<V>(V::MESSAGE, message),
        |ns| hash_message_namespace::<V>(V::MESSAGE, ns, message),
    )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{
        group::{G1_MESSAGE, G2_MESSAGE},
        variant::{MinPk, MinSig},
    };
    use blst::BLST_ERROR;
    use commonware_codec::{DecodeExt, Encode, ReadExt};
    use commonware_math::algebra::CryptoGroup;
    use commonware_utils::{from_hex_formatted, test_rng, union_unique};
    use rand::rngs::OsRng;

    fn codec<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let (private_bytes, public_bytes) = (private.encode(), public.encode());

        let (private_decoded, public_decoded) = (
            group::Private::decode(private_bytes.clone()).unwrap(),
            V::Public::decode(public_bytes.clone()).unwrap(),
        );

        assert_eq!(private, private_decoded);
        assert_eq!(public, public_decoded);

        match V::MESSAGE {
            G1_MESSAGE => {
                blst::min_sig::SecretKey::from_bytes(&private_bytes).unwrap();
                let blst_public_decoded =
                    blst::min_sig::PublicKey::from_bytes(&public_bytes).unwrap();
                blst_public_decoded.validate().unwrap();
                let blst_public_encoded = blst_public_decoded.compress().to_vec();
                assert_eq!(public_bytes, blst_public_encoded.as_slice());
            }
            G2_MESSAGE => {
                blst::min_pk::SecretKey::from_bytes(&private_bytes).unwrap();
                let blst_public_decoded =
                    blst::min_pk::PublicKey::from_bytes(&public_bytes).unwrap();
                blst_public_decoded.validate().unwrap();
                let blst_public_encoded = blst_public_decoded.compress().to_vec();
                assert_eq!(public_bytes, blst_public_encoded.as_slice());
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    #[test]
    fn test_codec() {
        codec::<MinPk>();
        codec::<MinSig>();
    }

    fn blst_verify_proof_of_possession<V: Variant>(
        public: &V::Public,
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR> {
        let msg = public.encode();
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, &msg, V::PROOF_OF_POSSESSION, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = blst::min_pk::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_pk::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, &msg, V::PROOF_OF_POSSESSION, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    fn single_proof_of_possession<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let pop = sign_proof_of_possession::<V>(&private);

        verify_proof_of_possession::<V>(&public, &pop).expect("PoP should be valid");
        blst_verify_proof_of_possession::<V>(&public, &pop).expect("PoP should be valid");
    }

    #[test]
    fn test_single_proof_of_possession() {
        single_proof_of_possession::<MinPk>();
        single_proof_of_possession::<MinSig>();
    }

    fn blst_verify_message<V: Variant>(
        public: &V::Public,
        msg: &[u8],
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR> {
        match V::MESSAGE {
            G1_MESSAGE => {
                let public = blst::min_sig::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_sig::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, msg, V::MESSAGE, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            G2_MESSAGE => {
                let public = blst::min_pk::PublicKey::from_bytes(&public.encode()).unwrap();
                let signature = blst::min_pk::Signature::from_bytes(&signature.encode()).unwrap();
                match signature.verify(true, msg, V::MESSAGE, &[], &public, true) {
                    BLST_ERROR::BLST_SUCCESS => Ok(()),
                    e => Err(e),
                }
            }
            _ => panic!("Unsupported Variant"),
        }
    }

    fn bad_namespace<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let msg = &[1, 9, 6, 9];
        let sig = sign_message::<V>(&private, Some(b"good"), msg);
        assert!(matches!(
            verify_message::<V>(&public, Some(b"bad"), msg, &sig).unwrap_err(),
            Error::InvalidSignature
        ));
    }

    #[test]
    fn test_bad_namespace() {
        bad_namespace::<MinPk>();
        bad_namespace::<MinSig>();
    }

    fn single_message<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let msg = &[1, 9, 6, 9];
        let namespace = b"test";
        let sig = sign_message::<V>(&private, Some(namespace), msg);
        verify_message::<V>(&public, Some(namespace), msg, &sig)
            .expect("signature should be valid");
        let payload = union_unique(namespace, msg);
        blst_verify_message::<V>(&public, &payload, &sig).expect("signature should be valid");
    }

    #[test]
    fn test_single_message() {
        single_message::<MinPk>();
        single_message::<MinSig>();
    }

    // Source: https://github.com/paulmillr/noble-curves/blob/bee1ffe0000095f95b982a969d06baaa3dd8ce73/test/bls12-381/bls12-381-g1-test-vectors.txt
    const MIN_SIG_TESTS: &str = include_str!("test_vectors/min_sig.txt");

    #[test]
    fn test_min_sig() {
        const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

        let mut publics = Vec::new();
        let mut hms = Vec::new();
        let mut signatures = Vec::new();
        for line in MIN_SIG_TESTS.lines() {
            let parts: Vec<_> = line.split(':').collect();
            let private = from_hex_formatted(parts[0]).unwrap();
            let private = Scalar::read(&mut private.as_ref()).unwrap();
            let message = from_hex_formatted(parts[1]).unwrap();
            let signature = from_hex_formatted(parts[2]).unwrap();
            let mut signature =
                <MinSig as Variant>::Signature::read(&mut signature.as_ref()).unwrap();

            let computed = sign::<MinSig>(&private, DST, &message);
            assert_eq!(signature, computed);

            let public = compute_public::<MinSig>(&private);
            verify::<MinSig>(&public, DST, &message, &signature).unwrap();

            publics.push(public);
            hms.push(hash_message::<MinSig>(DST, &message));
            signatures.push(signature);

            signature += &<MinSig as Variant>::Signature::generator();
            assert!(verify::<MinSig>(&public, DST, &message, &signature).is_err());
        }

        assert!(MinSig::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_ok());

        signatures[0] += &<MinSig as Variant>::Signature::generator();
        assert!(MinSig::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_err());
    }

    // Source: https://github.com/paulmillr/noble-curves/blob/bee1ffe0000095f95b982a969d06baaa3dd8ce73/test/bls12-381/bls12-381-g2-test-vectors.txt
    const MIN_PK_TESTS: &str = include_str!("test_vectors/min_pk.txt");

    #[test]
    fn test_min_pk() {
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        let mut publics = Vec::new();
        let mut hms = Vec::new();
        let mut signatures = Vec::new();
        for line in MIN_PK_TESTS.lines() {
            let parts: Vec<_> = line.split(':').collect();
            let private = from_hex_formatted(parts[0]).unwrap();
            let private = Scalar::read(&mut private.as_ref()).unwrap();
            let message = from_hex_formatted(parts[1]).unwrap();
            let signature = from_hex_formatted(parts[2]).unwrap();
            let mut signature =
                <MinPk as Variant>::Signature::read(&mut signature.as_ref()).unwrap();

            let computed = sign::<MinPk>(&private, DST, &message);
            assert_eq!(signature, computed);

            let public = compute_public::<MinPk>(&private);
            verify::<MinPk>(&public, DST, &message, &signature).unwrap();

            publics.push(public);
            hms.push(hash_message::<MinPk>(DST, &message));
            signatures.push(signature);

            signature += &<MinPk as Variant>::Signature::generator();
            assert!(verify::<MinPk>(&public, DST, &message, &signature).is_err());
        }

        assert!(MinPk::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_ok());

        signatures[0] += &<MinPk as Variant>::Signature::generator();
        assert!(MinPk::batch_verify(&mut OsRng, &publics, &hms, &signatures).is_err());
    }
}
