//! Digital signatures over the BLS12-381 curve.
//!
//! This module provides BLS12-381 signature operations:
//!
//! - Core primitives (keypair generation, signing, verification, proof of possession)
//! - [`aggregate`]: Aggregation of public keys and signatures
//! - [`batch`]: Batch verification of multiple signatures
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
//! when you only need to verify that the aggregate is valid (more efficient).

pub mod aggregate;
pub mod batch;
pub mod threshold;

use super::{
    group::{Private, DST},
    variant::Variant,
    Error,
};
use commonware_codec::Encode;
use commonware_math::algebra::{Additive, CryptoGroup, HashToGroup, Random};
use commonware_utils::union_unique;

/// Computes the public key from the private key.
pub fn compute_public<V: Variant>(private: &Private) -> V::Public {
    private.expose(|scalar| V::Public::generator() * scalar)
}

/// Returns a new keypair derived from the provided randomness.
pub fn keypair<R: rand_core::CryptoRngCore, V: Variant>(rng: &mut R) -> (Private, V::Public) {
    let private = Private::random(rng);
    let public = compute_public::<V>(&private);
    (private, public)
}

/// Hashes the provided message with the domain separation tag (DST) to
/// the curve.
pub fn hash<V: Variant>(dst: DST, message: &[u8]) -> V::Signature {
    V::Signature::hash_to_group(dst, message)
}

/// Hashes the provided message with the domain separation tag (DST) and namespace to
/// the curve.
pub fn hash_with_namespace<V: Variant>(dst: DST, namespace: &[u8], message: &[u8]) -> V::Signature {
    V::Signature::hash_to_group(dst, &union_unique(namespace, message))
}

/// Signs the provided message with the private key.
pub fn sign<V: Variant>(private: &Private, dst: DST, message: &[u8]) -> V::Signature {
    private.expose(|scalar| hash::<V>(dst, message) * scalar)
}

/// Verifies the signature with the provided public key.
pub fn verify<V: Variant>(
    public: &V::Public,
    dst: DST,
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    let hm = hash::<V>(dst, message);
    V::verify(public, &hm, signature)
}

/// Signs the provided message with the private key.
///
/// # Determinism
///
/// Signatures produced by this function are deterministic and are safe
/// to use in a consensus-critical context.
pub fn sign_message<V: Variant>(
    private: &Private,
    namespace: &[u8],
    message: &[u8],
) -> V::Signature {
    sign::<V>(private, V::MESSAGE, &union_unique(namespace, message))
}

/// Verifies the signature with the provided public key.
///
/// # Warning
///
/// This function assumes a group check was already performed on
/// `public` and `signature`.
pub fn verify_message<V: Variant>(
    public: &V::Public,
    namespace: &[u8],
    message: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    verify::<V>(
        public,
        V::MESSAGE,
        &union_unique(namespace, message),
        signature,
    )
}

/// Generates a proof of possession for the private key.
pub fn sign_proof_of_possession<V: Variant>(private: &Private, namespace: &[u8]) -> V::Signature {
    // Get public key
    let public = compute_public::<V>(private);
    let hm = hash_with_namespace::<V>(V::PROOF_OF_POSSESSION, namespace, &public.encode());

    private.expose(|scalar| hm * scalar)
}

/// Verifies a proof of possession for the provided public key.
pub fn verify_proof_of_possession<V: Variant>(
    public: &V::Public,
    namespace: &[u8],
    signature: &V::Signature,
) -> Result<(), Error> {
    if *public == V::Public::zero() || *signature == V::Signature::zero() {
        return Err(Error::InvalidSignature);
    }
    let hm = hash_with_namespace::<V>(V::PROOF_OF_POSSESSION, namespace, &public.encode());
    V::verify(public, &hm, signature)
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::{
        group::{G1_MESSAGE, G2_MESSAGE},
        variant::{MinPk, MinSig},
    };
    use blst::BLST_ERROR;
    use commonware_codec::{DecodeExt, Encode, Error as CodecError, ReadExt};
    use commonware_math::algebra::{Additive, CryptoGroup};
    use commonware_parallel::Sequential;
    use commonware_utils::{from_hex_formatted, test_rng, union_unique};
    use rstest::rstest;

    fn codec<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let (private_bytes, public_bytes) = (private.encode(), public.encode());

        let (private_decoded, public_decoded) = (
            Private::decode(private_bytes.clone()).unwrap(),
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
        namespace: &[u8],
        signature: &V::Signature,
    ) -> Result<(), BLST_ERROR> {
        let msg = union_unique(namespace, &public.encode());
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
        let namespace = b"test";
        let pop = sign_proof_of_possession::<V>(&private, namespace);

        verify_proof_of_possession::<V>(&public, namespace, &pop).expect("PoP should be valid");
        blst_verify_proof_of_possession::<V>(&public, namespace, &pop)
            .expect("PoP should be valid");
    }

    #[test]
    fn test_single_proof_of_possession() {
        single_proof_of_possession::<MinPk>();
        single_proof_of_possession::<MinSig>();
    }

    fn proof_of_possession_rejects_zero_inputs<V: Variant>() {
        let (private, public) = keypair::<_, V>(&mut test_rng());
        let namespace = b"test";
        let pop = sign_proof_of_possession::<V>(&private, namespace);

        assert!(matches!(
            verify_proof_of_possession::<V>(&V::Public::zero(), namespace, &pop),
            Err(Error::InvalidSignature)
        ));
        assert!(matches!(
            verify_proof_of_possession::<V>(&public, namespace, &V::Signature::zero()),
            Err(Error::InvalidSignature)
        ));
    }

    #[test]
    fn test_proof_of_possession_rejects_zero_inputs() {
        proof_of_possession_rejects_zero_inputs::<MinPk>();
        proof_of_possession_rejects_zero_inputs::<MinSig>();
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
        let sig = sign_message::<V>(&private, b"good", msg);
        assert!(matches!(
            verify_message::<V>(&public, b"bad", msg, &sig).unwrap_err(),
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
        let sig = sign_message::<V>(&private, namespace, msg);
        verify_message::<V>(&public, namespace, msg, &sig).expect("signature should be valid");
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
    fn test_noble_min_sig() {
        const DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

        let mut publics = Vec::new();
        let mut hms = Vec::new();
        let mut signatures = Vec::new();
        for line in MIN_SIG_TESTS.lines() {
            let parts: Vec<_> = line.split(':').collect();
            let private_bytes = from_hex_formatted(parts[0]).unwrap();
            let private = Private::read(&mut private_bytes.as_ref()).unwrap();
            let message = from_hex_formatted(parts[1]).unwrap();
            let signature = from_hex_formatted(parts[2]).unwrap();
            let mut signature =
                <MinSig as Variant>::Signature::read(&mut signature.as_ref()).unwrap();

            let computed = sign::<MinSig>(&private, DST, &message);
            assert_eq!(signature, computed);

            let public = compute_public::<MinSig>(&private);
            verify::<MinSig>(&public, DST, &message, &signature).unwrap();

            publics.push(public);
            hms.push(hash::<MinSig>(DST, &message));
            signatures.push(signature);

            signature += &<MinSig as Variant>::Signature::generator();
            assert!(verify::<MinSig>(&public, DST, &message, &signature).is_err());
        }

        assert!(
            MinSig::batch_verify(&mut test_rng(), &publics, &hms, &signatures, &Sequential).is_ok()
        );

        signatures[0] += &<MinSig as Variant>::Signature::generator();
        assert!(
            MinSig::batch_verify(&mut test_rng(), &publics, &hms, &signatures, &Sequential)
                .is_err()
        );
    }

    // Source: https://github.com/paulmillr/noble-curves/blob/bee1ffe0000095f95b982a969d06baaa3dd8ce73/test/bls12-381/bls12-381-g2-test-vectors.txt
    const MIN_PK_TESTS: &str = include_str!("test_vectors/min_pk.txt");

    #[test]
    fn test_noble_min_pk() {
        const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        let mut publics = Vec::new();
        let mut hms = Vec::new();
        let mut signatures = Vec::new();
        for line in MIN_PK_TESTS.lines() {
            let parts: Vec<_> = line.split(':').collect();
            let private_bytes = from_hex_formatted(parts[0]).unwrap();
            let private = Private::read(&mut private_bytes.as_ref()).unwrap();
            let message = from_hex_formatted(parts[1]).unwrap();
            let signature = from_hex_formatted(parts[2]).unwrap();
            let mut signature =
                <MinPk as Variant>::Signature::read(&mut signature.as_ref()).unwrap();

            let computed = sign::<MinPk>(&private, DST, &message);
            assert_eq!(signature, computed);

            let public = compute_public::<MinPk>(&private);
            verify::<MinPk>(&public, DST, &message, &signature).unwrap();

            publics.push(public);
            hms.push(hash::<MinPk>(DST, &message));
            signatures.push(signature);

            signature += &<MinPk as Variant>::Signature::generator();
            assert!(verify::<MinPk>(&public, DST, &message, &signature).is_err());
        }

        assert!(
            MinPk::batch_verify(&mut test_rng(), &publics, &hms, &signatures, &Sequential).is_ok()
        );

        signatures[0] += &<MinPk as Variant>::Signature::generator();
        assert!(
            MinPk::batch_verify(&mut test_rng(), &publics, &hms, &signatures, &Sequential).is_err()
        );
    }

    fn parse_sign_vector(
        private_key: &str,
        msg: &str,
        signature: &str,
    ) -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        (
            parse_private_key(private_key).unwrap(),
            commonware_utils::from_hex_formatted(msg).unwrap(),
            parse_signature(signature).unwrap(),
        )
    }

    fn parse_private_key(private_key: &str) -> Result<Private, CodecError> {
        let bytes = commonware_utils::from_hex_formatted(private_key).unwrap();
        Private::decode(bytes.as_ref())
    }

    fn parse_public_key(public_key: &str) -> Result<<MinPk as Variant>::Public, CodecError> {
        let bytes = commonware_utils::from_hex_formatted(public_key).unwrap();
        <MinPk as Variant>::Public::decode(bytes.as_ref())
    }

    fn parse_signature(signature: &str) -> Result<<MinPk as Variant>::Signature, CodecError> {
        let bytes = commonware_utils::from_hex_formatted(signature).unwrap();
        <MinPk as Variant>::Signature::decode(bytes.as_ref())
    }

    fn parse_verify_vector(
        public_key: &str,
        msg: &str,
        signature: &str,
    ) -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
    ) {
        (
            parse_public_key(public_key),
            commonware_utils::from_hex_formatted(msg).unwrap(),
            parse_signature(signature),
        )
    }

    #[test]
    fn test_zero_key_is_decodable() {
        let result =
            parse_private_key("0x0000000000000000000000000000000000000000000000000000000000000000");
        assert!(result.is_ok());
    }

    /// Test vectors sourced from https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2.
    #[rstest]
    #[case(vector_sign_1())]
    #[case(vector_sign_2())]
    #[case(vector_sign_3())]
    #[case(vector_sign_4())]
    #[case(vector_sign_5())]
    #[case(vector_sign_6())]
    #[case(vector_sign_7())]
    #[case(vector_sign_8())]
    #[case(vector_sign_9())]
    fn test_eth_sign(
        #[case] (private_key, message, expected): (Private, Vec<u8>, <MinPk as Variant>::Signature),
    ) {
        let signature = sign::<MinPk>(&private_key, MinPk::MESSAGE, &message);
        assert_eq!(signature, expected);
    }

    /// Test vectors sourced from https://github.com/ethereum/bls12-381-tests/releases/tag/v0.1.2.
    #[rstest]
    #[case(vector_verify_1())]
    #[case(vector_verify_2())]
    #[case(vector_verify_3())]
    #[case(vector_verify_4())]
    #[case(vector_verify_5())]
    #[case(vector_verify_6())]
    #[case(vector_verify_7())]
    #[case(vector_verify_8())]
    #[case(vector_verify_9())]
    #[case(vector_verify_10())]
    #[case(vector_verify_11())]
    #[case(vector_verify_12())]
    #[case(vector_verify_13())]
    #[case(vector_verify_14())]
    #[case(vector_verify_15())]
    #[case(vector_verify_16())]
    #[case(vector_verify_17())]
    #[case(vector_verify_18())]
    #[case(vector_verify_19())]
    #[case(vector_verify_20())]
    #[case(vector_verify_21())]
    #[case(vector_verify_22())]
    #[case(vector_verify_23())]
    #[case(vector_verify_24())]
    #[case(vector_verify_25())]
    #[case(vector_verify_26())]
    #[case(vector_verify_27())]
    #[case(vector_verify_28())]
    #[case(vector_verify_29())]
    fn test_eth_verify(
        #[case] (public_key, message, signature, expected): (
            Result<<MinPk as Variant>::Public, CodecError>,
            Vec<u8>,
            Result<<MinPk as Variant>::Signature, CodecError>,
            bool,
        ),
    ) {
        let expected = if !expected {
            public_key.is_err()
                || signature.is_err()
                || verify::<MinPk>(
                    &public_key.unwrap(),
                    MinPk::MESSAGE,
                    &message,
                    &signature.unwrap(),
                )
                .is_err()
        } else {
            let public_key = public_key.unwrap();
            let signature = signature.unwrap();

            // Verify using single verification
            let single_result =
                verify::<MinPk>(&public_key, MinPk::MESSAGE, &message, &signature).is_ok();

            // Verify using batch verification
            let hm = hash::<MinPk>(MinPk::MESSAGE, &message);
            let batch_result = MinPk::batch_verify(
                &mut rand::thread_rng(),
                &[public_key],
                &[hm],
                &[signature],
                &Sequential,
            )
            .is_ok();

            single_result && batch_result
        };
        assert!(expected);
    }

    #[test]
    fn test_eth_batch_verify() {
        let all_vectors = [
            vector_verify_1(),
            vector_verify_2(),
            vector_verify_3(),
            vector_verify_4(),
            vector_verify_5(),
            vector_verify_6(),
            vector_verify_7(),
            vector_verify_8(),
            vector_verify_9(),
            vector_verify_10(),
            vector_verify_11(),
            vector_verify_12(),
            vector_verify_13(),
            vector_verify_14(),
            vector_verify_15(),
            vector_verify_16(),
            vector_verify_17(),
            vector_verify_18(),
            vector_verify_19(),
            vector_verify_20(),
            vector_verify_21(),
            vector_verify_22(),
            vector_verify_23(),
            vector_verify_24(),
            vector_verify_25(),
            vector_verify_26(),
            vector_verify_27(),
            vector_verify_28(),
            vector_verify_29(),
        ];

        let mut valid_publics = Vec::new();
        let mut valid_hms = Vec::new();
        let mut valid_signatures = Vec::new();
        let mut all_publics = Vec::new();
        let mut all_hms = Vec::new();
        let mut all_signatures = Vec::new();

        for (public_key, message, signature, expected) in all_vectors {
            let Ok(public_key) = public_key else {
                continue;
            };
            let Ok(signature) = signature else {
                continue;
            };
            let hm = hash::<MinPk>(MinPk::MESSAGE, &message);
            if expected {
                valid_publics.push(public_key);
                valid_hms.push(hm);
                valid_signatures.push(signature);
            }
            all_publics.push(public_key);
            all_hms.push(hm);
            all_signatures.push(signature);
        }

        MinPk::batch_verify(
            &mut rand::thread_rng(),
            &valid_publics,
            &valid_hms,
            &valid_signatures,
            &Sequential,
        )
        .expect("batch verify of valid vectors should succeed");

        assert!(MinPk::batch_verify(
            &mut rand::thread_rng(),
            &all_publics,
            &all_hms,
            &all_signatures,
            &Sequential,
        )
        .is_err());
    }

    // sign_case_8cd3d4d0d9a5b265
    fn vector_sign_1() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        )
    }

    // sign_case_11b8c7cad5238946
    fn vector_sign_2() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        )
    }

    // sign_case_84d45c9c7cca6b92
    fn vector_sign_3() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        )
    }

    // sign_case_142f678a8d05fcd1
    fn vector_sign_4() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        )
    }

    // sign_case_37286e1a6d1f6eb3
    fn vector_sign_5() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        )
    }

    // sign_case_7055381f640f2c1d
    fn vector_sign_6() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        )
    }

    // sign_case_c82df61aa3ee60fb
    fn vector_sign_7() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        )
    }

    // sign_case_d0e28d7e76eb6e9c
    fn vector_sign_8() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        )
    }

    // sign_case_f2ae1097e7d0e18b
    fn vector_sign_9() -> (Private, Vec<u8>, <MinPk as Variant>::Signature) {
        parse_sign_vector(
            "0x263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        )
    }

    // verify_infinity_pubkey_and_infinity_signature
    fn vector_verify_1() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0x1212121212121212121212121212121212121212121212121212121212121212",
            "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_2ea479adf8c40300
    fn vector_verify_2() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_2f09d443ab8a3ac2
    fn vector_verify_3() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_6b3b17f6962a490c
    fn vector_verify_4() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xa4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_6eeb7c52dfd9baf0
    fn vector_verify_5() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_8761a0b7e920c323
    fn vector_verify_6() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b71ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_195246ee3bd3b6ec
    fn vector_verify_7() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_3208262581c8fc09
    fn vector_verify_8() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363ffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_d34885d766d5f705
    fn vector_verify_9() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075effffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_tampered_signature_case_e8a50c445c855360
    fn vector_verify_10() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_valid_case_2ea479adf8c40300
    fn vector_verify_11() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_2f09d443ab8a3ac2
    fn vector_verify_12() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_6b3b17f6962a490c
    fn vector_verify_13() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xa4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_6eeb7c52dfd9baf0
    fn vector_verify_14() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_8761a0b7e920c323
    fn vector_verify_15() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_195246ee3bd3b6ec
    fn vector_verify_16() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_3208262581c8fc09
    fn vector_verify_17() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_d34885d766d5f705
    fn vector_verify_18() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_valid_case_e8a50c445c855360
    fn vector_verify_19() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        );
        (v.0, v.1, v.2, true)
    }

    // verify_wrong_pubkey_case_2ea479adf8c40300
    fn vector_verify_20() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xa4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_2f09d443ab8a3ac2
    fn vector_verify_21() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_6b3b17f6962a490c
    fn vector_verify_22() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0xaf1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_6eeb7c52dfd9baf0
    fn vector_verify_23() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0xabababababababababababababababababababababababababababababababab",
            "0x91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_8761a0b7e920c323
    fn vector_verify_24() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0xabababababababababababababababababababababababababababababababab",
            "0xae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_195246ee3bd3b6ec
    fn vector_verify_25() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0xabababababababababababababababababababababababababababababababab",
            "0x9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_3208262581c8fc09
    fn vector_verify_26() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "0x5656565656565656565656565656565656565656565656565656565656565656",
            "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_d34885d766d5f705
    fn vector_verify_27() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xb53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0xb23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        );
        (v.0, v.1, v.2, false)
    }

    // verify_wrong_pubkey_case_e8a50c445c855360
    fn vector_verify_28() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        );
        (v.0, v.1, v.2, false)
    }

    // verifycase_one_privkey_47117849458281be
    fn vector_verify_29() -> (
        Result<<MinPk as Variant>::Public, CodecError>,
        Vec<u8>,
        Result<<MinPk as Variant>::Signature, CodecError>,
        bool,
    ) {
        let v = parse_verify_vector(
            "0x97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
            "0x1212121212121212121212121212121212121212121212121212121212121212",
            "0xa42ae16f1c2a5fa69c04cb5998d2add790764ce8dd45bf25b29b4700829232052b52352dcff1cf255b3a7810ad7269601810f03b2bc8b68cf289cf295b206770605a190b6842583e47c3d1c0f73c54907bfb2a602157d46a4353a20283018763",
        );
        (v.0, v.1, v.2, true)
    }
}
