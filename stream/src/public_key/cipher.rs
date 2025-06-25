use crate::Error;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, KeySizeUser};
use commonware_cryptography::{CoreSha256, Hasher, Sha256};
use hkdf::{hmac::digest::typenum::Unsigned, Hkdf};
use zeroize::Zeroize;

/// The size of the key used by the ChaCha20Poly1305 cipher.
const CHACHA_KEY_SIZE: usize = <ChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE;

/// A constant prefix used for the salt hash in the HKDF key derivation.
/// This prevents key derivation collisions with other applications.
const BASE_KDF_PREFIX: &[u8] = b"commonware-stream/KDF/v1/";

// Constant infos for directional ciphers.
const TRAFFIC_INFO_D2L: &[u8] = b"d2l/traffic";
const TRAFFIC_INFO_L2D: &[u8] = b"l2d/traffic";
const CONFIRMATION_INFO_D2L: &[u8] = b"d2l/confirmation";
const CONFIRMATION_INFO_L2D: &[u8] = b"l2d/confirmation";

/// Return value when deriving directional ciphers.
///
/// Contains all four ciphers needed for a complete bidirectional encrypted connection:
/// two for traffic (one per direction) and two for key confirmation during handshake.
pub struct DirectionalCipher {
    /// The cipher used for sending messages from the dialer to the listener.
    pub d2l: ChaCha20Poly1305,
    /// The cipher used for sending messages from the listener to the dialer.
    pub l2d: ChaCha20Poly1305,
    /// The cipher used for key confirmation by the dialer during the handshake.
    pub d2l_confirmation: ChaCha20Poly1305,
    /// The cipher used for key confirmation by the listener during the handshake.
    pub l2d_confirmation: ChaCha20Poly1305,
}

/// Derive directional ChaCha20Poly1305 ciphers from a given input key material, a unique
/// application namespace, and the handshake transcript.
///
/// Returns a DirectionalCipher struct containing the four directional ciphers.
pub fn derive_directional(
    ikm: &[u8],
    namespace: &[u8],
    handshake_transcript: &[u8],
) -> Result<DirectionalCipher, Error> {
    let infos = [
        TRAFFIC_INFO_D2L,
        TRAFFIC_INFO_L2D,
        CONFIRMATION_INFO_D2L,
        CONFIRMATION_INFO_L2D,
    ];
    let salts = [namespace, handshake_transcript];
    let ciphers = derive::<4>(ikm, &salts, &infos)?;
    let [d2l, l2d, d2l_confirmation, l2d_confirmation] = ciphers;
    Ok(DirectionalCipher {
        d2l,
        l2d,
        d2l_confirmation,
        l2d_confirmation,
    })
}

/// Key Derivation Function (KDF) to derive ChaCha20Poly1305 ciphers using HKDF-SHA256.
///
/// This function derives ChaCha20Poly1305 ciphers based on:
/// - The input key material (IKM), usually the shared secret from the Diffie-Hellman key exchange
/// - An ordered list of byte slices (salts), where the order is critical for consistent derivation
///
/// Returns a vector of ChaCha20Poly1305 ciphers, one for each info.
pub fn derive<const N: usize>(
    ikm: &[u8],
    salts: &[&[u8]],
    infos: &[&[u8]],
) -> Result<[ChaCha20Poly1305; N], Error> {
    // Create a unique salt for the HKDF expansion.
    // The salt is generated from a commonware-specific prefix and the list of salts provided.
    let mut hasher = Sha256::default();
    hasher.update(BASE_KDF_PREFIX);
    for salt in salts {
        hasher.update(salt);
    }
    let mut salt = hasher.finalize();

    // HKDF-Extract: creates a pseudorandom key (PRK)
    let prk = Hkdf::<CoreSha256>::new(Some(salt.as_ref()), ikm);
    salt.zeroize();

    // Expand the PRK to derive a ChaCha20Poly1305 key for each info.
    let mut result = Vec::with_capacity(N);
    let mut buf = [0u8; CHACHA_KEY_SIZE];
    for info in infos.iter() {
        prk.expand(info, &mut buf)
            .map_err(|_| Error::HKDFExpansion)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&buf).map_err(|_| Error::CipherCreation)?;
        result.push(cipher);
    }
    buf.zeroize();

    // The `map_err` should never happen, but is needed to satisfy compilation due to
    // `ChaCha20Poly1305` not implementing `Debug`.
    Ok(result
        .try_into()
        .map_err(|_| Error::CipherCreation)
        .expect("Failed to convert Vec to array"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead;

    // Helper function to test parameter sensitivity (reduces code duplication)
    fn test_parameter_sensitivity<const N: usize>(
        base_ikm: &[u8],
        base_salts: &[&[u8]],
        base_infos: &[&[u8]],
        modified_salts: &[&[u8]],
        modified_infos: &[&[u8]],
        test_name: &str,
    ) {
        let base_ciphers = derive::<N>(base_ikm, base_salts, base_infos).unwrap();
        let modified_salt_ciphers = derive::<N>(base_ikm, modified_salts, base_infos).unwrap();
        let modified_info_ciphers = derive::<N>(base_ikm, base_salts, modified_infos).unwrap();

        let nonce = Default::default();
        let plaintext = format!("{}_test", test_name);

        // All variants should produce different results
        for i in 0..N {
            let base_ct = base_ciphers[i]
                .encrypt(&nonce, plaintext.as_bytes())
                .unwrap();
            let salt_ct = modified_salt_ciphers[i]
                .encrypt(&nonce, plaintext.as_bytes())
                .unwrap();
            let info_ct = modified_info_ciphers[i]
                .encrypt(&nonce, plaintext.as_bytes())
                .unwrap();

            assert_ne!(
                base_ct, salt_ct,
                "Cipher {} should be sensitive to salt changes in {}",
                i, test_name
            );
            assert_ne!(
                base_ct, info_ct,
                "Cipher {} should be sensitive to info changes in {}",
                i, test_name
            );
        }
    }

    #[test]
    fn test_derive_basic_functionality() {
        let ikm = [1u8; CHACHA_KEY_SIZE];
        let salts: &[&[u8]] = &[b"salt1", b"salt2"];
        let infos: &[&[u8]] = &[b"info1", b"info2"];

        let result = derive::<2>(&ikm, salts, infos);
        assert!(result.is_ok(), "Basic derivation should succeed");
        let [cipher1, cipher2] = result.unwrap();

        // Test that different ciphers produce different outputs
        let nonce = Default::default();
        let plaintext = b"test_message";
        let ct1 = cipher1.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let ct2 = cipher2.encrypt(&nonce, plaintext.as_ref()).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_derive_consistency() {
        let ikm = [2u8; CHACHA_KEY_SIZE];
        let salts: &[&[u8]] = &[b"consistent_salt"];
        let infos: &[&[u8]] = &[b"info1", b"info2"];

        let [c1_a, c2_a] = derive::<2>(&ikm, salts, infos).unwrap();
        let [c1_b, c2_b] = derive::<2>(&ikm, salts, infos).unwrap();

        let nonce = Default::default();
        let plaintext = b"consistency_test";

        assert_eq!(
            c1_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            c1_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
        );
        assert_eq!(
            c2_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            c2_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
        );
    }

    #[test]
    fn test_parameter_sensitivity_comprehensive() {
        let ikm = [3u8; CHACHA_KEY_SIZE];

        // Test content sensitivity
        test_parameter_sensitivity::<2>(
            &ikm,
            &[b"salt_A", b"salt_C"],
            &[b"info_A", b"info_C"],
            &[b"salt_B", b"salt_D"], // Changed both salts
            &[b"info_B", b"info_D"], // Changed both infos
            "content_sensitivity",
        );

        // Test order sensitivity
        test_parameter_sensitivity::<2>(
            &ikm,
            &[b"first", b"second"],
            &[b"info_first", b"info_second"],
            &[b"second", b"first"],           // Swapped order
            &[b"info_second", b"info_first"], // Swapped order
            "order_sensitivity",
        );

        // Test count sensitivity
        let [cipher_single] = derive::<1>(&ikm, &[b"single_salt"], &[b"single_info"]).unwrap();
        let [cipher_multi, _] = derive::<2>(
            &ikm,
            &[b"multi_salt1", b"multi_salt2"],
            &[b"single_info", b"extra_info"],
        )
        .unwrap();

        let nonce = Default::default();
        let plaintext = b"count_test";
        assert_ne!(
            cipher_single.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher_multi.encrypt(&nonce, plaintext.as_ref()).unwrap(),
        );
    }

    #[test]
    fn test_ikm_sensitivity() {
        let salts: &[&[u8]] = &[b"common_salt"];
        let infos: &[&[u8]] = &[b"info1", b"info2"];

        let ikm1 = [1u8; CHACHA_KEY_SIZE];
        let ikm2 = [2u8; CHACHA_KEY_SIZE];

        let [c1_ikm1, c2_ikm1] = derive::<2>(&ikm1, salts, infos).unwrap();
        let [c1_ikm2, c2_ikm2] = derive::<2>(&ikm2, salts, infos).unwrap();

        let nonce = Default::default();
        let plaintext = b"ikm_test";

        assert_ne!(
            c1_ikm1.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            c1_ikm2.encrypt(&nonce, plaintext.as_ref()).unwrap(),
        );
        assert_ne!(
            c2_ikm1.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            c2_ikm2.encrypt(&nonce, plaintext.as_ref()).unwrap(),
        );
    }

    #[test]
    fn test_empty_parameters() {
        let ikm = [4u8; CHACHA_KEY_SIZE];

        // Empty arrays should work
        let empty_salts: [&[u8]; 0] = [];
        let empty_infos: [&[u8]; 0] = [];
        let result = derive::<0>(&ikm, &empty_salts, &empty_infos);
        assert!(result.is_ok(), "Empty parameter arrays should work");
        assert_eq!(result.unwrap().len(), 0);

        // Empty content should work but be different from non-empty
        let [cipher_empty] = derive::<1>(&ikm, &[b""], &[b""]).unwrap();
        let [cipher_non_empty] = derive::<1>(&ikm, &[b"salt"], &[b"info"]).unwrap();

        let nonce = Default::default();
        let plaintext = b"empty_test";
        assert_ne!(
            cipher_empty.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher_non_empty
                .encrypt(&nonce, plaintext.as_ref())
                .unwrap(),
        );
    }

    #[test]
    fn test_round_trip_encryption() {
        let ikm = [5u8; CHACHA_KEY_SIZE];
        let salts: &[&[u8]] = &[b"encryption_salt"];
        let infos: &[&[u8]] = &[b"encryption_info"];
        let [cipher] = derive::<1>(&ikm, salts, infos).unwrap();

        let nonce = Default::default();
        let original_plaintext = b"secret message that should round-trip correctly";

        // Encrypt then decrypt
        let ciphertext = cipher.encrypt(&nonce, original_plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(original_plaintext.as_ref(), decrypted);

        // Verify ciphertext is actually different from plaintext
        assert_ne!(original_plaintext.as_ref(), ciphertext.as_slice());
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertexts() {
        let ikm = [6u8; CHACHA_KEY_SIZE];
        let [cipher] = derive::<1>(&ikm, &[b"nonce_test_salt"], &[b"nonce_test_info"]).unwrap();

        let plaintext = b"same message";
        let nonce1 = [0u8; 12];
        let nonce2 = [1u8; 12];

        let ct1 = cipher.encrypt(&nonce1.into(), plaintext.as_ref()).unwrap();
        let ct2 = cipher.encrypt(&nonce2.into(), plaintext.as_ref()).unwrap();

        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_various_const_generic_sizes() {
        let ikm = [7u8; CHACHA_KEY_SIZE];
        let salts: &[&[u8]] = &[b"size_test_salt"];

        // Test different sizes
        let infos1: &[&[u8]] = &[b"info1"];
        let infos3: &[&[u8]] = &[b"info1", b"info2", b"info3"];
        let infos4: &[&[u8]] = &[b"info1", b"info2", b"info3", b"info4"];

        let result1 = derive::<1>(&ikm, salts, infos1);
        let result3 = derive::<3>(&ikm, salts, infos3);
        let result4 = derive::<4>(&ikm, salts, infos4);

        assert!(result1.is_ok(), "N=1 should work");
        assert!(result3.is_ok(), "N=3 should work");
        assert!(result4.is_ok(), "N=4 should work");

        assert_eq!(result1.unwrap().len(), 1);
        assert_eq!(result3.unwrap().len(), 3);
        assert_eq!(result4.unwrap().len(), 4);
    }

    #[test]
    fn test_zero_length_ikm() {
        let empty_ikm = [];
        let salts: &[&[u8]] = &[b"salt"];
        let infos: &[&[u8]] = &[b"info"];

        // This should still work - HKDF can handle empty IKM
        let result = derive::<1>(&empty_ikm, salts, infos);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_inputs() {
        let large_ikm = [42u8; 1024]; // Much larger than typical
        let large_salt = vec![0u8; 1024];
        let large_info = vec![1u8; 1024];

        let salts: &[&[u8]] = &[large_salt.as_slice()];
        let infos: &[&[u8]] = &[large_info.as_slice()];

        let result = derive::<1>(&large_ikm, salts, infos);
        assert!(result.is_ok());
    }

    #[test]
    fn test_derive_directional_functionality() {
        let ikm = b"directional_test_ikm";
        let namespace = b"test_namespace";
        let transcript = b"test_handshake_transcript_data";

        let result = derive_directional(ikm, namespace, transcript);
        assert!(result.is_ok(), "derive_directional should succeed");

        let directional = result.unwrap();

        // Test that all four ciphers produce different outputs
        let nonce = Default::default();
        let plaintext = b"directional_test";

        let d2l_ct = directional.d2l.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let l2d_ct = directional.l2d.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let d2l_conf_ct = directional
            .d2l_confirmation
            .encrypt(&nonce, plaintext.as_ref())
            .unwrap();
        let l2d_conf_ct = directional
            .l2d_confirmation
            .encrypt(&nonce, plaintext.as_ref())
            .unwrap();

        let ciphertexts = [&d2l_ct, &l2d_ct, &d2l_conf_ct, &l2d_conf_ct];

        // Ensure all are unique
        for i in 0..ciphertexts.len() {
            for j in (i + 1)..ciphertexts.len() {
                assert_ne!(ciphertexts[i], ciphertexts[j]);
            }
        }
    }

    #[test]
    fn test_derive_directional_consistency() {
        let ikm = b"consistency_ikm";
        let namespace = b"consistency_namespace";
        let transcript = b"consistency_test_transcript";

        let dir1 = derive_directional(ikm, namespace, transcript).unwrap();
        let dir2 = derive_directional(ikm, namespace, transcript).unwrap();

        let nonce = Default::default();
        let plaintext = b"consistency_check";

        // All corresponding ciphers should be identical
        assert_eq!(
            dir1.d2l.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            dir2.d2l.encrypt(&nonce, plaintext.as_ref()).unwrap(),
        );
        assert_eq!(
            dir1.l2d.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            dir2.l2d.encrypt(&nonce, plaintext.as_ref()).unwrap(),
        );
    }

    #[test]
    fn test_derive_directional_input_sensitivity() {
        let base_ikm = b"base_ikm";
        let base_namespace = b"base_namespace";
        let base_transcript = b"base_test_transcript";

        let base_dir = derive_directional(base_ikm, base_namespace, base_transcript).unwrap();

        // Test sensitivity to each parameter by changing one at a time
        let variants = [
            derive_directional(b"different_ikm", base_namespace, base_transcript).unwrap(),
            derive_directional(base_ikm, b"different_namespace", base_transcript).unwrap(),
            derive_directional(base_ikm, base_namespace, b"different_transcript_1").unwrap(),
            derive_directional(base_ikm, base_namespace, b"different_transcript_2").unwrap(),
        ];

        let nonce = Default::default();
        let plaintext = b"sensitivity_test";
        let base_ct = base_dir.d2l.encrypt(&nonce, plaintext.as_ref()).unwrap();

        for variant in variants.iter() {
            let variant_ct = variant.d2l.encrypt(&nonce, plaintext.as_ref()).unwrap();
            assert_ne!(base_ct, variant_ct);
        }
    }

    #[test]
    fn test_realistic_sizes() {
        // Test with realistic sizes for production use
        let ikm = [42u8; 32]; // Typical ECDH shared secret size
        let namespace = b"production-app-v2.1.0";

        let transcript = b"realistic_test_transcript_with_reasonable_length_for_testing";
        let result = derive_directional(&ikm, namespace, transcript);
        assert!(result.is_ok(), "Realistic inputs should work correctly");

        let directional = result.unwrap();

        // Test that we can actually use these ciphers
        let nonce = Default::default();
        let message = b"Hello, this is a realistic message that might be sent over the network";

        let encrypted = directional.d2l.encrypt(&nonce, message.as_ref()).unwrap();
        let decrypted = directional.d2l.decrypt(&nonce, encrypted.as_ref()).unwrap();

        assert_eq!(message.as_ref(), decrypted);
    }

    #[test]
    fn test_constants_are_unique() {
        // Ensure all constant info strings are different
        let constants = [
            TRAFFIC_INFO_D2L,
            TRAFFIC_INFO_L2D,
            CONFIRMATION_INFO_D2L,
            CONFIRMATION_INFO_L2D,
        ];

        for i in 0..constants.len() {
            for j in (i + 1)..constants.len() {
                assert_ne!(constants[i], constants[j]);
            }
        }
    }
}
