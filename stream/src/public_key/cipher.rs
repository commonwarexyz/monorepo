use crate::Error;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, KeySizeUser};
use commonware_cryptography::{CoreSha256, Hasher, Sha256};
use hkdf::{hmac::digest::typenum::Unsigned, Hkdf};
use zeroize::Zeroize;

// The size of the key used by the ChaCha20Poly1305 cipher.
const CHACHA_KEY_SIZE: usize = <ChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE;

// A constant prefix used for the salt hash in the HKDF key derivation.
const BASE_KDF_PREFIX: &[u8] = b"commonware-stream/KDF/v1/";

/// Key Derivation Function (KDF) to derive directional ChaCha20Poly1305 ciphers using HKDF-SHA256.
///
/// This function derives two ChaCha20Poly1305 ciphers based on:
/// - The input key material (IKM), usually the shared secret from the Diffie-Hellman key exchange
/// - An ordered list of byte slices (salts), where the order is critical for consistent derivation
///   between the dialer and the listener. The list usually contains:
///   - The unique application namespace
///   - The dialer handshake message bytes
///   - The listener handshake message bytes
///
/// Returns two ChaCha20Poly1305 ciphers, intended for use as:
/// - The dialer-to-listener cipher
/// - The listener-to-dialer cipher
///
/// The dialer and listener must use the ciphers in the same order to ensure proper encryption and
/// decryption.
pub fn derive(ikm: &[u8], salts: &[&[u8]]) -> Result<(ChaCha20Poly1305, ChaCha20Poly1305), Error> {
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

    // Expand the PRK to derive two ChaCha20Poly1305 keys.
    let mut buf = [0u8; CHACHA_KEY_SIZE * 2];
    prk.expand(&[], &mut buf)
        .map_err(|_| Error::HKDFExpansion)?;
    let d2l_cipher = ChaCha20Poly1305::new_from_slice(&buf[..CHACHA_KEY_SIZE])
        .map_err(|_| Error::CipherCreation)?;
    let l2d_cipher = ChaCha20Poly1305::new_from_slice(&buf[CHACHA_KEY_SIZE..])
        .map_err(|_| Error::CipherCreation)?;
    buf.zeroize();

    Ok((d2l_cipher, l2d_cipher))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20poly1305::aead::Aead;

    #[test]
    fn test_derive_success() {
        let ikm = [1u8; CHACHA_KEY_SIZE];
        let salt_data1 = b"test_salt_data_success_1";
        let salt_data2 = b"test_salt_data_success_2";
        let salts_arr: [&[u8]; 2] = [salt_data1, salt_data2];

        let result = derive(&ikm, &salts_arr);
        assert!(result.is_ok());
        let (cipher1, cipher2) = result.unwrap();

        // Basic check: encrypt something and ensure ciphers are different
        let nonce = Default::default();
        let plaintext = b"test_encryption";
        let ciphertext1 = cipher1
            .encrypt(&nonce, plaintext.as_ref())
            .expect("Cipher1 encryption failed");
        let ciphertext2 = cipher2
            .encrypt(&nonce, plaintext.as_ref())
            .expect("Cipher2 encryption failed");
        assert_ne!(
            ciphertext1, ciphertext2,
            "Derived ciphers (d2l and l2d) should be different due to KDF info params"
        );
    }

    #[test]
    fn test_derive_consistency() {
        let ikm = [2u8; CHACHA_KEY_SIZE];
        let salt_data1 = b"consistency_salt_1";
        let salt_data2 = b"consistency_salt_2";
        let salts_arr: [&[u8]; 2] = [salt_data1, salt_data2];

        let (cipher1_a, cipher2_a) = derive(&ikm, &salts_arr).unwrap();
        let (cipher1_b, cipher2_b) = derive(&ikm, &salts_arr).unwrap();

        let nonce = Default::default();
        let plaintext = b"consistency_check";

        assert_eq!(
            cipher1_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher1_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "D2L ciphers should be consistent for the same inputs"
        );
        assert_eq!(
            cipher2_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher2_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "L2D ciphers should be consistent for the same inputs"
        );
    }

    #[test]
    fn test_derive_sensitivity_to_ikm() {
        let salt_data = b"common_salt_for_ikm_test";
        let salts_arr: [&[u8]; 1] = [salt_data];

        let ikm1 = [3u8; CHACHA_KEY_SIZE];
        let (cipher1_a, cipher2_a) = derive(&ikm1, &salts_arr).unwrap();

        let ikm2 = [4u8; CHACHA_KEY_SIZE]; // Different IKM
        let (cipher1_b, cipher2_b) = derive(&ikm2, &salts_arr).unwrap();

        let nonce = Default::default();
        let plaintext = b"ikm_sensitivity_check";

        assert_ne!(
            cipher1_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher1_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "D2L cipher should change with IKM"
        );
        assert_ne!(
            cipher2_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher2_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "L2D cipher should change with IKM"
        );
    }

    #[test]
    fn test_derive_sensitivity_to_salt_element_content() {
        let ikm = [5u8; CHACHA_KEY_SIZE];
        let common_salt_element = b"common_element";

        let salts1_data: [&[u8]; 2] = [b"salt_A", common_salt_element];
        let (cipher1_a, cipher2_a) = derive(&ikm, &salts1_data).unwrap();

        let salts2_data: [&[u8]; 2] = [b"salt_B", common_salt_element]; // Different content in first salt element
        let (cipher1_b, cipher2_b) = derive(&ikm, &salts2_data).unwrap();

        let nonce = Default::default();
        let plaintext = b"salt_content_sensitivity";

        assert_ne!(
            cipher1_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher1_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "D2L cipher should change with salt element content"
        );
        assert_ne!(
            cipher2_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher2_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "L2D cipher should change with salt element content"
        );
    }

    #[test]
    fn test_derive_sensitivity_to_number_of_salt_elements() {
        let ikm = [6u8; CHACHA_KEY_SIZE];
        let salt_element_a = b"element_A";
        let salt_element_b = b"element_B";

        let salts1_data: [&[u8]; 1] = [salt_element_a]; // One salt element
        let (cipher1_a, cipher2_a) = derive(&ikm, &salts1_data).unwrap();

        let salts2_data: [&[u8]; 2] = [salt_element_a, salt_element_b]; // Two salt elements
        let (cipher1_b, cipher2_b) = derive(&ikm, &salts2_data).unwrap();

        let nonce = Default::default();
        let plaintext = b"num_salts_sensitivity";

        assert_ne!(
            cipher1_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher1_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "D2L cipher should change with the number of salt elements"
        );
        assert_ne!(
            cipher2_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher2_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "L2D cipher should change with the number of salt elements"
        );
    }

    #[test]
    fn test_derive_sensitivity_to_order_of_salt_elements() {
        let ikm = [7u8; CHACHA_KEY_SIZE];
        let salt_element_x = b"element_X";
        let salt_element_y = b"element_Y";

        let salts1_data: [&[u8]; 2] = [salt_element_x, salt_element_y];
        let (cipher1_a, cipher2_a) = derive(&ikm, &salts1_data).unwrap();

        let salts2_data: [&[u8]; 2] = [salt_element_y, salt_element_x]; // Different order
        let (cipher1_b, cipher2_b) = derive(&ikm, &salts2_data).unwrap();

        let nonce = Default::default();
        let plaintext = b"order_salts_sensitivity";

        assert_ne!(
            cipher1_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher1_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "D2L cipher should change with the order of salt elements"
        );
        assert_ne!(
            cipher2_a.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher2_b.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            "L2D cipher should change with the order of salt elements"
        );
    }

    #[test]
    fn test_derive_with_empty_salts_slice() {
        let ikm = [8u8; CHACHA_KEY_SIZE];
        let empty_salts: [&[u8]; 0] = []; // Empty slice of salts

        let result = derive(&ikm, &empty_salts);
        assert!(
            result.is_ok(),
            "Derivation with empty salts slice should succeed"
        );

        // Further check: ensure it's different from derivation with non-empty salts
        let salt_data = b"some_salt";
        let non_empty_salts: [&[u8]; 1] = [salt_data];
        let (cipher1_empty, cipher2_empty) = result.unwrap();
        let (cipher1_non_empty, cipher2_non_empty) = derive(&ikm, &non_empty_salts).unwrap();

        let nonce = Default::default();
        let plaintext = b"empty_salts_check";

        assert_ne!(
            cipher1_empty.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher1_non_empty
                .encrypt(&nonce, plaintext.as_ref())
                .unwrap(),
            "D2L cipher with empty salts should differ from non-empty"
        );
        assert_ne!(
            cipher2_empty.encrypt(&nonce, plaintext.as_ref()).unwrap(),
            cipher2_non_empty
                .encrypt(&nonce, plaintext.as_ref())
                .unwrap(),
            "L2D cipher with empty salts should differ from non-empty"
        );
    }

    #[test]
    fn test_derive_with_empty_salt_element_in_slice() {
        let ikm = [9u8; CHACHA_KEY_SIZE];
        let empty_salt_element: &[u8] = b"";
        let salts_with_empty_element: [&[u8]; 1] = [empty_salt_element];

        let result = derive(&ikm, &salts_with_empty_element);
        assert!(
            result.is_ok(),
            "Derivation with an empty salt element should succeed"
        );

        // Further check: ensure it's different from derivation with non-empty salt or fully empty salts
        let (cipher1_with_empty_el, cipher2_with_empty_el) = result.unwrap();

        let salt_data = b"non_empty_salt_element";
        let salts_with_non_empty_el: [&[u8]; 1] = [salt_data];
        let (cipher1_non_empty_el, cipher2_non_empty_el) =
            derive(&ikm, &salts_with_non_empty_el).unwrap();

        let nonce = Default::default();
        let plaintext = b"empty_salt_element_check";

        assert_ne!(
            cipher1_with_empty_el
                .encrypt(&nonce, plaintext.as_ref())
                .unwrap(),
            cipher1_non_empty_el
                .encrypt(&nonce, plaintext.as_ref())
                .unwrap(),
            "D2L cipher with empty salt element should differ from one with non-empty salt element"
        );
        assert_ne!(
            cipher2_with_empty_el
                .encrypt(&nonce, plaintext.as_ref())
                .unwrap(),
            cipher2_non_empty_el
                .encrypt(&nonce, plaintext.as_ref())
                .unwrap(),
            "L2D cipher with empty salt element should differ from one with non-empty salt element"
        );
    }

    #[test]
    fn test_d2l_and_l2d_are_different() {
        let ikm = [10u8; CHACHA_KEY_SIZE];
        let salt_data = b"test_salt_for_d2l_l2d_diff";
        let salts_arr: [&[u8]; 1] = [salt_data];
        let (d2l_cipher, l2d_cipher) = derive(&ikm, &salts_arr).unwrap();

        let nonce = Default::default();
        let plaintext = b"d2l_l2d_test_message";

        let ciphertext_d2l = d2l_cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("D2L encryption failed");
        let ciphertext_l2d = l2d_cipher
            .encrypt(&nonce, plaintext.as_ref())
            .expect("L2D encryption failed");

        assert_ne!(ciphertext_d2l, ciphertext_l2d, "D2L and L2D ciphers should produce different ciphertexts for the same input due to different KDF info parameters.");
    }
}
