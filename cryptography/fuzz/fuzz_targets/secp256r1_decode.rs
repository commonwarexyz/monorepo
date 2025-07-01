#![no_main]
extern crate core;

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    secp256r1::{PrivateKey, PublicKey, Signature},
    Signer, Verifier,
};
use libfuzzer_sys::fuzz_target;
use p256::{
    ecdsa::{
        Signature as RefSignature, SigningKey as RefSigningKey, VerifyingKey as RefVerifyingKey,
    },
    elliptic_curve::scalar::IsHigh,
};

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub private_key_32: [u8; 32],
    pub public_key_33: [u8; 33],
    pub signature_64: [u8; 64],
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| {
        let lengths = [0, 31, 32, 33, 34, 63, 64, 65, 128, 256];
        let len = u.choose(&lengths)?;
        u.bytes(*len).map(|b| b.to_vec())
    })]
    pub variable_data: Vec<u8>,
    pub message: Vec<u8>,
    pub case_selector: u8,
}

// Test private key validation and encoding
fn test_private_key(data: &[u8]) {
    let ref_result = RefSigningKey::from_slice(data);
    let our_result = PrivateKey::decode(data);

    // The reference P256 implements the following policy:
    // Deserialize secret key from an encoded secret scalar passed as a byte slice.
    // The slice is expected to be a minimum of 24-bytes (192-bits)
    // and at most C::FieldBytesSize bytes in length.
    // Byte slices shorter than the field size are handled by zero padding the input.
    // But our implementation accepts only 32-byte input.
    // The invariant is that on 32-byte input both implementations should generate
    // the same key or return an error.

    match data.len() {
        32 => {
            assert_eq!(
                ref_result.is_err(),
                our_result.is_err(),
                "32-byte input: implementations disagree on input validity"
            );
            if let (Ok(ref_key), Ok(our_key)) = (ref_result, our_result) {
                assert_eq!(
                    ref_key.to_bytes().as_slice(),
                    our_key.as_ref(),
                    "32-byte input: keys don't match"
                );
            }
        }
        _ => assert!(
            our_result.is_err(),
            "Expected error for {}-byte input",
            data.len()
        ),
    }
}

// Test public key validation and encoding
fn test_public_key(data: &[u8]) {
    let ref_result = RefVerifyingKey::from_sec1_bytes(data);
    let our_result = PublicKey::decode(data);
    assert_eq!(ref_result.is_err(), our_result.is_err());

    if let (Ok(ref_key), Ok(our_key)) = (ref_result, our_result) {
        // Workaround since the verifying key is not accessible.
        let verifying_key = RefVerifyingKey::from_sec1_bytes(our_key.as_ref()).unwrap();
        assert_eq!(ref_key, verifying_key);
    }
}

fn test_public_key_roundtrip(data: &[u8]) {
    if let Ok(public_key) = PublicKey::decode(data) {
        let encoded = public_key.encode();
        assert_eq!(
            data,
            encoded.as_ref(),
            "Public key roundtrip failed: original {:?} != encoded {:?}",
            data,
            encoded.as_ref()
        );
    }
}

// Test signature validation and encoding
fn test_signature(data: &[u8]) {
    let ref_result = RefSignature::from_slice(data);
    let our_result = Signature::decode(data);

    match (ref_result, our_result) {
        (Err(_), our) => {
            assert!(our.is_err(), "Our impl should reject invalid signatures");
        }
        (Ok(ref_sig), our) if ref_sig.s().is_high().into() => {
            assert!(our.is_err(), "Our impl should reject high-S signatures");
        }
        (Ok(ref_sig), Ok(our_sig)) => {
            assert_eq!(ref_sig.to_bytes().as_slice(), our_sig.as_ref());

            let encoded = our_sig.encode();
            assert_eq!(data, encoded.as_ref());
        }
        (Ok(_), Err(_)) => {
            panic!("Reference impl accepted signature but our impl rejected it");
        }
    }
}

// Test sign and verify operations
fn test_sign_verify(private_key_data: &[u8; 32], message: &[u8]) {
    // Create private key
    if let Ok(private_key) = PrivateKey::decode(private_key_data.as_ref()) {
        let signature = private_key.sign(None, message);
        let public_key = private_key.public_key();
        assert!(public_key.verify(None, message, &signature));

        let namespace = b"test_namespace";
        let sig_with_ns = private_key.sign(Some(namespace), message);
        assert!(public_key.verify(Some(namespace), message, &sig_with_ns));
        assert!(!public_key.verify(None, message, &sig_with_ns));
        assert!(!public_key.verify(Some(namespace), message, &signature));

        // Test encoding round-trip
        let encoded_sig = signature.encode();
        let decoded_sig = Signature::decode(encoded_sig.as_ref()).unwrap();
        assert!(public_key.verify(None, message, &decoded_sig));
    }
}

// Test public key derivation
fn test_public_key_derivation(private_key_data: &[u8]) {
    if let Ok(private_key) = PrivateKey::decode(private_key_data) {
        let public_key1 = private_key.public_key();
        let public_key2 = PublicKey::from(private_key.clone());
        assert_eq!(public_key1.encode(), public_key2.encode());
    }
}

fuzz_target!(|input: FuzzInput| {
    match input.case_selector % 10 {
        0 => test_private_key(&input.private_key_32),
        1 => test_public_key(&input.public_key_33),
        2 => test_signature(&input.signature_64),
        3 => test_private_key(&input.variable_data),
        4 => test_public_key(&input.variable_data),
        5 => test_signature(&input.variable_data),
        6 => test_public_key_derivation(&input.variable_data),
        7 => test_sign_verify(&input.private_key_32, &input.message),
        8 => test_public_key_roundtrip(&input.public_key_33),
        9 => test_public_key_roundtrip(&input.variable_data),
        _ => unreachable!(),
    }
});
