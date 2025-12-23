#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::ed25519::PublicKey;
use ed25519_zebra::{VerificationKey as RefPublicKey, VerificationKeyBytes as RefPublicKeyBytes};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub pubkey_32: [u8; 32],
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| {
        let lengths = [0, 1, 31, 33, 255, 256, 1024, 2048];
        let len = u.choose(&lengths)?;
        u.bytes(*len).map(|b| b.to_vec())
    })]
    pub pubkey_variable: Vec<u8>,
    pub case_selector: u8,
}

fn test_pubkey(pubkey: &[u8]) {
    let ref_result = RefPublicKey::try_from(pubkey);
    let our_result = PublicKey::decode(pubkey);
    // Both should agree on validity
    assert_eq!(ref_result.is_err(), our_result.is_err());

    // If both succeeded, check round-trip encoding
    if let (Ok(ref_key), Ok(our_key)) = (ref_result, our_result) {
        let ref_bytes = RefPublicKeyBytes::from(ref_key).as_ref().to_vec();
        let our_bytes = our_key.encode().to_vec();
        assert_eq!(ref_bytes, our_bytes);
    }
}

fn fuzz(input: FuzzInput) {
    match input.case_selector % 2 {
        0 => test_pubkey(&input.pubkey_32),
        1 => test_pubkey(&input.pubkey_variable),
        _ => unreachable!(),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
