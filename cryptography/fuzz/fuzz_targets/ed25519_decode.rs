#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::ed25519::PublicKey;
use ed25519_consensus::VerificationKey as ConsensusPublicKey;
use ed25519_zebra::{
    VerificationKey as ZebraPublicKey, VerificationKeyBytes as ZebraPublicKeyBytes,
};
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
    let consensus_result = ConsensusPublicKey::try_from(pubkey);
    let zebra_result = ZebraPublicKey::try_from(pubkey);
    let our_result = PublicKey::decode(pubkey);

    // All implementations should agree on public key validity.
    assert_eq!(consensus_result.is_err(), our_result.is_err());
    assert_eq!(zebra_result.is_err(), our_result.is_err());

    // If all succeeded, check round-trip encoding.
    if let (Ok(consensus_key), Ok(zebra_key), Ok(our_key)) =
        (consensus_result, zebra_result, our_result)
    {
        let consensus_bytes = consensus_key.to_bytes().to_vec();
        let zebra_bytes = ZebraPublicKeyBytes::from(zebra_key).as_ref().to_vec();
        let our_bytes = our_key.encode().to_vec();
        assert_eq!(consensus_bytes, our_bytes);
        assert_eq!(zebra_bytes, our_bytes);
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
