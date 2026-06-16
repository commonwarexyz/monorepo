#![no_main]

use arbitrary::Arbitrary;
use blst::min_pk::{PublicKey as RefPublicKey, Signature as RefSignature};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::{
        primitives::variant::{MinPk, Variant},
        PrivateKey as BlsPrivateKey, PublicKey, Signature,
    },
    Signer as _,
};
use libfuzzer_sys::fuzz_target;
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

const NAMESPACE: &[u8] = b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DECODE_FUZZ";

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub pubkey_48: [u8; 48],
    pub signature_96: [u8; 96],
    #[arbitrary(with = |u: &mut arbitrary::Unstructured| {
        let lengths = [0, 47, 48, 49, 95, 96, 97, 128, 256, 1024];
        let len = u.choose(&lengths)?;
        u.bytes(*len).map(|b| b.to_vec())
    })]
    pub variable_data: Vec<u8>,
    // Arbitrary-constructed values drive the `Arbitrary` impls for `PrivateKey`
    // and `Signature` and give us values to exercise the scheme trait impls.
    pub arb_priv: BlsPrivateKey,
    pub arb_sig_a: Signature,
    pub arb_sig_b: Signature,
    pub case_selector: u8,
}

fn signer(input: &FuzzInput) -> BlsPrivateKey {
    let seed = u64::from_le_bytes(input.pubkey_48[..8].try_into().unwrap());
    BlsPrivateKey::from_seed(seed)
}

fn valid_pubkey(input: &FuzzInput) -> Vec<u8> {
    signer(input).public_key().encode().to_vec()
}

fn valid_signature(input: &FuzzInput) -> Vec<u8> {
    signer(input)
        .sign(NAMESPACE, &input.variable_data)
        .encode()
        .to_vec()
}

fn test_pubkey_diff_validate(data: &[u8]) {
    let ref_result = RefPublicKey::key_validate(data);
    let our_result = PublicKey::decode(data);

    // Both should agree on validity
    assert_eq!(ref_result.is_err(), our_result.is_err());

    // If both succeeded, check round-trip encoding
    if let (Ok(ref_key), Ok(our_key)) = (ref_result, our_result) {
        let ref_bytes = ref_key.compress().to_vec();
        let our_bytes = our_key.encode().to_vec();
        assert_eq!(ref_bytes, our_bytes);
    }
}

fn test_signature_diff_validate(data: &[u8]) {
    let ref_result = RefSignature::sig_validate(data, true);
    let our_result = Signature::decode(data);

    // Both should agree on validity
    assert_eq!(ref_result.is_err(), our_result.is_err());

    // If both succeeded, check round-trip encoding
    if let (Ok(ref_sig), Ok(our_sig)) = (ref_result, our_result) {
        let ref_bytes = ref_sig.compress().to_vec();
        let our_bytes = our_sig.encode().to_vec();
        assert_eq!(ref_bytes, our_bytes);
    }
}
fn test_pubkey_decode_encode(data: &[u8]) {
    if let Ok(pk) = PublicKey::decode(data) {
        let data_round_trip = pk.encode().to_vec();
        assert_eq!(data.to_vec(), data_round_trip.to_vec());
    }
}

fn test_signature_decode_encode(data: &[u8]) {
    if let Ok(sig) = Signature::decode(data) {
        let data_round_trip = sig.encode().to_vec();
        assert_eq!(data.to_vec(), data_round_trip.to_vec());
    }
}

// Exercise the scheme's PrivateKey/PublicKey/Signature trait impls on
// Arbitrary-constructed values: private-key equality and codec round-trip, the
// public-key accessors/ordering/hash, and the signature wrappers.
fn test_trait_impls(input: &FuzzInput) {
    // PrivateKey: PartialEq plus Write/Read codec round-trip.
    let priv_a = &input.arb_priv;
    assert_eq!(*priv_a, priv_a.clone());
    assert_eq!(*priv_a, BlsPrivateKey::decode(priv_a.encode()).unwrap());

    // PublicKey: AsRef<Public>, Deref and AsRef<[u8]> agree, Ord agrees with
    // PartialOrd, Hash is deterministic.
    let pk_a = priv_a.public_key();
    let pk_b = signer(input).public_key();
    let _point: &<MinPk as Variant>::Public = pk_a.as_ref();
    let pk_bytes: &[u8] = &pk_a;
    assert_eq!(pk_bytes, AsRef::<[u8]>::as_ref(&pk_a));
    assert_eq!(pk_a.cmp(&pk_b), pk_a.partial_cmp(&pk_b).unwrap());
    let mut h1 = DefaultHasher::new();
    let mut h2 = DefaultHasher::new();
    pk_a.hash(&mut h1);
    pk_a.hash(&mut h2);
    assert_eq!(h1.finish(), h2.finish());

    // Signature: Deref and AsRef<[u8]> agree, Ord agrees with PartialOrd, Hash runs.
    let (sig_a, sig_b) = (&input.arb_sig_a, &input.arb_sig_b);
    let sig_bytes: &[u8] = sig_a;
    assert_eq!(sig_bytes, AsRef::<[u8]>::as_ref(sig_a));
    assert_eq!(sig_a.cmp(sig_b), sig_a.partial_cmp(sig_b).unwrap());
    let mut hs = DefaultHasher::new();
    sig_a.hash(&mut hs);
    let _ = hs.finish();
}

fn fuzz(input: FuzzInput) {
    match input.case_selector % 11 {
        0 => test_pubkey_diff_validate(&input.pubkey_48), // Fixed 48-byte pubkey
        1 => test_signature_diff_validate(&input.signature_96), // Fixed 96-byte signature
        2 => test_pubkey_diff_validate(&input.variable_data), // Variable length pubkey
        3 => test_signature_diff_validate(&input.variable_data), // Variable length signature
        4 => test_pubkey_decode_encode(&input.variable_data), // Pubkey encode/encode roundtrip
        5 => test_signature_decode_encode(&input.variable_data), // Signature decode/encode roundtrip
        6 => test_pubkey_diff_validate(&valid_pubkey(&input)),   // Valid pubkey differential
        7 => test_signature_diff_validate(&valid_signature(&input)), // Valid signature differential
        8 => test_pubkey_decode_encode(&valid_pubkey(&input)),   // Valid pubkey roundtrip
        9 => test_signature_decode_encode(&valid_signature(&input)), // Valid signature roundtrip
        10 => test_trait_impls(&input),                          // Scheme trait impls
        _ => unreachable!(),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
