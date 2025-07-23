#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::lthash::LtHash;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Operation {
    Add(Vec<u8>),
    Subtract(Vec<u8>),
    Combine,
    Reset,
    Checksum,
    IsZero,
}

#[derive(Debug, Arbitrary)]
enum Property {
    Homomorphic(Vec<u8>, Vec<u8>),
    SubtractionIdentity(Vec<u8>),
    Commutativity(Vec<u8>, Vec<u8>),
    CodecRoundtrip,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    operations: Vec<Operation>,
    properties: Vec<Property>,
}

fn verify_homomorphic_property(data1: &[u8], data2: &[u8]) {
    let mut hash1 = LtHash::new();
    hash1.add(data1);
    hash1.add(data2);
    let combined_checksum = hash1.checksum();

    let mut hash2 = LtHash::new();
    hash2.add(data1);
    let mut hash3 = LtHash::new();
    hash3.add(data2);
    hash2.combine(&hash3);
    let separate_checksum = hash2.checksum();

    assert_eq!(combined_checksum, separate_checksum);
}

fn verify_subtraction_identity(data: &[u8]) {
    let mut hash = LtHash::new();
    let initial_checksum = hash.checksum();

    hash.add(data);
    hash.subtract(data);
    let final_checksum = hash.checksum();

    assert_eq!(initial_checksum, final_checksum);
    assert!(hash.is_zero());
}

fn verify_commutativity(data1: &[u8], data2: &[u8]) {
    let mut hash1 = LtHash::new();
    hash1.add(data1);
    hash1.add(data2);
    let checksum1 = hash1.checksum();

    let mut hash2 = LtHash::new();
    hash2.add(data2);
    hash2.add(data1);
    let checksum2 = hash2.checksum();

    assert_eq!(checksum1, checksum2);
}

fn verify_codec_roundtrip(hash: &LtHash) {
    let encoded = hash.encode();
    let decoded = LtHash::decode(encoded).unwrap();
    assert_eq!(hash.checksum(), decoded.checksum());
}

fn fuzz_operation(operations: Vec<Operation>) {
    let mut hashes: Vec<LtHash> = vec![LtHash::new()];

    for op in operations {
        match op {
            Operation::Add(data) => {
                if let Some(hash) = hashes.last_mut() {
                    hash.add(&data);
                }
            }
            Operation::Subtract(data) => {
                if let Some(hash) = hashes.last_mut() {
                    hash.subtract(&data);
                }
            }
            Operation::Combine => {
                if hashes.len() >= 2 {
                    let hash2 = hashes.pop().unwrap();
                    if let Some(hash1) = hashes.last_mut() {
                        hash1.combine(&hash2);
                    }
                } else {
                    hashes.push(LtHash::new());
                }
            }
            Operation::Reset => {
                if let Some(hash) = hashes.last_mut() {
                    hash.reset();
                    assert!(hash.is_zero());
                }
            }
            Operation::Checksum => {
                if let Some(hash) = hashes.last() {
                    let _ = hash.checksum();
                }
            }
            Operation::IsZero => {
                if let Some(hash) = hashes.last() {
                    let _ = hash.is_zero();
                }
            }
        }
    }
}

fn fuzz_properties(properties: Vec<Property>) {
    let hashes: Vec<LtHash> = vec![LtHash::new()];

    for property in properties {
        match property {
            Property::Homomorphic(data1, data2) => {
                verify_homomorphic_property(&data1, &data2);
            }
            Property::SubtractionIdentity(data) => {
                verify_subtraction_identity(&data);
            }
            Property::Commutativity(data1, data2) => {
                verify_commutativity(&data1, &data2);
            }
            Property::CodecRoundtrip => {
                if let Some(hash) = hashes.last() {
                    verify_codec_roundtrip(hash);
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz_operation(input.operations);
    fuzz_properties(input.properties);
});
