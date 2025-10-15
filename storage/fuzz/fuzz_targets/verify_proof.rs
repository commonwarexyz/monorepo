#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::{
    adb::verify::verify_multi_proof,
    mmr::{Location, Position, Proof, StandardHasher as Standard},
};
use libfuzzer_sys::fuzz_target;

const MAX_DIGESTS: usize = 128;
const MAX_OPERATIONS: usize = 50;
const MAX_OPERATION_BYTES: usize = 512;

#[derive(Arbitrary, Debug)]
struct OperationInput {
    location: u64,
    payload: Vec<u8>,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    proof_size: u64,
    digests: Vec<[u8; 32]>,
    operations: Vec<OperationInput>,
    root: [u8; 32],
}

fn fuzz(input: FuzzInput) {
    let mut hasher: Standard<Sha256> = Standard::new();

    let digests = input
        .digests
        .into_iter()
        .take(MAX_DIGESTS)
        .map(Digest::from)
        .collect::<Vec<_>>();

    let proof = Proof {
        size: Position::new(input.proof_size),
        digests,
    };

    let mut operations = Vec::new();
    for entry in input.operations.into_iter().take(MAX_OPERATIONS) {
        let mut payload = entry.payload;
        if payload.len() > MAX_OPERATION_BYTES {
            payload.truncate(MAX_OPERATION_BYTES);
        }
        // Only add operations with valid locations
        if let Some(location) = Location::new(entry.location) {
            operations.push((location, payload));
        }
    }

    let root = Digest::from(input.root);
    let _ = verify_multi_proof(&mut hasher, &proof, operations.as_slice(), &root);
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut unstructured) else {
        return;
    };
    fuzz(input);
});
