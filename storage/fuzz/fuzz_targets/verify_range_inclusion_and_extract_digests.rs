#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::mmr::{proof::Proof, Position, StandardHasher as Standard};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    proof_size: u64,
    digests: Vec<[u8; 32]>,
    elements: Vec<Vec<u8>>,
    start_loc: u64,
    root: [u8; 32],
}

fn fuzz(input: FuzzInput) {
    let proof = Proof {
        size: Position::new(input.proof_size),
        digests: input
            .digests
            .iter()
            .map(|d| Digest::from(*d))
            .collect::<Vec<_>>(),
    };

    let elements: Vec<Vec<u8>> = input.elements;

    let root = Digest::from(input.root);
    let mut hasher: Standard<Sha256> = Standard::new();

    let _ = proof.verify_range_inclusion_and_extract_digests(
        &mut hasher,
        &elements,
        input.start_loc.into(),
        &root,
    );
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
