#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::mmr::{Proof, StandardHasher as Standard};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    mmr_size: u64,
    proof_digests: Vec<[u8; 32]>,
    elements: Vec<(Vec<u8>, u64)>,
    root_digest: [u8; 32],
}

fuzz_target!(|input: FuzzInput| {
    let mut hasher = Standard::<Sha256>::default();

    let digests: Vec<Digest> = input.proof_digests.into_iter().map(Digest::from).collect();

    let proof = Proof {
        size: input.mmr_size,
        digests,
    };

    let elements: Vec<(&[u8], u64)> = input
        .elements
        .iter()
        .map(|(data, loc)| (data.as_slice(), *loc))
        .collect();

    let root = Digest::from(input.root_digest);

    let _ = proof.verify_multi_inclusion(&mut hasher, &elements, &root);
});
