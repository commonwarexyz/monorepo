#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::mmr::{
    verification::ProofStore, Location, Position, Proof, StandardHasher as Standard,
};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    proof_size: u64,
    digests: Vec<[u8; 32]>,
    elements: Vec<Vec<u8>>,
    locations: Vec<u64>,
    start_loc: u64,
    end_loc: u64,
    root: [u8; 32],
}

async fn fuzz(input: FuzzInput) {
    if input.start_loc > commonware_storage::mmr::MAX_LOCATION {
        return;
    }

    if input.elements.is_empty() {
        return;
    }

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

    let Ok(proof) = ProofStore::new(
        &mut hasher,
        &proof,
        &elements,
        input.start_loc.into(),
        &root,
    ) else {
        return;
    };

    let Some(range_start) = Location::new(input.start_loc) else {
        return;
    };
    let Some(range_end) = Location::new(input.end_loc) else {
        return;
    };
    let _ = proof.range_proof(range_start..range_end).await;

    let Ok(locations): Result<Vec<Location>, _> = input
        .locations
        .into_iter()
        .map(|loc| Location::new(loc).ok_or(()))
        .collect()
    else {
        return;
    };
    let _ = proof.multi_proof(locations.as_slice()).await;
}

fuzz_target!(|input: FuzzInput| {
    futures::executor::block_on(fuzz(input));
});
