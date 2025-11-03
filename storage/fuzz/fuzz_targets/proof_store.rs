#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::Encode as _;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::mmr::{
    verification::ProofStore, Location, Position, Proof, StandardHasher as Standard,
};
use libfuzzer_sys::fuzz_target;
use std::ops::Range;

#[derive(Debug)]
struct FuzzInput {
    proof: Proof<Digest>,
    elements: Vec<Vec<u8>>,
    start_loc: Location,
    root: Digest,
    range: Range<Location>,
    locations: Vec<Location>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FuzzInput {
            proof: Proof {
                size: Position::from(u.arbitrary::<u64>()?),
                digests: u
                    .arbitrary::<Vec<[u8; 32]>>()?
                    .into_iter()
                    .map(Digest::from)
                    .collect(),
            },
            elements: u.arbitrary::<Vec<Vec<u8>>>()?,
            start_loc: Location::from(u.arbitrary::<u64>()?),
            root: Digest::from(u.arbitrary::<[u8; 32]>()?),
            range: Location::from(u.arbitrary::<u64>()?)..Location::from(u.arbitrary::<u64>()?),
            locations: u
                .arbitrary::<Vec<u64>>()?
                .into_iter()
                .map(Location::from)
                .collect(),
        })
    }
}

async fn fuzz(input: FuzzInput) {
    let mut hasher: Standard<Sha256> = Standard::new();
    let Ok(proof_store) = ProofStore::new(
        &mut hasher,
        &input.proof,
        &input.elements,
        input.start_loc,
        &input.root,
    ) else {
        return;
    };

    if let Ok(proof) = proof_store.range_proof(input.range).await {
        let _ = proof.verify_range_inclusion(
            &mut hasher,
            &input.elements,
            input.start_loc,
            &input.root,
        );

        let _ = proof.verify_range_inclusion_and_extract_digests(
            &mut hasher,
            &input.elements,
            input.start_loc,
            &input.root,
        );
    }

    if let Ok(proof) = proof_store.multi_proof(input.locations.as_slice()).await {
        let _ = proof.verify_multi_inclusion(
            &mut hasher,
            &input
                .locations
                .iter()
                .map(|loc| (loc.encode(), *loc))
                .collect::<Vec<_>>(),
            &input.root,
        );

        let _ = proof.verify_range_inclusion_and_extract_digests(
            &mut hasher,
            &input.elements,
            input.start_loc,
            &input.root,
        );
    }
}

fuzz_target!(|input: FuzzInput| {
    futures::executor::block_on(fuzz(input));
});
