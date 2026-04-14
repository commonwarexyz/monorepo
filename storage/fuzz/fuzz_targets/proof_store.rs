#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::Encode as _;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::mmr::{
    verification::ProofStore, Location, Position, Proof, StandardHasher as Standard,
};
use libfuzzer_sys::fuzz_target;
use std::ops::Range;

const MAX_ITEMS: usize = 256;
const MAX_PEAKS: usize = 64;

#[derive(Debug)]
struct FuzzInput {
    proof: Proof<Digest>,
    elements: Vec<Vec<u8>>,
    start_loc: Location,
    root: Digest,
    range: Range<Location>,
    locations: Vec<Location>,
    peaks: Vec<(u64, [u8; 32])>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_digests = u.int_in_range(0..=MAX_ITEMS)?;
        let num_elements = u.int_in_range(0..=MAX_ITEMS)?;
        let num_locations = u.int_in_range(0..=MAX_ITEMS)?;
        let num_peaks = u.int_in_range(0..=MAX_PEAKS)?;
        Ok(FuzzInput {
            proof: Proof {
                leaves: Location::from(u.arbitrary::<u64>()?),
                digests: (0..num_digests)
                    .map(|_| Ok(Digest::from(u.arbitrary::<[u8; 32]>()?)))
                    .collect::<arbitrary::Result<Vec<_>>>()?,
            },
            elements: (0..num_elements)
                .map(|_| u.arbitrary::<Vec<u8>>())
                .collect::<arbitrary::Result<Vec<_>>>()?,
            start_loc: Location::from(u.arbitrary::<u64>()?),
            root: Digest::from(u.arbitrary::<[u8; 32]>()?),
            range: Location::from(u.arbitrary::<u64>()?)..Location::from(u.arbitrary::<u64>()?),
            locations: (0..num_locations)
                .map(|_| Ok(Location::from(u.arbitrary::<u64>()?)))
                .collect::<arbitrary::Result<Vec<_>>>()?,
            peaks: (0..num_peaks)
                .map(|_| Ok((u.arbitrary::<u64>()?, u.arbitrary::<[u8; 32]>()?)))
                .collect::<arbitrary::Result<Vec<_>>>()?,
        })
    }
}

fn fuzz(input: FuzzInput) {
    let hasher: Standard<Sha256> = Standard::new();
    let Ok(proof_store) = ProofStore::new(
        &hasher,
        &input.proof,
        &input.elements,
        input.start_loc,
        &input.root,
    ) else {
        return;
    };

    if let Ok(proof) = proof_store.range_proof(&hasher, input.range) {
        let _ =
            proof.verify_range_inclusion(&hasher, &input.elements, input.start_loc, &input.root);

        let _ = proof.verify_range_inclusion_and_extract_digests(
            &hasher,
            &input.elements,
            input.start_loc,
            &input.root,
        );
    }

    let peaks: Vec<(Position, Digest)> = input
        .peaks
        .iter()
        .map(|(pos, bytes)| (Position::from(*pos), Digest::from(*bytes)))
        .collect();

    if let Ok(proof) = proof_store.multi_proof(input.locations.as_slice(), &peaks) {
        let _ = proof.verify_multi_inclusion(
            &hasher,
            &input
                .locations
                .iter()
                .map(|loc| (loc.encode(), *loc))
                .collect::<Vec<_>>(),
            &input.root,
        );

        let _ = proof.verify_range_inclusion_and_extract_digests(
            &hasher,
            &input.elements,
            input.start_loc,
            &input.root,
        );
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
