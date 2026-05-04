#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::Encode as _;
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::merkle::{
    self, mmb, mmr, verification::ProofStore, Family as MerkleFamily, Location, Position, Proof,
};
use libfuzzer_sys::fuzz_target;
use std::ops::Range;

const MAX_ITEMS: usize = 256;
const MAX_PEAKS: usize = 64;

// `proof_leaves` is typed `Location<F>` so `ProofStore::new` is reachable; the other
// `u64` location/position fields stay raw to also exercise overflow rejection paths in
// `range_proof`, `multi_proof`, and the `verify_*` entry points.
#[derive(Debug)]
struct FuzzInput<F: MerkleFamily> {
    proof_leaves: Location<F>,
    inactive_peaks: usize,
    proof_digests: Vec<[u8; 32]>,
    elements: Vec<Vec<u8>>,
    start_loc: u64,
    root: [u8; 32],
    range: Range<u64>,
    locations: Vec<u64>,
    peaks: Vec<(u64, [u8; 32])>,
}

impl<'a, F: MerkleFamily> Arbitrary<'a> for FuzzInput<F> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let num_digests = u.int_in_range(0..=MAX_ITEMS)?;
        let num_elements = u.int_in_range(0..=MAX_ITEMS)?;
        let num_locations = u.int_in_range(0..=MAX_ITEMS)?;
        let num_peaks = u.int_in_range(0..=MAX_PEAKS)?;
        Ok(FuzzInput {
            proof_leaves: u.arbitrary()?,
            inactive_peaks: u.arbitrary()?,
            proof_digests: (0..num_digests)
                .map(|_| u.arbitrary::<[u8; 32]>())
                .collect::<arbitrary::Result<Vec<_>>>()?,
            elements: (0..num_elements)
                .map(|_| u.arbitrary::<Vec<u8>>())
                .collect::<arbitrary::Result<Vec<_>>>()?,
            start_loc: u.arbitrary::<u64>()?,
            root: u.arbitrary::<[u8; 32]>()?,
            range: u.arbitrary::<u64>()?..u.arbitrary::<u64>()?,
            locations: (0..num_locations)
                .map(|_| u.arbitrary::<u64>())
                .collect::<arbitrary::Result<Vec<_>>>()?,
            peaks: (0..num_peaks)
                .map(|_| Ok((u.arbitrary::<u64>()?, u.arbitrary::<[u8; 32]>()?)))
                .collect::<arbitrary::Result<Vec<_>>>()?,
        })
    }
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput<F>) {
    let hasher = merkle::hasher::Standard::<Sha256>::with_bagging(merkle::Bagging::BackwardFold);
    let proof = Proof::<F, Digest> {
        leaves: input.proof_leaves,
        inactive_peaks: input.inactive_peaks,
        digests: input
            .proof_digests
            .iter()
            .copied()
            .map(Digest::from)
            .collect(),
    };
    let start_loc = Location::<F>::new(input.start_loc);
    let root = Digest::from(input.root);
    let range = Location::<F>::new(input.range.start)..Location::<F>::new(input.range.end);

    let Ok(proof_store) = ProofStore::new(&hasher, &proof, &input.elements, start_loc, &root)
    else {
        return;
    };

    if let Ok(proof) = proof_store.range_proof(&hasher, range) {
        let _ = proof.verify_range_inclusion(&hasher, &input.elements, start_loc, &root);
        let _ = proof.verify_range_inclusion_and_extract_digests(
            &hasher,
            &input.elements,
            start_loc,
            &root,
        );
    }

    let peaks: Vec<(Position<F>, Digest)> = input
        .peaks
        .iter()
        .map(|(pos, bytes)| (Position::<F>::new(*pos), Digest::from(*bytes)))
        .collect();
    let locations: Vec<Location<F>> = input
        .locations
        .iter()
        .copied()
        .map(Location::<F>::new)
        .collect();

    if let Ok(proof) = proof_store.multi_proof(&locations, &peaks) {
        let _ = proof.verify_multi_inclusion(
            &hasher,
            &locations
                .iter()
                .map(|loc| (loc.encode(), *loc))
                .collect::<Vec<_>>(),
            &root,
        );

        let _ = proof.verify_range_inclusion_and_extract_digests(
            &hasher,
            &input.elements,
            start_loc,
            &root,
        );
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = FuzzInput::<mmr::Family>::arbitrary(&mut Unstructured::new(data)) {
        fuzz_family::<mmr::Family>(&input);
    }
    if let Ok(input) = FuzzInput::<mmb::Family>::arbitrary(&mut Unstructured::new(data)) {
        fuzz_family::<mmb::Family>(&input);
    }
});
