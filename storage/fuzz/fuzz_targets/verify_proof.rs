#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_storage::{
    merkle::{self, mmb, mmr, Bagging::BackwardFold, Family as MerkleFamily, Location, Proof},
    qmdb::verify::verify_multi_proof,
};
use libfuzzer_sys::fuzz_target;

const MAX_DIGESTS: usize = 128;
const MAX_OPERATIONS: usize = 50;
const MAX_OPERATION_BYTES: usize = 512;

#[derive(Arbitrary, Debug)]
struct OperationInput {
    // Raw `u64` so we also exercise the per-op `is_valid()` rejection path.
    location: u64,
    payload: Vec<u8>,
}

// `proof_leaves` is typed `Location<F>` so that `Arbitrary` bounds it to `F::MAX_LEAVES`;
// otherwise `verify_multi_proof` would reject on overflow before exercising its inner logic.
#[derive(Debug)]
struct FuzzInput<F: MerkleFamily> {
    proof_leaves: Location<F>,
    inactive_peaks: usize,
    digests: Vec<[u8; 32]>,
    operations: Vec<OperationInput>,
    root: [u8; 32],
}

impl<'a, F: MerkleFamily> Arbitrary<'a> for FuzzInput<F> {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            proof_leaves: u.arbitrary()?,
            inactive_peaks: u.arbitrary()?,
            digests: u.arbitrary()?,
            operations: u.arbitrary()?,
            root: u.arbitrary()?,
        })
    }
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput<F>) {
    let hasher = merkle::hasher::Standard::<Sha256>::new(BackwardFold);

    let digests: Vec<Digest> = input
        .digests
        .iter()
        .copied()
        .take(MAX_DIGESTS)
        .map(Digest::from)
        .collect();

    let proof = Proof::<F, Digest> {
        leaves: input.proof_leaves,
        inactive_peaks: input.inactive_peaks,
        digests,
    };

    let mut operations: Vec<(Location<F>, Vec<u8>)> = Vec::new();
    for entry in input.operations.iter().take(MAX_OPERATIONS) {
        let mut payload = entry.payload.clone();
        if payload.len() > MAX_OPERATION_BYTES {
            payload.truncate(MAX_OPERATION_BYTES);
        }
        let location = Location::<F>::new(entry.location);
        if location.is_valid() {
            operations.push((location, payload));
        }
    }

    let root = Digest::from(input.root);
    let _ = verify_multi_proof(&hasher, &proof, operations.as_slice(), &root);
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = FuzzInput::<mmr::Family>::arbitrary(&mut Unstructured::new(data)) {
        fuzz_family::<mmr::Family>(&input);
    }
    if let Ok(input) = FuzzInput::<mmb::Family>::arbitrary(&mut Unstructured::new(data)) {
        fuzz_family::<mmb::Family>(&input);
    }
});
