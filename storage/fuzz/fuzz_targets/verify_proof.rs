#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_storage::{
    merkle::{Family as MerkleFamily, Location, Proof, mmb, mmr},
    qmdb::verify::verify_multi_proof,
};
use libfuzzer_sys::fuzz_target;

const MAX_DIGESTS: usize = 128;
const MAX_OPERATIONS: usize = 50;
const MAX_OPERATION_BYTES: usize = 512;

#[derive(Debug)]
struct OperationInput {
    // Raw `u64` so we also exercise the per-op `is_valid()` rejection path.
    location: u64,
    payload: Vec<u8>,
}

impl<'a> Arbitrary<'a> for OperationInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let location = u.arbitrary()?;
        let payload_len = u.int_in_range(0..=MAX_OPERATION_BYTES)?;
        let payload = u.bytes(payload_len.min(u.len()))?.to_vec();
        Ok(Self { location, payload })
    }
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
        let proof_leaves = u.arbitrary()?;
        let inactive_peaks = u.arbitrary()?;
        let root = u.arbitrary()?;

        // Keep enough bytes for a non-empty operation list after fixed-size digests.
        let max_digests = ((u.len().saturating_sub(12)) / 32).min(MAX_DIGESTS);
        let num_digests = u.int_in_range(0..=max_digests)?;
        let digests = (0..num_digests)
            .map(|_| <[u8; 32]>::arbitrary(u))
            .collect::<arbitrary::Result<Vec<_>>>()?;

        // Partition the remaining input so one variable payload cannot starve later operations.
        let max_operations = ((u.len().saturating_sub(1)) / 10).min(MAX_OPERATIONS);
        if max_operations == 0 {
            return Err(arbitrary::Error::NotEnoughData);
        }
        let num_operations = u.int_in_range(1..=max_operations)?;
        let mut operations = Vec::with_capacity(num_operations);
        for remaining in (1..=num_operations).rev() {
            let chunk_len = u.len() / remaining;
            let mut chunk = Unstructured::new(u.bytes(chunk_len)?);
            operations.push(OperationInput::arbitrary(&mut chunk)?);
        }

        Ok(Self {
            proof_leaves,
            inactive_peaks,
            digests,
            operations,
            root,
        })
    }
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput<F>) {
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
    let verified = verify_multi_proof::<Sha256, _, _>(&proof, operations.as_slice(), &root);
    if verified {
        assert!(
            operations.iter().all(|(loc, _)| *loc < proof.leaves),
            "verified operation locations must be within the authenticated tree",
        );

        let mut tampered_root = input.root;
        tampered_root[0] ^= 1;
        assert!(
            !verify_multi_proof::<Sha256, _, _>(
                &proof,
                operations.as_slice(),
                &Digest::from(tampered_root),
            ),
            "a multi-proof must reject a different root",
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
