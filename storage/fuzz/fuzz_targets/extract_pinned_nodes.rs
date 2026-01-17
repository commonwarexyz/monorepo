#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::sha256;
use commonware_storage::{
    mmr::{Location, Proof, MAX_LOCATION},
    qmdb::verify::extract_pinned_nodes,
};
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 256;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    start_loc: u64,
    operations_len: u64,
    proof_leaves: u64,
    digests: Vec<[u8; 32]>,
}

fuzz_target!(|input: FuzzInput| {
    let digests: Vec<sha256::Digest> = input
        .digests
        .iter()
        .take(MAX_SIZE)
        .map(|bytes| sha256::Digest::from(*bytes))
        .collect();

    let leaves = input.proof_leaves.clamp(0, MAX_LOCATION);

    let proof = Proof {
        leaves: Location::new(leaves).unwrap(),
        digests,
    };

    if let Some(start_loc) = Location::new(input.start_loc) {
        _ = extract_pinned_nodes(&proof, start_loc, input.operations_len);
    }
});
