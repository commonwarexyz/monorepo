#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::sha256;
use commonware_storage::{
    mmr::{Location, Proof},
    qmdb::verify::extract_pinned_nodes,
};
use libfuzzer_sys::fuzz_target;

const MAX_SIZE: usize = 256;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    start_loc: u64,
    operations_len: u64,
    proof_size: u64,
    digests: Vec<[u8; 32]>,
}

fuzz_target!(|input: FuzzInput| {
    let digests: Vec<sha256::Digest> = input
        .digests
        .iter()
        .take(MAX_SIZE)
        .map(|bytes| sha256::Digest::from(*bytes))
        .collect();

    let proof = Proof {
        size: input.proof_size.into(),
        digests,
    };

    if let Some(start_loc) = Location::new(input.start_loc) {
        _ = extract_pinned_nodes(&proof, start_loc, input.operations_len);
    }
});
