#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::Sha256;
use commonware_storage::{adb::extract_pinned_nodes, mmr::Proof};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    proof_size: u64,
    start_loc: u64,
    operations_len: u64,
    num_digests: u8,
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let input: FuzzInput = match u.arbitrary() {
        Ok(v) => v,
        Err(_) => return,
    };

    if input.operations_len == 0 {
        return;
    }

    let mut digests = Vec::new();
    let num_digests = input.num_digests.min(100) as usize;

    for i in 0..num_digests {
        let mut digest_bytes = [0u8; 32];
        for (j, byte) in digest_bytes.iter_mut().enumerate() {
            *byte = ((i + j) % 256) as u8;
        }
        let digest = <Sha256 as commonware_cryptography::Hasher>::Digest::from(digest_bytes);
        digests.push(digest);
    }

    let proof = Proof {
        size: input.proof_size,
        digests,
    };

    let _ = extract_pinned_nodes(&proof, input.start_loc, input.operations_len);
});
