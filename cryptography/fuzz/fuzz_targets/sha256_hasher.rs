#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256 as OurSha256};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as RefSha2Digest, Sha256 as RefSha256};

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub chunks: Vec<Vec<u8>>,
    pub data: Vec<u8>,
    pub case_selector: u8,
}

// Basic hashing comparison with chunks
fn fuzz_basic_hashing(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurSha256::new();
    let mut ref_hasher = RefSha256::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let our_result = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_slice());
}

// Reset functionality
fn fuzz_reset_functionality(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurSha256::new();
    let mut ref_hasher = RefSha256::new();

    // First round
    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }
    let our_result = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_slice());

    // Reset and second round
    our_hasher.reset();
    let mut ref_hasher = RefSha256::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let our_result_after_reset = our_hasher.finalize();
    let ref_result_after_reset = ref_hasher.finalize();
    assert_eq!(our_result, our_result_after_reset);
    assert_eq!(
        our_result_after_reset.as_ref(),
        ref_result_after_reset.as_slice()
    );
}

// Chunked vs all-at-once hashing
fn fuzz_chunked_vs_whole(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurSha256::new();
    let mut all_data = Vec::new();

    for chunk in chunks {
        all_data.extend_from_slice(chunk);
        our_hasher.update(chunk);
    }

    let our_final = our_hasher.finalize();
    let ref_final = RefSha256::digest(&all_data);
    assert_eq!(our_final.as_ref(), ref_final.as_slice());
}

// Differential fuzzing
fn fuzz_diff_hash(data: &[u8]) {
    let our_hash_result = OurSha256::hash(data);
    let ref_hash_result = RefSha256::digest(data);
    assert_eq!(our_hash_result.as_ref(), ref_hash_result.as_slice());
}

// Encode/decode functionality
fn fuzz_encode_decode(data: &[u8]) {
    let mut hasher = OurSha256::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let encoded = digest.encode();
    assert_eq!(encoded.len(), 32); // DIGEST_LENGTH = 32
    assert_eq!(encoded, digest.as_ref());

    let decoded = Digest::decode(encoded).unwrap();
    assert_eq!(digest, decoded);
}

fn fuzz(input: FuzzInput) {
    match input.case_selector % 5 {
        0 => fuzz_basic_hashing(&input.chunks),
        1 => fuzz_reset_functionality(&input.chunks),
        2 => fuzz_chunked_vs_whole(&input.chunks),
        3 => fuzz_diff_hash(&input.data),
        4 => fuzz_encode_decode(&input.data),
        _ => unreachable!(),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
