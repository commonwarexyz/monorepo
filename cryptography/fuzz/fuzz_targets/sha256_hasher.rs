#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{sha256::Digest, Hasher, Sha256 as OurSha256};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as RefSha2Digest, Sha256 as RefSha256};
use zeroize::Zeroize;

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

// Test Default and Clone implementations
fn fuzz_default_clone() {
    let mut hasher1 = OurSha256::default();
    let mut hasher2 = hasher1.clone();

    // Both should produce the same result for empty input
    let digest1 = hasher1.finalize();
    let digest2 = hasher2.finalize();
    assert_eq!(digest1, digest2);
}

// Test fill method and formatting
fn fuzz_fill_and_format(byte_val: u8) {
    let digest = OurSha256::fill(byte_val);

    // Test Deref trait
    let slice: &[u8] = &digest;
    assert_eq!(slice.len(), 32);
    assert!(slice.iter().all(|&b| b == byte_val));

    // Test Debug and Display formatting
    let debug_str = format!("{digest:?}");
    let display_str = format!("{digest}");
    assert_eq!(debug_str, display_str);
    assert_eq!(debug_str.len(), 64); // 32 bytes * 2 hex chars each
}

// Test empty method
fn fuzz_empty() {
    let empty_digest = OurSha256::empty();
    let manual_empty = OurSha256::new().finalize();
    assert_eq!(empty_digest, manual_empty);
}

// Test Zeroize implementation
fn fuzz_zeroize() {
    let mut digest = OurSha256::fill(0xFF);

    // Verify it's not all zeros initially
    assert!(digest.as_ref().iter().any(|&b| b != 0));

    // Zeroize and verify all bytes are zero
    digest.zeroize();
    assert!(digest.as_ref().iter().all(|&b| b == 0));
}

fn fuzz(input: FuzzInput) {
    match input.case_selector % 9 {
        0 => fuzz_basic_hashing(&input.chunks),
        1 => fuzz_reset_functionality(&input.chunks),
        2 => fuzz_chunked_vs_whole(&input.chunks),
        3 => fuzz_diff_hash(&input.data),
        4 => fuzz_encode_decode(&input.data),
        5 => fuzz_default_clone(),
        6 => fuzz_fill_and_format(input.data.first().copied().unwrap_or(0)),
        7 => fuzz_empty(),
        8 => fuzz_zeroize(),
        _ => unreachable!(),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
