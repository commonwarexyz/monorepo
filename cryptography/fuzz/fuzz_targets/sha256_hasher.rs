#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    Hasher, Sha256 as OurSha256,
    fuzz::{BatchPlan, Plan},
    sha256::Digest,
};
use commonware_parallel::{Manual, Rayon, Strategy as _};
use commonware_utils::NZUsize;
use libfuzzer_sys::fuzz_target;
use sha2::{Digest as RefSha2Digest, Sha256 as RefSha256};
use std::sync::LazyLock;
use zeroize::Zeroize;

/// A four-worker strategy with adaptive decisions disabled, so it takes every split a hasher
/// offers it. It is built once and reused across invocations because starting a thread pool is
/// expensive.
static STRATEGY: LazyLock<Manual<Rayon>> =
    LazyLock::new(|| Rayon::new(NZUsize!(4)).unwrap().manual());

#[derive(Debug, Arbitrary)]
enum Operation {
    /// Streaming matches the reference, and one-shot hashing matches streaming.
    BasicHashing(Vec<Vec<u8>>),
    /// The hasher returned by finalize starts over.
    ResetFunctionality(Vec<Vec<u8>>),
    /// Streaming in chunks matches the reference over the whole input.
    ChunkedVsWhole(Vec<Vec<u8>>),
    /// One-shot hashing matches the reference.
    DiffHash(Vec<u8>),
    /// Codec roundtrip.
    EncodeDecode(Vec<u8>),
    /// Two default hashers agree.
    DefaultClone,
    /// A filled digest's bytes and formatting.
    FillAndFormat(u8),
    /// Zeroize clears a digest.
    Zeroize,
    /// One-shot and pair entrypoints match streaming.
    HasherPlan(Plan<OurSha256>),
    /// Batched hashing matches streaming, on the calling thread and across workers.
    HasherBatchPlan(BatchPlan<OurSha256>),
}

// Basic hashing comparison with chunks
fn fuzz_basic_hashing(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurSha256::default();
    let mut ref_hasher = RefSha256::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let (_, our_result) = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_slice());

    // The one-shot API should agree with streaming.
    let parts: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    assert_eq!(OurSha256::hash(&parts), our_result);
}

// Reset functionality: the hasher returned by `finalize` is freshly reset.
fn fuzz_reset_functionality(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurSha256::default();
    let mut ref_hasher = RefSha256::new();

    // First round
    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }
    let (our_hasher, our_result) = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_slice());

    // Reuse the reset hasher for the second round
    let mut our_hasher = our_hasher;
    let mut ref_hasher = RefSha256::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let (_, our_result_after_reset) = our_hasher.finalize();
    let ref_result_after_reset = ref_hasher.finalize();
    assert_eq!(our_result, our_result_after_reset);
    assert_eq!(
        our_result_after_reset.as_ref(),
        ref_result_after_reset.as_slice()
    );
}

// Chunked vs all-at-once hashing
fn fuzz_chunked_vs_whole(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurSha256::default();
    let mut all_data = Vec::new();

    for chunk in chunks {
        all_data.extend_from_slice(chunk);
        our_hasher.update(chunk);
    }

    let (_, our_final) = our_hasher.finalize();
    let ref_final = RefSha256::digest(&all_data);
    assert_eq!(our_final.as_ref(), ref_final.as_slice());
}

// Differential fuzzing
fn fuzz_diff_hash(data: &[u8]) {
    let our_hash_result = OurSha256::hash(&[data]);
    let ref_hash_result = RefSha256::digest(data);
    assert_eq!(our_hash_result.as_ref(), ref_hash_result.as_slice());
}

// Encode/decode functionality
fn fuzz_encode_decode(data: &[u8]) {
    let mut hasher = OurSha256::default();
    hasher.update(data);
    let (_, digest) = hasher.finalize();

    let encoded = digest.encode();
    assert_eq!(encoded.len(), 32); // DIGEST_LENGTH = 32
    assert_eq!(encoded, digest.as_ref());

    let decoded = Digest::decode(encoded).unwrap();
    assert_eq!(digest, decoded);
}

// Two independently-constructed default hashers produce the same result
fn fuzz_default_clone() {
    let hasher1 = OurSha256::default();
    let hasher2 = OurSha256::default();

    // Both should produce the same result for empty input
    let (_, digest1) = hasher1.finalize();
    let (_, digest2) = hasher2.finalize();
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

// Test Zeroize implementation
fn fuzz_zeroize() {
    let mut digest = OurSha256::fill(0xFF);

    // Verify it's not all zeros initially
    assert!(digest.as_ref().iter().any(|&b| b != 0));

    // Zeroize and verify all bytes are zero
    digest.zeroize();
    assert!(digest.as_ref().iter().all(|&b| b == 0));
}

fuzz_target!(|op: Operation| {
    match op {
        Operation::BasicHashing(chunks) => fuzz_basic_hashing(&chunks),
        Operation::ResetFunctionality(chunks) => fuzz_reset_functionality(&chunks),
        Operation::ChunkedVsWhole(chunks) => fuzz_chunked_vs_whole(&chunks),
        Operation::DiffHash(data) => fuzz_diff_hash(&data),
        Operation::EncodeDecode(data) => fuzz_encode_decode(&data),
        Operation::DefaultClone => fuzz_default_clone(),
        Operation::FillAndFormat(byte) => fuzz_fill_and_format(byte),
        Operation::Zeroize => fuzz_zeroize(),
        Operation::HasherPlan(plan) => plan.run(),
        Operation::HasherBatchPlan(plan) => plan.run(&*STRATEGY),
    }
});
