#![no_main]

use arbitrary::Arbitrary;
use blake3::{CHUNK_LEN, Hasher as RefBlake3};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    Hasher,
    blake3::{Blake3 as OurBlake3, Digest},
    fuzz::Plan,
};
use commonware_parallel::{Manual, Rayon, Strategy as _};
use commonware_utils::{NZUsize, TestRng};
use libfuzzer_sys::fuzz_target;
use rand::Rng as _;
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
    /// Determinism and Debug/Display formatting.
    CloneAndFormat(Vec<Vec<u8>>),
    /// Digest slicing and zeroize.
    DigestOperations(Vec<u8>),
    /// Conversion from the reference digest, and Deref.
    FromHashAndDeref(Vec<u8>),
    /// One-shot and pair entrypoints match streaming.
    HasherPlan(Plan<OurBlake3>),
    /// A long message cut into parts hashes across workers to the reference digest.
    HashAcross {
        seed: u64,
        extra_len: u16,
        cuts: Vec<u32>,
    },
}

fn fuzz_basic_hashing(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurBlake3::default();
    let mut ref_hasher = RefBlake3::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let (_, our_result) = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_bytes());

    // The one-shot API should agree with streaming.
    let parts: Vec<&[u8]> = chunks.iter().map(|c| c.as_slice()).collect();
    assert_eq!(OurBlake3::hash(&parts), our_result);
}

fn fuzz_reset_functionality(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurBlake3::default();
    let mut ref_hasher = RefBlake3::new();

    // First round
    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }
    let (our_hasher, our_result) = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_bytes());

    // Reuse the reset hasher for the second round
    let mut our_hasher = our_hasher;
    let mut ref_hasher = RefBlake3::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let (_, our_result_after_reset) = our_hasher.finalize();
    let ref_result_after_reset = ref_hasher.finalize();
    assert_eq!(our_result, our_result_after_reset);
    assert_eq!(
        our_result_after_reset.as_ref(),
        ref_result_after_reset.as_bytes()
    );
}

fn fuzz_chunked_vs_whole(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurBlake3::default();
    let mut ref_hasher = RefBlake3::new();
    let mut all_data = Vec::new();

    for chunk in chunks {
        all_data.extend_from_slice(chunk);
        our_hasher.update(chunk);
    }

    let (_, our_final) = our_hasher.finalize();

    let ref_final = ref_hasher.update(&all_data).finalize();
    assert_eq!(our_final.as_ref(), ref_final.as_bytes());
}

fn fuzz_diff_hash(data: &[u8]) {
    let our_hash_result = OurBlake3::hash(&[data]);
    let mut ref_hasher = RefBlake3::new();
    assert_eq!(
        our_hash_result.as_ref(),
        ref_hasher.update(data).finalize().as_bytes()
    );
}

fn fuzz_digest_operations(data: &[u8]) {
    let hash_result = OurBlake3::hash(&[data]);
    let digest_from_hash = hash_result;

    let slice_ref: &[u8] = &digest_from_hash;
    assert_eq!(slice_ref.len(), 32);

    let mut mutable_digest = digest_from_hash;
    mutable_digest.zeroize();
    assert_eq!(mutable_digest.as_ref(), &[0u8; 32]);
}

fn fuzz_encode_decode(data: &[u8]) {
    let mut hasher = OurBlake3::default();
    hasher.update(data);
    let (_, digest) = hasher.finalize();

    let encoded = digest.encode();
    assert_eq!(encoded.len(), 32); // DIGEST_LENGTH = 32
    assert_eq!(encoded, digest.as_ref());

    let decoded = Digest::decode(encoded).unwrap();
    assert_eq!(digest, decoded);
}

fn fuzz_clone_and_format(chunks: &[Vec<u8>]) {
    // Two independently-built hashers over the same input must agree.
    let mut original_hasher = OurBlake3::default();
    for chunk in chunks {
        original_hasher.update(chunk);
    }

    let mut second_hasher = OurBlake3::default();
    for chunk in chunks {
        second_hasher.update(chunk);
    }

    let (_, original_digest) = original_hasher.finalize();
    let (_, second_digest) = second_hasher.finalize();
    assert_eq!(original_digest, second_digest);

    let debug_str = format!("{original_digest:?}");
    let display_str = format!("{second_digest}");
    assert_eq!(debug_str, display_str);
    assert!(!debug_str.is_empty());
    assert_eq!(debug_str.len(), 64); // 32 bytes * 2 hex chars each
}

// Test From<Hash> implementation and Deref trait
fn fuzz_from_hash_and_deref(data: &[u8]) {
    // Test From<blake3::Hash> conversion
    let ref_hash = RefBlake3::new().update(data).finalize();
    let our_digest: Digest = ref_hash.into();

    // Test Deref trait - should be able to use as &[u8]
    let slice: &[u8] = &our_digest;
    assert_eq!(slice.len(), 32);
    assert_eq!(slice, our_digest.as_ref());

    // Verify the conversion worked correctly
    let our_hash = OurBlake3::hash(&[data]);
    assert_eq!(our_digest.as_ref(), our_hash.as_ref());
}

// Hash a message of 127 to 191 KiB, around the 128 KiB from which `hash_across` splits a
// message across workers, cut into parts at `cuts` (a repeated cut leaves an empty part).
fn fuzz_hash_across(seed: u64, extra_len: u16, cuts: &[u32]) {
    let len = 128 * 1024 - CHUNK_LEN + usize::from(extra_len);
    let mut message = vec![0; len];
    TestRng::new(seed).fill_bytes(&mut message);

    let mut bounds: Vec<usize> = cuts.iter().map(|&cut| cut as usize % (len + 1)).collect();
    bounds.extend([0, len]);
    bounds.sort_unstable();
    let parts: Vec<&[u8]> = bounds
        .windows(2)
        .map(|bound| &message[bound[0]..bound[1]])
        .collect();

    let our_result = OurBlake3::hash_across(&parts, &*STRATEGY);
    let ref_result = RefBlake3::new().update(&message).finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_bytes());
}

fuzz_target!(|op: Operation| {
    match op {
        Operation::BasicHashing(chunks) => fuzz_basic_hashing(&chunks),
        Operation::ResetFunctionality(chunks) => fuzz_reset_functionality(&chunks),
        Operation::ChunkedVsWhole(chunks) => fuzz_chunked_vs_whole(&chunks),
        Operation::DiffHash(data) => fuzz_diff_hash(&data),
        Operation::EncodeDecode(data) => fuzz_encode_decode(&data),
        Operation::CloneAndFormat(chunks) => fuzz_clone_and_format(&chunks),
        Operation::DigestOperations(data) => fuzz_digest_operations(&data),
        Operation::FromHashAndDeref(data) => fuzz_from_hash_and_deref(&data),
        Operation::HasherPlan(plan) => plan.run(),
        Operation::HashAcross {
            seed,
            extra_len,
            cuts,
        } => fuzz_hash_across(seed, extra_len, &cuts),
    }
});
