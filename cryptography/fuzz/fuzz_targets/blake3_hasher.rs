#![no_main]

use arbitrary::Arbitrary;
use blake3::Hasher as RefBlake3;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    blake3::{hash as our_hash, Blake3 as OurBlake3, Digest},
    Hasher,
};
use libfuzzer_sys::fuzz_target;
use zeroize::Zeroize;

#[derive(Debug, Arbitrary)]
pub struct FuzzInput {
    pub chunks: Vec<Vec<u8>>,
    pub data: Vec<u8>,
    pub case_selector: u8,
}

fn fuzz_basic_hashing(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurBlake3::new();
    let mut ref_hasher = RefBlake3::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let our_result = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_bytes());
}

fn fuzz_reset_functionality(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurBlake3::new();
    let mut ref_hasher = RefBlake3::new();

    // First round
    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }
    let our_result = our_hasher.finalize();
    let ref_result = ref_hasher.finalize();
    assert_eq!(our_result.as_ref(), ref_result.as_bytes());

    // Reset and second round
    our_hasher.reset();
    let mut ref_hasher = RefBlake3::new();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_hasher.update(chunk);
    }

    let our_result_after_reset = our_hasher.finalize();
    let ref_result_after_reset = ref_hasher.finalize();
    assert_eq!(our_result, our_result_after_reset);
    assert_eq!(
        our_result_after_reset.as_ref(),
        ref_result_after_reset.as_bytes()
    );
}

fn fuzz_chunked_vs_whole(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurBlake3::new();
    let mut ref_hasher = RefBlake3::new();
    let mut all_data = Vec::new();

    for chunk in chunks {
        all_data.extend_from_slice(chunk);
        our_hasher.update(chunk);
    }

    let our_final = our_hasher.finalize();

    let ref_final = ref_hasher.update(&all_data).finalize();
    assert_eq!(our_final.as_ref(), ref_final.as_bytes());
}

fn fuzz_diff_hash(data: &[u8]) {
    let our_hash_result = our_hash(data);
    let mut ref_hasher = RefBlake3::new();
    assert_eq!(
        our_hash_result.as_ref(),
        ref_hasher.update(data).finalize().as_bytes()
    );
}

fn fuzz_digest_operations(data: &[u8]) {
    let empty_digest = OurBlake3::empty();
    assert_eq!(empty_digest.len(), 32);

    let hash_result = our_hash(data);
    let digest_from_hash = hash_result;

    let slice_ref: &[u8] = &digest_from_hash;
    assert_eq!(slice_ref.len(), 32);

    let mut mutable_digest = digest_from_hash;
    mutable_digest.zeroize();
    assert_eq!(mutable_digest.as_ref(), &[0u8; 32]);
}

fn fuzz_encode_decode(data: &[u8]) {
    let mut hasher = OurBlake3::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let encoded = digest.encode();
    assert_eq!(encoded.len(), 32); // DIGEST_LENGTH = 32
    assert_eq!(encoded, digest.as_ref());

    let decoded = Digest::decode(encoded).unwrap();
    assert_eq!(digest, decoded);
}

fn fuzz_clone_and_format(chunks: &[Vec<u8>]) {
    let mut original_hasher = OurBlake3::new();
    for chunk in chunks {
        original_hasher.update(chunk);
    }

    let mut cloned_hasher = original_hasher.clone();
    for chunk in chunks {
        cloned_hasher.update(chunk);
    }

    let original_digest = original_hasher.finalize();
    let cloned_digest = cloned_hasher.finalize();

    let debug_str = format!("{original_digest:?}");
    let display_str = format!("{cloned_digest}");
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
    let our_hash = our_hash(data);
    assert_eq!(our_digest.as_ref(), our_hash.as_ref());
}

fn fuzz(input: FuzzInput) {
    match input.case_selector % 8 {
        0 => fuzz_basic_hashing(&input.chunks),
        1 => fuzz_reset_functionality(&input.chunks),
        2 => fuzz_chunked_vs_whole(&input.chunks),
        3 => fuzz_diff_hash(&input.data),
        4 => fuzz_encode_decode(&input.data),
        5 => fuzz_clone_and_format(&input.chunks),
        6 => fuzz_digest_operations(&input.data),
        7 => fuzz_from_hash_and_deref(&input.data),
        _ => unreachable!(),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
