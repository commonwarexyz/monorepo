#![no_main]

use arbitrary::Arbitrary;
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    crc32::{Crc32 as OurCrc32, Digest},
    Hasher,
};
use crc::{Crc, CRC_32_ISCSI};
use libfuzzer_sys::fuzz_target;

/// Reference CRC32C implementation from the `crc` crate.
const CRC32C_REF: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

#[derive(Debug, Arbitrary)]
enum Operation {
    /// Differential hashing with chunks.
    BasicHashing(Vec<Vec<u8>>),
    /// Reset and re-hash produces same result.
    ResetFunctionality(Vec<Vec<u8>>),
    /// Chunked hashing matches all-at-once.
    ChunkedVsWhole(Vec<Vec<u8>>),
    /// Static hash method matches reference.
    DiffHash(Vec<u8>),
    /// Codec roundtrip.
    EncodeDecode(Vec<u8>),
    /// u32 conversion roundtrip.
    DigestU32Roundtrip(Vec<u8>),
    /// Determinism and Debug/Display formatting.
    Determinism(Vec<Vec<u8>>),
}

fn fuzz_basic_hashing(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurCrc32::new();
    let mut ref_digest = CRC32C_REF.digest();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_digest.update(chunk);
    }

    let our_result = our_hasher.finalize();
    let ref_result = ref_digest.finalize();
    assert_eq!(our_result.as_u32(), ref_result);
}

fn fuzz_reset_functionality(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurCrc32::new();
    let mut ref_digest = CRC32C_REF.digest();

    // First round
    for chunk in chunks {
        our_hasher.update(chunk);
        ref_digest.update(chunk);
    }
    let our_result = our_hasher.finalize();
    let ref_result = ref_digest.finalize();
    assert_eq!(our_result.as_u32(), ref_result);

    // Reset and second round
    our_hasher.reset();
    let mut ref_digest = CRC32C_REF.digest();

    for chunk in chunks {
        our_hasher.update(chunk);
        ref_digest.update(chunk);
    }

    let our_result_after_reset = our_hasher.finalize();
    let ref_result_after_reset = ref_digest.finalize();
    assert_eq!(our_result, our_result_after_reset);
    assert_eq!(our_result_after_reset.as_u32(), ref_result_after_reset);
}

fn fuzz_chunked_vs_whole(chunks: &[Vec<u8>]) {
    let mut our_hasher = OurCrc32::new();
    let mut all_data = Vec::new();

    for chunk in chunks {
        all_data.extend_from_slice(chunk);
        our_hasher.update(chunk);
    }

    let our_final = our_hasher.finalize();
    let ref_final = CRC32C_REF.checksum(&all_data);
    assert_eq!(our_final.as_u32(), ref_final);
}

fn fuzz_encode_decode(data: &[u8]) {
    let mut hasher = OurCrc32::new();
    hasher.update(data);
    let digest = hasher.finalize();

    let encoded = digest.encode();
    assert_eq!(encoded.len(), 4);
    assert_eq!(encoded, digest.as_ref());

    let decoded = Digest::decode(encoded).unwrap();
    assert_eq!(digest, decoded);
}

fn fuzz_digest_u32_roundtrip(data: &[u8]) {
    let checksum = OurCrc32::checksum(data);
    let digest = Digest::from(checksum);
    assert_eq!(digest.as_u32(), checksum);

    // Verify against reference
    let ref_checksum = CRC32C_REF.checksum(data);
    assert_eq!(digest.as_u32(), ref_checksum);
}

fn fuzz_diff_hash(data: &[u8]) {
    let our_hash_result = OurCrc32::hash(data);
    let ref_result = CRC32C_REF.checksum(data);
    assert_eq!(our_hash_result.as_u32(), ref_result);
}

fn fuzz_determinism(chunks: &[Vec<u8>]) {
    // Two fresh hashers with same input produce identical output
    let mut hasher1 = OurCrc32::default();
    let mut hasher2 = OurCrc32::default();
    for chunk in chunks {
        hasher1.update(chunk);
        hasher2.update(chunk);
    }
    let digest1 = hasher1.finalize();
    let digest2 = hasher2.finalize();
    assert_eq!(digest1, digest2);

    // Debug and Display produce identical hex output
    let debug_str = format!("{digest1:?}");
    let display_str = format!("{digest1}");
    assert_eq!(debug_str, display_str);
    assert_eq!(debug_str.len(), 8); // 4 bytes * 2 hex chars
}

fuzz_target!(|op: Operation| {
    match op {
        Operation::BasicHashing(chunks) => fuzz_basic_hashing(&chunks),
        Operation::ResetFunctionality(chunks) => fuzz_reset_functionality(&chunks),
        Operation::ChunkedVsWhole(chunks) => fuzz_chunked_vs_whole(&chunks),
        Operation::DiffHash(data) => fuzz_diff_hash(&data),
        Operation::EncodeDecode(data) => fuzz_encode_decode(&data),
        Operation::DigestU32Roundtrip(data) => fuzz_digest_u32_roundtrip(&data),
        Operation::Determinism(chunks) => fuzz_determinism(&chunks),
    }
});
