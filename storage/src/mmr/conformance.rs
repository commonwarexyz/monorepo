//! MMR conformance tests and shared test utilities for root stability.

use crate::mmr::{
    hasher::{Hasher as MmrHasher, Standard},
    mem::CleanMmr,
};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::{sha256, Hasher, Sha256};

/// Number of elements used in stability tests.
pub const STABILITY_TEST_ELEMENTS: u64 = 199;

/// Build a reference MMR with `STABILITY_TEST_ELEMENTS` elements using `CleanMmr::add`
/// and return all 200 roots (indices 0-199, where index i is the root after i elements).
pub fn build_reference_roots() -> Vec<sha256::Digest> {
    let mut hasher: Standard<Sha256> = Standard::new();
    let mut mmr: CleanMmr<sha256::Digest> = CleanMmr::new(&mut hasher);
    let mut roots = Vec::with_capacity(200);

    for i in 0u64..200 {
        roots.push(*mmr.root());
        if i < STABILITY_TEST_ELEMENTS {
            hasher.inner().update(&i.to_be_bytes());
            let element = hasher.inner().finalize();
            mmr.add(&mut hasher, &element);
        }
    }
    roots
}

/// Build a test MMR by adding `STABILITY_TEST_ELEMENTS` elements using the provided hasher.
pub fn build_test_mmr<H: MmrHasher<sha256::Digest>>(
    hasher: &mut H,
    mut mmr: CleanMmr<sha256::Digest>,
) -> CleanMmr<sha256::Digest> {
    for i in 0u64..STABILITY_TEST_ELEMENTS {
        hasher.inner().update(&i.to_be_bytes());
        let element = hasher.inner().finalize();
        mmr.add(hasher, &element);
    }
    mmr
}

/// Tests stability of MMR root computation.
///
/// Builds an MMR by adding 199 elements and returns all 200 roots concatenated
/// (including the empty root at index 0). Any change to the root computation
/// algorithm will cause this test to fail.
struct MmrRootStability;

impl Conformance for MmrRootStability {
    async fn commit(_seed: u64) -> Vec<u8> {
        // Use the shared helper to build roots.
        let roots = build_reference_roots();
        // Concatenate all root bytes for hashing.
        roots.iter().flat_map(|r| r.as_ref()).copied().collect()
    }
}

conformance_tests! {
    MmrRootStability => 1,
}
