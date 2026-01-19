//! MMR conformance tests and shared test utilities for root stability.

use crate::mmr::{
    hasher::{Hasher as MmrHasher, Standard},
    mem::CleanMmr,
};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::{sha256, Hasher, Sha256};

/// Build a test MMR by adding `elements` elements using the provided hasher.
pub fn build_test_mmr<H: MmrHasher<Digest = sha256::Digest>>(
    hasher: &mut H,
    mut mmr: CleanMmr<sha256::Digest>,
    elements: u64,
) -> CleanMmr<sha256::Digest> {
    for i in 0u64..elements {
        hasher.inner().update(&i.to_be_bytes());
        let element = hasher.inner().finalize();
        mmr.add(hasher, &element);
    }
    mmr
}

/// Tests stability of MMR root computation.
///
/// Builds an MMR by adding `seed` elements and returns the final root. Any change to the root
/// computation algorithm will cause this test to fail.
struct MmrRootStability;

impl Conformance for MmrRootStability {
    async fn commit(seed: u64) -> Vec<u8> {
        let mut hasher: Standard<Sha256> = Standard::new();
        let mmr = CleanMmr::new(&mut hasher);
        let mmr = build_test_mmr(&mut hasher, mmr, seed);

        mmr.root().to_vec()
    }
}

conformance_tests! {
    MmrRootStability => 200,
}
