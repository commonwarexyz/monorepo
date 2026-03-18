//! MMR conformance tests and shared test utilities for root stability.

use crate::mmr::{
    hasher::{Hasher, Standard},
    mem::Mmr,
};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::{sha256, Sha256};

/// Build a test MMR by adding `elements` elements using the provided hasher.
pub fn build_test_mmr<H: Hasher<Digest = sha256::Digest>>(
    hasher: &H,
    mut mmr: Mmr<sha256::Digest>,
    elements: u64,
) -> Mmr<sha256::Digest> {
    let changeset = {
        let mut batch = mmr.new_batch();
        for i in 0u64..elements {
            let element = hasher.digest(&i.to_be_bytes());
            batch = batch.add(hasher, &element);
        }
        batch.merkleize(hasher).finalize()
    };
    mmr.apply(changeset).unwrap();
    mmr
}

/// Tests stability of MMR root computation.
///
/// Builds an MMR by adding `seed` elements and returns the final root. Any change to the root
/// computation algorithm will cause this test to fail.
struct MmrRootStability;

impl Conformance for MmrRootStability {
    async fn commit(seed: u64) -> Vec<u8> {
        let hasher: Standard<Sha256> = Standard::new();
        let mmr = Mmr::new(&hasher);
        let mmr = build_test_mmr(&hasher, mmr, seed);

        mmr.root().to_vec()
    }
}

conformance_tests! {
    MmrRootStability => 200,
}
