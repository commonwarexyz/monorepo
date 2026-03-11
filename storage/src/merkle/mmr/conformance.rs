//! MMR conformance tests and shared test utilities for root stability.

use crate::mmr::{
    hasher::{Hasher as MmrHasher, Standard},
    mem::Mmr,
};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::{sha256, Sha256};

/// Build a test MMR by adding `elements` elements using the provided hasher.
pub fn build_test_mmr<H: MmrHasher<Digest = sha256::Digest>>(
    hasher: &mut H,
    mut mmr: Mmr<H>,
    elements: u64,
) -> Mmr<H> {
    let changeset = {
        let mut batch = mmr.new_batch();
        for i in 0u64..elements {
            let element = hasher.digest(&i.to_be_bytes());
            batch.add(hasher, &element);
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
        let mut hasher: Standard<Sha256> = Standard::new();
        let mmr = Mmr::new(hasher.clone());
        let mmr = build_test_mmr(&mut hasher, mmr, seed);

        mmr.root().to_vec()
    }
}

conformance_tests! {
    MmrRootStability => 200,
}
