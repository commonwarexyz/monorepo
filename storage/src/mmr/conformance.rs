//! MMR conformance tests and shared test utilities for root stability.

use crate::mmr::{
    hasher::{Hasher as MmrHasher, Standard},
    mem::Mmr,
};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::{sha256, Sha256};

/// Build a test MMR by adding `elements` elements.
pub fn build_test_mmr<A: MmrHasher<Digest = sha256::Digest>>(
    mut mmr: Mmr<A>,
    elements: u64,
) -> Mmr<A> {
    let changeset = {
        let mut batch = mmr.new_batch();
        for i in 0u64..elements {
            let element = batch.hasher().digest(&i.to_be_bytes());
            batch.add(&element);
        }
        batch.merkleize().finalize()
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
        let mmr = Mmr::new(Standard::<Sha256>::new());
        let mmr = build_test_mmr(mmr, seed);

        mmr.root().to_vec()
    }
}

conformance_tests! {
    MmrRootStability => 200,
}
