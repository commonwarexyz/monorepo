//! Shared conformance test utilities and stability tests for Merkle-family structures.

use crate::merkle::{hasher::Hasher, mem::Mem, Family};
use commonware_conformance::{conformance_tests, Conformance};
use commonware_cryptography::{sha256, Sha256};

/// Build a test Merkle structure by adding `elements` elements using the provided hasher.
///
/// Each element's preimage is `i.to_be_bytes()` for `i` in `0..elements`. The elements are
/// first hashed (via [`Hasher::digest`]) before being added, so the leaf digests are
/// deterministic regardless of family.
pub fn build_test_mem<F, H>(
    hasher: &H,
    mut mem: Mem<F, sha256::Digest>,
    elements: u64,
) -> Mem<F, sha256::Digest>
where
    F: Family,
    H: Hasher<F, Digest = sha256::Digest>,
{
    let batch = {
        let mut batch = mem.new_batch();
        for i in 0u64..elements {
            let element = hasher.digest(&i.to_be_bytes());
            batch = batch.add(hasher, &element);
        }
        batch.merkleize(&mem, hasher)
    };
    mem.apply_batch(&batch).unwrap();
    mem
}

/// Build a test MMR by adding `elements` elements using the provided hasher.
///
/// Thin wrapper around [`build_test_mem`] with the MMR family types fixed.
pub fn build_test_mmr<H: Hasher<crate::mmr::Family, Digest = sha256::Digest>>(
    hasher: &H,
    mmr: crate::mmr::mem::Mmr<sha256::Digest>,
    elements: u64,
) -> crate::mmr::mem::Mmr<sha256::Digest> {
    build_test_mem(hasher, mmr, elements)
}

// ---------------------------------------------------------------------------
// Conformance tests
// ---------------------------------------------------------------------------

type Standard = crate::merkle::hasher::Standard<Sha256>;

/// Tests stability of MMR root computation.
///
/// Builds an MMR by adding `seed` elements and returns the final root. Any change to the root
/// computation algorithm will cause this test to fail.
struct MmrRootStability;

impl Conformance for MmrRootStability {
    async fn commit(seed: u64) -> Vec<u8> {
        let hasher = Standard::new();
        let mmr = crate::mmr::mem::Mmr::new(&hasher);
        build_test_mem(&hasher, mmr, seed).root().to_vec()
    }
}

/// Tests stability of MMB root computation.
///
/// Builds an MMB by adding `seed` elements and returns the final root. Any change to the root
/// computation algorithm will cause this test to fail.
struct MmbRootStability;

impl Conformance for MmbRootStability {
    async fn commit(seed: u64) -> Vec<u8> {
        let hasher = Standard::new();
        let mmb = crate::mmb::mem::Mmb::new(&hasher);
        build_test_mem(&hasher, mmb, seed).root().to_vec()
    }
}

conformance_tests! {
    MmrRootStability => 200,
    MmbRootStability => 200,
}
