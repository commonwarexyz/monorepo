//! Shared conformance test utilities and stability tests for Merkle-family structures.

use crate::merkle::{hasher::Hasher, mem::Mem, Family};
use commonware_cryptography::sha256;

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

#[cfg(feature = "arbitrary")]
mod tests {
    use super::*;
    use crate::merkle::{full, Bagging::ForwardFold};
    use commonware_conformance::{conformance_tests, Conformance};
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef,
        conformance::{StorageConformance, StorageWorkload},
        BufferPooler, Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use rand::RngExt as _;

    type Standard = crate::merkle::hasher::Standard<Sha256>;

    /// Tests stability of MMR root computation.
    ///
    /// Builds an MMR by adding `seed` elements and returns the final root. Any change to the root
    /// computation algorithm will cause this test to fail.
    struct MmrRootStability;

    impl Conformance for MmrRootStability {
        async fn commit(seed: u64) -> Vec<u8> {
            let hasher = Standard::new(ForwardFold);
            let mmr = crate::mmr::mem::Mmr::new();
            build_test_mem(&hasher, mmr, seed)
                .root(&hasher, 0)
                .unwrap()
                .to_vec()
        }
    }

    /// Tests stability of MMB root computation.
    ///
    /// Builds an MMB by adding `seed` elements and returns the final root. Any change to the root
    /// computation algorithm will cause this test to fail.
    struct MmbRootStability;

    impl Conformance for MmbRootStability {
        async fn commit(seed: u64) -> Vec<u8> {
            let hasher = Standard::new(ForwardFold);
            let mmb = crate::mmb::mem::Mmb::new();
            build_test_mem(&hasher, mmb, seed)
                .root(&hasher, 0)
                .unwrap()
                .to_vec()
        }
    }

    fn storage_config(prefix: &str, pooler: &impl BufferPooler) -> full::Config<Sequential> {
        full::Config {
            journal_partition: format!("{prefix}-journal"),
            metadata_partition: format!("{prefix}-metadata"),
            items_per_blob: NZU64!(11),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: CacheRef::from_pooler(pooler, NZU16!(1024), NZUsize!(10)),
        }
    }

    async fn run_full_merkle<F>(
        mut context: commonware_runtime::deterministic::Context,
        seed: u64,
        prefix: &'static str,
    ) -> Result<(), crate::merkle::Error<F>>
    where
        F: Family,
    {
        let hasher = Standard::new(ForwardFold);
        let cfg = storage_config(&format!("{prefix}-{seed}"), &context);
        let mut merkle = full::Merkle::<F, _, sha256::Digest, Sequential>::init(
            context.child("merkle"),
            &hasher,
            cfg,
        )
        .await?;

        let items = context.random_range(16..96);
        let mut batch = merkle.new_batch();
        for i in 0..items {
            let element = hasher.digest(&seed.wrapping_add(i as u64).to_be_bytes());
            batch = batch.add(&hasher, &element);
        }
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle.apply_batch(&batch)?;
        merkle.sync().await?;

        if items > 32 {
            merkle
                .prune(crate::merkle::Location::new(items as u64 / 3))
                .await?;
            merkle.sync().await?;
        }

        Ok(())
    }

    struct MmrFullWorkload;

    impl StorageWorkload for MmrFullWorkload {
        type Error = crate::merkle::Error<crate::mmr::Family>;

        async fn run(
            context: commonware_runtime::deterministic::Context,
            seed: u64,
        ) -> Result<(), Self::Error> {
            run_full_merkle::<crate::mmr::Family>(context, seed, "mmr-full-conformance").await
        }
    }

    struct MmbFullWorkload;

    impl StorageWorkload for MmbFullWorkload {
        type Error = crate::merkle::Error<crate::mmb::Family>;

        async fn run(
            context: commonware_runtime::deterministic::Context,
            seed: u64,
        ) -> Result<(), Self::Error> {
            run_full_merkle::<crate::mmb::Family>(context, seed, "mmb-full-conformance").await
        }
    }

    conformance_tests! {
        MmrRootStability => 200,
        MmbRootStability => 200,
        StorageConformance<MmrFullWorkload> => 256,
        StorageConformance<MmbFullWorkload> => 256,
    }
}
