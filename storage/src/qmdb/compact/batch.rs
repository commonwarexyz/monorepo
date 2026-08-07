//! Shared helpers for compact QMDB batches.

use crate::{
    merkle::{self, Family, batch, compact, hasher::Hasher as _},
    qmdb,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use std::sync::Arc;

/// Encode operations, append them to a compact Merkle batch, merkleize, and compute the post-apply
/// root, all as one CPU-bound job submitted through [`Strategy::spawn`].
///
/// The job hashes against an immutable snapshot of the committed Merkle state, so a parallel
/// strategy can offload the dominant CPU phase onto its own pool instead of occupying the calling
/// task. If the caller is cancelled mid-job, the job still runs to completion against its snapshot
/// and the result is discarded.
#[allow(clippy::type_complexity)]
pub(crate) async fn merkleize_ops<F, H, S, Op>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    batch: compact::UnmerkleizedBatch<F, H::Digest, S>,
    ops: Vec<Op>,
    inactive_peaks: usize,
) -> Result<(Arc<batch::MerkleizedBatch<F, H::Digest, S>>, H::Digest), merkle::Error<F>>
where
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: EncodeShared + 'static,
{
    let first_leaf = batch.leaves();
    let ancestors = batch.retain_ancestors();
    let mem = merkle.snapshot();
    let strategy = merkle.strategy().clone();
    strategy
        .spawn(ops.len(), move |strategy| {
            let hasher = qmdb::hasher::<H>();
            let leaf_digests =
                strategy.map_init_collect_vec(ops.iter().enumerate(), Vec::new, |buf, (i, op)| {
                    let offset = u64::try_from(i).expect("operation offset exceeds u64");
                    let pos = F::location_to_position(first_leaf + offset);
                    buf.clear();
                    op.write(buf);
                    hasher.leaf_digest(pos, buf.as_slice())
                });

            let batch = batch.add_leaf_digests(leaf_digests);
            let merkleized = batch.merkleize(&mem, &hasher);
            let root = merkleized.root(&mem, &hasher, inactive_peaks)?;
            drop(ancestors);
            Ok((merkleized, root))
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{mmb, mmr},
        utils::detached::{DropMonitor, block_strategy},
    };
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{Runner as _, deterministic};
    use commonware_utils::NZUsize;
    use std::time::Duration;

    /// Merkleization retains a speculative suffix after its committed prefix is released.
    async fn test_merkleize_ops_after_committed_prefix_dropped_inner<F: Family>() {
        let mut merkle =
            compact::Merkle::<F, <Sha256 as Hasher>::Digest, Sequential>::new(Sequential);

        // Build a speculative suffix over a prefix that will be committed independently.
        let (prefix, _) =
            merkleize_ops::<F, Sha256, _, _>(&merkle, merkle.new_batch(), (0..8u64).collect(), 0)
                .await
                .unwrap();
        let (pending, _) = merkleize_ops::<F, Sha256, _, _>(
            &merkle,
            compact::UnmerkleizedBatch::wrap(prefix.new_batch()),
            vec![8u64, 9],
            0,
        )
        .await
        .unwrap();

        // Commit and release the prefix. Its Merkle nodes now resolve through the snapshot.
        merkle.apply_batch(&prefix).unwrap();
        drop(prefix);

        // The child batch is the pending suffix's only remaining owner. Merkleization must retain
        // that suffix through root computation.
        let child_batch = compact::UnmerkleizedBatch::wrap(pending.new_batch());
        drop(pending);
        let (child, expected_root) =
            merkleize_ops::<F, Sha256, _, _>(&merkle, child_batch, vec![10u64], 0)
                .await
                .unwrap();
        merkle.apply_batch(&child).unwrap();

        assert_eq!(*merkle.leaves(), 11);
        assert_eq!(
            merkle.root(&qmdb::hasher::<Sha256>(), 0).unwrap(),
            expected_root
        );
    }

    #[test_traced]
    fn test_merkleize_ops_after_committed_prefix_dropped_mmr() {
        deterministic::Runner::default()
            .start(|_| test_merkleize_ops_after_committed_prefix_dropped_inner::<mmr::Family>());
    }

    #[test_traced]
    fn test_merkleize_ops_after_committed_prefix_dropped_mmb() {
        deterministic::Runner::default()
            .start(|_| test_merkleize_ops_after_committed_prefix_dropped_inner::<mmb::Family>());
    }

    /// A detached merkleization job owns the full ancestor chain after its waiter is dropped.
    #[test_traced]
    fn test_merkleize_ops_retains_ancestors_after_cancellation() {
        deterministic::Runner::default().start(|_| async move {
            let strategy = Rayon::new(NZUsize!(2)).unwrap();
            let merkle =
                compact::Merkle::<mmb::Family, <Sha256 as Hasher>::Digest, _>::new(strategy);
            let hasher = qmdb::hasher::<Sha256>();

            let mut a_batch = merkle.new_batch();
            for i in 0..8u64 {
                a_batch = a_batch.add(&hasher, &i.to_be_bytes());
            }
            let a = merkle.with_mem(|mem| a_batch.merkleize(mem, &hasher));
            let mut b_batch = compact::UnmerkleizedBatch::wrap(a.new_batch());
            for i in 8..10u64 {
                b_batch = b_batch.add(&hasher, &i.to_be_bytes());
            }
            let b = merkle.with_mem(|mem| b_batch.merkleize(mem, &hasher));

            let ancestor = Arc::downgrade(&a);
            let c_batch = compact::UnmerkleizedBatch::wrap(b.new_batch());
            drop(b);

            let release = block_strategy(merkle.strategy(), 2);
            let (op, clean_drop) = DropMonitor::tracked(10u64);
            let mut merkleize = Box::pin(merkleize_ops::<mmb::Family, Sha256, _, _>(
                &merkle,
                c_batch,
                vec![op],
                0,
            ));
            assert!(futures::poll!(merkleize.as_mut()).is_pending());
            drop(merkleize);
            drop(a);

            assert!(ancestor.upgrade().is_some());
            drop(release);
            assert!(
                clean_drop
                    .recv_timeout(Duration::from_secs(10))
                    .expect("detached merkleization did not finish"),
                "detached merkleization panicked"
            );
            assert!(ancestor.upgrade().is_none());
        });
    }
}
