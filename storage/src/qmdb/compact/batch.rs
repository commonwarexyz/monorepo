//! Shared helpers for compact QMDB batches.

use crate::{
    merkle::{self, Family, batch, compact, hasher::Hasher as _},
    qmdb,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use std::sync::Arc;

/// Encode operations, append them to a compact Merkle batch, merkleize, and compute the
/// post-apply root, all as one CPU-bound job submitted through [`Strategy::spawn`].
///
/// The job hashes against an immutable snapshot of the committed Merkle state, so a parallel
/// strategy hosts the batch's dominant CPU phase on its own pool instead of occupying the
/// calling task. If the caller is cancelled mid-job, the job still runs to completion against
/// its snapshot and the result is discarded.
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
    let mem = merkle.snapshot();
    let strategy = merkle.strategy().clone();
    strategy
        .spawn(move |strategy| {
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
            Ok((merkleized, root))
        })
        .await
}
