//! Shared helpers for compact QMDB batches.

use crate::{
    merkle::{batch, compact, hasher::Hasher as _, Family},
    qmdb, Context,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use std::sync::Arc;

/// Encode operations, append them to a compact Merkle batch, and compute its root.
pub(crate) fn merkleize_ops<F, E, H, S, Op>(
    merkle: &compact::Merkle<F, E, H::Digest, S>,
    mut batch: compact::UnmerkleizedBatch<F, H::Digest, S>,
    ops: &[Op],
) -> Arc<batch::MerkleizedBatch<F, H::Digest, S>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    Op: EncodeShared,
{
    // Compute the leaf digests in parallel.
    let first_leaf = batch.leaves();
    let leaf_digests = merkle.strategy().map_init_collect_vec(
        ops.iter().enumerate(),
        qmdb::hasher::<H>,
        |hasher, (i, op)| {
            let offset = u64::try_from(i).expect("operation offset exceeds u64");
            let pos = F::location_to_position(first_leaf + offset);
            hasher.leaf_digest(pos, &op.encode())
        },
    );

    // Add the leaf digests to the batch.
    batch = batch.add_leaf_digests(leaf_digests);

    // Merkleize the batch.
    merkle.with_mem(|mem| batch.merkleize(mem, &qmdb::hasher::<H>()))
}
