//! Shared helpers for compact QMDB batches.

use crate::{
    merkle::{batch, compact, hasher::Hasher as _, Family},
    qmdb,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use std::sync::Arc;

/// Encode operations, append them to a compact Merkle batch, and compute its root.
pub(crate) fn merkleize_ops<F, H, S, Op>(
    merkle: &compact::Merkle<F, H::Digest, S>,
    batch: compact::UnmerkleizedBatch<F, H::Digest, S>,
    ops: &[Op],
) -> Arc<batch::MerkleizedBatch<F, H::Digest, S>>
where
    F: Family,
    H: Hasher,
    S: Strategy,
    Op: EncodeShared,
{
    let mut hasher = qmdb::hasher::<H>();
    let first_leaf = batch.leaves();

    // Hash before `with_mem` borrows committed Merkle state under its read lock.
    let leaf_digests = merkle.strategy().map_init_collect_vec(
        ops.iter().enumerate(),
        qmdb::hasher::<H>,
        |hasher, (i, op)| {
            let offset = u64::try_from(i).expect("operation offset exceeds u64");
            let pos = F::location_to_position(first_leaf + offset);
            hasher.leaf_digest_ref(pos, op)
        },
    );

    let batch = batch.add_leaf_digests(leaf_digests);
    merkle.with_mem(|mem| batch.merkleize(mem, &mut hasher))
}
