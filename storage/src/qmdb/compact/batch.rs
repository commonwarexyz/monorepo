//! Shared helpers for compact QMDB batches.

use crate::{
    merkle::{batch, compact, hasher::Standard as StandardHasher, Family},
    Context,
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
    let hasher = StandardHasher::<H>::new();
    for op in ops {
        batch = batch.add(&hasher, &op.encode());
    }
    merkle.with_mem(|mem| batch.merkleize(mem, &hasher))
}
