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
    batch: compact::UnmerkleizedBatch<F, H::Digest, S>,
    ops: &[Op],
) -> Arc<batch::MerkleizedBatch<F, H::Digest, S>>
where
    F: Family,
    E: Context,
    H: Hasher,
    S: Strategy,
    Op: EncodeShared,
{
    // Hash each operation's leaf digest in parallel, then merkleize.
    let hasher = qmdb::hasher::<H>();
    merkle.with_mem(|mem| {
        batch.merkleize_leaves(mem, &hasher, ops, Vec::new, |buf, op, pos| {
            buf.clear();
            op.write(buf);
            hasher.leaf_digest(pos, buf.as_slice())
        })
    })
}
