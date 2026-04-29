//! Compact batch artifact shared by compact QMDB variants.

use crate::{
    merkle::{
        self, batch as merkle_batch, hasher::Hasher as MerkleHasher, Family, Location, Position,
    },
    qmdb::batch::Bounds,
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use std::sync::Arc;

/// Merkle state and bounds for a compact merkleized batch.
///
/// Full variants keep this state inside their authenticated journal batch. Compact variants do not
/// retain a journal batch, so they carry only the compact Merkle batch plus the shared validation
/// bounds.
pub(crate) struct Batch<F: Family, D: Digest> {
    /// Speculative Merkle batch built from this chain's leaves.
    pub(crate) merkle: Arc<merkle_batch::MerkleizedBatch<F, D>>,
    /// Log bounds plus the floor declared by this batch's commit.
    pub(crate) bounds: Bounds<F>,
}

impl<F: Family, D: Digest> Batch<F, D> {
    /// Build a compact batch by merkleizing pre-computed leaf digests.
    fn from_leaf_digests(
        parent: Arc<merkle_batch::MerkleizedBatch<F, D>>,
        mem: &merkle::mem::Mem<F, D>,
        hasher: &impl MerkleHasher<F, Digest = D>,
        leaves: &[D],
        bounds: Bounds<F>,
    ) -> Self {
        let mut batch = parent.new_batch();
        for digest in leaves {
            batch = batch.add_leaf_digest(*digest);
        }
        Self {
            merkle: batch.merkleize(mem, hasher),
            bounds,
        }
    }

    /// Build a compact batch by hashing encoded operations at consecutive locations.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_encoded_ops<H, Op>(
        parent: Arc<merkle_batch::MerkleizedBatch<F, D>>,
        mem: &merkle::mem::Mem<F, D>,
        hasher: &H,
        base_size: u64,
        committed_size: u64,
        commit_floor: Location<F>,
        data_ops: impl ExactSizeIterator<Item = Op>,
        commit_op: Op,
    ) -> Self
    where
        H: MerkleHasher<F, Digest = D>,
        Op: Encode,
    {
        let mut leaves = Vec::with_capacity(data_ops.len() + 1);
        for (i, op) in data_ops.enumerate() {
            let loc = Location::<F>::new(base_size + i as u64);
            let pos = Position::try_from(loc).expect("valid leaf location");
            leaves.push(hasher.leaf_digest(pos, &op.encode()));
        }
        let commit_loc = Location::<F>::new(base_size + leaves.len() as u64);
        let pos = Position::try_from(commit_loc).expect("valid leaf location");
        leaves.push(hasher.leaf_digest(pos, &commit_op.encode()));

        let bounds =
            Bounds::from_item_count(base_size, committed_size, leaves.len() - 1, commit_floor);
        Self::from_leaf_digests(parent, mem, hasher, &leaves, bounds)
    }

    /// Return the speculative root.
    pub(crate) fn root(&self) -> D {
        self.merkle.root()
    }
}
