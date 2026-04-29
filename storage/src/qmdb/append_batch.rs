//! Shared append-batch algebra for QMDB variants.

use crate::{
    merkle::{self, batch, hasher::Hasher as MerkleHasher, Family, Location, Position},
    qmdb::Error,
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use std::sync::Arc;

/// Log bounds covered by a merkleized batch and the floor declared by its commit.
#[derive(Clone, Copy)]
pub(crate) struct BatchBounds<F: Family> {
    /// Leaf count this batch starts at; equals `db_size` when the batch has no ancestors.
    base_size: u64,
    /// Committed leaf count when the batch chain was forked. Used for stale-batch detection.
    db_size: u64,
    /// Leaf count after this batch (data ops + the commit leaf) is applied.
    total_size: u64,
    /// Inactivity floor declared by this batch's commit operation.
    commit_floor: Location<F>,
}

/// View of a merkleized append batch used by shared validation and child-batch creation.
pub(crate) trait AppendBatchView<F: Family, D: Digest> {
    /// Speculative Merkle batch built from this chain's leaves.
    fn merkle(&self) -> &Arc<batch::MerkleizedBatch<F, D>>;

    /// Log bounds plus the floor declared by this batch's commit.
    fn bounds(&self) -> &BatchBounds<F>;

    /// Return the speculative root.
    fn root(&self) -> D {
        self.merkle().root()
    }
}

impl<F: Family> BatchBounds<F> {
    /// Build metadata for a committed state with no speculative appends. Used by `to_batch` to
    /// represent the database tip as an empty batch; all three positions collapse to `size`.
    pub(crate) const fn committed(size: u64, commit_floor: Location<F>) -> Self {
        Self {
            base_size: size,
            db_size: size,
            total_size: size,
            commit_floor,
        }
    }

    /// Build metadata for a batch of `item_count` data ops plus one trailing commit leaf.
    /// `total_size` becomes `base_size + item_count + 1`.
    pub(crate) const fn from_item_count(
        base_size: u64,
        db_size: u64,
        item_count: usize,
        commit_floor: Location<F>,
    ) -> Self {
        Self {
            base_size,
            db_size,
            total_size: base_size + item_count as u64 + 1,
            commit_floor,
        }
    }

    /// Return the committed leaf count when this batch chain forked.
    pub(crate) const fn db_size(&self) -> u64 {
        self.db_size
    }

    /// Return the leaf count after this batch is applied.
    pub(crate) const fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Return the inactivity floor declared by this batch's commit operation.
    pub(crate) const fn commit_floor(&self) -> Location<F> {
        self.commit_floor
    }

    /// Return whether this batch has not yet been reflected in a database of `current_db_size`.
    pub(crate) const fn is_unapplied(&self, current_db_size: u64) -> bool {
        self.total_size > current_db_size
    }

    /// Return the location of the commit operation ending this chain.
    pub(crate) fn commit_loc(&self) -> Location<F> {
        debug_assert!(self.total_size > 0);
        Location::new(self.total_size - 1)
    }

    /// Validate that the current database size can reach this batch.
    ///
    /// This is intentionally size-based, matching the underlying Merkle batch layer. Callers must
    /// still treat equal-size orphaned branches as invalid.
    pub(crate) fn validate_stale(
        &self,
        current_db_size: u64,
        ancestor_ends: impl IntoIterator<Item = u64>,
    ) -> Result<(), Error<F>> {
        if current_db_size == self.db_size || current_db_size == self.base_size {
            return Ok(());
        }
        if ancestor_ends.into_iter().any(|end| end == current_db_size) {
            return Ok(());
        }
        Err(Error::StaleBatch {
            db_size: current_db_size,
            batch_db_size: self.db_size,
            batch_base_size: self.base_size,
        })
    }

    /// Validate floor monotonicity for unapplied ancestors and this batch.
    pub(crate) fn validate_floors<I>(
        &self,
        starting_floor: Location<F>,
        current_db_size: u64,
        ancestors: I,
    ) -> Result<(), Error<F>>
    where
        I: IntoIterator<Item = (u64, Location<F>)>,
        I::IntoIter: DoubleEndedIterator,
    {
        let mut prev_floor = starting_floor;
        for (ancestor_end, ancestor_floor) in ancestors.into_iter().rev() {
            if ancestor_end <= current_db_size {
                continue;
            }
            let ancestor_commit_loc = Location::new(ancestor_end - 1);
            if ancestor_floor < prev_floor {
                return Err(Error::FloorRegressed(ancestor_floor, prev_floor));
            }
            if ancestor_floor > ancestor_commit_loc {
                return Err(Error::FloorBeyondSize(ancestor_floor, ancestor_commit_loc));
            }
            prev_floor = ancestor_floor;
        }

        let commit_loc = self.commit_loc();
        if self.commit_floor < prev_floor {
            return Err(Error::FloorRegressed(self.commit_floor, prev_floor));
        }
        if self.commit_floor > commit_loc {
            return Err(Error::FloorBeyondSize(self.commit_floor, commit_loc));
        }
        Ok(())
    }
}

/// Concrete append-batch view for compact variants.
///
/// Full variants derive their Merkle view from the authenticated journal batch. Compact variants
/// do not carry a journal batch, so they store this Merkle state and bounds directly.
pub(crate) struct CompactBatch<F: Family, D: Digest> {
    /// Speculative Merkle batch built from this chain's leaves.
    pub(crate) merkle: Arc<batch::MerkleizedBatch<F, D>>,
    /// Log bounds plus the floor declared by this batch's commit.
    pub(crate) bounds: BatchBounds<F>,
}

impl<F: Family, D: Digest> AppendBatchView<F, D> for CompactBatch<F, D> {
    fn merkle(&self) -> &Arc<batch::MerkleizedBatch<F, D>> {
        &self.merkle
    }

    fn bounds(&self) -> &BatchBounds<F> {
        &self.bounds
    }
}

impl<F: Family, D: Digest> CompactBatch<F, D> {
    /// Build a compact batch by merkleizing pre-computed leaf digests.
    fn from_leaf_digests(
        parent: Arc<batch::MerkleizedBatch<F, D>>,
        mem: &merkle::mem::Mem<F, D>,
        hasher: &impl MerkleHasher<F, Digest = D>,
        leaves: &[D],
        bounds: BatchBounds<F>,
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
        parent: Arc<batch::MerkleizedBatch<F, D>>,
        mem: &merkle::mem::Mem<F, D>,
        hasher: &H,
        base_size: u64,
        db_size: u64,
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

        let range =
            BatchBounds::from_item_count(base_size, db_size, leaves.len() - 1, commit_floor);
        Self::from_leaf_digests(parent, mem, hasher, &leaves, range)
    }

    /// Return the speculative root.
    pub(crate) fn root(&self) -> D {
        self.merkle.root()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::mmr;

    type F = mmr::Family;

    #[test]
    fn batch_range_validates_stale_sizes() {
        let range = BatchBounds::<F>::from_item_count(10, 10, 2, Location::new(12));

        assert!(range.validate_stale(10, []).is_ok());
        assert!(range.validate_stale(12, [12]).is_ok());

        let err = range.validate_stale(11, []).unwrap_err();
        assert!(matches!(
            err,
            Error::StaleBatch {
                db_size: 11,
                batch_db_size: 10,
                batch_base_size: 10,
            }
        ));
    }

    #[test]
    fn batch_range_validates_floor_monotonicity() {
        let range = BatchBounds::<F>::from_item_count(10, 10, 2, Location::new(8));

        assert!(range
            .validate_floors(Location::new(5), 10, [(12, Location::new(7))])
            .is_ok());

        let err = range
            .validate_floors(Location::new(5), 10, [(12, Location::new(4))])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::FloorRegressed(floor, previous)
                if floor == Location::new(4) && previous == Location::new(5)
        ));
    }

    #[test]
    fn batch_range_rejects_floor_beyond_commit() {
        let range = BatchBounds::<F>::from_item_count(10, 10, 2, Location::new(13));

        let err = range.validate_floors(Location::new(5), 10, []).unwrap_err();
        assert!(matches!(
            err,
            Error::FloorBeyondSize(floor, commit)
                if floor == Location::new(13) && commit == Location::new(12)
        ));
    }
}
