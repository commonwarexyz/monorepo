//! Shared append-batch machinery for QMDb variants.

use crate::{
    merkle::{self, batch, hasher::Hasher as MerkleHasher, Family, Location, Position},
    qmdb::Error,
};
use commonware_codec::Encode;
use commonware_cryptography::Digest;
use core::ops::Range;
use std::sync::Arc;

/// Root state for an unmerkleized batch.
pub(crate) enum BatchBase<F: Family, D: Digest, W> {
    /// The batch is rooted directly in the committed database.
    Db {
        db_size: u64,
        merkle_parent: Arc<batch::MerkleizedBatch<F, D>>,
    },
    /// The batch is rooted in a speculative parent batch.
    Child(Arc<W>),
}

/// Resolved root state for a batch before new leaves are appended.
pub(crate) struct ResolvedBase<F: Family, D: Digest, W> {
    pub(crate) base_size: u64,
    pub(crate) db_size: u64,
    pub(crate) merkle_parent: Arc<batch::MerkleizedBatch<F, D>>,
    pub(crate) ancestors: Vec<Arc<W>>,
}

/// Shared chain metadata and validation state.
pub(crate) struct ChainMeta<F: Family> {
    pub(crate) base_size: u64,
    pub(crate) db_size: u64,
    pub(crate) total_size: u64,
    pub(crate) new_floor: Location<F>,
}

/// Wrapper access to a shared append core.
pub(crate) trait HasCore<F: Family, D: Digest> {
    fn core(&self) -> &AppendBatchCore<F, D>;
}

/// Wrapper access to a speculative ancestor chain.
pub(crate) trait HasAncestors<F: Family, D: Digest>: HasCore<F, D> + Sized {
    fn ancestors(&self) -> &[Arc<Self>];

    /// Build a newest-to-oldest ancestor chain rooted at `parent`, including `parent` itself.
    /// Returns an empty `Vec` when `parent` is `None`.
    fn ancestor_chain(parent: Option<&Arc<Self>>) -> Vec<Arc<Self>> {
        let Some(parent) = parent else {
            return Vec::new();
        };
        let mut ancestors = Vec::with_capacity(parent.ancestors().len() + 1);
        ancestors.push(Arc::clone(parent));
        ancestors.extend(parent.ancestors().iter().cloned());
        ancestors
    }
}

impl<F, D, W> BatchBase<F, D, W>
where
    F: Family,
    D: Digest,
    W: HasAncestors<F, D>,
{
    /// Resolve this base into merkle parent state and newest-to-oldest ancestors.
    pub(crate) fn resolve(self) -> ResolvedBase<F, D, W> {
        match self {
            Self::Db {
                db_size,
                merkle_parent,
            } => ResolvedBase {
                base_size: db_size,
                db_size,
                merkle_parent,
                ancestors: Vec::new(),
            },
            Self::Child(parent) => ResolvedBase {
                base_size: parent.core().chain.total_size,
                db_size: parent.core().chain.db_size,
                merkle_parent: Arc::clone(&parent.core().merkle),
                ancestors: W::ancestor_chain(Some(&parent)),
            },
        }
    }
}

impl<F: Family> ChainMeta<F> {
    /// Build metadata for a quiescent committed state with no speculative appends.
    pub(crate) const fn quiescent(size: u64, new_floor: Location<F>) -> Self {
        Self {
            base_size: size,
            db_size: size,
            total_size: size,
            new_floor,
        }
    }

    /// Build metadata for a batch with `item_count` data leaves followed by one commit leaf.
    pub(crate) const fn from_item_count(
        base_size: u64,
        db_size: u64,
        item_count: usize,
        new_floor: Location<F>,
    ) -> Self {
        Self {
            base_size,
            db_size,
            total_size: base_size + item_count as u64 + 1,
            new_floor,
        }
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
        if self.new_floor < prev_floor {
            return Err(Error::FloorRegressed(self.new_floor, prev_floor));
        }
        if self.new_floor > commit_loc {
            return Err(Error::FloorBeyondSize(self.new_floor, commit_loc));
        }
        Ok(())
    }
}

/// Sidecar-free merkleized append value shared by compact and full variants.
pub(crate) struct AppendBatchCore<F: Family, D: Digest> {
    pub(crate) merkle: Arc<batch::MerkleizedBatch<F, D>>,
    pub(crate) chain: ChainMeta<F>,
}

impl<F: Family, D: Digest> AppendBatchCore<F, D> {
    /// Build a core by merkleizing pre-computed leaf digests.
    fn from_leaf_digests(
        parent: Arc<batch::MerkleizedBatch<F, D>>,
        mem: &merkle::mem::Mem<F, D>,
        hasher: &impl MerkleHasher<F, Digest = D>,
        leaves: &[D],
        chain: ChainMeta<F>,
    ) -> Self {
        let mut batch = parent.new_batch();
        for digest in leaves {
            batch = batch.add_leaf_digest(*digest);
        }
        Self {
            merkle: batch.merkleize(mem, hasher),
            chain,
        }
    }

    /// Build a core by hashing encoded operations at consecutive locations.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_encoded_ops<H, Op>(
        parent: Arc<batch::MerkleizedBatch<F, D>>,
        mem: &merkle::mem::Mem<F, D>,
        hasher: &H,
        base_size: u64,
        db_size: u64,
        new_floor: Location<F>,
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

        let chain = ChainMeta::from_item_count(base_size, db_size, leaves.len() - 1, new_floor);
        Self::from_leaf_digests(parent, mem, hasher, &leaves, chain)
    }

    /// Return the location of the commit operation ending this batch.
    pub(crate) fn commit_loc(&self) -> Location<F> {
        self.chain.commit_loc()
    }

    /// Return the inactivity floor declared by this batch's commit operation.
    pub(crate) const fn commit_floor(&self) -> Location<F> {
        self.chain.new_floor
    }

    /// Return the speculative root.
    pub(crate) fn root(&self) -> D {
        self.merkle.root()
    }

    /// Validate whether this batch can be applied on top of the current database state.
    pub(crate) fn validate_apply<W>(
        &self,
        starting_floor: Location<F>,
        current_db_size: u64,
        ancestors: &[Arc<W>],
    ) -> Result<(), Error<F>>
    where
        W: HasCore<F, D>,
    {
        self.chain.validate_stale(
            current_db_size,
            ancestors
                .iter()
                .map(|ancestor| ancestor.core().chain.total_size),
        )?;
        self.chain.validate_floors(
            starting_floor,
            current_db_size,
            ancestors.iter().map(|ancestor| {
                (
                    ancestor.core().chain.total_size,
                    ancestor.core().commit_floor(),
                )
            }),
        )
    }

    /// Advance committed chain state after the backing Merkle or journal applies this batch.
    pub(crate) fn commit_to(
        &self,
        last_commit_loc: &mut Location<F>,
        inactivity_floor_loc: &mut Location<F>,
    ) -> Range<Location<F>> {
        let start_loc = *last_commit_loc + 1;
        *last_commit_loc = self.commit_loc();
        *inactivity_floor_loc = self.commit_floor();
        start_loc..Location::new(self.chain.total_size)
    }
}
