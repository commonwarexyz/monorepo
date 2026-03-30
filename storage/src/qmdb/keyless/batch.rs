//! Batch mutation API for Keyless QMDBs.

use super::Keyless;
use crate::{
    journal::authenticated,
    merkle::mmr::{self, Location, Position},
    qmdb::{any::VariableValue, keyless::operation::Operation},
    Context,
};
use commonware_cryptography::{Digest, Hasher};
use std::sync::Arc;

type Error = crate::qmdb::Error<mmr::Family>;

/// A speculative batch of operations whose root digest has not yet been computed, in contrast
/// to [`MerkleizedBatch`].
///
/// Consuming [`UnmerkleizedBatch::merkleize`] produces an owned [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<H, V>
where
    V: VariableValue,
    H: Hasher,
{
    /// Authenticated journal batch for computing the speculative MMR root.
    journal_batch: authenticated::UnmerkleizedBatch<mmr::Family, H, Operation<V>>,

    /// Pending appends.
    appends: Vec<V>,

    /// One Arc segment of operations per prior batch in the chain.
    base_operations: Vec<Arc<Vec<Operation<V>>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// The database size when this batch was created, used to detect stale changesets.
    db_size: u64,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
pub struct MerkleizedBatch<D: Digest, V: VariableValue> {
    /// Journal batch (MMR state + accumulated operation segments).
    journal_batch: authenticated::MerkleizedBatch<mmr::Family, D, Operation<V>>,

    /// Total operation count after this batch.
    total_size: u64,

    /// The database size when the initial batch was created.
    db_size: u64,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<D: Digest, V: VariableValue> {
    /// The finalized authenticated journal batch (MMR changeset + item chain).
    pub(super) journal_finalized: authenticated::Changeset<mmr::Family, D, Operation<V>>,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the batch was created. Used to detect stale changesets.
    pub(super) db_size: u64,
}

impl<H, V> UnmerkleizedBatch<H, V>
where
    V: VariableValue,
    H: Hasher,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E>(keyless: &Keyless<E, V, H>, journal_size: u64) -> Self
    where
        E: Context,
    {
        Self {
            journal_batch: keyless.journal.to_merkleized_batch().new_batch::<H>(),
            appends: Vec::new(),
            base_operations: Vec::new(),
            base_size: journal_size,
            db_size: journal_size,
        }
    }

    /// The location that the next appended value will be placed at.
    pub const fn size(&self) -> Location {
        Location::new(self.base_size + self.appends.len() as u64)
    }

    /// Append a value.
    pub fn append(mut self, value: V) -> Self {
        self.appends.push(value);
        self
    }

    /// Read a value at `loc`.
    ///
    /// Reads from pending appends, parent chain, or base DB.
    pub async fn get<E>(&self, loc: Location, db: &Keyless<E, V, H>) -> Result<Option<V>, Error>
    where
        E: Context,
    {
        let loc_val = *loc;
        let parent_ops_len: u64 = self.base_operations.iter().map(|s| s.len() as u64).sum();
        let db_journal_size = self.base_size - parent_ops_len;

        // Check this batch's pending appends.
        if loc_val >= self.base_size {
            let idx = (loc_val - self.base_size) as usize;
            return if idx < self.appends.len() {
                Ok(Some(self.appends[idx].clone()))
            } else {
                Ok(None)
            };
        }

        // Check parent operation chain.
        if loc_val >= db_journal_size {
            let op = read_from_chain(loc_val - db_journal_size, &self.base_operations);
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Resolve appends into operations, merkleize, and return a [`MerkleizedBatch`].
    pub fn merkleize(self, metadata: Option<V>) -> MerkleizedBatch<H::Digest, V> {
        let base = self.base_size;

        // Build operations: one Append per value, then Commit.
        let mut ops: Vec<Operation<V>> = Vec::with_capacity(self.appends.len() + 1);
        for value in self.appends {
            ops.push(Operation::Append(value));
        }
        ops.push(Operation::Commit(metadata));

        let total_size = base + ops.len() as u64;

        // Add operations to the journal batch and merkleize.
        let mut journal_batch = self.journal_batch;
        for op in &ops {
            journal_batch = journal_batch.add(op.clone());
        }
        let journal = journal_batch.merkleize();

        MerkleizedBatch {
            journal_batch: journal,
            total_size,
            db_size: self.db_size,
        }
    }
}

impl<D: Digest, V: VariableValue> MerkleizedBatch<D, V> {
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal_batch.root()
    }

    /// Read a value at `loc`.
    pub async fn get<E, H>(&self, loc: Location, db: &Keyless<E, V, H>) -> Result<Option<V>, Error>
    where
        E: Context,
        H: Hasher<Digest = D>,
    {
        let loc_val = *loc;
        let parent_ops_len: u64 = self
            .journal_batch
            .items
            .iter()
            .map(|s| s.len() as u64)
            .sum();
        let db_journal_size = self.total_size - parent_ops_len;

        // Check operation chain.
        if loc_val >= db_journal_size {
            let op = read_from_chain(loc_val - db_journal_size, &self.journal_batch.items);
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H>(&self) -> UnmerkleizedBatch<H, V>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            appends: Vec::new(),
            base_operations: self.journal_batch.items.clone(),
            base_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<D, V> {
        Changeset {
            journal_finalized: self.journal_batch.finalize(),
            total_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Like [`Self::finalize`], but produces a [`Changeset`] relative to `current_db_size`
    /// instead of the original DB size when this batch chain was created.
    ///
    /// Use this when an ancestor batch in the chain has already been committed, advancing
    /// the DB past the original fork point.
    ///
    /// # Panics
    ///
    /// Panics if `current_db_size` is less than the DB size when this batch was created.
    pub fn finalize_from(self, current_db_size: u64) -> Changeset<D, V> {
        assert!(
            current_db_size >= self.db_size,
            "current_db_size ({current_db_size}) < batch db_size ({})",
            self.db_size
        );
        let items_to_skip = current_db_size - self.db_size;
        let mmr_base =
            Position::try_from(Location::new(current_db_size)).expect("valid leaf count");
        Changeset {
            journal_finalized: self.journal_batch.finalize_from(mmr_base, items_to_skip),
            total_size: self.total_size,
            db_size: current_db_size,
        }
    }
}

impl<E, V, H> Keyless<E, V, H>
where
    E: Context,
    V: VariableValue,
    H: Hasher,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> MerkleizedBatch<H::Digest, V> {
        let journal_size = *self.last_commit_loc + 1;
        MerkleizedBatch {
            journal_batch: self.journal.to_merkleized_batch(),
            total_size: journal_size,
            db_size: journal_size,
        }
    }
}

/// Read an operation from the in-memory chain at the given offset.
fn read_from_chain<V: VariableValue>(
    offset: u64,
    chain: &[Arc<Vec<Operation<V>>>],
) -> Operation<V> {
    let mut remaining = offset as usize;
    for segment in chain {
        if remaining < segment.len() {
            return segment[remaining].clone();
        }
        remaining -= segment.len();
    }
    unreachable!("offset within chain range but not found in segments");
}
