//! Batch mutation API for Keyless QMDBs.

use super::Keyless;
use crate::{
    journal::authenticated,
    mmr::{Location, Position},
    qmdb::{any::VariableValue, keyless::operation::Operation, Error},
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use std::sync::Arc;

/// A speculative batch whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Borrows `&Keyless` for reads during the build phase. Consuming
/// [`UnmerkleizedBatch::merkleize`] produces an owned [`MerkleizedBatch`]
/// and releases the borrow.
pub struct UnmerkleizedBatch<'a, E, V, H>
where
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
{
    /// The committed DB this batch reads from.
    keyless: &'a Keyless<E, V, H>,

    /// Journal batch for computing the speculative MMR root.
    journal_builder: authenticated::UnmerkleizedBatch<H, Operation<V>>,

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

/// A speculative batch whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
pub struct MerkleizedBatch<D: Digest, V: VariableValue> {
    /// Journal batch (MMR state + accumulated operation segments).
    pub(crate) journal: authenticated::MerkleizedBatch<D, Operation<V>>,

    /// Total operation count after this batch.
    pub(crate) total_size: u64,

    /// The database size when the initial batch was created.
    pub(crate) db_size: u64,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<D: Digest, V: VariableValue> {
    /// The finalized authenticated journal batch (MMR changeset + item chain).
    pub(super) journal_finalized: crate::journal::authenticated::Changeset<D, Operation<V>>,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the batch was created. Used to detect stale changesets.
    pub(super) db_size: u64,
}

impl<'a, E, V, H> UnmerkleizedBatch<'a, E, V, H>
where
    E: Storage + Clock + Metrics,
    V: VariableValue + Encode,
    H: Hasher,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new(keyless: &'a Keyless<E, V, H>, journal_size: u64) -> Self {
        Self {
            keyless,
            journal_builder: keyless.journal.to_snapshot().new_batch::<H>(),
            appends: Vec::new(),
            base_operations: Vec::new(),
            base_size: journal_size,
            db_size: journal_size,
        }
    }

    /// Append a value.
    /// Returns the uncommitted location where this value will be placed.
    pub fn append(&mut self, value: V) -> Location {
        let loc = Location::new(self.base_size + self.appends.len() as u64);
        self.appends.push(value);
        loc
    }

    /// Read a value at `loc`.
    ///
    /// Reads from pending appends, parent chain, or base DB.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error> {
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
        self.keyless.get(loc).await
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
        let mut journal_builder = self.journal_builder;
        for op in &ops {
            journal_builder.add(op.clone());
        }
        let journal = journal_builder.merkleize();

        MerkleizedBatch {
            journal,
            total_size,
            db_size: self.db_size,
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

impl<D: Digest, V: VariableValue> MerkleizedBatch<D, V> {
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal.root()
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<'a, E, H>(&'a self, db: &'a Keyless<E, V, H>) -> UnmerkleizedBatch<'a, E, V, H>
    where
        E: Storage + Clock + Metrics,
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            keyless: db,
            journal_builder: self.journal.new_batch::<H>(),
            appends: Vec::new(),
            base_operations: self.journal.items_chain.clone(),
            base_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Read a value at `loc`.
    pub async fn get<E, H>(&self, loc: Location, db: &Keyless<E, V, H>) -> Result<Option<V>, Error>
    where
        E: Storage + Clock + Metrics,
        H: Hasher<Digest = D>,
    {
        let loc_val = *loc;
        let parent_ops_len: u64 = self
            .journal
            .items_chain
            .iter()
            .map(|s| s.len() as u64)
            .sum();
        let db_journal_size = self.total_size - parent_ops_len;

        // Check operation chain.
        if loc_val >= db_journal_size {
            let op = read_from_chain(loc_val - db_journal_size, &self.journal.items_chain);
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<D, V> {
        Changeset {
            journal_finalized: self.journal.into_finalize(),
            total_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Produce a [`Changeset`] relative to the current committed DB size.
    pub fn finalize_from(self, current_db_size: u64) -> Changeset<D, V> {
        let mmr_base =
            Position::try_from(Location::new(current_db_size)).expect("valid leaf count");
        assert!(
            current_db_size >= self.db_size,
            "current_db_size ({current_db_size}) < batch db_size ({})",
            self.db_size
        );
        let items_to_skip = current_db_size - self.db_size;
        Changeset {
            journal_finalized: self.journal.into_finalize_from(mmr_base, items_to_skip),
            total_size: self.total_size,
            db_size: current_db_size,
        }
    }
}

// Conversion: Keyless::to_snapshot
impl<E, V, H> Keyless<E, V, H>
where
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_snapshot(&self) -> MerkleizedBatch<H::Digest, V> {
        let journal_size = *self.last_commit_loc + 1;
        MerkleizedBatch {
            journal: self.journal.to_snapshot(),
            total_size: journal_size,
            db_size: journal_size,
        }
    }
}
