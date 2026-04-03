//! Batch mutation API for Keyless QMDBs.

use super::{operation::Operation, Keyless};
use crate::{
    journal::{authenticated, contiguous::Mutable, Error as JournalError},
    merkle::{Family, Location, Position},
    qmdb::{any::value::ValueEncoding, Error},
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher};
use std::sync::Arc;

/// A speculative batch of operations whose root digest has not yet been computed, in contrast
/// to [`MerkleizedBatch`].
///
/// Consuming [`UnmerkleizedBatch::merkleize`] produces an owned [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<F, H, V>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<V>>,

    /// Pending appends.
    appends: Vec<V::Value>,

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
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding>
where
    Operation<V>: EncodeShared,
{
    /// Journal batch (Merkle state + accumulated operation segments).
    pub(super) journal_batch: authenticated::MerkleizedBatch<F, D, Operation<V>>,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the initial batch was created.
    pub(super) db_size: u64,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<F: Family, D: Digest, V: ValueEncoding> {
    /// The finalized authenticated journal batch (Merkle changeset + item chain).
    pub(super) journal_finalized: authenticated::Changeset<F, D, Operation<V>>,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the batch was created. Used to detect stale changesets.
    pub(super) db_size: u64,
}

impl<F, H, V> UnmerkleizedBatch<F, H, V>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C>(keyless: &Keyless<F, E, V, C, H>, journal_size: u64) -> Self
    where
        E: Context,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
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
    pub const fn size(&self) -> Location<F> {
        Location::new(self.base_size + self.appends.len() as u64)
    }

    /// Append a value.
    pub fn append(mut self, value: V::Value) -> Self {
        self.appends.push(value);
        self
    }

    /// Read a value at `loc`.
    ///
    /// Reads from pending appends, parent chain, or base DB.
    pub async fn get<E, C>(
        &self,
        loc: Location<F>,
        db: &Keyless<F, E, V, C, H>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
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
    pub fn merkleize(self, metadata: Option<V::Value>) -> MerkleizedBatch<F, H::Digest, V> {
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

impl<F: Family, D: Digest, V: ValueEncoding> MerkleizedBatch<F, D, V>
where
    Operation<V>: EncodeShared,
{
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal_batch.root()
    }

    /// Read a value at `loc`.
    pub async fn get<E, H, C>(
        &self,
        loc: Location<F>,
        db: &Keyless<F, E, V, C, H>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
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
    pub fn new_batch<H>(&self) -> UnmerkleizedBatch<F, H, V>
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
    pub fn finalize(self) -> Changeset<F, D, V> {
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
    pub fn finalize_from(self, current_db_size: u64) -> Changeset<F, D, V> {
        assert!(
            current_db_size >= self.db_size,
            "current_db_size ({current_db_size}) < batch db_size ({})",
            self.db_size
        );
        let items_to_skip = current_db_size - self.db_size;
        let merkle_base =
            Position::try_from(Location::<F>::new(current_db_size)).expect("valid leaf count");
        Changeset {
            journal_finalized: self.journal_batch.finalize_from(merkle_base, items_to_skip),
            total_size: self.total_size,
            db_size: current_db_size,
        }
    }
}

/// Read an operation from the in-memory chain at the given offset.
fn read_from_chain<V: ValueEncoding>(
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
