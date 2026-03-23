//! Batch mutation API for Keyless QMDBs.

use super::Keyless;
use crate::{
    journal::authenticated::{self, BatchChain},
    merkle::batch::ChainInfo,
    mmr::{self, Location, Readable},
    qmdb::{any::VariableValue, keyless::operation::Operation, Error},
    Context,
};
use commonware_cryptography::{Digest, Hasher};
use std::sync::Arc;

/// A speculative batch of operations whose root digest has not yet been
/// computed, in contrast to [MerkleizedBatch].
pub struct UnmerkleizedBatch<'a, E, V, H, P>
where
    E: Context,
    V: VariableValue,
    H: Hasher,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<V>>,
{
    /// The committed DB this batch is built on top of.
    pub(super) keyless: &'a Keyless<E, V, H>,

    /// Authenticated journal batch for computing the speculative MMR root.
    pub(super) journal_batch: authenticated::UnmerkleizedBatch<'a, H, P, Operation<V>>,

    /// Pending appends.
    pub(super) appends: Vec<V>,

    /// One Arc segment of operations per prior batch in the chain.
    pub(super) base_operations: Vec<Arc<Vec<Operation<V>>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    pub(super) base_size: u64,

    /// The database size when this batch was created, used to detect stale changesets.
    pub(super) db_size: u64,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [UnmerkleizedBatch].
pub struct MerkleizedBatch<'a, E, V, H, P>
where
    E: Context,
    V: VariableValue,
    H: Hasher,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<V>>,
{
    /// The committed DB this batch is built on top of.
    keyless: &'a Keyless<E, V, H>,

    /// Merkleized authenticated journal batch (provides the speculative MMR root).
    journal_batch: authenticated::MerkleizedBatch<'a, H, P, Operation<V>>,

    /// One Arc segment of operations per batch in the chain (chronological order).
    base_operations: Vec<Arc<Vec<Operation<V>>>>,

    /// Total operation count after this batch.
    total_size: u64,

    /// The database size when this batch was created, used to detect stale changesets.
    db_size: u64,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<D: Digest, V: VariableValue> {
    /// The finalized authenticated journal batch (MMR changeset + item chain).
    pub(super) journal_finalized: authenticated::Changeset<D, Operation<V>>,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the batch was created. Used to detect stale changesets.
    pub(super) db_size: u64,
}

impl<'a, E, V, H, P> UnmerkleizedBatch<'a, E, V, H, P>
where
    E: Context,
    V: VariableValue,
    H: Hasher,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<V>>,
{
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
    pub fn merkleize(self, metadata: Option<V>) -> MerkleizedBatch<'a, E, V, H, P> {
        let base = self.base_size;

        // Build operations: one Append per value, then Commit.
        let mut ops: Vec<Operation<V>> = Vec::with_capacity(self.appends.len() + 1);
        for value in self.appends {
            ops.push(Operation::Append(value));
        }
        ops.push(Operation::Commit(metadata));

        let total_size = base + ops.len() as u64;

        // Merkleize the journal batch (created eagerly at batch construction).
        let mut journal_batch = self.journal_batch;
        for op in &ops {
            journal_batch = journal_batch.add(op.clone());
        }
        let journal_batch = journal_batch.merkleize();

        // Build the operation chain: parent segments + this batch's segment.
        let mut base_operations = self.base_operations;
        base_operations.push(Arc::new(ops));

        MerkleizedBatch {
            keyless: self.keyless,
            journal_batch,
            base_operations,
            total_size,
            db_size: self.db_size,
        }
    }
}

impl<'a, E, V, H, P> MerkleizedBatch<'a, E, V, H, P>
where
    E: Context,
    V: VariableValue,
    H: Hasher,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<V>>,
{
    /// Return the speculative root.
    pub fn root(&self) -> H::Digest {
        self.journal_batch.root()
    }

    /// Read a value at `loc`.
    ///
    /// Reads from the operation chain or base DB.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error> {
        let loc_val = *loc;
        let parent_ops_len: u64 = self.base_operations.iter().map(|s| s.len() as u64).sum();
        let db_journal_size = self.total_size - parent_ops_len;

        // Check operation chain.
        if loc_val >= db_journal_size {
            let op = read_from_chain(loc_val - db_journal_size, &self.base_operations);
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        self.keyless.get(loc).await
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(
        &self,
    ) -> UnmerkleizedBatch<'_, E, V, H, authenticated::MerkleizedBatch<'a, H, P, Operation<V>>>
    {
        UnmerkleizedBatch {
            keyless: self.keyless,
            journal_batch: self.journal_batch.new_batch(),
            appends: Vec::new(),
            base_operations: self.base_operations.clone(),
            base_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Consume this batch, producing an owned `Changeset`.
    pub fn finalize(self) -> Changeset<H::Digest, V> {
        Changeset {
            journal_finalized: self.journal_batch.finalize(),
            total_size: self.total_size,
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
