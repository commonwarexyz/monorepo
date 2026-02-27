//! Batch mutation API for Keyless QMDBs.
//!
//! Provides a collect-then-resolve pattern for keyless database mutations:
//! 1. `db.new_batch()` creates a `Batch` that borrows `&db`
//! 2. `batch.append(value)` records appends synchronously
//! 3. `batch.merkleize(metadata)` generates operations and merkleizes
//! 4. `merkleized.root()` returns the exact committed root
//! 5. `merkleized.finalize()` produces an owned `FinalizedBatch`
//! 6. `db.apply_batch(finalized)` writes to journal, flushes, and updates state

use super::Keyless;
use crate::{
    journal::authenticated::{self, ItemChain},
    mmr::{
        read::{ChainInfo, MmrRead},
        Location,
    },
    qmdb::{any::VariableValue, keyless::operation::Operation, Error},
};
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use std::sync::Arc;

/// A keyless batch that accumulates appends and can be merkleized.
///
/// Appends are sync -- just Vec pushes, no I/O. All async work happens
/// in `merkleize()`.
///
/// `JP` is the journal parent type: `Journal` for top-level batches,
/// or `authenticated::MerkleizedBatch` for stacked batches.
pub struct Batch<'a, E, V, H, JP>
where
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
    JP: authenticated::Batchable<H, Operation<V>>,
{
    /// Reference to the underlying DB.
    pub(super) keyless: &'a Keyless<E, V, H>,

    /// The journal parent for creating authenticated journal batches.
    pub(super) journal_parent: &'a JP,

    /// Pending appends. Sync inserts only, no I/O.
    pub(super) appends: Vec<V>,

    /// Arc segments of operations accumulated by ancestor MerkleizedBatch chain.
    /// Empty for top-level batches.
    pub(super) parent_operation_chain: Vec<Arc<Vec<Operation<V>>>>,

    /// The virtual base: this batch's i-th operation will land at
    /// location `parent_total_size + i`.
    pub(super) parent_total_size: u64,
}

/// A merkleized batch of keyless operations.
///
/// `root()` returns the exact committed root -- identical to what `db.root()`
/// will return after `apply_batch()`.
pub struct MerkleizedBatch<'a, E, V, H, P>
where
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<V>>,
{
    /// Reference to the parent DB.
    keyless: &'a Keyless<E, V, H>,

    /// The authenticated journal's MerkleizedBatch.
    journal_merkleized: authenticated::MerkleizedBatch<'a, H, P, Operation<V>>,

    /// Arc segments of all operations in the entire chain.
    operation_chain: Vec<Arc<Vec<Operation<V>>>>,

    /// The new last commit location (the Commit operation's location).
    new_last_commit_loc: Location,

    /// The total size after this batch: parent_total_size + num_ops.
    total_size: u64,
}

/// An owned batch ready to be applied. No borrows -- can outlive the Db reference.
pub struct FinalizedBatch<D: Digest, V: VariableValue> {
    /// The finalized authenticated journal batch.
    pub(super) journal_finalized: authenticated::FinalizedBatch<D, Operation<V>>,

    /// The new last commit location.
    pub(super) new_last_commit_loc: Location,
}

// ============================================================
// Batch: sync appends + merkleize
// ============================================================

impl<'a, E, V, H, JP> Batch<'a, E, V, H, JP>
where
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
    JP: authenticated::Batchable<H, Operation<V>>,
{
    /// Append a value. Sync -- just a Vec push, no I/O.
    /// Returns the virtual location where this value will be placed.
    pub fn append(&mut self, value: V) -> Location {
        let loc = Location::new_unchecked(self.parent_total_size + self.appends.len() as u64);
        self.appends.push(value);
        loc
    }

    /// Read a value at `loc`.
    ///
    /// Reads from pending appends, parent chain, or base DB.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error> {
        let loc_val = *loc;
        let parent_ops_len: u64 = self
            .parent_operation_chain
            .iter()
            .map(|s| s.len() as u64)
            .sum();
        let db_journal_size = self.parent_total_size - parent_ops_len;

        // Check this batch's pending appends.
        if loc_val >= self.parent_total_size {
            let idx = (loc_val - self.parent_total_size) as usize;
            return if idx < self.appends.len() {
                Ok(Some(self.appends[idx].clone()))
            } else {
                Ok(None)
            };
        }

        // Check parent operation chain.
        if loc_val >= db_journal_size {
            let op = read_from_chain(loc_val - db_journal_size, &self.parent_operation_chain);
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        self.keyless.get(loc).await
    }

    /// Generate operations and merkleize. Produces Append ops for each pending
    /// value, then a Commit op with optional metadata.
    pub fn merkleize(self, metadata: Option<V>) -> MerkleizedBatch<'a, E, V, H, JP::Parent> {
        let base = self.parent_total_size;

        // Build operations: one Append per value, then Commit.
        let mut ops: Vec<Operation<V>> = Vec::with_capacity(self.appends.len() + 1);
        for value in self.appends {
            ops.push(Operation::Append(value));
        }
        let commit_loc = Location::new_unchecked(base + ops.len() as u64);
        ops.push(Operation::Commit(metadata));

        let total_size = base + ops.len() as u64;

        // Create and merkleize the journal batch.
        let mut journal_batch = self.journal_parent.new_batch();
        for op in &ops {
            journal_batch.add(op.clone());
        }
        let journal_merkleized = journal_batch.merkleize();

        // Build the operation chain: parent segments + this batch's segment.
        let mut operation_chain = self.parent_operation_chain;
        operation_chain.push(Arc::new(ops));

        MerkleizedBatch {
            keyless: self.keyless,
            journal_merkleized,
            operation_chain,
            new_last_commit_loc: commit_loc,
            total_size,
        }
    }
}

// ============================================================
// MerkleizedBatch: root, get, new_batch, finalize
// ============================================================

impl<'a, E, V, H, P> MerkleizedBatch<'a, E, V, H, P>
where
    E: Storage + Clock + Metrics,
    V: VariableValue,
    H: Hasher,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<V>>,
{
    /// Return the speculative root.
    pub fn root(&self) -> H::Digest {
        self.journal_merkleized.root()
    }

    /// Read a value at `loc`.
    ///
    /// Reads from the operation chain or base DB.
    pub async fn get(&self, loc: Location) -> Result<Option<V>, Error> {
        let loc_val = *loc;
        let parent_ops_len: u64 = self.operation_chain.iter().map(|s| s.len() as u64).sum();
        let db_journal_size = self.total_size - parent_ops_len;

        // Check operation chain.
        if loc_val >= db_journal_size {
            let op = read_from_chain(loc_val - db_journal_size, &self.operation_chain);
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        self.keyless.get(loc).await
    }

    /// Create a child batch that sees this batch's state (stacking).
    #[allow(clippy::type_complexity)]
    pub fn new_batch(
        &self,
    ) -> Batch<'_, E, V, H, authenticated::MerkleizedBatch<'a, H, P, Operation<V>>> {
        Batch {
            keyless: self.keyless,
            journal_parent: &self.journal_merkleized,
            appends: Vec::new(),
            parent_operation_chain: self.operation_chain.clone(), // O(D) Arc bumps
            parent_total_size: self.total_size,
        }
    }

    /// Consume this batch, producing an owned `FinalizedBatch`.
    pub fn finalize(self) -> FinalizedBatch<H::Digest, V> {
        FinalizedBatch {
            journal_finalized: self.journal_merkleized.finalize(),
            new_last_commit_loc: self.new_last_commit_loc,
        }
    }
}

// ============================================================
// Helper
// ============================================================

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
