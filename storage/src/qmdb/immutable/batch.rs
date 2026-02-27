//! Batch mutation API for Immutable QMDBs.
//!
//! Provides a collect-then-resolve pattern for immutable database mutations:
//! 1. `db.new_batch()` creates a `Batch` that borrows `&db`
//! 2. `batch.set(key, value)` records sets synchronously
//! 3. `batch.merkleize(metadata)` generates operations and merkleizes
//! 4. `merkleized.root()` returns the exact committed root
//! 5. `merkleized.finalize()` produces an owned `FinalizedBatch`
//! 6. `db.apply_batch(finalized)` writes to journal, flushes, and updates state

use super::Immutable;
use crate::{
    journal::authenticated::{self, ItemChain},
    mmr::{
        read::{ChainInfo, MmrRead},
        Location,
    },
    qmdb::{any::VariableValue, immutable::operation::Operation, Error},
    translator::Translator,
};
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use std::{collections::BTreeMap, sync::Arc};

/// What happened to a key in this batch.
#[derive(Clone)]
pub(crate) struct OverlayEntry<V> {
    pub(crate) value: V,
    pub(crate) loc: Location,
}

/// A single snapshot index mutation to apply to the base DB's snapshot.
pub(crate) enum SnapshotDelta<K> {
    /// Insert a new key at new_loc.
    Insert { key: K, new_loc: Location },
}

/// An immutable batch that accumulates sets and can be merkleized.
///
/// Sets are sync -- just BTreeMap inserts, no I/O. All async work happens
/// in `merkleize()`.
///
/// `JP` is the journal parent type: `Journal` for top-level batches,
/// or `authenticated::MerkleizedBatch` for stacked batches.
pub struct Batch<'a, E, K, V, H, T, JP>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    JP: authenticated::Batchable<H, Operation<K, V>>,
{
    /// Reference to the underlying DB.
    pub(super) immutable: &'a Immutable<E, K, V, H, T>,

    /// The journal parent for creating authenticated journal batches.
    pub(super) journal_parent: &'a JP,

    /// Pending sets. Sync inserts only, no I/O.
    pub(super) mutations: BTreeMap<K, V>,

    /// Overlay from parent MerkleizedBatch (for stacked batches).
    /// Empty for top-level batches.
    pub(super) parent_overlay: BTreeMap<K, OverlayEntry<V>>,

    /// Arc segments of operations accumulated by ancestor MerkleizedBatch chain.
    /// Empty for top-level batches.
    pub(super) parent_operation_chain: Vec<Arc<Vec<Operation<K, V>>>>,

    /// The virtual base: this batch's i-th operation will land at
    /// location `parent_total_size + i`.
    pub(super) parent_total_size: u64,
}

/// A merkleized batch of immutable operations.
///
/// `root()` returns the exact committed root -- identical to what `db.root()`
/// will return after `apply_batch()`.
pub struct MerkleizedBatch<'a, E, K, V, H, T, P>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<K, V>>,
{
    /// Reference to the parent DB.
    immutable: &'a Immutable<E, K, V, H, T>,

    /// The authenticated journal's MerkleizedBatch.
    journal_merkleized: authenticated::MerkleizedBatch<'a, H, P, Operation<K, V>>,

    /// Snapshot overlay: key -> entry for all keys touched by this batch chain.
    overlay: BTreeMap<K, OverlayEntry<V>>,

    /// Arc segments of all operations in the entire chain.
    operation_chain: Vec<Arc<Vec<Operation<K, V>>>>,

    /// The new last commit location.
    new_last_commit_loc: Location,

    /// The total size after this batch.
    total_size: u64,
}

/// An owned batch ready to be applied. No borrows -- can outlive the Db reference.
pub struct FinalizedBatch<K: Array, D: Digest, V: VariableValue> {
    /// The finalized authenticated journal batch.
    pub(super) journal_finalized: authenticated::FinalizedBatch<D, Operation<K, V>>,

    /// Snapshot mutations to apply.
    pub(super) snapshot_deltas: Vec<SnapshotDelta<K>>,

    /// The new last commit location.
    pub(super) new_last_commit_loc: Location,
}

// ============================================================
// Batch: sync sets + merkleize
// ============================================================

impl<'a, E, K, V, H, T, JP> Batch<'a, E, K, V, H, T, JP>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    JP: authenticated::Batchable<H, Operation<K, V>>,
{
    /// Set a key to a value. Sync -- just a BTreeMap insert, no I/O.
    pub fn set(&mut self, key: K, value: V) {
        self.mutations.insert(key, value);
    }

    /// Read through: mutations -> parent overlay -> base DB.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        // Check this batch's pending mutations.
        if let Some(value) = self.mutations.get(key) {
            return Ok(Some(value.clone()));
        }
        // Check parent overlay.
        if let Some(entry) = self.parent_overlay.get(key) {
            return Ok(Some(entry.value.clone()));
        }
        // Fall through to base DB.
        self.immutable.get(key).await
    }

    /// Generate operations and merkleize. Produces Set ops for each pending
    /// key/value (in key-sorted order), then a Commit op with optional metadata.
    pub fn merkleize(self, metadata: Option<V>) -> MerkleizedBatch<'a, E, K, V, H, T, JP::Parent> {
        let base = self.parent_total_size;

        // Build operations: one Set per key (BTreeMap iterates in sorted order), then Commit.
        let mut ops: Vec<Operation<K, V>> = Vec::with_capacity(self.mutations.len() + 1);
        let mut overlay: BTreeMap<K, OverlayEntry<V>> = BTreeMap::new();

        for (key, value) in self.mutations {
            let loc = Location::new_unchecked(base + ops.len() as u64);
            ops.push(Operation::Set(key.clone(), value.clone()));
            overlay.insert(key, OverlayEntry { value, loc });
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

        // Merge parent overlay entries that weren't overridden by this batch.
        for (k, v) in self.parent_overlay {
            overlay.entry(k).or_insert(v);
        }

        MerkleizedBatch {
            immutable: self.immutable,
            journal_merkleized,
            overlay,
            operation_chain,
            new_last_commit_loc: commit_loc,
            total_size,
        }
    }
}

// ============================================================
// MerkleizedBatch: root, get, new_batch, finalize
// ============================================================

impl<'a, E, K, V, H, T, P> MerkleizedBatch<'a, E, K, V, H, T, P>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<K, V>>,
{
    /// Return the speculative root.
    pub fn root(&self) -> H::Digest {
        self.journal_merkleized.root()
    }

    /// Read through: overlay -> base DB.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        if let Some(entry) = self.overlay.get(key) {
            return Ok(Some(entry.value.clone()));
        }
        self.immutable.get(key).await
    }

    /// Create a child batch that sees this batch's state (stacking).
    #[allow(clippy::type_complexity)]
    pub fn new_batch(
        &self,
    ) -> Batch<'_, E, K, V, H, T, authenticated::MerkleizedBatch<'a, H, P, Operation<K, V>>> {
        Batch {
            immutable: self.immutable,
            journal_parent: &self.journal_merkleized,
            mutations: BTreeMap::new(),
            parent_overlay: self.overlay.clone(),
            parent_operation_chain: self.operation_chain.clone(), // O(D) Arc bumps
            parent_total_size: self.total_size,
        }
    }

    /// Consume this batch, producing an owned `FinalizedBatch`.
    pub fn finalize(self) -> FinalizedBatch<K, H::Digest, V> {
        // Build snapshot deltas from overlay. All entries are inserts since
        // immutable databases don't support updates or deletes.
        let snapshot_deltas: Vec<_> = self
            .overlay
            .into_iter()
            .map(|(key, entry)| SnapshotDelta::Insert {
                key,
                new_loc: entry.loc,
            })
            .collect();

        FinalizedBatch {
            journal_finalized: self.journal_merkleized.finalize(),
            snapshot_deltas,
            new_last_commit_loc: self.new_last_commit_loc,
        }
    }
}
