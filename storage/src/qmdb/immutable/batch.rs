//! Batch mutation API for Immutable QMDBs.

use super::Immutable;
use crate::{
    journal::authenticated,
    mmr::{Location, Position},
    qmdb::{any::VariableValue, immutable::operation::Operation, Error},
    translator::Translator,
};
use commonware_codec::Encode;
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use commonware_utils::Array;
use std::{collections::BTreeMap, sync::Arc};

/// What happened to a key in this batch.
#[derive(Clone)]
pub(crate) struct DiffEntry<V> {
    pub(crate) value: V,
    pub(crate) loc: Location,
}

/// A single snapshot index mutation to apply to the base DB's snapshot.
pub(crate) enum SnapshotDiff<K> {
    /// Insert a new key at new_loc.
    Insert { key: K, new_loc: Location },
}

/// A speculative batch whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Borrows `&Immutable` for reads during the build phase. Consuming
/// [`UnmerkleizedBatch::merkleize`] produces an owned [`MerkleizedBatch`]
/// and releases the borrow.
pub struct UnmerkleizedBatch<'a, E, K, V, H, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
{
    /// The committed DB this batch reads from.
    immutable: &'a Immutable<E, K, V, H, T>,

    /// Journal batch for computing the speculative MMR root.
    journal_builder: authenticated::UnmerkleizedBatch<H, Operation<K, V>>,

    /// Pending mutations.
    mutations: BTreeMap<K, V>,

    /// Uncommitted key-level changes accumulated by prior batches in the chain.
    base_diff: Arc<BTreeMap<K, DiffEntry<V>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// The database size when this batch was created, used to detect stale changesets.
    db_size: u64,
}

/// A speculative batch whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
pub struct MerkleizedBatch<D: Digest, K: Array, V: VariableValue> {
    /// Journal batch (MMR state + accumulated operation segments).
    pub(crate) journal: authenticated::MerkleizedBatch<D, Operation<K, V>>,

    /// All uncommitted key-level changes from the batch chain.
    pub(crate) diff: Arc<BTreeMap<K, DiffEntry<V>>>,

    /// Total operation count after this batch.
    pub(crate) total_size: u64,

    /// The database size when the initial batch was created.
    pub(crate) db_size: u64,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<K: Array, D: Digest, V: VariableValue> {
    /// The finalized authenticated journal batch (MMR changeset + item chain).
    pub(super) journal_finalized: crate::journal::authenticated::Changeset<D, Operation<K, V>>,

    /// Snapshot mutations to apply, in order.
    pub(super) snapshot_diffs: Vec<SnapshotDiff<K>>,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the batch was created. Used to detect stale changesets.
    pub(super) db_size: u64,
}

impl<'a, E, K, V, H, T> UnmerkleizedBatch<'a, E, K, V, H, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue + Encode,
    H: CHasher,
    T: Translator,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new(immutable: &'a Immutable<E, K, V, H, T>, journal_size: u64) -> Self {
        Self {
            immutable,
            journal_builder: immutable.journal.to_snapshot().new_batch::<H>(),
            mutations: BTreeMap::new(),
            base_diff: Arc::new(BTreeMap::new()),
            base_size: journal_size,
            db_size: journal_size,
        }
    }

    /// Set a key to a value.
    ///
    /// The key must not already exist in the database or in any ancestor batch
    /// in the chain. Setting a key that already exists causes undefined behavior.
    pub fn set(mut self, key: K, value: V) -> Self {
        self.mutations.insert(key, value);
        self
    }

    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        // Check this batch's pending mutations.
        if let Some(value) = self.mutations.get(key) {
            return Ok(Some(value.clone()));
        }
        // Check parent diff.
        if let Some(entry) = self.base_diff.get(key) {
            return Ok(Some(entry.value.clone()));
        }
        // Fall through to base DB.
        self.immutable.get(key).await
    }

    /// Resolve mutations into operations, merkleize, and return an [`MerkleizedBatch`].
    pub fn merkleize(self, metadata: Option<V>) -> MerkleizedBatch<H::Digest, K, V> {
        let base = self.base_size;

        // Build operations: one Set per key (BTreeMap iterates in sorted order), then Commit.
        let mut ops: Vec<Operation<K, V>> = Vec::with_capacity(self.mutations.len() + 1);
        let mut diff: BTreeMap<K, DiffEntry<V>> = BTreeMap::new();

        for (key, value) in self.mutations {
            let loc = Location::new(base + ops.len() as u64);
            ops.push(Operation::Set(key.clone(), value.clone()));
            diff.insert(key, DiffEntry { value, loc });
        }

        ops.push(Operation::Commit(metadata));

        let total_size = base + ops.len() as u64;

        // Add operations to the journal batch and merkleize.
        let mut journal_builder = self.journal_builder;
        for op in &ops {
            journal_builder.add(op.clone());
        }
        let journal = journal_builder.merkleize();

        // Merge parent diff entries that weren't overridden by this batch.
        let base_diff = Arc::try_unwrap(self.base_diff).unwrap_or_else(|arc| (*arc).clone());
        for (k, v) in base_diff {
            diff.entry(k).or_insert(v);
        }

        MerkleizedBatch {
            journal,
            diff: Arc::new(diff),
            total_size,
            db_size: self.db_size,
        }
    }
}

impl<D: Digest, K: Array, V: VariableValue> MerkleizedBatch<D, K, V> {
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal.root()
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<'a, E, H, T>(
        &'a self,
        db: &'a Immutable<E, K, V, H, T>,
    ) -> UnmerkleizedBatch<'a, E, K, V, H, T>
    where
        E: RStorage + Clock + Metrics,
        H: CHasher<Digest = D>,
        T: Translator,
    {
        UnmerkleizedBatch {
            immutable: db,
            journal_builder: self.journal.new_batch::<H>(),
            mutations: BTreeMap::new(),
            base_diff: Arc::clone(&self.diff),
            base_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Read through: diff -> committed DB.
    pub async fn get<E, H, T>(
        &self,
        key: &K,
        db: &Immutable<E, K, V, H, T>,
    ) -> Result<Option<V>, Error>
    where
        E: RStorage + Clock + Metrics,
        H: CHasher<Digest = D>,
        T: Translator,
    {
        if let Some(entry) = self.diff.get(key) {
            return Ok(Some(entry.value.clone()));
        }
        db.get(key).await
    }

    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<K, D, V> {
        let diff = Arc::try_unwrap(self.diff).unwrap_or_else(|arc| (*arc).clone());
        let snapshot_diffs: Vec<_> = diff
            .into_iter()
            .map(|(key, entry)| SnapshotDiff::Insert {
                key,
                new_loc: entry.loc,
            })
            .collect();

        Changeset {
            journal_finalized: self.journal.into_finalize(),
            snapshot_diffs,
            total_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Produce a [`Changeset`] relative to the current committed DB size.
    pub fn finalize_from(self, current_db_size: u64) -> Changeset<K, D, V> {
        let diff = Arc::try_unwrap(self.diff).unwrap_or_else(|arc| (*arc).clone());
        let snapshot_diffs: Vec<_> = diff
            .into_iter()
            .filter(|(_, entry)| *entry.loc >= current_db_size)
            .map(|(key, entry)| SnapshotDiff::Insert {
                key,
                new_loc: entry.loc,
            })
            .collect();

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
            snapshot_diffs,
            total_size: self.total_size,
            db_size: current_db_size,
        }
    }
}

// Conversion: Immutable::to_snapshot
impl<E, K, V, H, T> Immutable<E, K, V, H, T>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_snapshot(&self) -> MerkleizedBatch<H::Digest, K, V> {
        let journal_size = *self.last_commit_loc + 1;
        MerkleizedBatch {
            journal: self.journal.to_snapshot(),
            diff: Arc::new(BTreeMap::new()),
            total_size: journal_size,
            db_size: journal_size,
        }
    }
}
