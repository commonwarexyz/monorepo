//! Batch mutation API for Immutable QMDBs.

use super::Immutable;
use crate::{
    journal::authenticated::{self, BatchChain},
    merkle::batch::ChainInfo,
    mmr::{self, Location, Readable},
    qmdb::{any::VariableValue, immutable::operation::Operation, Error},
    translator::Translator,
};
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

/// A speculative batch of operations whose root digest has not yet been
/// computed, in contrast to [MerkleizedBatch].
pub struct UnmerkleizedBatch<'a, E, K, V, H, T, P>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<K, V>>,
{
    /// The committed DB this batch is built on top of.
    pub(super) immutable: &'a Immutable<E, K, V, H, T>,

    /// Authenticated journal batch for computing the speculative MMR root.
    pub(super) journal_batch: authenticated::UnmerkleizedBatch<'a, H, P, Operation<K, V>>,

    /// Pending mutations.
    pub(super) mutations: BTreeMap<K, V>,

    /// Uncommitted key-level changes accumulated by prior batches in the chain.
    pub(super) base_diff: Arc<BTreeMap<K, DiffEntry<V>>>,

    /// One Arc segment of operations per prior batch in the chain.
    pub(super) base_operations: Vec<Arc<Vec<Operation<K, V>>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    pub(super) base_size: u64,

    /// The database size when this batch was created, used to detect stale changesets.
    pub(super) db_size: u64,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [UnmerkleizedBatch].
pub struct MerkleizedBatch<'a, E, K, V, H, T, P>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<K, V>>,
{
    /// The committed DB this batch is built on top of.
    immutable: &'a Immutable<E, K, V, H, T>,

    /// Merkleized authenticated journal batch (provides the speculative MMR root).
    journal_batch: authenticated::MerkleizedBatch<'a, H, P, Operation<K, V>>,

    /// All uncommitted key-level changes in this batch chain.
    diff: Arc<BTreeMap<K, DiffEntry<V>>>,

    /// One Arc segment of operations per batch in the chain (chronological order).
    base_operations: Vec<Arc<Vec<Operation<K, V>>>>,

    /// Total operation count after this batch.
    total_size: u64,

    /// The database size when this batch was created, used to detect stale changesets.
    db_size: u64,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<K: Array, D: Digest, V: VariableValue> {
    /// The finalized authenticated journal batch (MMR changeset + item chain).
    pub(super) journal_finalized: authenticated::Changeset<D, Operation<K, V>>,

    /// Snapshot mutations to apply, in order.
    pub(super) snapshot_diffs: Vec<SnapshotDiff<K>>,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the batch was created. Used to detect stale changesets.
    pub(super) db_size: u64,
}

impl<'a, E, K, V, H, T, P> UnmerkleizedBatch<'a, E, K, V, H, T, P>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<K, V>>,
{
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

    /// Resolve mutations into operations, merkleize, and return a [`MerkleizedBatch`].
    pub fn merkleize(self, metadata: Option<V>) -> MerkleizedBatch<'a, E, K, V, H, T, P> {
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

        // Merkleize the journal batch (created eagerly at batch construction).
        let mut journal_batch = self.journal_batch;
        for op in &ops {
            journal_batch = journal_batch.add(op.clone());
        }
        let journal_batch = journal_batch.merkleize();

        // Build the operation chain: parent segments + this batch's segment.
        let mut base_operations = self.base_operations;
        base_operations.push(Arc::new(ops));

        // Merge parent diff entries that weren't overridden by this batch.
        let base_diff = Arc::try_unwrap(self.base_diff).unwrap_or_else(|arc| (*arc).clone());
        for (k, v) in base_diff {
            diff.entry(k).or_insert(v);
        }

        MerkleizedBatch {
            immutable: self.immutable,
            journal_batch,
            diff: Arc::new(diff),
            base_operations,
            total_size,
            db_size: self.db_size,
        }
    }
}

impl<'a, E, K, V, H, T, P> MerkleizedBatch<'a, E, K, V, H, T, P>
where
    E: RStorage + Clock + Metrics,
    K: Array,
    V: VariableValue,
    H: CHasher,
    T: Translator,
    P: Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>
        + ChainInfo<mmr::Family, Digest = H::Digest>
        + BatchChain<Operation<K, V>>,
{
    /// Return the speculative root.
    pub fn root(&self) -> H::Digest {
        self.journal_batch.root()
    }

    /// Read through: diff -> committed DB.
    pub async fn get(&self, key: &K) -> Result<Option<V>, Error> {
        if let Some(entry) = self.diff.get(key) {
            return Ok(Some(entry.value.clone()));
        }
        self.immutable.get(key).await
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(
        &self,
    ) -> UnmerkleizedBatch<
        '_,
        E,
        K,
        V,
        H,
        T,
        authenticated::MerkleizedBatch<'a, H, P, Operation<K, V>>,
    > {
        UnmerkleizedBatch {
            immutable: self.immutable,
            journal_batch: self.journal_batch.new_batch(),
            mutations: BTreeMap::new(),
            base_diff: Arc::clone(&self.diff),
            base_operations: self.base_operations.clone(),
            base_size: self.total_size,
            db_size: self.db_size,
        }
    }

    /// Consume this batch, producing an owned `Changeset`.
    pub fn finalize(self) -> Changeset<K, H::Digest, V> {
        // Build snapshot diffs from diff. All entries are inserts since
        // immutable databases don't support updates or deletes.
        let diff = Arc::try_unwrap(self.diff).unwrap_or_else(|arc| (*arc).clone());
        let snapshot_diffs: Vec<_> = diff
            .into_iter()
            .map(|(key, entry)| SnapshotDiff::Insert {
                key,
                new_loc: entry.loc,
            })
            .collect();

        Changeset {
            journal_finalized: self.journal_batch.finalize(),
            snapshot_diffs,
            total_size: self.total_size,
            db_size: self.db_size,
        }
    }
}
