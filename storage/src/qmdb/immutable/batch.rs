//! Batch mutation API for Immutable QMDBs.

use super::Immutable;
use crate::{
    journal::{authenticated, contiguous::Mutable, Error as JournalError},
    merkle::{Family, Location},
    qmdb::{any::ValueEncoding, immutable::operation::Operation, operation::Key, Error},
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher as CHasher};
use std::{collections::BTreeMap, sync::Arc};

/// Snapshot diff and boundary for a single ancestor batch.
#[derive(Clone)]
pub(super) struct Ancestor<K: Key, F: Family, V: ValueEncoding> {
    /// Key-level changes from this ancestor.
    pub(super) diff: Arc<BTreeMap<K, DiffEntry<F, V::Value>>>,
    /// Total operation count after this ancestor (used to detect committed ancestors).
    pub(super) end_index: u64,
}

/// What happened to a key in this batch.
#[derive(Clone)]
pub(crate) struct DiffEntry<F: Family, V> {
    pub(crate) value: V,
    pub(crate) loc: Location<F>,
}

/// A speculative batch of operations whose root digest has not yet been computed, in contrast
/// to [`MerkleizedBatch`].
///
/// Consuming [`UnmerkleizedBatch::merkleize`] produces an `Arc<MerkleizedBatch>`.
/// Methods that need the committed DB (e.g. [`get`](Self::get)) accept it as a parameter.
#[allow(clippy::type_complexity)]
pub struct UnmerkleizedBatch<F, H, K, V>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: CHasher,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<K, V>>,

    /// Pending mutations.
    mutations: BTreeMap<K, V::Value>,

    /// Parent batch in the chain. `None` for batches created directly from the DB.
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, K, V>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// The database size when this batch was created, used to detect stale batches.
    db_size: u64,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, K: Key, V: ValueEncoding> {
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<K, V>>>,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    pub(super) diff: Arc<BTreeMap<K, DiffEntry<F, V::Value>>>,

    /// Total operations before this batch's own ops (DB + ancestor batches).
    pub(super) base_size: u64,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the initial batch was created.
    pub(super) db_size: u64,

    /// Ancestor diffs collected during `merkleize()` while the parent is alive.
    /// Used by `apply_batch` to apply uncommitted ancestor snapshot diffs.
    /// Tip-to-root order (nearest ancestor first).
    pub(super) ancestors: Vec<Ancestor<K, F, V>>,
}

impl<F, H, K, V> UnmerkleizedBatch<F, H, K, V>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: CHasher,
    Operation<K, V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C, T>(
        immutable: &Immutable<F, E, K, V, C, H, T>,
        journal_size: u64,
    ) -> Self
    where
        E: Context,
        C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        T: Translator,
    {
        Self {
            journal_batch: immutable.journal.new_batch(),
            mutations: BTreeMap::new(),
            parent: None,
            base_size: journal_size,
            db_size: journal_size,
        }
    }

    /// Set a key to a value.
    ///
    /// The key must not already exist in the database or in any ancestor batch
    /// in the chain. Setting a key that already exists causes undefined behavior.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.mutations.insert(key, value);
        self
    }

    /// Read through: mutations -> ancestor diffs -> committed DB.
    pub async fn get<E, C, T>(
        &self,
        key: &K,
        db: &Immutable<F, E, K, V, C, H, T>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        T: Translator,
    {
        // Check this batch's pending mutations.
        if let Some(value) = self.mutations.get(key) {
            return Ok(Some(value.clone()));
        }
        // Check parent diff and ancestor diffs (tip-to-root ordering).
        if let Some(parent) = self.parent.as_ref() {
            if let Some(entry) = parent.diff.get(key) {
                return Ok(Some(entry.value.clone()));
            }
            for ancestor in &parent.ancestors {
                if let Some(entry) = ancestor.diff.get(key) {
                    return Ok(Some(entry.value.clone()));
                }
            }
        }
        // Fall through to base DB.
        db.get(key).await
    }

    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub fn merkleize<E, C, T>(
        self,
        db: &Immutable<F, E, K, V, C, H, T>,
        metadata: Option<V::Value>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, K, V>>
    where
        E: Context,
        C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        T: Translator,
    {
        let base = self.base_size;

        // Build operations: one Set per key (BTreeMap iterates in sorted order), then Commit.
        let mut ops: Vec<Operation<K, V>> = Vec::with_capacity(self.mutations.len() + 1);
        let mut diff: BTreeMap<K, DiffEntry<F, V::Value>> = BTreeMap::new();

        for (key, value) in self.mutations {
            let loc = Location::new(base + ops.len() as u64);
            ops.push(Operation::Set(key.clone(), value.clone()));
            diff.insert(key, DiffEntry { value, loc });
        }

        ops.push(Operation::Commit(metadata));

        let total_size = base + ops.len() as u64;

        // Add operations to the journal batch and merkleize.
        let mut journal_batch = self.journal_batch;
        for op in &ops {
            journal_batch = journal_batch.add(op.clone());
        }
        let journal_merkleized = db.journal.with_mem(|mem| journal_batch.merkleize(mem));

        let ancestors = self.parent.as_ref().map_or_else(Vec::new, |parent| {
            let mut segs = vec![Ancestor {
                diff: Arc::clone(&parent.diff),
                end_index: parent.total_size,
            }];
            segs.extend(parent.ancestors.iter().cloned());
            segs
        });

        Arc::new(MerkleizedBatch {
            journal_batch: journal_merkleized,
            diff: Arc::new(diff),
            base_size: self.base_size,
            total_size,
            db_size: self.db_size,
            ancestors,
        })
    }
}

impl<F: Family, D: Digest, K: Key, V: ValueEncoding> MerkleizedBatch<F, D, K, V>
where
    Operation<K, V>: EncodeShared,
{
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal_batch.root()
    }

    /// Read through: local diff -> ancestor diffs -> committed DB.
    pub async fn get<E, C, H, T>(
        &self,
        key: &K,
        db: &Immutable<F, E, K, V, C, H, T>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        H: CHasher<Digest = D>,
        T: Translator,
    {
        if let Some(entry) = self.diff.get(key) {
            return Ok(Some(entry.value.clone()));
        }
        // ancestors is tip-to-root, so nearest ancestor is checked first.
        for ancestor in &self.ancestors {
            if let Some(entry) = ancestor.diff.get(key) {
                return Ok(Some(entry.value.clone()));
            }
        }
        db.get(key).await
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, K, V>
    where
        H: CHasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            mutations: BTreeMap::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.total_size,
            db_size: self.db_size,
        }
    }
}

impl<F, E, K, V, C, H, T> Immutable<F, E, K, V, C, H, T>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V>> + Persistable<Error = JournalError>,
    C::Item: EncodeShared,
    H: CHasher,
    T: Translator,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, K, V>> {
        let journal_size = *self.last_commit_loc + 1;
        Arc::new(MerkleizedBatch {
            journal_batch: self.journal.to_merkleized_batch(),
            diff: Arc::new(BTreeMap::new()),
            base_size: journal_size,
            total_size: journal_size,
            db_size: journal_size,
            ancestors: Vec::new(),
        })
    }
}
