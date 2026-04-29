//! Batch mutation API for Immutable QMDBs.

use super::Immutable;
use crate::{
    journal::{authenticated, contiguous::Mutable, Error as JournalError},
    merkle::{Family, Location},
    qmdb::{
        any::{batch::lookup_sorted, ValueEncoding},
        append_batch::{AppendBatchView, BatchBounds},
        immutable::operation::Operation,
        operation::Key,
        Error,
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher as CHasher};
use std::{collections::BTreeMap, sync::Arc};

type DiffVec<K, F, V> = Vec<(K, DiffEntry<F, V>)>;
type JournalBatch<F, D, K, V> = authenticated::MerkleizedBatch<F, D, Operation<F, K, V>>;

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
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, K, V>>,

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
pub struct MerkleizedBatch<F: Family, D: Digest, K: Key, V: ValueEncoding> {
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: Arc<JournalBatch<F, D, K, V>>,

    /// Position bookkeeping plus the floor declared by this batch's commit.
    pub(super) bounds: BatchBounds<F>,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    /// Sorted by key with no duplicates; queried via `lookup_sorted` (binary search).
    pub(super) diff: Arc<DiffVec<K, F, V::Value>>,

    /// Strong refs to uncommitted ancestors, newest-to-oldest.
    ///
    /// This is a wrapper-level chain for validation/read-through and may include itemless
    /// `to_batch` markers that the journal layer intentionally filters out.
    pub(super) ancestors: Vec<Arc<Self>>,
}

impl<F: Family, D: Digest, K: Key, V: ValueEncoding> AppendBatchView<F, D>
    for MerkleizedBatch<F, D, K, V>
{
    fn merkle(&self) -> &Arc<crate::merkle::batch::MerkleizedBatch<F, D>> {
        &self.journal_batch.inner
    }

    fn bounds(&self) -> &BatchBounds<F> {
        &self.bounds
    }
}

impl<F, H, K, V> UnmerkleizedBatch<F, H, K, V>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: CHasher,
    Operation<F, K, V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C, T>(
        immutable: &Immutable<F, E, K, V, C, H, T>,
        journal_size: u64,
    ) -> Self
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
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
        C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        T: Translator,
    {
        // Check this batch's pending mutations.
        if let Some(value) = self.mutations.get(key) {
            return Ok(Some(value.clone()));
        }
        // Walk the live parent chain captured by the parent batch.
        if let Some(parent) = self.parent.as_ref() {
            if let Some(entry) = lookup_sorted(parent.diff.as_slice(), key) {
                return Ok(Some(entry.value.clone()));
            }
            for batch in &parent.ancestors {
                if let Some(entry) = lookup_sorted(batch.diff.as_slice(), key) {
                    return Ok(Some(entry.value.clone()));
                }
            }
        }
        // Fall through to base DB.
        db.get(key).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, T>(
        &self,
        keys: &[&K],
        db: &Immutable<F, E, K, V, C, H, T>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        T: Translator,
    {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut results: Vec<Option<V::Value>> = Vec::with_capacity(keys.len());
        let mut db_indices = Vec::new();
        let mut db_keys = Vec::new();

        for (i, key) in keys.iter().enumerate() {
            // Check local mutations.
            if let Some(value) = self.mutations.get(*key) {
                results.push(Some(value.clone()));
                continue;
            }

            // Check parent diff chain.
            let mut found = false;
            if let Some(parent) = self.parent.as_ref() {
                if let Some(entry) = lookup_sorted(parent.diff.as_slice(), *key) {
                    results.push(Some(entry.value.clone()));
                    found = true;
                }
                if !found {
                    for batch in &parent.ancestors {
                        if let Some(entry) = lookup_sorted(batch.diff.as_slice(), *key) {
                            results.push(Some(entry.value.clone()));
                            found = true;
                            break;
                        }
                    }
                }
            }

            if found {
                continue;
            }

            // Need DB fallthrough.
            db_indices.push(i);
            db_keys.push(*key);
            results.push(None);
        }

        if !db_keys.is_empty() {
            let db_results = db.get_many(&db_keys).await?;
            for (slot, value) in db_indices.into_iter().zip(db_results) {
                results[slot] = value;
            }
        }

        Ok(results)
    }

    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    ///
    /// `inactivity_floor` declares that all operations before this location are inactive.
    /// It must be >= the database's current inactivity floor (monotonically non-decreasing).
    pub fn merkleize<E, C, T>(
        self,
        db: &Immutable<F, E, K, V, C, H, T>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, K, V>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        T: Translator,
    {
        let base = self.base_size;

        let mut diff: DiffVec<K, F, V::Value> = Vec::with_capacity(self.mutations.len());
        let item_count = self.mutations.len();

        // Add mutations directly to the journal batch. `self.mutations` is a BTreeMap, so iteration
        // yields keys in sorted order, which `diff` relies on for binary search.
        let mut journal_batch = self.journal_batch;
        for (i, (key, value)) in self.mutations.into_iter().enumerate() {
            let loc = Location::new(base + i as u64);
            journal_batch = journal_batch.add(Operation::Set(key.clone(), value.clone()));
            diff.push((key, DiffEntry { value, loc }));
        }
        debug_assert!(diff.is_sorted_by(|a, b| a.0 < b.0));

        journal_batch = journal_batch.add(Operation::Commit(metadata, inactivity_floor));
        let journal_merkleized = db.journal.with_mem(|mem| journal_batch.merkleize(mem));

        let ancestors = self
            .parent
            .as_ref()
            .map(MerkleizedBatch::ancestor_chain)
            .unwrap_or_default();
        let bounds = BatchBounds::from_item_count(
            self.base_size,
            self.db_size,
            item_count,
            inactivity_floor,
        );

        Arc::new(MerkleizedBatch {
            journal_batch: journal_merkleized,
            bounds,
            diff: Arc::new(diff),
            ancestors,
        })
    }
}

impl<F: Family, D: Digest, K: Key, V: ValueEncoding> MerkleizedBatch<F, D, K, V>
where
    Operation<F, K, V>: EncodeShared,
{
    /// Build a newest-to-oldest ancestor chain rooted at `parent`, including `parent` itself.
    fn ancestor_chain(parent: &Arc<Self>) -> Vec<Arc<Self>> {
        let mut ancestors = Vec::with_capacity(parent.ancestors.len() + 1);
        ancestors.push(Arc::clone(parent));
        ancestors.extend(parent.ancestors.iter().cloned());
        ancestors
    }

    /// Return the speculative root.
    pub fn root(&self) -> D {
        <Self as AppendBatchView<F, D>>::root(self)
    }

    /// Read through: local diff -> ancestor diffs -> committed DB.
    pub async fn get<E, C, H, T>(
        &self,
        key: &K,
        db: &Immutable<F, E, K, V, C, H, T>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        H: CHasher<Digest = D>,
        T: Translator,
    {
        if let Some(entry) = lookup_sorted(self.diff.as_slice(), key) {
            return Ok(Some(entry.value.clone()));
        }
        for batch in &self.ancestors {
            if let Some(entry) = lookup_sorted(batch.diff.as_slice(), key) {
                return Ok(Some(entry.value.clone()));
            }
        }
        db.get(key).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, H, T>(
        &self,
        keys: &[&K],
        db: &Immutable<F, E, K, V, C, H, T>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        H: CHasher<Digest = D>,
        T: Translator,
    {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut results: Vec<Option<V::Value>> = Vec::with_capacity(keys.len());
        let mut db_indices = Vec::new();
        let mut db_keys = Vec::new();

        for (i, key) in keys.iter().enumerate() {
            // Check local diff.
            if let Some(entry) = lookup_sorted(self.diff.as_slice(), *key) {
                results.push(Some(entry.value.clone()));
                continue;
            }

            // Walk ancestor diffs captured when this batch was merkleized.
            let mut found = false;
            for batch in &self.ancestors {
                if let Some(entry) = lookup_sorted(batch.diff.as_slice(), *key) {
                    results.push(Some(entry.value.clone()));
                    found = true;
                    break;
                }
            }

            if found {
                continue;
            }

            // Need DB fallthrough.
            db_indices.push(i);
            db_keys.push(*key);
            results.push(None);
        }

        if !db_keys.is_empty() {
            let db_results = db.get_many(&db_keys).await?;
            for (slot, value) in db_indices.into_iter().zip(db_results) {
                results[slot] = value;
            }
        }

        Ok(results)
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    ///
    /// All uncommitted ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Dropping an uncommitted ancestor causes data
    /// loss detected at `apply_batch` time.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, K, V>
    where
        H: CHasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            mutations: BTreeMap::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.bounds.total_size(),
            db_size: self.bounds.db_size(),
        }
    }
}

impl<F, E, K, V, C, H, T> Immutable<F, E, K, V, C, H, T>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    C::Item: EncodeShared,
    H: CHasher,
    T: Translator,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, K, V>> {
        let journal_size = *self.last_commit_loc + 1;
        let journal_batch = self.journal.to_merkleized_batch();
        let bounds = BatchBounds::committed(journal_size, self.inactivity_floor_loc);
        Arc::new(MerkleizedBatch {
            journal_batch,
            bounds,
            diff: Arc::new(Vec::new()),
            ancestors: Vec::new(),
        })
    }
}
