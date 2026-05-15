//! Batch mutation API for Immutable QMDBs.

use super::Immutable;
use crate::{
    journal::{authenticated, contiguous::Mutable, Error as JournalError},
    merkle::{Family, Location},
    qmdb::{
        any::{batch::lookup_sorted, ValueEncoding},
        batch_chain::{self, Bounds},
        immutable::operation::Operation,
        operation::Key,
        Error,
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher as CHasher};
use commonware_parallel::Strategy;
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

type DiffVec<K, F, V> = Vec<(K, DiffEntry<F, V>)>;

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
pub struct UnmerkleizedBatch<F, H, K, V, S: Strategy>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: CHasher,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, K, V>, S>,

    /// Pending mutations.
    mutations: BTreeMap<K, V::Value>,

    /// Parent batch in the chain. `None` for batches created directly from the DB.
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, K, V, S>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// The database size when this batch was created, used to detect stale batches.
    db_size: u64,
}

/// Merkleized authenticated-journal batch wrapping an [`Operation`] payload.
type JournalBatch<F, D, K, V, S> = Arc<authenticated::MerkleizedBatch<F, D, Operation<F, K, V>, S>>;

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, K: Key, V: ValueEncoding, S: Strategy> {
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: JournalBatch<F, D, K, V, S>,

    /// Cached operations root after applying this batch.
    pub(super) root: D,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    /// Sorted by key with no duplicates; queried via `lookup_sorted` (binary search).
    pub(super) diff: Arc<DiffVec<K, F, V::Value>>,

    /// The parent batch in the chain, if any.
    pub(super) parent: Option<Weak<Self>>,

    /// Arc refs to each ancestor's diff, collected during `merkleize()` while the parent
    /// is alive. Used by `apply_batch` to apply uncommitted ancestor snapshot diffs.
    /// 1:1 with `bounds.ancestors` (same length, same ordering).
    pub(super) ancestor_diffs: Vec<Arc<DiffVec<K, F, V::Value>>>,

    /// Position and floor bounds for this batch chain.
    pub(super) bounds: batch_chain::Bounds<F>,
}

impl<F, H, K, V, S: Strategy> UnmerkleizedBatch<F, H, K, V, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: CHasher,
    Operation<F, K, V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C, T>(
        immutable: &Immutable<F, E, K, V, C, H, T, S>,
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
        db: &Immutable<F, E, K, V, C, H, T, S>,
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
        // Walk parent chain. The first parent is a strong Arc (held by UnmerkleizedBatch),
        // subsequent parents are Weak refs.
        if let Some(parent) = self.parent.as_ref() {
            if let Some(entry) = lookup_sorted(parent.diff.as_slice(), key) {
                return Ok(Some(entry.value.clone()));
            }
            for batch in parent.ancestors() {
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
        db: &Immutable<F, E, K, V, C, H, T, S>,
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
                    for batch in parent.ancestors() {
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
        db: &Immutable<F, E, K, V, C, H, T, S>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
        T: Translator,
    {
        let base = self.base_size;

        // Build operations: one Set per key, then Commit. `self.mutations` is a BTreeMap, so
        // iteration yields keys in sorted order, which `diff` relies on for binary search.
        let mut ops: Vec<Operation<F, K, V>> = Vec::with_capacity(self.mutations.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> = Vec::with_capacity(self.mutations.len());

        for (key, value) in self.mutations {
            let loc = Location::new(base + ops.len() as u64);
            ops.push(Operation::Set(key.clone(), value.clone()));
            diff.push((key, DiffEntry { value, loc }));
        }
        debug_assert!(diff.is_sorted_by(|a, b| a.0 < b.0));

        ops.push(Operation::Commit(metadata, inactivity_floor));

        let total_size = base + ops.len() as u64;

        // Add operations to the journal batch and merkleize.
        let mut journal_batch = self.journal_batch;
        for op in &ops {
            journal_batch = journal_batch.add(op.clone());
        }
        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(total_size)),
            inactivity_floor,
        );
        let journal_merkleized = db.journal.with_mem(|mem| journal_batch.merkleize(mem));
        let root = db
            .journal
            .with_mem(|mem| journal_merkleized.root(mem, &db.journal.hasher, inactive_peaks))
            .expect("inactive_peaks computed from batch size");

        let mut ancestor_diffs = Vec::new();
        let mut ancestors = Vec::new();
        for batch in
            batch_chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors())
        {
            ancestor_diffs.push(Arc::clone(&batch.diff));
            ancestors.push(batch_chain::AncestorBounds {
                floor: batch.bounds.inactivity_floor,
                end: batch.bounds.total_size,
            });
        }

        Arc::new(MerkleizedBatch {
            journal_batch: journal_merkleized,
            root,
            diff: Arc::new(diff),
            parent: self.parent.as_ref().map(Arc::downgrade),
            ancestor_diffs,
            bounds: batch_chain::Bounds {
                base_size: self.base_size,
                db_size: self.db_size,
                total_size,
                ancestors,
                inactivity_floor,
            },
        })
    }
}

impl<F: Family, D: Digest, K: Key, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, K, V, S>
where
    Operation<F, K, V>: EncodeShared,
{
    /// Return the speculative root.
    pub const fn root(&self) -> D {
        self.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F> {
        &self.bounds
    }

    /// Iterate over ancestor batches (parent first, then grandparent, etc.).
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }

    /// Read through: local diff -> ancestor diffs -> committed DB.
    pub async fn get<E, C, H, T>(
        &self,
        key: &K,
        db: &Immutable<F, E, K, V, C, H, T, S>,
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
        for batch in self.ancestors() {
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
        db: &Immutable<F, E, K, V, C, H, T, S>,
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

            // Walk parent chain.
            let mut found = false;
            for batch in self.ancestors() {
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
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, K, V, S>
    where
        H: CHasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            mutations: BTreeMap::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.bounds.total_size,
            db_size: self.bounds.db_size,
        }
    }
}

impl<F, E, K, V, C, H, T, S> Immutable<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    C::Item: EncodeShared,
    H: CHasher,
    T: Translator,
    S: Strategy,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>> {
        let journal_size = *self.last_commit_loc + 1;
        Arc::new(MerkleizedBatch {
            journal_batch: self.journal.to_merkleized_batch(),
            root: self.root,
            diff: Arc::new(Vec::new()),
            parent: None,
            ancestor_diffs: Vec::new(),
            bounds: batch_chain::Bounds {
                base_size: journal_size,
                db_size: journal_size,
                total_size: journal_size,
                ancestors: Vec::new(),
                inactivity_floor: self.inactivity_floor_loc,
            },
        })
    }
}
