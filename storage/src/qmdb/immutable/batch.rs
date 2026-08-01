//! Batch mutation API for Immutable QMDBs.

use super::Immutable;
use crate::{
    Context,
    journal::{authenticated, contiguous::Mutable},
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::{ValueEncoding, batch::lookup_sorted},
        batch_chain::{self, Bounds, CommitId},
        immutable::operation::Operation,
        operation::Key,
    },
    translator::Translator,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher};
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
    H: Hasher,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, K, V>, S>,

    /// Pending mutations.
    mutations: BTreeMap<K, V::Value>,

    /// Parent batch in the chain. `None` for batches created directly from the DB.
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, K, V, S>>>,

    /// The committed state immediately before this batch's operations (committed DB + prior
    /// batches). This batch's i-th operation lands at location `base.size + i`.
    base: CommitId<F, H::Digest>,
}

/// Merkleized authenticated-journal batch wrapping an [`Operation`] payload.
type JournalBatch<F, D, K, V, S> = Arc<authenticated::MerkleizedBatch<F, D, Operation<F, K, V>, S>>;

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, K: Key, V: ValueEncoding, S: Strategy> {
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: JournalBatch<F, D, K, V, S>,

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
    pub(super) bounds: batch_chain::Bounds<F, D>,
}

impl<F, H, K, V, S: Strategy> UnmerkleizedBatch<F, H, K, V, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C, T>(
        immutable: &Immutable<F, E, K, V, C, H, T, S>,
        commit: CommitId<F, H::Digest>,
    ) -> Self
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        C::Item: EncodeShared,
        T: Translator,
    {
        Self {
            journal_batch: immutable.journal.new_batch(),
            mutations: BTreeMap::new(),
            parent: None,
            base: commit,
        }
    }

    /// The database's committed state at the base of this batch chain.
    ///
    /// Derived: a DB-created batch's base is the DB commit; a child's is its parent's `db_commit`.
    fn db_commit(&self) -> CommitId<F, H::Digest> {
        self.parent
            .as_ref()
            .map_or(self.base, |parent| parent.bounds.db_commit)
    }

    /// Set a key to a value.
    ///
    /// If the key already exists in the database or an ancestor batch, reads
    /// of it may return any of its written values.
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
        C: Mutable<Item = Operation<F, K, V>>,
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
        C: Mutable<Item = Operation<F, K, V>>,
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
    #[tracing::instrument(name = "qmdb.immutable.batch.merkleize", level = "info", skip_all)]
    pub async fn merkleize<E, C, T>(
        self,
        db: &Immutable<F, E, K, V, C, H, T, S>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        C::Item: EncodeShared,
        T: Translator,
    {
        let base = self.base.size;

        // Capture the DB boundary before `self` is consumed below.
        let db_commit = self.db_commit();

        // Build operations: one Set per key, then Commit. `self.mutations` is a BTreeMap, so
        // iteration yields keys in sorted order, which `diff` relies on for binary search.
        let mut ops: Vec<Operation<F, K, V>> = Vec::with_capacity(self.mutations.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> = Vec::with_capacity(self.mutations.len());

        for (key, value) in self.mutations {
            let loc = base + ops.len() as u64;
            ops.push(Operation::Set(key.clone(), value.clone()));
            diff.push((key, DiffEntry { value, loc }));
        }
        assert!(diff.is_sorted_by(|a, b| a.0 < b.0));

        ops.push(Operation::Commit(metadata, inactivity_floor));

        let total_size = base + ops.len() as u64;
        let inactive_peaks = F::inactive_peaks(total_size, inactivity_floor);

        // Leaf and node hashing dominate merkleization, so run them as one job on the
        // strategy instead of occupying the calling task (see `Journal::merkleize`).
        let (journal, root) = db
            .journal
            .merkleize(self.journal_batch, ops, inactive_peaks)
            .await
            .expect("inactive_peaks computed from batch size");

        // Compute the batch chain bounds.
        let mut ancestor_diffs = Vec::new();
        let mut ancestors = Vec::new();
        for batch in
            batch_chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors())
        {
            ancestor_diffs.push(Arc::clone(&batch.diff));
            ancestors.push(batch_chain::AncestorBounds {
                floor: batch.bounds.inactivity_floor,
                state: batch.commit_id(),
            });
        }

        Arc::new(MerkleizedBatch {
            journal_batch: journal,
            diff: Arc::new(diff),
            parent: self.parent.as_ref().map(Arc::downgrade),
            ancestor_diffs,
            bounds: batch_chain::Bounds {
                base_commit: self.base,
                db_commit,
                tip_commit: CommitId::new(total_size, root),
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
        self.bounds.tip_commit.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F, D> {
        &self.bounds
    }

    /// Iterate over ancestor batches (parent first, then grandparent, etc.).
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, K, V, S> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }

    /// The [`CommitId`] this batch commits to.
    pub(super) const fn commit_id(&self) -> CommitId<F, D> {
        self.bounds.tip_commit
    }

    /// Read through: local diff -> ancestor diffs -> committed DB.
    pub async fn get<E, C, H, T>(
        &self,
        key: &K,
        db: &Immutable<F, E, K, V, C, H, T, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, K, V>>,
        C::Item: EncodeShared,
        H: Hasher<Digest = D>,
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
        C: Mutable<Item = Operation<F, K, V>>,
        C::Item: EncodeShared,
        H: Hasher<Digest = D>,
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
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            mutations: BTreeMap::new(),
            parent: Some(Arc::clone(self)),
            base: self.commit_id(),
        }
    }
}

impl<F, E, K, V, C, H, T, S> Immutable<F, E, K, V, C, H, T, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>>,
    C::Item: EncodeShared,
    H: Hasher,
    T: Translator,
    S: Strategy,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>> {
        Arc::new(MerkleizedBatch {
            journal_batch: self.journal.to_merkleized_batch(),
            diff: Arc::new(Vec::new()),
            parent: None,
            ancestor_diffs: Vec::new(),
            bounds: batch_chain::Bounds::from_db(self.commit_id(), self.inactivity_floor_loc),
        })
    }
}
