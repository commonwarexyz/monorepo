//! Batch mutation API for Keyless QMDBs.

use super::{operation::Operation, Keyless};
use crate::{
    journal::{authenticated, contiguous::Mutable, Error as JournalError},
    merkle::{Family, Location},
    qmdb::{
        any::value::ValueEncoding,
        append_batch::{AppendBatchView, BatchExtent},
        Error,
    },
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher};
use std::sync::Arc;

/// A speculative batch of operations whose root digest has not yet been computed, in contrast
/// to [`MerkleizedBatch`].
///
/// Consuming [`UnmerkleizedBatch::merkleize`] produces an `Arc<MerkleizedBatch>`.
pub struct UnmerkleizedBatch<F, H, V>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, V>>,

    /// Pending appends.
    appends: Vec<V::Value>,

    /// Parent batch in the chain. `None` for batches created directly from the DB.
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, V>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// The database size when this batch was created, used to detect stale batches.
    db_size: u64,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding>
where
    Operation<F, V>: EncodeShared,
{
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, V>>>,
    /// Position bookkeeping plus the floor declared by this batch's commit.
    pub(super) extent: BatchExtent<F>,
    /// Strong refs to uncommitted ancestors, newest-to-oldest.
    ///
    /// This is a wrapper-level chain for validation/read-through and may include itemless
    /// `to_batch` markers that the journal layer intentionally filters out.
    pub(super) ancestors: Vec<Arc<Self>>,
}

impl<F: Family, D: Digest, V: ValueEncoding> AppendBatchView<F, D> for MerkleizedBatch<F, D, V>
where
    Operation<F, V>: EncodeShared,
{
    fn merkle(&self) -> &Arc<crate::merkle::batch::MerkleizedBatch<F, D>> {
        &self.journal_batch.inner
    }

    fn extent(&self) -> &BatchExtent<F> {
        &self.extent
    }
}

/// Read a single operation from the parent chain at the given location.
///
/// Returns `None` if the location cannot be found in the live parent chain (e.g. the
/// owning ancestor was committed and freed). Callers should fall through to the committed
/// DB in that case.
fn read_chain_op<F: Family, D: Digest, V: ValueEncoding>(
    batch: &MerkleizedBatch<F, D, V>,
    loc: u64,
) -> Option<Operation<F, V>>
where
    Operation<F, V>: EncodeShared,
{
    // Each batch's items extent [size - items.len(), size). We compute the range from the
    // journal (strong Arcs, always intact).
    let self_end = batch.journal_batch.size();
    let self_base = self_end - batch.journal_batch.items().len() as u64;
    if loc >= self_base && loc < self_end {
        return Some(batch.journal_batch.items()[(loc - self_base) as usize].clone());
    }
    for ancestor in &batch.ancestors {
        let end = ancestor.journal_batch.size();
        let base = end - ancestor.journal_batch.items().len() as u64;
        if loc >= base && loc < end {
            return Some(ancestor.journal_batch.items()[(loc - base) as usize].clone());
        }
    }
    None
}

impl<F, H, V> UnmerkleizedBatch<F, H, V>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C>(keyless: &Keyless<F, E, V, C, H>, journal_size: u64) -> Self
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        Self {
            journal_batch: keyless.journal.new_batch(),
            appends: Vec::new(),
            parent: None,
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
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        let loc_val = *loc;

        // Check this batch's pending appends.
        if loc_val >= self.base_size {
            let idx = (loc_val - self.base_size) as usize;
            return if idx < self.appends.len() {
                Ok(Some(self.appends[idx].clone()))
            } else {
                Ok(None)
            };
        }

        // Check parent operation chain. If the ancestor was freed, read_chain_op returns None
        // and we fall through to the DB.
        if let Some(parent) = self.parent.as_ref() {
            if loc_val >= self.db_size {
                if let Some(op) = read_chain_op(parent, loc_val) {
                    return Ok(op.into_value());
                }
            }
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Batch read values at multiple locations.
    ///
    /// Locations must be sorted in ascending order.
    /// Returns results in the same order as the input locations.
    pub async fn get_many<E, C>(
        &self,
        locs: &[Location<F>],
        db: &Keyless<F, E, V, C, H>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        if locs.is_empty() {
            return Ok(Vec::new());
        }
        debug_assert!(
            locs.is_sorted(),
            "locations must be sorted in ascending order"
        );
        let mut results = Vec::with_capacity(locs.len());
        let mut db_indices = Vec::new();
        let mut db_locs = Vec::new();

        for (i, &loc) in locs.iter().enumerate() {
            let loc_val = *loc;

            // Check this batch's pending appends.
            if loc_val >= self.base_size {
                let idx = (loc_val - self.base_size) as usize;
                results.push(if idx < self.appends.len() {
                    Some(self.appends[idx].clone())
                } else {
                    None
                });
                continue;
            }

            // Check parent operation chain.
            if let Some(parent) = self.parent.as_ref() {
                if loc_val >= self.db_size {
                    if let Some(op) = read_chain_op(parent, loc_val) {
                        results.push(op.into_value());
                        continue;
                    }
                }
            }

            // Need DB fallthrough -- record index for reassembly.
            db_indices.push(i);
            db_locs.push(loc);
            results.push(None);
        }

        if !db_locs.is_empty() {
            let db_results = db.get_many(&db_locs).await?;
            for (slot, value) in db_indices.into_iter().zip(db_results) {
                results[slot] = value;
            }
        }

        Ok(results)
    }

    /// Resolve appends into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    ///
    /// `inactivity_floor` is the application-declared floor embedded in the commit. It must
    /// be monotonically non-decreasing across the chain (enforced on `apply_batch`) and must
    /// be at most this batch's own commit location (`total_size - 1`). A floor past the commit
    /// would let a later `prune(floor)` remove the last readable commit.
    pub fn merkleize<E, C>(
        self,
        db: &Keyless<F, E, V, C, H>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, V>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        let item_count = self.appends.len();

        // Add operations to the journal batch and merkleize.
        let mut journal_batch = self.journal_batch;
        for value in self.appends {
            journal_batch = journal_batch.add(Operation::Append(value));
        }
        journal_batch = journal_batch.add(Operation::Commit(metadata, inactivity_floor));
        let journal = db.journal.with_mem(|mem| journal_batch.merkleize(mem));

        let ancestors = self
            .parent
            .as_ref()
            .map(MerkleizedBatch::ancestor_chain)
            .unwrap_or_default();
        let extent = BatchExtent::from_item_count(
            self.base_size,
            self.db_size,
            item_count,
            inactivity_floor,
        );

        Arc::new(MerkleizedBatch {
            journal_batch: journal,
            extent,
            ancestors,
        })
    }
}

impl<F: Family, D: Digest, V: ValueEncoding> MerkleizedBatch<F, D, V>
where
    Operation<F, V>: EncodeShared,
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

    /// Read a value at `loc`.
    pub async fn get<E, H, C>(
        &self,
        loc: Location<F>,
        db: &Keyless<F, E, V, C, H>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        let loc_val = *loc;

        // Check this batch's local items first, then walk parent chain. If an ancestor was
        // freed, fall through to the committed DB.
        if loc_val >= self.extent.db_size() {
            if let Some(op) = read_chain_op(self, loc_val) {
                return Ok(op.into_value());
            }
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Batch read values at multiple locations.
    ///
    /// Locations must be sorted in ascending order.
    /// Returns results in the same order as the input locations.
    pub async fn get_many<E, H, C>(
        &self,
        locs: &[Location<F>],
        db: &Keyless<F, E, V, C, H>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        if locs.is_empty() {
            return Ok(Vec::new());
        }
        debug_assert!(
            locs.is_sorted(),
            "locations must be sorted in ascending order"
        );
        let mut results = Vec::with_capacity(locs.len());
        let mut db_indices = Vec::new();
        let mut db_locs = Vec::new();

        for (i, &loc) in locs.iter().enumerate() {
            let loc_val = *loc;

            if loc_val >= self.extent.db_size() {
                if let Some(op) = read_chain_op(self, loc_val) {
                    results.push(op.into_value());
                    continue;
                }
            }

            db_indices.push(i);
            db_locs.push(loc);
            results.push(None);
        }

        if !db_locs.is_empty() {
            let db_results = db.get_many(&db_locs).await?;
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
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, V>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            appends: Vec::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.extent.total_size(),
            db_size: self.extent.db_size(),
        }
    }
}
