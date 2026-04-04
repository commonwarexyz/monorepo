//! Batch mutation API for Keyless QMDBs.

use super::{operation::Operation, Keyless};
use crate::{
    journal::{authenticated, contiguous::Mutable, Error as JournalError},
    merkle::{Family, Location},
    qmdb::{any::value::ValueEncoding, Error},
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher};
use core::iter;
use std::sync::{Arc, Weak};

/// A speculative batch of operations whose root digest has not yet been computed, in contrast
/// to [`MerkleizedBatch`].
///
/// Consuming [`UnmerkleizedBatch::merkleize`] produces an `Arc<MerkleizedBatch>`.
pub struct UnmerkleizedBatch<F, H, V>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<V>: EncodeShared,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<V>>,

    /// Pending appends.
    appends: Vec<V::Value>,

    /// Parent batch in the chain. `None` for batches created directly from the DB.
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, V>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// The database size when this batch was created, used to detect stale changesets.
    db_size: u64,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding>
where
    Operation<V>: EncodeShared,
{
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<V>>>,

    /// The parent batch in the chain, if any.
    pub(super) parent: Option<Weak<Self>>,

    /// Total operations before this batch's own ops (DB + ancestor batches).
    pub(super) base_size: u64,

    /// Total operation count after this batch.
    pub(super) total_size: u64,

    /// The database size when the initial batch was created.
    pub(super) db_size: u64,
}

// Manual Clone: derive would add unnecessary Clone bounds on generic params.
impl<F: Family, D: Digest, V: ValueEncoding> Clone for MerkleizedBatch<F, D, V>
where
    Operation<V>: EncodeShared,
{
    fn clone(&self) -> Self {
        Self {
            journal_batch: Arc::clone(&self.journal_batch),
            parent: self.parent.clone(),
            base_size: self.base_size,
            total_size: self.total_size,
            db_size: self.db_size,
        }
    }
}

impl<F: Family, D: Digest, V: ValueEncoding> MerkleizedBatch<F, D, V>
where
    Operation<V>: EncodeShared,
{
    /// Iterate over ancestor batches (parent first, then grandparent, etc.).
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> {
        let mut next = self.parent.as_ref().and_then(Weak::upgrade);
        iter::from_fn(move || {
            let batch = next.take()?;
            next = batch.parent.as_ref().and_then(Weak::upgrade);
            Some(batch)
        })
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
) -> Option<Operation<V>>
where
    Operation<V>: EncodeShared,
{
    // Each batch's items span [size - items.len(), size). We compute the range from the
    // journal (strong Arcs, always intact) rather than from the QMDB-layer Weak parent
    // (which may be dead).
    let self_end = batch.journal_batch.size();
    let self_base = self_end - batch.journal_batch.items().len() as u64;
    if loc >= self_base && loc < self_end {
        return Some(batch.journal_batch.items()[(loc - self_base) as usize].clone());
    }
    for ancestor in batch.ancestors() {
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
    Operation<V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C>(keyless: &Keyless<F, E, V, C, H>, journal_size: u64) -> Self
    where
        E: Context,
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
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

    /// Resolve appends into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub fn merkleize(self, metadata: Option<V::Value>) -> Arc<MerkleizedBatch<F, H::Digest, V>> {
        let base = self.base_size;

        // Build operations: one Append per value, then Commit.
        let mut ops: Vec<Operation<V>> = Vec::with_capacity(self.appends.len() + 1);
        for value in self.appends {
            ops.push(Operation::Append(value));
        }
        ops.push(Operation::Commit(metadata));

        let total_size = base + ops.len() as u64;

        // Add operations to the journal batch and merkleize.
        let mut journal_batch = self.journal_batch;
        for op in &ops {
            journal_batch = journal_batch.add(op.clone());
        }
        let journal = Arc::new(journal_batch.merkleize());

        Arc::new(MerkleizedBatch {
            journal_batch: journal,
            parent: self.parent.as_ref().map(Arc::downgrade),
            base_size: self.base_size,
            total_size,
            db_size: self.db_size,
        })
    }
}

impl<F: Family, D: Digest, V: ValueEncoding> MerkleizedBatch<F, D, V>
where
    Operation<V>: EncodeShared,
{
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal_batch.root()
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
        C: Mutable<Item = Operation<V>> + Persistable<Error = JournalError>,
    {
        let loc_val = *loc;

        // Check this batch's local items first, then walk parent chain. If an ancestor was
        // freed, fall through to the committed DB.
        if loc_val >= self.db_size {
            if let Some(op) = read_chain_op(self, loc_val) {
                return Ok(op.into_value());
            }
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, V>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            appends: Vec::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.total_size,
            db_size: self.db_size,
        }
    }
}
