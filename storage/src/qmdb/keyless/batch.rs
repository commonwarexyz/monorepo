//! Batch mutation API for Keyless QMDBs.

use super::{operation::Operation, Keyless};
use crate::{
    journal::{authenticated, contiguous::Mutable, Error as JournalError},
    merkle::{Family, Location},
    qmdb::{
        any::value::ValueEncoding,
        batch_chain::{self, Bounds},
        Error,
    },
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use std::sync::{Arc, Weak};

/// Strong ref to an ancestor [`MerkleizedBatch`] in the keyless-batch chain.
type MerkleizedParent<F, H, V, S> = Arc<MerkleizedBatch<F, <H as Hasher>::Digest, V, S>>;

/// A speculative batch of operations whose root digest has not yet been computed, in contrast
/// to [`MerkleizedBatch`].
///
/// Consuming [`UnmerkleizedBatch::merkleize`] produces an `Arc<MerkleizedBatch>`.
pub struct UnmerkleizedBatch<F, H, V, S: Strategy>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, V>, S>,

    /// Pending appends.
    appends: Vec<V::Value>,

    /// Parent batch in the chain. `None` for batches created directly from the DB.
    parent: Option<MerkleizedParent<F, H, V, S>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// The database size when this batch was created, used to detect stale batches.
    db_size: u64,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding, S: Strategy>
where
    Operation<F, V>: EncodeShared,
{
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, V>, S>>,

    /// Cached operations root after applying this batch.
    pub(super) root: D,

    /// The parent batch in the chain, if any.
    pub(super) parent: Option<Weak<Self>>,

    /// Position and floor bounds for this batch chain.
    pub(super) bounds: batch_chain::Bounds<F>,
}

impl<F: Family, D: Digest, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, V, S>
where
    Operation<F, V>: EncodeShared,
{
    /// Iterate over ancestor batches (parent first, then grandparent, etc.).
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }
}

/// Read a single operation from the parent chain at the given location.
///
/// Returns `None` if the location cannot be found in the live parent chain (e.g. the
/// owning ancestor was committed and freed). Callers should fall through to the committed
/// DB in that case.
fn read_chain_op<F: Family, D: Digest, V: ValueEncoding, S: Strategy>(
    batch: &MerkleizedBatch<F, D, V, S>,
    loc: u64,
) -> Option<Operation<F, V>>
where
    Operation<F, V>: EncodeShared,
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

impl<F, H, V, S: Strategy> UnmerkleizedBatch<F, H, V, S>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    /// Create a batch from a committed DB (no parent chain).
    pub(super) fn new<E, C>(keyless: &Keyless<F, E, V, C, H, S>, journal_size: u64) -> Self
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
        db: &Keyless<F, E, V, C, H, S>,
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
    /// Locations must be strictly increasing.
    /// Returns results in the same order as the input locations.
    pub async fn get_many<E, C>(
        &self,
        locs: &[Location<F>],
        db: &Keyless<F, E, V, C, H, S>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        if locs.is_empty() {
            return Ok(Vec::new());
        }
        debug_assert!(
            locs.windows(2).all(|w| w[0] < w[1]),
            "locations must be strictly increasing"
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
        db: &Keyless<F, E, V, C, H, S>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, V, S>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        let base = self.base_size;

        // Build operations: one Append per value, then Commit.
        let mut ops: Vec<Operation<F, V>> = Vec::with_capacity(self.appends.len() + 1);
        for value in self.appends {
            ops.push(Operation::Append(value));
        }
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
        let journal = db.journal.with_mem(|mem| journal_batch.merkleize(mem));
        let root = db
            .journal
            .with_mem(|mem| journal.root(mem, &db.journal.hasher, inactive_peaks))
            .expect("inactive_peaks computed from batch size");

        let ancestors =
            batch_chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors());
        let ancestors = batch_chain::collect_ancestor_bounds(
            ancestors,
            |batch| batch.bounds.inactivity_floor,
            |batch| batch.bounds.total_size,
        );

        Arc::new(MerkleizedBatch {
            journal_batch: journal,
            root,
            parent: self.parent.as_ref().map(Arc::downgrade),
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

impl<F: Family, D: Digest, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, V, S>
where
    Operation<F, V>: EncodeShared,
{
    /// Return the inactivity floor declared by this batch's commit.
    pub const fn inactivity_floor(&self) -> Location<F> {
        self.bounds.inactivity_floor
    }

    /// Return the location of the next append after this batch commits.
    pub const fn size(&self) -> Location<F> {
        Location::new(self.bounds.total_size)
    }

    /// Return the speculative root.
    pub const fn root(&self) -> D {
        self.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F> {
        &self.bounds
    }

    /// Read a value at `loc`.
    pub async fn get<E, H, C>(
        &self,
        loc: Location<F>,
        db: &Keyless<F, E, V, C, H, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
        C: Mutable<Item = Operation<F, V>> + Persistable<Error = JournalError>,
    {
        let loc_val = *loc;

        // Check this batch's local items first, then walk parent chain. If an ancestor was
        // freed, fall through to the committed DB.
        if loc_val >= self.bounds.db_size {
            if let Some(op) = read_chain_op(self, loc_val) {
                return Ok(op.into_value());
            }
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Batch read values at multiple locations.
    ///
    /// Locations must be strictly increasing.
    /// Returns results in the same order as the input locations.
    pub async fn get_many<E, H, C>(
        &self,
        locs: &[Location<F>],
        db: &Keyless<F, E, V, C, H, S>,
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
            locs.windows(2).all(|w| w[0] < w[1]),
            "locations must be strictly increasing"
        );
        let mut results = Vec::with_capacity(locs.len());
        let mut db_indices = Vec::new();
        let mut db_locs = Vec::new();

        for (i, &loc) in locs.iter().enumerate() {
            let loc_val = *loc;

            if loc_val >= self.bounds.db_size {
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
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, V, S>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            appends: Vec::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.bounds.total_size,
            db_size: self.bounds.db_size,
        }
    }
}
