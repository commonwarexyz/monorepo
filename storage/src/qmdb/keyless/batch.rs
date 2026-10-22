//! Batch mutation API for Keyless QMDBs.

use super::{Keyless, operation::Operation};
use crate::{
    Context,
    journal::{authenticated, contiguous::Mutable},
    merkle::{Family, Location, Proof},
    qmdb::{
        Error,
        any::value::ValueEncoding,
        chain::{self, Bounds, Commitment, Compatible},
    },
};
use commonware_codec::EncodeShared;
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_parallel::Strategy;
use std::sync::{Arc, Weak};

/// Strong ref to an ancestor [`MerkleizedBatch`] in the keyless-batch chain.
type MerkleizedParent<F, H, V, S> = Arc<MerkleizedBatch<F, DigestOf<H>, V, S>>;

/// Result of merkleizing a batch.
type MerkleizeResult<F, D, V, S> = Result<Arc<MerkleizedBatch<F, D, V, S>>, Error<F>>;

/// A speculative batch of operations whose root digest has not yet been computed, in contrast
/// to [`MerkleizedBatch`].
///
/// Consuming [`UnmerkleizedBatch::merkleize`] produces a result containing an
/// `Arc<MerkleizedBatch>`.
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

    /// The state immediately before this batch's operations.
    /// This batch's i-th operation lands at location `base.size + i`.
    base: Commitment<F, H::Digest>,
}

/// A speculative batch of operations whose root digest has been computed, in contrast to
/// [`UnmerkleizedBatch`]. Reads through it return [`crate::qmdb::Error::StaleRead`] once the
/// database is at no state of its chain, for example after a sibling or one of its descendants
/// is applied (see [`crate::qmdb::chain`]).
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding, S: Strategy>
where
    Operation<F, V>: EncodeShared,
{
    /// Authenticated journal batch (Merkle state + local items).
    pub(super) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, V>, S>>,

    /// The parent batch in the chain, if any.
    pub(super) parent: Option<Weak<Self>>,

    /// Position and floor bounds for this batch chain.
    pub(super) bounds: chain::Bounds<F, D>,
}

/// Read the operation at `loc` from this batch's items or its retained ancestor items, or return
/// `None` when the caller must read from the database.
///
/// `loc` must be at or above the chain's recorded database boundary. Nonempty ancestor chunks
/// align with the newest end of the journal batch's ancestor chunks, and detached clones can hold
/// older chunks beyond those. A batch from [`Keyless::to_batch`] has no chunk, but its tip is its
/// recorded boundary, so no location in range selects it.
fn read_chain_op<F: Family, D: Digest, V: ValueEncoding, S: Strategy>(
    batch: &MerkleizedBatch<F, D, V, S>,
    loc: u64,
) -> Option<Operation<F, V>>
where
    Operation<F, V>: EncodeShared,
{
    let read = |end: u64, items: &[Operation<F, V>]| {
        let start = end - items.len() as u64;
        (start..end)
            .contains(&loc)
            .then(|| items[(loc - start) as usize].clone())
    };
    let journal = &batch.journal_batch;
    if let Some(op) = read(journal.size(), journal.items()) {
        return Some(op);
    }
    let ancestors = &batch.bounds.ancestors;
    if let Some(parent) = ancestors.first()
        && let Some(items) = journal.ancestor_items.last()
        && let Some(op) = read(*parent.size, items)
    {
        return Some(op);
    }

    let index = ancestors
        .partition_point(|state| loc < *state.size)
        .checked_sub(1)?;
    let chunk = journal.ancestor_items.len().checked_sub(index + 1)?;
    read(*ancestors[index].size, journal.ancestor_items.get(chunk)?)
}

/// Return [`Error::BelowInactivityFloor`] for a read of `loc` below `floor`.
///
/// Whether the journal still retains such a location depends on local pruning, so every database
/// at the same commitment rejects it alike. The journal retains every location at or above the
/// floor, unless the database was recovered or synced with its floor below its retained start
/// (see [`Keyless::init`]).
fn check_floor<F: Family>(loc: Location<F>, floor: Location<F>) -> Result<(), Error<F>> {
    if loc < floor {
        return Err(Error::BelowInactivityFloor(loc));
    }
    Ok(())
}

impl<F, H, V, S: Strategy> UnmerkleizedBatch<F, H, V, S>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    /// Create a batch from the DB (no parent chain).
    pub(super) fn new<E, C>(
        keyless: &Keyless<F, E, V, C, H, S>,
        base: Commitment<F, H::Digest>,
    ) -> Self
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
    {
        Self {
            journal_batch: keyless.journal.new_batch(),
            appends: Vec::new(),
            parent: None,
            base,
        }
    }

    /// The location that the next appended value will be placed at.
    pub fn size(&self) -> Location<F> {
        self.base.size + self.appends.len() as u64
    }

    /// The recorded database boundary for this batch chain.
    ///
    /// A batch created from the database uses its base. A child inherits its parent's `db`.
    fn db(&self) -> Commitment<F, H::Digest> {
        self.parent
            .as_ref()
            .map_or(self.base, |parent| parent.bounds.db)
    }

    /// The inactivity floor this batch builds on: its parent's, or `db`'s for a batch with no
    /// parent.
    fn floor<E, C>(&self, db: &Keyless<F, E, V, C, H, S>) -> Location<F>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
    {
        self.parent.as_ref().map_or_else(
            || db.inactivity_floor_loc(),
            |parent| parent.bounds.inactivity_floor,
        )
    }

    /// Check that `db` is at a state of this batch's chain and return the [`Compatible`]
    /// witness that database reads require.
    #[allow(clippy::type_complexity)]
    fn compatible<'a, E, C>(
        &self,
        db: &'a Keyless<F, E, V, C, H, S>,
    ) -> Result<Compatible<'a, Keyless<F, E, V, C, H, S>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
    {
        self.parent.as_ref().map_or_else(
            || self.base.compatible(db, db.commitment()),
            |parent| parent.bounds.compatible(db, db.commitment()),
        )
    }

    /// Append a value.
    pub fn append(mut self, value: V::Value) -> Self {
        self.appends.push(value);
        self
    }

    /// Read a value at `loc`.
    ///
    /// Reads this batch's pending appends, then its chain's operations, then the database. Returns
    /// `None` at or past [`Self::size`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain, and
    /// [`Error::BelowInactivityFloor`] if `loc` is below the inactivity floor this batch builds on.
    ///
    /// Returns [`crate::journal::Error::ItemPruned`] (as [`Error::Journal`]) for a location
    /// between the floor and the database's retained start that neither this batch nor its chain
    /// holds. Only a database recovered or synced with its floor below its retained start has such
    /// locations (see [`Keyless::init`]).
    pub async fn get<E, C>(
        &self,
        loc: Location<F>,
        db: &Keyless<F, E, V, C, H, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
    {
        let db = self.compatible(db)?;
        let loc_val = *loc;

        // Check this batch's pending appends.
        if loc_val >= self.base.size {
            let pending = usize::try_from(loc_val - *self.base.size)
                .ok()
                .and_then(|idx| self.appends.get(idx));
            return Ok(pending.cloned());
        }
        check_floor(loc, self.floor(&*db))?;

        if let Some(parent) = self.parent.as_ref()
            && loc_val >= parent.bounds.db.size
            && let Some(op) = read_chain_op(parent, loc_val)
        {
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Batch read values at multiple locations.
    ///
    /// Locations must be strictly increasing. Returns results in the same order as the input
    /// locations, each as [`Self::get`] would.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocationOutOfOrder`] if the locations are not strictly increasing, and
    /// otherwise the errors [`Self::get`] returns for each location.
    pub async fn get_many<E, C>(
        &self,
        locs: &[Location<F>],
        db: &Keyless<F, E, V, C, H, S>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
    {
        let db = self.compatible(db)?;
        if locs.is_empty() {
            return Ok(Vec::new());
        }
        super::check_increasing(locs)?;
        check_floor(locs[0], self.floor(&*db))?;
        let mut results = Vec::with_capacity(locs.len());
        let mut db_indices = Vec::new();
        let mut db_locs = Vec::new();

        for (i, &loc) in locs.iter().enumerate() {
            let loc_val = *loc;

            // Check this batch's pending appends.
            if loc_val >= self.base.size {
                let pending = usize::try_from(loc_val - *self.base.size)
                    .ok()
                    .and_then(|idx| self.appends.get(idx));
                results.push(pending.cloned());
                continue;
            }

            // Check parent operation chain.
            if let Some(parent) = self.parent.as_ref()
                && loc_val >= parent.bounds.db.size
                && let Some(op) = read_chain_op(parent, loc_val)
            {
                results.push(op.into_value());
                continue;
            }

            // Need DB fallthrough, so record index for reassembly.
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

    /// Resolve appends into operations, merkleize, and return the batch.
    ///
    /// `inactivity_floor` is the application-declared floor embedded in the commit. It must be at
    /// least the floor this batch builds on (its parent's, or the database's) and at most this
    /// batch's own commit location (`total_size - 1`). A floor past the commit would let a later
    /// `prune(floor)` remove the last readable commit.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::StaleBatch`] if `db` is not at a state of this batch's chain or an
    ///   unapplied ancestor was dropped.
    /// - Returns [`Error::FloorRegressed`] if `inactivity_floor` is below the floor this batch
    ///   builds on, and [`Error::FloorBeyondSize`] if it is past the commit location.
    #[tracing::instrument(name = "qmdb.keyless.batch.merkleize", level = "info", skip_all)]
    #[allow(clippy::type_complexity)]
    pub async fn merkleize<E, C>(
        self,
        db: &Keyless<F, E, V, C, H, S>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> MerkleizeResult<F, H::Digest, V, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
    {
        let live_ancestors: Vec<_> =
            chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors())
                .collect();
        let boundary = chain::effective_boundary(
            self.db(),
            live_ancestors.last().map(|oldest| oldest.bounds.base),
        );

        let ancestors: Vec<_> = live_ancestors
            .iter()
            .map(|batch| batch.commitment())
            .collect();
        let db = chain::merkleizable(db, db.commitment(), boundary, ancestors.iter().copied())?;
        let start_floor = self.floor(&*db);

        // Build operations: one Append per value, then Commit.
        let mut ops: Vec<Operation<F, V>> = Vec::with_capacity(self.appends.len() + 1);
        ops.extend(self.appends.into_iter().map(Operation::Append));
        ops.push(Operation::Commit(metadata, inactivity_floor));

        let total_size = self.base.size + ops.len() as u64;
        chain::validate_merkleize_floor::<F>(start_floor, inactivity_floor, total_size - 1)?;
        let inactive_peaks = F::inactive_peaks(total_size, inactivity_floor);

        // Leaf and node hashing dominate merkleization, so run them as one job through the
        // strategy (see `Journal::merkleize`).
        let (journal, root) = db
            .journal
            .merkleize(self.journal_batch, ops, inactive_peaks)
            .await?;

        // Hold ancestor batches until the journal has captured their operations and nodes.
        drop(live_ancestors);

        Ok(Arc::new(MerkleizedBatch {
            journal_batch: journal,
            parent: self.parent.as_ref().map(Arc::downgrade),
            bounds: chain::Bounds {
                base: self.base,
                db: boundary,
                tip: Commitment::new(total_size, root),
                ancestors,
                inactivity_floor,
            },
        }))
    }
}

impl<F: Family, D: Digest, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, V, S>
where
    Operation<F, V>: EncodeShared,
{
    /// Iterate over ancestor batches (parent first, then grandparent, etc.).
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, V, S> {
        chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }

    /// The [`Commitment`] this batch commits to.
    pub(super) const fn commitment(&self) -> Commitment<F, D> {
        self.bounds.tip
    }

    /// Return the speculative root.
    pub const fn root(&self) -> D {
        self.bounds.tip.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F, D> {
        &self.bounds
    }

    /// Return the operations this batch appends to the log and the location of the first.
    pub fn operations(&self) -> (Location<F>, Arc<Vec<Operation<F, V>>>) {
        (
            self.bounds.base.size,
            Arc::clone(self.journal_batch.items()),
        )
    }

    /// Inclusion proof for the operations returned by [`Self::operations`], anchored at
    /// this batch's tip. The pair verifies against [`Self::root`] via
    /// [`crate::qmdb::verify_proof`]. Together with [`Self::pinned_nodes`] they verify via
    /// [`crate::qmdb::verify_proof_and_pinned_nodes`].
    ///
    /// Nodes of unapplied ancestors are read through the chain, so those ancestors must still be
    /// held. Nodes below the chain are read from `db`'s [Merkle store][crate::merkle::mem::Mem],
    /// which retains them at least until this batch's changes are flushed (by a commit or sync
    /// after apply).
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain,
    /// [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or belongs to a
    /// dropped unapplied ancestor, and [`crate::merkle::Error::Empty`] if the batch has no
    /// operations (such as a batch from [`Keyless::to_batch`]).
    pub fn proof<E, C, H>(&self, db: &Keyless<F, E, V, C, H, S>) -> Result<Proof<F, D>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
        H: Hasher<Digest = D>,
    {
        let db = self.bounds.compatible(db, db.commitment())?;
        let inactive_peaks = F::inactive_peaks(self.bounds.tip.size, self.bounds.inactivity_floor);
        db.journal
            .speculative_proof(&self.journal_batch, inactive_peaks)
            .map_err(Into::into)
    }

    /// The Merkle frontier at the first operation returned by [`Self::operations`]
    /// ([`Family::nodes_to_pin`]), which lets a consumer holding only this batch's base rebuild
    /// compact state and replay the operations. The operations, [`Self::proof`], and pinned
    /// nodes verify against [`Self::root`] via [`crate::qmdb::verify_proof_and_pinned_nodes`].
    ///
    /// Nodes of unapplied ancestors are read through the chain, so those ancestors must still be
    /// held. Nodes below the chain are read from `db`'s [Merkle store][crate::merkle::mem::Mem],
    /// which retains them at least until this batch's changes are flushed (by a commit or sync
    /// after apply).
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain, and
    /// [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or belongs to a
    /// dropped unapplied ancestor.
    pub fn pinned_nodes<E, C, H>(&self, db: &Keyless<F, E, V, C, H, S>) -> Result<Vec<D>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, V>>,
        H: Hasher<Digest = D>,
    {
        let db = self.bounds.compatible(db, db.commitment())?;
        db.journal
            .speculative_pinned_nodes(&self.journal_batch)
            .map_err(Into::into)
    }

    /// Read a value at `loc`. Returns `None` at or past this batch's tip.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain, and
    /// [`Error::BelowInactivityFloor`] if `loc` is below this batch's inactivity floor.
    ///
    /// Returns [`crate::journal::Error::ItemPruned`] (as [`Error::Journal`]) for a location
    /// between the floor and the database's retained start that neither this batch nor its chain
    /// holds. Only a database recovered or synced with its floor below its retained start has such
    /// locations (see [`Keyless::init`]).
    pub async fn get<E, H, C>(
        &self,
        loc: Location<F>,
        db: &Keyless<F, E, V, C, H, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
        C: Mutable<Item = Operation<F, V>>,
    {
        let db = self.bounds.compatible(db, db.commitment())?;
        if loc >= self.bounds.tip.size {
            return Ok(None);
        }
        check_floor(loc, self.bounds.inactivity_floor)?;
        let loc_val = *loc;

        if loc_val >= self.bounds.db.size
            && let Some(op) = read_chain_op(self, loc_val)
        {
            return Ok(op.into_value());
        }

        // Fall through to base DB.
        db.get(loc).await
    }

    /// Batch read values at multiple locations.
    ///
    /// Locations must be strictly increasing. Returns results in the same order as the input
    /// locations, each as [`Self::get`] would.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocationOutOfOrder`] if the locations are not strictly increasing, and
    /// otherwise the errors [`Self::get`] returns for each location.
    pub async fn get_many<E, H, C>(
        &self,
        locs: &[Location<F>],
        db: &Keyless<F, E, V, C, H, S>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        H: Hasher<Digest = D>,
        C: Mutable<Item = Operation<F, V>>,
    {
        let db = self.bounds.compatible(db, db.commitment())?;
        if locs.is_empty() {
            return Ok(Vec::new());
        }
        super::check_increasing(locs)?;
        check_floor(locs[0], self.bounds.inactivity_floor)?;
        let mut results = Vec::with_capacity(locs.len());
        let mut db_indices = Vec::new();
        let mut db_locs = Vec::new();

        for (i, &loc) in locs.iter().enumerate() {
            let loc_val = *loc;

            if loc >= self.bounds.tip.size {
                results.push(None);
                continue;
            }
            if loc_val >= self.bounds.db.size
                && let Some(op) = read_chain_op(self, loc_val)
            {
                results.push(op.into_value());
                continue;
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
    /// Every unapplied ancestor in the chain must be held until the child (or any descendant) is
    /// merkleized. Otherwise, `merkleize` returns [`Error::StaleBatch`].
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, V, S>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            appends: Vec::new(),
            parent: Some(Arc::clone(self)),
            base: self.commitment(),
        }
    }
}
