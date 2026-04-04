//! A shared, generic implementation of the _Current_ QMDB.
//!
//! The impl blocks in this file define shared functionality across all Current QMDB variants.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        contiguous::{Contiguous, Mutable, Reader},
        Error as JournalError,
    },
    merkle::{
        batch::MIN_TO_PARALLELIZE,
        hasher::Hasher as _,
        mmr::{self, iterator::PeakIterator, Location, Position, StandardHasher},
        storage::Storage as MerkleStorage,
        Family as _,
    },
    metadata::{Config as MConfig, Metadata},
    qmdb::{
        any::{
            self,
            operation::{update::Update, Operation},
        },
        current::{
            batch::BitmapBatch,
            grafting,
            proof::{OperationProof, RangeProof},
        },
        operation::Operation as _,
    },
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared, DecodeExt};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_parallel::ThreadPool;
use commonware_utils::{
    bitmap::{Prunable as BitMap, Readable as BitmapReadable},
    sequence::prefixed_u64::U64,
    sync::AsyncMutex,
};
use core::{num::NonZeroU64, ops::Range};
use futures::future::try_join_all;
use rayon::prelude::*;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{error, warn};

/// Convenience alias: all `current` databases use the MMR family.
type Error = crate::qmdb::Error<mmr::Family>;

/// Prefix used for the metadata key for grafted MMR pinned nodes.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key for the number of pruned bitmap chunks.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

/// A Current QMDB implementation generic over ordered/unordered keys and variable/fixed values.
pub struct Db<
    E: Context,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
    const N: usize,
> {
    /// An authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    pub(super) any: any::db::Db<mmr::Family, E, C, I, H, U>,

    /// The bitmap over the activity status of each operation. Supports augmenting [Db] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    ///
    /// Stored as a [`BitmapBatch`] so that `apply_batch` can
    /// push layers in O(changeset) instead of deep-cloning.
    pub(super) status: BitmapBatch<N>,

    /// Each leaf corresponds to a complete bitmap chunk at the grafting height.
    /// See the [grafted leaf formula](super) in the module documentation.
    ///
    /// Internal nodes are hashed using their position in the ops MMR rather than their
    /// grafted position.
    pub(super) grafted_mmr: mmr::mem::Mmr<H::Digest>,

    /// Persists:
    /// - The number of pruned bitmap chunks at key [PRUNED_CHUNKS_PREFIX]
    /// - The grafted MMR pinned nodes at key [NODE_PREFIX]
    pub(super) metadata: AsyncMutex<Metadata<E, U64, Vec<u8>>>,

    /// Optional thread pool for parallelizing grafted leaf computation.
    pub(super) thread_pool: Option<ThreadPool>,

    /// The cached canonical root.
    /// See the [Root structure](super) section in the module documentation.
    pub(super) root: DigestOf<H>,
}

// Shared read-only functionality.
impl<E, C, I, H, U, const N: usize> Db<E, C, I, H, U, N>
where
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.any.inactivity_floor_loc()
    }

    /// Whether the snapshot currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.any.is_empty()
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<U::Value>, Error> {
        self.any.get_metadata().await
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location> {
        self.any.bounds().await
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc`
    /// in the log with the provided `root`, having the activity status described by `chunks`.
    pub fn verify_range_proof(
        hasher: &mut H,
        proof: &RangeProof<H::Digest>,
        start_loc: Location,
        ops: &[Operation<mmr::Family, U>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        proof.verify(hasher, start_loc, ops, chunks, root)
    }
}

// Functionality requiring non-mutable journal.
impl<E, U, C, I, H, const N: usize> Db<E, C, I, H, U, N>
where
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    /// Returns a virtual [grafting::Storage] over the grafted MMR and ops MMR. For positions at or
    /// above the grafting height, returns grafted MMR node. For positions below the grafting
    /// height, the ops MMR is used.
    fn grafted_storage(&self) -> impl MerkleStorage<mmr::Family, Digest = H::Digest> + '_ {
        grafting::Storage::new(
            &self.grafted_mmr,
            grafting::height::<N>(),
            &self.any.log.merkle,
        )
    }

    /// Returns the canonical root.
    /// See the [Root structure](super) section in the module documentation.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// Returns the ops MMR root.
    ///
    /// This is the root of the raw operations log, without the activity bitmap. It is used as the
    /// sync target because the sync engine verifies batches against the ops MMR, not the canonical
    /// root.
    ///
    /// See the [Root structure](super) section in the module documentation.
    pub fn ops_root(&self) -> H::Digest {
        self.any.log.root()
    }

    /// Snapshot of the grafted MMR for use in batch chains.
    pub(super) fn grafted_snapshot(&self) -> Arc<mmr::batch::MerkleizedBatch<H::Digest>> {
        mmr::batch::MerkleizedBatch::from_mem(&self.grafted_mmr)
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> super::batch::UnmerkleizedBatch<H, U, N> {
        super::batch::UnmerkleizedBatch::new(
            self.any.new_batch(),
            None, // No parent -- created from DB.
            self.grafted_snapshot(),
            self.status.clone(),
        )
    }

    /// Returns a proof for the operation at `loc`.
    pub(super) async fn operation_proof(
        &self,
        hasher: &mut H,
        loc: Location,
    ) -> Result<OperationProof<H::Digest, N>, Error> {
        let storage = self.grafted_storage();
        let ops_root = self.any.log.root();
        OperationProof::new(hasher, &self.status, &storage, loc, ops_root).await
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range. A truncated range (from hitting the max) can be detected by
    /// looking at the length of the returned operations vector. Also returns the bitmap chunks
    /// required to verify the proof.
    ///
    /// # Errors
    ///
    /// Returns [Error::OperationPruned] if `start_loc` falls in a pruned bitmap chunk.
    /// Returns [mmr::Error::LocationOverflow] if `start_loc` > [crate::merkle::Family::MAX_LEAVES].
    /// Returns [mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<
        (
            RangeProof<H::Digest>,
            Vec<Operation<mmr::Family, U>>,
            Vec<[u8; N]>,
        ),
        Error,
    > {
        let storage = self.grafted_storage();
        let ops_root = self.any.log.root();
        RangeProof::new_with_ops(
            hasher,
            &self.status,
            &storage,
            &self.any.log,
            start_loc,
            max_ops,
            ops_root,
        )
        .await
    }
}

// Functionality requiring mutable journal.
impl<E, U, C, I, H, const N: usize> Db<E, C, I, H, U, N>
where
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    /// Returns an ops-level historical proof for the specified range.
    ///
    /// Unlike [`range_proof`](Self::range_proof) which returns grafted proofs incorporating the
    /// activity bitmap, this returns standard MMR proofs suitable for state sync.
    pub async fn ops_historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(mmr::Proof<H::Digest>, Vec<Operation<mmr::Family, U>>), Error> {
        self.any
            .historical_proof(historical_size, start_loc, max_ops)
            .await
    }

    /// Return the pinned MMR nodes for a lower operation boundary of `loc`.
    pub async fn pinned_nodes_at(&self, loc: Location) -> Result<Vec<H::Digest>, Error> {
        self.any.pinned_nodes_at(loc).await
    }

    /// Collapse accumulated `Layer` chains in the bitmap and grafted MMR into flat `Base`
    /// representations.
    ///
    /// Each [`Db::apply_batch`] pushes a new `Layer` on both the bitmap and the grafted MMR.
    /// These layers are cheap to create (O(changeset)) but make subsequent reads walk the full
    /// chain. Calling `flatten` collapses the chain into a single `Base`, bounding lookup cost
    /// and reducing memory overhead from stale intermediate layers.
    ///
    /// This is called automatically by [`Db::prune`]. Callers that apply many batches without
    /// pruning should call this periodically.
    pub fn flatten(&mut self) {
        self.status.flatten();
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [mmr::Error::LocationOverflow] if `prune_loc` > [crate::merkle::Family::MAX_LEAVES].
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.flatten();

        // Prune bitmap chunks below the inactivity floor.
        let BitmapBatch::Base(base) = &mut self.status else {
            unreachable!("flatten() guarantees Base");
        };
        Arc::make_mut(base).prune_to_bit(*self.any.inactivity_floor_loc);

        // Prune the grafted MMR to match the bitmap's pruned chunks.
        let pruned_chunks = self.status.pruned_chunks() as u64;
        if pruned_chunks > 0 {
            let prune_loc_grafted = Location::new(pruned_chunks);
            let bounds_start = self.grafted_mmr.bounds().start;
            let grafted_prune_pos =
                Position::try_from(prune_loc_grafted).expect("valid leaf count");
            if prune_loc_grafted > bounds_start {
                let root = *self.grafted_mmr.root();
                let size = self.grafted_mmr.size();

                let mut pinned = BTreeMap::new();
                for (pos, _) in PeakIterator::new(grafted_prune_pos) {
                    pinned.insert(
                        pos,
                        self.grafted_mmr
                            .get_node(pos)
                            .expect("pinned peak must exist"),
                    );
                }
                let mut retained = Vec::with_capacity((*size - *grafted_prune_pos) as usize);
                for p in *grafted_prune_pos..*size {
                    retained.push(
                        self.grafted_mmr
                            .get_node(Position::new(p))
                            .expect("retained node must exist"),
                    );
                }
                self.grafted_mmr = mmr::mem::Mmr::from_pruned_with_retained(
                    root,
                    grafted_prune_pos,
                    pinned,
                    retained,
                );
            }
        }

        // Persist grafted MMR pruning state before pruning the ops log. If the subsequent
        // `any.prune` fails, the metadata is ahead of the log, which is safe: on recovery,
        // `build_grafted_mmr` will recompute from the (un-pruned) log and the metadata
        // simply records peaks that haven't been pruned yet. The reverse order would be unsafe:
        // a pruned log with stale metadata would lose peak digests permanently.
        self.sync_metadata().await?;

        self.any.prune(prune_loc).await
    }

    /// Rewind the database to `size` operations, where `size` is the location of the next append.
    ///
    /// This rewinds the underlying Any database and rebuilds the Current overlay state (bitmap,
    /// grafted MMR, and canonical root) for the rewound size.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `size` is not a valid rewind target
    /// - the target's required logical range is not fully retained (for Current, this includes the
    ///   underlying Any inactivity-floor boundary and bitmap pruning boundary)
    /// - `size - 1` is not a commit operation
    /// - `size` is below the bitmap pruning boundary
    ///
    /// Any error from this method is fatal for this handle. Rewind may mutate state in the
    /// underlying Any database before this Current overlay finishes rebuilding. Callers must drop
    /// this database handle after any `Err` from `rewind` and reopen from storage.
    ///
    /// A successful rewind is not restart-stable until a subsequent [`Db::commit`] or
    /// [`Db::sync`].
    pub async fn rewind(&mut self, size: Location) -> Result<(), Error> {
        self.flatten();

        let rewind_size = *size;
        let current_size = *self.any.last_commit_loc + 1;
        if rewind_size == current_size {
            return Ok(());
        }
        if rewind_size == 0 || rewind_size > current_size {
            return Err(Error::Journal(JournalError::InvalidRewind(rewind_size)));
        }

        let pruned_chunks = self.status.pruned_chunks();
        let pruned_bits = (pruned_chunks as u64)
            .checked_mul(BitMap::<N>::CHUNK_SIZE_BITS)
            .ok_or_else(|| Error::DataCorrupted("pruned ops leaves overflow"))?;
        if rewind_size < pruned_bits {
            return Err(Error::Journal(JournalError::ItemPruned(rewind_size - 1)));
        }

        // Ensure the target commit's logical range is fully representable with the current
        // bitmap pruning boundary. Even if the ops log still retains older entries, rewinding
        // to a commit with floor below `pruned_bits` would require bitmap chunks we've already
        // discarded.
        {
            let reader = self.any.log.reader().await;
            let rewind_last_loc = Location::new(rewind_size - 1);
            let rewind_last_op = reader.read(*rewind_last_loc).await?;
            let Some(rewind_floor) = rewind_last_op.has_floor() else {
                return Err(Error::UnexpectedData(rewind_last_loc));
            };
            if *rewind_floor < pruned_bits {
                return Err(Error::Journal(JournalError::ItemPruned(*rewind_floor)));
            }
        }

        // Extract pinned nodes for the existing pruning boundary from the in-memory grafted MMR.
        let pinned_nodes = if pruned_chunks > 0 {
            let mmr_size = Location::new(pruned_chunks as u64);
            let mut pinned_nodes = Vec::new();
            for pos in mmr::Family::nodes_to_pin(mmr_size) {
                let digest = self
                    .grafted_mmr
                    .get_node(pos)
                    .ok_or(mmr::Error::MissingNode(pos))?;
                pinned_nodes.push(digest);
            }
            pinned_nodes
        } else {
            Vec::new()
        };

        // Rewind underlying ops log + Any state. If a later overlay rebuild step fails, this
        // handle may be internally diverged and must be dropped by the caller.
        let restored_locs = self.any.rewind(size).await?;

        // Patch bitmap: truncate to rewound size, then mark restored locations as active.
        {
            let BitmapBatch::Base(base) = &mut self.status else {
                unreachable!("flatten() guarantees Base");
            };
            let status = Arc::get_mut(base).expect("flatten ensures sole owner");
            status.truncate(rewind_size);
            for loc in &restored_locs {
                status.set_bit(**loc, true);
            }
            status.set_bit(rewind_size - 1, true);
        }
        let BitmapBatch::Base(status) = &self.status else {
            unreachable!("flatten() guarantees Base");
        };
        let status = status.as_ref();

        // Rebuild grafted MMR and canonical root for the patched bitmap.
        let hasher = StandardHasher::<H>::new();
        let grafted_mmr = build_grafted_mmr::<H, N>(
            &hasher,
            status,
            &pinned_nodes,
            &self.any.log.merkle,
            self.thread_pool.as_ref(),
        )
        .await?;
        let storage =
            grafting::Storage::new(&grafted_mmr, grafting::height::<N>(), &self.any.log.merkle);
        let partial_chunk = partial_chunk(status);
        let ops_root = self.any.log.root();
        let root = compute_db_root(&hasher, &storage, partial_chunk, &ops_root).await?;

        self.grafted_mmr = grafted_mmr;
        self.root = root;

        Ok(())
    }

    /// Sync the metadata to disk.
    pub(crate) async fn sync_metadata(&self) -> Result<(), Error> {
        let mut metadata = self.metadata.lock().await;
        metadata.clear();

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        metadata.put(
            key,
            (self.status.pruned_chunks() as u64).to_be_bytes().to_vec(),
        );

        // Write the grafted MMR pinned nodes. These are the ops-space peaks covering the
        // pruned portion of the bitmap.
        let pruned_ops = (self.status.pruned_chunks() as u64)
            .checked_mul(BitMap::<N>::CHUNK_SIZE_BITS)
            .ok_or_else(|| Error::DataCorrupted("pruned ops leaves overflow"))?;
        let ops_mmr_size = Position::try_from(Location::new(pruned_ops))?;
        let grafting_height = grafting::height::<N>();
        for (i, (ops_pos, _)) in PeakIterator::new(ops_mmr_size).enumerate() {
            let grafted_pos = grafting::ops_to_grafted_pos(ops_pos, grafting_height);
            let digest = self
                .grafted_mmr
                .get_node(grafted_pos)
                .ok_or(mmr::Error::MissingNode(ops_pos))?;
            let key = U64::new(NODE_PREFIX, i as u64);
            metadata.put(key, digest.to_vec());
        }

        metadata.sync().await.map_err(mmr::Error::Metadata)?;

        Ok(())
    }
}

// Functionality requiring mutable + persistable journal.
impl<E, U, C, I, H, const N: usize> Db<E, C, I, H, U, N>
where
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<mmr::Family, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    /// Durably commit the journal state published by prior [`Db::apply_batch`]
    /// calls.
    pub async fn commit(&self) -> Result<(), Error> {
        self.any.commit().await
    }

    /// Sync all database state to disk.
    pub async fn sync(&self) -> Result<(), Error> {
        self.any.sync().await?;

        // Write the bitmap pruning boundary to disk so that next startup doesn't have to
        // re-Merkleize the inactive portion up to the inactivity floor.
        self.sync_metadata().await
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        // Clean up bitmap metadata partition.
        self.metadata.into_inner().destroy().await?;

        // Clean up Any components (MMR and log).
        self.any.destroy().await
    }
}

impl<E, U, C, I, H, const N: usize> Db<E, C, I, H, U, N>
where
    E: Context,
    U: Update + 'static,
    C: Mutable<Item = Operation<mmr::Family, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    /// Apply a batch to the database, returning the range of written operations.
    ///
    /// A batch is valid only if every batch applied to the database since this batch's
    /// ancestor chain was created is an ancestor of this batch. Applying a batch from a
    /// different fork returns [`Error::StaleBatch`].
    ///
    /// This publishes the batch to the in-memory Current view and appends it to the journal,
    /// but does not durably persist it. Call [`Db::commit`] or [`Db::sync`] to guarantee
    /// durability.
    pub async fn apply_batch(
        &mut self,
        batch: Arc<super::batch::MerkleizedBatch<H::Digest, U, N>>,
    ) -> Result<Range<Location>, Error> {
        // Staleness is checked by self.any.apply_batch() below.
        let db_size = *self.any.last_commit_loc + 1;
        let skip_ancestors = db_size > batch.inner.db_size;

        // 1. Apply inner any-layer batch.
        let range = self.any.apply_batch(Arc::clone(&batch.inner)).await?;

        // 2. Apply bitmap. When ancestors are committed, their bitmap changes are already
        // applied; only push this batch's local changes.
        if skip_ancestors {
            self.status.push_changeset(
                batch.bitmap_pushes.as_ref().clone(),
                (*batch.bitmap_clears).clone(),
            );
        } else {
            let mut pushes = Vec::new();
            let mut clears = super::batch::ClearSet::with_capacity(0);
            for p in &batch.ancestor_bitmap_pushes {
                pushes.extend_from_slice(p);
            }
            for c in &batch.ancestor_bitmap_clears {
                clears.merge(c);
            }
            pushes.extend_from_slice(&batch.bitmap_pushes);
            clears.merge(&batch.bitmap_clears);
            self.status.push_changeset(pushes, clears);
        }

        // 3. Apply grafted MMR.
        self.grafted_mmr.apply_batch(&batch.grafted)?;

        // 4. Canonical root.
        self.root = batch.canonical_root;

        Ok(range)
    }
}

impl<E, U, C, I, H, const N: usize> Persistable for Db<E, C, I, H, U, N>
where
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<mmr::Family, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    type Error = Error;

    async fn commit(&self) -> Result<(), Error> {
        Self::commit(self).await
    }

    async fn sync(&self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

/// Returns `Some((last_chunk, next_bit))` if the bitmap has an incomplete trailing chunk, or
/// `None` if all bits fall on complete chunk boundaries.
pub(super) fn partial_chunk<B: BitmapReadable<N>, const N: usize>(
    bitmap: &B,
) -> Option<([u8; N], u64)> {
    let (last_chunk, next_bit) = bitmap.last_chunk();
    if next_bit == BitMap::<N>::CHUNK_SIZE_BITS {
        None
    } else {
        Some((last_chunk, next_bit))
    }
}

/// Compute the canonical root from the ops root, grafted MMR root, and optional partial chunk.
///
/// See the [Root structure](super) section in the module documentation.
pub(super) fn combine_roots<H: Hasher>(
    hasher: &StandardHasher<H>,
    ops_root: &H::Digest,
    grafted_mmr_root: &H::Digest,
    partial: Option<(u64, &H::Digest)>,
) -> H::Digest {
    match partial {
        Some((next_bit, last_chunk_digest)) => {
            let next_bit = next_bit.to_be_bytes();
            hasher.hash([
                ops_root.as_ref(),
                grafted_mmr_root.as_ref(),
                next_bit.as_slice(),
                last_chunk_digest.as_ref(),
            ])
        }
        None => hasher.hash([ops_root.as_ref(), grafted_mmr_root.as_ref()]),
    }
}

/// Compute the canonical root digest of a [Db].
///
/// See the [Root structure](super) section in the module documentation.
pub(super) async fn compute_db_root<
    H: Hasher,
    G: mmr::Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>,
    S: MerkleStorage<mmr::Family, Digest = H::Digest>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    storage: &grafting::Storage<'_, H::Digest, G, S>,
    partial_chunk: Option<([u8; N], u64)>,
    ops_root: &H::Digest,
) -> Result<H::Digest, Error> {
    let grafted_mmr_root = compute_grafted_mmr_root(hasher, storage).await?;
    let partial = partial_chunk.map(|(chunk, next_bit)| {
        let digest = hasher.digest(&chunk);
        (next_bit, digest)
    });
    Ok(combine_roots(
        hasher,
        ops_root,
        &grafted_mmr_root,
        partial.as_ref().map(|(nb, d)| (*nb, d)),
    ))
}

/// Compute the root of the grafted MMR.
///
/// `storage` is the grafted storage over the grafted MMR and the ops MMR.
pub(super) async fn compute_grafted_mmr_root<
    H: Hasher,
    G: mmr::Readable<Family = mmr::Family, Digest = H::Digest, Error = mmr::Error>,
    S: MerkleStorage<mmr::Family, Digest = H::Digest>,
>(
    hasher: &StandardHasher<H>,
    storage: &grafting::Storage<'_, H::Digest, G, S>,
) -> Result<H::Digest, Error> {
    let size = storage.size().await;
    let leaves = Location::try_from(size)?;

    // Collect peak digests from the grafted storage, which transparently dispatches
    // to the grafted MMR or the ops MMR based on height.
    let mut peaks = Vec::new();
    for (peak_pos, _) in PeakIterator::new(size) {
        let digest = storage
            .get_node(peak_pos)
            .await?
            .ok_or(mmr::Error::MissingNode(peak_pos))?;
        peaks.push(digest);
    }

    Ok(hasher.root(leaves, peaks.iter()))
}

/// Compute grafted leaf digests for the given bitmap chunks as `(ops_pos, digest)` pairs.
///
/// Each grafted leaf is `hash(chunk || ops_subtree_root)`, except for all-zero chunks where
/// the grafted leaf equals the ops subtree root directly (zero-chunk identity).
///
/// When a thread pool is provided and there are enough chunks, hashing is parallelized.
pub(super) async fn compute_grafted_leaves<H: Hasher, const N: usize>(
    hasher: &StandardHasher<H>,
    ops_mmr: &impl MerkleStorage<mmr::Family, Digest = H::Digest>,
    chunks: impl IntoIterator<Item = (usize, [u8; N])>,
    pool: Option<&ThreadPool>,
) -> Result<Vec<(Position, H::Digest)>, Error> {
    let grafting_height = grafting::height::<N>();

    // (ops_pos, ops_digest, chunk) for each chunk, where ops_pos is the position of the ops MMR
    // node on which to graft the chunk, and ops_digest is the digest of that node.
    let inputs = try_join_all(chunks.into_iter().map(|(chunk_idx, chunk)| {
        let ops_pos = grafting::chunk_idx_to_ops_pos(chunk_idx as u64, grafting_height);
        async move {
            let ops_digest = ops_mmr
                .get_node(ops_pos)
                .await?
                .ok_or(mmr::Error::MissingGraftedLeaf(ops_pos))?;
            Ok::<_, Error>((ops_pos, ops_digest, chunk))
        }
    }))
    .await?;

    // Compute grafted leaf for each chunk.
    let zero_chunk = [0u8; N];
    Ok(match pool.filter(|_| inputs.len() >= MIN_TO_PARALLELIZE) {
        Some(pool) => pool.install(|| {
            inputs
                .into_par_iter()
                .map_init(
                    || hasher.clone(),
                    |h, (ops_pos, ops_digest, chunk)| {
                        if chunk == zero_chunk {
                            (ops_pos, ops_digest)
                        } else {
                            (ops_pos, h.hash([chunk.as_slice(), ops_digest.as_ref()]))
                        }
                    },
                )
                .collect()
        }),
        None => inputs
            .into_iter()
            .map(|(ops_pos, ops_digest, chunk)| {
                if chunk == zero_chunk {
                    (ops_pos, ops_digest)
                } else {
                    (
                        ops_pos,
                        hasher.hash([chunk.as_slice(), ops_digest.as_ref()]),
                    )
                }
            })
            .collect(),
    })
}

/// Build a grafted [mmr::mem::Mmr] from scratch using bitmap chunks and the ops MMR.
///
/// For each non-pruned complete chunk (index in `pruned_chunks..complete_chunks`), reads the
/// ops MMR node at the grafting height to compute the grafted leaf (see the
/// [grafted leaf formula](super) in the module documentation). The caller must ensure that all
/// ops MMR nodes for chunks >= `bitmap.pruned_chunks()` are still accessible in the ops MMR
/// (i.e., not pruned from the journal).
pub(super) async fn build_grafted_mmr<H: Hasher, const N: usize>(
    hasher: &StandardHasher<H>,
    bitmap: &BitMap<N>,
    pinned_nodes: &[H::Digest],
    ops_mmr: &impl MerkleStorage<mmr::Family, Digest = H::Digest>,
    pool: Option<&ThreadPool>,
) -> Result<mmr::mem::Mmr<H::Digest>, Error> {
    let grafting_height = grafting::height::<N>();
    let pruned_chunks = bitmap.pruned_chunks();
    let complete_chunks = bitmap.complete_chunks();

    // Compute grafted leaves for each unpruned complete chunk.
    let leaves = compute_grafted_leaves::<H, N>(
        hasher,
        ops_mmr,
        (pruned_chunks..complete_chunks).map(|chunk_idx| (chunk_idx, *bitmap.get_chunk(chunk_idx))),
        pool,
    )
    .await?;

    // Build a base Mmr: either from pruned components or empty.
    let grafted_hasher = grafting::GraftedHasher::new(hasher.clone(), grafting_height);
    let mut grafted_mmr = if pruned_chunks > 0 {
        let grafted_pruning_boundary = Location::new(pruned_chunks as u64);
        mmr::mem::Mmr::from_components(
            &grafted_hasher,
            Vec::new(),
            grafted_pruning_boundary,
            pinned_nodes.to_vec(),
        )?
    } else {
        mmr::mem::Mmr::new(&grafted_hasher)
    };

    // Add each grafted leaf digest.
    if !leaves.is_empty() {
        let batch = {
            let mut batch = grafted_mmr.new_batch().with_pool(pool.cloned());
            for &(_ops_pos, digest) in &leaves {
                batch = batch.add_leaf_digest(digest);
            }
            batch.merkleize(&grafted_hasher, &grafted_mmr)
        };
        grafted_mmr.apply_batch(&batch)?;
    }

    Ok(grafted_mmr)
}

/// Load the metadata and recover the pruning state persisted by previous runs.
///
/// The metadata store holds two kinds of entries (keyed by prefix):
/// - **Pruned chunks count** ([PRUNED_CHUNKS_PREFIX]): the number of bitmap chunks that have been
///   pruned. This tells us where the active portion of the bitmap begins.
/// - **Pinned node digests** ([NODE_PREFIX]): grafted MMR digests at peak positions whose
///   underlying data has been pruned. These are needed to recompute the grafted MMR root without
///   the pruned chunks.
///
/// Returns `(metadata_handle, pruned_chunks, pinned_node_digests)`.
pub(super) async fn init_metadata<E: Context, D: Digest>(
    context: E,
    partition: &str,
) -> Result<(Metadata<E, U64, Vec<u8>>, usize, Vec<D>), Error> {
    let metadata_cfg = MConfig {
        partition: partition.into(),
        codec_config: ((0..).into(), ()),
    };
    let metadata =
        Metadata::<_, U64, Vec<u8>>::init(context.with_label("metadata"), metadata_cfg).await?;

    let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
    let pruned_chunks = match metadata.get(&key) {
        Some(bytes) => u64::from_be_bytes(bytes.as_slice().try_into().map_err(|_| {
            error!("pruned chunks value not a valid u64");
            Error::DataCorrupted("pruned chunks value not a valid u64")
        })?),
        None => {
            warn!("bitmap metadata does not contain pruned chunks, initializing as empty");
            0
        }
    } as usize;

    // Load pinned nodes if database was pruned. We use nodes_to_pin on the grafted leaf count
    // to determine how many peaks to read. (Multiplying pruned_chunks by chunk_size is a
    // left-shift, preserving popcount, so the peak count is the same in grafted or ops space.)
    let pinned_nodes = if pruned_chunks > 0 {
        let pruned_loc = Location::new(pruned_chunks as u64);
        if !pruned_loc.is_valid() {
            return Err(Error::DataCorrupted("pruned chunks exceeds MAX_LEAVES"));
        }
        let mut pinned = Vec::new();
        for (index, pos) in mmr::Family::nodes_to_pin(pruned_loc).enumerate() {
            let metadata_key = U64::new(NODE_PREFIX, index as u64);
            let Some(bytes) = metadata.get(&metadata_key) else {
                return Err(mmr::Error::MissingNode(pos).into());
            };
            let digest = D::decode(bytes.as_ref()).map_err(|_| mmr::Error::MissingNode(pos))?;
            pinned.push(digest);
        }
        pinned
    } else {
        Vec::new()
    };

    Ok((metadata, pruned_chunks, pinned_nodes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::FixedSize;
    use commonware_cryptography::{sha256, Sha256};
    use commonware_utils::bitmap::Prunable as PrunableBitMap;

    const N: usize = sha256::Digest::SIZE;

    #[test]
    fn partial_chunk_single_bit() {
        let mut bm = PrunableBitMap::<N>::new();
        bm.push(true);
        let result = partial_chunk::<PrunableBitMap<N>, N>(&bm);
        assert!(result.is_some());
        let (chunk, next_bit) = result.unwrap();
        assert_eq!(next_bit, 1);
        assert_eq!(chunk[0], 1); // bit 0 set
    }

    #[test]
    fn partial_chunk_aligned() {
        let mut bm = PrunableBitMap::<N>::new();
        for _ in 0..PrunableBitMap::<N>::CHUNK_SIZE_BITS {
            bm.push(true);
        }
        let result = partial_chunk::<PrunableBitMap<N>, N>(&bm);
        assert!(result.is_none());
    }

    #[test]
    fn partial_chunk_partial() {
        let mut bm = PrunableBitMap::<N>::new();
        for _ in 0..(PrunableBitMap::<N>::CHUNK_SIZE_BITS + 5) {
            bm.push(true);
        }
        let result = partial_chunk::<PrunableBitMap<N>, N>(&bm);
        assert!(result.is_some());
        let (_chunk, next_bit) = result.unwrap();
        assert_eq!(next_bit, 5);
    }

    #[test]
    fn combine_roots_deterministic() {
        let h1 = StandardHasher::<Sha256>::new();
        let h2 = StandardHasher::<Sha256>::new();
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let r1 = combine_roots(&h1, &ops, &grafted, None);
        let r2 = combine_roots(&h2, &ops, &grafted, None);
        assert_eq!(r1, r2);
    }

    #[test]
    fn combine_roots_with_partial_differs() {
        let h1 = StandardHasher::<Sha256>::new();
        let h2 = StandardHasher::<Sha256>::new();
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let partial_digest = Sha256::hash(b"partial");

        let without = combine_roots(&h1, &ops, &grafted, None);
        let with = combine_roots(&h2, &ops, &grafted, Some((5, &partial_digest)));
        assert_ne!(without, with);
    }

    #[test]
    fn combine_roots_different_ops_root() {
        let h1 = StandardHasher::<Sha256>::new();
        let h2 = StandardHasher::<Sha256>::new();
        let ops_a = Sha256::hash(b"ops_a");
        let ops_b = Sha256::hash(b"ops_b");
        let grafted = Sha256::hash(b"grafted");

        let r1 = combine_roots(&h1, &ops_a, &grafted, None);
        let r2 = combine_roots(&h2, &ops_b, &grafted, None);
        assert_ne!(r1, r2);
    }
}
