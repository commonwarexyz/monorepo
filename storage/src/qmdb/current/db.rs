//! A shared, generic implementation of the _Current_ QMDB.
//!
//! The impl blocks in this file define shared functionality across all Current QMDB variants.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        contiguous::{Contiguous, Mutable},
        Error as JournalError,
    },
    merkle::{
        self, batch::MIN_TO_PARALLELIZE, hasher::Standard as StandardHasher, mem::Mem,
        storage::Storage as MerkleStorage, Location, Position,
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
            witness,
        },
        Error,
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

/// Prefix used for the metadata key for grafted tree pinned nodes.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key for the number of pruned bitmap chunks.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

/// Prefix used for the metadata key for grafted root witness digests.
///
/// Each entry is a `(grafted_position, digest)` pair for a non-pinned interior node in the
/// pruned grafted subtree that `compute_grafted_root` may need when delayed MMB merges expose
/// nodes no longer individually materialized in the grafted Mem. Entries are captured before
/// pruning and rebuilt at each prune cycle; see [`witness::rebuild_grafted_root_witness`] for
/// the selection algorithm.
const GRAFTED_ROOT_WITNESS_PREFIX: u8 = 2;

pub(super) use super::witness::GraftedRootWitness;

/// A Current QMDB implementation generic over ordered/unordered keys and variable/fixed values.
pub struct Db<
    F: merkle::Graftable,
    E: Context,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: Send + Sync,
    const N: usize,
> {
    /// An authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    pub(super) any: any::db::Db<F, E, C, I, H, U>,

    /// The bitmap over the activity status of each operation. Supports augmenting [Db] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    ///
    /// Stored as a [`BitmapBatch`] so that `apply_batch` can
    /// push layers in O(batch) instead of deep-cloning.
    pub(super) status: BitmapBatch<N>,

    /// Each leaf corresponds to a complete bitmap chunk at the grafting height.
    /// See the [grafted leaf formula](super) in the module documentation.
    ///
    /// Internal nodes are hashed using their position in the ops tree rather than their
    /// grafted position.
    pub(super) grafted_tree: Mem<F, H::Digest>,

    /// Persists:
    /// - The number of pruned bitmap chunks at key [PRUNED_CHUNKS_PREFIX]
    /// - The grafted tree pinned nodes at key [NODE_PREFIX]
    pub(super) metadata: AsyncMutex<Metadata<E, U64, Vec<u8>>>,

    /// Optional thread pool for parallelizing grafted leaf computation.
    pub(super) thread_pool: Option<ThreadPool>,

    /// The cached canonical root.
    /// See the [Root structure](super) section in the module documentation.
    pub(super) root: DigestOf<H>,

    /// Grafted root witness: `(grafted_position, digest)` pairs for non-pinned interior nodes in
    /// the pruned grafted subtree. Captured before pruning and persisted to metadata so that
    /// `compute_grafted_root` can resolve nodes that delayed MMB merges expose after the grafted
    /// Mem has been compacted. Empty when the grafted tree has never been pruned.
    pub(super) grafted_root_witness: GraftedRootWitness<H::Digest>,
}

// Shared read-only functionality.
impl<F, E, C, I, H, U, const N: usize> Db<F, E, C, I, H, U, N>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location<F> {
        self.any.inactivity_floor_loc()
    }

    /// Whether the snapshot currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.any.is_empty()
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<U::Value>, Error<F>> {
        self.any.get_metadata().await
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location<F>> {
        self.any.bounds().await
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc`
    /// in the log with the provided `root`, having the activity status described by `chunks`.
    pub fn verify_range_proof(
        hasher: &mut H,
        proof: &RangeProof<F, H::Digest>,
        start_loc: Location<F>,
        ops: &[Operation<F, U>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        proof.verify(hasher, start_loc, ops, chunks, root)
    }
}

// Functionality requiring non-mutable journal.
impl<F, E, U, C, I, H, const N: usize> Db<F, E, C, I, H, U, N>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Returns the most aggressive bitmap/grafted prune boundary that is both inactivity-safe and
    /// fully settled for the current family.
    ///
    /// For MMB, the youngest complete chunk can keep changing briefly after it becomes inactive
    /// because delayed merges may still change its `chunk_peaks(...)` digest. In that case we keep
    /// that one chunk unpruned and only advance the bitmap/grafted floor to the previous complete
    /// chunk. Earlier complete chunks are already settled.
    fn settled_bitmap_prune_loc(
        &self,
        inactivity_floor: Location<F>,
    ) -> Result<Location<F>, Error<F>> {
        let chunk_bits = BitMap::<N>::CHUNK_SIZE_BITS;
        let mut pruned_chunks = *inactivity_floor / chunk_bits;
        if pruned_chunks == 0 {
            return Ok(Location::new(0));
        }

        let current_ops_leaves = Location::<F>::try_from(self.any.log.merkle.size())?.as_u64();
        let grafting_height = grafting::height::<N>();
        let last_complete_chunk = pruned_chunks - 1;
        let chunk_start = last_complete_chunk
            .checked_shl(grafting_height)
            .ok_or(Error::DataCorrupted("chunk start overflow"))?;
        let chunk_pos = F::subtree_root_position(Location::<F>::new(chunk_start), grafting_height);
        let stable_after = F::peak_birth_size(chunk_pos, grafting_height);
        if current_ops_leaves < stable_after {
            pruned_chunks -= 1;
        }

        let settled_bits = pruned_chunks
            .checked_mul(chunk_bits)
            .ok_or(Error::DataCorrupted("bitmap prune boundary overflow"))?;
        Ok(Location::new(settled_bits))
    }

    /// Returns a virtual [grafting::Storage] over the grafted tree and ops tree. For positions at
    /// or above the grafting height, returns the grafted node. For positions below the grafting
    /// height, the ops tree is used.
    fn grafted_storage(&self) -> impl MerkleStorage<F, Digest = H::Digest> + '_ {
        grafting::Storage::new(
            &self.grafted_tree,
            grafting::height::<N>(),
            &self.any.log.merkle,
            &self.grafted_root_witness,
            StandardHasher::<H>::new(),
        )
    }

    /// Returns the canonical root.
    /// See the [Root structure](super) section in the module documentation.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// Returns the ops tree root.
    ///
    /// This is the root of the raw operations log, without the activity bitmap. It is used as the
    /// sync target because the sync engine verifies batches against the ops root, not the canonical
    /// root.
    ///
    /// See the [Root structure](super) section in the module documentation.
    pub fn ops_root(&self) -> H::Digest {
        self.any.log.root()
    }

    /// Snapshot of the grafted tree for use in batch chains.
    pub(super) fn grafted_snapshot(&self) -> Arc<merkle::batch::MerkleizedBatch<F, H::Digest>> {
        merkle::batch::MerkleizedBatch::from_mem(&self.grafted_tree)
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> super::batch::UnmerkleizedBatch<F, H, U, N> {
        super::batch::UnmerkleizedBatch::new(
            self.any.new_batch(),
            self.grafted_snapshot(),
            self.status.clone(),
        )
    }

    /// Returns a proof for the operation at `loc`.
    pub(super) async fn operation_proof(
        &self,
        hasher: &mut H,
        loc: Location<F>,
    ) -> Result<OperationProof<F, H::Digest, N>, Error<F>> {
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
    /// Returns [Error::OperationPruned] if `start_loc` falls in a pruned bitmap chunk. Returns
    /// [`crate::merkle::Error::LocationOverflow`] if `start_loc` >
    /// [`crate::merkle::Family::MAX_LEAVES`]. Returns [`crate::merkle::Error::RangeOutOfBounds`] if
    /// `start_loc` >= number of leaves in the tree.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(RangeProof<F, H::Digest>, Vec<Operation<F, U>>, Vec<[u8; N]>), Error<F>> {
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
impl<F, E, U, C, I, H, const N: usize> Db<F, E, C, I, H, U, N>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Returns an ops-level historical proof for the specified range.
    ///
    /// Unlike [`range_proof`](Self::range_proof) which returns grafted proofs incorporating the
    /// activity bitmap, this returns standard range proofs suitable for state sync.
    pub async fn ops_historical_proof(
        &self,
        historical_size: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(merkle::Proof<F, H::Digest>, Vec<Operation<F, U>>), Error<F>> {
        self.any
            .historical_proof(historical_size, start_loc, max_ops)
            .await
    }

    /// Return the pinned nodes for a lower operation boundary of `loc`.
    pub async fn pinned_nodes_at(&self, loc: Location<F>) -> Result<Vec<H::Digest>, Error<F>> {
        self.any.pinned_nodes_at(loc).await
    }

    /// Rebuild the grafted root witness from the current grafted tree state.
    pub(super) fn capture_grafted_root_witness(&mut self) -> Result<(), Error<F>> {
        let ops_size = self.any.log.merkle.size();
        witness::rebuild_grafted_root_witness::<F, H::Digest, _, N>(
            &self.grafted_tree,
            ops_size,
            self.status.pruned_chunks() as u64,
            &mut self.grafted_root_witness,
        )
    }

    /// Collapse the accumulated bitmap `Layer` chain into a flat `Base`.
    ///
    /// Each [`Db::apply_batch`] pushes a new `Layer` on the bitmap. These layers are cheap
    /// to create but make subsequent reads walk the full chain. Calling `flatten` collapses
    /// the chain into a single `Base`, bounding lookup cost.
    ///
    /// This is called automatically by [`Db::prune`]. Callers that apply many batches without
    /// pruning should call this periodically.
    pub fn flatten(&mut self) {
        self.status.flatten();
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// The bitmap/grafted overlay prunes as far as the inactivity floor allows, except that it
    /// retains the youngest complete chunk until its grafted digest has settled. The ops log still
    /// prunes only to `prune_loc`, so the bitmap pruning boundary may advance past
    /// [`Db::bounds`].start.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [`crate::merkle::Error::LocationOverflow`] if `prune_loc` >
    ///   [crate::merkle::Family::MAX_LEAVES].
    pub async fn prune(&mut self, prune_loc: Location<F>) -> Result<(), Error<F>> {
        let inactivity_floor = self.inactivity_floor_loc();
        if prune_loc > inactivity_floor {
            return Err(Error::PruneBeyondMinRequired(prune_loc, inactivity_floor));
        }

        self.flatten();

        // The Current overlay can prune bitmap/grafted state ahead of the ops log because
        // operations below the inactivity floor are known inactive. For MMB, keep the youngest
        // complete chunk until its grafted digest has settled under delayed merges.
        let settled_bitmap_floor = self.settled_bitmap_prune_loc(inactivity_floor)?;
        let BitmapBatch::<N>::Base(base) = &mut self.status else {
            unreachable!("flatten() guarantees Base");
        };
        Arc::make_mut(base).prune_to_bit(*settled_bitmap_floor);

        // Prune the grafted tree to match the bitmap's pruned chunks.
        let pruned_chunks = self.status.pruned_chunks() as u64;
        self.capture_grafted_root_witness()?;
        if pruned_chunks > 0 {
            let prune_loc_grafted = Location::<F>::new(pruned_chunks);
            let bounds_start = self.grafted_tree.bounds().start;
            let grafted_prune_pos =
                Position::try_from(prune_loc_grafted).expect("valid leaf count");
            if prune_loc_grafted > bounds_start {
                let root = *self.grafted_tree.root();
                let size = self.grafted_tree.size();

                let mut pinned = BTreeMap::new();
                for pos in F::nodes_to_pin(prune_loc_grafted) {
                    pinned.insert(
                        pos,
                        self.grafted_tree
                            .get_node(pos)
                            .expect("pinned peak must exist"),
                    );
                }
                let mut retained = Vec::with_capacity((*size - *grafted_prune_pos) as usize);
                for p in *grafted_prune_pos..*size {
                    retained.push(
                        self.grafted_tree
                            .get_node(Position::new(p))
                            .expect("retained node must exist"),
                    );
                }
                self.grafted_tree =
                    Mem::from_pruned_with_retained(root, grafted_prune_pos, pinned, retained);
            }
        }

        // Persist grafted tree pruning state before pruning the ops log. If the subsequent
        // `any.prune` fails, the metadata is ahead of the log, which is safe: on recovery,
        // `build_grafted_tree` will recompute from the (un-pruned) log and the metadata
        // simply records peaks that haven't been pruned yet. The reverse order would be unsafe:
        // a pruned log with stale metadata would lose peak digests permanently.
        self.sync_metadata().await?;

        self.any.prune(prune_loc).await
    }
    /// Sync the metadata to disk.
    pub(crate) async fn sync_metadata(&self) -> Result<(), Error<F>> {
        let mut metadata = self.metadata.lock().await;
        metadata.clear();

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        metadata.put(
            key,
            (self.status.pruned_chunks() as u64).to_be_bytes().to_vec(),
        );

        // Write the pinned nodes of the grafted tree.
        let pruned_chunks = Location::<F>::new(self.status.pruned_chunks() as u64);
        for (i, grafted_pos) in F::nodes_to_pin(pruned_chunks).enumerate() {
            let digest = self
                .grafted_tree
                .get_node(grafted_pos)
                .ok_or(Error::<F>::DataCorrupted("missing grafted pinned node"))?;
            let key = U64::new(NODE_PREFIX, i as u64);
            metadata.put(key, digest.to_vec());
        }

        // Write the grafted root witness (captured by capture_grafted_root_witness before
        // the grafted tree was pruned).
        for (i, &(pos, digest)) in self
            .grafted_root_witness
            .persisted_entries()
            .iter()
            .enumerate()
        {
            let key = U64::new(GRAFTED_ROOT_WITNESS_PREFIX, i as u64);
            let mut val = pos.to_be_bytes().to_vec();
            val.extend_from_slice(digest.as_ref());
            metadata.put(key, val);
        }

        metadata.sync().await?;

        Ok(())
    }
}

// Functionality requiring mutable + persistable journal.
impl<F, E, U, C, I, H, const N: usize> Db<F, E, C, I, H, U, N>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Durably commit the journal state published by prior [`Db::apply_batch`]
    /// calls.
    pub async fn commit(&self) -> Result<(), Error<F>> {
        self.any.commit().await
    }

    /// Sync all database state to disk.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        self.any.sync().await?;

        // Write the bitmap pruning boundary to disk so that next startup doesn't have to
        // re-Merkleize the inactive portion up to the inactivity floor.
        self.sync_metadata().await
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.metadata.into_inner().destroy().await?;
        self.any.destroy().await
    }
}

impl<F, E, U, C, I, H, const N: usize> Db<F, E, C, I, H, U, N>
where
    F: merkle::Graftable,
    E: Context,
    U: Update + 'static,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
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
        batch: Arc<super::batch::MerkleizedBatch<F, H::Digest, U, N>>,
    ) -> Result<Range<Location<F>>, Error<F>> {
        // Staleness is checked by self.any.apply_batch() below.
        let db_size = *self.any.last_commit_loc + 1;

        // 1. Apply inner any-layer batch (handles snapshot + journal partial skipping).
        let range = self.any.apply_batch(Arc::clone(&batch.inner)).await?;

        // 2. Apply bitmap overlay. The batch's bitmap is a Layer whose overlay
        //    contains all dirty chunks. Walk the layer chain to collect and apply
        //    all uncommitted ancestor overlays + this batch's overlay.
        {
            let mut overlays = Vec::new();
            let mut current = &batch.bitmap;
            while let super::batch::BitmapBatch::Layer(layer) = current {
                if layer.overlay.len <= db_size {
                    break;
                }
                overlays.push(Arc::clone(&layer.overlay));
                current = &layer.parent;
            }
            // Apply in chronological order (deepest ancestor first).
            for overlay in overlays.into_iter().rev() {
                self.status.apply_overlay(overlay);
            }
        }

        // 3. Apply grafted tree (merkle layer handles partial ancestor skipping).
        self.grafted_tree.apply_batch(&batch.grafted)?;

        // 4. Canonical root.
        self.root = batch.canonical_root;

        Ok(range)
    }
}

impl<F, E, U, C, I, H, const N: usize> Persistable for Db<F, E, C, I, H, U, N>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    type Error = Error<F>;

    async fn commit(&self) -> Result<(), Error<F>> {
        Self::commit(self).await
    }

    async fn sync(&self) -> Result<(), Error<F>> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error<F>> {
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

/// Compute the canonical root from the ops root, grafted tree root, and optional partial chunk.
///
/// See the [Root structure](super) section in the module documentation.
pub(super) fn combine_roots<H: Hasher>(
    hasher: &StandardHasher<H>,
    ops_root: &H::Digest,
    grafted_root: &H::Digest,
    partial: Option<(u64, &H::Digest)>,
) -> H::Digest {
    match partial {
        Some((next_bit, last_chunk_digest)) => {
            let next_bit = next_bit.to_be_bytes();
            hasher.hash([
                ops_root.as_ref(),
                grafted_root.as_ref(),
                next_bit.as_slice(),
                last_chunk_digest.as_ref(),
            ])
        }
        None => hasher.hash([ops_root.as_ref(), grafted_root.as_ref()]),
    }
}

/// Compute the canonical root digest of a [Db].
///
/// See the [Root structure](super) section in the module documentation.
pub(super) async fn compute_db_root<
    F: merkle::Graftable,
    H: Hasher,
    B: BitmapReadable<N>,
    S: MerkleStorage<F, Digest = H::Digest>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    status: &B,
    storage: &S,
    partial_chunk: Option<([u8; N], u64)>,
    ops_root: &H::Digest,
) -> Result<H::Digest, Error<F>> {
    let grafted_root = compute_grafted_root(hasher, status, storage).await?;
    let partial = partial_chunk.map(|(chunk, next_bit)| {
        let digest = hasher.digest(&chunk);
        (next_bit, digest)
    });
    Ok(combine_roots(
        hasher,
        ops_root,
        &grafted_root,
        partial.as_ref().map(|(nb, d)| (*nb, d)),
    ))
}

/// Compute the root of the grafted structure represented by `storage`.
///
/// We use [`grafting::grafted_root`] instead of a standard `hasher.root()` fold to correctly handle
/// grafting over MMB (Merkle Mountain Belt) structures. In an MMB, the trailing operations at the
/// right edge of the structure might not be numerous enough to form a complete subtree at the
/// grafting height. Therefore, a single bitmap chunk may span across multiple smaller ops peaks.
/// `grafting::grafted_root` intercepts the folding process to group these sub-grafting-height
/// peaks, hash them together with their corresponding bitmap chunks, and then complete the final
/// fold. For MMR, this produces the exact same result as `hasher.root()`.
pub(super) async fn compute_grafted_root<
    F: merkle::Graftable,
    H: Hasher,
    B: BitmapReadable<N>,
    S: MerkleStorage<F, Digest = H::Digest>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    status: &B,
    storage: &S,
) -> Result<H::Digest, Error<F>> {
    let size = storage.size().await;
    let leaves = Location::try_from(size)?;

    // Collect peak digests of the grafted structure. The storage layer resolves nodes below the
    // grafting height from the ops tree and may reconstruct missing pruned grafted nodes from
    // pinned descendants plus witness digests.
    let mut peaks: Vec<H::Digest> = Vec::new();
    for (peak_pos, _) in F::peaks(size) {
        let digest = storage
            .get_node(peak_pos)
            .await?
            .ok_or_else(|| merkle::Error::<F>::MissingNode(peak_pos))?;
        peaks.push(digest);
    }
    let grafting_height = grafting::height::<N>();
    let complete_chunks = status.complete_chunks() as u64;
    let pruned_chunks = status.pruned_chunks() as u64;

    Ok(grafting::grafted_root(
        hasher,
        leaves,
        &peaks,
        grafting_height,
        |chunk_idx| {
            if chunk_idx < complete_chunks {
                // Pruned chunks are guaranteed to be all-zero (only chunks with no active
                // operations are prunable), so a synthetic zero chunk produces the correct grafted
                // digest via the zero-chunk identity shortcut.
                if chunk_idx < pruned_chunks {
                    Some([0u8; N])
                } else {
                    Some(status.get_chunk(chunk_idx as usize))
                }
            } else {
                None
            }
        },
    ))
}

/// Compute grafted leaf digests for the given bitmap chunks as `(chunk_idx, digest)` pairs.
///
/// For each chunk, reads the covering peak digests from the ops structure via
/// [`Graftable::chunk_peaks`](merkle::Graftable::chunk_peaks), folds them into a single
/// `chunk_ops_digest`, then combines with the bitmap chunk: `hash(chunk || chunk_ops_digest)`. For
/// all-zero chunks the grafted leaf equals the `chunk_ops_digest` directly (zero-chunk identity).
///
/// When a thread pool is provided and there are enough chunks, hashing is parallelized.
pub(super) async fn compute_grafted_leaves<F: merkle::Graftable, H: Hasher, const N: usize>(
    hasher: &StandardHasher<H>,
    ops_tree: &impl MerkleStorage<F, Digest = H::Digest>,
    chunks: impl IntoIterator<Item = (usize, [u8; N])>,
    pool: Option<&ThreadPool>,
) -> Result<Vec<(usize, H::Digest)>, Error<F>> {
    let grafting_height = grafting::height::<N>();
    let ops_size = ops_tree.size().await;

    // For each chunk, read the covering peak digests and fold them into a single
    // chunk_ops_digest. With MMR there is always exactly one peak; with MMB there
    // may be multiple. The fold happens inline to avoid per-chunk Vec allocations.
    let inputs = try_join_all(chunks.into_iter().map(|(chunk_idx, chunk)| async move {
        let mut chunk_ops_digest: Option<H::Digest> = None;
        for (pos, _) in F::chunk_peaks(ops_size, chunk_idx as u64, grafting_height) {
            let digest = ops_tree
                .get_node(pos)
                .await?
                .ok_or(merkle::Error::<F>::MissingGraftedLeaf(pos))?;
            chunk_ops_digest = Some(
                chunk_ops_digest.map_or(digest, |acc| hasher.hash([acc.as_ref(), digest.as_ref()])),
            );
        }
        let chunk_ops_digest =
            chunk_ops_digest.expect("chunk must have at least one covering peak");
        Ok::<_, Error<F>>((chunk_idx, chunk_ops_digest, chunk))
    }))
    .await?;

    // Compute the grafted leaf digest for each chunk. For all-zero chunks, the
    // grafted leaf equals the chunk_ops_digest directly (zero-chunk identity).
    let zero_chunk = [0u8; N];
    let graft =
        |h: &StandardHasher<H>, chunk_idx: usize, chunk_ops_digest: H::Digest, chunk: [u8; N]| {
            if chunk == zero_chunk {
                (chunk_idx, chunk_ops_digest)
            } else {
                (
                    chunk_idx,
                    h.hash([chunk.as_slice(), chunk_ops_digest.as_ref()]),
                )
            }
        };

    Ok(match pool.filter(|_| inputs.len() >= MIN_TO_PARALLELIZE) {
        Some(pool) => pool.install(|| {
            inputs
                .into_par_iter()
                .map_init(
                    || hasher.clone(),
                    |h, (chunk_idx, chunk_ops_digest, chunk)| {
                        graft(h, chunk_idx, chunk_ops_digest, chunk)
                    },
                )
                .collect()
        }),
        None => inputs
            .into_iter()
            .map(|(chunk_idx, chunk_ops_digest, chunk)| {
                graft(hasher, chunk_idx, chunk_ops_digest, chunk)
            })
            .collect(),
    })
}

/// Build a grafted [Mem] from scratch using bitmap chunks and the ops tree.
///
/// For each non-pruned complete chunk (index in `pruned_chunks..complete_chunks`), reads the
/// ops tree node at the grafting height to compute the grafted leaf (see the
/// [grafted leaf formula](super) in the module documentation). The caller must ensure that all
/// ops tree nodes for chunks >= `bitmap.pruned_chunks()` are still accessible in the ops tree
/// (i.e., not pruned from the journal).
pub(super) async fn build_grafted_tree<F: merkle::Graftable, H: Hasher, const N: usize>(
    hasher: &StandardHasher<H>,
    bitmap: &BitMap<N>,
    pinned_nodes: &[H::Digest],
    ops_tree: &impl MerkleStorage<F, Digest = H::Digest>,
    pool: Option<&ThreadPool>,
) -> Result<Mem<F, H::Digest>, Error<F>> {
    let grafting_height = grafting::height::<N>();
    let pruned_chunks = bitmap.pruned_chunks();
    let complete_chunks = bitmap.complete_chunks();

    // Compute grafted leaves for each unpruned complete chunk.
    let leaves = compute_grafted_leaves::<F, H, N>(
        hasher,
        ops_tree,
        (pruned_chunks..complete_chunks).map(|chunk_idx| (chunk_idx, *bitmap.get_chunk(chunk_idx))),
        pool,
    )
    .await?;

    // Build the base grafted tree: either from pruned components or empty.
    let grafted_hasher = grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
    let mut grafted_tree = if pruned_chunks > 0 {
        let grafted_pruning_boundary = Location::<F>::new(pruned_chunks as u64);
        Mem::from_components(
            &grafted_hasher,
            Vec::new(),
            grafted_pruning_boundary,
            pinned_nodes.to_vec(),
        )
        .map_err(|_| Error::<F>::DataCorrupted("grafted tree rebuild failed"))?
    } else {
        Mem::new(&grafted_hasher)
    };

    // Add each grafted leaf digest.
    if !leaves.is_empty() {
        let batch = {
            let mut batch = grafted_tree.new_batch().with_pool(pool.cloned());
            for &(_ops_pos, digest) in &leaves {
                batch = batch.add_leaf_digest(digest);
            }
            batch.merkleize(&grafted_tree, &grafted_hasher)
        };
        grafted_tree.apply_batch(&batch)?;
    }

    Ok(grafted_tree)
}

/// Load the metadata and recover the pruning state persisted by previous runs.
///
/// The metadata store holds three kinds of entries (keyed by prefix):
/// - **Pruned chunks count** ([PRUNED_CHUNKS_PREFIX]): the number of bitmap chunks that have been
///   pruned. This tells us where the active portion of the bitmap begins.
/// - **Pinned node digests** ([NODE_PREFIX]): grafted tree digests at peak positions whose
///   underlying data has been pruned. These are needed to recompute the grafted tree root without
///   the pruned chunks.
/// - **Grafted root witness** ([GRAFTED_ROOT_WITNESS_PREFIX]): extra grafted digests retained for
///   MMB so delayed merges can still reconstruct pruned grafted nodes after reopen.
///
/// Returns `(metadata_handle, pruned_chunks, pinned_node_digests, grafted_root_witness)`.
pub(super) async fn init_metadata<F: merkle::Graftable, E: Context, D: Digest>(
    context: E,
    partition: &str,
) -> Result<
    (
        Metadata<E, U64, Vec<u8>>,
        usize,
        Vec<D>,
        GraftedRootWitness<D>,
    ),
    Error<F>,
> {
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
            Error::<F>::DataCorrupted("pruned chunks value not a valid u64")
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
        let pruned_loc = Location::<F>::new(pruned_chunks as u64);
        if !pruned_loc.is_valid() {
            return Err(Error::DataCorrupted("pruned chunks exceeds MAX_LEAVES"));
        }
        let mut pinned = Vec::new();
        for (index, _pos) in F::nodes_to_pin(pruned_loc).enumerate() {
            let metadata_key = U64::new(NODE_PREFIX, index as u64);
            let Some(bytes) = metadata.get(&metadata_key) else {
                return Err(Error::DataCorrupted(
                    "missing pinned node in grafted tree metadata",
                ));
            };
            let digest = D::decode(bytes.as_ref())
                .map_err(|_| Error::<F>::DataCorrupted("invalid pinned node digest"))?;
            pinned.push(digest);
        }
        pinned
    } else {
        Vec::new()
    };

    // Load the grafted root witness (may be empty for fresh databases or MMR).
    let mut grafted_root_witness = Vec::new();
    for idx in 0u64.. {
        let key = U64::new(GRAFTED_ROOT_WITNESS_PREFIX, idx);
        let Some(bytes) = metadata.get(&key) else {
            break;
        };
        if bytes.len() < size_of::<u64>() {
            return Err(Error::<F>::DataCorrupted("invalid witness pos"));
        }
        let pos = u64::from_be_bytes(
            bytes[0..8]
                .try_into()
                .map_err(|_| Error::<F>::DataCorrupted("invalid witness pos"))?,
        );
        let digest = D::decode(&bytes[8..])
            .map_err(|_| Error::<F>::DataCorrupted("invalid grafted root witness digest"))?;
        grafted_root_witness.push((pos, digest));
    }
    let grafted_root_witness = GraftedRootWitness::from_entries(grafted_root_witness);
    tracing::debug!(
        "init_metadata: loaded {} witness entries, pruned_chunks={pruned_chunks}",
        grafted_root_witness.len()
    );

    Ok((metadata, pruned_chunks, pinned_nodes, grafted_root_witness))
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
