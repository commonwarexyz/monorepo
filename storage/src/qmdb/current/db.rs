//! A shared, generic implementation of the _Current_ QMDB.
//!
//! The impl blocks in this file define shared functionality across all Current QMDB variants.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        contiguous::{Contiguous, Mutable},
        Error as JournalError,
    },
    metadata::{Config as MConfig, Metadata},
    mmr::{
        self,
        hasher::Hasher as _,
        iterator::{nodes_to_pin, PeakIterator},
        mem::MIN_TO_PARALLELIZE,
        storage::Storage as _,
        Location, Position, StandardHasher,
    },
    qmdb::{
        any::{
            self,
            operation::{update::Update, Operation},
        },
        current::{
            grafting,
            proof::{OperationProof, RangeProof},
        },
        Error,
    },
    Persistable,
};
use commonware_codec::{Codec, CodecShared, DecodeExt};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{bitmap::Prunable as BitMap, sequence::prefixed_u64::U64, sync::AsyncMutex};
use core::{num::NonZeroU64, ops::Range};
use futures::future::try_join_all;
use rayon::prelude::*;
use tracing::{error, warn};

/// Prefix used for the metadata key for grafted MMR pinned nodes.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key for the number of pruned bitmap chunks.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

/// A Current QMDB implementation generic over ordered/unordered keys and variable/fixed values.
pub struct Db<
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
    const N: usize,
> {
    /// An authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    pub(super) any: any::db::Db<E, C, I, H, U>,

    /// The bitmap over the activity status of each operation. Supports augmenting [Db] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    pub(super) status: BitMap<N>,

    /// Each leaf corresponds to a complete bitmap chunk at the grafting height.
    /// See the [grafted leaf formula](super) in the module documentation.
    ///
    /// Internal nodes are hashed using their position in the ops MMR rather than their
    /// grafted position.
    pub(super) grafted_mmr: mmr::mem::Mmr<grafting::GraftedHasher<StandardHasher<H>>>,

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
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
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
        ops: &[Operation<U>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        proof.verify(hasher, start_loc, ops, chunks, root)
    }
}

// Functionality requiring non-mutable journal.
impl<E, U, C, I, H, const N: usize> Db<E, C, I, H, U, N>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Returns a virtual [grafting::Storage] over the grafted MMR and ops MMR. For positions at or
    /// above the grafting height, returns grafted MMR node. For positions below the grafting
    /// height, the ops MMR is used.
    fn grafted_storage(&self) -> impl mmr::storage::Storage<Digest = H::Digest> + '_ {
        grafting::Storage::new(
            &self.grafted_mmr,
            grafting::height::<N>(),
            &self.any.log.mmr,
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

    /// Create a new speculative batch of operations with this database as its parent.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(
        &self,
    ) -> super::batch::UnmerkleizedBatch<
        '_,
        E,
        C,
        I,
        H,
        U,
        mmr::journaled::Mmr<E, StandardHasher<H>>,
        mmr::mem::Mmr<grafting::GraftedHasher<StandardHasher<H>>>,
        BitMap<N>,
        N,
    > {
        super::batch::UnmerkleizedBatch::new(
            self.any.new_batch(),
            self,
            Vec::new(),
            Vec::new(),
            &self.grafted_mmr,
            &self.status,
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
    /// Returns [mmr::Error::LocationOverflow] if `start_loc` > [mmr::MAX_LOCATION].
    /// Returns [mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(RangeProof<H::Digest>, Vec<Operation<U>>, Vec<[u8; N]>), Error> {
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
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
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
    ) -> Result<(mmr::Proof<H::Digest>, Vec<Operation<U>>), Error> {
        self.any
            .historical_proof(historical_size, start_loc, max_ops)
            .await
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [mmr::Error::LocationOverflow] if `prune_loc` > [mmr::MAX_LOCATION].
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        // Persist grafted MMR pruning state before pruning the ops log. If the subsequent
        // `any.prune` fails, the metadata is ahead of the log, which is safe: on recovery,
        // `build_grafted_mmr` will recompute from the (un-pruned) log and the metadata
        // simply records peaks that haven't been pruned yet. The reverse order would be unsafe:
        // a pruned log with stale metadata would lose peak digests permanently.
        self.sync_metadata().await?;

        self.any.prune(prune_loc).await
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

        metadata.sync().await.map_err(mmr::Error::MetadataError)?;

        Ok(())
    }
}

// Functionality requiring mutable + persistable journal.
impl<E, U, C, I, H, const N: usize> Db<E, C, I, H, U, N>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
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
    E: Storage + Clock + Metrics,
    U: Update + 'static,
    C: Mutable<Item = Operation<U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Apply a changeset to the database, returning the range of written operations.
    ///
    /// A changeset is only valid if the database has not been modified since the batch that
    /// produced it was created. Multiple batches can be forked from the same parent for speculative
    /// execution, but only one may be applied. Applying a stale changeset returns
    /// [`Error::StaleChangeset`].
    ///
    /// This publishes the batch to the in-memory Current view and appends it to the underlying
    /// journal, but does not durably persist it. Call [`Db::commit`] or [`Db::sync`] to guarantee
    /// durability.
    pub async fn apply_batch(
        &mut self,
        batch: super::batch::Changeset<U::Key, H::Digest, Operation<U>, N>,
    ) -> Result<Range<Location>, Error> {
        // 1. Apply inner any batch (writes ops, updates snapshot).
        let range = self.any.apply_batch(batch.inner).await?;

        // 2. Push new bits FIRST. Must happen before clears because for chained batches, some
        //    clears target locations within the push range (ancestor-segment superseded ops that
        //    were pushed as active by an ancestor and then superseded by a descendant).
        for &bit in &batch.bitmap_pushes {
            self.status.push(bit);
        }

        // 3. Clear superseded locations: previous commit inactivation, diff base_old_locs, and
        //    ancestor-segment superseded locations (chaining).
        for loc in &batch.bitmap_clears {
            self.status.set_bit(**loc, false);
        }

        // 4. Apply precomputed grafted MMR changeset from merkleize().
        self.grafted_mmr.apply(batch.grafted_changeset)?;

        // 5. Prune bitmap chunks fully below the inactivity floor.
        self.status.prune_to_bit(*self.any.inactivity_floor_loc);

        // 6. Prune the grafted MMR to match.
        let pruned_chunks = self.status.pruned_chunks() as u64;
        if pruned_chunks > 0 {
            let prune_loc = Location::new(pruned_chunks);
            if prune_loc > self.grafted_mmr.bounds().start {
                self.grafted_mmr.prune(prune_loc)?;
            }
        }

        // 7. Use precomputed canonical root from merkleize().
        self.root = batch.canonical_root;

        Ok(range)
    }
}

impl<E, U, C, I, H, const N: usize> Persistable for Db<E, C, I, H, U, N>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
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
pub(super) fn partial_chunk<B: super::batch::BitmapRead<N>, const N: usize>(
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
    hasher: &mut StandardHasher<H>,
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
    G: mmr::read::Readable<Digest = H::Digest>,
    S: mmr::storage::Storage<Digest = H::Digest>,
    const N: usize,
>(
    hasher: &mut StandardHasher<H>,
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
    G: mmr::read::Readable<Digest = H::Digest>,
    S: mmr::storage::Storage<Digest = H::Digest>,
>(
    hasher: &mut StandardHasher<H>,
    storage: &grafting::Storage<'_, H::Digest, G, S>,
) -> Result<H::Digest, Error> {
    let size = storage.size().await;
    let leaves = Location::try_from(size).map_err(mmr::Error::from)?;

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
    hasher: &mut StandardHasher<H>,
    ops_mmr: &impl mmr::storage::Storage<Digest = H::Digest>,
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
    hasher: &mut StandardHasher<H>,
    bitmap: &BitMap<N>,
    pinned_nodes: &[H::Digest],
    ops_mmr: &impl mmr::storage::Storage<Digest = H::Digest>,
    pool: Option<&ThreadPool>,
) -> Result<mmr::mem::Mmr<grafting::GraftedHasher<StandardHasher<H>>>, Error> {
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
        let grafted_pruned_to = Location::new(pruned_chunks as u64);
        mmr::mem::Mmr::from_components(
            grafted_hasher,
            Vec::new(),
            grafted_pruned_to,
            pinned_nodes.to_vec(),
        )?
    } else {
        mmr::mem::Mmr::new(grafted_hasher)
    };

    // Add each grafted leaf digest.
    if !leaves.is_empty() {
        let changeset = {
            let mut hasher_for_merkleize = grafted_mmr.hasher().clone();
            let mut batch = grafted_mmr.new_batch().with_pool(pool.cloned());
            for &(_ops_pos, digest) in &leaves {
                batch.add_leaf_digest(digest);
            }
            batch.merkleize(&mut hasher_for_merkleize).finalize()
        };
        grafted_mmr.apply(changeset)?;
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
pub(super) async fn init_metadata<E: Storage + Clock + Metrics, D: Digest>(
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
        let mmr_size = Position::try_from(Location::new(pruned_chunks as u64))?;
        let mut pinned = Vec::new();
        for (index, pos) in nodes_to_pin(mmr_size).enumerate() {
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
        let mut h1 = StandardHasher::<Sha256>::new();
        let mut h2 = StandardHasher::<Sha256>::new();
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let r1 = combine_roots(&mut h1, &ops, &grafted, None);
        let r2 = combine_roots(&mut h2, &ops, &grafted, None);
        assert_eq!(r1, r2);
    }

    #[test]
    fn combine_roots_with_partial_differs() {
        let mut h1 = StandardHasher::<Sha256>::new();
        let mut h2 = StandardHasher::<Sha256>::new();
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let partial_digest = Sha256::hash(b"partial");

        let without = combine_roots(&mut h1, &ops, &grafted, None);
        let with = combine_roots(&mut h2, &ops, &grafted, Some((5, &partial_digest)));
        assert_ne!(without, with);
    }

    #[test]
    fn combine_roots_different_ops_root() {
        let mut h1 = StandardHasher::<Sha256>::new();
        let mut h2 = StandardHasher::<Sha256>::new();
        let ops_a = Sha256::hash(b"ops_a");
        let ops_b = Sha256::hash(b"ops_b");
        let grafted = Sha256::hash(b"grafted");

        let r1 = combine_roots(&mut h1, &ops_a, &grafted, None);
        let r2 = combine_roots(&mut h2, &ops_b, &grafted, None);
        assert_ne!(r1, r2);
    }
}
