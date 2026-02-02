//! A shared, generic implementation of the _Current_ QMDB.
//!
//! The impl blocks in this file defines shared functionality across all Current QMDB variants.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        contiguous::{Contiguous, MutableContiguous},
        Error as JournalError,
    },
    metadata::Metadata,
    mmr::{
        grafting::destination_pos, hasher::Hasher as MmrHasher, mem::CleanMmr, Location, Position,
        Proof, StandardHasher,
    },
    qmdb::{
        any::{
            self,
            operation::{update::Update, Operation},
            ValueEncoding,
        },
        current::proof::RangeProof,
        store::{self, LogStore, MerkleizedStore, PrunableStore},
        DurabilityState, Durable, Error, MerkleizationState, Merkleized, NonDurable, Unmerkleized,
    },
    Persistable,
};
use commonware_codec::{Codec, CodecShared, DecodeExt};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{bitmap::Prunable as PrunableBitMap, sequence::prefixed_u64::U64, Array};
use core::{num::NonZeroU64, ops::Range};
use std::sync::Arc;

/// Get the grafting height for a bitmap with chunk size determined by N.
pub(super) const fn grafting_height<const N: usize>() -> u32 {
    PrunableBitMap::<N>::CHUNK_SIZE_BITS.trailing_zeros()
}

/// Returns a root digest that incorporates bits not yet part of the MMR because they
/// belong to the last (unfilled) chunk.
pub(super) fn partial_chunk_root<H: Hasher, const N: usize>(
    hasher: &mut H,
    mmr_root: &H::Digest,
    next_bit: u64,
    last_chunk_digest: &H::Digest,
) -> H::Digest {
    assert!(next_bit > 0);
    assert!(next_bit < PrunableBitMap::<N>::CHUNK_SIZE_BITS);
    hasher.update(mmr_root);
    hasher.update(&next_bit.to_be_bytes());
    hasher.update(last_chunk_digest);
    hasher.finalize()
}

/// Metadata key prefixes for bitmap persistence.
const BITMAP_PRUNED_CHUNKS_KEY: u8 = 0;
const BITMAP_PINNED_NODE_PREFIX: u8 = 1;

/// A Current QMDB implementation generic over ordered/unordered keys and variable/fixed values.
pub struct Db<
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
    const N: usize,
    M: MerkleizationState<DigestOf<H>> = Merkleized<H>,
    D: DurabilityState = Durable,
> {
    /// An authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    pub(super) any: any::db::Db<E, C, I, H, U, M, D>,

    /// The bitmap over the activity status of each operation. Uses PrunableBitMap directly
    /// without an internal MMR - the grafted MMR is built on demand during merkleization.
    pub(super) status: PrunableBitMap<N>,

    /// Pinned nodes from the grafted MMR at the pruning boundary.
    /// These are grafted digests: H(chunk || ops_digest).
    pub(super) grafted_pinned_nodes: Vec<H::Digest>,

    /// Metadata storage for bitmap persistence (pruned_chunks and pinned_nodes).
    pub(super) bitmap_metadata: Metadata<E, U64, Vec<u8>>,

    /// Cached root digest. Valid when in Merkleized state.
    pub(super) cached_root: Option<H::Digest>,

    /// Cached grafted MMR for proof generation. Only set in Merkleized state.
    pub(super) grafted_mmr: Option<Arc<CleanMmr<H::Digest>>>,
}

// Functionality shared across all DB states, such as most non-mutating operations.
impl<E, K, V, C, I, H, U, const N: usize, M, D> Db<E, C, I, H, U, N, M, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    M: MerkleizationState<DigestOf<H>>,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    pub fn op_count(&self) -> Location {
        self.any.op_count()
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.any.inactivity_floor_loc()
    }

    /// Whether the snapshot currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.any.is_empty()
    }

    /// Returns the location of the oldest operation that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Location {
        self.any.oldest_retained_loc()
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        self.any.get_metadata().await
    }

    /// Get the level of the base MMR into which we are grafting.
    ///
    /// This value is log2 of the chunk size in bits. Since we assume the chunk size is a power of
    /// 2, we compute this from trailing_zeros.
    pub const fn grafting_height() -> u32 {
        grafting_height::<N>()
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range. A truncated range (from hitting the max) can be detected by
    /// looking at the length of the returned operations vector. Also returns the bitmap chunks
    /// required to verify the proof.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    /// Return true if the given sequence of `ops` were applied starting at location `start_loc` in
    /// the log with the provided root.
    pub fn verify_range_proof(
        hasher: &mut H,
        proof: &RangeProof<H::Digest>,
        start_loc: Location,
        ops: &[Operation<K, V, U>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        let height = Self::grafting_height();

        proof.verify(hasher, height, start_loc, ops, chunks, root)
    }

    /// Load bitmap pruning state from metadata.
    /// Returns (pruned_chunks, pinned_nodes).
    pub(super) async fn load_bitmap_state(
        metadata: &Metadata<E, U64, Vec<u8>>,
    ) -> Result<(usize, Vec<H::Digest>), Error> {
        // Load pruned_chunks
        let pruned_chunks = match metadata.get(&U64::new(BITMAP_PRUNED_CHUNKS_KEY, 0)) {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::DataCorrupted("invalid pruned_chunks"))?;
                u64::from_be_bytes(arr) as usize
            }
            None => 0,
        };

        // Load pinned nodes
        let mut pinned_nodes = Vec::new();
        for i in 0u64.. {
            match metadata.get(&U64::new(BITMAP_PINNED_NODE_PREFIX, i)) {
                Some(bytes) => {
                    let digest = H::Digest::decode(bytes.as_ref())
                        .map_err(|_| Error::DataCorrupted("invalid pinned node"))?;
                    pinned_nodes.push(digest);
                }
                None => break,
            }
        }

        Ok((pruned_chunks, pinned_nodes))
    }

    /// Save bitmap pruning state to metadata.
    pub(super) async fn save_bitmap_state(&mut self) -> Result<(), Error> {
        self.bitmap_metadata.clear();

        // Save pruned_chunks
        let pruned_chunks = self.status.pruned_chunks() as u64;
        self.bitmap_metadata.put(
            U64::new(BITMAP_PRUNED_CHUNKS_KEY, 0),
            pruned_chunks.to_be_bytes().to_vec(),
        );

        // Save pinned nodes
        for (i, node) in self.grafted_pinned_nodes.iter().enumerate() {
            self.bitmap_metadata
                .put(U64::new(BITMAP_PINNED_NODE_PREFIX, i as u64), node.to_vec());
        }

        self.bitmap_metadata.sync().await.map_err(Into::into)
    }
}

// Functionality shared across Merkleized states, such as the ability to prune the log and retrieve
// the state root
impl<E, K, V, U, C, I, H, D, const N: usize> Db<E, C, I, H, U, N, Merkleized<H>, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    pub const fn root(&self) -> H::Digest {
        self.cached_root.expect("Cached root must be set")
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range. A truncated range (from hitting the max) can be detected by
    /// looking at the length of the returned operations vector. Also returns the bitmap chunks
    /// required to verify the proof.
    ///
    /// # Errors
    ///
    /// Returns [crate::mmr::Error::LocationOverflow] if `start_loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [crate::mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(RangeProof<H::Digest>, Vec<Operation<K, V, U>>, Vec<[u8; N]>), Error> {
        let grafted_mmr = self
            .grafted_mmr
            .as_ref()
            .expect("grafted_mmr must be set in Merkleized state");
        RangeProof::<H::Digest>::new_with_ops(
            hasher,
            &self.status,
            Self::grafting_height(),
            grafted_mmr.as_ref(),
            &self.any.log.mmr,
            &self.any.log,
            start_loc,
            max_ops,
        )
        .await
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        // CRASH SAFETY: We must persist bitmap state BEFORE pruning the ops log.
        // If we crash after ops log prune but before bitmap persist, recovery would
        // fail because build_grafted_mmr would try to access pruned ops_mmr positions.
        //
        // By persisting bitmap state first:
        // - If crash after bitmap persist but before ops prune: safe, we have more
        //   data in ops log than needed, recovery works correctly.
        // - If crash after ops prune: bitmap state is already persisted, recovery
        //   uses correct pinned nodes.

        // Prune the bitmap in memory and compute new pinned nodes
        self.status.prune_to_bit(*prune_loc);
        let grafted_mmr = self
            .grafted_mmr
            .as_ref()
            .expect("grafted_mmr must be set in Merkleized state");
        let new_prune_pos =
            Position::try_from(Location::new_unchecked(self.status.pruned_chunks() as u64))?;
        self.grafted_pinned_nodes = grafted_mmr
            .nodes_to_pin(new_prune_pos)
            .into_values()
            .collect();

        // Persist bitmap state BEFORE pruning ops log
        self.save_bitmap_state().await?;

        // Now safe to prune the operations log
        self.any.prune(prune_loc).await
    }
}

// Functionality specific to Clean state, such as ability to persist the database.
impl<E, K, V, U, C, I, H, const N: usize> Db<E, C, I, H, U, N, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Sync all database state to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.any.sync().await?;
        self.save_bitmap_state().await
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        // Clean up bitmap metadata partition.
        self.bitmap_metadata.destroy().await?;

        // Clean up Any components (MMR and log).
        self.any.destroy().await
    }

    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            grafted_pinned_nodes: self.grafted_pinned_nodes,
            bitmap_metadata: self.bitmap_metadata,
            cached_root: None,
            grafted_mmr: None,
        }
    }
}

// Functionality shared across Unmerkleized states.
impl<E, K, V, U, C, I, H, const N: usize, D> Db<E, C, I, H, U, N, Unmerkleized, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    /// Merkleize the database and transition to the provable state.
    pub async fn into_merkleized(self) -> Result<Db<E, C, I, H, U, N, Merkleized<H>, D>, Error> {
        // Merkleize the any db
        let mut any = self.any.into_merkleized();
        let hasher = &mut any.log.hasher;

        let mut status = self.status;

        // Build the grafted MMR from current pinned nodes + fresh computation
        // We must build this BEFORE pruning so the pinned nodes match.
        let grafted_mmr = build_grafted_mmr::<H, N>(
            hasher,
            &status,
            &self.grafted_pinned_nodes,
            &any.log.mmr,
            grafting_height::<N>(),
        )
        .await?;

        // Compute and cache the root
        let cached_root = Some(
            compute_root::<H, N>(
                hasher,
                &status,
                &grafted_mmr,
                &any.log.mmr,
                grafting_height::<N>(),
            )
            .await?,
        );

        // Now prune the bitmap to the inactivity floor
        status.prune_to_bit(*any.inactivity_floor_loc);

        // Compute pinned nodes for the new pruning boundary from the already-built grafted MMR
        let new_prune_pos =
            Position::try_from(Location::new_unchecked(status.pruned_chunks() as u64))?;
        let new_pinned_nodes: Vec<_> = grafted_mmr
            .nodes_to_pin(new_prune_pos)
            .into_values()
            .collect();

        Ok(Db {
            any,
            status,
            grafted_pinned_nodes: new_pinned_nodes,
            bitmap_metadata: self.bitmap_metadata,
            cached_root,
            grafted_mmr: Some(Arc::new(grafted_mmr)),
        })
    }
}

// Functionality specific to (Unmerkleized,Durable) state.
impl<E, K, V, U, C, I, H, const N: usize> Db<E, C, I, H, U, N, Unmerkleized, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            grafted_pinned_nodes: self.grafted_pinned_nodes,
            bitmap_metadata: self.bitmap_metadata,
            cached_root: None,
            grafted_mmr: None,
        }
    }
}

// Functionality specific to (Unmerkleized,NonDurable) state.
impl<E, K, V, U, C, I, H, const N: usize> Db<E, C, I, H, U, N, Unmerkleized, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Raises the activity floor according to policy followed by appending a commit operation with
    /// the provided `metadata` and the new inactivity floor value. Returns the `[start_loc,
    /// end_loc)` location range of committed operations.
    async fn apply_commit_op(
        &mut self,
        metadata: Option<V::Value>,
    ) -> Result<Range<Location>, Error> {
        let start_loc = self.any.last_commit_loc + 1;

        // Inactivate the current commit operation.
        self.status.set_bit(*self.any.last_commit_loc, false);

        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.any.raise_floor_with_bitmap(&mut self.status).await?;

        // Append the commit operation with the new floor and tag it as active in the bitmap.
        self.status.push(true);
        let commit_op = Operation::CommitFloor(metadata, inactivity_floor_loc);

        self.any.apply_commit_op(commit_op).await?;

        Ok(start_loc..self.op_count())
    }

    /// Commit any pending operations to the database, ensuring their durability upon return.
    /// This transitions to the Durable state without merkleizing. Returns the committed database
    /// and the `[start_loc, end_loc)` range of committed operations.
    pub async fn commit(
        mut self,
        metadata: Option<V::Value>,
    ) -> Result<(Db<E, C, I, H, U, N, Unmerkleized, Durable>, Range<Location>), Error> {
        let range = self.apply_commit_op(metadata).await?;

        // Transition to Durable state without merkleizing
        let any = any::db::Db {
            log: self.any.log,
            inactivity_floor_loc: self.any.inactivity_floor_loc,
            last_commit_loc: self.any.last_commit_loc,
            snapshot: self.any.snapshot,
            durable_state: store::Durable,
            active_keys: self.any.active_keys,
            _update: core::marker::PhantomData,
        };

        Ok((
            Db {
                any,
                status: self.status,
                grafted_pinned_nodes: self.grafted_pinned_nodes,
                bitmap_metadata: self.bitmap_metadata,
                cached_root: None, // Not merkleized yet
                grafted_mmr: None,
            },
            range,
        ))
    }
}

// Functionality specific to (Merkleized,NonDurable) state.
impl<E, K, V, U, C, I, H, const N: usize> Db<E, C, I, H, U, N, Merkleized<H>, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            grafted_pinned_nodes: self.grafted_pinned_nodes,
            bitmap_metadata: self.bitmap_metadata,
            cached_root: None,
            grafted_mmr: None,
        }
    }
}

impl<E, K, V, U, C, I, H, const N: usize> Persistable
    for Db<E, C, I, H, U, N, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Error> {
        // No-op, DB already in recoverable state.
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

// MerkleizedStore for Merkleized states (both Durable and NonDurable)
// TODO(https://github.com/commonwarexyz/monorepo/issues/2560): This is broken -- it's computing
// proofs only over the any db mmr not the grafted mmr, so they won't validate against the grafted
// root.
impl<E, K, V, U, C, I, H, D, const N: usize> MerkleizedStore
    for Db<E, C, I, H, U, N, Merkleized<H>, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V, U>;

    fn root(&self) -> H::Digest {
        self.root()
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<Self::Digest>, Vec<Self::Operation>), Error> {
        self.any
            .historical_proof(historical_size, start_loc, max_ops)
            .await
    }
}

impl<E, K, V, U, C, I, H, const N: usize, M, D> LogStore for Db<E, C, I, H, U, N, M, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    M: MerkleizationState<DigestOf<H>>,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    type Value = V::Value;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        self.get_metadata().await
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<E, K, V, U, C, I, H, const N: usize, D> PrunableStore
    for Db<E, C, I, H, U, N, Merkleized<H>, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

/// Build the grafted MMR from pinned nodes + fresh computation for unpruned chunks.
pub(super) async fn build_grafted_mmr<H, const N: usize>(
    hasher: &mut StandardHasher<H>,
    bitmap: &PrunableBitMap<N>,
    pinned_nodes: &[H::Digest],
    ops_mmr: &impl crate::mmr::storage::Storage<H::Digest>,
    graft_height: u32,
) -> Result<CleanMmr<H::Digest>, Error>
where
    H: Hasher,
{
    let pruned_chunks = bitmap.pruned_chunks();

    // Initialize MMR with pinned nodes if pruned
    let mut mmr = if pruned_chunks > 0 {
        let pruned_pos = Position::try_from(Location::new_unchecked(pruned_chunks as u64))?;
        CleanMmr::init(
            crate::mmr::mem::Config {
                nodes: Vec::new(),
                pruned_to_pos: pruned_pos,
                pinned_nodes: pinned_nodes.to_vec(),
            },
            hasher,
        )?
    } else {
        CleanMmr::new(hasher)
    };

    // Calculate complete chunks (exclude partial last chunk)
    let total_chunks = bitmap.chunks_len() + pruned_chunks;
    let complete_chunks = if bitmap.is_chunk_aligned() {
        total_chunks
    } else {
        total_chunks.saturating_sub(1)
    };

    // Add fresh grafted leaves for unpruned complete chunks
    for abs_chunk_idx in pruned_chunks..complete_chunks {
        // Get chunk data (adjusted for pruning)
        let rel_chunk_idx = abs_chunk_idx - pruned_chunks;
        let chunk = bitmap.get_chunk(rel_chunk_idx);

        // Get ops MMR node at grafting position
        // The chunk index is used as a leaf location in the peak tree.
        // We need to find the corresponding base tree position (at grafting height)
        // to get the ops_digest.
        let chunk_loc = Location::new_unchecked(abs_chunk_idx as u64);
        // Convert leaf location to leaf POSITION in the peak tree
        let peak_leaf_pos = Position::try_from(chunk_loc)?;
        // destination_pos converts peak tree position to base tree position
        let ops_pos = destination_pos(peak_leaf_pos, graft_height);
        let ops_digest = ops_mmr
            .get_node(ops_pos)
            .await?
            .ok_or(crate::mmr::Error::MissingNode(ops_pos))?;

        // Compute grafted leaf: H(chunk || ops_digest)
        // Use inner() to get a fresh hasher state for computing the grafted digest
        hasher.inner().update(chunk);
        hasher.inner().update(&ops_digest);
        let leaf_digest = hasher.inner().finalize();

        // Use add_leaf_digest to store the pre-computed grafted digest directly,
        // without re-hashing it (which add() would do).
        mmr.add_leaf_digest(hasher, leaf_digest);
    }

    Ok(mmr)
}

/// Compute the root of the current QMDB from the grafted MMR, ops MMR, and bitmap.
pub(super) async fn compute_root<H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    bitmap: &PrunableBitMap<N>,
    grafted_mmr: &CleanMmr<H::Digest>,
    ops_mmr: &impl crate::mmr::storage::Storage<H::Digest>,
    graft_height: u32,
) -> Result<H::Digest, Error> {
    use crate::mmr::grafting::Storage as GraftingStorage;

    // Create grafted storage to compute the combined root
    let grafted_storage = GraftingStorage::<'_, H, _, _>::new(grafted_mmr, ops_mmr, graft_height);
    let mmr_root = grafted_storage.root(hasher).await?;

    // If on a chunk boundary, mmr_root fully captures the state
    let (last_chunk, next_bit) = bitmap.last_chunk();
    if next_bit == PrunableBitMap::<N>::CHUNK_SIZE_BITS {
        return Ok(mmr_root);
    }

    // Include partial chunk in root
    hasher.inner().update(last_chunk);
    let last_chunk_digest = hasher.inner().finalize();

    Ok(partial_chunk_root::<H, N>(
        hasher.inner(),
        &mmr_root,
        next_bit,
        &last_chunk_digest,
    ))
}
