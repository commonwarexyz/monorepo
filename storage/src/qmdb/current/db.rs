//! A shared, generic implementation of the _Current_ QMDB.
//!
//! The impl blocks in this file defines shared functionality across all Current QMDB variants.

use crate::{
    bitmap::{CleanBitMap, DirtyBitMap},
    index::Unordered as UnorderedIndex,
    journal::{
        contiguous::{Contiguous, MutableContiguous},
        Error as JournalError,
    },
    mmr::{
        grafting::{Hasher as GraftingHasher, Storage as GraftingStorage},
        hasher::Hasher as MmrHasher,
        journaled::Mmr,
        mem::Clean,
        Location, Proof, StandardHasher,
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
    AuthenticatedBitMap as BitMap, Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{bitmap::Prunable as PrunableBitMap, Array};
use core::{num::NonZeroU64, ops::Range};

/// Get the grafting height for a bitmap with chunk size determined by N.
const fn grafting_height<const N: usize>() -> u32 {
    PrunableBitMap::<N>::CHUNK_SIZE_BITS.trailing_zeros()
}

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

    /// The bitmap over the activity status of each operation. Supports augmenting [Db] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    pub(super) status: BitMap<E, H::Digest, N, M>,

    /// Cached root digest. Invariant: valid when in Clean state.
    pub(super) cached_root: Option<H::Digest>,
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
        RangeProof::<H::Digest>::new_with_ops(
            hasher,
            &self.status,
            Self::grafting_height(),
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
        // Write the pruned portion of the bitmap to disk *first* to ensure recovery in case of
        // failure during pruning. If we don't do this, we may not be able to recover the bitmap
        // because it may require replaying of pruned operations.
        self.status.write_pruned().await?;

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

        // Write the bitmap pruning boundary to disk so that next startup doesn't have to
        // re-Merkleize the inactive portion up to the inactivity floor.
        self.status.write_pruned().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        // Clean up bitmap metadata partition.
        self.status.destroy().await?;

        // Clean up Any components (MMR and log).
        self.any.destroy().await
    }

    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status.into_dirty(),
            cached_root: None,
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

        // Merkleize the bitmap using the clean MMR
        let hasher = &mut any.log.hasher;
        let mut status = merkleize_grafted_bitmap(hasher, self.status, &any.log.mmr).await?;

        // Prune the bitmap of no-longer-necessary bits.
        status.prune_to_bit(*any.inactivity_floor_loc)?;

        // Compute and cache the root
        let cached_root = Some(root(hasher, &status, &any.log.mmr).await?);

        Ok(Db {
            any,
            status,
            cached_root,
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
            cached_root: None,
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
                cached_root: None, // Not merkleized yet
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
            status: self.status.into_dirty(),
            cached_root: None,
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

/// Return the root of the current QMDB represented by the provided mmr and bitmap.
pub(super) async fn root<E: Storage + Clock + Metrics, H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    status: &CleanBitMap<E, H::Digest, N>,
    mmr: &Mmr<E, H::Digest, Clean<DigestOf<H>>>,
) -> Result<H::Digest, Error> {
    let grafted_mmr = GraftingStorage::<'_, H, _, _>::new(status, mmr, grafting_height::<N>());
    let mmr_root = grafted_mmr.root(hasher).await?;

    // If we are on a chunk boundary, then the mmr_root fully captures the state of the DB.
    let (last_chunk, next_bit) = status.last_chunk();
    if next_bit == PrunableBitMap::<N>::CHUNK_SIZE_BITS {
        // Last chunk is complete, no partial chunk to add
        return Ok(mmr_root);
    }

    // There are bits in an uncommitted (partial) chunk, so we need to incorporate that information
    // into the root digest to fully capture the database state. We do so by hashing the mmr root
    // along with the number of bits within the last chunk and the digest of the last chunk.
    hasher.inner().update(last_chunk);
    let last_chunk_digest = hasher.inner().finalize();

    Ok(crate::bitmap::partial_chunk_root::<H, N>(
        hasher.inner(),
        &mmr_root,
        next_bit,
        &last_chunk_digest,
    ))
}

/// Consumes a `DirtyBitMap`, performs merkleization using the provided hasher and MMR storage,
/// and returns a `CleanBitMap` containing the merkleized result.
///
/// # Arguments
/// * `hasher` - The hasher used for merkleization.
/// * `status` - The `DirtyBitMap` to be merkleized. Ownership is taken.
/// * `mmr` - The MMR storage used for grafting.
pub(super) async fn merkleize_grafted_bitmap<E, H, const N: usize>(
    hasher: &mut StandardHasher<H>,
    status: DirtyBitMap<E, H::Digest, N>,
    mmr: &impl crate::mmr::storage::Storage<H::Digest>,
) -> Result<CleanBitMap<E, H::Digest, N>, Error>
where
    E: Storage + Clock + Metrics,
    H: Hasher,
{
    let mut grafter = GraftingHasher::new(hasher, grafting_height::<N>());
    grafter
        .load_grafted_digests(&status.dirty_chunks(), mmr)
        .await?;
    status.merkleize(&mut grafter).await.map_err(Into::into)
}
