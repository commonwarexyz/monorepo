//! A shared, generic implementation of the _Current_ QMDB.
//! This module contains the core [Db] struct and its state transitions.

use crate::{
    bitmap::partial_chunk_root,
    index::Unordered as UnorderedIndex,
    journal::{
        contiguous::{Contiguous, MutableContiguous},
        Error as JournalError,
    },
    metadata::{Config as MConfig, Metadata},
    mmr::{
        self,
        hasher::Hasher as _,
        iterator::{nodes_to_pin, PeakIterator},
        Location, Position, Proof, StandardHasher,
    },
    qmdb::{
        any::{
            self,
            operation::{update::Update, Operation},
            ValueEncoding,
        },
        current::{
            grafting,
            proof::{OperationProof, RangeProof},
        },
        store::{self, LogStore, MerkleizedStore, PrunableStore},
        DurabilityState, Durable, Error, NonDurable,
    },
    Persistable,
};
use commonware_codec::{Codec, CodecShared, DecodeExt};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{bitmap::Prunable as BitMap, sequence::prefixed_u64::U64, Array};
use core::{num::NonZeroU64, ops::Range};
use std::collections::{BTreeMap, HashSet};
use tracing::{error, warn};

/// Prefix used for the metadata key identifying grafted digest pinned node digests.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key identifying the pruned_chunks value.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

mod private {
    pub trait Sealed {}
}

/// Trait for valid [Db] type states.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {
    /// The merkleization type state for the inner `any::db::Db`.
    type MmrState: mmr::mem::State<D>;
}

/// Merkleized state: the database has been merkleized and the root is cached.
pub struct Merkleized<D: Digest> {
    /// The cached root of the database (combining bitmap and operations MMR).
    pub(super) root: D,
}

impl<D: Digest> private::Sealed for Merkleized<D> {}
impl<D: Digest> State<D> for Merkleized<D> {
    type MmrState = mmr::mem::Clean<D>;
}

/// Unmerkleized state: the database has pending changes not yet merkleized.
pub struct Unmerkleized {
    /// Bitmap chunks modified since the last merkleization. Each entry is an absolute chunk index
    /// (accounting for pruning). May contain the index of the last, partial chunk.
    pub(super) dirty_chunks: HashSet<usize>,
}

impl private::Sealed for Unmerkleized {}
impl<D: Digest> State<D> for Unmerkleized {
    type MmrState = mmr::mem::Dirty;
}

/// A Current QMDB implementation generic over ordered/unordered keys and variable/fixed values.
pub struct Db<
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
    const N: usize,
    S: State<DigestOf<H>> = Merkleized<DigestOf<H>>,
    D: DurabilityState = Durable,
> {
    /// An authenticated database that provides the ability to prove whether a key ever had a
    /// specific value.
    pub(super) any: any::db::Db<E, C, I, H, U, S::MmrState, D>,

    /// The raw bitmap over the activity status of each operation.
    pub(super) status: BitMap<N>,

    /// Cache of grafted digests keyed by ops MMR positions. At the grafting height, entries are
    /// `hash(chunk || ops_subtree_root)`. Above the grafting height, entries are standard MMR
    /// internal nodes using ops-space positions in their hash pre-image.
    pub(super) grafted_digests: BTreeMap<Position, H::Digest>,

    /// The number of complete bitmap chunks that have grafted leaf entries in `grafted_digests`.
    /// Set during merkleization and init; used to detect new complete chunks.
    pub(super) grafted_leaf_count: usize,

    /// Metadata storage for persisting pruned_chunks count and grafted digest pinned nodes.
    pub(super) bitmap_metadata: Metadata<E, U64, Vec<u8>>,

    /// Type state based on whether the database is [Merkleized] or [Unmerkleized].
    pub(super) state: S,
}

// Functionality shared across all DB states, such as most non-mutating operations.
impl<E, K, V, C, I, H, U, const N: usize, S, D> Db<E, C, I, H, U, N, S, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    S: State<DigestOf<H>>,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
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
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        self.any.get_metadata().await
    }

    /// Return true if the given sequence of `ops` were applied starting at location `start_loc`
    /// in the log with the provided `root`, having the activity status described by `chunks`.
    pub fn verify_range_proof(
        hasher: &mut H,
        proof: &RangeProof<H::Digest>,
        start_loc: Location,
        ops: &[Operation<K, V, U>],
        chunks: &[[u8; N]],
        root: &H::Digest,
    ) -> bool {
        proof.verify(hasher, start_loc, ops, chunks, root)
    }
}

// Functionality shared across Merkleized states with non-mutable journal.
impl<E, K, V, U, C, I, H, D, const N: usize> Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, D>
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
    pub const fn root(&self) -> H::Digest {
        self.state.root
    }

    /// Returns a virtual [grafting::Storage] over the grafted digest cache and ops MMR.
    ///
    /// This presents the grafted digests (at or above grafting height) and the raw ops
    /// MMR nodes (below grafting height) as a single combined MMR storage.
    fn grafted_storage(&self) -> impl mmr::storage::Storage<H::Digest> + '_ {
        grafting::Storage::new(
            &self.grafted_digests,
            &self.any.log.mmr,
            grafting::height::<N>(),
        )
    }

    /// Returns a proof for the operation at `loc`.
    pub(super) async fn operation_proof(
        &self,
        hasher: &mut H,
        loc: Location,
    ) -> Result<OperationProof<H::Digest, N>, Error> {
        let storage = self.grafted_storage();
        OperationProof::new(hasher, &self.status, &storage, loc).await
    }

    /// Returns a proof that the specified range of operations are part of the database, along with
    /// the operations from the range. A truncated range (from hitting the max) can be detected by
    /// looking at the length of the returned operations vector. Also returns the bitmap chunks
    /// required to verify the proof.
    ///
    /// # Errors
    ///
    /// Returns [mmr::Error::LocationOverflow] if `start_loc` > [mmr::MAX_LOCATION].
    /// Returns [mmr::Error::RangeOutOfBounds] if `start_loc` >= number of leaves in the MMR.
    pub async fn range_proof(
        &self,
        hasher: &mut H,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(RangeProof<H::Digest>, Vec<Operation<K, V, U>>, Vec<[u8; N]>), Error> {
        let storage = self.grafted_storage();
        RangeProof::new_with_ops(
            hasher,
            &self.status,
            &storage,
            &self.any.log,
            start_loc,
            max_ops,
        )
        .await
    }
}

// Functionality shared across Merkleized states with mutable journal.
impl<E, K, V, U, C, I, H, D, const N: usize> Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, D>
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
    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [mmr::Error::LocationOverflow] if `prune_loc` > [mmr::MAX_LOCATION].
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        // Persist grafted digest pruning state before pruning the ops log. If the subsequent
        // `any.prune` fails, the metadata is ahead of the log, which is safe: on recovery,
        // `build_grafted_digests` will recompute from the (un-pruned) log and the metadata
        // simply records peaks that haven't been pruned yet. The reverse order would be unsafe:
        // a pruned log with stale metadata would lose peak digests permanently.
        self.write_pruned().await?;

        self.any.prune(prune_loc).await
    }

    /// Write the information necessary to restore grafted digests after pruning.
    async fn write_pruned(&mut self) -> Result<(), Error> {
        self.bitmap_metadata.clear();

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        self.bitmap_metadata
            .put(key, self.status.pruned_chunks().to_be_bytes().to_vec());

        // Write the grafted digest pinned nodes. These are the ops-space peaks covering the
        // pruned portion of the bitmap.
        let pruned_ops_leaves = self.status.pruned_chunks() as u64 * BitMap::<N>::CHUNK_SIZE_BITS;
        let ops_mmr_size = Position::try_from(Location::new_unchecked(pruned_ops_leaves))?;
        for (i, (ops_pos, _)) in PeakIterator::new(ops_mmr_size).enumerate() {
            let digest = self
                .grafted_digests
                .get(&ops_pos)
                .ok_or(mmr::Error::MissingNode(ops_pos))?;
            let key = U64::new(NODE_PREFIX, i as u64);
            self.bitmap_metadata.put(key, digest.to_vec());
        }

        self.bitmap_metadata
            .sync()
            .await
            .map_err(mmr::Error::MetadataError)?;

        Ok(())
    }
}

// Functionality specific to (Merkleized, Durable) state, such as ability to persist the database.
impl<E, K, V, U, C, I, H, const N: usize> Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, Durable>
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
        self.write_pruned().await
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        // Clean up bitmap metadata partition.
        self.bitmap_metadata
            .destroy()
            .await
            .map_err(|e| Error::Mmr(mmr::Error::MetadataError(e)))?;

        // Clean up Any components (MMR and log).
        self.any.destroy().await
    }

    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            grafted_digests: self.grafted_digests,
            grafted_leaf_count: self.grafted_leaf_count,
            bitmap_metadata: self.bitmap_metadata,
            state: Unmerkleized {
                dirty_chunks: HashSet::new(),
            },
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
    pub async fn into_merkleized(
        self,
    ) -> Result<Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, D>, Error> {
        let Self {
            any,
            mut status,
            mut grafted_digests,
            grafted_leaf_count,
            bitmap_metadata,
            state,
        } = self;

        // Merkleize the any db (ops MMR: Dirty -> Clean)
        let mut any = any.into_merkleized();

        // Number of grafted leaves (i.e. complete chunks) at last merkleization.
        let old_grafted_leaves = grafted_leaf_count;
        // Number of grafted leaves (i.e. complete chunks) now.
        let new_grafted_leaves = status.complete_chunks();

        // Need to compute grafted leaves for new complete chunks and modified existing chunks.
        let chunks_to_update = (old_grafted_leaves..new_grafted_leaves).chain(
            state
                .dirty_chunks
                .iter()
                .copied()
                .filter(|&c| c < old_grafted_leaves),
        );
        recompute_grafted_leaves::<H, N>(
            &mut any.log.hasher,
            &status,
            &mut grafted_digests,
            &any.log.mmr,
            chunks_to_update,
        )
        .await?;

        // Prune the bitmap of no-longer-necessary bits.
        status.prune_to_bit(*any.inactivity_floor_loc);

        // Compute and cache the root.
        let storage =
            grafting::Storage::new(&grafted_digests, &any.log.mmr, grafting::height::<N>());
        let root = compute_root::<H, N>(&mut any.log.hasher, &status, &storage).await?;

        Ok(Db {
            any,
            status,
            grafted_digests,
            grafted_leaf_count: new_grafted_leaves,
            bitmap_metadata,
            state: Merkleized { root },
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
            grafted_digests: self.grafted_digests,
            grafted_leaf_count: self.grafted_leaf_count,
            bitmap_metadata: self.bitmap_metadata,
            state: Unmerkleized {
                dirty_chunks: self.state.dirty_chunks,
            },
        }
    }
}

// Functionality specific to (Unmerkleized, NonDurable) state.
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
        self.state
            .dirty_chunks
            .insert(BitMap::<N>::unpruned_chunk(*self.any.last_commit_loc));

        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let dirty_chunks = &mut self.state.dirty_chunks;
        let inactivity_floor_loc = self
            .any
            .raise_floor_with_callback(&mut self.status, &mut |old_loc, new_loc| {
                dirty_chunks.insert(BitMap::<N>::unpruned_chunk(*old_loc));
                dirty_chunks.insert(BitMap::<N>::unpruned_chunk(*new_loc));
            })
            .await?;

        // Append the commit operation with the new floor and tag it as active in the bitmap.
        self.status.push(true);
        let commit_op = Operation::CommitFloor(metadata, inactivity_floor_loc);

        self.any.apply_commit_op(commit_op).await?;

        Ok(start_loc..self.any.log.bounds().end)
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
                grafted_digests: self.grafted_digests,
                grafted_leaf_count: self.grafted_leaf_count,
                bitmap_metadata: self.bitmap_metadata,
                state: Unmerkleized {
                    dirty_chunks: self.state.dirty_chunks,
                },
            },
            range,
        ))
    }
}

// Functionality specific to (Merkleized, NonDurable) state.
impl<E, K, V, U, C, I, H, const N: usize> Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, NonDurable>
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
            grafted_digests: self.grafted_digests,
            grafted_leaf_count: self.grafted_leaf_count,
            bitmap_metadata: self.bitmap_metadata,
            state: Unmerkleized {
                dirty_chunks: HashSet::new(),
            },
        }
    }
}

impl<E, K, V, U, C, I, H, const N: usize> Persistable
    for Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, Durable>
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
    for Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, D>
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

impl<E, K, V, U, C, I, H, const N: usize, S, D> LogStore for Db<E, C, I, H, U, N, S, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    S: State<DigestOf<H>>,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    type Value = V::Value;

    fn bounds(&self) -> std::ops::Range<Location> {
        self.any.bounds()
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

impl<E, K, V, U, C, I, H, D, const N: usize> PrunableStore
    for Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, D>
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

/// Compute the root of the current QMDB from the grafted storage and bitmap.
pub(super) async fn compute_root<H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    bitmap: &BitMap<N>,
    storage: &impl mmr::storage::Storage<H::Digest>,
) -> Result<H::Digest, Error> {
    let size = storage.size();
    let leaves = Location::try_from(size).map_err(mmr::Error::from)?;

    // Collect peak digests from the grafted storage, which transparently dispatches
    // to the grafted digest cache or the ops MMR based on height.
    let mut peaks = Vec::new();
    for (peak_pos, _) in PeakIterator::new(size) {
        let digest = storage
            .get_node(peak_pos)
            .await?
            .ok_or(mmr::Error::MissingNode(peak_pos))?;
        peaks.push(digest);
    }

    let mmr_root = hasher.root(leaves, peaks.iter());

    let (last_chunk, next_bit) = bitmap.last_chunk();
    if next_bit == BitMap::<N>::CHUNK_SIZE_BITS {
        return Ok(mmr_root);
    }

    // There are bits in an uncommitted (partial) chunk, so we need to incorporate that information
    // into the root digest to fully capture the database state.
    let last_chunk_digest = hasher.digest(last_chunk);

    Ok(partial_chunk_root::<H, N>(
        hasher.inner(),
        &mmr_root,
        next_bit,
        &last_chunk_digest,
    ))
}

/// Compute the grafted leaf digest for a given chunk index.
///
/// grafted_leaf = hash(chunk || ops_subtree_root)
async fn compute_grafted_leaf_for_chunk<H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    status: &BitMap<N>,
    ops_mmr: &impl mmr::storage::Storage<H::Digest>,
    chunk_idx: usize,
) -> Result<H::Digest, Error> {
    let relative_idx = chunk_idx - status.pruned_chunks();
    let chunk = status.get_chunk(relative_idx);

    let ops_pos = grafting::chunk_idx_to_ops_pos(chunk_idx as u64, grafting::height::<N>());
    let ops_digest = ops_mmr
        .get_node(ops_pos)
        .await?
        .ok_or(mmr::Error::MissingGraftedDigest(Location::new_unchecked(
            chunk_idx as u64,
        )))?;

    hasher.inner().update(chunk);
    hasher.inner().update(&ops_digest);
    Ok(hasher.inner().finalize())
}

/// Update the grafted digest cache to reflect changes in the given bitmap chunks.
///
/// Each chunk's grafted leaf is recomputed as `hash(chunk || ops_subtree_root)`, and ancestor
/// nodes are propagated upward so the tree stays consistent.
async fn recompute_grafted_leaves<H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    bitmap: &BitMap<N>,
    grafted_digests: &mut BTreeMap<Position, H::Digest>,
    ops_mmr: &impl mmr::storage::Storage<H::Digest>,
    chunks: impl Iterator<Item = usize>,
) -> Result<(), Error> {
    let grafting_height = grafting::height::<N>();
    let mut dirty_positions = Vec::new();
    for chunk_idx in chunks {
        let ops_pos = grafting::chunk_idx_to_ops_pos(chunk_idx as u64, grafting_height);
        let leaf = compute_grafted_leaf_for_chunk(hasher, bitmap, ops_mmr, chunk_idx).await?;
        grafted_digests.insert(ops_pos, leaf);
        dirty_positions.push(ops_pos);
    }
    grafting::propagate_dirty(grafted_digests, hasher, &dirty_positions, ops_mmr.size());
    Ok(())
}

/// Build a grafted digests cache from scratch using bitmap chunks and the ops MMR.
///
/// Returns the BTreeMap of grafted digests (keyed by ops-space positions) and the number of
/// complete chunks that were processed (for initializing `grafted_leaf_count`).
pub(super) async fn build_grafted_digests<H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    bitmap: &BitMap<N>,
    pinned_nodes: &[H::Digest],
    ops_mmr: &impl mmr::storage::Storage<H::Digest>,
) -> Result<(BTreeMap<Position, H::Digest>, usize), Error> {
    let pruned_chunks = bitmap.pruned_chunks();
    let mut map = BTreeMap::new();

    // Load pinned nodes from recovery (if pruned). Pinned nodes are the ops-space peaks
    // covering the pruned portion of the bitmap.
    if pruned_chunks > 0 {
        let pruned_ops_leaves = pruned_chunks as u64 * BitMap::<N>::CHUNK_SIZE_BITS;
        let ops_mmr_size = Position::try_from(Location::new_unchecked(pruned_ops_leaves))?;
        for (digest, (ops_pos, _)) in pinned_nodes.iter().zip(PeakIterator::new(ops_mmr_size)) {
            map.insert(ops_pos, *digest);
        }
    }

    // Compute grafted leaves for each unpruned complete chunk and propagate upward. Pinned
    // nodes (peaks of the pruned subtree) serve as siblings during propagation.
    let complete_chunks = bitmap.complete_chunks();
    recompute_grafted_leaves::<H, N>(
        hasher,
        bitmap,
        &mut map,
        ops_mmr,
        pruned_chunks..complete_chunks,
    )
    .await?;

    Ok((map, complete_chunks))
}

/// Load the bitmap metadata store and recover the pruning state persisted by previous runs.
///
/// The metadata store holds two kinds of entries (keyed by prefix):
/// - **Pruned chunks count** ([PRUNED_CHUNKS_PREFIX]): the number of bitmap chunks that have been
///   pruned. This tells us where the active portion of the bitmap begins.
/// - **Pinned node digests** ([NODE_PREFIX]): grafted MMR digests at peak positions whose
///   underlying data has been pruned. These are needed to recompute the grafted MMR root without
///   the pruned chunks.
///
/// Returns `(metadata_handle, pruned_chunks, pinned_node_digests)`.
pub(super) async fn init_bitmap_metadata<E: Storage + Clock + Metrics, D: Digest>(
    context: E,
    partition: &str,
) -> Result<(Metadata<E, U64, Vec<u8>>, usize, Vec<D>), Error> {
    let metadata_cfg = MConfig {
        partition: partition.to_string(),
        codec_config: ((0..).into(), ()),
    };
    let metadata =
        Metadata::<_, U64, Vec<u8>>::init(context.with_label("metadata"), metadata_cfg).await?;

    let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
    let pruned_chunks = match metadata.get(&key) {
        Some(bytes) => u64::from_be_bytes(bytes.as_slice().try_into().map_err(|_| {
            error!("pruned chunks value not a valid u64");
            mmr::Error::DataCorrupted("pruned chunks value not a valid u64")
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
        let mmr_size = Position::try_from(Location::new_unchecked(pruned_chunks as u64))?;
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
