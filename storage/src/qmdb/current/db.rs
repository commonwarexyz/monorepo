//! A shared, generic implementation of the _Current_ QMDB.
//!
//! The impl blocks in this file defines shared functionality across all Current QMDB variants.

use crate::{
    bitmap::partial_chunk_root,
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable, Persistable as JournalPersistable},
    metadata::{Config as MConfig, Metadata},
    mmr::{
        self,
        hasher::Hasher as _,
        iterator::{nodes_to_pin, PeakIterator},
        storage::Storage as _,
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
        DurabilityState, Durable, Error, MerkleizationState, NonDurable,
    },
    Persistable,
};
use commonware_codec::{Codec, CodecShared, DecodeExt};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_parallel::ThreadPool;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{bitmap::Prunable as BitMap, sequence::prefixed_u64::U64, Array};
use core::{num::NonZeroU64, ops::Range};
use futures::{future::try_join_all, lock::Mutex};
use rayon::prelude::*;
use std::collections::HashSet;
use tracing::{error, warn};

/// Prefix used for the metadata key for grafted MMR pinned nodes.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key for the number of pruned bitmap chunks.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

mod private {
    pub trait Sealed {}
}

/// Trait for valid [Db] type states.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {
    /// The merkleization type state for the inner `any::db::Db`.
    type MerkleizationState: MerkleizationState<D>;
}

/// Merkleized state: the database has been merkleized and the root is cached.
pub struct Merkleized<D: Digest> {
    /// The cached root of the database (combining bitmap and operations MMR).
    pub(super) root: D,
}

impl<D: Digest> private::Sealed for Merkleized<D> {}
impl<D: Digest> State<D> for Merkleized<D> {
    type MerkleizationState = mmr::mem::Clean<D>;
}

/// Unmerkleized state: the database has pending changes not yet merkleized.
pub struct Unmerkleized {
    /// Bitmap chunks modified since the last merkleization. Only contains chunks that were
    /// complete at last merkleization (index < old_grafted_leaves). Chunks completed or created
    /// since then are covered by the `old_grafted_leaves..new_grafted_leaves` range in
    /// `into_merkleized`.
    pub(super) dirty_chunks: HashSet<usize>,
}

impl private::Sealed for Unmerkleized {}
impl<D: Digest> State<D> for Unmerkleized {
    type MerkleizationState = mmr::mem::Dirty;
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
    pub(super) any: any::db::Db<E, C, I, H, U, S::MerkleizationState, D>,

    /// The bitmap over the activity status of each operation. Supports augmenting [Db] proofs in
    /// order to further prove whether a key _currently_ has a specific value.
    pub(super) status: BitMap<N>,

    /// Each leaf is hash(chunk || ops_subtree_root) for a complete bitmap chunk and
    /// the ops MMR node at the grafting height.
    /// Internal nodes are hashed using their position in the ops MMR rather than their
    /// grafted position.
    pub(super) grafted_mmr: mmr::mem::CleanMmr<H::Digest>,

    /// Persists:
    /// - The number of pruned bitmap chunks at key [PRUNED_CHUNKS_PREFIX]
    /// - The grafted MMR pinned nodes at key [NODE_PREFIX]
    pub(super) metadata: Mutex<Metadata<E, U64, Vec<u8>>>,

    /// Optional thread pool for parallelizing grafted leaf computation.
    pub(super) thread_pool: Option<ThreadPool>,

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

    /// Returns a virtual [grafting::Storage] over the grafted MMR and ops MMR.
    /// For positions at or above the grafting height, returns grafted MMR node.
    /// For positions below the grafting height, the ops MMR is used.
    fn grafted_storage(&self) -> impl mmr::storage::Storage<H::Digest> + '_ {
        grafting::Storage::new(
            &self.grafted_mmr,
            grafting::height::<N>(),
            &self.any.log.mmr,
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
    C: Mutable<Item = Operation<K, V, U>>,
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
        // Persist grafted MMR pruning state before pruning the ops log. If the subsequent
        // `any.prune` fails, the metadata is ahead of the log, which is safe: on recovery,
        // `build_grafted_mmr` will recompute from the (un-pruned) log and the metadata
        // simply records peaks that haven't been pruned yet. The reverse order would be unsafe:
        // a pruned log with stale metadata would lose peak digests permanently.
        self.sync_metadata().await?;

        self.any.prune(prune_loc).await
    }

    /// Sync the metadata to disk.
    async fn sync_metadata(&self) -> Result<(), Error> {
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
        let ops_mmr_size = Position::try_from(Location::new_unchecked(pruned_ops))?;
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

// Functionality specific to (Merkleized, Durable) state, such as ability to persist the database.
impl<E, K, V, U, C, I, H, const N: usize> Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + JournalPersistable,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
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

    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            grafted_mmr: self.grafted_mmr,
            metadata: self.metadata,
            thread_pool: self.thread_pool,
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
            grafted_mmr,
            metadata,
            thread_pool: pool,
            state,
        } = self;

        // Merkleize the any db
        let mut any = any.into_merkleized();

        // Number of grafted leaves (i.e. complete bitmap chunks) at last merkleization.
        let old_grafted_leaves = *grafted_mmr.leaves() as usize;
        // Number of grafted leaves (i.e. complete bitmap chunks) now.
        let new_grafted_leaves = status.complete_chunks();

        // Compute grafted leaves for new complete bitmap chunks and modified existing chunks.
        // dirty_chunks is guaranteed to only contain indices < old_grafted_leaves, so no
        // filtering or deduplication is needed.
        let chunks_to_update = (old_grafted_leaves..new_grafted_leaves)
            .chain(state.dirty_chunks.iter().copied())
            .map(|chunk_idx| (chunk_idx, *status.get_chunk(chunk_idx)));
        let grafted_leaves = compute_grafted_leaves::<H, N>(
            &mut any.log.hasher,
            &any.log.mmr,
            chunks_to_update,
            pool.as_ref(),
        )
        .await?;

        // Update the grafted MMR with new/dirty leaves and re-merkleize.
        let grafting_height = grafting::height::<N>();
        let mut dirty = grafted_mmr.into_dirty();
        for &(ops_pos, digest) in &grafted_leaves {
            let grafted_pos = grafting::ops_to_grafted_pos(ops_pos, grafting_height);
            if grafted_pos < dirty.size() {
                let loc = Location::try_from(grafted_pos).expect("grafted_pos overflow");
                dirty
                    .update_leaf_digest(loc, digest)
                    .expect("update_leaf_digest failed");
            } else {
                dirty.add_leaf_digest(digest);
            }
        }
        let mut grafted_mmr = {
            let mut grafted_hasher =
                grafting::GraftedHasher::new(any.log.hasher.fork(), grafting_height);
            dirty.merkleize(&mut grafted_hasher, pool.clone())
        };

        // Prune bitmap chunks that are fully below the inactivity floor. All their bits are
        // guaranteed to be 0, so we can discard them.
        status.prune_to_bit(*any.inactivity_floor_loc);

        // Prune the grafted MMR to match: nodes for pruned bitmap chunks are no longer needed
        // in memory. `prune_to_pos` pins the O(log n) peak digests covering the pruned region,
        // which remain accessible via `get_node` for root computation and metadata persistence.
        let pruned_chunks = status.pruned_chunks() as u64;
        if pruned_chunks > 0 {
            let new_grafted_mmr_prune_pos =
                Position::try_from(Location::new_unchecked(pruned_chunks))?;
            if new_grafted_mmr_prune_pos > grafted_mmr.bounds().start {
                grafted_mmr.prune_to_pos(new_grafted_mmr_prune_pos);
            }
        }

        // Compute and cache the root.
        let storage = grafting::Storage::new(&grafted_mmr, grafting_height, &any.log.mmr);
        let partial_chunk = partial_chunk(&status);
        let root = compute_root(&mut any.log.hasher, &storage, partial_chunk).await?;

        Ok(Db {
            any,
            status,
            grafted_mmr,
            metadata,
            thread_pool: pool,
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
            grafted_mmr: self.grafted_mmr,
            metadata: self.metadata,
            thread_pool: self.thread_pool,
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
    C: Mutable<Item = Operation<K, V, U>> + JournalPersistable,
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
        let old_grafted_leaves = *self.grafted_mmr.leaves() as usize;

        // Inactivate the current commit operation.
        self.status.set_bit(*self.any.last_commit_loc, false);
        let chunk = BitMap::<N>::to_chunk_index(*self.any.last_commit_loc);
        if chunk < old_grafted_leaves {
            self.state.dirty_chunks.insert(chunk);
        }

        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let dirty_chunks = &mut self.state.dirty_chunks;
        let inactivity_floor_loc = self
            .any
            .raise_floor_with_bitmap(&mut self.status, &mut |old_loc, _new_loc| {
                let chunk = BitMap::<N>::to_chunk_index(*old_loc);
                if chunk < old_grafted_leaves {
                    dirty_chunks.insert(chunk);
                }
            })
            .await?;

        // Append the commit operation with the new floor and tag it as active in the bitmap.
        self.status.push(true);
        let commit_op = Operation::CommitFloor(metadata, inactivity_floor_loc);

        self.any.apply_commit_op(commit_op).await?;

        Ok(start_loc..self.any.log.size().await)
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
                grafted_mmr: self.grafted_mmr,
                metadata: self.metadata,
                thread_pool: self.thread_pool,
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
    C: Mutable<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, N, Unmerkleized, NonDurable> {
        Db {
            any: self.any.into_mutable(),
            status: self.status,
            grafted_mmr: self.grafted_mmr,
            metadata: self.metadata,
            thread_pool: self.thread_pool,
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
    C: Mutable<Item = Operation<K, V, U>> + JournalPersistable,
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
        Self::sync(self).await
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
    C: Mutable<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V, U>;

    async fn root(&self) -> H::Digest {
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

    async fn bounds(&self) -> std::ops::Range<Location> {
        self.any.bounds().await
    }

    async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        self.get_metadata().await
    }
}

impl<E, K, V, U, C, I, H, D, const N: usize> PrunableStore
    for Db<E, C, I, H, U, N, Merkleized<DigestOf<H>>, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }

    async fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }
}

/// Returns `Some((last_chunk, next_bit))` if the bitmap has an incomplete trailing chunk, or
/// `None` if all bits fall on complete chunk boundaries.
pub(super) fn partial_chunk<const N: usize>(bitmap: &BitMap<N>) -> Option<(&[u8; N], u64)> {
    let (last_chunk, next_bit) = bitmap.last_chunk();
    if next_bit == BitMap::<N>::CHUNK_SIZE_BITS {
        None
    } else {
        Some((last_chunk, next_bit))
    }
}

/// Compute the root digest of a [Db].
/// `storage` is the grafted storage over the grafted MMR and the ops MMR.
/// `partial_chunk` is `Some((last_chunk, next_bit))` if the bitmap has an incomplete trailing chunk,
/// or `None` if all bits fall on complete chunk boundaries.
pub(super) async fn compute_root<H: Hasher, S: mmr::storage::Storage<H::Digest>, const N: usize>(
    hasher: &mut StandardHasher<H>,
    storage: &grafting::Storage<'_, H::Digest, S>,
    partial_chunk: Option<(&[u8; N], u64)>,
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

    let mmr_root = hasher.root(leaves, peaks.iter());

    let Some((last_chunk, next_bit)) = partial_chunk else {
        return Ok(mmr_root);
    };

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

/// Compute grafted leaf digests for the given bitmap chunks.
///
/// Each leaf is `hash(chunk || ops_subtree_root)`. Returns `(ops_pos, digest)` pairs.
///
/// When a thread pool is provided and there are enough chunks, hashing is parallelized.
async fn compute_grafted_leaves<H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    ops_mmr: &impl mmr::storage::Storage<H::Digest>,
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

    // Hash each: grafted_leaf = hash(chunk || ops_subtree_root).
    Ok(
        match pool.filter(|_| inputs.len() >= grafting::MIN_TO_PARALLELIZE) {
            Some(pool) => pool.install(|| {
                inputs
                    .into_par_iter()
                    .map_init(
                        || hasher.fork(),
                        |h, (ops_pos, ops_digest, chunk)| {
                            h.inner().update(&chunk);
                            h.inner().update(&ops_digest);
                            (ops_pos, h.inner().finalize())
                        },
                    )
                    .collect()
            }),
            None => inputs
                .into_iter()
                .map(|(ops_pos, ops_digest, chunk)| {
                    hasher.inner().update(&chunk);
                    hasher.inner().update(&ops_digest);
                    (ops_pos, hasher.inner().finalize())
                })
                .collect(),
        },
    )
}

/// Build a grafted [mmr::mem::CleanMmr] from scratch using bitmap chunks and the ops MMR.
pub(super) async fn build_grafted_mmr<H: Hasher, const N: usize>(
    hasher: &mut StandardHasher<H>,
    bitmap: &BitMap<N>,
    pinned_nodes: &[H::Digest],
    ops_mmr: &impl mmr::storage::Storage<H::Digest>,
    pool: Option<&ThreadPool>,
) -> Result<mmr::mem::CleanMmr<H::Digest>, Error> {
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

    // Build a DirtyMmr: either from pruned components or empty.
    let mut dirty = if pruned_chunks > 0 {
        let grafted_pruned_to_pos =
            Position::try_from(Location::new_unchecked(pruned_chunks as u64))
                .expect("pruned_chunks overflow");
        mmr::mem::DirtyMmr::from_components(
            Vec::new(),
            grafted_pruned_to_pos,
            pinned_nodes.to_vec(),
        )
    } else {
        mmr::mem::DirtyMmr::default()
    };

    // Add each grafted leaf digest. Leaves arrive in chunk-index order (ascending),
    // which is the same as grafted leaf location order.
    for &(_ops_pos, digest) in &leaves {
        dirty.add_leaf_digest(digest);
    }

    // Merkleize with the GraftedHasher to produce ops-space positions in hash pre-images.
    let mut grafted_hasher = grafting::GraftedHasher::new(hasher.fork(), grafting_height);
    let grafted_mmr = dirty.merkleize(&mut grafted_hasher, pool.cloned());

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
