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
        self,
        hasher::{Hasher as MerkleHasher, Standard as StandardHasher},
        mem::Mem,
        storage::Storage as MerkleStorage,
        Location, Position,
    },
    metadata::{Config as MConfig, Metadata},
    qmdb::{
        self,
        any::{
            self,
            operation::{update::Update, Operation},
        },
        current::{
            batch::BitmapBatch,
            grafting,
            proof::{OperationProof, OpsRootWitness, RangeProof, RangeProofSpec},
        },
        operation::Operation as _,
        Error,
    },
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared, DecodeExt};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_runtime::telemetry::metrics::{
    histogram::{duration_histogram, ScopedTimer, Timed},
    Counter, Gauge, GaugeExt as _, MetricsExt as _,
};
use commonware_utils::{
    bitmap::{self, Readable as _},
    sequence::prefixed_u64::U64,
    sync::AsyncMutex,
};
use core::{num::NonZeroU64, ops::Range};
use futures::future::try_join_all;
use std::{collections::BTreeMap, sync::Arc};
use tracing::{error, warn};

/// Prefix used for the metadata key for grafted tree pinned nodes.
const NODE_PREFIX: u8 = 0;

/// Prefix used for the metadata key for the number of pruned bitmap chunks.
const PRUNED_CHUNKS_PREFIX: u8 = 1;

/// Metrics for the Current layer.
pub(crate) struct Metrics<E: Context> {
    /// Clock used for duration timers.
    clock: Arc<E>,
    /// Pruned bitmap chunks.
    pruned_chunks: Gauge,
    /// Most recent safe sync/prune boundary location.
    sync_boundary: Gauge,
    /// Current-layer apply-batch calls.
    pub apply_batch_calls: Counter,
    /// Duration of Current-layer apply-batch calls.
    apply_batch_duration: Timed,
    /// Current-layer sync calls.
    pub sync_calls: Counter,
    /// Duration of Current-layer sync calls.
    sync_duration: Timed,
    /// Current-layer prune calls.
    pub prune_calls: Counter,
    /// Duration of Current-layer prune calls.
    prune_duration: Timed,
}

impl<E: Context> Metrics<E> {
    /// Create and register metrics.
    pub fn new(context: E) -> Self {
        let pruned_chunks = context.gauge("pruned_chunks", "Number of pruned bitmap chunks");
        let sync_boundary =
            context.gauge("sync_boundary", "Most recent safe sync boundary location");
        let apply_batch_calls = context.counter("apply_batch_calls", "Number of apply-batch calls");
        let apply_batch_duration = duration_histogram(
            &context,
            "apply_batch_duration",
            "Duration of apply-batch calls",
        );
        let sync_calls = context.counter("sync_calls", "Number of sync calls");
        let sync_duration = duration_histogram(&context, "sync_duration", "Duration of sync calls");
        let prune_calls = context.counter("prune_calls", "Number of prune calls");
        let prune_duration =
            duration_histogram(&context, "prune_duration", "Duration of prune calls");
        let clock = Arc::new(context);

        Self {
            clock,
            pruned_chunks,
            sync_boundary,
            apply_batch_calls,
            apply_batch_duration: Timed::new(apply_batch_duration),
            sync_calls,
            sync_duration: Timed::new(sync_duration),
            prune_calls,
            prune_duration: Timed::new(prune_duration),
        }
    }

    pub fn apply_batch_timer(&self) -> ScopedTimer<E> {
        self.apply_batch_duration.scoped(&self.clock)
    }

    pub fn sync_timer(&self) -> ScopedTimer<E> {
        self.sync_duration.scoped(&self.clock)
    }

    pub fn prune_timer(&self) -> ScopedTimer<E> {
        self.prune_duration.scoped(&self.clock)
    }

    /// Update Current-specific state gauges.
    pub fn update(&self, pruned_chunks: u64, sync_boundary: u64) {
        let _ = self.pruned_chunks.try_set(pruned_chunks);
        let _ = self.sync_boundary.try_set(sync_boundary);
    }
}

/// A Current QMDB implementation generic over ordered/unordered keys and variable/fixed values.
pub struct Db<
    F: merkle::Graftable,
    E: Context,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: Send + Sync,
    const N: usize,
    S: Strategy = Sequential,
> {
    /// An authenticated database that provides the ability to prove whether a key ever had a
    /// specific value. Owns the activity-status bitmap (`any.bitmap`) that this layer reads to
    /// install grafted-tree updates and serve proofs.
    pub(super) any: any::db::Db<F, E, C, I, H, U, N, S>,

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

    /// Strategy used to parallelize batch operations across the ops tree, the grafted tree,
    /// and grafted leaf computation.
    pub(super) strategy: S,

    /// The cached canonical root.
    /// See the [Root structure](super) section in the module documentation.
    pub(super) root: DigestOf<H>,

    /// Metrics for the Current layer.
    pub(super) metrics: Metrics<E>,
}

// Shared read-only functionality.
impl<F, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive.
    #[cfg(any(test, feature = "test-traits"))]
    pub(crate) const fn inactivity_floor_loc(&self) -> Location<F> {
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
        hasher: &StandardHasher<H>,
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
impl<F, E, U, C, I, H, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Returns a virtual [grafting::Storage] over the grafted tree and ops tree. For positions at
    /// or above the grafting height, returns the grafted node. For positions below the grafting
    /// height, the ops tree is used.
    fn grafted_storage(&self) -> impl MerkleStorage<F, Digest = H::Digest> + '_ {
        grafting::Storage::new(
            &self.grafted_tree,
            grafting::height::<N>(),
            &self.any.log.merkle,
            qmdb::hasher::<H>(),
        )
    }

    /// Returns the canonical root.
    /// See the [Root structure](super) section in the module documentation.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        &self.strategy
    }

    /// Returns the ops tree root.
    ///
    /// This is the root of the raw operations log, without the activity bitmap. It is used as the
    /// sync target because the sync engine verifies batches against the ops root, not the canonical
    /// root.
    ///
    /// External consumers that receive a trusted canonical `current` root should use
    /// [`Self::ops_root_witness`] to authenticate this ops root against it.
    ///
    /// See the [Root structure](super) section in the module documentation.
    pub const fn ops_root(&self) -> H::Digest {
        self.any.root()
    }

    /// Returns a witness that this database's canonical root commits to its ops root.
    ///
    /// This can be used to authenticate an ops root against a trusted canonical `current` root.
    pub async fn ops_root_witness(
        &self,
        hasher: &StandardHasher<H>,
    ) -> Result<OpsRootWitness<H::Digest>, Error<F>> {
        let storage = self.grafted_storage();
        // Snapshot ops_leaves once and thread it through both root computation and the
        // pending/partial chunk derivation so they observe the same `(ops, bitmap)` state.
        let ops_size = storage.size().await;
        let ops_leaves = Location::<F>::try_from(ops_size)?;
        let grafted_root = compute_grafted_root::<F, H, _, _, N>(
            hasher,
            self.any.bitmap.as_ref(),
            &storage,
            ops_leaves,
            self.any.inactivity_floor_loc,
        )
        .await?;
        let partial_chunk = partial_chunk::<_, N>(self.any.bitmap.as_ref())
            .map(|(chunk, next_bit)| (next_bit, hasher.digest(&chunk)));
        let pending_chunk_digest = pending_chunk::<F, _, N>(
            self.any.bitmap.as_ref(),
            ops_leaves,
            grafting::height::<N>(),
        )?
        .map(|chunk| hasher.digest(&chunk));
        Ok(OpsRootWitness {
            grafted_root,
            pending_chunk_digest,
            partial_chunk,
        })
    }

    /// Snapshot of the grafted tree for use in batch chains.
    pub(super) fn grafted_snapshot(&self) -> Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>> {
        merkle::batch::MerkleizedBatch::from_mem_with_strategy(
            &self.grafted_tree,
            self.strategy.clone(),
        )
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> super::batch::UnmerkleizedBatch<F, H, U, N, S> {
        super::batch::UnmerkleizedBatch::new(
            self.any.new_batch(),
            self.grafted_snapshot(),
            BitmapBatch::Base(Arc::clone(&self.any.bitmap)),
        )
    }

    /// Returns a proof for the operation at `loc`.
    pub(super) async fn operation_proof(
        &self,
        hasher: &StandardHasher<H>,
        loc: Location<F>,
    ) -> Result<OperationProof<F, H::Digest, N>, Error<F>> {
        let storage = self.grafted_storage();
        let ops_root = self.any.root();
        OperationProof::new(
            hasher,
            self.any.bitmap.as_ref(),
            &storage,
            self.any.inactivity_floor_loc,
            loc,
            ops_root,
        )
        .await
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
        hasher: &StandardHasher<H>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(RangeProof<F, H::Digest>, Vec<Operation<F, U>>, Vec<[u8; N]>), Error<F>> {
        let storage = self.grafted_storage();
        let ops_root = self.any.root();
        RangeProof::new_with_ops(
            hasher,
            self.any.bitmap.as_ref(),
            &storage,
            &self.any.log,
            RangeProofSpec {
                start_loc,
                max_ops,
                inactivity_floor: self.any.inactivity_floor_loc,
                ops_root,
            },
        )
        .await
    }
}

// Functionality requiring mutable journal.
impl<F, E, U, C, I, H, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Returns an ops-level historical proof for the specified range.
    ///
    /// Unlike [`range_proof`](Self::range_proof) which returns grafted proofs incorporating the
    /// activity bitmap, this returns ops-tree Merkle proofs suitable for state sync. Direct
    /// verifiers should use [`crate::qmdb::hasher`].
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

    /// Returns the most recent location from which this database can safely be synced, and the
    /// upper bound on [`Self::prune`]'s `prune_loc`.
    ///
    /// Callers constructing a sync [`Target`](crate::qmdb::sync::Target) may use this value, or
    /// any earlier retained location, as `range.start`. Values *above* this boundary are unsafe:
    /// the receiver's grafted-pin derivation requires absorption-settled state for every fully
    /// pruned chunk, which this value guarantees.
    ///
    /// # Computation
    ///
    /// Starts from the inactivity floor (the most chunks we could possibly prune) and walks
    /// backward until two conditions hold for the youngest chunk that would be pruned:
    ///
    /// 1. **Settled**: the chunk's ops subtree root at height `gh` has been born in the ops
    ///    tree (its `peak_birth_size <= ops_leaves`).
    ///
    /// 2. **Absorbed**: the chunk-pair parent at height `gh+1` has been born. This guarantees
    ///    that the ops tree has no individual height-`gh` peaks for pruned chunks, so
    ///    `compute_grafted_root` never queries a discarded grafted leaf.
    ///
    /// Because older chunk-pairs have strictly earlier birth times, checking only the youngest
    /// pair is sufficient: if the youngest pair's parent is born, all older pairs' parents are
    /// too. In the worst case the loop decrements twice (once past the unsettled chunk, once
    /// to land on the older pair boundary).
    ///
    /// For families without delayed merges (e.g. MMR), `peak_birth_size` at height `gh` equals
    /// the chunk's last leaf, so condition (1) always holds and the function returns the
    /// inactivity floor rounded down to the nearest chunk boundary.
    pub fn sync_boundary(&self) -> Location<F> {
        let chunk_bits = bitmap::Prunable::<N>::CHUNK_SIZE_BITS;
        let mut pruned_chunks = *self.any.inactivity_floor_loc / chunk_bits;

        let ops_leaves = *self.any.last_commit_loc + 1;
        let grafting_height = grafting::height::<N>();

        while pruned_chunks > 0 {
            let required_ops =
                Self::pair_absorption_threshold(pruned_chunks).unwrap_or_else(|| {
                    let youngest_start = (pruned_chunks - 1) * chunk_bits;
                    let pos = F::subtree_root_position(
                        Location::<F>::new(youngest_start),
                        grafting_height,
                    );
                    F::peak_birth_size(pos, grafting_height)
                });

            if ops_leaves >= required_ops {
                break;
            }
            pruned_chunks -= 1;
        }

        Location::new(pruned_chunks * chunk_bits)
    }

    /// Update Current-specific state gauges.
    pub(super) fn update_metrics(&self) {
        self.metrics.update(
            self.any.bitmap.pruned_chunks() as u64,
            *self.sync_boundary(),
        );
    }

    /// For the youngest of `pruned_chunks` chunks, return the `peak_birth_size` of its
    /// chunk-pair parent at height `gh+1`. Returns `None` for families without delayed merges
    /// (where `peak_birth_size` at height `gh` equals the chunk boundary).
    fn pair_absorption_threshold(pruned_chunks: u64) -> Option<u64> {
        if pruned_chunks == 0 {
            return None;
        }

        let grafting_height = grafting::height::<N>();
        let youngest = pruned_chunks - 1;
        let youngest_start = youngest << grafting_height;
        let youngest_end = (youngest + 1) << grafting_height;
        let youngest_pos =
            F::subtree_root_position(Location::<F>::new(youngest_start), grafting_height);

        // Families without delayed merges: birth_size == chunk_end.
        if F::peak_birth_size(youngest_pos, grafting_height) <= youngest_end {
            return None;
        }

        let pair_chunk = youngest & !1;
        let pair_start = pair_chunk << grafting_height;
        let pair_pos =
            F::subtree_root_position(Location::<F>::new(pair_start), grafting_height + 1);
        Some(F::peak_birth_size(pair_pos, grafting_height + 1))
    }

    /// Returns the minimum rewind target that keeps delayed-merge grafting queries valid
    /// for the current bitmap pruning boundary.
    ///
    /// This is the same absorption threshold used by [`Self::sync_boundary`]: the
    /// `peak_birth_size` of the youngest pruned chunk-pair's height-(gh+1) parent.
    /// Rewinding below this size would put the ops tree in a state where the parent has not
    /// been born, re-exposing individual height-`gh` ops peaks for pruned chunks whose
    /// grafted leaves are no longer available.
    ///
    /// Returns `None` for families without delayed merges.
    fn delayed_merge_rewind_floor(&self) -> Option<u64> {
        Self::pair_absorption_threshold(self.any.bitmap.pruned_chunks() as u64)
    }

    /// Prune the grafted tree to match the committed bitmap's pruned chunks.
    fn prune_grafted_tree_to_bitmap(&mut self) -> Result<(), Error<F>> {
        let pruned_chunks = self.any.bitmap.pruned_chunks() as u64;
        if pruned_chunks == 0 {
            return Ok(());
        }

        let prune_loc = Location::<F>::new(pruned_chunks);
        if prune_loc <= self.grafted_tree.bounds().start {
            return Ok(());
        }

        let prune_pos = Position::try_from(prune_loc)
            .map_err(|_| Error::<F>::DataCorrupted("prune location overflow"))?;
        let size = self.grafted_tree.size();

        let mut pinned = BTreeMap::new();
        for pos in F::nodes_to_pin(prune_loc) {
            let digest = self
                .grafted_tree
                .get_node(pos)
                .ok_or(Error::<F>::DataCorrupted("missing grafted pinned node"))?;
            pinned.insert(pos, digest);
        }

        let mut retained = Vec::with_capacity((*size - *prune_pos) as usize);
        for p in *prune_pos..*size {
            let digest = self
                .grafted_tree
                .get_node(Position::new(p))
                .ok_or(Error::<F>::DataCorrupted("missing retained grafted node"))?;
            retained.push(digest);
        }

        self.grafted_tree = Mem::from_pruned_with_retained(prune_pos, pinned, retained);
        Ok(())
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// `prune_loc` must be at most [`Self::sync_boundary`]: the ops log's lower bound must not
    /// advance past the point where the grafting overlay has been pruned. The bitmap and grafted
    /// tree advance to the sync boundary regardless of `prune_loc`.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > [`Self::sync_boundary`].
    /// - Returns [`crate::merkle::Error::LocationOverflow`] if `prune_loc` >
    ///   [crate::merkle::Family::MAX_LEAVES].
    /// - Returns [Error::DataCorrupted] if internal grafted-tree state is inconsistent (a pinned
    ///   or retained node is missing, or the prune location overflows a [Position]).
    pub async fn prune(&mut self, prune_loc: Location<F>) -> Result<(), Error<F>> {
        let _timer = self.metrics.prune_timer();
        self.metrics.prune_calls.inc();
        let sync_boundary = self.sync_boundary();
        if prune_loc > sync_boundary {
            return Err(Error::PruneBeyondMinRequired(prune_loc, sync_boundary));
        }

        // Prune the bitmap to the sync boundary (most aggressive safe location).
        self.any.prune_bitmap(sync_boundary);
        self.prune_grafted_tree_to_bitmap()?;

        // Persist grafted tree pruning state before pruning the ops log. If the subsequent
        // `any.prune_log` fails, the metadata is ahead of the log, which is safe: on recovery,
        // `build_grafted_tree` will recompute from the (un-pruned) log and the metadata
        // simply records peaks that haven't been pruned yet. The reverse order would be unsafe:
        // a pruned log with stale metadata would lose peak digests permanently.
        self.sync_metadata().await?;

        self.any.prune_log(prune_loc).await?;
        self.any.update_metrics().await;
        self.update_metrics();
        Ok(())
    }

    /// Rewind the database to `size` operations, where `size` is the location of the next append.
    ///
    /// This rewinds the underlying Any database and rebuilds the Current overlay state (bitmap,
    /// grafted tree, and canonical root) for the rewound size.
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
    pub async fn rewind(&mut self, size: Location<F>) -> Result<(), Error<F>> {
        let rewind_size = *size;
        let current_size = *self.any.last_commit_loc + 1;
        // No-op short-circuit. Avoids the post-rewind grafted-tree rebuild and the validation
        // and journal-read overhead below. Validation runs after this on the non-no-op path.
        if rewind_size == current_size {
            return Ok(());
        }
        // Reject zero / out-of-range up front: lines below compute `rewind_size - 1`, which
        // underflows when `rewind_size == 0`. `any::Db::rewind` would catch these, but it isn't
        // called until after those subtractions.
        if rewind_size == 0 || rewind_size > current_size {
            return Err(Error::Journal(JournalError::InvalidRewind(rewind_size)));
        }

        let pruned_chunks = self.any.bitmap.pruned_chunks();
        let pruned_bits = (pruned_chunks as u64)
            .checked_mul(bitmap::Prunable::<N>::CHUNK_SIZE_BITS)
            .ok_or_else(|| Error::DataCorrupted("pruned ops leaves overflow"))?;
        if rewind_size < pruned_bits {
            return Err(Error::Journal(JournalError::ItemPruned(rewind_size - 1)));
        }
        if let Some(rewind_floor) = self.delayed_merge_rewind_floor() {
            if rewind_size < rewind_floor {
                return Err(Error::Journal(JournalError::ItemPruned(rewind_size - 1)));
            }
        }

        // Ensure the target commit's logical range is fully representable with the current
        // bitmap pruning boundary. Even if the ops log still retains older entries, rewinding
        // to a commit with floor below `pruned_bits` would require bitmap chunks we've already
        // discarded.
        {
            let reader = self.any.log.reader().await;
            let rewind_last_loc = Location::<F>::new(rewind_size - 1);
            let rewind_last_op = reader.read(*rewind_last_loc).await?;
            let Some(rewind_floor) = rewind_last_op.has_floor() else {
                return Err(Error::<F>::UnexpectedData(rewind_last_loc));
            };
            if *rewind_floor < pruned_bits {
                return Err(Error::<F>::Journal(JournalError::ItemPruned(*rewind_floor)));
            }
        }

        // Extract pinned nodes for the existing pruning boundary from the in-memory grafted tree.
        let pinned_nodes = if pruned_chunks > 0 {
            let grafted_leaves = Location::<F>::new(pruned_chunks as u64);
            let mut pinned_nodes = Vec::new();
            for pos in F::nodes_to_pin(grafted_leaves) {
                let digest = self
                    .grafted_tree
                    .get_node(pos)
                    .ok_or(Error::<F>::DataCorrupted("missing grafted pinned node"))?;
                pinned_nodes.push(digest);
            }
            pinned_nodes
        } else {
            Vec::new()
        };

        // `any.rewind` rewinds the log and patches the shared bitmap (truncate + restore graftable
        // bits + set the rewound tail's CommitFloor). Live pre-rewind batches must be dropped by
        // the caller; reads through them now return inconsistent data.
        self.any.rewind(size).await?;

        let hasher = qmdb::hasher::<H>();
        let ops_size = self.any.log.merkle.size();
        let ops_leaves = Location::<F>::try_from(ops_size)?;
        let grafted_tree = build_grafted_tree::<F, H, S, N>(
            &hasher,
            self.any.bitmap.as_ref(),
            &pinned_nodes,
            &self.any.log.merkle,
            ops_leaves,
            &self.strategy,
        )
        .await?;
        let storage = grafting::Storage::new(
            &grafted_tree,
            grafting::height::<N>(),
            &self.any.log.merkle,
            hasher.clone(),
        );
        let partial_chunk = partial_chunk(self.any.bitmap.as_ref());
        let ops_root = self.any.root();
        let root = compute_db_root(
            &hasher,
            self.any.bitmap.as_ref(),
            &storage,
            ops_leaves,
            partial_chunk,
            self.any.inactivity_floor_loc,
            &ops_root,
        )
        .await?;

        self.grafted_tree = grafted_tree;
        self.root = root;
        self.update_metrics();

        Ok(())
    }

    /// Sync the metadata to disk.
    pub(crate) async fn sync_metadata(&self) -> Result<(), Error<F>> {
        let mut metadata = self.metadata.lock().await;
        metadata.clear();

        // Snapshot the pruning boundary under the read lock; the guard drops before any await.
        let pruned_chunks_u64 = self.any.bitmap.pruned_chunks() as u64;

        // Write the number of pruned chunks.
        let key = U64::new(PRUNED_CHUNKS_PREFIX, 0);
        metadata.put(key, pruned_chunks_u64.to_be_bytes().to_vec());

        // Write the pinned nodes of the grafted tree.
        let pruned_chunks = Location::<F>::new(pruned_chunks_u64);
        for (i, grafted_pos) in F::nodes_to_pin(pruned_chunks).enumerate() {
            let digest = self
                .grafted_tree
                .get_node(grafted_pos)
                .ok_or(Error::<F>::DataCorrupted("missing grafted pinned node"))?;
            let key = U64::new(NODE_PREFIX, i as u64);
            metadata.put(key, digest.to_vec());
        }

        metadata.sync().await?;

        Ok(())
    }
}

// Functionality requiring mutable + persistable journal.
impl<F, E, U, C, I, H, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Durably commit the journal state published by prior [`Db::apply_batch`]
    /// calls.
    pub async fn commit(&self) -> Result<(), Error<F>> {
        self.any.commit().await
    }

    /// Sync all database state to disk.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        self.any.sync().await?;

        // Write the bitmap pruning boundary to disk so that next startup doesn't have to
        // re-Merkleize the inactive portion up to the inactivity floor.
        self.sync_metadata().await?;
        self.update_metrics();
        Ok(())
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.metadata.into_inner().destroy().await?;
        self.any.destroy().await
    }
}

impl<F, E, U, C, I, H, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: merkle::Graftable,
    E: Context,
    U: Update + 'static,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
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
        batch: Arc<super::batch::MerkleizedBatch<F, H::Digest, U, N, S>>,
    ) -> Result<Range<Location<F>>, Error<F>> {
        let _timer = self.metrics.apply_batch_timer();
        self.metrics.apply_batch_calls.inc();
        let range = self.any.apply_batch(Arc::clone(&batch.inner)).await?;
        self.grafted_tree.apply_batch(&batch.grafted)?;
        self.root = batch.canonical_root;
        self.update_metrics();
        Ok(range)
    }
}

impl<F, E, U, C, I, H, const N: usize, S> Persistable for Db<F, E, C, I, H, U, N, S>
where
    F: merkle::Graftable,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
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
pub(super) fn partial_chunk<B: bitmap::Readable<N>, const N: usize>(
    bitmap: &B,
) -> Option<([u8; N], u64)> {
    let (last_chunk, next_bit) = bitmap.last_chunk();
    if next_bit == bitmap::Prunable::<N>::CHUNK_SIZE_BITS {
        None
    } else {
        Some((last_chunk, next_bit))
    }
}

/// Return complete and graftable chunk counts, enforcing the pending and pruning invariants.
///
/// Returns [`Error::DataCorrupted`] if `bitmap` and `ops_leaves` imply more than one
/// pending chunk, or if pruning has advanced past the graftable chunk boundary.
fn graftable_chunk_window<F: merkle::Graftable, B: bitmap::Readable<N>, const N: usize>(
    bitmap: &B,
    ops_leaves: Location<F>,
    grafting_height: u32,
) -> Result<(u64, u64), Error<F>> {
    let complete = bitmap.complete_chunks() as u64;
    let graftable = grafting::graftable_chunks::<F>(*ops_leaves, grafting_height).min(complete);
    let pending = complete - graftable;
    if pending > 1 {
        return Err(Error::DataCorrupted("multiple pending bitmap chunks"));
    }

    let pruned = bitmap.pruned_chunks() as u64;
    if pruned > graftable {
        return Err(Error::DataCorrupted(
            "pruned chunks exceed graftable chunks",
        ));
    }

    Ok((complete, graftable))
}

/// Returns the bytes of the "pending" chunk if the bitmap currently has one, else `None`.
///
/// A chunk is pending when its bits are fully written to the bitmap but its h=G ancestor
/// has not yet been born in the ops tree. At most one chunk is ever in this state (the most
/// recently completed one); see [`super::grafting::graftable_chunks`] for the structural
/// argument.
///
/// The caller must pass a consistent snapshot of `ops_leaves` (the ops tree's leaf count)
/// and the bitmap state. Both inputs are used to derive `graftable_chunks`; deriving them from
/// independent snapshots can violate the pending-window or pruning invariants.
///
/// Returns [`Error::DataCorrupted`] when those invariants are violated.
pub(super) fn pending_chunk<F: merkle::Graftable, B: bitmap::Readable<N>, const N: usize>(
    bitmap: &B,
    ops_leaves: Location<F>,
    grafting_height: u32,
) -> Result<Option<[u8; N]>, Error<F>> {
    let (complete, graftable) =
        graftable_chunk_window::<F, B, N>(bitmap, ops_leaves, grafting_height)?;
    if complete - graftable != 1 {
        return Ok(None);
    }
    Ok(Some(bitmap.get_chunk(graftable as usize)))
}

/// Compute the canonical root from the ops root, grafted tree root, and optional pending /
/// partial chunk digests.
///
/// See [Canonical root structure](super::proof#canonical-root-structure) for the full layout.
/// The pending and partial inputs are independent: either, both, or neither may be set, and
/// pending precedes partial in hash order when both are present.
///
/// # Collision resistance
///
/// `pending` contributes `D` bytes when present; `partial` contributes `D + 8` bytes (`D` =
/// digest size). Different fixed lengths, so the two cannot produce the same input bytes —
/// even when their digests are identical. Collisions reduce to H.
pub(super) fn combine_roots<H: Hasher>(
    hasher: &StandardHasher<H>,
    ops_root: &H::Digest,
    grafted_root: &H::Digest,
    pending: Option<&H::Digest>,
    partial: Option<(u64, &H::Digest)>,
) -> H::Digest {
    match (pending, partial) {
        (None, None) => hasher.hash([ops_root.as_ref(), grafted_root.as_ref()]),
        (Some(pe), None) => hasher.hash([ops_root.as_ref(), grafted_root.as_ref(), pe.as_ref()]),
        (None, Some((nb, p))) => {
            let nb_bytes = nb.to_be_bytes();
            hasher.hash([
                ops_root.as_ref(),
                grafted_root.as_ref(),
                nb_bytes.as_slice(),
                p.as_ref(),
            ])
        }
        (Some(pe), Some((nb, p))) => {
            let nb_bytes = nb.to_be_bytes();
            hasher.hash([
                ops_root.as_ref(),
                grafted_root.as_ref(),
                pe.as_ref(),
                nb_bytes.as_slice(),
                p.as_ref(),
            ])
        }
    }
}

/// Compute the canonical root digest of a [Db].
///
/// See the [Root structure](super) section in the module documentation.
///
/// `ops_leaves` must be a single consistent snapshot of the ops tree's leaf count, taken
/// in the same logical instant as the bitmap state passed via `status`. Both the pending
/// chunk derivation and `compute_grafted_root` use this value to compute `graftable_chunks`;
/// deriving them from independent snapshots risks the inconsistent state where a chunk is
/// counted in one path but not the other.
#[allow(clippy::too_many_arguments)]
pub(super) async fn compute_db_root<
    F: merkle::Graftable,
    H: Hasher,
    B: bitmap::Readable<N>,
    S: MerkleStorage<F, Digest = H::Digest>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    status: &B,
    storage: &S,
    ops_leaves: Location<F>,
    partial_chunk: Option<([u8; N], u64)>,
    inactivity_floor: Location<F>,
    ops_root: &H::Digest,
) -> Result<H::Digest, Error<F>> {
    let grafted_root =
        compute_grafted_root(hasher, status, storage, ops_leaves, inactivity_floor).await?;
    let pending = pending_chunk::<F, B, N>(status, ops_leaves, grafting::height::<N>())?
        .map(|chunk| hasher.digest(&chunk));
    let partial = partial_chunk.map(|(chunk, next_bit)| {
        let digest = hasher.digest(&chunk);
        (next_bit, digest)
    });
    Ok(combine_roots(
        hasher,
        ops_root,
        &grafted_root,
        pending.as_ref(),
        partial.as_ref().map(|(nb, d)| (*nb, d)),
    ))
}

/// Compute the root of the grafted structure represented by `storage`.
///
/// Only **graftable** chunks (those whose h=G ancestor has been born in the ops tree) are
/// committed by the grafted tree. The most recently completed but ungraftable chunk, if
/// any, is hashed into the canonical root directly by [`combine_roots`] as the pending
/// chunk, not by this function.
///
/// `ops_leaves` must come from the same single snapshot as `status` to preserve the
/// `pruned_chunks <= graftable_chunks <= complete_chunks` invariant.
pub(super) async fn compute_grafted_root<
    F: merkle::Graftable,
    H: Hasher,
    B: bitmap::Readable<N>,
    S: MerkleStorage<F, Digest = H::Digest>,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    status: &B,
    storage: &S,
    ops_leaves: Location<F>,
    inactivity_floor: Location<F>,
) -> Result<H::Digest, Error<F>> {
    let size = storage.size().await;
    let leaves = Location::try_from(size)?;

    // Collect peak digests of the grafted structure.
    let mut peaks: Vec<H::Digest> = Vec::new();
    for (peak_pos, _) in F::peaks(size) {
        let digest = storage
            .get_node(peak_pos)
            .await?
            .ok_or_else(|| merkle::Error::<F>::MissingNode(peak_pos))?;
        peaks.push(digest);
    }

    let grafting_height = grafting::height::<N>();
    let (_complete_chunks, _graftable_chunks) =
        graftable_chunk_window::<F, B, N>(status, ops_leaves, grafting_height)?;

    let inactive_peaks =
        grafting::chunk_aligned_inactive_peaks::<F>(leaves, inactivity_floor, grafting_height)?;

    // Every peak the storage layer surfaces is either a grafted-tree node (graftable chunks
    // already incorporate `hash(chunk || h_G_node)`), an ops node above G (hashed
    // normally), or an ops node below G (raw, because its chunk is pending and its digest
    // is hashed directly into the canonical root rather than through the tree). Bagging is
    // a straight fold; no per-chunk transformation is needed.
    Ok(hasher.root(leaves, inactive_peaks, peaks.iter())?)
}

/// Compute grafted leaf digests for the given bitmap chunks as `(chunk_idx, digest)` pairs.
///
/// Callers must pass only **graftable** chunks (those whose h=G ancestor has already been born
/// in the ops tree). Each graftable chunk has exactly one covering ops node at height G,
/// looked up via [`merkle::Graftable::subtree_root_position`]. The grafted leaf digest is
/// `hash(chunk || ops_h_G_node)`; for all-zero chunks the grafted leaf equals the ops digest
/// directly (zero-chunk identity).
///
/// The provided strategy determines if or how to parallelize merkleization.
pub(super) async fn compute_grafted_leaves<
    F: merkle::Graftable,
    H: Hasher,
    S: Strategy,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    ops_tree: &impl MerkleStorage<F, Digest = H::Digest>,
    chunks: impl IntoIterator<Item = (usize, [u8; N])>,
    strategy: &S,
) -> Result<Vec<(usize, H::Digest)>, Error<F>> {
    let grafting_height = grafting::height::<N>();

    // Each graftable chunk has a single h=G ancestor at the deterministic
    // `subtree_root_position(chunk_idx << G, G)`. Look it up directly.
    let inputs = try_join_all(chunks.into_iter().map(|(chunk_idx, chunk)| async move {
        let leaf_start = Location::<F>::new((chunk_idx as u64) << grafting_height);
        let pos = F::subtree_root_position(leaf_start, grafting_height);
        let chunk_ops_digest = ops_tree
            .get_node(pos)
            .await?
            .ok_or(merkle::Error::<F>::MissingGraftedLeaf(pos))?;
        Ok::<_, Error<F>>((chunk_idx, chunk_ops_digest, chunk))
    }))
    .await?;

    // Compute the grafted leaf digest for each chunk. For all-zero chunks, the
    // grafted leaf equals the chunk_ops_digest directly (zero-chunk identity).
    let zero_chunk = [0u8; N];
    Ok(strategy.map_init_collect_vec(
        inputs,
        || hasher.clone(),
        |h, (chunk_idx, chunk_ops_digest, chunk)| {
            if chunk == zero_chunk {
                (chunk_idx, chunk_ops_digest)
            } else {
                (
                    chunk_idx,
                    h.hash([chunk.as_slice(), chunk_ops_digest.as_ref()]),
                )
            }
        },
    ))
}

/// Build a grafted [Mem] from scratch using bitmap chunks and the ops tree.
///
/// For each non-pruned **graftable** chunk (index in `pruned_chunks..graftable_chunks`), reads the
/// ops tree node at the grafting height to compute the grafted leaf (see the
/// [grafted leaf formula](super) in the module documentation).
///
/// The most recently completed chunk may not yet be graftable (its h=G ancestor not yet born);
/// that chunk is **excluded** from the grafted tree and its digest is hashed directly into
/// the canonical root as the pending chunk. The caller must ensure that all ops tree nodes
/// for chunks `>= pruned_chunks` are still accessible in the ops tree (i.e., not pruned from
/// the journal).
///
/// `ops_leaves` must be a single consistent snapshot of `ops_tree.size()` taken in the same
/// instant as the bitmap state.
pub(super) async fn build_grafted_tree<
    F: merkle::Graftable,
    H: Hasher,
    S: Strategy,
    const N: usize,
>(
    hasher: &StandardHasher<H>,
    bitmap: &impl bitmap::Readable<N>,
    pinned_nodes: &[H::Digest],
    ops_tree: &impl MerkleStorage<F, Digest = H::Digest>,
    ops_leaves: Location<F>,
    strategy: &S,
) -> Result<Mem<F, H::Digest>, Error<F>> {
    let grafting_height = grafting::height::<N>();
    let pruned_chunks = bitmap.pruned_chunks();
    let complete_chunks = bitmap.complete_chunks();
    let graftable_chunks = grafting::graftable_chunks::<F>(*ops_leaves, grafting_height)
        .min(complete_chunks as u64) as usize;
    debug_assert!(
        pruned_chunks <= graftable_chunks && graftable_chunks <= complete_chunks,
        "invariant violated: pruned={pruned_chunks} graftable={graftable_chunks} complete={complete_chunks}"
    );

    // Compute grafted leaves for each unpruned graftable chunk. The pending chunk (if any)
    // sits at index `graftable_chunks` and is excluded; its digest is hashed directly into
    // the canonical root.
    let leaves = compute_grafted_leaves::<F, H, S, N>(
        hasher,
        ops_tree,
        (pruned_chunks..graftable_chunks).map(|chunk_idx| (chunk_idx, bitmap.get_chunk(chunk_idx))),
        strategy,
    )
    .await?;

    // Build the base grafted tree: either from pruned components or empty.
    let grafted_hasher = grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
    let mut grafted_tree = if pruned_chunks > 0 {
        let grafted_pruning_boundary = Location::<F>::new(pruned_chunks as u64);
        Mem::from_components(Vec::new(), grafted_pruning_boundary, pinned_nodes.to_vec())
            .map_err(|_| Error::<F>::DataCorrupted("grafted tree rebuild failed"))?
    } else {
        Mem::new()
    };

    // Add each grafted leaf digest.
    if !leaves.is_empty() {
        let batch = {
            let mut batch = grafted_tree.new_batch_with_strategy(strategy.clone());
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
/// The metadata store holds two kinds of entries (keyed by prefix):
/// - **Pruned chunks count** ([PRUNED_CHUNKS_PREFIX]): the number of bitmap chunks that have been
///   pruned. This tells us where the graftable portion of the bitmap begins.
/// - **Pinned node digests** ([NODE_PREFIX]): grafted tree digests at peak positions whose
///   underlying data has been pruned. These are needed to recompute the grafted tree root without
///   the pruned chunks.
///
/// Returns `(metadata_handle, pruned_chunks, pinned_node_digests)`.
pub(super) async fn init_metadata<F: merkle::Graftable, E: Context, D: Digest>(
    context: E,
    partition: &str,
) -> Result<(Metadata<E, U64, Vec<u8>>, usize, Vec<D>), Error<F>> {
    let metadata_cfg = MConfig {
        partition: partition.into(),
        codec_config: ((0..).into(), ()),
    };
    let metadata =
        Metadata::<_, U64, Vec<u8>>::init(context.child("metadata"), metadata_cfg).await?;

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

    Ok((metadata, pruned_chunks, pinned_nodes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{mmb, mmr, Bagging::ForwardFold},
        qmdb::{
            any::traits::{DbAny, UnmerkleizedBatch as _},
            current::{tests::fixed_config, unordered::fixed},
        },
        translator::OneCap,
    };
    use commonware_codec::FixedSize;
    use commonware_cryptography::{sha256, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
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
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let r1 = combine_roots(&hasher, &ops, &grafted, None, None);
        let r2 = combine_roots(&hasher, &ops, &grafted, None, None);
        assert_eq!(r1, r2);
    }

    #[test]
    fn combine_roots_with_partial_differs() {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let partial_digest = Sha256::hash(b"partial");

        let without = combine_roots(&hasher, &ops, &grafted, None, None);
        let with = combine_roots(&hasher, &ops, &grafted, None, Some((5, &partial_digest)));
        assert_ne!(without, with);
    }

    #[test]
    fn combine_roots_with_pending_differs() {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let pending_digest = Sha256::hash(b"pending");

        let without = combine_roots(&hasher, &ops, &grafted, None, None);
        let with = combine_roots(&hasher, &ops, &grafted, Some(&pending_digest), None);
        assert_ne!(without, with);
    }

    #[test]
    fn combine_roots_pending_and_partial_independent() {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let pending_digest = Sha256::hash(b"pending");
        let partial_digest = Sha256::hash(b"partial");

        let only_pending = combine_roots(&hasher, &ops, &grafted, Some(&pending_digest), None);
        let only_partial = combine_roots(&hasher, &ops, &grafted, None, Some((5, &partial_digest)));
        let both = combine_roots(
            &hasher,
            &ops,
            &grafted,
            Some(&pending_digest),
            Some((5, &partial_digest)),
        );
        assert_ne!(only_pending, only_partial);
        assert_ne!(only_pending, both);
        assert_ne!(only_partial, both);
    }

    #[test]
    fn combine_roots_different_ops_root() {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let ops_a = Sha256::hash(b"ops_a");
        let ops_b = Sha256::hash(b"ops_b");
        let grafted = Sha256::hash(b"grafted");

        let r1 = combine_roots(&hasher, &ops_a, &grafted, None, None);
        let r2 = combine_roots(&hasher, &ops_b, &grafted, None, None);
        assert_ne!(r1, r2);
    }

    /// Pin the canonical-root format down to the byte. A change to `combine_roots`'s hash
    /// pre-image (e.g., reordering, dropping a length tag, swapping pending/partial order)
    /// would silently break wire compatibility; this test catches that.
    #[test]
    fn combine_roots_format_golden() {
        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let ops = Sha256::hash(b"ops");
        let grafted = Sha256::hash(b"grafted");
        let pending = Sha256::hash(b"pending");
        let partial = Sha256::hash(b"partial");
        let next_bit: u64 = 0x1122_3344_5566_7788;

        // Neither pending nor partial.
        assert_eq!(
            combine_roots(&hasher, &ops, &grafted, None, None),
            hasher.hash([ops.as_ref(), grafted.as_ref()])
        );

        // Pending only.
        assert_eq!(
            combine_roots(&hasher, &ops, &grafted, Some(&pending), None),
            hasher.hash([ops.as_ref(), grafted.as_ref(), pending.as_ref()])
        );

        // Partial only.
        assert_eq!(
            combine_roots(&hasher, &ops, &grafted, None, Some((next_bit, &partial))),
            hasher.hash([
                ops.as_ref(),
                grafted.as_ref(),
                next_bit.to_be_bytes().as_slice(),
                partial.as_ref(),
            ])
        );

        // Both: pending precedes partial.
        assert_eq!(
            combine_roots(
                &hasher,
                &ops,
                &grafted,
                Some(&pending),
                Some((next_bit, &partial))
            ),
            hasher.hash([
                ops.as_ref(),
                grafted.as_ref(),
                pending.as_ref(),
                next_bit.to_be_bytes().as_slice(),
                partial.as_ref(),
            ])
        );
    }

    type MmrDb = fixed::Db<
        mmr::Family,
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        OneCap,
        32,
    >;
    type MmbDb = fixed::Db<
        mmb::Family,
        deterministic::Context,
        sha256::Digest,
        sha256::Digest,
        Sha256,
        OneCap,
        32,
    >;

    async fn populate_fixed_db<F, DB>(db: &mut DB, start: u64, count: u64)
    where
        F: merkle::Graftable,
        DB: DbAny<F, Key = sha256::Digest, Value = sha256::Digest>,
    {
        let mut batch = db.new_batch();
        for idx in start..start + count {
            let key = Sha256::hash(&idx.to_be_bytes());
            let value = Sha256::hash(&(idx + count).to_be_bytes());
            batch = batch.write(key, Some(value));
        }
        let merkleized = batch.merkleize(db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
    }

    #[test_traced]
    fn test_ops_root_witness_verifies_without_partial_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let mut db = MmrDb::init(
                ctx.child("storage"),
                fixed_config::<OneCap>("ops-root-witness-full", &ctx),
            )
            .await
            .unwrap();
            let mut next_idx = 0;
            populate_fixed_db::<mmr::Family, _>(&mut db, next_idx, 256).await;
            next_idx += 256;
            while partial_chunk::<_, 32>(db.any.bitmap.as_ref()).is_some() {
                populate_fixed_db::<mmr::Family, _>(&mut db, next_idx, 1).await;
                next_idx += 1;
            }

            let hasher = qmdb::hasher::<Sha256>();
            let witness = db.ops_root_witness(&hasher).await.unwrap();
            let ops_root = db.ops_root();
            let canonical_root = db.root();

            assert!(witness.partial_chunk.is_none());
            assert!(witness.verify(&hasher, &ops_root, &canonical_root));

            let wrong_ops_root = Sha256::hash(b"wrong ops root");
            assert!(!witness.verify(&hasher, &wrong_ops_root, &canonical_root));

            let wrong_canonical_root = Sha256::hash(b"wrong canonical root");
            assert!(!witness.verify(&hasher, &ops_root, &wrong_canonical_root));

            let mut tampered = witness;
            tampered.grafted_root = Sha256::hash(b"wrong grafted root");
            assert!(!tampered.verify(&hasher, &ops_root, &canonical_root));
        });
    }

    #[test_traced]
    fn test_ops_root_witness_verifies_with_partial_chunk() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let mut db = MmbDb::init(
                ctx.child("storage"),
                fixed_config::<OneCap>("ops-root-witness-partial", &ctx),
            )
            .await
            .unwrap();
            populate_fixed_db::<mmb::Family, _>(&mut db, 0, 260).await;

            let hasher = qmdb::hasher::<Sha256>();
            let witness = db.ops_root_witness(&hasher).await.unwrap();
            let ops_root = db.ops_root();
            let canonical_root = db.root();

            assert!(witness.partial_chunk.is_some());
            assert!(witness.verify(&hasher, &ops_root, &canonical_root));

            let wrong_ops_root = Sha256::hash(b"wrong ops root");
            assert!(!witness.verify(&hasher, &wrong_ops_root, &canonical_root));

            let wrong_canonical_root = Sha256::hash(b"wrong canonical root");
            assert!(!witness.verify(&hasher, &ops_root, &wrong_canonical_root));

            let mut tampered = witness.clone();
            tampered.grafted_root = Sha256::hash(b"wrong grafted root");
            assert!(!tampered.verify(&hasher, &ops_root, &canonical_root));

            let mut tampered = witness.clone();
            tampered.partial_chunk.as_mut().unwrap().0 += 1;
            assert!(!tampered.verify(&hasher, &ops_root, &canonical_root));

            let mut tampered = witness;
            tampered.partial_chunk.as_mut().unwrap().1 = Sha256::hash(b"wrong partial chunk");
            assert!(!tampered.verify(&hasher, &ops_root, &canonical_root));
        });
    }

    #[test_traced]
    fn test_ops_root_witness_verifies_with_pruned_db() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let mut db = MmrDb::init(
                ctx.child("storage"),
                fixed_config::<OneCap>("ops-root-witness-pruned", &ctx),
            )
            .await
            .unwrap();

            // Churn the same keys repeatedly to drive the inactivity floor past chunk boundaries.
            for _ in 0..5 {
                populate_fixed_db::<mmr::Family, _>(&mut db, 0, 512).await;
            }
            db.prune(db.sync_boundary()).await.unwrap();
            assert!(
                db.any.bitmap.pruned_chunks() > 0,
                "test requires at least one pruned chunk to exercise the zero-chunk path"
            );

            let hasher = qmdb::hasher::<Sha256>();
            let witness = db.ops_root_witness(&hasher).await.unwrap();
            let ops_root = db.ops_root();
            let canonical_root = db.root();

            assert!(witness.verify(&hasher, &ops_root, &canonical_root));

            let wrong_canonical_root = Sha256::hash(b"wrong canonical root");
            assert!(!witness.verify(&hasher, &ops_root, &wrong_canonical_root));

            let mut tampered = witness;
            tampered.grafted_root = Sha256::hash(b"wrong grafted root");
            assert!(!tampered.verify(&hasher, &ops_root, &canonical_root));
        });
    }

    #[test_traced]
    fn test_ops_root_witness_verifies_on_fresh_db() {
        let executor = deterministic::Runner::default();
        executor.start(|ctx| async move {
            let db = MmrDb::init(
                ctx.child("storage"),
                fixed_config::<OneCap>("ops-root-witness-fresh", &ctx),
            )
            .await
            .unwrap();

            let hasher = qmdb::hasher::<Sha256>();
            let witness = db.ops_root_witness(&hasher).await.unwrap();
            let ops_root = db.ops_root();
            let canonical_root = db.root();

            assert!(witness.verify(&hasher, &ops_root, &canonical_root));
        });
    }
}
