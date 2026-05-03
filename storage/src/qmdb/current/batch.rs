//! Batch mutation API for Current QMDBs.
//!
//! Wraps the [`any::batch`] API.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    merkle::{
        self, hasher::Standard as StandardHasher, storage::Storage as MerkleStorage, Graftable,
        Location, Position, Readable,
    },
    qmdb::{
        any::{
            self,
            batch::{lookup_sorted, DiffEntry},
            operation::{update, Operation},
            ValueEncoding,
        },
        bitmap::Shared,
        current::{
            db::{compute_db_root, compute_grafted_leaves},
            grafting,
        },
        operation::Key,
        Error,
    },
    Context,
};
use ahash::AHasher;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::bitmap::{self, Readable as _};
use std::{
    collections::{BTreeSet, HashMap},
    hash::BuildHasherDefault,
    sync::Arc,
};

/// Speculative chunk-level bitmap overlay.
///
/// Instead of tracking individual pushed bits and cleared locations, maintains materialized chunk
/// bytes for every chunk that differs from the parent bitmap. This directly produces the chunk data
/// needed for grafted MMR leaf computation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChunkOverlay<const N: usize> {
    /// Dirty chunks: chunk_idx -> materialized chunk bytes.
    ///
    /// `ahash` (fast on integer keys) with `BuildHasherDefault` (no per-construction RNG
    /// sampling). Iteration order is not observed by any consumer.
    pub(crate) chunks: HashMap<usize, [u8; N], BuildHasherDefault<AHasher>>,
    /// Total number of bits (parent + new operations).
    pub(crate) len: u64,
}

impl<const N: usize> ChunkOverlay<N> {
    const CHUNK_BITS: u64 = bitmap::Prunable::<N>::CHUNK_SIZE_BITS;

    fn new(len: u64) -> Self {
        Self {
            chunks: HashMap::default(),
            len,
        }
    }

    /// Load-or-create a chunk: returns a mutable reference to the materialized chunk bytes. On
    /// first access for an existing chunk, reads from `base`.
    fn chunk_mut<B: bitmap::Readable<N>>(&mut self, base: &B, idx: usize) -> &mut [u8; N] {
        self.chunks.entry(idx).or_insert_with(|| {
            let base_len = base.len();
            let base_complete = base.complete_chunks();
            let base_has_partial = !base_len.is_multiple_of(Self::CHUNK_BITS);
            if idx < base_complete {
                base.get_chunk(idx)
            } else if idx == base_complete && base_has_partial {
                base.last_chunk().0
            } else {
                [0u8; N]
            }
        })
    }

    /// Set a single bit (used for pushes and active operations).
    fn set_bit<B: bitmap::Readable<N>>(&mut self, base: &B, loc: u64) {
        let idx = bitmap::Prunable::<N>::to_chunk_index(loc);
        let rel = (loc % Self::CHUNK_BITS) as usize;
        let chunk = self.chunk_mut(base, idx);
        chunk[rel / 8] |= 1 << (rel % 8);
    }

    /// Clear a single bit (used for superseded locations). `pruned_chunks` is passed in by the
    /// caller so the hot loop in `build_chunk_overlay` reads it once rather than per call.
    /// Skips locations in pruned chunks since those bits are already inactive.
    fn clear_bit<B: bitmap::Readable<N>>(&mut self, base: &B, pruned_chunks: usize, loc: u64) {
        let idx = bitmap::Prunable::<N>::to_chunk_index(loc);
        if idx < pruned_chunks {
            return;
        }
        let rel = (loc % Self::CHUNK_BITS) as usize;
        let chunk = self.chunk_mut(base, idx);
        chunk[rel / 8] &= !(1 << (rel % 8));
    }

    /// Get a dirty chunk's bytes, or `None` if unmodified.
    pub(crate) fn get(&self, idx: usize) -> Option<&[u8; N]> {
        self.chunks.get(&idx)
    }

    /// Number of complete chunks.
    pub(crate) const fn complete_chunks(&self) -> usize {
        (self.len / Self::CHUNK_BITS) as usize
    }
}

/// Bitmap-accelerated floor scan over a layered `BitmapBatch` chain. Skips locations where the
/// bitmap bit is unset, avoiding I/O reads for inactive operations.
///
/// Mirrors the contract on `any::batch::next_candidate`: may return only locations that are
/// *possibly* active in `[floor, tip)`, may skip locations only when known inactive.
/// `is_active_at` revalidates each candidate, so false positives are tolerated; false negatives
/// are forbidden.
///
/// False positives can arise two ways:
/// - In the committed prefix, an uncommitted ancestor batch in the chain may have superseded
///   the location — the committed bitmap doesn't reflect uncommitted shadows.
/// - Beyond the committed bitmap, locations are returned as sequential candidates (one per
///   index) without per-location filtering, so any inactive uncommitted op shows up here.
pub(crate) fn next_candidate<F: Graftable, B: bitmap::Readable<N>, const N: usize>(
    bitmap: &B,
    floor: Location<F>,
    tip: u64,
) -> Option<Location<F>> {
    let floor = *floor;
    let bitmap_len = bitmap.len();
    let committed_end = bitmap_len.min(tip);
    if floor < committed_end {
        if let Some(idx) = bitmap.ones_iter_from(floor).next() {
            if idx < committed_end {
                return Some(Location::<F>::new(idx));
            }
        }
    }
    let candidate = floor.max(bitmap_len);
    (candidate < tip).then(|| Location::<F>::new(candidate))
}

/// Adapter that resolves ops MMR nodes for a batch's `compute_current_layer`.
///
/// Tries the batch chain's sync [`Readable`] first (which covers nodes appended or overwritten
/// by the batch, plus anything still in the in-memory MMR). Falls through to the base's async
/// [`MerkleStorage`].
struct BatchStorageAdapter<
    'a,
    F: Graftable,
    D: Digest,
    R: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
    S: MerkleStorage<F, Digest = D>,
> {
    batch: &'a R,
    base: &'a S,
    _phantom: core::marker::PhantomData<(F, D)>,
}

impl<
        'a,
        F: Graftable,
        D: Digest,
        R: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
        S: MerkleStorage<F, Digest = D>,
    > BatchStorageAdapter<'a, F, D, R, S>
{
    const fn new(batch: &'a R, base: &'a S) -> Self {
        Self {
            batch,
            base,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<
        F: Graftable,
        D: Digest,
        R: Readable<Family = F, Digest = D, Error = merkle::Error<F>>,
        S: MerkleStorage<F, Digest = D>,
    > MerkleStorage<F> for BatchStorageAdapter<'_, F, D, R, S>
{
    type Digest = D;

    async fn size(&self) -> Position<F> {
        self.batch.size()
    }
    async fn get_node(&self, pos: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        if let Some(node) = self.batch.get_node(pos) {
            return Ok(Some(node));
        }
        self.base.get_node(pos).await
    }
}

/// Layers a [`merkle::batch::MerkleizedBatch`] over a [`merkle::mem::Mem`] for node resolution.
///
/// [`merkle::batch::MerkleizedBatch::get_node`] only covers the batch chain; committed positions
/// return `None`. This adapter falls through to the committed Mem for those positions.
struct BatchOverMem<'a, F: Graftable, D: Digest, S: Strategy = Sequential> {
    batch: &'a merkle::batch::MerkleizedBatch<F, D, S>,
    mem: &'a merkle::mem::Mem<F, D>,
}

impl<F: Graftable, D: Digest, S: Strategy> Readable for BatchOverMem<'_, F, D, S> {
    type Family = F;
    type Digest = D;
    type Error = merkle::Error<F>;

    fn size(&self) -> Position<F> {
        self.batch.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        if let Some(d) = self.batch.get_node(pos) {
            return Some(d);
        }
        self.mem.get_node(pos)
    }

    fn root(&self) -> D {
        self.batch.root()
    }

    fn pruning_boundary(&self) -> Location<F> {
        self.batch.pruning_boundary()
    }

    fn proof(
        &self,
        _hasher: &impl crate::merkle::hasher::Hasher<F, Digest = D>,
        _loc: Location<F>,
    ) -> Result<crate::merkle::Proof<F, D>, merkle::Error<F>> {
        unreachable!("proof not used in compute_current_layer")
    }

    fn range_proof(
        &self,
        _hasher: &impl crate::merkle::hasher::Hasher<F, Digest = D>,
        _range: core::ops::Range<Location<F>>,
    ) -> Result<crate::merkle::Proof<F, D>, merkle::Error<F>> {
        unreachable!("range_proof not used in compute_current_layer")
    }
}

/// A speculative batch of mutations whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Wraps a [`any::batch::UnmerkleizedBatch`] and adds bitmap and grafted MMR parent state
/// needed to compute the current layer during [`merkleize`](Self::merkleize).
pub struct UnmerkleizedBatch<F, H, U, const N: usize, S: Strategy = Sequential>
where
    F: Graftable,
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// The inner any-layer batch that handles mutations, journal, and floor raise.
    inner: any::batch::UnmerkleizedBatch<F, H, U, S>,

    /// Parent's grafted MMR state.
    grafted_parent: Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,

    /// Parent's bitmap state (COW, Arc-based).
    bitmap_parent: BitmapBatch<N>,
}

/// A speculative batch of operations whose root digest has been computed, in contrast to
/// [`UnmerkleizedBatch`].
///
/// Wraps an [`any::batch::MerkleizedBatch`] and adds the bitmap and grafted MMR state needed to
/// compute the canonical root.
///
/// # Branch validity
///
/// A `MerkleizedBatch` is a branch-scoped view rooted at a specific committed prefix of the DB. It
/// is not an immutable snapshot.
///
/// Internally, the batch chain terminates in the DB's committed bitmap via `BitmapBatch::Base`.
/// That committed bitmap evolves in place as [`Db::apply_batch`](super::db::Db::apply_batch),
/// [`Db::prune`](super::db::Db::prune), and [`Db::rewind`](super::db::Db::rewind) update the DB.
///
/// Reads through this batch's chain, constructing child batches from it, and applying it later are
/// only semantically correct while its ancestor chain is still the committed prefix of the DB. In
/// other words, every successful [`apply_batch`](super::db::Db::apply_batch) since this batch was
/// merkleized must have applied an ancestor of this batch.
///
/// Once a non-ancestor batch is applied, this batch and all of its descendants become invalid
/// objects. The library does not guard against continued use after that point.
///
/// Applying an invalid batch is caught by the any-layer staleness check and returns
/// [`Error::StaleBatch`] without mutating committed state, so `apply_batch` itself cannot corrupt
/// the DB. The one exception is equal-size sibling branches (where both branches have the same
/// total operation count): the staleness check is size-based and cannot distinguish them, so
/// applying a descendant of one sibling after the other was already applied can silently corrupt
/// snapshot/log state. Callers must not apply batches from an orphaned branch.
///
/// Rules of thumb:
/// - Drop any `Arc<MerkleizedBatch>` you no longer intend to apply.
/// - Extending a batch after `apply_batch` has consumed it (building a child off the just-applied
///   parent) is safe. The committed bitmap now equals the parent's post-apply state, so child reads
///   are consistent.
/// - Extending a batch after a different branch has been applied is not safe. Do not call `get`,
///   `new_batch`, or `apply_batch` on that branch again.
pub struct MerkleizedBatch<
    F: Graftable,
    D: Digest,
    U: update::Update + Send + Sync,
    const N: usize,
    S: Strategy = Sequential,
> where
    Operation<F, U>: Send + Sync,
{
    /// Inner any-layer batch (ops MMR, diff, floor, commit loc, sizes).
    pub(crate) inner: Arc<any::batch::MerkleizedBatch<F, D, U, S>>,

    /// Grafted MMR state.
    pub(crate) grafted: Arc<merkle::batch::MerkleizedBatch<F, D, S>>,

    /// COW bitmap state (for use as a parent in speculative batches).
    pub(crate) bitmap: BitmapBatch<N>,

    /// The canonical root (ops root + grafted root + partial chunk).
    pub(crate) canonical_root: D,
}

impl<F, H, U, const N: usize, S: Strategy> UnmerkleizedBatch<F, H, U, N, S>
where
    F: Graftable,
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    pub(super) const fn new(
        inner: any::batch::UnmerkleizedBatch<F, H, U, S>,
        grafted_parent: Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,
        bitmap_parent: BitmapBatch<N>,
    ) -> Self {
        Self {
            inner,
            grafted_parent,
            bitmap_parent,
        }
    }

    /// Record a mutation. Use `Some(value)` for update/create, `None` for delete.
    ///
    /// If the same key is written multiple times within a batch, the last
    /// value wins.
    pub fn write(mut self, key: U::Key, value: Option<U::Value>) -> Self {
        self.inner = self.inner.write(key, value);
        self
    }
}

// Unordered get + merkleize.
impl<F, K, V, H, const N: usize, S: Strategy> UnmerkleizedBatch<F, H, update::Unordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Read through: mutations -> ancestor diffs -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &K,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.inner.get(key, &db.any).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, I>(
        &self,
        keys: &[&K],
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.inner.get_many(keys, &db.any).await
    }

    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub async fn merkleize<E, C, I>(
        self,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, N, S>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        // Use the speculative parent bitmap rather than the committed `any` bitmap.
        let inner = inner
            .merkleize_with_floor_scan(&db.any, metadata, |floor, tip| {
                next_candidate(&bitmap_parent, floor, tip)
            })
            .await?;
        compute_current_layer(inner, db, &grafted_parent, &bitmap_parent).await
    }
}

// Ordered get + merkleize.
impl<F, K, V, H, const N: usize, S: Strategy> UnmerkleizedBatch<F, H, update::Ordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Read through: mutations -> ancestor diffs -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &K,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
    {
        self.inner.get(key, &db.any).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, I>(
        &self,
        keys: &[&K],
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> Result<Vec<Option<V::Value>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
    {
        self.inner.get_many(keys, &db.any).await
    }

    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub async fn merkleize<E, C, I>(
        self,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, N, S>>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        // Use the speculative parent bitmap rather than the committed `any` bitmap.
        let inner = inner
            .merkleize_with_floor_scan(&db.any, metadata, |floor, tip| {
                next_candidate(&bitmap_parent, floor, tip)
            })
            .await?;
        compute_current_layer(inner, db, &grafted_parent, &bitmap_parent).await
    }
}

/// Derive all bitmap mutations (pushes + clears) for this batch in a single pass over the diff and
/// ancestor diffs. Avoids iterating raw operations.
///
/// Pushes: one bit per operation in the batch. All false except active diff entries (whose `loc`
/// falls in the batch) and the CommitFloor (last op).
///
/// Clears: previous CommitFloor, plus the most recent superseded location for each mutated key. We
/// search back through ancestors to find the most recent active location; if none exists, we clear
/// the committed DB location (`base_old_loc`).
#[allow(clippy::type_complexity)]
fn build_chunk_overlay<F: Graftable, U, B: bitmap::Readable<N>, const N: usize>(
    base: &B,
    batch_len: usize,
    batch_base: u64,
    diff: &[(U::Key, DiffEntry<F, U::Value>)],
    ancestor_diffs: &[Arc<Vec<(U::Key, DiffEntry<F, U::Value>)>>],
) -> ChunkOverlay<N>
where
    U: update::Update,
{
    let total_bits = base.len() + batch_len as u64;
    let mut overlay = ChunkOverlay::new(total_bits);
    let pruned_chunks = base.pruned_chunks();

    // 1. CommitFloor (last op) is always active.
    let commit_loc = batch_base + batch_len as u64 - 1;
    overlay.set_bit(base, commit_loc);

    // 2. Inactivate previous CommitFloor.
    overlay.clear_bit(base, pruned_chunks, batch_base - 1);

    // 3. Set active bits + clear superseded locations from the diff.
    for (key, entry) in diff {
        // Set the active bit for this key's final location.
        if let Some(loc) = entry.loc() {
            if *loc >= batch_base && *loc < batch_base + batch_len as u64 {
                overlay.set_bit(base, *loc);
            }
        }

        // Clear the most recent superseded location. Older locations were already cleared by the
        // ancestor batch that superseded them.
        let mut prev_loc = entry.base_old_loc();
        for ancestor_diff in ancestor_diffs {
            if let Some(ancestor_entry) = lookup_sorted(ancestor_diff.as_slice(), key) {
                prev_loc = ancestor_entry.loc();
                break;
            }
        }
        if let Some(old) = prev_loc {
            overlay.clear_bit(base, pruned_chunks, *old);
        }
    }

    // Ensure all new complete chunks beyond the parent are materialized, so downstream consumers
    // don't read from the parent and panic on out-of-range indices. Uses chunk_mut to inherit the
    // parent's partial chunk data when idx == parent_complete (avoiding loss of existing bits).
    let parent_complete = base.complete_chunks();
    let new_complete = overlay.complete_chunks();
    for idx in parent_complete..new_complete {
        overlay.chunk_mut(base, idx);
    }

    overlay
}

/// Compute the current layer (bitmap + grafted MMR + canonical root) on top of a merkleized any
/// batch.
///
/// Builds a chunk overlay from the diff, computes grafted MMR leaves from dirty chunks, and
/// produces the `Arc<MerkleizedBatch>` directly.
async fn compute_current_layer<F, E, U, C, I, H, const N: usize, S>(
    inner: Arc<any::batch::MerkleizedBatch<F, H::Digest, U, S>>,
    current_db: &super::db::Db<F, E, C, I, H, U, N, S>,
    grafted_parent: &Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,
    bitmap_parent: &BitmapBatch<N>,
) -> Result<Arc<MerkleizedBatch<F, H::Digest, U, N, S>>, Error<F>>
where
    F: Graftable,
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    let batch_len = inner.journal_batch.items().len();
    let batch_base = *inner.new_last_commit_loc + 1 - batch_len as u64;

    // Build chunk overlay: materialized bytes for every dirty chunk.
    let overlay = build_chunk_overlay::<F, U, _, N>(
        bitmap_parent,
        batch_len,
        batch_base,
        &inner.diff,
        &inner.ancestor_diffs,
    );

    let grafting_height = grafting::height::<N>();
    let ops_tree_adapter =
        BatchStorageAdapter::new(&inner.journal_batch, &current_db.any.log.merkle);
    let base_ops_leaves = Location::<F>::try_from(current_db.any.log.merkle.size())?.as_u64();

    // Recompute grafted leaves for dirty complete chunks. For MMB, the last complete chunk can
    // still change while delayed merges finalize its grafting-height digest, so we force-refresh
    // that chunk until its peak birth threshold is reached.
    let new_grafted_leaves = overlay.complete_chunks();
    let mut chunk_indices_to_update: BTreeSet<usize> = overlay
        .chunks
        .iter()
        .filter(|(&idx, _)| idx < new_grafted_leaves)
        .map(|(&idx, _)| idx)
        .collect();
    // Both are chunk indices (not bit positions); cast to u64 only for the shift arithmetic.
    let pruned_chunks = bitmap_parent.pruned_chunks();
    if new_grafted_leaves > 0 {
        let last_complete_chunk = new_grafted_leaves - 1;
        let chunk_start = (last_complete_chunk as u64)
            .checked_shl(grafting_height)
            .ok_or(Error::DataCorrupted("chunk start overflow"))?;
        let chunk_end = ((last_complete_chunk + 1) as u64)
            .checked_shl(grafting_height)
            .ok_or(Error::DataCorrupted("chunk end overflow"))?;
        let chunk_pos = F::subtree_root_position(Location::<F>::new(chunk_start), grafting_height);
        let stable_after = F::peak_birth_size(chunk_pos, grafting_height);
        if stable_after > chunk_end
            && last_complete_chunk >= pruned_chunks // skip already-pruned chunks
            && base_ops_leaves < stable_after
        {
            chunk_indices_to_update.insert(last_complete_chunk);
        }
    }
    let chunks_to_update = chunk_indices_to_update.into_iter().map(|idx| {
        let chunk = overlay
            .get(idx)
            .copied()
            .unwrap_or_else(|| bitmap_parent.get_chunk(idx));
        (idx, chunk)
    });

    let hasher = StandardHasher::<H>::new();
    let new_leaves = compute_grafted_leaves::<F, H, S, N>(
        &hasher,
        &ops_tree_adapter,
        chunks_to_update,
        &current_db.strategy,
    )
    .await?;

    // Build grafted MMR from parent batch.
    let grafted_batch = {
        let mut grafted_batch = grafted_parent.new_batch();
        let old_grafted_leaves = *grafted_parent.leaves() as usize;
        for &(chunk_idx, digest) in &new_leaves {
            if chunk_idx < old_grafted_leaves {
                grafted_batch = grafted_batch
                    .update_leaf_digest(Location::<F>::new(chunk_idx as u64), digest)
                    .expect("update_leaf_digest failed");
            } else {
                grafted_batch = grafted_batch.add_leaf_digest(digest);
            }
        }
        let gh = grafting::GraftedHasher::<F, _>::new(hasher.clone(), grafting_height);
        grafted_batch.merkleize(&current_db.grafted_tree, &gh)
    };

    // Build the layered bitmap (parent + overlay) before computing the canonical root, so that
    // compute_db_root sees newly completed chunks. Using bitmap_parent alone would miss chunks
    // that transitioned from partial to complete in this batch.
    let bitmap_batch = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
        parent: bitmap_parent.clone(),
        overlay: Arc::new(overlay),
        shared: Arc::clone(bitmap_parent.shared()),
    }));

    // Compute canonical root. The grafted batch alone cannot resolve committed nodes,
    // so layer it over the committed grafted MMR.
    let ops_root = inner.root();
    let layered = BatchOverMem {
        batch: &grafted_batch,
        mem: &current_db.grafted_tree,
    };
    let grafted_storage =
        grafting::Storage::new(&layered, grafting_height, &ops_tree_adapter, hasher.clone());
    // Compute partial chunk (last incomplete chunk, if any).
    let partial = {
        let rem = bitmap_batch.len() % BitmapBatch::<N>::CHUNK_SIZE_BITS;
        if rem == 0 {
            None
        } else {
            let idx = new_grafted_leaves;
            let chunk = bitmap_batch.get_chunk(idx);
            Some((chunk, rem))
        }
    };
    let canonical_root = compute_db_root::<F, H, _, _, N>(
        &hasher,
        &bitmap_batch,
        &grafted_storage,
        partial,
        &ops_root,
    )
    .await?;

    Ok(Arc::new(MerkleizedBatch {
        inner,
        grafted: grafted_batch,
        bitmap: bitmap_batch,
        canonical_root,
    }))
}

/// A view of the committed bitmap plus zero or more speculative overlay `Layer`s.
///
/// The chain terminates in a `Base` that references the shared committed bitmap. No validity
/// check is performed. Callers must ensure they only read through batches whose chains are
/// still valid prefixes of committed state (see [`Shared`]'s docs).
#[derive(Clone, Debug)]
pub(crate) enum BitmapBatch<const N: usize> {
    /// Chain terminal: shared reference to the committed bitmap.
    Base(Arc<Shared<N>>),
    /// Speculative layer on top of a parent batch.
    Layer(Arc<BitmapBatchLayer<N>>),
}

/// The data behind a [`BitmapBatch::Layer`].
#[derive(Debug)]
pub(crate) struct BitmapBatchLayer<const N: usize> {
    pub(crate) parent: BitmapBatch<N>,
    /// Chunk-level overlay: materialized bytes for every chunk that differs from parent.
    pub(crate) overlay: Arc<ChunkOverlay<N>>,
    /// Cached terminal [`Shared`] so [`BitmapBatch::shared`] and
    /// [`BitmapBatch::pruned_chunks`] answer in O(1) instead of walking the chain.
    pub(crate) shared: Arc<Shared<N>>,
}

impl<const N: usize> BitmapBatch<N> {
    const CHUNK_SIZE_BITS: u64 = bitmap::Prunable::<N>::CHUNK_SIZE_BITS;

    /// Return the terminal [`Shared`] at the bottom of the chain.
    fn shared(&self) -> &Arc<Shared<N>> {
        match self {
            Self::Base(s) => s,
            Self::Layer(layer) => &layer.shared,
        }
    }

    /// Return a chain equivalent to `self` with any `Layer` whose overlay is now fully committed
    /// replaced by a direct reference to the committed bitmap. Since `apply_batch` commits
    /// contiguous prefixes, committed `Layer`s are always at the bottom of the chain.
    fn trim_committed(&self) -> Self {
        let shared = self.shared();
        let committed = bitmap::Readable::<N>::len(shared.as_ref());
        let mut kept = Vec::new();
        let mut current = self;
        while let Self::Layer(layer) = current {
            if layer.overlay.len <= committed {
                break;
            }
            kept.push(Arc::clone(&layer.overlay));
            current = &layer.parent;
        }
        let mut result = Self::Base(Arc::clone(shared));
        for overlay in kept.into_iter().rev() {
            result = Self::Layer(Arc::new(BitmapBatchLayer {
                parent: result,
                overlay,
                shared: Arc::clone(shared),
            }));
        }
        result
    }
}

impl<const N: usize> bitmap::Readable<N> for BitmapBatch<N> {
    fn complete_chunks(&self) -> usize {
        (self.len() / Self::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        // Walk the layer chain. Each layer's overlay either holds the chunk (return it) or
        // doesn't (descend).
        let mut current = self;
        loop {
            match current {
                Self::Base(shared) => return shared.get_chunk(idx),
                Self::Layer(layer) => {
                    if let Some(&chunk) = layer.overlay.get(idx) {
                        return chunk;
                    }
                    current = &layer.parent;
                }
            }
        }
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let total = self.len();
        if total == 0 {
            return ([0u8; N], 0);
        }
        let rem = total % Self::CHUNK_SIZE_BITS;
        let bits_in_last = if rem == 0 { Self::CHUNK_SIZE_BITS } else { rem };
        let idx = if rem == 0 {
            self.complete_chunks().saturating_sub(1)
        } else {
            self.complete_chunks()
        };
        (self.get_chunk(idx), bits_in_last)
    }

    fn pruned_chunks(&self) -> usize {
        self.shared().pruned_chunks()
    }

    fn len(&self) -> u64 {
        match self {
            Self::Base(shared) => bitmap::Readable::<N>::len(shared.as_ref()),
            Self::Layer(layer) => layer.overlay.len,
        }
    }
}

impl<F: Graftable, D: Digest, U: update::Update + Send + Sync, const N: usize, S: Strategy>
    MerkleizedBatch<F, D, U, N, S>
where
    Operation<F, U>: Send + Sync,
{
    /// Return the canonical root.
    pub const fn root(&self) -> D {
        self.canonical_root
    }

    /// Return the ops-only MMR root.
    pub fn ops_root(&self) -> D {
        self.inner.root()
    }
}

impl<F: Graftable, D: Digest, U: update::Update + Send + Sync, const N: usize, S: Strategy>
    MerkleizedBatch<F, D, U, N, S>
where
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    ///
    /// All uncommitted ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Dropping an uncommitted ancestor causes data
    /// loss detected at `apply_batch` time.
    ///
    /// This is only valid while `self` is still on the winning branch. If a different branch has
    /// been applied since `self` was created, `self` is no longer a valid parent and must not be
    /// extended.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, U, N, S>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch::new(
            self.inner.new_batch::<H>(),
            Arc::clone(&self.grafted),
            self.bitmap.trim_committed(),
        )
    }

    /// Read through: local diff -> ancestor diffs -> committed DB.
    ///
    /// This is only valid while `self` remains on the committed prefix. If a non-ancestor batch
    /// has been applied since `self` was merkleized, do not read through it.
    pub async fn get<E, C, I, H>(
        &self,
        key: &U::Key,
        db: &super::db::Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Option<U::Value>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher<Digest = D>,
    {
        self.inner.get(key, &db.any).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, I, H>(
        &self,
        keys: &[&U::Key],
        db: &super::db::Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Vec<Option<U::Value>>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher<Digest = D>,
    {
        self.inner.get_many(keys, &db.any).await
    }
}

impl<F, E, C, I, H, U, const N: usize, S> super::db::Db<F, E, C, I, H, U, N, S>
where
    F: Graftable,
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Create an initial [`MerkleizedBatch`] from the current committed DB state.
    ///
    /// The returned batch is rooted at the current committed prefix, but it is not a persistent
    /// snapshot across later divergent commits. If some other branch is applied afterward, this
    /// batch is no longer valid and must not be read through, extended, or applied.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, U, N, S>> {
        let grafted = self.grafted_snapshot();
        Arc::new(MerkleizedBatch {
            inner: self.any.to_batch(),
            grafted,
            bitmap: BitmapBatch::Base(Arc::clone(&self.any.bitmap)),
            canonical_root: self.root,
        })
    }
}

#[cfg(any(test, feature = "test-traits"))]
mod trait_impls {
    use super::*;
    use crate::{
        journal::contiguous::Mutable,
        qmdb::any::traits::{
            BatchableDb, MerkleizedBatch as MerkleizedBatchTrait,
            UnmerkleizedBatch as UnmerkleizedBatchTrait,
        },
        Persistable,
    };
    use std::future::Future;

    type CurrentDb<F, E, C, I, H, U, const N: usize, S> =
        crate::qmdb::current::db::Db<F, E, C, I, H, U, N, S>;

    impl<F, K, V, H, E, C, I, const N: usize, S>
        UnmerkleizedBatchTrait<CurrentDb<F, E, C, I, H, update::Unordered<K, V>, N, S>>
        for UnmerkleizedBatch<F, H, update::Unordered<K, V>, N, S>
    where
        F: Graftable,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        S: Strategy,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, N, S>>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            db: &CurrentDb<F, E, C, I, H, update::Unordered<K, V>, N, S>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata)
        }
    }

    impl<F, K, V, H, E, C, I, const N: usize, S>
        UnmerkleizedBatchTrait<CurrentDb<F, E, C, I, H, update::Ordered<K, V>, N, S>>
        for UnmerkleizedBatch<F, H, update::Ordered<K, V>, N, S>
    where
        F: Graftable,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
        S: Strategy,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, N, S>>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            db: &CurrentDb<F, E, C, I, H, update::Ordered<K, V>, N, S>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata)
        }
    }

    impl<
            F: Graftable,
            D: Digest,
            U: update::Update + Send + Sync + 'static,
            const N: usize,
            S: Strategy,
        > MerkleizedBatchTrait for Arc<MerkleizedBatch<F, D, U, N, S>>
    where
        Operation<F, U>: Codec,
    {
        type Digest = D;

        fn root(&self) -> D {
            MerkleizedBatch::root(self)
        }
    }

    impl<F, E, K, V, C, I, H, const N: usize, S> BatchableDb
        for CurrentDb<F, E, C, I, H, update::Unordered<K, V>, N, S>
    where
        F: Graftable,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher,
        S: Strategy,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, N, S>>;
        type Batch = UnmerkleizedBatch<F, H, update::Unordered<K, V>, N, S>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Merkleized,
        ) -> impl Future<Output = Result<core::ops::Range<Location<F>>, crate::qmdb::Error<F>>>
        {
            self.apply_batch(batch)
        }
    }

    impl<F, E, K, V, C, I, H, const N: usize, S> BatchableDb
        for CurrentDb<F, E, C, I, H, update::Ordered<K, V>, N, S>
    where
        F: Graftable,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
        H: Hasher,
        S: Strategy,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, N, S>>;
        type Batch = UnmerkleizedBatch<F, H, update::Ordered<K, V>, N, S>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Merkleized,
        ) -> impl Future<Output = Result<core::ops::Range<Location<F>>, crate::qmdb::Error<F>>>
        {
            self.apply_batch(batch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr;
    use commonware_utils::bitmap::Prunable as BitMap;

    // N=4 -> CHUNK_SIZE_BITS = 32
    const N: usize = 4;
    type Bm = BitMap<N>;
    type Location = mmr::Location;

    fn make_bitmap(bits: &[bool]) -> Bm {
        let mut bm = Bm::new();
        for &b in bits {
            bm.push(b);
        }
        bm
    }

    // ---- build_chunk_overlay tests ----

    #[test]
    fn chunk_overlay_pushes() {
        use crate::qmdb::any::value::FixedEncoding;
        use commonware_utils::sequence::FixedBytes;

        type K = FixedBytes<4>;
        type V = FixedEncoding<u64>;
        type U = crate::qmdb::any::operation::update::Unordered<K, V>;

        let key1 = FixedBytes::from([1, 0, 0, 0]);
        let key2 = FixedBytes::from([2, 0, 0, 0]);

        // Base: 4 bits, all set (previous commit at loc 3).
        // Segment of 4 operations starting at base_size=4.
        // Diff: key1 active at loc=4 (in batch), key2 active at loc=99 (not in batch,
        // so superseded within this batch).
        let base = make_bitmap(&[true; 4]);
        let mut diff = vec![
            (
                key1,
                DiffEntry::Active {
                    value: 100u64,
                    loc: Location::new(4), // offset 0 in batch
                    base_old_loc: None,
                },
            ),
            (
                key2,
                DiffEntry::Active {
                    value: 200u64,
                    loc: Location::new(99), // not in batch [4,8), so superseded
                    base_old_loc: None,
                },
            ),
        ];
        diff.sort_by(|a, b| a.0.cmp(&b.0));

        let overlay = build_chunk_overlay::<mmr::Family, U, _, N>(&base, 4, 4, &diff, &[]);

        // Chunk 0 should have: bits 0-3 from base (all set), bit 4 set (key1), bits 5-6 false
        // (inactive), bit 7 set (CommitFloor at loc 7). Also bit 3 cleared (previous commit).
        let c0 = overlay.get(0).expect("chunk 0 should be dirty");
        assert_ne!(c0[0] & (1 << 4), 0); // key1 active
        assert_eq!(c0[0] & (1 << 5), 0); // inactive
        assert_eq!(c0[0] & (1 << 6), 0); // inactive
        assert_ne!(c0[0] & (1 << 7), 0); // CommitFloor
        assert_eq!(c0[0] & (1 << 3), 0); // previous commit cleared
    }

    #[test]
    fn chunk_overlay_clears() {
        use crate::qmdb::any::value::FixedEncoding;
        use commonware_utils::sequence::FixedBytes;

        type K = FixedBytes<4>;
        type U = crate::qmdb::any::operation::update::Unordered<K, FixedEncoding<u64>>;

        let key1 = FixedBytes::from([1, 0, 0, 0]);
        let key2 = FixedBytes::from([2, 0, 0, 0]);
        let key3 = FixedBytes::from([3, 0, 0, 0]);

        // Base bitmap with 64 bits, all set.
        let base = make_bitmap(&[true; 64]);

        let mut diff: Vec<(K, DiffEntry<mmr::Family, u64>)> = vec![
            (
                key1,
                DiffEntry::Active {
                    value: 100,
                    loc: Location::new(70),
                    base_old_loc: Some(Location::new(5)),
                },
            ),
            (
                key2,
                DiffEntry::Deleted {
                    base_old_loc: Some(Location::new(10)),
                },
            ),
            (
                key3,
                DiffEntry::Active {
                    value: 300,
                    loc: Location::new(71),
                    base_old_loc: None,
                },
            ),
        ];
        diff.sort_by(|a, b| a.0.cmp(&b.0));

        // Segment of 8 ops starting at 64; previous commit at loc 63.
        let overlay = build_chunk_overlay::<mmr::Family, U, _, N>(&base, 8, 64, &diff, &[]);

        // Verify bits 5 and 10 are cleared in chunk 0.
        let c0 = overlay.get(0).expect("chunk 0 should be dirty");
        assert_eq!(c0[0] & (1 << 5), 0); // bit 5 cleared
        assert_eq!(c0[1] & (1 << 2), 0); // bit 10 = byte 1, bit 2 cleared

        // Other bits should still be set.
        assert_eq!(c0[0] & (1 << 4), 1 << 4); // bit 4 still set
        assert_eq!(c0[1] & (1 << 3), 1 << 3); // bit 11 still set
    }

    /// Regression: when the parent bitmap has a partial last chunk that becomes complete in the
    /// child (without any active bits landing in that chunk), the overlay must inherit the parent's
    /// partial chunk data, not zero it out.
    #[test]
    fn chunk_overlay_preserves_partial_parent_chunk() {
        use crate::qmdb::any::value::FixedEncoding;
        use commonware_utils::sequence::FixedBytes;

        type K = FixedBytes<4>;
        type U = crate::qmdb::any::operation::update::Unordered<K, FixedEncoding<u64>>;

        // Base: 20 bits set (partial chunk 0, CHUNK_SIZE_BITS=32).
        let base = make_bitmap(&[true; 20]);
        assert_eq!(base.complete_chunks(), 0); // partial

        // Segment of 20 ops starting at loc 20. This pushes total to 40 bits, completing chunk 0
        // (32 bits) and starting chunk 1. Diff: only one active key at loc 35 (in chunk 1), plus
        // CommitFloor at loc 39. No active bits land in chunk 0's new region (bits 20-31).
        let key1 = FixedBytes::from([1, 0, 0, 0]);
        let mut diff = vec![(
            key1,
            DiffEntry::Active {
                value: 42u64,
                loc: Location::new(35),
                base_old_loc: None,
            },
        )];
        diff.sort_by(|a, b| a.0.cmp(&b.0));

        let overlay = build_chunk_overlay::<mmr::Family, U, _, N>(&base, 20, 20, &diff, &[]);

        // Chunk 0 should be materialized and preserve the parent's first 20 bits.
        let c0 = overlay.get(0).expect("chunk 0 should be in overlay");
        // Bits 0-7 all set -> byte 0 = 0xFF
        assert_eq!(c0[0], 0xFF);
        // Bits 8-15 all set -> byte 1 = 0xFF
        assert_eq!(c0[1], 0xFF);
        // Bits 16-18 set, bit 19 cleared (previous commit), 20-23 not set -> byte 2 = 0x07
        assert_eq!(c0[2], 0x07);
    }

    // ---- next_candidate tests ----

    #[test]
    fn bitmap_scan_all_active() {
        let bm = make_bitmap(&[true; 8]);
        for i in 0..8 {
            assert_eq!(
                next_candidate(&bm, Location::new(i), 8),
                Some(Location::new(i))
            );
        }
        assert_eq!(next_candidate(&bm, Location::new(8), 8), None);
    }

    #[test]
    fn bitmap_scan_all_inactive() {
        let bm = make_bitmap(&[false; 8]);
        assert_eq!(next_candidate(&bm, Location::new(0), 8), None);
    }

    #[test]
    fn bitmap_scan_skips_inactive() {
        // Pattern: inactive, inactive, active, inactive, active
        let bm = make_bitmap(&[false, false, true, false, true]);
        assert_eq!(
            next_candidate(&bm, Location::new(0), 5),
            Some(Location::new(2))
        );
        assert_eq!(
            next_candidate(&bm, Location::new(3), 5),
            Some(Location::new(4))
        );
        assert_eq!(next_candidate(&bm, Location::new(5), 5), None);
    }

    #[test]
    fn bitmap_scan_beyond_bitmap_len_returns_candidate() {
        // Bitmap has 4 bits, but tip is 8. Locations 4..8 are beyond the bitmap and should be
        // returned as candidates.
        let bm = make_bitmap(&[false; 4]);
        // All bitmap bits are unset, so 0..4 are skipped; loc 4 is beyond bitmap -> candidate.
        assert_eq!(
            next_candidate(&bm, Location::new(0), 8),
            Some(Location::new(4))
        );
        assert_eq!(
            next_candidate(&bm, Location::new(6), 8),
            Some(Location::new(6))
        );
    }

    #[test]
    fn bitmap_scan_respects_tip() {
        let bm = make_bitmap(&[false, false, false, true]);
        // Active bit at 3, but tip is 3 so it's excluded.
        assert_eq!(next_candidate(&bm, Location::new(0), 3), None);
        // With tip=4, bit 3 is included.
        assert_eq!(
            next_candidate(&bm, Location::new(0), 4),
            Some(Location::new(3))
        );
    }

    #[test]
    fn bitmap_scan_floor_at_tip() {
        let bm = make_bitmap(&[true; 4]);
        assert_eq!(next_candidate(&bm, Location::new(4), 4), None);
    }

    #[test]
    fn bitmap_scan_empty_bitmap() {
        let bm = Bm::new();
        // Empty bitmap, but tip > 0: all locations are beyond bitmap.
        assert_eq!(
            next_candidate(&bm, Location::new(0), 5),
            Some(Location::new(0))
        );
        // Empty bitmap, tip = 0: no candidates.
        assert_eq!(next_candidate(&bm, Location::new(0), 0), None);
    }

    // ---- trim_committed tests ----
    //
    // `trim_committed` is called from `MerkleizedBatch::new_batch` to strip any `Layer`s whose
    // overlays have already been absorbed into the shared committed bitmap by a prior apply.
    // The implementation is a single loop that collects uncommitted overlays top-down and
    // rebuilds a fresh chain rooted at `Base`. These tests cover distinct input shapes directly,
    // without going through the full Db/batch machinery, so the function's structural output
    // can be asserted.

    /// Build a chain `Base(shared) -> Layer(len=L1) -> Layer(len=L2) -> ...` from a list of
    /// overlay lengths (bottom to top). Each constructed `Layer` caches `shared` per the
    /// struct's invariant.
    fn make_chain(shared: &Arc<Shared<N>>, overlay_lens: &[u64]) -> BitmapBatch<N> {
        let mut chain = BitmapBatch::Base(Arc::clone(shared));
        for &len in overlay_lens {
            chain = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
                parent: chain,
                overlay: Arc::new(ChunkOverlay::new(len)),
                shared: Arc::clone(shared),
            }));
        }
        chain
    }

    /// Walk a chain and return its overlay lengths in bottom-to-top order. Used to assert the
    /// structural output of `trim_committed` without touching private fields. Panics if the
    /// chain isn't terminated by a single `Base` at the bottom.
    fn chain_overlays(batch: &BitmapBatch<N>) -> Vec<u64> {
        let mut lens = Vec::new();
        let mut current = batch;
        while let BitmapBatch::Layer(layer) = current {
            lens.push(layer.overlay.len);
            current = &layer.parent;
        }
        assert!(matches!(current, BitmapBatch::Base(_)));
        lens.reverse();
        lens
    }

    /// Input is already a bare `Base` with no speculative layers on top — the loop body never
    /// runs, `kept` stays empty, and the result is a freshly constructed `Base` pointing at the
    /// same `Shared`. Real-world trigger: `MerkleizedBatch::new_batch` on a batch whose
    /// chain was previously trimmed flat (e.g., immediately after an apply collapsed everything).
    #[test]
    fn trim_committed_already_base() {
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 64])));
        let base = BitmapBatch::Base(Arc::clone(&shared));
        let result = base.trim_committed();
        // Still `Base`, pointing at the same shared terminal.
        match result {
            BitmapBatch::Base(s) => assert!(Arc::ptr_eq(&s, &shared)),
            BitmapBatch::Layer(_) => panic!("expected Base"),
        }
    }

    /// Every layer has been absorbed by prior applies — the loop breaks on the first iteration
    /// and `kept` stays empty, so the result is a bare `Base`. This is the steady-state
    /// "extend a just-applied batch" flow: after `apply_batch(A)`, `A`'s own layer has
    /// `overlay.len == committed` and the next `new_batch` call should start from a clean
    /// terminal.
    #[test]
    fn trim_committed_all_committed() {
        // `shared.len() == 64`; the single layer's `overlay.len == 32 (<= 64)`, so it's committed.
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 64])));
        let chain = make_chain(&shared, &[32]);
        let result = chain.trim_committed();
        // Collapsed to a bare Base, pointing at the original shared.
        match result {
            BitmapBatch::Base(s) => assert!(Arc::ptr_eq(&s, &shared)),
            BitmapBatch::Layer(_) => panic!("expected Base after full trim"),
        }
    }

    /// Every layer is still speculative — the loop walks all the way to `Base` without
    /// breaking, and `kept` holds every overlay. The rebuilt chain is structurally equivalent
    /// to the input (same overlay lens, same shared terminal). Real-world trigger: speculating
    /// multiple batches deep (A, then B off A, then C off B) without `apply_batch` in between.
    #[test]
    fn trim_committed_none_committed() {
        // `shared.len() == 32`; both overlays have `len > 32`, so neither is committed.
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 32])));
        let chain = make_chain(&shared, &[64, 96]);
        let result = chain.trim_committed();
        // Structure must be preserved in bottom-to-top order.
        assert_eq!(chain_overlays(&result), vec![64, 96]);
    }

    /// Exactly one layer is uncommitted (the newest) on top of a committed prefix — the
    /// dominant pattern in chained growth. The loop collects the one uncommitted overlay, and
    /// the rebuild produces `Layer(Base, overlay_B)`. Also verifies the rebuilt layer carries
    /// the cached `shared` reference correctly. Real-world trigger: apply parent A, then B
    /// held alive off A, then `B.new_batch()` to build C.
    #[test]
    fn trim_committed_exactly_one_uncommitted() {
        // `shared.len() == 64`; committed layer (`overlay.len == 64`) + uncommitted (`96`).
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 64])));
        let chain = make_chain(&shared, &[64, 96]);
        let result = chain.trim_committed();
        // The committed layer is gone; only the uncommitted overlay remains.
        assert_eq!(chain_overlays(&result), vec![96]);
        // And the rebuilt layer's `shared` field still points at the original terminal.
        assert!(Arc::ptr_eq(result.shared(), &shared));
    }

    /// Two or more uncommitted layers on top of a committed prefix — exercises the loop's
    /// iterated `kept.push` and the rebuild's iterated `Arc::new(BitmapBatchLayer)`, including
    /// the cached `shared` wire-through on every reconstructed layer. Real-world trigger:
    /// build A, then B off A, then C off B; apply only A; then call `C.new_batch()`.
    #[test]
    fn trim_committed_multiple_uncommitted() {
        // `shared.len() == 64`; committed layer (64), then two uncommitted (96, 128).
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 64])));
        let chain = make_chain(&shared, &[64, 96, 128]);
        let result = chain.trim_committed();
        // Committed layer dropped; uncommitted pair preserved in order.
        assert_eq!(chain_overlays(&result), vec![96, 128]);
        // Every reconstructed layer must still cache the original shared terminal.
        assert!(Arc::ptr_eq(result.shared(), &shared));
    }
}
