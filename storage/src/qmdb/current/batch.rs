//! Batch mutation API for Current QMDBs.
//!
//! Wraps the [`any::batch`] API.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    merkle::{self, storage::Storage as MerkleStorage, Graftable, Location, Position, Readable},
    mmr::StandardHasher,
    qmdb::{
        any::{
            self,
            batch::{DiffEntry, FloorScan},
            operation::{update, Operation},
            ValueEncoding,
        },
        current::{
            db::{compute_db_root, compute_grafted_leaves, partial_chunk},
            grafting,
        },
        operation::{Key, Operation as OperationTrait},
        Error,
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

/// Cleared bitmap bits tracked in two synchronized views.
///
/// `locations` preserves the original clear operations so batch chaining, flattening, and
/// finalization can replay them in order. `masks` indexes the same clears by chunk, allowing
/// [`apply_push_clear`] to zero an entire chunk without rescanning every cleared location.
#[derive(Clone, Debug, Default)]
pub(super) struct ClearSet<F: Graftable, const N: usize> {
    locations: Vec<Location<F>>,
    masks: BTreeMap<usize, [u8; N]>,
}

impl<F: Graftable, const N: usize> ClearSet<F, N> {
    /// Create a clear set with a given capacity.
    fn with_capacity(capacity: usize) -> Self {
        Self {
            locations: Vec::with_capacity(capacity),
            masks: BTreeMap::new(),
        }
    }

    /// Push a location to the clear set.
    fn push(&mut self, loc: Location<F>) {
        self.locations.push(loc);

        let chunk_idx = BitMap::<N>::to_chunk_index(*loc);
        let rel = (*loc % BitMap::<N>::CHUNK_SIZE_BITS) as usize;
        let chunk = self.masks.entry(chunk_idx).or_insert([0u8; N]);
        chunk[rel / 8] |= 1 << (rel % 8);
    }

    /// Merge another clear set into this one.
    fn merge(&mut self, other: &Self) {
        self.locations.extend_from_slice(&other.locations);
        for (&idx, other_mask) in &other.masks {
            let chunk = self.masks.entry(idx).or_insert([0u8; N]);
            for (byte, &m) in chunk.iter_mut().zip(other_mask) {
                *byte |= m;
            }
        }
    }

    /// Return the number of locations in the clear set.
    const fn len(&self) -> usize {
        self.locations.len()
    }

    const fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Return the locations in the clear set.
    fn locations(&self) -> &[Location<F>] {
        &self.locations
    }

    /// Return the mask for the given chunk index.
    fn mask(&self, idx: usize) -> Option<&[u8; N]> {
        self.masks.get(&idx)
    }
}

/// Apply pushed bits and cleared bits to `chunk` at absolute position `chunk_start`.
///
/// `push_start` is the absolute bit index where pushes begin (i.e. the parent's length).
/// `clear_mask` is the chunk-local view returned by [`ClearSet::mask`].
fn apply_push_clear<const N: usize>(
    chunk: &mut [u8; N],
    chunk_start: u64,
    push_start: u64,
    pushed_bits: &[bool],
    clear_mask: Option<&[u8; N]>,
) {
    let chunk_end = chunk_start + BitMap::<N>::CHUNK_SIZE_BITS;

    let push_end = push_start + pushed_bits.len() as u64;
    if push_start < chunk_end && push_end > chunk_start {
        let abs_start = push_start.max(chunk_start);
        let abs_end = push_end.min(chunk_end);
        let from = (abs_start - push_start) as usize;
        let to = (abs_end - push_start) as usize;
        let rel_offset = (abs_start - chunk_start) as usize;
        for (j, &bit) in pushed_bits[from..to].iter().enumerate() {
            if bit {
                let rel = rel_offset + j;
                chunk[rel / 8] |= 1 << (rel % 8);
            }
        }
    }

    if let Some(clear_mask) = clear_mask {
        for (byte, mask) in chunk.iter_mut().zip(clear_mask) {
            *byte &= !mask;
        }
    }
}

/// Bitmap-accelerated floor scan. Skips locations where the bitmap bit is
/// unset, avoiding I/O reads for inactive operations.
pub(crate) struct BitmapScan<'a, B, const N: usize> {
    bitmap: &'a B,
}

impl<'a, B: BitmapReadable<N>, const N: usize> BitmapScan<'a, B, N> {
    pub(crate) const fn new(bitmap: &'a B) -> Self {
        Self { bitmap }
    }
}

impl<F: Graftable, B: BitmapReadable<N>, const N: usize> FloorScan<F> for BitmapScan<'_, B, N> {
    fn next_candidate(&mut self, floor: Location<F>, tip: u64) -> Option<Location<F>> {
        let loc = *floor;
        if loc >= tip {
            return None;
        }
        let bitmap_len = self.bitmap.len();
        // Within the bitmap: find the next set bit at or after floor.
        // ones_iter_from returns set indices in ascending order so the
        // first result is the only possible candidate below bound.
        // tip >= bitmap_len always holds (base_size ==
        // bitmap_parent.len()), so bound == bitmap_len and the
        // length check inside the iterator prevents scanning past bound.
        if loc < bitmap_len {
            let bound = bitmap_len.min(tip);
            if let Some(idx) = self.bitmap.ones_iter_from(loc).next() {
                if idx < bound {
                    return Some(Location::new(idx));
                }
            }
        }
        // Beyond the bitmap: uncommitted ops from prior batches in the
        // chain that aren't tracked by the bitmap yet. Conservatively
        // treat them as candidates.
        if bitmap_len < tip {
            let candidate = loc.max(bitmap_len);
            if candidate < tip {
                return Some(Location::new(candidate));
            }
        }
        None
    }
}

/// Uncommitted bitmap changes on top of a base bitmap. Records pushed bits and cleared bits
/// without cloning the base. Implements [`BitmapReadable`] for read-through access.
pub struct BitmapDiff<'a, F: Graftable, B: BitmapReadable<N>, const N: usize> {
    /// The parent bitmap this diff is built on top of.
    base: &'a B,
    /// Number of bits in the base bitmap at diff creation time.
    base_len: u64,
    /// New bits appended beyond the base bitmap.
    pushed_bits: Vec<bool>,
    /// Base bits that have been deactivated, plus chunk masks derived from them.
    clears: ClearSet<F, N>,
    /// Chunk indices containing cleared bits that need grafted tree recomputation.
    dirty_chunks: HashSet<usize>,
    /// Number of complete chunks in the base bitmap at diff creation time.
    old_grafted_leaves: usize,
}

impl<'a, F: Graftable, B: BitmapReadable<N>, const N: usize> BitmapDiff<'a, F, B, N> {
    const CHUNK_SIZE_BITS: u64 = BitMap::<N>::CHUNK_SIZE_BITS;

    fn new(base: &'a B, old_grafted_leaves: usize) -> Self {
        Self {
            base_len: base.len(),
            base,
            pushed_bits: Vec::new(),
            clears: ClearSet::default(),
            dirty_chunks: HashSet::new(),
            old_grafted_leaves,
        }
    }

    fn push_bit(&mut self, active: bool) {
        self.pushed_bits.push(active);
    }

    fn clear_bit(&mut self, loc: Location<F>) {
        self.clears.push(loc);
        let chunk = BitMap::<N>::to_chunk_index(*loc);
        if chunk < self.old_grafted_leaves {
            self.dirty_chunks.insert(chunk);
        }
    }

    /// Consume the diff, returning the parts needed for a [`BitmapBatchLayer`].
    fn into_parts(self) -> (u64, Vec<bool>, ClearSet<F, N>) {
        (self.base_len, self.pushed_bits, self.clears)
    }
}

impl<F: Graftable, B: BitmapReadable<N>, const N: usize> BitmapReadable<N>
    for BitmapDiff<'_, F, B, N>
{
    fn complete_chunks(&self) -> usize {
        (self.len() / Self::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        let chunk_start = idx as u64 * Self::CHUNK_SIZE_BITS;

        // Start with base data.
        let base_complete = self.base.complete_chunks();
        let base_has_partial = !self.base_len.is_multiple_of(Self::CHUNK_SIZE_BITS);
        let mut chunk = if idx < base_complete {
            self.base.get_chunk(idx)
        } else if idx == base_complete && base_has_partial {
            self.base.last_chunk().0
        } else {
            [0u8; N]
        };

        apply_push_clear(
            &mut chunk,
            chunk_start,
            self.base_len,
            &self.pushed_bits,
            self.clears.mask(idx),
        );
        chunk
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let total = self.len();
        if total == 0 {
            return ([0u8; N], 0);
        }
        let rem = total % Self::CHUNK_SIZE_BITS;
        let bits_in_last = if rem == 0 { Self::CHUNK_SIZE_BITS } else { rem };
        let last_idx = self.complete_chunks();
        // If chunk-aligned, last complete chunk is at complete_chunks - 1.
        let idx = if rem == 0 {
            last_idx.saturating_sub(1)
        } else {
            last_idx
        };
        (self.get_chunk(idx), bits_in_last)
    }

    fn pruned_chunks(&self) -> usize {
        self.base.pruned_chunks()
    }

    fn len(&self) -> u64 {
        self.base_len + self.pushed_bits.len() as u64
    }
}

/// Adapter that resolves ops tree nodes for a batch's `compute_current_layer`.
///
/// Tries the batch chain's sync [`Readable`] first (which covers nodes appended or overwritten by
/// the batch, plus anything still in the in-memory merkle structure). Falls through to the base's
/// async [`MerkleStorage`].
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

/// A speculative batch of mutations whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Wraps a [`any::batch::UnmerkleizedBatch`] and adds bitmap and grafted tree parent state
/// needed to compute the current layer during [`merkleize`](Self::merkleize).
pub struct UnmerkleizedBatch<F, H, U, const N: usize>
where
    F: Graftable,
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// The inner any-layer batch that handles mutations, journal, and floor raise.
    inner: any::batch::UnmerkleizedBatch<F, H, U>,

    /// Bitmap pushes accumulated by prior batches in the chain.
    base_bitmap_pushes: Vec<Arc<Vec<bool>>>,

    /// Bitmap clears accumulated by prior batches in the chain.
    base_bitmap_clears: Vec<Arc<ClearSet<F, N>>>,

    /// Parent's grafted tree state (owned, Arc-based internally).
    grafted_parent: merkle::batch::MerkleizedBatch<F, H::Digest>,

    /// Parent's bitmap state (COW, Arc-based).
    bitmap_parent: BitmapBatch<F, N>,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
///
/// Wraps an [`any::batch::MerkleizedBatch`] and adds the bitmap and grafted tree state needed
/// to compute the canonical root.
pub struct MerkleizedBatch<F: Graftable, D: Digest, U: update::Update + Send + Sync, const N: usize>
where
    Operation<F, U>: Send + Sync,
{
    /// Inner any-layer batch (ops tree, diff, floor, commit loc, sizes).
    inner: any::batch::MerkleizedBatch<F, D, U>,

    /// Accumulated bitmap pushes from all batches in the chain.
    bitmap_pushes: Vec<Arc<Vec<bool>>>,

    /// Accumulated bitmap clears from all batches in the chain.
    bitmap_clears: Vec<Arc<ClearSet<F, N>>>,

    /// Grafted tree state.
    grafted: merkle::batch::MerkleizedBatch<F, D>,

    /// COW bitmap state (for use as a parent in `BitmapDiff`).
    bitmap: BitmapBatch<F, N>,

    /// The canonical root (ops root + grafted root + partial chunk).
    canonical_root: D,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<F: Graftable, K, D: Digest, Item: Send, const N: usize> {
    /// The inner any-layer changeset.
    pub(super) inner: any::batch::Changeset<F, K, D, Item>,

    /// One bool per operation in the batch chain (pushes applied before clears).
    pub(super) bitmap_pushes: Vec<bool>,

    /// Cleared bitmap locations, plus per-chunk masks cached for fast reapplication.
    pub(super) bitmap_clears: ClearSet<F, N>,

    /// Changeset for the grafted tree.
    pub(super) grafted_changeset: merkle::batch::Changeset<F, D>,

    /// Precomputed canonical root.
    pub(super) canonical_root: D,
}

impl<F, H, U, const N: usize> UnmerkleizedBatch<F, H, U, N>
where
    F: Graftable,
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    pub(super) const fn new(
        inner: any::batch::UnmerkleizedBatch<F, H, U>,
        base_bitmap_pushes: Vec<Arc<Vec<bool>>>,
        base_bitmap_clears: Vec<Arc<ClearSet<F, N>>>,
        grafted_parent: merkle::batch::MerkleizedBatch<F, H::Digest>,
        bitmap_parent: BitmapBatch<F, N>,
    ) -> Self {
        Self {
            inner,
            base_bitmap_pushes,
            base_bitmap_clears,
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
impl<F, K, V, H, const N: usize> UnmerkleizedBatch<F, H, update::Unordered<K, V>, N>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &K,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.inner.get(key, &db.any).await
    }

    /// Resolve mutations into operations, merkleize, and return a
    /// [`MerkleizedBatch`].
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N>,
    ) -> Result<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, N>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let Self {
            inner,
            base_bitmap_pushes,
            base_bitmap_clears,
            grafted_parent,
            bitmap_parent,
        } = self;
        let scan = BitmapScan::new(&bitmap_parent);
        let inner = inner
            .merkleize_with_floor_scan(metadata, scan, &db.any)
            .await?;
        compute_current_layer(
            inner,
            db,
            base_bitmap_pushes,
            base_bitmap_clears,
            &grafted_parent,
            &bitmap_parent,
        )
        .await
    }
}

// Ordered get + merkleize.
impl<F, K, V, H, const N: usize> UnmerkleizedBatch<F, H, update::Ordered<K, V>, N>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &K,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N>,
    ) -> Result<Option<V::Value>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
    {
        self.inner.get(key, &db.any).await
    }

    /// Resolve mutations into operations, merkleize, and return a
    /// [`MerkleizedBatch`].
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N>,
    ) -> Result<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, N>, Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
    {
        let Self {
            inner,
            base_bitmap_pushes,
            base_bitmap_clears,
            grafted_parent,
            bitmap_parent,
        } = self;
        let scan = BitmapScan::new(&bitmap_parent);
        let inner = inner
            .merkleize_with_floor_scan(metadata, scan, &db.any)
            .await?;
        compute_current_layer(
            inner,
            db,
            base_bitmap_pushes,
            base_bitmap_clears,
            &grafted_parent,
            &bitmap_parent,
        )
        .await
    }
}

/// Push one bitmap bit per operation in `segment`. An Update is active only if
/// the merged diff shows it as the final location for its key.
fn push_operation_bits<F, U, B, const N: usize>(
    bitmap: &mut BitmapDiff<'_, F, B, N>,
    segment: &[Operation<F, U>],
    segment_base: u64,
    diff: &BTreeMap<U::Key, DiffEntry<F, U::Value>>,
) where
    F: Graftable,
    U: update::Update,
    B: BitmapReadable<N>,
    Operation<F, U>: Codec,
{
    for (i, op) in segment.iter().enumerate() {
        let op_loc = Location::new(segment_base + i as u64);
        match op {
            Operation::Update(update) => {
                let is_active = diff
                    .get(update.key())
                    .is_some_and(|entry| entry.loc() == Some(op_loc));
                bitmap.push_bit(is_active);
            }
            Operation::CommitFloor(..) => {
                // Active until the next commit supersedes it.
                bitmap.push_bit(true);
            }
            Operation::Delete(..) => {
                bitmap.push_bit(false);
            }
        }
    }
}

/// Clear bits for base-DB operations superseded by this chain's diff.
fn clear_base_old_locs<F, K, V, B, const N: usize>(
    bitmap: &mut BitmapDiff<'_, F, B, N>,
    diff: &BTreeMap<K, DiffEntry<F, V>>,
) where
    F: Graftable,
    K: Ord,
    B: BitmapReadable<N>,
{
    for entry in diff.values() {
        if let Some(old) = entry.base_old_loc() {
            bitmap.clear_bit(old);
        }
    }
}

/// Clear bits for ancestor-segment operations superseded by a later segment.
/// Only relevant for chained batches (chain length > 1).
#[allow(clippy::type_complexity)]
fn clear_ancestor_superseded<F, U, B, const N: usize>(
    bitmap: &mut BitmapDiff<'_, F, B, N>,
    chain: &[std::sync::Arc<Vec<Operation<F, U>>>],
    diff: &BTreeMap<U::Key, DiffEntry<F, U::Value>>,
    db_base: u64,
) where
    F: Graftable,
    U: update::Update,
    B: BitmapReadable<N>,
    Operation<F, U>: Codec,
{
    let mut seg_base = db_base;
    for ancestor_seg in &chain[..chain.len() - 1] {
        for (j, op) in ancestor_seg.iter().enumerate() {
            if let Some(key) = op.key() {
                let ancestor_loc = Location::new(seg_base + j as u64);
                if let Some(entry) = diff.get(key) {
                    if entry.loc() != Some(ancestor_loc) {
                        bitmap.clear_bit(ancestor_loc);
                    }
                }
            }
        }
        seg_base += ancestor_seg.len() as u64;
    }
}

/// Compute the current layer (bitmap + grafted tree + canonical root) on top of a merkleized
/// any batch.
///
/// Creates a `BitmapDiff` and grafted tree batch from the immediate parent's state, and
/// produces the [`MerkleizedBatch`] directly. The ancestor chain's accumulated bitmap
/// pushes/clears are stored alongside the batch so that `finalize()` can concatenate them
/// without recomputation.
async fn compute_current_layer<F, E, U, C, I, H, const N: usize>(
    inner: any::batch::MerkleizedBatch<F, H::Digest, U>,
    current_db: &super::db::Db<F, E, C, I, H, U, N>,
    base_bitmap_pushes: Vec<Arc<Vec<bool>>>,
    base_bitmap_clears: Vec<Arc<ClearSet<F, N>>>,
    grafted_parent: &merkle::batch::MerkleizedBatch<F, H::Digest>,
    bitmap_parent: &BitmapBatch<F, N>,
) -> Result<MerkleizedBatch<F, H::Digest, U, N>, Error<F>>
where
    F: Graftable,
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    let old_grafted_leaves = *grafted_parent.leaves() as usize;
    let mut bitmap = BitmapDiff::new(bitmap_parent, old_grafted_leaves);

    let chain = &inner.journal_batch.items;
    let this_segment = chain.last().expect("operation chain should not be empty");
    let segment_base = *inner.new_last_commit_loc + 1 - this_segment.len() as u64;

    // 1. Inactivate previous commit.
    let prev_commit_loc = Location::new(segment_base - 1);
    bitmap.clear_bit(prev_commit_loc);

    // 2. Push bitmap bits for this segment's operations.
    push_operation_bits(&mut bitmap, this_segment, segment_base, &inner.diff);

    // 3. Clear superseded base-DB operations.
    clear_base_old_locs(&mut bitmap, &inner.diff);

    // 4. Clear ancestor-segment superseded operations (chaining only).
    if chain.len() > 1 {
        clear_ancestor_superseded(
            &mut bitmap,
            chain,
            &inner.diff,
            *current_db.any.last_commit_loc + 1,
        );
    }

    // 5. Compute grafted leaves for dirty + new chunks.
    //    dirty_chunks contains indices < old_grafted_leaves (existing chunks
    //    modified by clears). New chunks are in [old_grafted_leaves, new_grafted_leaves).
    //    These ranges never overlap, so each chunk is processed exactly once.
    let new_grafted_leaves = bitmap.complete_chunks();
    let chunks_to_update = (old_grafted_leaves..new_grafted_leaves)
        .chain(bitmap.dirty_chunks.iter().copied())
        .map(|i| (i, bitmap.get_chunk(i)));
    let ops_tree_adapter =
        BatchStorageAdapter::new(&inner.journal_batch, &current_db.any.log.merkle);
    let hasher = StandardHasher::<H>::new();
    let new_leaves = compute_grafted_leaves::<F, H, N>(
        &hasher,
        &ops_tree_adapter,
        chunks_to_update,
        current_db.thread_pool.as_ref(),
    )
    .await?;

    // 6. Build grafted tree from parent batch (owned, no borrow).
    let grafting_height = grafting::height::<N>();
    let grafted_batch = {
        let mut grafted_batch = grafted_parent
            .new_batch()
            .with_pool(current_db.thread_pool.clone());
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
        grafted_batch.merkleize(&gh)
    };

    // 7. Compute canonical root using the grafted batch directly.
    let ops_root = inner.root();
    let grafted_storage =
        grafting::Storage::new(&grafted_batch, grafting_height, &ops_tree_adapter);
    let partial = partial_chunk(&bitmap);
    let canonical_root =
        compute_db_root::<F, H, _, _, _, N>(&hasher, &bitmap, &grafted_storage, partial, &ops_root)
            .await?;

    // 8. Extract diff data and build COW bitmap layer + push/clear chain.
    let (parent_len, pushed_bits, clears) = bitmap.into_parts();

    let pushed_bits = Arc::new(pushed_bits);
    let clears = Arc::new(clears);

    let mut bitmap_pushes = base_bitmap_pushes;
    bitmap_pushes.push(Arc::clone(&pushed_bits));
    let mut bitmap_clears = base_bitmap_clears;
    bitmap_clears.push(Arc::clone(&clears));

    let bitmap_batch = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
        parent: bitmap_parent.clone(),
        parent_len,
        pushed_bits,
        clears,
    }));

    Ok(MerkleizedBatch {
        inner,
        bitmap_pushes,
        bitmap_clears,
        grafted: grafted_batch,
        bitmap: bitmap_batch,
        canonical_root,
    })
}

/// Immutable bitmap state at any point in a batch chain.
///
/// Mirrors the generic [`crate::merkle::batch::MerkleizedBatch`] pattern.
#[derive(Clone, Debug)]
pub(crate) enum BitmapBatch<F: Graftable, const N: usize> {
    /// Committed bitmap (chain terminal).
    Base(Arc<BitMap<N>>),
    /// Speculative layer on top of a parent batch.
    Layer(Arc<BitmapBatchLayer<F, N>>),
}

/// The data behind a [`BitmapBatch::Layer`].
#[derive(Debug)]
pub(crate) struct BitmapBatchLayer<F: Graftable, const N: usize> {
    parent: BitmapBatch<F, N>,
    /// Cached `parent.len()` at layer creation time.
    parent_len: u64,
    /// New bits appended contiguously from `parent_len`.
    pushed_bits: Arc<Vec<bool>>,
    /// Parent bits that were deactivated, plus chunk masks derived from them.
    clears: Arc<ClearSet<F, N>>,
}

impl<F: Graftable, const N: usize> BitmapBatch<F, N> {
    const CHUNK_SIZE_BITS: u64 = BitMap::<N>::CHUNK_SIZE_BITS;
}

impl<F: Graftable, const N: usize> BitmapReadable<N> for BitmapBatch<F, N> {
    fn complete_chunks(&self) -> usize {
        (self.len() / Self::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        match self {
            Self::Base(bm) => *bm.get_chunk(idx),
            Self::Layer(layer) => {
                let chunk_start = idx as u64 * Self::CHUNK_SIZE_BITS;

                // Start with parent's data, or zeroed if this chunk is
                // entirely beyond the parent's range (created by pushes).
                let parent_chunks = layer.parent_len.div_ceil(Self::CHUNK_SIZE_BITS);
                let mut chunk = if (idx as u64) < parent_chunks {
                    layer.parent.get_chunk(idx)
                } else {
                    [0u8; N]
                };

                apply_push_clear(
                    &mut chunk,
                    chunk_start,
                    layer.parent_len,
                    &layer.pushed_bits,
                    layer.clears.mask(idx),
                );
                chunk
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
        match self {
            Self::Base(bm) => bm.pruned_chunks(),
            Self::Layer(layer) => layer.parent.pruned_chunks(),
        }
    }

    fn len(&self) -> u64 {
        match self {
            Self::Base(bm) => BitmapReadable::<N>::len(bm.as_ref()),
            Self::Layer(layer) => layer.parent_len + layer.pushed_bits.len() as u64,
        }
    }
}

impl<F: Graftable, const N: usize> BitmapBatch<F, N> {
    /// Push a changeset as a new layer on top of this bitmap, mutating `self` in place.
    ///
    /// The old value becomes the parent of the new layer.
    pub(super) fn push_changeset(&mut self, pushed_bits: Vec<bool>, clears: ClearSet<F, N>) {
        if pushed_bits.is_empty() && clears.is_empty() {
            return;
        }
        let parent_len = self.len();
        let parent = self.clone();
        *self = Self::Layer(Arc::new(BitmapBatchLayer {
            parent,
            parent_len,
            pushed_bits: Arc::new(pushed_bits),
            clears: Arc::new(clears),
        }));
    }

    /// Flatten all layers back to a single `Base(Arc<BitMap<N>>)`.
    ///
    /// After flattening, the new `Base` Arc has refcount 1 (assuming no external clones
    /// are held).
    pub(super) fn flatten(&mut self) {
        if matches!(self, Self::Base(_)) {
            return;
        }

        // Take ownership of the chain so that Arc refcounts are not
        // artificially inflated by a clone.
        let mut owned = std::mem::replace(self, Self::Base(Arc::new(BitMap::default())));

        // Collect layers from tip to base.
        let mut layers = Vec::new();
        let base = loop {
            match owned {
                Self::Base(bm) => break bm,
                Self::Layer(layer) => match Arc::try_unwrap(layer) {
                    Ok(inner) => {
                        layers.push((inner.pushed_bits, inner.clears));
                        owned = inner.parent;
                    }
                    Err(arc) => {
                        layers.push((arc.pushed_bits.clone(), arc.clears.clone()));
                        owned = arc.parent.clone();
                    }
                },
            }
        };

        // Replay mutations from base to tip.
        let mut bitmap = Arc::try_unwrap(base).unwrap_or_else(|arc| (*arc).clone());
        for (pushed, clears) in layers.into_iter().rev() {
            for &bit in pushed.iter() {
                bitmap.push(bit);
            }
            for &loc in clears.locations() {
                bitmap.set_bit(*loc, false);
            }
        }
        *self = Self::Base(Arc::new(bitmap));
    }
}

impl<F: Graftable, D: Digest, U: update::Update + Send + Sync, const N: usize>
    MerkleizedBatch<F, D, U, N>
where
    Operation<F, U>: Send + Sync,
{
    /// Return the canonical root.
    pub const fn root(&self) -> D {
        self.canonical_root
    }

    /// Return the ops-only Merkle root.
    pub fn ops_root(&self) -> D {
        self.inner.root()
    }
}

impl<F: Graftable, D: Digest, U: update::Update + Send + Sync, const N: usize>
    MerkleizedBatch<F, D, U, N>
where
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H>(&self) -> UnmerkleizedBatch<F, H, U, N>
    where
        H: Hasher<Digest = D>,
    {
        let pushes = self.bitmap_pushes.clone();
        let clears = self.bitmap_clears.clone();

        UnmerkleizedBatch::new(
            self.inner.new_batch::<H>(),
            pushes,
            clears,
            self.grafted.clone(),
            self.bitmap.clone(),
        )
    }

    /// Read through: diff -> committed DB.
    pub async fn get<E, C, I, H>(
        &self,
        key: &U::Key,
        db: &super::db::Db<F, E, C, I, H, U, N>,
    ) -> Result<Option<U::Value>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher<Digest = D>,
    {
        self.inner.get(key, &db.any).await
    }

    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<F, U::Key, D, Operation<F, U>, N>
    where
        U: 'static,
    {
        // Flatten accumulated bitmap pushes + clears into flat Vecs.
        let total_pushes: usize = self.bitmap_pushes.iter().map(|s| s.len()).sum();
        let mut bitmap_pushes = Vec::with_capacity(total_pushes);
        for seg in &self.bitmap_pushes {
            bitmap_pushes.extend_from_slice(seg);
        }

        let total_clears: usize = self.bitmap_clears.iter().map(|s| s.len()).sum();
        let mut bitmap_clears = ClearSet::with_capacity(total_clears);
        for seg in &self.bitmap_clears {
            bitmap_clears.merge(seg);
        }

        Changeset {
            inner: self.inner.finalize(),
            bitmap_pushes,
            bitmap_clears,
            grafted_changeset: self.grafted.finalize(),
            canonical_root: self.canonical_root,
        }
    }

    /// Like [`Self::finalize`], but produces a [`Changeset`] relative to `current_db_size`
    /// instead of the original DB size when this batch chain was created.
    ///
    /// Use this when an ancestor batch in the chain has already been committed, advancing
    /// the DB's operation count past the original fork point. Skips bitmap pushes/clears
    /// and grafted tree entries from ancestor batches that have already been committed.
    ///
    /// # Panics
    ///
    /// Panics if `current_db_size` is less than the DB size when this batch was created,
    /// or if `items_to_skip` does not align with push segment boundaries.
    pub fn finalize_from(self, current_db_size: u64) -> Changeset<F, U::Key, D, Operation<F, U>, N>
    where
        U: 'static,
    {
        assert!(
            current_db_size >= self.inner.db_size,
            "current_db_size ({current_db_size}) < batch db_size ({})",
            self.inner.db_size
        );
        let items_to_skip = (current_db_size - self.inner.db_size) as usize;

        // Determine how many complete batch segments have been committed.
        // Push segments have one entry per operation, so their cumulative
        // length maps directly to items_to_skip. Committed batches are
        // always committed as whole units, so items_to_skip always aligns
        // with segment boundaries.
        let mut remaining = items_to_skip;
        let mut segments_to_skip = 0;
        for seg in &self.bitmap_pushes {
            if remaining == 0 {
                break;
            }
            assert!(
                remaining >= seg.len(),
                "items_to_skip does not align with push segment boundary"
            );
            remaining -= seg.len();
            segments_to_skip += 1;
        }

        // Flatten uncommitted push segments.
        let mut bitmap_pushes = Vec::new();
        for seg in &self.bitmap_pushes[segments_to_skip..] {
            bitmap_pushes.extend_from_slice(seg);
        }

        // Flatten uncommitted clear segments (1:1 with push segments).
        let mut bitmap_clears = ClearSet::with_capacity(
            self.bitmap_clears[segments_to_skip..]
                .iter()
                .map(|s| s.len())
                .sum(),
        );
        for seg in &self.bitmap_clears[segments_to_skip..] {
            bitmap_clears.merge(seg);
        }

        // The grafted tree base must reflect the current committed bitmap's
        // complete chunk count (after committed ancestors' pushes).
        let committed_complete_chunks = current_db_size / BitmapBatch::<F, N>::CHUNK_SIZE_BITS;
        let grafted_base = Position::<F>::try_from(Location::<F>::new(committed_complete_chunks))
            .expect("valid leaf count");
        let grafted_changeset = self.grafted.finalize_from(grafted_base);

        Changeset {
            inner: self.inner.finalize_from(current_db_size),
            bitmap_pushes,
            bitmap_clears,
            grafted_changeset,
            canonical_root: self.canonical_root,
        }
    }
}

impl<F, E, C, I, H, U, const N: usize> super::db::Db<F, E, C, I, H, U, N>
where
    F: Graftable,
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> MerkleizedBatch<F, H::Digest, U, N> {
        MerkleizedBatch {
            inner: self.any.to_batch(),
            bitmap_pushes: Vec::new(),
            bitmap_clears: Vec::new(),
            grafted: self.grafted_snapshot(),
            bitmap: self.status.clone(),
            canonical_root: self.root,
        }
    }
}

#[cfg(any(test, feature = "test-traits"))]
mod trait_impls {
    use super::*;
    use crate::{
        journal::contiguous::Mutable,
        merkle,
        qmdb::any::traits::{
            BatchableDb, MerkleizedBatch as MerkleizedBatchTrait,
            UnmerkleizedBatch as UnmerkleizedBatchTrait,
        },
        Persistable,
    };
    use std::future::Future;

    type CurrentDb<F, E, C, I, H, U, const N: usize> =
        crate::qmdb::current::db::Db<F, E, C, I, H, U, N>;

    impl<F, K, V, H, E, C, I, const N: usize>
        UnmerkleizedBatchTrait<CurrentDb<F, E, C, I, H, update::Unordered<K, V>, N>>
        for UnmerkleizedBatch<F, H, update::Unordered<K, V>, N>
    where
        F: Graftable,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = merkle::Location<F>> + 'static,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, N>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &CurrentDb<F, E, C, I, H, update::Unordered<K, V>, N>,
        ) -> impl Future<Output = Result<Self::Merkleized, Error<F>>> {
            self.merkleize(metadata, db)
        }
    }

    impl<F, K, V, H, E, C, I, const N: usize>
        UnmerkleizedBatchTrait<CurrentDb<F, E, C, I, H, update::Ordered<K, V>, N>>
        for UnmerkleizedBatch<F, H, update::Ordered<K, V>, N>
    where
        F: Graftable,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: crate::index::Ordered<Value = merkle::Location<F>> + 'static,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, N>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &CurrentDb<F, E, C, I, H, update::Ordered<K, V>, N>,
        ) -> impl Future<Output = Result<Self::Merkleized, Error<F>>> {
            self.merkleize(metadata, db)
        }
    }

    impl<F, D: Digest, U: update::Update + Send + Sync + 'static, const N: usize>
        MerkleizedBatchTrait for MerkleizedBatch<F, D, U, N>
    where
        F: Graftable,
        Operation<F, U>: Codec,
    {
        type Digest = D;
        type Changeset = Changeset<F, U::Key, D, Operation<F, U>, N>;

        fn root(&self) -> D {
            self.root()
        }

        fn finalize(self) -> Self::Changeset {
            self.finalize()
        }
    }

    impl<F, E, K, V, C, I, H, const N: usize> BatchableDb
        for CurrentDb<F, E, C, I, H, update::Unordered<K, V>, N>
    where
        F: Graftable,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = merkle::Location<F>> + 'static,
        H: Hasher,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<F, K, H::Digest, Operation<F, update::Unordered<K, V>>, N>;
        type Batch = UnmerkleizedBatch<F, H, update::Unordered<K, V>, N>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<core::ops::Range<merkle::Location<F>>, Error<F>>> {
            self.apply_batch(batch)
        }
    }

    impl<F, E, K, V, C, I, H, const N: usize> BatchableDb
        for CurrentDb<F, E, C, I, H, update::Ordered<K, V>, N>
    where
        F: Graftable,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: crate::index::Ordered<Value = merkle::Location<F>> + 'static,
        H: Hasher,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<F, K, H::Digest, Operation<F, update::Ordered<K, V>>, N>;
        type Batch = UnmerkleizedBatch<F, H, update::Ordered<K, V>, N>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<core::ops::Range<merkle::Location<F>>, Error<F>>> {
            self.apply_batch(batch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mmr,
        qmdb::any::{
            batch::{FloorScan, SequentialScan},
            operation::{update, Operation},
            value::FixedEncoding,
        },
    };
    use commonware_utils::{bitmap::Prunable as BitMap, sequence::FixedBytes};

    // N=4 -> CHUNK_SIZE_BITS = 32
    const N: usize = 4;
    type Bm = BitMap<N>;

    fn make_bitmap(bits: &[bool]) -> Bm {
        let mut bm = Bm::new();
        for &b in bits {
            bm.push(b);
        }
        bm
    }

    // ---- BitmapDiff tests ----

    #[test]
    fn bitmap_diff_push_only() {
        let base = Bm::new();
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);
        for i in 0..10 {
            diff.push_bit(i % 2 == 0);
        }
        assert_eq!(diff.len(), 10);
        assert_eq!(diff.complete_chunks(), 0);

        let chunk = diff.get_chunk(0);
        // Bits 0,2,4,6,8 set -> 0b_0000_0001_0101_0101 in LE byte order
        // byte 0: bits 0..7 -> 0b0101_0101 = 0x55
        // byte 1: bits 8..9 -> bit 8 set -> 0b0000_0001 = 0x01
        assert_eq!(chunk[0], 0x55);
        assert_eq!(chunk[1], 0x01);
        assert_eq!(chunk[2], 0);
        assert_eq!(chunk[3], 0);
    }

    #[test]
    fn bitmap_diff_clear_on_base() {
        // Base has bits 0..8 all set.
        let base = make_bitmap(&[true; 8]);
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);

        // Clear bit 3.
        diff.clear_bit(Location::new(3));
        let chunk = diff.get_chunk(0);
        // 0xFF with bit 3 cleared -> 0b1111_0111 = 0xF7
        assert_eq!(chunk[0], 0xF7);
    }

    #[test]
    fn bitmap_diff_push_and_clear_same_chunk() {
        // Base has 8 bits set.
        let base = make_bitmap(&[true; 8]);
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);

        // Push 2 more bits (active).
        diff.push_bit(true);
        diff.push_bit(true);
        assert_eq!(diff.len(), 10);

        // Clear base bit 0.
        diff.clear_bit(Location::new(0));
        let chunk = diff.get_chunk(0);
        // Base byte 0: 0xFF -> clear bit 0 -> 0xFE
        // Pushed bits at positions 8,9 -> byte 1: bit 0 and 1 set -> 0x03
        assert_eq!(chunk[0], 0xFE);
        assert_eq!(chunk[1], 0x03);
    }

    #[test]
    fn bitmap_diff_cross_chunk_boundary() {
        // Base has 30 bits (partial first chunk, CHUNK_SIZE_BITS=32).
        let base = make_bitmap(&[true; 30]);
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);

        // Push 5 bits to cross into second chunk (total 35).
        for _ in 0..5 {
            diff.push_bit(true);
        }
        assert_eq!(diff.len(), 35);
        assert_eq!(diff.complete_chunks(), 1);

        // First chunk (32 bits) should be all ones.
        let c0 = diff.get_chunk(0);
        assert_eq!(c0, [0xFF, 0xFF, 0xFF, 0xFF]);

        // Second chunk: 3 bits set (positions 32,33,34).
        let c1 = diff.get_chunk(1);
        assert_eq!(c1[0], 0x07);
        assert_eq!(c1[1], 0);
    }

    #[test]
    fn bitmap_diff_last_chunk_partial() {
        let base = Bm::new();
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);
        // Push 5 bits.
        for _ in 0..5 {
            diff.push_bit(true);
        }
        let (chunk, bits_in_last) = diff.last_chunk();
        assert_eq!(bits_in_last, 5);
        assert_eq!(chunk[0], 0x1F); // lower 5 bits set
    }

    #[test]
    fn bitmap_diff_last_chunk_aligned() {
        let base = Bm::new();
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);
        // Push exactly CHUNK_SIZE_BITS = 32 bits.
        for _ in 0..32 {
            diff.push_bit(true);
        }
        let (chunk, bits_in_last) = diff.last_chunk();
        assert_eq!(bits_in_last, 32);
        assert_eq!(chunk, [0xFF; 4]);
    }

    #[test]
    fn bitmap_diff_dirty_chunks_tracking() {
        // 3 complete chunks = 96 bits.
        let base = make_bitmap(&[true; 96]);
        assert_eq!(base.complete_chunks(), 3);

        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 3);

        // Clear bit in chunk 1 (bit 40 -> chunk 40/32 = 1).
        diff.clear_bit(Location::new(40));
        assert!(diff.dirty_chunks.contains(&1));

        // Push a bit, then clear it. It's beyond old_grafted_leaves, so
        // dirty_chunks should still only contain {1}.
        diff.push_bit(true);
        diff.clear_bit(Location::new(96)); // in the pushed region
        assert_eq!(diff.dirty_chunks.len(), 1);
        assert!(diff.dirty_chunks.contains(&1));
    }

    #[test]
    fn clear_set_merge_empty_into_empty() {
        let mut a = ClearSet::<mmr::Family, N>::default();
        let b = ClearSet::<mmr::Family, N>::default();
        a.merge(&b);
        assert_eq!(a.len(), 0);
        assert!(a.is_empty());
    }

    #[test]
    fn clear_set_merge_non_empty_into_empty() {
        let mut a = ClearSet::<mmr::Family, N>::default();
        let mut b = ClearSet::<mmr::Family, N>::default();
        b.push(Location::new(3));
        b.push(Location::new(7));

        a.merge(&b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.locations(), &[Location::new(3), Location::new(7)]);
        // Both bits in chunk 0.
        let mask = a.mask(0).unwrap();
        assert_eq!(mask[0], (1 << 3) | (1 << 7));
    }

    #[test]
    fn clear_set_merge_empty_into_non_empty() {
        let mut a = ClearSet::<mmr::Family, N>::default();
        a.push(Location::new(5));
        let b = ClearSet::<mmr::Family, N>::default();

        a.merge(&b);
        assert_eq!(a.len(), 1);
        assert_eq!(a.locations(), &[Location::new(5)]);
        let mask = a.mask(0).unwrap();
        assert_eq!(mask[0], 1 << 5);
    }

    #[test]
    fn clear_set_merge_disjoint_chunks() {
        // N=4 -> CHUNK_SIZE_BITS = 32. Bit 2 is in chunk 0, bit 33 is in chunk 1.
        let mut a = ClearSet::<mmr::Family, N>::default();
        a.push(Location::new(2));

        let mut b = ClearSet::<mmr::Family, N>::default();
        b.push(Location::new(33));

        a.merge(&b);
        assert_eq!(a.len(), 2);
        assert_eq!(a.locations(), &[Location::new(2), Location::new(33)]);
        // Chunk 0: only bit 2.
        let m0 = a.mask(0).unwrap();
        assert_eq!(m0[0], 1 << 2);
        // Chunk 1: bit 33 -> relative bit 1 -> byte 0, bit 1.
        let m1 = a.mask(1).unwrap();
        assert_eq!(m1[0], 1 << 1);
    }

    #[test]
    fn clear_set_merge_overlapping_chunk() {
        // Both sets clear bits in the same chunk; masks must be OR'd.
        let mut a = ClearSet::<mmr::Family, N>::default();
        a.push(Location::new(1));
        a.push(Location::new(4));

        let mut b = ClearSet::<mmr::Family, N>::default();
        b.push(Location::new(4)); // duplicate with a
        b.push(Location::new(6));

        a.merge(&b);
        assert_eq!(a.len(), 4);
        let mask = a.mask(0).unwrap();
        // bits 1, 4, 6 (4 appears in both but OR is idempotent for mask)
        assert_eq!(mask[0], (1 << 1) | (1 << 4) | (1 << 6));
    }

    #[test]
    fn clear_set_merge_matches_sequential_push() {
        // Verify merge produces the same masks as pushing each location individually.
        let locs_a: Vec<mmr::Location> = (0..5).map(Location::new).collect();
        let locs_b: Vec<mmr::Location> = (30..36).map(Location::new).collect(); // spans chunks 0 and 1

        // Build via merge.
        let mut via_merge = ClearSet::<mmr::Family, N>::default();
        let mut part_a = ClearSet::<mmr::Family, N>::default();
        for &loc in &locs_a {
            part_a.push(loc);
        }
        let mut part_b = ClearSet::<mmr::Family, N>::default();
        for &loc in &locs_b {
            part_b.push(loc);
        }
        via_merge.merge(&part_a);
        via_merge.merge(&part_b);

        // Build via sequential push.
        let mut via_push = ClearSet::<mmr::Family, N>::default();
        for &loc in locs_a.iter().chain(&locs_b) {
            via_push.push(loc);
        }

        assert_eq!(via_merge.locations(), via_push.locations());
        for idx in 0..2 {
            assert_eq!(via_merge.mask(idx), via_push.mask(idx));
        }
    }

    #[test]
    fn bitmap_diff_clear_set_tracks_chunk_bits() {
        let base = make_bitmap(&[true; 96]);
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 3);

        diff.clear_bit(Location::new(3));
        diff.clear_bit(Location::new(40));
        diff.clear_bit(Location::new(63));

        assert_eq!(diff.clears.mask(0).unwrap()[0], 1 << 3);
        assert_eq!(diff.clears.mask(1).unwrap()[1], 0x01);
        assert_eq!(diff.clears.mask(1).unwrap()[3], 0x80);
    }

    #[test]
    fn bitmap_batch_push_changeset_preserves_clear_set() {
        let mut batch: BitmapBatch<mmr::Family, N> =
            BitmapBatch::Base(Arc::new(make_bitmap(&[true; 64])));
        let mut clears: ClearSet<mmr::Family, N> = ClearSet::default();
        clears.push(Location::new(3));
        clears.push(Location::new(40));
        batch.push_changeset(Vec::new(), clears);

        let BitmapBatch::Layer(layer) = &batch else {
            panic!("expected layer");
        };
        assert_eq!(layer.clears.mask(0).unwrap()[0], 1 << 3);
        assert_eq!(layer.clears.mask(1).unwrap()[1], 0x01);

        let chunk0 = batch.get_chunk(0);
        let chunk1 = batch.get_chunk(1);
        assert_eq!(chunk0[0] & (1 << 3), 0);
        assert_eq!(chunk1[1] & 0x01, 0);
    }

    // ---- push_operation_bits test ----

    #[test]
    fn push_operation_bits_mixed() {
        type K = FixedBytes<4>;
        type V = FixedEncoding<u64>;
        type U = update::Unordered<K, V>;
        type Op = Operation<mmr::Family, U>;

        let key1 = FixedBytes::from([1, 0, 0, 0]);
        let key2 = FixedBytes::from([2, 0, 0, 0]);
        let key3 = FixedBytes::from([3, 0, 0, 0]);

        // Segment: Update(key1), Update(key2), Delete(key3), CommitFloor
        let segment: Vec<Op> = vec![
            Op::Update(update::Unordered(key1.clone(), 100u64)),
            Op::Update(update::Unordered(key2.clone(), 200u64)),
            Op::Delete(key3),
            Op::CommitFloor(None, Location::new(99)),
        ];

        // Diff: key1 active at loc=0, key2 superseded (active at loc=99, not loc=1).
        let mut diff = BTreeMap::new();
        diff.insert(
            key1,
            DiffEntry::Active {
                value: 100u64,
                loc: Location::new(0),
                base_old_loc: None,
            },
        );
        diff.insert(
            key2,
            DiffEntry::Active {
                value: 200u64,
                loc: Location::new(99), // not loc=1, so superseded
                base_old_loc: None,
            },
        );

        let base = Bm::new();
        let mut bitmap = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);
        push_operation_bits::<mmr::Family, U, Bm, N>(&mut bitmap, &segment, 0, &diff);

        // Expected: [true(key1 active), false(key2 superseded), false(delete), true(commit)]
        assert_eq!(bitmap.pushed_bits, [true, false, false, true]);
    }

    // ---- clear_base_old_locs test ----

    #[test]
    fn clear_base_old_locs_mixed() {
        type K = u64;

        // Base bitmap with 64 bits.
        let base = make_bitmap(&[true; 64]);
        let mut bitmap = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 2);

        let mut diff: BTreeMap<K, DiffEntry<mmr::Family, u64>> = BTreeMap::new();

        // key1: Active with base_old_loc = Some(5) -> should clear bit 5.
        diff.insert(
            1,
            DiffEntry::Active {
                value: 100,
                loc: Location::new(70),
                base_old_loc: Some(Location::new(5)),
            },
        );

        // key2: Deleted with base_old_loc = Some(10) -> should clear bit 10.
        diff.insert(
            2,
            DiffEntry::Deleted {
                base_old_loc: Some(Location::new(10)),
            },
        );

        // key3: Active with base_old_loc = None -> no clear.
        diff.insert(
            3,
            DiffEntry::Active {
                value: 300,
                loc: Location::new(71),
                base_old_loc: None,
            },
        );

        clear_base_old_locs::<mmr::Family, K, u64, Bm, N>(&mut bitmap, &diff);

        assert_eq!(bitmap.clears.len(), 2);

        // Verify bits 5 and 10 are cleared.
        let c0 = bitmap.get_chunk(0);
        assert_eq!(c0[0] & (1 << 5), 0); // bit 5 cleared
        assert_eq!(c0[1] & (1 << 2), 0); // bit 10 = byte 1, bit 2 cleared

        // Other bits should still be set.
        assert_eq!(c0[0] & (1 << 4), 1 << 4); // bit 4 still set
        assert_eq!(c0[1] & (1 << 3), 1 << 3); // bit 11 still set
    }

    // ---- FloorScan tests ----

    #[test]
    fn sequential_scan_returns_floor_when_below_tip() {
        let mut scan = SequentialScan;
        assert_eq!(
            scan.next_candidate(mmr::Location::new(5), 10),
            Some(mmr::Location::new(5))
        );
    }

    #[test]
    fn sequential_scan_returns_none_at_tip() {
        let mut scan = SequentialScan;
        assert_eq!(scan.next_candidate(mmr::Location::new(10), 10), None);
        assert_eq!(scan.next_candidate(mmr::Location::new(11), 10), None);
    }

    #[test]
    fn bitmap_scan_all_active() {
        let bm = make_bitmap(&[true; 8]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);
        for i in 0..8 {
            assert_eq!(
                scan.next_candidate(mmr::Location::new(i), 8),
                Some(mmr::Location::new(i))
            );
        }
        assert_eq!(scan.next_candidate(mmr::Location::new(8), 8), None);
    }

    #[test]
    fn bitmap_scan_all_inactive() {
        let bm = make_bitmap(&[false; 8]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);
        assert_eq!(scan.next_candidate(mmr::Location::new(0), 8), None);
    }

    #[test]
    fn bitmap_scan_skips_inactive() {
        // Pattern: inactive, inactive, active, inactive, active
        let bm = make_bitmap(&[false, false, true, false, true]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);

        assert_eq!(
            scan.next_candidate(mmr::Location::new(0), 5),
            Some(mmr::Location::new(2))
        );
        assert_eq!(
            scan.next_candidate(mmr::Location::new(3), 5),
            Some(mmr::Location::new(4))
        );
        assert_eq!(scan.next_candidate(mmr::Location::new(5), 5), None);
    }

    #[test]
    fn bitmap_scan_beyond_bitmap_len_returns_candidate() {
        // Bitmap has 4 bits, but tip is 8. Locations 4..8 are beyond the
        // bitmap and should be returned as candidates.
        let bm = make_bitmap(&[false; 4]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);

        // All bitmap bits are unset, so 0..4 are skipped.
        // Location 4 is beyond bitmap -> candidate.
        assert_eq!(
            scan.next_candidate(mmr::Location::new(0), 8),
            Some(mmr::Location::new(4))
        );
        assert_eq!(
            scan.next_candidate(mmr::Location::new(6), 8),
            Some(mmr::Location::new(6))
        );
    }

    #[test]
    fn bitmap_scan_respects_tip() {
        let bm = make_bitmap(&[false, false, false, true]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);

        // Active bit at 3, but tip is 3 so it's excluded.
        assert_eq!(scan.next_candidate(mmr::Location::new(0), 3), None);
        // With tip=4, bit 3 is included.
        assert_eq!(
            scan.next_candidate(mmr::Location::new(0), 4),
            Some(mmr::Location::new(3))
        );
    }

    #[test]
    fn bitmap_scan_floor_at_tip() {
        let bm = make_bitmap(&[true; 4]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);
        assert_eq!(scan.next_candidate(mmr::Location::new(4), 4), None);
    }

    #[test]
    fn bitmap_scan_empty_bitmap() {
        let bm = Bm::new();
        let mut scan = BitmapScan::<Bm, N>::new(&bm);

        // Empty bitmap, but tip > 0: all locations are beyond bitmap.
        assert_eq!(
            scan.next_candidate(mmr::Location::new(0), 5),
            Some(mmr::Location::new(0))
        );
        // Empty bitmap, tip = 0: no candidates.
        assert_eq!(scan.next_candidate(mmr::Location::new(0), 0), None);
    }

    #[test]
    fn bitmap_scan_with_bitmap_diff() {
        // Base: bits 0..8 all active.
        let base = make_bitmap(&[true; 8]);
        let mut diff = BitmapDiff::<mmr::Family, Bm, N>::new(&base, 0);

        // Clear bits 2 and 5.
        diff.clear_bit(mmr::Location::new(2));
        diff.clear_bit(mmr::Location::new(5));

        // Push two inactive bits and one active bit beyond the base.
        diff.push_bit(false);
        diff.push_bit(false);
        diff.push_bit(true);

        let mut scan = BitmapScan::<BitmapDiff<'_, mmr::Family, Bm, N>, N>::new(&diff);

        // Should skip bit 2 (cleared), return 0.
        assert_eq!(
            scan.next_candidate(mmr::Location::new(0), 11),
            Some(mmr::Location::new(0))
        );
        // From 2: skip cleared bit 2, return 3.
        assert_eq!(
            scan.next_candidate(mmr::Location::new(2), 11),
            Some(mmr::Location::new(3))
        );
        // From 5: skip cleared bit 5, return 6.
        assert_eq!(
            scan.next_candidate(mmr::Location::new(5), 11),
            Some(mmr::Location::new(6))
        );
        // From 8: skip pushed inactive 8,9, return active pushed 10.
        assert_eq!(
            scan.next_candidate(mmr::Location::new(8), 11),
            Some(mmr::Location::new(10))
        );
    }
}
