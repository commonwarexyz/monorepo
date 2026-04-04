//! Batch mutation API for Current QMDBs.
//!
//! Wraps the [`any::batch`] API.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    merkle::{
        mmr::{self, Location, Position, Readable, StandardHasher},
        storage::Storage as MerkleStorage,
    },
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
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

type Error = crate::qmdb::Error<mmr::Family>;

/// Cleared bitmap bits tracked in two synchronized views.
///
/// `locations` preserves the original clear operations so batch chaining, flattening, and
/// finalization can replay them in order. `masks` indexes the same clears by chunk, allowing
/// [`apply_push_clear`] to zero an entire chunk without rescanning every cleared location.
#[derive(Clone, Debug, Default)]
pub(super) struct ClearSet<const N: usize> {
    locations: Vec<Location>,

    /// Chunk masks used for fast block-clearing operations. A HashMap is safe to use here because
    /// it is exclusively accessed via direct point lookups (`.get()`) in production code, avoiding
    /// any iteration-order non-determinism during Merkleization.
    masks: HashMap<usize, [u8; N]>,
}

impl<const N: usize> ClearSet<N> {
    /// Push a location to the clear set.
    pub(super) fn push(&mut self, loc: Location) {
        self.locations.push(loc);

        let chunk_idx = BitMap::<N>::to_chunk_index(*loc);
        let rel = (*loc % BitMap::<N>::CHUNK_SIZE_BITS) as usize;
        let chunk = self.masks.entry(chunk_idx).or_insert([0u8; N]);
        chunk[rel / 8] |= 1 << (rel % 8);
    }

    const fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    #[cfg(test)]
    fn merge(&mut self, other: &Self) {
        self.locations.extend_from_slice(&other.locations);
        for (&idx, other_mask) in &other.masks {
            let chunk = self.masks.entry(idx).or_insert([0u8; N]);
            for (byte, &m) in chunk.iter_mut().zip(other_mask) {
                *byte |= m;
            }
        }
    }

    #[cfg(test)]
    const fn len(&self) -> usize {
        self.locations.len()
    }

    /// Return the locations in the clear set.
    fn locations(&self) -> &[Location] {
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

impl<B: BitmapReadable<N>, const N: usize> FloorScan<mmr::Family> for BitmapScan<'_, B, N> {
    fn next_candidate(&mut self, floor: Location, tip: u64) -> Option<Location> {
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
pub struct BitmapDiff<'a, B: BitmapReadable<N>, const N: usize> {
    /// The parent bitmap this diff is built on top of.
    base: &'a B,
    /// Number of bits in the base bitmap at diff creation time.
    base_len: u64,
    /// New bits appended beyond the base bitmap.
    pushed_bits: Vec<bool>,
    /// Base bits that have been deactivated, plus chunk masks derived from them.
    clears: ClearSet<N>,
    /// Chunk indices containing cleared bits that need grafted MMR recomputation.
    dirty_chunks: HashSet<usize>,
    /// Number of complete chunks in the base bitmap at diff creation time.
    old_grafted_leaves: usize,
}

impl<'a, B: BitmapReadable<N>, const N: usize> BitmapDiff<'a, B, N> {
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

    fn clear_bit(&mut self, loc: Location) {
        self.clears.push(loc);
        let chunk = BitMap::<N>::to_chunk_index(*loc);
        if chunk < self.old_grafted_leaves {
            self.dirty_chunks.insert(chunk);
        }
    }

    /// Consume the diff, returning the parts needed for a [`BitmapBatchLayer`].
    fn into_parts(self) -> (u64, Vec<bool>, ClearSet<N>) {
        (self.base_len, self.pushed_bits, self.clears)
    }
}

impl<B: BitmapReadable<N>, const N: usize> BitmapReadable<N> for BitmapDiff<'_, B, N> {
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

/// Adapter that resolves ops MMR nodes for a batch's `compute_current_layer`.
///
/// Tries the batch chain's sync [`Readable`] first (which covers nodes appended or overwritten
/// by the batch, plus anything still in the in-memory MMR). Falls through to the base's async
/// [`MerkleStorage`].
struct BatchStorageAdapter<
    'a,
    D: Digest,
    R: Readable<Family = mmr::Family, Digest = D, Error = mmr::Error>,
    S: MerkleStorage<mmr::Family, Digest = D>,
> {
    batch: &'a R,
    base: &'a S,
    _phantom: core::marker::PhantomData<D>,
}

impl<
        'a,
        D: Digest,
        R: Readable<Family = mmr::Family, Digest = D, Error = mmr::Error>,
        S: MerkleStorage<mmr::Family, Digest = D>,
    > BatchStorageAdapter<'a, D, R, S>
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
        D: Digest,
        R: Readable<Family = mmr::Family, Digest = D, Error = mmr::Error>,
        S: MerkleStorage<mmr::Family, Digest = D>,
    > MerkleStorage<mmr::Family> for BatchStorageAdapter<'_, D, R, S>
{
    type Digest = D;

    async fn size(&self) -> Position {
        self.batch.size()
    }
    async fn get_node(&self, pos: Position) -> Result<Option<D>, mmr::Error> {
        if let Some(node) = self.batch.get_node(pos) {
            return Ok(Some(node));
        }
        self.base.get_node(pos).await
    }
}

/// A speculative batch of mutations whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Wraps a [`any::batch::UnmerkleizedBatch`] and adds bitmap and grafted MMR parent state
/// needed to compute the current layer during [`merkleize`](Self::merkleize).
pub struct UnmerkleizedBatch<H, U, const N: usize>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    /// The inner any-layer batch that handles mutations, journal, and floor raise.
    inner: any::batch::UnmerkleizedBatch<mmr::Family, H, U>,

    /// Parent's grafted MMR state (owned, Arc-based internally).
    grafted_parent: mmr::batch::MerkleizedBatch<H::Digest>,

    /// Parent's bitmap state (COW, Arc-based).
    bitmap_parent: BitmapBatch<N>,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
///
/// Wraps an [`any::batch::MerkleizedBatch`] and adds the bitmap and grafted MMR state needed
/// to compute the canonical root.
pub struct MerkleizedBatch<D: Digest, U: update::Update + Send + Sync, const N: usize>
where
    Operation<mmr::Family, U>: Send + Sync,
{
    /// Inner any-layer batch (ops MMR, diff, floor, commit loc, sizes).
    inner: any::batch::MerkleizedBatch<mmr::Family, D, U>,

    /// Grafted MMR state.
    grafted: mmr::batch::MerkleizedBatch<D>,

    /// COW bitmap state (for use as a parent in `BitmapDiff`).
    bitmap: BitmapBatch<N>,

    /// The canonical root (ops root + grafted root + partial chunk).
    canonical_root: D,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<K, D: Digest, Item: Send, const N: usize> {
    /// The inner any-layer changeset.
    pub(super) inner: any::batch::Changeset<mmr::Family, K, D, Item>,

    /// Changeset for the grafted MMR.
    pub(super) grafted_changeset: mmr::Changeset<D>,

    /// Precomputed canonical root.
    pub(super) canonical_root: D,
}

impl<H, U, const N: usize> UnmerkleizedBatch<H, U, N>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    pub(super) const fn new(
        inner: any::batch::UnmerkleizedBatch<mmr::Family, H, U>,
        grafted_parent: mmr::batch::MerkleizedBatch<H::Digest>,
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
impl<K, V, H, const N: usize> UnmerkleizedBatch<H, update::Unordered<K, V>, N>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<mmr::Family, update::Unordered<K, V>>: Codec,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &K,
        db: &super::db::Db<E, C, I, H, update::Unordered<K, V>, N>,
    ) -> Result<Option<V::Value>, Error>
    where
        E: Context,
        C: Mutable<Item = Operation<mmr::Family, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location> + 'static,
    {
        self.inner.get(key, &db.any).await
    }

    /// Resolve mutations into operations, merkleize, and return a
    /// [`MerkleizedBatch`].
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &super::db::Db<E, C, I, H, update::Unordered<K, V>, N>,
    ) -> Result<MerkleizedBatch<H::Digest, update::Unordered<K, V>, N>, Error>
    where
        E: Context,
        C: Mutable<Item = Operation<mmr::Family, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location> + 'static,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        let scan = BitmapScan::new(&bitmap_parent);
        let inner = inner
            .merkleize_with_floor_scan(metadata, scan, &db.any)
            .await?;
        compute_current_layer(inner, db, &grafted_parent, &bitmap_parent).await
    }
}

// Ordered get + merkleize.
impl<K, V, H, const N: usize> UnmerkleizedBatch<H, update::Ordered<K, V>, N>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<mmr::Family, update::Ordered<K, V>>: Codec,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &K,
        db: &super::db::Db<E, C, I, H, update::Ordered<K, V>, N>,
    ) -> Result<Option<V::Value>, Error>
    where
        E: Context,
        C: Mutable<Item = Operation<mmr::Family, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location> + 'static,
    {
        self.inner.get(key, &db.any).await
    }

    /// Resolve mutations into operations, merkleize, and return a
    /// [`MerkleizedBatch`].
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &super::db::Db<E, C, I, H, update::Ordered<K, V>, N>,
    ) -> Result<MerkleizedBatch<H::Digest, update::Ordered<K, V>, N>, Error>
    where
        E: Context,
        C: Mutable<Item = Operation<mmr::Family, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location> + 'static,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        let scan = BitmapScan::new(&bitmap_parent);
        let inner = inner
            .merkleize_with_floor_scan(metadata, scan, &db.any)
            .await?;
        compute_current_layer(inner, db, &grafted_parent, &bitmap_parent).await
    }
}

/// Push one bitmap bit per operation in `segment`. An Update is active only if
/// the merged diff shows it as the final location for its key.
fn push_operation_bits<U, B, const N: usize>(
    bitmap: &mut BitmapDiff<'_, B, N>,
    segment: &[Operation<mmr::Family, U>],
    segment_base: u64,
    diff: &BTreeMap<U::Key, DiffEntry<mmr::Family, U::Value>>,
) where
    U: update::Update,
    B: BitmapReadable<N>,
    Operation<mmr::Family, U>: Codec,
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
fn clear_base_old_locs<K, V, B, const N: usize>(
    bitmap: &mut BitmapDiff<'_, B, N>,
    diff: &BTreeMap<K, DiffEntry<mmr::Family, V>>,
) where
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
fn clear_ancestor_superseded<U, B, const N: usize>(
    bitmap: &mut BitmapDiff<'_, B, N>,
    chain: &[std::sync::Arc<Vec<Operation<mmr::Family, U>>>],
    diff: &BTreeMap<U::Key, DiffEntry<mmr::Family, U::Value>>,
    db_base: u64,
) where
    U: update::Update,
    B: BitmapReadable<N>,
    Operation<mmr::Family, U>: Codec,
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

/// Compute the current layer (bitmap + grafted MMR + canonical root) on top of a merkleized
/// any batch.
///
/// Creates a `BitmapDiff` and grafted MMR batch from the immediate parent's state, and
/// produces the [`MerkleizedBatch`] directly.
async fn compute_current_layer<E, U, C, I, H, const N: usize>(
    inner: any::batch::MerkleizedBatch<mmr::Family, H::Digest, U>,
    current_db: &super::db::Db<E, C, I, H, U, N>,
    grafted_parent: &mmr::batch::MerkleizedBatch<H::Digest>,
    bitmap_parent: &BitmapBatch<N>,
) -> Result<MerkleizedBatch<H::Digest, U, N>, Error>
where
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    let old_grafted_leaves = *grafted_parent.leaves() as usize;
    let mut bitmap = BitmapDiff::new(bitmap_parent, old_grafted_leaves);

    let chain = &inner.journal_batch.items;
    let this_segment = chain.last().expect("operation chain should not be empty");
    let segment_base = *inner.new_last_commit_loc + 1 - this_segment.len() as u64;
    bitmap.pushed_bits.reserve(this_segment.len());

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
    let ops_mmr_adapter =
        BatchStorageAdapter::new(&inner.journal_batch, &current_db.any.log.merkle);
    let hasher = StandardHasher::<H>::new();
    let new_leaves = compute_grafted_leaves::<H, N>(
        &hasher,
        &ops_mmr_adapter,
        chunks_to_update,
        current_db.thread_pool.as_ref(),
    )
    .await?;

    // 6. Build grafted MMR from parent batch (owned, no borrow).
    let grafting_height = grafting::height::<N>();
    let grafted_batch = {
        let mut grafted_batch = grafted_parent
            .new_batch()
            .with_pool(current_db.thread_pool.clone());
        for &(ops_pos, digest) in &new_leaves {
            let grafted_pos = grafting::ops_to_grafted_pos(ops_pos, grafting_height);
            if grafted_pos < grafted_batch.size() {
                let loc = Location::try_from(grafted_pos).expect("grafted_pos overflow");
                grafted_batch = grafted_batch
                    .update_leaf_digest(loc, digest)
                    .expect("update_leaf_digest failed");
            } else {
                grafted_batch = grafted_batch.add_leaf_digest(digest);
            }
        }
        let gh = grafting::GraftedHasher::new(hasher.clone(), grafting_height);
        grafted_batch.merkleize(&gh)
    };

    // 7. Compute canonical root using the grafted batch directly.
    let ops_root = inner.root();
    let grafted_storage = grafting::Storage::new(&grafted_batch, grafting_height, &ops_mmr_adapter);
    let partial = partial_chunk(&bitmap);
    let canonical_root =
        compute_db_root::<H, _, _, N>(&hasher, &grafted_storage, partial, &ops_root).await?;

    // 8. Extract diff data and build COW bitmap layer.
    let (parent_len, pushed_bits, clears) = bitmap.into_parts();

    let bitmap_batch = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
        parent: bitmap_parent.clone(),
        parent_len,
        pushed_bits: Arc::new(pushed_bits),
        clears: Arc::new(clears),
    }));

    Ok(MerkleizedBatch {
        inner,
        grafted: grafted_batch,
        bitmap: bitmap_batch,
        canonical_root,
    })
}

/// Immutable bitmap state at any point in a batch chain.
///
/// Mirrors the [`crate::mmr::batch::MerkleizedBatch`] pattern.
#[derive(Clone, Debug)]
pub(crate) enum BitmapBatch<const N: usize> {
    /// Committed bitmap (chain terminal).
    Base(Arc<BitMap<N>>),
    /// Speculative layer on top of a parent batch.
    Layer(Arc<BitmapBatchLayer<N>>),
}

/// The data behind a [`BitmapBatch::Layer`].
#[derive(Debug)]
pub(crate) struct BitmapBatchLayer<const N: usize> {
    parent: BitmapBatch<N>,
    /// Cached `parent.len()` at layer creation time.
    parent_len: u64,
    /// New bits appended contiguously from `parent_len`.
    pushed_bits: Arc<Vec<bool>>,
    /// Parent bits that were deactivated, plus chunk masks derived from them.
    clears: Arc<ClearSet<N>>,
}

impl<const N: usize> BitmapBatch<N> {
    const CHUNK_SIZE_BITS: u64 = BitMap::<N>::CHUNK_SIZE_BITS;
}

impl<const N: usize> BitmapReadable<N> for BitmapBatch<N> {
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

impl<const N: usize> BitmapBatch<N> {
    /// Push a changeset on top of this bitmap, mutating `self` in place.
    ///
    /// When the bitmap is a `Base` with no outstanding clones (typical for
    /// sequential commit patterns), mutations are applied directly in place,
    /// keeping the bitmap flat and `get_chunk` O(1). Otherwise a new `Layer`
    /// is created. `pushed_bits[i]` corresponds to the operation at
    /// `parent_len + i` in the new committed range.
    pub(super) fn push_changeset(&mut self, pushed_bits: Vec<bool>, clears: ClearSet<N>) {
        if pushed_bits.is_empty() && clears.is_empty() {
            return;
        }
        if self.try_apply_changeset_in_place(&pushed_bits, &clears) {
            return;
        }
        self.push_changeset_as_layer(pushed_bits, clears);
    }

    /// Fast path: mutate the committed bitmap directly when we have the only
    /// reference to the Base allocation.
    fn try_apply_changeset_in_place(&mut self, pushed_bits: &[bool], clears: &ClearSet<N>) -> bool {
        let Self::Base(base) = self else {
            return false;
        };
        let Some(bitmap) = Arc::get_mut(base) else {
            return false;
        };
        for &bit in pushed_bits {
            bitmap.push(bit);
        }
        for loc in clears.locations() {
            bitmap.set_bit(**loc, false);
        }
        true
    }

    /// Slow path: retain the parent bitmap and append a new COW layer.
    fn push_changeset_as_layer(&mut self, pushed_bits: Vec<bool>, clears: ClearSet<N>) {
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

impl<D: Digest, U: update::Update + Send + Sync, const N: usize> MerkleizedBatch<D, U, N>
where
    Operation<mmr::Family, U>: Send + Sync,
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

impl<D: Digest, U: update::Update + Send + Sync, const N: usize> MerkleizedBatch<D, U, N>
where
    Operation<mmr::Family, U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H>(&self) -> UnmerkleizedBatch<H, U, N>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch::new(
            self.inner.new_batch::<H>(),
            self.grafted.clone(),
            self.bitmap.clone(),
        )
    }

    /// Read through: diff -> committed DB.
    pub async fn get<E, C, I, H>(
        &self,
        key: &U::Key,
        db: &super::db::Db<E, C, I, H, U, N>,
    ) -> Result<Option<U::Value>, Error>
    where
        E: Context,
        C: Contiguous<Item = Operation<mmr::Family, U>>,
        I: UnorderedIndex<Value = Location> + 'static,
        H: Hasher<Digest = D>,
    {
        self.inner.get(key, &db.any).await
    }

    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<U::Key, D, Operation<mmr::Family, U>, N>
    where
        U: 'static,
    {
        Changeset {
            inner: self.inner.finalize(),
            grafted_changeset: self.grafted.finalize(),
            canonical_root: self.canonical_root,
        }
    }

    /// Like [`Self::finalize`], but produces a [`Changeset`] relative to `current_db_size`
    /// instead of the original DB size when this batch chain was created.
    ///
    /// Use this when an ancestor batch in the chain has already been committed, advancing
    /// the DB's operation count past the original fork point. Skips grafted MMR entries
    /// from ancestor batches that have already been committed.
    ///
    /// # Panics
    ///
    /// Panics if `current_db_size` is less than the DB size when this batch was created.
    pub fn finalize_from(
        self,
        current_db_size: u64,
    ) -> Changeset<U::Key, D, Operation<mmr::Family, U>, N>
    where
        U: 'static,
    {
        assert!(
            current_db_size >= self.inner.db_size,
            "current_db_size ({current_db_size}) < batch db_size ({})",
            self.inner.db_size
        );

        // The grafted MMR base must reflect the current committed bitmap's
        // complete chunk count (after committed ancestors' pushes).
        let committed_complete_chunks = current_db_size / BitmapBatch::<N>::CHUNK_SIZE_BITS;
        let grafted_base =
            Position::try_from(Location::new(committed_complete_chunks)).expect("valid leaf count");
        let grafted_changeset = self.grafted.finalize_from(grafted_base);

        Changeset {
            // Bitmap rebasing happens later in current::Db::apply_batch(),
            // derived from the rebased inner snapshot diffs.
            inner: self.inner.finalize_from(current_db_size),
            grafted_changeset,
            canonical_root: self.canonical_root,
        }
    }
}

impl<E, C, I, H, U, const N: usize> super::db::Db<E, C, I, H, U, N>
where
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    pub fn to_batch(&self) -> MerkleizedBatch<H::Digest, U, N> {
        MerkleizedBatch {
            inner: self.any.to_batch(),
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
        qmdb::any::traits::{
            BatchableDb, MerkleizedBatch as MerkleizedBatchTrait,
            UnmerkleizedBatch as UnmerkleizedBatchTrait,
        },
        Persistable,
    };
    use std::future::Future;

    type CurrentDb<E, C, I, H, U, const N: usize> = crate::qmdb::current::db::Db<E, C, I, H, U, N>;

    impl<K, V, H, E, C, I, const N: usize>
        UnmerkleizedBatchTrait<CurrentDb<E, C, I, H, update::Unordered<K, V>, N>>
        for UnmerkleizedBatch<H, update::Unordered<K, V>, N>
    where
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<mmr::Family, update::Unordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location> + 'static,
        Operation<mmr::Family, update::Unordered<K, V>>: Codec,
    {
        type Family = mmr::Family;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<H::Digest, update::Unordered<K, V>, N>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &CurrentDb<E, C, I, H, update::Unordered<K, V>, N>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<mmr::Family>>>
        {
            self.merkleize(metadata, db)
        }
    }

    impl<K, V, H, E, C, I, const N: usize>
        UnmerkleizedBatchTrait<CurrentDb<E, C, I, H, update::Ordered<K, V>, N>>
        for UnmerkleizedBatch<H, update::Ordered<K, V>, N>
    where
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<mmr::Family, update::Ordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: crate::index::Ordered<Value = Location> + 'static,
        Operation<mmr::Family, update::Ordered<K, V>>: Codec,
    {
        type Family = mmr::Family;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<H::Digest, update::Ordered<K, V>, N>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &CurrentDb<E, C, I, H, update::Ordered<K, V>, N>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<mmr::Family>>>
        {
            self.merkleize(metadata, db)
        }
    }

    impl<D: Digest, U: update::Update + Send + Sync + 'static, const N: usize> MerkleizedBatchTrait
        for MerkleizedBatch<D, U, N>
    where
        Operation<mmr::Family, U>: Codec,
    {
        type Digest = D;
        type Changeset = Changeset<U::Key, D, Operation<mmr::Family, U>, N>;

        fn root(&self) -> D {
            self.root()
        }

        fn finalize(self) -> Self::Changeset {
            self.finalize()
        }
    }

    impl<E, K, V, C, I, H, const N: usize> BatchableDb
        for CurrentDb<E, C, I, H, update::Unordered<K, V>, N>
    where
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<mmr::Family, update::Unordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location> + 'static,
        H: Hasher,
        Operation<mmr::Family, update::Unordered<K, V>>: Codec,
    {
        type Family = mmr::Family;
        type K = K;
        type V = V::Value;
        type Changeset =
            Changeset<K, H::Digest, Operation<mmr::Family, update::Unordered<K, V>>, N>;
        type Batch = UnmerkleizedBatch<H, update::Unordered<K, V>, N>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<
            Output = Result<core::ops::Range<Location>, crate::qmdb::Error<crate::mmr::Family>>,
        > {
            self.apply_batch(batch)
        }
    }

    impl<E, K, V, C, I, H, const N: usize> BatchableDb
        for CurrentDb<E, C, I, H, update::Ordered<K, V>, N>
    where
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<mmr::Family, update::Ordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: crate::index::Ordered<Value = Location> + 'static,
        H: Hasher,
        Operation<mmr::Family, update::Ordered<K, V>>: Codec,
    {
        type Family = mmr::Family;
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<K, H::Digest, Operation<mmr::Family, update::Ordered<K, V>>, N>;
        type Batch = UnmerkleizedBatch<H, update::Ordered<K, V>, N>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<
            Output = Result<core::ops::Range<Location>, crate::qmdb::Error<crate::mmr::Family>>,
        > {
            self.apply_batch(batch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::bitmap::Prunable as BitMap;

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
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 0);
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
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 0);

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
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 0);

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
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 0);

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
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 0);
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
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 0);
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

        let mut diff = BitmapDiff::<Bm, N>::new(&base, 3);

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
        let mut a = ClearSet::<N>::default();
        let b = ClearSet::<N>::default();
        a.merge(&b);
        assert_eq!(a.len(), 0);
        assert!(a.is_empty());
    }

    #[test]
    fn clear_set_merge_non_empty_into_empty() {
        let mut a = ClearSet::<N>::default();
        let mut b = ClearSet::<N>::default();
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
        let mut a = ClearSet::<N>::default();
        a.push(Location::new(5));
        let b = ClearSet::<N>::default();

        a.merge(&b);
        assert_eq!(a.len(), 1);
        assert_eq!(a.locations(), &[Location::new(5)]);
        let mask = a.mask(0).unwrap();
        assert_eq!(mask[0], 1 << 5);
    }

    #[test]
    fn clear_set_merge_disjoint_chunks() {
        // N=4 -> CHUNK_SIZE_BITS = 32. Bit 2 is in chunk 0, bit 33 is in chunk 1.
        let mut a = ClearSet::<N>::default();
        a.push(Location::new(2));

        let mut b = ClearSet::<N>::default();
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
        let mut a = ClearSet::<N>::default();
        a.push(Location::new(1));
        a.push(Location::new(4));

        let mut b = ClearSet::<N>::default();
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
        let locs_a: Vec<Location> = (0..5).map(Location::new).collect();
        let locs_b: Vec<Location> = (30..36).map(Location::new).collect(); // spans chunks 0 and 1

        // Build via merge.
        let mut via_merge = ClearSet::<N>::default();
        let mut part_a = ClearSet::<N>::default();
        for &loc in &locs_a {
            part_a.push(loc);
        }
        let mut part_b = ClearSet::<N>::default();
        for &loc in &locs_b {
            part_b.push(loc);
        }
        via_merge.merge(&part_a);
        via_merge.merge(&part_b);

        // Build via sequential push.
        let mut via_push = ClearSet::<N>::default();
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
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 3);

        diff.clear_bit(Location::new(3));
        diff.clear_bit(Location::new(40));
        diff.clear_bit(Location::new(63));

        assert_eq!(diff.clears.mask(0).unwrap()[0], 1 << 3);
        assert_eq!(diff.clears.mask(1).unwrap()[1], 0x01);
        assert_eq!(diff.clears.mask(1).unwrap()[3], 0x80);
    }

    #[test]
    fn bitmap_batch_push_changeset_preserves_clear_set() {
        let mut batch = BitmapBatch::Base(Arc::new(make_bitmap(&[true; 64])));
        let mut clears = ClearSet::default();
        clears.push(Location::new(3));
        clears.push(Location::new(40));
        batch.push_changeset(Vec::new(), clears);

        // Verify the cleared bits are reflected in the chunks.
        let chunk0 = batch.get_chunk(0);
        let chunk1 = batch.get_chunk(1);
        assert_eq!(chunk0[0] & (1 << 3), 0);
        assert_eq!(chunk1[1] & 0x01, 0);
    }

    // ---- push_operation_bits test ----

    #[test]
    fn push_operation_bits_mixed() {
        use crate::qmdb::any::{
            operation::{update, Operation},
            value::FixedEncoding,
        };
        use commonware_utils::sequence::FixedBytes;

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
        let mut bitmap = BitmapDiff::<Bm, N>::new(&base, 0);
        push_operation_bits::<U, Bm, N>(&mut bitmap, &segment, 0, &diff);

        // Expected: [true(key1 active), false(key2 superseded), false(delete), true(commit)]
        assert_eq!(bitmap.pushed_bits, [true, false, false, true]);
    }

    // ---- clear_base_old_locs test ----

    #[test]
    fn clear_base_old_locs_mixed() {
        type K = u64;

        // Base bitmap with 64 bits.
        let base = make_bitmap(&[true; 64]);
        let mut bitmap = BitmapDiff::<Bm, N>::new(&base, 2);

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

        clear_base_old_locs::<K, u64, Bm, N>(&mut bitmap, &diff);

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

    use crate::qmdb::any::batch::{FloorScan, SequentialScan};

    #[test]
    fn sequential_scan_returns_floor_when_below_tip() {
        let mut scan = SequentialScan;
        assert_eq!(
            scan.next_candidate(Location::new(5), 10),
            Some(Location::new(5))
        );
    }

    #[test]
    fn sequential_scan_returns_none_at_tip() {
        let mut scan = SequentialScan;
        assert_eq!(scan.next_candidate(Location::new(10), 10), None);
        assert_eq!(scan.next_candidate(Location::new(11), 10), None);
    }

    #[test]
    fn bitmap_scan_all_active() {
        let bm = make_bitmap(&[true; 8]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);
        for i in 0..8 {
            assert_eq!(
                scan.next_candidate(Location::new(i), 8),
                Some(Location::new(i))
            );
        }
        assert_eq!(scan.next_candidate(Location::new(8), 8), None);
    }

    #[test]
    fn bitmap_scan_all_inactive() {
        let bm = make_bitmap(&[false; 8]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);
        assert_eq!(scan.next_candidate(Location::new(0), 8), None);
    }

    #[test]
    fn bitmap_scan_skips_inactive() {
        // Pattern: inactive, inactive, active, inactive, active
        let bm = make_bitmap(&[false, false, true, false, true]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);

        assert_eq!(
            scan.next_candidate(Location::new(0), 5),
            Some(Location::new(2))
        );
        assert_eq!(
            scan.next_candidate(Location::new(3), 5),
            Some(Location::new(4))
        );
        assert_eq!(scan.next_candidate(Location::new(5), 5), None);
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
            scan.next_candidate(Location::new(0), 8),
            Some(Location::new(4))
        );
        assert_eq!(
            scan.next_candidate(Location::new(6), 8),
            Some(Location::new(6))
        );
    }

    #[test]
    fn bitmap_scan_respects_tip() {
        let bm = make_bitmap(&[false, false, false, true]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);

        // Active bit at 3, but tip is 3 so it's excluded.
        assert_eq!(scan.next_candidate(Location::new(0), 3), None);
        // With tip=4, bit 3 is included.
        assert_eq!(
            scan.next_candidate(Location::new(0), 4),
            Some(Location::new(3))
        );
    }

    #[test]
    fn bitmap_scan_floor_at_tip() {
        let bm = make_bitmap(&[true; 4]);
        let mut scan = BitmapScan::<Bm, N>::new(&bm);
        assert_eq!(scan.next_candidate(Location::new(4), 4), None);
    }

    #[test]
    fn bitmap_scan_empty_bitmap() {
        let bm = Bm::new();
        let mut scan = BitmapScan::<Bm, N>::new(&bm);

        // Empty bitmap, but tip > 0: all locations are beyond bitmap.
        assert_eq!(
            scan.next_candidate(Location::new(0), 5),
            Some(Location::new(0))
        );
        // Empty bitmap, tip = 0: no candidates.
        assert_eq!(scan.next_candidate(Location::new(0), 0), None);
    }

    #[test]
    fn bitmap_scan_with_bitmap_diff() {
        // Base: bits 0..8 all active.
        let base = make_bitmap(&[true; 8]);
        let mut diff = BitmapDiff::<Bm, N>::new(&base, 0);

        // Clear bits 2 and 5.
        diff.clear_bit(Location::new(2));
        diff.clear_bit(Location::new(5));

        // Push two inactive bits and one active bit beyond the base.
        diff.push_bit(false);
        diff.push_bit(false);
        diff.push_bit(true);

        let mut scan = BitmapScan::<BitmapDiff<'_, Bm, N>, N>::new(&diff);

        // Should skip bit 2 (cleared), return 0.
        assert_eq!(
            scan.next_candidate(Location::new(0), 11),
            Some(Location::new(0))
        );
        // From 2: skip cleared bit 2, return 3.
        assert_eq!(
            scan.next_candidate(Location::new(2), 11),
            Some(Location::new(3))
        );
        // From 5: skip cleared bit 5, return 6.
        assert_eq!(
            scan.next_candidate(Location::new(5), 11),
            Some(Location::new(6))
        );
        // From 8: skip pushed inactive 8,9, return active pushed 10.
        assert_eq!(
            scan.next_candidate(Location::new(8), 11),
            Some(Location::new(10))
        );
    }
}
