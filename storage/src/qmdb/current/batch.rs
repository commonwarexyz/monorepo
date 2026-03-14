//! Batch mutation API for Current QMDBs.
//!
//! Wraps the [`any::batch`] API, layering bitmap and grafted MMR
//! computation on top during [`UnmerkleizedBatch::merkleize()`].

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        authenticated::{self, BatchChain},
        contiguous::{Contiguous, Mutable},
    },
    mmr::{
        self,
        read::{BatchChainInfo, Readable},
        storage::Storage as MmrStorage,
        Location, Position, StandardHasher,
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
        Error,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::bitmap::Prunable as BitMap;
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

/// A bitmap that can be read.
pub trait BitmapRead<const N: usize> {
    /// Return the number of complete (fully filled) chunks.
    fn complete_chunks(&self) -> usize;
    /// Return the chunk data at the given absolute chunk index.
    fn get_chunk(&self, chunk: usize) -> [u8; N];
    /// Return the last chunk and its size in bits.
    fn last_chunk(&self) -> ([u8; N], u64);
    /// Return the number of pruned chunks.
    fn pruned_chunks(&self) -> usize;
    /// Return the total number of bits.
    fn len(&self) -> u64;
    /// Returns true if the bitmap is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Return the value of a single bit.
    fn get_bit(&self, bit: u64) -> bool {
        let chunk = self.get_chunk(BitMap::<N>::to_chunk_index(bit));
        BitMap::<N>::get_bit_from_chunk(&chunk, bit % BitMap::<N>::CHUNK_SIZE_BITS)
    }
}

impl<const N: usize> BitmapRead<N> for BitMap<N> {
    fn complete_chunks(&self) -> usize {
        Self::complete_chunks(self)
    }
    fn get_chunk(&self, chunk: usize) -> [u8; N] {
        *Self::get_chunk(self, chunk)
    }
    fn last_chunk(&self) -> ([u8; N], u64) {
        let (c, n) = Self::last_chunk(self);
        (*c, n)
    }
    fn pruned_chunks(&self) -> usize {
        Self::pruned_chunks(self)
    }
    fn len(&self) -> u64 {
        Self::len(self)
    }
}

/// Bitmap-accelerated floor scan. Skips locations where the bitmap bit is
/// unset, avoiding I/O reads for inactive operations.
pub(crate) struct BitmapScan<'a, B, const N: usize> {
    bitmap: &'a B,
}

impl<'a, B: BitmapRead<N>, const N: usize> BitmapScan<'a, B, N> {
    pub(crate) const fn new(bitmap: &'a B) -> Self {
        Self { bitmap }
    }
}

impl<B: BitmapRead<N>, const N: usize> FloorScan for BitmapScan<'_, B, N> {
    fn next_candidate(&mut self, floor: Location, tip: u64) -> Option<Location> {
        let mut loc = *floor;
        let bitmap_len = self.bitmap.len();
        while loc < tip {
            // Beyond the bitmap: uncommitted ops from prior batches in the
            // chain that aren't tracked by the bitmap yet. Conservatively
            // treat them as candidates.
            // Within the bitmap: only consider locations with the bit set.
            if loc >= bitmap_len || self.bitmap.get_bit(loc) {
                return Some(Location::new(loc));
            }
            loc += 1;
        }
        None
    }
}

/// Uncommitted bitmap changes on top of a base bitmap. Records pushed bits
/// and cleared bits without cloning the base. Implements [`BitmapRead`] for
/// read-through access.
pub struct BitmapDiff<'a, B: BitmapRead<N>, const N: usize> {
    /// The parent bitmap this diff is built on top of.
    base: &'a B,
    /// Number of bits in the base bitmap at diff creation time.
    base_len: u64,
    /// New bits appended beyond the base bitmap.
    pushed_bits: Vec<bool>,
    /// Locations of base bits that have been deactivated.
    cleared_bits: Vec<Location>,
    /// Chunk indices containing cleared bits that need grafted MMR recomputation.
    dirty_chunks: HashSet<usize>,
    /// Number of complete chunks in the base bitmap at diff creation time.
    old_grafted_leaves: usize,
}

impl<'a, B: BitmapRead<N>, const N: usize> BitmapDiff<'a, B, N> {
    const CHUNK_SIZE_BITS: u64 = BitMap::<N>::CHUNK_SIZE_BITS;

    fn new(base: &'a B, old_grafted_leaves: usize) -> Self {
        Self {
            base_len: base.len(),
            base,
            pushed_bits: Vec::new(),
            cleared_bits: Vec::new(),
            dirty_chunks: HashSet::new(),
            old_grafted_leaves,
        }
    }

    fn push_bit(&mut self, active: bool) {
        self.pushed_bits.push(active);
    }

    fn clear_bit(&mut self, loc: Location) {
        self.cleared_bits.push(loc);
        let chunk = BitMap::<N>::to_chunk_index(*loc);
        if chunk < self.old_grafted_leaves {
            self.dirty_chunks.insert(chunk);
        }
    }

    fn pushed_bits(&self) -> &[bool] {
        &self.pushed_bits
    }

    fn cleared_bits(&self) -> &[Location] {
        &self.cleared_bits
    }
}

impl<B: BitmapRead<N>, const N: usize> BitmapRead<N> for BitmapDiff<'_, B, N> {
    fn complete_chunks(&self) -> usize {
        (self.len() / Self::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        let chunk_start = idx as u64 * Self::CHUNK_SIZE_BITS;
        let chunk_end = chunk_start + Self::CHUNK_SIZE_BITS;

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

        // Apply pushed bits. The relevant slice is identified in O(1) since pushes
        // are contiguous from base_len.
        let push_start = self.base_len;
        let push_end = push_start + self.pushed_bits.len() as u64;
        if push_start < chunk_end && push_end > chunk_start {
            let abs_start = push_start.max(chunk_start);
            let abs_end = push_end.min(chunk_end);
            let from = (abs_start - push_start) as usize;
            let to = (abs_end - push_start) as usize;
            let rel_offset = (abs_start - chunk_start) as usize;
            for (j, &bit) in self.pushed_bits[from..to].iter().enumerate() {
                if bit {
                    let rel = rel_offset + j;
                    chunk[rel / 8] |= 1 << (rel % 8);
                }
            }
        }

        // Apply clears.
        for &loc in &self.cleared_bits {
            let bit = *loc;
            if bit >= chunk_start && bit < chunk_end {
                let rel = (bit - chunk_start) as usize;
                chunk[rel / 8] &= !(1 << (rel % 8));
            }
        }

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
/// Tries the batch chain's sync [`Readable`] first (which covers nodes appended
/// or overwritten by the batch, plus anything still in the in-memory MMR).
/// Falls through to the base's async [`MmrStorage`].
struct BatchStorageAdapter<'a, D: Digest, R: Readable<Digest = D>, S: MmrStorage<Digest = D>> {
    batch: &'a R,
    base: &'a S,
    _phantom: core::marker::PhantomData<D>,
}

impl<'a, D: Digest, R: Readable<Digest = D>, S: MmrStorage<Digest = D>>
    BatchStorageAdapter<'a, D, R, S>
{
    const fn new(batch: &'a R, base: &'a S) -> Self {
        Self {
            batch,
            base,
            _phantom: core::marker::PhantomData,
        }
    }
}

impl<D: Digest, R: Readable<Digest = D>, S: MmrStorage<Digest = D>> MmrStorage
    for BatchStorageAdapter<'_, D, R, S>
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
/// in contrast to [MerkleizedBatch].
#[allow(clippy::type_complexity)]
pub struct UnmerkleizedBatch<'a, E, C, I, H, U, P, G, B, const N: usize>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
    P: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest> + BatchChain<Operation<U>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// The inner any-layer batch that handles mutations, journal, and floor raise.
    inner: any::batch::UnmerkleizedBatch<'a, E, C, I, H, U, P>,

    /// The committed current-layer DB (for bitmap and grafted MMR access).
    current_db: &'a super::db::Db<E, C, I, H, U, N>,

    /// Bitmap pushes accumulated by prior batches in the chain.
    base_bitmap_pushes: Vec<Arc<Vec<bool>>>,

    /// Bitmap clears accumulated by prior batches in the chain.
    base_bitmap_clears: Vec<Arc<Vec<Location>>>,

    /// Parent's grafted MMR state.
    grafted_parent: &'a G,

    /// Parent's bitmap state.
    bitmap_parent: &'a B,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [UnmerkleizedBatch].
#[allow(clippy::type_complexity)]
pub struct MerkleizedBatch<'a, E, C, I, H, U, P, G, B, const N: usize>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
    P: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest> + BatchChain<Operation<U>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// The inner any-layer merkleized batch.
    inner: any::batch::MerkleizedBatch<'a, E, C, I, H, U, P>,

    /// The committed current-layer DB (for bitmap and grafted MMR access).
    current_db: &'a super::db::Db<E, C, I, H, U, N>,

    /// Bitmap pushes accumulated by prior batches in the chain.
    base_bitmap_pushes: Vec<Arc<Vec<bool>>>,

    /// Bitmap clears accumulated by prior batches in the chain.
    base_bitmap_clears: Vec<Arc<Vec<Location>>>,

    /// Merkleized grafted MMR changes on top of the parent's state.
    grafted_merkleized: mmr::MerkleizedBatch<'a, H::Digest, G>,

    /// Uncommitted bitmap changes on top of the parent bitmap.
    bitmap_diff: BitmapDiff<'a, B, N>,

    /// The canonical root (ops MMR root + grafted MMR root + partial chunk).
    canonical_root: H::Digest,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<K, D: Digest, Item: Send, const N: usize> {
    /// The inner any-layer changeset.
    pub(super) inner: any::batch::Changeset<K, D, Item>,

    /// One bool per operation in the batch chain (pushes applied before clears).
    pub(super) bitmap_pushes: Vec<bool>,

    /// Locations of bits to clear after pushing.
    pub(super) bitmap_clears: Vec<Location>,

    /// Changeset for the grafted MMR.
    pub(super) grafted_changeset: mmr::Changeset<D>,

    /// Precomputed canonical root.
    pub(super) canonical_root: D,
}

impl<'a, E, C, I, H, U, P, G, B, const N: usize> UnmerkleizedBatch<'a, E, C, I, H, U, P, G, B, N>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
    P: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest> + BatchChain<Operation<U>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    pub(super) const fn new(
        inner: any::batch::UnmerkleizedBatch<'a, E, C, I, H, U, P>,
        current_db: &'a super::db::Db<E, C, I, H, U, N>,
        base_bitmap_pushes: Vec<Arc<Vec<bool>>>,
        base_bitmap_clears: Vec<Arc<Vec<Location>>>,
        grafted_parent: &'a G,
        bitmap_parent: &'a B,
    ) -> Self {
        Self {
            inner,
            current_db,
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
impl<'a, E, K, V, C, I, H, P, G, B, const N: usize>
    UnmerkleizedBatch<'a, E, C, I, H, update::Unordered<K, V>, P, G, B, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Unordered<K, V>>: Codec,
    P: Readable<Digest = H::Digest>
        + BatchChainInfo<Digest = H::Digest>
        + BatchChain<Operation<update::Unordered<K, V>>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }

    /// Resolve mutations into operations, merkleize, and return a [`MerkleizedBatch`].
    pub async fn merkleize(
        self,
        metadata: Option<V::Value>,
    ) -> Result<MerkleizedBatch<'a, E, C, I, H, update::Unordered<K, V>, P, G, B, N>, Error> {
        let Self {
            inner,
            current_db,
            base_bitmap_pushes,
            base_bitmap_clears,
            grafted_parent,
            bitmap_parent,
        } = self;
        let scan = BitmapScan::new(bitmap_parent);
        let inner = inner.merkleize_with_floor_scan(metadata, scan).await?;
        compute_current_layer(
            inner,
            current_db,
            base_bitmap_pushes,
            base_bitmap_clears,
            grafted_parent,
            bitmap_parent,
        )
        .await
    }
}

// Ordered get + merkleize.
impl<'a, E, K, V, C, I, H, P, G, B, const N: usize>
    UnmerkleizedBatch<'a, E, C, I, H, update::Ordered<K, V>, P, G, B, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<update::Ordered<K, V>>>,
    I: crate::index::Ordered<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Ordered<K, V>>: Codec,
    P: Readable<Digest = H::Digest>
        + BatchChainInfo<Digest = H::Digest>
        + BatchChain<Operation<update::Ordered<K, V>>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }

    /// Resolve mutations into operations, merkleize, and return a [`MerkleizedBatch`].
    pub async fn merkleize(
        self,
        metadata: Option<V::Value>,
    ) -> Result<MerkleizedBatch<'a, E, C, I, H, update::Ordered<K, V>, P, G, B, N>, Error> {
        let Self {
            inner,
            current_db,
            base_bitmap_pushes,
            base_bitmap_clears,
            grafted_parent,
            bitmap_parent,
        } = self;
        let scan = BitmapScan::new(bitmap_parent);
        let inner = inner.merkleize_with_floor_scan(metadata, scan).await?;
        compute_current_layer(
            inner,
            current_db,
            base_bitmap_pushes,
            base_bitmap_clears,
            grafted_parent,
            bitmap_parent,
        )
        .await
    }
}

/// Push one bitmap bit per operation in `segment`. An Update is active only if
/// the merged diff shows it as the final location for its key.
fn push_operation_bits<U, B, const N: usize>(
    bitmap: &mut BitmapDiff<'_, B, N>,
    segment: &[Operation<U>],
    segment_base: u64,
    diff: &BTreeMap<U::Key, DiffEntry<U::Value>>,
) where
    U: update::Update,
    B: BitmapRead<N>,
    Operation<U>: Codec,
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
    diff: &BTreeMap<K, DiffEntry<V>>,
) where
    K: Ord,
    B: BitmapRead<N>,
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
    chain: &[std::sync::Arc<Vec<Operation<U>>>],
    diff: &BTreeMap<U::Key, DiffEntry<U::Value>>,
    db_base: u64,
) where
    U: update::Update,
    B: BitmapRead<N>,
    Operation<U>: Codec,
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

/// Compute the current layer (bitmap + grafted MMR + canonical root) on top of
/// a merkleized any batch.
///
/// Creates a `BitmapDiff` and grafted MMR batch from the immediate parent's
/// state, and produces the speculative grafted `MerkleizedBatch` and
/// `BitmapDiff` that live on the returned `MerkleizedBatch`. The ancestor
/// chain's accumulated bitmap pushes/clears are stored alongside the diff
/// so that `finalize()` can concatenate them without recomputation.
async fn compute_current_layer<'a, E, U, C, I, H, P, G, B, const N: usize>(
    inner: any::batch::MerkleizedBatch<'a, E, C, I, H, U, P>,
    current_db: &'a super::db::Db<E, C, I, H, U, N>,
    base_bitmap_pushes: Vec<Arc<Vec<bool>>>,
    base_bitmap_clears: Vec<Arc<Vec<Location>>>,
    grafted_parent: &'a G,
    bitmap_parent: &'a B,
) -> Result<MerkleizedBatch<'a, E, C, I, H, U, P, G, B, N>, Error>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
    P: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest> + BatchChain<Operation<U>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    let old_grafted_leaves = *grafted_parent.leaves() as usize;
    let mut bitmap = BitmapDiff::new(bitmap_parent, old_grafted_leaves);

    let chain = &inner.base_operations;
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
    let ops_mmr_adapter = BatchStorageAdapter::new(&inner.journal_batch, &current_db.any.log.mmr);
    let hasher = StandardHasher::<H>::new();
    let new_leaves = compute_grafted_leaves::<H, N>(
        &hasher,
        &ops_mmr_adapter,
        chunks_to_update,
        current_db.thread_pool.as_ref(),
    )
    .await?;

    // 6. Build grafted MMR batch from parent ref (no clone).
    let grafting_height = grafting::height::<N>();
    let grafted_merkleized = {
        let mut grafted_batch =
            mmr::UnmerkleizedBatch::new(grafted_parent).with_pool(current_db.thread_pool.clone());
        for &(ops_pos, digest) in &new_leaves {
            let grafted_pos = grafting::ops_to_grafted_pos(ops_pos, grafting_height);
            if grafted_pos < grafted_batch.size() {
                let loc = Location::try_from(grafted_pos).expect("grafted_pos overflow");
                grafted_batch
                    .update_leaf_digest(loc, digest)
                    .expect("update_leaf_digest failed");
            } else {
                grafted_batch.add_leaf_digest(digest);
            }
        }
        let gh = grafting::GraftedHasher::new(hasher.clone(), grafting_height);
        grafted_batch.merkleize(&gh)
    };

    // 7. Compute canonical root using the merkleized batch directly.
    let ops_root = inner.root();
    let grafted_storage =
        grafting::Storage::new(&grafted_merkleized, grafting_height, &ops_mmr_adapter);
    let partial = partial_chunk(&bitmap);
    let canonical_root =
        compute_db_root::<H, _, _, N>(&hasher, &grafted_storage, partial, &ops_root).await?;

    Ok(MerkleizedBatch {
        inner,
        current_db,
        base_bitmap_pushes,
        base_bitmap_clears,
        grafted_merkleized,
        bitmap_diff: bitmap,
        canonical_root,
    })
}

impl<'a, E, C, I, H, U, P, G, B, const N: usize> MerkleizedBatch<'a, E, C, I, H, U, P, G, B, N>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
    P: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest> + BatchChain<Operation<U>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// Return the speculative root.
    pub const fn root(&self) -> H::Digest {
        self.canonical_root
    }

    /// Return the ops-only MMR root.
    pub fn ops_root(&self) -> H::Digest {
        self.inner.root()
    }

    /// Create a new speculative batch of operations with this batch as its parent.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(
        &self,
    ) -> UnmerkleizedBatch<
        '_,
        E,
        C,
        I,
        H,
        U,
        authenticated::MerkleizedBatch<'a, H, P, Operation<U>>,
        mmr::MerkleizedBatch<'a, H::Digest, G>,
        BitmapDiff<'a, B, N>,
        N,
    > {
        // Clone the chain of Arc segments (1 Arc bump per batch in the chain), then push this
        // batch's diff data as a new segment.
        let mut pushes = self.base_bitmap_pushes.clone();
        pushes.push(Arc::new(self.bitmap_diff.pushed_bits().to_vec()));
        let mut clears = self.base_bitmap_clears.clone();
        clears.push(Arc::new(self.bitmap_diff.cleared_bits().to_vec()));
        UnmerkleizedBatch {
            inner: self.inner.new_batch(),
            current_db: self.current_db,
            base_bitmap_pushes: pushes,
            base_bitmap_clears: clears,
            grafted_parent: &self.grafted_merkleized,
            bitmap_parent: &self.bitmap_diff,
        }
    }
}

// Unordered get.
impl<'a, E, K, V, C, I, H, P, G, B, const N: usize>
    MerkleizedBatch<'a, E, C, I, H, update::Unordered<K, V>, P, G, B, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Unordered<K, V>>: Codec,
    P: Readable<Digest = H::Digest>
        + BatchChainInfo<Digest = H::Digest>
        + BatchChain<Operation<update::Unordered<K, V>>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// Read through: diff -> committed DB.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }
}

// Ordered get.
impl<'a, E, K, V, C, I, H, P, G, B, const N: usize>
    MerkleizedBatch<'a, E, C, I, H, update::Ordered<K, V>, P, G, B, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<update::Ordered<K, V>>>,
    I: crate::index::Ordered<Value = Location> + 'static,
    H: Hasher,
    Operation<update::Ordered<K, V>>: Codec,
    P: Readable<Digest = H::Digest>
        + BatchChainInfo<Digest = H::Digest>
        + BatchChain<Operation<update::Ordered<K, V>>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// Read through: diff -> committed DB.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }
}

// Finalize (requires Mutable journal for apply_batch).
impl<'a, E, C, I, H, U, P, G, B, const N: usize> MerkleizedBatch<'a, E, C, I, H, U, P, G, B, N>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync + 'static,
    C: Mutable<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
    P: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest> + BatchChain<Operation<U>>,
    G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
    B: BitmapRead<N>,
{
    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<U::Key, H::Digest, Operation<U>, N> {
        // Flatten the chain of Arc segments + this level's diff into flat Vecs.
        let total_pushes: usize = self
            .base_bitmap_pushes
            .iter()
            .map(|s| s.len())
            .sum::<usize>()
            + self.bitmap_diff.pushed_bits().len();
        let mut bitmap_pushes = Vec::with_capacity(total_pushes);
        for seg in &self.base_bitmap_pushes {
            bitmap_pushes.extend_from_slice(seg);
        }
        bitmap_pushes.extend_from_slice(self.bitmap_diff.pushed_bits());

        let total_clears: usize = self
            .base_bitmap_clears
            .iter()
            .map(|s| s.len())
            .sum::<usize>()
            + self.bitmap_diff.cleared_bits().len();
        let mut bitmap_clears = Vec::with_capacity(total_clears);
        for seg in &self.base_bitmap_clears {
            bitmap_clears.extend_from_slice(seg);
        }
        bitmap_clears.extend_from_slice(self.bitmap_diff.cleared_bits());

        Changeset {
            inner: self.inner.finalize(),
            bitmap_pushes,
            bitmap_clears,
            grafted_changeset: self.grafted_merkleized.finalize(),
            canonical_root: self.canonical_root,
        }
    }
}

#[cfg(any(test, feature = "test-traits"))]
mod trait_impls {
    use super::*;
    use crate::{
        journal::contiguous::Mutable,
        mmr::journaled::Mmr,
        qmdb::any::traits::{
            BatchableDb, MerkleizedBatch as MerkleizedBatchTrait,
            UnmerkleizedBatch as UnmerkleizedBatchTrait,
        },
        Persistable,
    };
    use std::future::Future;

    type CurrentDb<E, C, I, H, U, const N: usize> = crate::qmdb::current::db::Db<E, C, I, H, U, N>;

    impl<'a, E, K, V, C, I, H, P, G, B, const N: usize> UnmerkleizedBatchTrait
        for UnmerkleizedBatch<'a, E, C, I, H, update::Unordered<K, V>, P, G, B, N>
    where
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location> + 'static,
        H: Hasher,
        Operation<update::Unordered<K, V>>: Codec,
        P: Readable<Digest = H::Digest>
            + BatchChainInfo<Digest = H::Digest>
            + BatchChain<Operation<update::Unordered<K, V>>>,
        G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
        B: BitmapRead<N>,
    {
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized =
            super::MerkleizedBatch<'a, E, C, I, H, update::Unordered<K, V>, P, G, B, N>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            UnmerkleizedBatch::write(self, key, value)
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error>> {
            self.merkleize(metadata)
        }
    }

    impl<'a, E, K, V, C, I, H, P, G, B, const N: usize> UnmerkleizedBatchTrait
        for UnmerkleizedBatch<'a, E, C, I, H, update::Ordered<K, V>, P, G, B, N>
    where
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location> + 'static,
        H: Hasher,
        Operation<update::Ordered<K, V>>: Codec,
        P: Readable<Digest = H::Digest>
            + BatchChainInfo<Digest = H::Digest>
            + BatchChain<Operation<update::Ordered<K, V>>>,
        G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
        B: BitmapRead<N>,
    {
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = super::MerkleizedBatch<'a, E, C, I, H, update::Ordered<K, V>, P, G, B, N>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            UnmerkleizedBatch::write(self, key, value)
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error>> {
            self.merkleize(metadata)
        }
    }

    impl<'a, E, C, I, H, U, P, G, B, const N: usize> MerkleizedBatchTrait
        for super::MerkleizedBatch<'a, E, C, I, H, U, P, G, B, N>
    where
        E: Storage + Clock + Metrics,
        U: update::Update + Send + Sync + 'static,
        C: Mutable<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        Operation<U>: Codec,
        P: Readable<Digest = H::Digest>
            + BatchChainInfo<Digest = H::Digest>
            + BatchChain<Operation<U>>,
        G: Readable<Digest = H::Digest> + BatchChainInfo<Digest = H::Digest>,
        B: BitmapRead<N>,
    {
        type Digest = H::Digest;
        type Changeset = Changeset<U::Key, H::Digest, Operation<U>, N>;

        fn root(&self) -> H::Digest {
            self.root()
        }

        fn finalize(self) -> Self::Changeset {
            self.finalize()
        }
    }

    impl<E, K, V, C, I, H, const N: usize> BatchableDb
        for CurrentDb<E, C, I, H, update::Unordered<K, V>, N>
    where
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<update::Unordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location> + 'static,
        H: Hasher,
        Operation<update::Unordered<K, V>>: Codec,
    {
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<K, H::Digest, Operation<update::Unordered<K, V>>, N>;
        type Batch<'a>
            = UnmerkleizedBatch<
            'a,
            E,
            C,
            I,
            H,
            update::Unordered<K, V>,
            Mmr<E, H::Digest>,
            mmr::mem::Mmr<H::Digest>,
            commonware_utils::bitmap::Prunable<N>,
            N,
        >
        where
            Self: 'a;

        fn new_batch(&self) -> Self::Batch<'_> {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<core::ops::Range<Location>, crate::qmdb::Error>> {
            self.apply_batch(batch)
        }
    }

    impl<E, K, V, C, I, H, const N: usize> BatchableDb
        for CurrentDb<E, C, I, H, update::Ordered<K, V>, N>
    where
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<update::Ordered<K, V>>>
            + Persistable<Error = crate::journal::Error>,
        I: crate::index::Ordered<Value = Location> + 'static,
        H: Hasher,
        Operation<update::Ordered<K, V>>: Codec,
    {
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<K, H::Digest, Operation<update::Ordered<K, V>>, N>;
        type Batch<'a>
            = UnmerkleizedBatch<
            'a,
            E,
            C,
            I,
            H,
            update::Ordered<K, V>,
            Mmr<E, H::Digest>,
            mmr::mem::Mmr<H::Digest>,
            commonware_utils::bitmap::Prunable<N>,
            N,
        >
        where
            Self: 'a;

        fn new_batch(&self) -> Self::Batch<'_> {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<core::ops::Range<Location>, crate::qmdb::Error>> {
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
        type Op = Operation<U>;

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
        assert_eq!(bitmap.pushed_bits(), &[true, false, false, true]);
    }

    // ---- clear_base_old_locs test ----

    #[test]
    fn clear_base_old_locs_mixed() {
        type K = u64;

        // Base bitmap with 64 bits.
        let base = make_bitmap(&[true; 64]);
        let mut bitmap = BitmapDiff::<Bm, N>::new(&base, 2);

        let mut diff: BTreeMap<K, DiffEntry<u64>> = BTreeMap::new();

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

        assert_eq!(bitmap.cleared_bits().len(), 2);

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
