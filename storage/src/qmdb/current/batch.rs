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
            db::{compute_db_root, compute_grafted_leaves},
            grafting,
        },
        operation::Key,
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::bitmap::{Prunable as BitMap, Readable as BitmapReadable};
use std::{collections::BTreeMap, sync::Arc};

type Error = crate::qmdb::Error<mmr::Family>;

/// Speculative chunk-level bitmap overlay.
///
/// Instead of tracking individual pushed bits and cleared locations, maintains materialized chunk
/// bytes for every chunk that differs from the parent bitmap. This directly produces the chunk data
/// needed for grafted MMR leaf computation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChunkOverlay<const N: usize> {
    /// Dirty chunks: chunk_idx -> materialized chunk bytes.
    pub(crate) chunks: BTreeMap<usize, [u8; N]>,
    /// Total number of bits (parent + new operations).
    pub(crate) len: u64,
}

impl<const N: usize> ChunkOverlay<N> {
    const CHUNK_BITS: u64 = BitMap::<N>::CHUNK_SIZE_BITS;

    const fn new(len: u64) -> Self {
        Self {
            chunks: BTreeMap::new(),
            len,
        }
    }

    /// Load-or-create a chunk: returns a mutable reference to the materialized chunk bytes. On
    /// first access for an existing chunk, reads from `base`.
    fn chunk_mut<B: BitmapReadable<N>>(&mut self, base: &B, idx: usize) -> &mut [u8; N] {
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
    fn set_bit<B: BitmapReadable<N>>(&mut self, base: &B, loc: u64) {
        let idx = BitMap::<N>::to_chunk_index(loc);
        let rel = (loc % Self::CHUNK_BITS) as usize;
        let chunk = self.chunk_mut(base, idx);
        chunk[rel / 8] |= 1 << (rel % 8);
    }

    /// Clear a single bit (used for superseded locations).
    /// Skips locations in pruned chunks — those bits are already inactive.
    fn clear_bit<B: BitmapReadable<N>>(&mut self, base: &B, loc: u64) {
        let idx = BitMap::<N>::to_chunk_index(loc);
        if idx < base.pruned_chunks() {
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
        // Within the bitmap: find the next set bit at or after floor. ones_iter_from returns
        // set indices in ascending order so the first result is the only possible candidate
        // below bound. tip >= bitmap_len always holds (base_size == bitmap_parent.len()), so
        // bound == bitmap_len and the length check inside the iterator prevents scanning past
        // bound.
        if loc < bitmap_len {
            let bound = bitmap_len.min(tip);
            if let Some(idx) = self.bitmap.ones_iter_from(loc).next() {
                if idx < bound {
                    return Some(Location::new(idx));
                }
            }
        }
        // Beyond the bitmap: uncommitted ops from prior batches in the chain that aren't
        // tracked by the bitmap yet. Conservatively treat them as candidates.
        if bitmap_len < tip {
            let candidate = loc.max(bitmap_len);
            if candidate < tip {
                return Some(Location::new(candidate));
            }
        }
        None
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

/// Layers a [`mmr::batch::MerkleizedBatch`] over a [`mmr::mem::Mmr`] for node resolution.
///
/// [`mmr::batch::MerkleizedBatch::get_node`] only covers the batch chain; committed positions
/// return `None`. This adapter falls through to the committed Mem for those positions.
struct BatchOverMem<'a, D: Digest> {
    batch: &'a mmr::batch::MerkleizedBatch<D>,
    mem: &'a mmr::mem::Mmr<D>,
}

impl<D: Digest> Readable for BatchOverMem<'_, D> {
    type Family = mmr::Family;
    type Digest = D;
    type Error = mmr::Error;

    fn size(&self) -> Position {
        self.batch.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        if let Some(d) = self.batch.get_node(pos) {
            return Some(d);
        }
        self.mem.get_node(pos)
    }

    fn root(&self) -> D {
        self.batch.root()
    }

    fn pruning_boundary(&self) -> Location {
        self.batch.pruning_boundary()
    }

    fn proof(
        &self,
        _hasher: &impl crate::merkle::hasher::Hasher<mmr::Family, Digest = D>,
        _loc: Location,
    ) -> Result<crate::merkle::Proof<mmr::Family, D>, mmr::Error> {
        unreachable!("proof not used in compute_current_layer")
    }

    fn range_proof(
        &self,
        _hasher: &impl crate::merkle::hasher::Hasher<mmr::Family, Digest = D>,
        _range: core::ops::Range<Location>,
    ) -> Result<crate::merkle::Proof<mmr::Family, D>, mmr::Error> {
        unreachable!("range_proof not used in compute_current_layer")
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

    /// Parent's grafted MMR state.
    grafted_parent: Arc<mmr::batch::MerkleizedBatch<H::Digest>>,

    /// Parent's bitmap state (COW, Arc-based).
    bitmap_parent: BitmapBatch<N>,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
///
/// Wraps an [`any::batch::MerkleizedBatch`] and adds the bitmap and grafted MMR state needed
/// to compute the canonical root.
#[derive(Clone)]
pub struct MerkleizedBatch<D: Digest, U: update::Update + Send + Sync, const N: usize>
where
    Operation<mmr::Family, U>: Send + Sync,
{
    /// Inner any-layer batch (ops MMR, diff, floor, commit loc, sizes).
    pub(crate) inner: Arc<any::batch::MerkleizedBatch<mmr::Family, D, U>>,

    /// Grafted MMR state.
    pub(crate) grafted: Arc<mmr::batch::MerkleizedBatch<D>>,

    /// COW bitmap state (for use as a parent in speculative batches).
    pub(crate) bitmap: BitmapBatch<N>,

    /// The canonical root (ops root + grafted root + partial chunk).
    pub(crate) canonical_root: D,
}

impl<H, U, const N: usize> UnmerkleizedBatch<H, U, N>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    pub(super) const fn new(
        inner: any::batch::UnmerkleizedBatch<mmr::Family, H, U>,
        grafted_parent: Arc<mmr::batch::MerkleizedBatch<H::Digest>>,
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
    /// Read through: mutations -> ancestor diffs -> committed DB.
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

    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub async fn merkleize<E, C, I>(
        self,
        db: &super::db::Db<E, C, I, H, update::Unordered<K, V>, N>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<H::Digest, update::Unordered<K, V>, N>>, Error>
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
            .merkleize_with_floor_scan(&db.any, metadata, scan)
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
    /// Read through: mutations -> ancestor diffs -> committed DB.
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

    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub async fn merkleize<E, C, I>(
        self,
        db: &super::db::Db<E, C, I, H, update::Ordered<K, V>, N>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<H::Digest, update::Ordered<K, V>, N>>, Error>
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
            .merkleize_with_floor_scan(&db.any, metadata, scan)
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
/// Build a [`ChunkOverlay`] for this batch by setting active bits and clearing
/// superseded locations directly in materialized chunk bytes.
#[allow(clippy::type_complexity)]
fn build_chunk_overlay<U, B: BitmapReadable<N>, const N: usize>(
    base: &B,
    batch_len: usize,
    batch_base: u64,
    diff: &BTreeMap<U::Key, DiffEntry<mmr::Family, U::Value>>,
    ancestor_diffs: &[Arc<BTreeMap<U::Key, DiffEntry<mmr::Family, U::Value>>>],
) -> ChunkOverlay<N>
where
    U: update::Update,
{
    let total_bits = base.len() + batch_len as u64;
    let mut overlay = ChunkOverlay::new(total_bits);

    // 1. CommitFloor (last op) is always active.
    let commit_loc = batch_base + batch_len as u64 - 1;
    overlay.set_bit(base, commit_loc);

    // 2. Inactivate previous CommitFloor.
    overlay.clear_bit(base, batch_base - 1);

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
            if let Some(ancestor_entry) = ancestor_diff.get(key) {
                prev_loc = ancestor_entry.loc();
                break;
            }
        }
        if let Some(old) = prev_loc {
            overlay.clear_bit(base, *old);
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
async fn compute_current_layer<E, U, C, I, H, const N: usize>(
    inner: Arc<any::batch::MerkleizedBatch<mmr::Family, H::Digest, U>>,
    current_db: &super::db::Db<E, C, I, H, U, N>,
    grafted_parent: &Arc<mmr::batch::MerkleizedBatch<H::Digest>>,
    bitmap_parent: &BitmapBatch<N>,
) -> Result<Arc<MerkleizedBatch<H::Digest, U, N>>, Error>
where
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<mmr::Family, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<mmr::Family, U>: Codec,
{
    let batch_len = inner.journal_batch.items().len();
    let batch_base = *inner.new_last_commit_loc + 1 - batch_len as u64;

    // Build chunk overlay: materialized bytes for every dirty chunk.
    let overlay = build_chunk_overlay::<U, _, N>(
        bitmap_parent,
        batch_len,
        batch_base,
        &inner.diff,
        &inner.ancestor_diffs,
    );

    // Grafted MMR recomputation: iterate complete chunks in the overlay.
    // This covers both new chunks and dirty existing chunks in a single pass.
    let new_grafted_leaves = overlay.complete_chunks();
    let chunks_to_update = overlay
        .chunks
        .iter()
        .filter(|(&idx, _)| idx < new_grafted_leaves)
        .map(|(&idx, &chunk)| (idx, chunk));
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

    // Build grafted MMR from parent batch.
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
        grafted_batch.merkleize(&current_db.grafted_mmr, &gh)
    };

    // Compute canonical root. The grafted batch alone cannot resolve committed nodes,
    // so layer it over the committed grafted MMR.
    let ops_root = inner.root();
    let layered = BatchOverMem {
        batch: &grafted_batch,
        mem: &current_db.grafted_mmr,
    };
    let grafted_storage = grafting::Storage::new(&layered, grafting_height, &ops_mmr_adapter);
    // Compute partial chunk (last incomplete chunk, if any).
    let partial = {
        let rem = overlay.len % ChunkOverlay::<N>::CHUNK_BITS;
        if rem == 0 {
            None
        } else {
            let idx = new_grafted_leaves;
            let chunk = overlay
                .get(idx)
                .copied()
                .unwrap_or_else(|| bitmap_parent.get_chunk(idx));
            Some((chunk, rem))
        }
    };
    let canonical_root =
        compute_db_root::<H, _, _, N>(&hasher, &grafted_storage, partial, &ops_root).await?;

    let bitmap_batch = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
        parent: bitmap_parent.clone(),
        overlay: Arc::new(overlay),
    }));

    Ok(Arc::new(MerkleizedBatch {
        inner,
        grafted: grafted_batch,
        bitmap: bitmap_batch,
        canonical_root,
    }))
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
    pub(crate) parent: BitmapBatch<N>,
    /// Chunk-level overlay: materialized bytes for every chunk that differs from parent.
    pub(crate) overlay: Arc<ChunkOverlay<N>>,
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
                // Check overlay first; fall through to parent if unmodified.
                if let Some(&chunk) = layer.overlay.get(idx) {
                    chunk
                } else {
                    layer.parent.get_chunk(idx)
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
        match self {
            Self::Base(bm) => bm.pruned_chunks(),
            Self::Layer(layer) => layer.parent.pruned_chunks(),
        }
    }

    fn len(&self) -> u64 {
        match self {
            Self::Base(bm) => BitmapReadable::<N>::len(bm.as_ref()),
            Self::Layer(layer) => layer.overlay.len,
        }
    }
}

impl<const N: usize> BitmapBatch<N> {
    /// Apply a chunk overlay to this bitmap. When `self` is `Base` with sole ownership, writes
    /// overlay chunks directly into the bitmap. Otherwise creates a new `Layer`.
    pub(super) fn apply_overlay(&mut self, overlay: Arc<ChunkOverlay<N>>) {
        // Fast path: write overlay chunks directly into the Base bitmap.
        if let Self::Base(base) = self {
            if let Some(bitmap) = Arc::get_mut(base) {
                // Extend bitmap to the overlay's length.
                bitmap.extend_to(overlay.len);
                // Overwrite dirty chunks.
                for (&idx, chunk_bytes) in &overlay.chunks {
                    if idx >= bitmap.pruned_chunks() {
                        bitmap.set_chunk_by_index(idx, chunk_bytes);
                    }
                }
                return;
            }
        }

        // Slow path: create a new layer.
        let parent = self.clone();
        *self = Self::Layer(Arc::new(BitmapBatchLayer { parent, overlay }));
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

        // Collect overlays from tip to base.
        let mut overlays = Vec::new();
        let base = loop {
            match owned {
                Self::Base(bm) => break bm,
                Self::Layer(layer) => match Arc::try_unwrap(layer) {
                    Ok(inner) => {
                        overlays.push(inner.overlay);
                        owned = inner.parent;
                    }
                    Err(arc) => {
                        overlays.push(arc.overlay.clone());
                        owned = arc.parent.clone();
                    }
                },
            }
        };

        // Apply overlays from base to tip.
        let mut bitmap = Arc::try_unwrap(base).unwrap_or_else(|arc| (*arc).clone());
        for overlay in overlays.into_iter().rev() {
            // Extend bitmap to the overlay's length.
            bitmap.extend_to(overlay.len);
            // Apply dirty chunks.
            for (&idx, chunk_bytes) in &overlay.chunks {
                if idx >= bitmap.pruned_chunks() {
                    bitmap.set_chunk_by_index(idx, chunk_bytes);
                }
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
    ///
    /// All uncommitted ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Dropping an uncommitted ancestor causes data
    /// loss detected at `apply_batch` time.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<H, U, N>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch::new(
            self.inner.new_batch::<H>(),
            Arc::clone(&self.grafted),
            self.bitmap.clone(),
        )
    }

    /// Read through: local diff -> ancestor diffs -> committed DB.
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
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<H::Digest, U, N>> {
        let grafted = self.grafted_snapshot();
        Arc::new(MerkleizedBatch {
            inner: self.any.to_batch(),
            grafted,
            bitmap: self.status.clone(),
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
        type Merkleized = Arc<MerkleizedBatch<H::Digest, update::Unordered<K, V>, N>>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            db: &CurrentDb<E, C, I, H, update::Unordered<K, V>, N>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<mmr::Family>>>
        {
            self.merkleize(db, metadata)
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
        type Merkleized = Arc<MerkleizedBatch<H::Digest, update::Ordered<K, V>, N>>;

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
        }

        fn merkleize(
            self,
            db: &CurrentDb<E, C, I, H, update::Ordered<K, V>, N>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<mmr::Family>>>
        {
            self.merkleize(db, metadata)
        }
    }

    impl<D: Digest, U: update::Update + Send + Sync + 'static, const N: usize> MerkleizedBatchTrait
        for Arc<MerkleizedBatch<D, U, N>>
    where
        Operation<mmr::Family, U>: Codec,
    {
        type Digest = D;

        fn root(&self) -> D {
            MerkleizedBatch::root(self)
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
        type Merkleized = Arc<MerkleizedBatch<H::Digest, update::Unordered<K, V>, N>>;
        type Batch = UnmerkleizedBatch<H, update::Unordered<K, V>, N>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Merkleized,
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
        type Merkleized = Arc<MerkleizedBatch<H::Digest, update::Ordered<K, V>, N>>;
        type Batch = UnmerkleizedBatch<H, update::Ordered<K, V>, N>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Merkleized,
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
        // Diff: key1 active at loc=4 (in segment), key2 active at loc=99 (not in segment,
        // so superseded within this segment).
        let base = make_bitmap(&[true; 4]);
        let mut diff = BTreeMap::new();
        diff.insert(
            key1,
            DiffEntry::Active {
                value: 100u64,
                loc: Location::new(4), // offset 0 in segment
                base_old_loc: None,
            },
        );
        diff.insert(
            key2,
            DiffEntry::Active {
                value: 200u64,
                loc: Location::new(99), // not in segment [4,8), so superseded
                base_old_loc: None,
            },
        );

        let overlay = build_chunk_overlay::<U, _, N>(&base, 4, 4, &diff, &[]);

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

        let mut diff: BTreeMap<K, DiffEntry<mmr::Family, u64>> = BTreeMap::new();

        // key1: Active with base_old_loc = Some(5) -> should clear bit 5.
        diff.insert(
            key1,
            DiffEntry::Active {
                value: 100,
                loc: Location::new(70),
                base_old_loc: Some(Location::new(5)),
            },
        );

        // key2: Deleted with base_old_loc = Some(10) -> should clear bit 10.
        diff.insert(
            key2,
            DiffEntry::Deleted {
                base_old_loc: Some(Location::new(10)),
            },
        );

        // key3: Active with base_old_loc = None -> no clear.
        diff.insert(
            key3,
            DiffEntry::Active {
                value: 300,
                loc: Location::new(71),
                base_old_loc: None,
            },
        );

        // Segment of 8 ops starting at 64; previous commit at loc 63.
        let overlay = build_chunk_overlay::<U, _, N>(&base, 8, 64, &diff, &[]);

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
        let mut diff = BTreeMap::new();
        diff.insert(
            key1,
            DiffEntry::Active {
                value: 42u64,
                loc: Location::new(35),
                base_old_loc: None,
            },
        );

        let overlay = build_chunk_overlay::<U, _, N>(&base, 20, 20, &diff, &[]);

        // Chunk 0 should be materialized and preserve the parent's first 20 bits.
        let c0 = overlay.get(0).expect("chunk 0 should be in overlay");
        // Bits 0-7 all set -> byte 0 = 0xFF
        assert_eq!(c0[0], 0xFF);
        // Bits 8-15 all set -> byte 1 = 0xFF
        assert_eq!(c0[1], 0xFF);
        // Bits 16-18 set, bit 19 cleared (previous commit), 20-23 not set -> byte 2 = 0x07
        assert_eq!(c0[2], 0x07);
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
    fn test_apply_overlay() {
        // Base: 8 bits all set, sole owner -> fast path.
        let base = make_bitmap(&[true; 8]);
        let mut batch = BitmapBatch::Base(Arc::new(base));

        let mut overlay = ChunkOverlay::new(12);
        let mut c0 = [0u8; N];
        c0[0] = 0b1111_0111; // bits 0-7 set except bit 3
        c0[1] = 0b0000_0100; // bit 10 set
        overlay.chunks.insert(0, c0);
        batch.apply_overlay(Arc::new(overlay));

        // Fast path keeps Base, extends length, applies chunks.
        assert!(matches!(batch, BitmapBatch::Base(_)));
        assert_eq!(batch.len(), 12);
        assert_eq!(batch.get_chunk(0)[0] & (1 << 3), 0);
        assert_ne!(batch.get_chunk(0)[1] & (1 << 2), 0);

        // Shared Arc -> slow path creates Layer.
        let BitmapBatch::Base(ref base_arc) = batch else {
            panic!("expected Base");
        };
        let _shared = Arc::clone(base_arc);
        let overlay2 = ChunkOverlay::new(12);
        batch.apply_overlay(Arc::new(overlay2));
        assert!(matches!(batch, BitmapBatch::Layer(_)));
    }
}
