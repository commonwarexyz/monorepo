//! Batch mutation API for Current QMDBs.
//!
//! Wraps the [`any::batch`] API, layering bitmap and grafted MMR
//! computation on top during [`Batch::merkleize()`].

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        authenticated::{self, ItemChain},
        contiguous::{Contiguous, Mutable},
    },
    mmr::{
        self,
        hasher::Hasher as _,
        read::{ChainInfo, MmrRead},
        storage::Storage as MmrStorage,
        Location, Position, StandardHasher,
    },
    qmdb::{
        any::{
            self,
            batch::OverlayEntry,
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
use std::collections::HashSet;

/// Adapter from sync [`MmrRead`] to async [`MmrStorage`].
struct MmrReadAdapter<'a, D: Digest, R: MmrRead<D>>(&'a R, core::marker::PhantomData<D>);

impl<'a, D: Digest, R: MmrRead<D>> MmrReadAdapter<'a, D, R> {
    const fn new(inner: &'a R) -> Self {
        Self(inner, core::marker::PhantomData)
    }
}

impl<D: Digest, R: MmrRead<D>> MmrStorage<D> for MmrReadAdapter<'_, D, R> {
    async fn size(&self) -> Position {
        self.0.size()
    }
    async fn get_node(&self, pos: Position) -> Result<Option<D>, mmr::Error> {
        Ok(self.0.get_node(pos))
    }
}

/// A Current QMDB batch that wraps an [`any::batch::Batch`].
///
/// Mutations are sync (delegated to the inner any batch). All bitmap and grafted
/// MMR work happens in [`merkleize()`](Batch::merkleize).
#[allow(clippy::type_complexity)]
pub struct Batch<'a, E, K, V, C, I, H, U, JP, const N: usize>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
    JP: authenticated::Batchable<H, Operation<K, V, U>>,
{
    /// The inner any::batch::Batch that handles mutations and journal stacking.
    inner: any::batch::Batch<'a, E, K, V, C, I, H, U, JP>,

    /// Reference to the current::db::Db for bitmap and grafted MMR access.
    current_db: &'a super::db::Db<E, C, I, H, U, N>,

    /// Parent's speculative bitmap. For top-level batches: clone of db.status.
    parent_bitmap: BitMap<N>,

    /// Parent's speculative grafted MMR. For top-level batches: clone of db.grafted_mmr.
    parent_grafted_mmr: mmr::mem::Mmr<H::Digest>,

    /// Dirty chunks inherited from a stacked parent.
    parent_dirty_chunks: HashSet<usize>,
}

/// A resolved and merkleized Current batch.
///
/// Wraps [`any::batch::MerkleizedBatch`] and adds the speculative bitmap,
/// grafted MMR, and canonical root.
#[allow(clippy::type_complexity)]
pub struct MerkleizedBatch<'a, E, K, V, C, I, H, U, P, const N: usize>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<K, V, U>>,
{
    /// The inner any::batch::MerkleizedBatch.
    inner: any::batch::MerkleizedBatch<'a, E, K, V, C, I, H, U, P>,

    /// Reference to the current::db::Db.
    current_db: &'a super::db::Db<E, C, I, H, U, N>,

    /// Speculative bitmap after this batch's operations.
    bitmap: BitMap<N>,

    /// Speculative grafted MMR after this batch's operations.
    grafted_mmr: mmr::mem::Mmr<H::Digest>,

    /// Dirty chunks accumulated through the batch chain.
    dirty_chunks: HashSet<usize>,

    /// The canonical root (ops_root + grafted_mmr_root + partial_chunk).
    canonical_root: H::Digest,
}

/// An owned, borrow-free finalized batch ready for [`super::db::Db::apply_batch()`].
pub struct FinalizedBatch<K, D: Digest, Item: Send, const N: usize> {
    /// The inner any::batch::FinalizedBatch.
    pub(super) inner: any::batch::FinalizedBatch<K, D, Item>,

    /// One bool per operation across the entire chain: true for
    /// Update/CommitFloor (active), false for Delete (inactive).
    pub(super) bitmap_pushes: Vec<bool>,

    /// Base-DB locations whose bits must be flipped to false.
    pub(super) bitmap_clears: Vec<Location>,

    /// Chunks that need grafted leaf recomputation during apply.
    pub(super) dirty_chunks: HashSet<usize>,
}

// ============================================================
// Batch: sync mutations + async merkleize
// ============================================================

impl<'a, E, K, V, C, I, H, U, JP, const N: usize> Batch<'a, E, K, V, C, I, H, U, JP, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
    JP: authenticated::Batchable<H, Operation<K, V, U>>,
{
    pub(super) const fn new(
        inner: any::batch::Batch<'a, E, K, V, C, I, H, U, JP>,
        current_db: &'a super::db::Db<E, C, I, H, U, N>,
        parent_bitmap: BitMap<N>,
        parent_grafted_mmr: mmr::mem::Mmr<H::Digest>,
        parent_dirty_chunks: HashSet<usize>,
    ) -> Self {
        Self {
            inner,
            current_db,
            parent_bitmap,
            parent_grafted_mmr,
            parent_dirty_chunks,
        }
    }

    /// Record a mutation. Sync -- delegates to the inner any batch.
    pub fn write(&mut self, key: K, value: Option<V::Value>) {
        self.inner.write(key, value);
    }
}

// Unordered get + merkleize.
impl<'a, E, K, V, C, I, H, JP, const N: usize>
    Batch<'a, E, K, V, C, I, H, update::Unordered<K, V>, JP, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V, update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, update::Unordered<K, V>>: Codec,
    V::Value: Send + Sync,
    JP: authenticated::Batchable<H, Operation<K, V, update::Unordered<K, V>>>,
{
    /// Read through: mutations -> parent overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }

    /// Resolve all mutations, perform floor raise, merkleize the ops journal,
    /// then compute the speculative bitmap, grafted MMR, and canonical root.
    pub async fn merkleize(
        self,
        metadata: Option<V::Value>,
    ) -> Result<MerkleizedBatch<'a, E, K, V, C, I, H, update::Unordered<K, V>, JP::Parent, N>, Error>
    {
        let current_db = self.current_db;
        let parent_bitmap = self.parent_bitmap;
        let parent_grafted_mmr = self.parent_grafted_mmr;
        let parent_dirty_chunks = self.parent_dirty_chunks;

        // Merkleize the inner any batch then compute current layer on top.
        let inner = self.inner.merkleize(metadata).await?;
        compute_current_layer(
            inner,
            current_db,
            parent_bitmap,
            parent_grafted_mmr,
            parent_dirty_chunks,
        )
        .await
    }
}

// Ordered get + merkleize.
impl<'a, E, K, V, C, I, H, JP, const N: usize>
    Batch<'a, E, K, V, C, I, H, update::Ordered<K, V>, JP, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V, update::Ordered<K, V>>>,
    I: crate::index::Ordered<Value = Location>,
    H: Hasher,
    Operation<K, V, update::Ordered<K, V>>: Codec,
    V::Value: Send + Sync,
    JP: authenticated::Batchable<H, Operation<K, V, update::Ordered<K, V>>>,
{
    /// Read through: mutations -> parent overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }

    /// Resolve all mutations, perform floor raise, merkleize the ops journal,
    /// then compute the speculative bitmap, grafted MMR, and canonical root.
    pub async fn merkleize(
        self,
        metadata: Option<V::Value>,
    ) -> Result<MerkleizedBatch<'a, E, K, V, C, I, H, update::Ordered<K, V>, JP::Parent, N>, Error>
    {
        let current_db = self.current_db;
        let parent_bitmap = self.parent_bitmap;
        let parent_grafted_mmr = self.parent_grafted_mmr;
        let parent_dirty_chunks = self.parent_dirty_chunks;

        // Merkleize the inner any batch then compute current layer on top.
        let inner = self.inner.merkleize(metadata).await?;
        compute_current_layer(
            inner,
            current_db,
            parent_bitmap,
            parent_grafted_mmr,
            parent_dirty_chunks,
        )
        .await
    }
}

/// Compute the Current layer (bitmap + grafted MMR + canonical root) on top of
/// a merkleized any batch.
async fn compute_current_layer<'a, E, K, V, U, C, I, H, P, const N: usize>(
    inner: any::batch::MerkleizedBatch<'a, E, K, V, C, I, H, U, P>,
    current_db: &'a super::db::Db<E, C, I, H, U, N>,
    mut bitmap: BitMap<N>,
    mut grafted_mmr: mmr::mem::Mmr<H::Digest>,
    mut dirty_chunks: HashSet<usize>,
) -> Result<MerkleizedBatch<'a, E, K, V, C, I, H, U, P, N>, Error>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<K, V, U>>,
{
    let old_grafted_leaves = *grafted_mmr.leaves() as usize;

    // Compute the absolute base location of this segment.
    let chain = inner.operation_chain();
    let this_segment = chain.last().expect("operation chain should not be empty");
    let segment_base = *inner.new_last_commit_loc() + 1 - this_segment.len() as u64;

    // Inactivate the previous commit (the operation just before this segment).
    // For top-level batches this is the base DB's commit; for stacked batches
    // this is the parent batch's CommitFloor.
    let prev_commit_loc = segment_base - 1;
    bitmap.set_bit(prev_commit_loc, false);
    let chunk = BitMap::<N>::to_chunk_index(prev_commit_loc);
    if chunk < old_grafted_leaves {
        dirty_chunks.insert(chunk);
    }

    // Walk this batch's operations and push bitmap bits.
    // For Updates, only push `true` if this is the final (active) position for the key.
    // If a floor-raise move superseded an earlier Update in the same segment, the
    // earlier one should be `false`.
    let overlay = inner.overlay();
    for (i, op) in this_segment.iter().enumerate() {
        let op_loc = Location::new(segment_base + i as u64);
        match op {
            Operation::Update(update) => {
                let key = update.key();
                let is_active = overlay.get(key).is_some_and(|entry| match entry {
                    OverlayEntry::Active { loc, .. } => *loc == op_loc,
                    _ => false,
                });
                bitmap.push(is_active);
            }
            Operation::CommitFloor(..) => bitmap.push(true),
            Operation::Delete(..) => bitmap.push(false),
        }
    }

    // Clear base_old_locs from overlay (superseded base-DB operations).
    for entry in overlay.values() {
        let old = match entry {
            OverlayEntry::Active {
                base_old_loc: Some(old),
                ..
            } => old,
            OverlayEntry::Deleted {
                base_old_loc: Some(old),
            } => old,
            _ => continue,
        };
        bitmap.set_bit(**old, false);
        let chunk = BitMap::<N>::to_chunk_index(**old);
        if chunk < old_grafted_leaves {
            dirty_chunks.insert(chunk);
        }
    }

    // Clear parent-segment locations that were superseded by this segment.
    // For each key whose final location is in this segment, check if it had
    // an earlier location in a parent segment (tracked in parent segments of the chain).
    // We can detect this by walking earlier segments.
    if chain.len() > 1 {
        let db_base = *current_db.any.last_commit_loc + 1;
        let mut parent_base = db_base;
        for parent_seg in &chain[..chain.len() - 1] {
            for (j, op) in parent_seg.iter().enumerate() {
                if let Some(key) = op.key() {
                    let parent_loc = Location::new(parent_base + j as u64);
                    // Check if the merged overlay has a different (later) location for this key.
                    if let Some(entry) = overlay.get(key) {
                        let final_loc = match entry {
                            OverlayEntry::Active { loc, .. } => Some(*loc),
                            OverlayEntry::Deleted { .. } => None,
                        };
                        if final_loc != Some(parent_loc) {
                            // This parent-segment op was superseded.
                            bitmap.set_bit(*parent_loc, false);
                            let chunk = BitMap::<N>::to_chunk_index(*parent_loc);
                            if chunk < old_grafted_leaves {
                                dirty_chunks.insert(chunk);
                            }
                        }
                    }
                }
            }
            parent_base += parent_seg.len() as u64;
        }
    }

    // Compute grafted leaves for dirty + new chunks.
    let new_grafted_leaves = bitmap.complete_chunks();
    let chunks_to_update = (old_grafted_leaves..new_grafted_leaves)
        .chain(dirty_chunks.iter().copied())
        .map(|i| (i, *bitmap.get_chunk(i)));

    let ops_mmr_adapter = MmrReadAdapter::new(inner.journal_merkleized());
    let mut hasher = StandardHasher::<H>::new();
    let grafted_leaves = compute_grafted_leaves::<H, N>(
        &mut hasher,
        &ops_mmr_adapter,
        chunks_to_update,
        current_db.thread_pool.as_ref(),
    )
    .await?;

    // Update grafted MMR.
    let grafting_height = grafting::height::<N>();
    if !grafted_leaves.is_empty() {
        let changeset = {
            let mut batch = grafted_mmr
                .new_batch()
                .with_pool(current_db.thread_pool.clone());
            for &(ops_pos, digest) in &grafted_leaves {
                let grafted_pos = grafting::ops_to_grafted_pos(ops_pos, grafting_height);
                if grafted_pos < batch.size() {
                    let loc = Location::try_from(grafted_pos).expect("grafted_pos overflow");
                    batch
                        .update_leaf_digest(loc, digest)
                        .expect("update_leaf_digest failed");
                } else {
                    batch.add_leaf_digest(digest);
                }
            }
            let mut grafted_hasher = grafting::GraftedHasher::new(hasher.fork(), grafting_height);
            batch.merkleize(&mut grafted_hasher).finalize()
        };
        grafted_mmr.apply(changeset);
    }

    // Compute canonical root.
    let ops_root = inner.root();
    let grafted_storage = grafting::Storage::new(&grafted_mmr, grafting_height, &ops_mmr_adapter);
    let partial = partial_chunk(&bitmap);
    let canonical_root =
        compute_db_root::<H, _, N>(&mut hasher, &grafted_storage, partial, &ops_root).await?;

    Ok(MerkleizedBatch {
        inner,
        current_db,
        bitmap,
        grafted_mmr,
        dirty_chunks,
        canonical_root,
    })
}

// ============================================================
// MerkleizedBatch: root, get, new_batch, finalize
// ============================================================

impl<'a, E, K, V, C, I, H, U, P, const N: usize> MerkleizedBatch<'a, E, K, V, C, I, H, U, P, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<K, V, U>>,
{
    /// Return the canonical root (ops root + grafted MMR root + partial chunk).
    pub const fn root(&self) -> H::Digest {
        self.canonical_root
    }

    /// Return the ops-only MMR root.
    pub fn ops_root(&self) -> H::Digest {
        self.inner.root()
    }

    /// Create a child batch that sees this batch's state.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(
        &self,
    ) -> Batch<
        '_,
        E,
        K,
        V,
        C,
        I,
        H,
        U,
        authenticated::MerkleizedBatch<'a, H, P, Operation<K, V, U>>,
        N,
    > {
        Batch {
            inner: self.inner.new_batch(),
            current_db: self.current_db,
            parent_bitmap: self.bitmap.clone(),
            parent_grafted_mmr: self.grafted_mmr.clone(),
            parent_dirty_chunks: self.dirty_chunks.clone(),
        }
    }
}

// Unordered get.
impl<'a, E, K, V, C, I, H, P, const N: usize>
    MerkleizedBatch<'a, E, K, V, C, I, H, update::Unordered<K, V>, P, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<K, V, update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, update::Unordered<K, V>>: Codec,
    V::Value: Send + Sync,
    P: MmrRead<H::Digest>
        + ChainInfo<H::Digest>
        + ItemChain<Operation<K, V, update::Unordered<K, V>>>,
{
    /// Read through: overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }
}

// Ordered get.
impl<'a, E, K, V, C, I, H, P, const N: usize>
    MerkleizedBatch<'a, E, K, V, C, I, H, update::Ordered<K, V>, P, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<K, V, update::Ordered<K, V>>>,
    I: crate::index::Ordered<Value = Location>,
    H: Hasher,
    Operation<K, V, update::Ordered<K, V>>: Codec,
    V::Value: Send + Sync,
    P: MmrRead<H::Digest>
        + ChainInfo<H::Digest>
        + ItemChain<Operation<K, V, update::Ordered<K, V>>>,
{
    /// Read through: overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        self.inner.get(key).await
    }
}

// Finalize (requires Mutable journal for apply_batch).
impl<'a, E, K, V, C, I, H, U, P, const N: usize> MerkleizedBatch<'a, E, K, V, C, I, H, U, P, N>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync + 'static,
    C: Mutable<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
    P: MmrRead<H::Digest> + ChainInfo<H::Digest> + ItemChain<Operation<K, V, U>>,
{
    /// Consume this batch, producing an owned [`FinalizedBatch`].
    pub fn finalize(self) -> FinalizedBatch<K, H::Digest, Operation<K, V, U>, N> {
        let chain = self.inner.operation_chain();
        let overlay = self.inner.overlay();
        let db_base = *self.current_db.any.last_commit_loc + 1;

        // Compute bitmap_pushes: one bool per operation across the entire chain.
        // For Updates, only `true` if this is the final (active) location for its key.
        let mut bitmap_pushes = Vec::new();
        let mut seg_base = db_base;
        for segment in chain {
            for (i, op) in segment.iter().enumerate() {
                let op_loc = Location::new(seg_base + i as u64);
                match op {
                    Operation::Update(update) => {
                        let key = update.key();
                        let is_active = overlay.get(key).is_some_and(|entry| match entry {
                            OverlayEntry::Active { loc, .. } => *loc == op_loc,
                            _ => false,
                        });
                        bitmap_pushes.push(is_active);
                    }
                    Operation::CommitFloor(..) => {
                        // Only the final CommitFloor is active. Intermediate
                        // commits from parent batches are superseded.
                        let is_final = op_loc == self.inner.new_last_commit_loc();
                        bitmap_pushes.push(is_final);
                    }
                    Operation::Delete(..) => bitmap_pushes.push(false),
                }
            }
            seg_base += segment.len() as u64;
        }

        // Collect bitmap_clears: base_old_locs from overlay.
        let mut bitmap_clears = Vec::new();
        for entry in overlay.values() {
            match entry {
                OverlayEntry::Active {
                    base_old_loc: Some(old),
                    ..
                }
                | OverlayEntry::Deleted {
                    base_old_loc: Some(old),
                } => {
                    bitmap_clears.push(*old);
                }
                _ => {}
            }
        }

        FinalizedBatch {
            inner: self.inner.finalize(),
            bitmap_pushes,
            bitmap_clears,
            dirty_chunks: self.dirty_chunks,
        }
    }
}
