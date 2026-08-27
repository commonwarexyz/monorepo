//! Batch mutation API for Current QMDBs.
//!
//! Wraps the [`any::batch`] API.

use crate::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    merkle::{
        self, Graftable, Location, Position, Readable,
        batch::MerkleizedBatch as GenericMerkleizedBatch, mem::Mem,
        storage::Storage as MerkleStorage,
    },
    qmdb::{
        Error,
        any::{
            self, ValueEncoding,
            batch::{DiffCursors, DiffEntry, Staged as AnyStaged, StagedUpdates},
            operation::{Operation, update},
        },
        batch_chain::{Bounds, OnChain},
        current::{
            db::{compute_db_root, partial_chunk, read_graft_inputs},
            grafting,
        },
        operation::Key,
    },
};
use ahash::AHashMap;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::bitmap::{self, Readable as _};
use core::ops::Range;
use std::sync::Arc;

/// Speculative chunk-level bitmap overlay.
///
/// Instead of tracking individual pushed bits and cleared locations, maintains materialized chunk
/// bytes for every chunk that differs from the parent bitmap. This directly produces the chunk data
/// needed for grafted MMR leaf computation.
#[derive(Clone, Debug, Default)]
pub(crate) struct ChunkOverlay<const N: usize> {
    /// Dirty chunks: chunk_idx -> materialized chunk bytes.
    ///
    /// Iteration order is not observed by any consumer.
    pub(crate) chunks: AHashMap<usize, [u8; N]>,
    /// Total number of bits (parent + new operations).
    pub(crate) len: u64,
    /// The parent bitmap's dimensions, captured at construction.
    parent: Dimensions,
}

/// Parent-bitmap dimensions captured once per overlay. `chunk_mut` needs them on every newly
/// materialized chunk, so they are read once instead of per touched chunk. `len` also records
/// the committed length the overlay was built on (see `BitmapView::trim_committed`).
#[derive(Clone, Copy, Debug, Default)]
struct Dimensions {
    len: u64,
    complete_chunks: usize,
    pruned_chunks: usize,
}

impl Dimensions {
    fn of<B: bitmap::Readable<N>, const N: usize>(base: &B) -> Self {
        Self {
            len: base.len(),
            complete_chunks: base.complete_chunks(),
            pruned_chunks: base.pruned_chunks(),
        }
    }
}

impl<const N: usize> ChunkOverlay<N> {
    const CHUNK_BITS: u64 = bitmap::Prunable::<N>::CHUNK_SIZE_BITS;

    /// Create an overlay of `len` total bits on top of `base`. The `base` handed to later
    /// `set_bit` / `clear_bit` / `chunk_mut` calls must be the bitmap given here.
    fn new<B: bitmap::Readable<N>>(base: &B, len: u64, capacity: usize) -> Self {
        Self {
            chunks: AHashMap::with_capacity(capacity),
            len,
            parent: Dimensions::of(base),
        }
    }

    /// Load-or-create a chunk: returns a mutable reference to the materialized chunk bytes. On
    /// first access for an existing chunk, reads from `base`.
    fn chunk_mut<B: bitmap::Readable<N>>(&mut self, base: &B, idx: usize) -> &mut [u8; N] {
        let parent = self.parent;
        self.chunks.entry(idx).or_insert_with(|| {
            let base_has_partial = !parent.len.is_multiple_of(Self::CHUNK_BITS);
            if idx < parent.complete_chunks {
                base.get_chunk(idx)
            } else if idx == parent.complete_chunks && base_has_partial {
                base.last_chunk().0
            } else {
                bitmap::BitMap::<N>::EMPTY_CHUNK
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

    /// Clear a single bit (used for superseded locations). Skips locations in pruned chunks
    /// since those bits are already inactive.
    fn clear_bit<B: bitmap::Readable<N>>(&mut self, base: &B, loc: u64) {
        let idx = bitmap::Prunable::<N>::to_chunk_index(loc);
        if idx < self.parent.pruned_chunks {
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

/// Adapter that resolves ops MMR nodes for a batch's `compute_current_layer`.
///
/// Tries the batch chain's sync [`Readable`] first (which covers nodes appended or overwritten
/// by the batch, plus anything still in the in-memory MMR). Falls through to the base's async
/// [`MerkleStorage`].
struct BatchStorageAdapter<
    'a,
    F: Graftable,
    D: Digest,
    R: Readable<Family = F, Digest = D>,
    S: MerkleStorage<Family = F, Digest = D>,
> {
    batch: &'a R,
    base: &'a S,
    _phantom: core::marker::PhantomData<(F, D)>,
}

impl<
    'a,
    F: Graftable,
    D: Digest,
    R: Readable<Family = F, Digest = D>,
    S: MerkleStorage<Family = F, Digest = D>,
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
    R: Readable<Family = F, Digest = D>,
    S: MerkleStorage<Family = F, Digest = D>,
> MerkleStorage for BatchStorageAdapter<'_, F, D, R, S>
{
    type Family = F;
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.batch.size()
    }
    async fn get_node(&self, pos: Position<F>) -> Result<Option<D>, merkle::Error<F>> {
        if let Some(node) = self.batch.get_node(pos) {
            return Ok(Some(node));
        }
        self.base.get_node(pos).await
    }

    async fn get_nodes(&self, positions: &[Position<F>]) -> Result<Vec<D>, merkle::Error<F>> {
        let mut nodes = vec![None; positions.len()];
        let mut base_positions = Vec::with_capacity(positions.len());

        // Look up nodes already in the batch chain.
        for (slot, &pos) in nodes.iter_mut().zip(positions) {
            match self.batch.get_node(pos) {
                Some(node) => *slot = Some(node),
                None => base_positions.push(pos),
            }
        }

        // Look up remaining nodes from the base.
        let base_nodes = if base_positions.is_empty() {
            Vec::new()
        } else {
            self.base.get_nodes(&base_positions).await?
        };
        let mut base_nodes = base_nodes.into_iter();
        Ok(nodes
            .into_iter()
            .map(|node| node.unwrap_or_else(|| base_nodes.next().expect("one node per base read")))
            .collect())
    }
}

/// Layers a [`GenericMerkleizedBatch`] over a [`Mem`] for node resolution.
///
/// [`GenericMerkleizedBatch::get_node`] only covers the batch chain; committed positions
/// return `None`. This adapter falls through to the committed Mem for those positions.
struct BatchOverMem<'a, F: Graftable, D: Digest, S: Strategy> {
    batch: &'a GenericMerkleizedBatch<F, D, S>,
    mem: &'a Mem<F, D>,
}

impl<F: Graftable, D: Digest, S: Strategy> Readable for BatchOverMem<'_, F, D, S> {
    type Family = F;
    type Digest = D;

    fn size(&self) -> Position<F> {
        self.batch.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        if let Some(d) = self.batch.get_node(pos) {
            return Some(d);
        }
        self.mem.get_node(pos)
    }
}

/// A speculative batch of mutations whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Wraps a [`any::batch::UnmerkleizedBatch`] and adds bitmap and grafted MMR parent state
/// needed to compute the current layer during [`merkleize`](Self::merkleize).
pub struct UnmerkleizedBatch<F, H, U, const N: usize, S: Strategy>
where
    F: Graftable,
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// The inner any-layer batch that handles mutations, journal, and floor raise.
    inner: any::batch::UnmerkleizedBatch<F, H, U, S>,

    /// Parent's grafted MMR state.
    grafted_parent: Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,

    /// Parent's bitmap overlays, oldest first (see [`BitmapView`]).
    bitmap_parent: Overlays<N>,
}

/// Staged batch returned by [`UnmerkleizedBatch::stage`].
pub struct Staged<F, H, U, const N: usize, S: Strategy>
where
    F: Graftable,
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    inner: AnyStaged<F, H, U, S>,
    grafted_parent: Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,
    bitmap_parent: Overlays<N>,
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
/// Reads through this batch, constructing child batches from it, and applying it later are
/// only semantically correct while its ancestor chain is still the committed prefix of the DB. In
/// other words, every successful [`apply_batch`](super::db::Db::apply_batch) since this batch was
/// merkleized must have applied an ancestor of this batch.
///
/// Once a non-ancestor batch is applied, this batch and all of its descendants are stale.
/// Reading through or merkleizing them refuses with [`Error::StaleRead`], and applying them
/// is rejected with [`Error::StaleBatch`] without mutating committed state (see
/// [`crate::qmdb::batch_chain`]).
///
/// Building a child off a batch that `apply_batch` has consumed (the just-applied
/// parent) is valid. The committed bitmap then equals the parent's post-apply state,
/// so child reads are consistent.
pub struct MerkleizedBatch<F: Graftable, D: Digest, U: update::Update, const N: usize, S: Strategy>
{
    /// Inner any-layer batch (ops MMR, diff, floor, commit loc, sizes).
    pub(crate) inner: Arc<any::batch::MerkleizedBatch<F, D, U, S>>,

    /// Grafted MMR state.
    pub(crate) grafted: Arc<merkle::batch::MerkleizedBatch<F, D, S>>,

    /// This batch's bitmap overlays, oldest first (see [`BitmapView`]).
    pub(crate) bitmap: Overlays<N>,

    /// The canonical root (ops root + grafted root + partial chunk).
    pub(crate) canonical_root: D,
}

impl<F, H, U, const N: usize, S: Strategy> UnmerkleizedBatch<F, H, U, N, S>
where
    F: Graftable,
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    pub(super) const fn new(
        inner: any::batch::UnmerkleizedBatch<F, H, U, S>,
        grafted_parent: Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,
        bitmap_parent: Overlays<N>,
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

    /// Read through: mutations -> ancestor diffs -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &U::Key,
        db: &super::db::Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Option<U::Value>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.inner.get(key, &db.any).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys. Resolved locations are not retained,
    /// so writing a key read only through `get_many` requires an index re-probe and journal re-read
    /// during merkleize. Use [`stage`](Self::stage) for keys that may be written. When the writable
    /// subset is known and much smaller than the full read set, call `get_many` for the read-only
    /// keys first, then [`stage`](Self::stage) only the writable keys.
    pub async fn get_many<E, C, I>(
        &self,
        keys: &[&U::Key],
        db: &super::db::Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Vec<Option<U::Value>>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.inner.get_many(keys, &db.any).await
    }

    /// Batch read multiple keys and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys. The staged batch records updates by
    /// read index: the initial keys occupy `0..keys.len()`, and each [`expand`](Staged::expand)
    /// appends another index range.
    pub async fn stage<E, C, I>(
        self,
        keys: &[&U::Key],
        db: &super::db::Db<F, E, C, I, H, U, N, S>,
    ) -> Result<(Vec<Option<U::Value>>, Staged<F, H, U, N, S>), Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        let (values, inner) = inner.stage(keys, &db.any).await?;
        Ok((
            values,
            Staged {
                inner,
                grafted_parent,
                bitmap_parent,
            },
        ))
    }
}

impl<F, H, U, const N: usize, S: Strategy> Staged<F, H, U, N, S>
where
    F: Graftable,
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Expand this staged batch with more reads.
    ///
    /// Existing read indices remain stable. Newly read keys are appended to the staged read set and
    /// assigned the returned range. The returned values are in the same order as `keys`.
    ///
    /// Expansion does not deduplicate against previously staged keys and does not observe values the
    /// caller has computed for earlier staged slots but not yet passed to
    /// [`merkleize`](Staged::merkleize).
    pub async fn expand<E, C, I>(
        self,
        keys: &[&U::Key],
        db: &super::db::Db<F, E, C, I, H, U, N, S>,
    ) -> Result<(Range<usize>, Vec<Option<U::Value>>, Self), Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        let (range, values, inner) = inner.expand(keys, &db.any).await?;
        Ok((
            range,
            values,
            Self {
                inner,
                grafted_parent,
                bitmap_parent,
            },
        ))
    }
}

impl<F, K, V, H, const N: usize, S: Strategy> Staged<F, H, update::Unordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](Staged::expand) before this
    /// method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](Staged::expand) ranges. `metadata`
    /// is committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.current.unordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(updates = updates.len() as u64, upserts = upserts.len() as u64),
    )]
    pub async fn merkleize<E, C, I>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        metadata: Option<V::Value>,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
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

        let db_any = inner.on_chain(&db.any)?;
        let bitmap_parent = BitmapView::over(bitmap_parent, &db.any.bitmap)
            .trim_committed()
            .ok_or(Error::StaleRead)?;

        // Overlap the update resolution with a committed-prefix candidate prefetch.
        // Candidates come from the speculative `bitmap_parent` (the same bitmap the floor
        // raise scans below), clamped to the committed prefix by `resolve_updates_prefetched`.
        let (inner, staged_updates, prefetched) = inner
            .resolve_updates_prefetched(updates, upserts, db_any, &bitmap_parent)
            .await?;
        let inner = inner
            .merkleize_with_floor_scan(
                db_any,
                metadata,
                staged_updates,
                Some(prefetched),
                &bitmap_parent,
            )
            .await?;
        let current_db = inner.bounds().on_chain(db, db.any.commitment())?;
        compute_current_layer(inner, current_db, &grafted_parent, bitmap_parent).await
    }
}

impl<F, K, V, H, const N: usize, S: Strategy> Staged<F, H, update::Ordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](Staged::expand) before this
    /// method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](Staged::expand) ranges. `metadata`
    /// is committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.current.ordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(updates = updates.len() as u64, upserts = upserts.len() as u64),
    )]
    pub async fn merkleize<E, C, I>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        metadata: Option<V::Value>,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
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
        let db_any = inner.on_chain(&db.any)?;
        let bitmap_parent = BitmapView::over(bitmap_parent, &db.any.bitmap)
            .trim_committed()
            .ok_or(Error::StaleRead)?;
        let (inner, staged_updates) = inner.resolve_updates(updates, upserts, db.any.strategy());
        let inner = inner
            .merkleize_with_floor_scan(db_any, metadata, staged_updates, &bitmap_parent)
            .await?;
        let current_db = inner.bounds().on_chain(db, db.any.commitment())?;
        compute_current_layer(inner, current_db, &grafted_parent, bitmap_parent).await
    }
}

// Unordered merkleize.
impl<F, K, V, H, const N: usize, S: Strategy> UnmerkleizedBatch<F, H, update::Unordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.current.unordered.batch.merkleize",
        level = "info",
        skip_all
    )]
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
        let db_any = inner.on_chain(&db.any)?;
        let bitmap_parent = BitmapView::over(bitmap_parent, &db.any.bitmap)
            .trim_committed()
            .ok_or(Error::StaleRead)?;
        // Use the speculative parent bitmap rather than the committed `any` bitmap.
        let inner = inner
            .merkleize_with_floor_scan(
                db_any,
                metadata,
                StagedUpdates::<F, update::Unordered<K, V>>::new(),
                None,
                &bitmap_parent,
            )
            .await?;
        let current_db = inner.bounds().on_chain(db, db.any.commitment())?;
        compute_current_layer(inner, current_db, &grafted_parent, bitmap_parent).await
    }
}

// Ordered merkleize.
impl<F, K, V, H, const N: usize, S: Strategy> UnmerkleizedBatch<F, H, update::Ordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.current.ordered.batch.merkleize",
        level = "info",
        skip_all
    )]
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
        let db_any = inner.on_chain(&db.any)?;
        let bitmap_parent = BitmapView::over(bitmap_parent, &db.any.bitmap)
            .trim_committed()
            .ok_or(Error::StaleRead)?;
        // Use the speculative parent bitmap rather than the committed `any` bitmap.
        let inner = inner
            .merkleize_with_floor_scan(
                db_any,
                metadata,
                StagedUpdates::<F, update::Ordered<K, V>>::new(),
                &bitmap_parent,
            )
            .await?;
        let current_db = inner.bounds().on_chain(db, db.any.commitment())?;
        compute_current_layer(inner, current_db, &grafted_parent, bitmap_parent).await
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
    let appended_chunks = (batch_len as u64).div_ceil(ChunkOverlay::<N>::CHUNK_BITS) as usize;
    let mut overlay = ChunkOverlay::new(base, total_bits, diff.len() + appended_chunks + 1);

    // 1. CommitFloor (last op) is always active.
    let commit_loc = batch_base + batch_len as u64 - 1;
    overlay.set_bit(base, commit_loc);

    // 2. Inactivate previous CommitFloor.
    overlay.clear_bit(base, batch_base - 1);

    // 3. Set active bits + clear superseded locations from the diff. The diff is key-sorted,
    // so ancestor resolution streams (one cursor per ancestor diff).
    let mut ancestors = DiffCursors::new(ancestor_diffs.iter().map(|d| d.as_slice()));
    for (key, entry) in diff {
        // Set the active bit for this key's final location.
        if let Some(loc) = entry.loc()
            && *loc >= batch_base
            && *loc < batch_base + batch_len as u64
        {
            overlay.set_bit(base, *loc);
        }

        // Clear the most recent superseded location. Older locations were already cleared by the
        // ancestor batch that superseded them.
        let mut prev_loc = entry.base_old_loc();
        if let Some(ancestor_entry) = ancestors.resolve(key) {
            prev_loc = ancestor_entry.loc();
        }
        if let Some(old) = prev_loc {
            overlay.clear_bit(base, *old);
        }
    }

    // Ensure all new complete chunks beyond the parent are materialized, so downstream consumers
    // don't read from the parent and panic on out-of-range indices. Uses chunk_mut to inherit the
    // parent's partial chunk data when idx == parent_complete (avoiding loss of existing bits).
    let parent_complete = overlay.parent.complete_chunks;
    let new_complete = overlay.complete_chunks();
    for idx in parent_complete..new_complete {
        overlay.chunk_mut(base, idx);
    }

    overlay
}

/// Merkleize grafted chunk digests while retaining the live ancestor chain.
async fn merkleize_grafted_batch<F, H, S, const N: usize>(
    strategy: &S,
    grafted_parent: Arc<GenericMerkleizedBatch<F, H::Digest, S>>,
    grafted_tree: &Arc<Mem<F, H::Digest>>,
    graft_inputs: Vec<(usize, H::Digest, [u8; N])>,
    grafting_height: u32,
) -> Arc<GenericMerkleizedBatch<F, H::Digest, S>>
where
    F: Graftable,
    H: Hasher,
    S: Strategy,
{
    let old_grafted_leaves = *grafted_parent.leaves() as usize;
    let mut grafted_batch = grafted_parent.new_batch();
    let ancestors = grafted_batch.retain_ancestors();
    let grafted_tree = Arc::clone(grafted_tree);
    strategy
        .clone()
        .spawn(move |strategy| {
            let new_leaves = grafting::graft_chunk_digests::<H, _, N>(&strategy, graft_inputs);
            for (chunk_idx, digest) in new_leaves {
                if chunk_idx < old_grafted_leaves {
                    grafted_batch = grafted_batch
                        .update_leaf_digest(Location::<F>::new(chunk_idx as u64), digest)
                        .expect("update_leaf_digest failed");
                } else {
                    grafted_batch = grafted_batch.add_leaf_digest(digest);
                }
            }
            let grafted_hasher = grafting::hasher::<F, H>(grafting_height);
            let merkleized = grafted_batch.merkleize(&grafted_tree, &grafted_hasher);
            drop(ancestors);
            merkleized
        })
        .await
}

/// Compute the current layer (bitmap + grafted MMR + canonical root) on top of a merkleized any
/// batch.
///
/// Builds a chunk overlay from the diff, computes grafted MMR leaves from dirty chunks, and
/// produces the `Arc<MerkleizedBatch>` directly.
#[allow(clippy::type_complexity)]
async fn compute_current_layer<F, E, U, C, I, H, const N: usize, S>(
    inner: Arc<any::batch::MerkleizedBatch<F, H::Digest, U, S>>,
    current_db: OnChain<'_, super::db::Db<F, E, C, I, H, U, N, S>>,
    grafted_parent: &Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,
    mut bitmap: BitmapView<'_, N>,
) -> Result<Arc<MerkleizedBatch<F, H::Digest, U, N, S>>, Error<F>>
where
    F: Graftable,
    E: Context,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: update::Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    let batch_len = inner.journal_batch.items().len();
    let batch_base = *inner.bounds.tip.size - batch_len as u64;

    // Build chunk overlay: materialized bytes for every dirty chunk.
    let overlay = build_chunk_overlay::<F, U, _, N>(
        &bitmap,
        batch_len,
        batch_base,
        &inner.diff,
        &inner.ancestor_diffs,
    );

    let grafting_height = grafting::height::<N>();
    let ops_tree_adapter =
        BatchStorageAdapter::new(&inner.journal_batch, &current_db.any.log.merkle);

    // Snapshot ops_leaves for the post-batch state (the canonical root we're about to compute
    // sees this many ops). Thread it through `graftable_chunks` derivation and root computation.
    let overlay_ops_leaves = inner.bounds.tip.size;

    // Distinguish three counters:
    //   - new_complete_chunks: chunks with all bits filled in the post-batch bitmap
    //   - graftable_overlay:      chunks committed by the grafted tree (have a single h=G ancestor)
    //   - graftable_parent:       grafted-tree leaf count from the parent (structural source of truth)
    //
    // The pending chunk (if any) sits at index `graftable_overlay` and is excluded from the
    // grafted tree; its digest is hashed directly into the canonical root.
    let new_complete_chunks = overlay.complete_chunks();
    let graftable_overlay = grafting::graftable_chunks::<F>(*overlay_ops_leaves, grafting_height)
        .min(new_complete_chunks as u64) as usize;
    let graftable_parent = *grafted_parent.leaves() as usize;
    let pruned_chunks = bitmap.pruned_chunks();
    assert!(
        pruned_chunks <= graftable_parent
            && graftable_parent <= graftable_overlay
            && graftable_overlay <= new_complete_chunks,
        "invariant violated: pruned={pruned_chunks} graftable_parent={graftable_parent} graftable_overlay={graftable_overlay} new_complete={new_complete_chunks}"
    );

    // Build the set of chunk indices whose grafted-leaf needs (re)computing:
    //   1) Dirty chunks (bits changed in this batch) within the graftable range.
    //   2) Pending -> graftable transitions: chunks newly graftable because the ops tree built
    //      their h=G ancestor in this batch. Their bitmap bytes may not be dirty (the chunk
    //      became graftable via ops growth alone) but they need a grafted-leaf entry now.
    let mut chunk_indices_to_update: Vec<usize> = overlay
        .chunks
        .iter()
        .filter(|&(&idx, _)| idx < graftable_overlay && idx >= pruned_chunks)
        .map(|(&idx, _)| idx)
        .collect();
    chunk_indices_to_update.extend(graftable_parent..graftable_overlay);
    chunk_indices_to_update.sort_unstable();
    chunk_indices_to_update.dedup();
    let chunks_to_update = chunk_indices_to_update.into_iter().map(|idx| {
        let chunk = overlay
            .get(idx)
            .copied()
            .unwrap_or_else(|| bitmap.get_chunk(idx));
        (idx, chunk)
    });

    // Prefetch each chunk's covering ops-tree node, then run graft hashing and the grafted
    // MMR build/merkleize as one job on the strategy (against a snapshot of the committed
    // grafted tree) instead of occupying the calling task. An empty graft set hashes
    // nothing, so it merkleizes inline rather than paying for a job handoff.
    let graft_inputs = read_graft_inputs::<F, _, N>(&ops_tree_adapter, chunks_to_update).await?;
    let grafted_batch = if graft_inputs.is_empty() {
        let grafted_hasher = grafting::hasher::<F, H>(grafting_height);
        grafted_parent
            .new_batch()
            .merkleize(&current_db.grafted_tree, &grafted_hasher)
    } else {
        merkleize_grafted_batch::<F, H, S, N>(
            &current_db.strategy,
            Arc::clone(grafted_parent),
            &current_db.grafted_tree,
            graft_inputs,
            grafting_height,
        )
        .await
    };

    // Layer this batch's overlay on before computing the canonical root, so that
    // compute_db_root sees newly completed chunks. The parent alone would miss chunks that
    // transitioned from partial to complete in this batch.
    bitmap.overlays.push(Arc::new(overlay));

    // Compute canonical root. The grafted batch alone cannot resolve committed nodes,
    // so layer it over the committed grafted MMR.
    let ops_root = inner.root();
    let layered = BatchOverMem {
        batch: &grafted_batch,
        mem: &current_db.grafted_tree,
    };
    let grafted_storage =
        grafting::Storage::<F, H, _, _>::new(&layered, grafting_height, &ops_tree_adapter);
    // Compute partial chunk (last incomplete chunk, if any). The partial chunk lives at
    // index `new_complete_chunks` (the chunk currently being filled with bits) -- distinct
    // from `graftable_overlay` (the grafted-tree boundary). At gh >= 3, partial and pending can
    // coexist; this branch only handles partial. The pending chunk (when present) is read
    // from the bitmap inside `compute_db_root` via `pending_chunk()`.
    let partial = partial_chunk::<_, N>(&bitmap);
    let canonical_root = compute_db_root::<F, H, _, _, N>(
        &bitmap,
        &grafted_storage,
        overlay_ops_leaves,
        partial,
        inner.bounds.inactivity_floor,
        &ops_root,
    )
    .await?;

    Ok(Arc::new(MerkleizedBatch {
        inner,
        grafted: grafted_batch,
        bitmap: bitmap.overlays,
        canonical_root,
    }))
}

/// A batch's speculative bitmap overlays, oldest first. Read through [`BitmapView`].
pub(crate) type Overlays<const N: usize> = Vec<Arc<ChunkOverlay<N>>>;

/// A batch's bitmap: `overlays` read over `committed`, the database bitmap they were built on.
/// A chunk comes from the newest overlay that materialized it, else from the committed bitmap.
///
/// The view performs no validity check of its own. Its committed-read consumers run behind the
/// batch-chain gate (see [`crate::qmdb::batch_chain`]), which refuses stale batches before they
/// read through it.
#[derive(Debug)]
pub(crate) struct BitmapView<'a, const N: usize> {
    overlays: Overlays<N>,
    committed: &'a bitmap::Prunable<N>,
}

impl<'a, const N: usize> BitmapView<'a, N> {
    const CHUNK_SIZE_BITS: u64 = bitmap::Prunable::<N>::CHUNK_SIZE_BITS;

    pub(crate) const fn over(overlays: Overlays<N>, committed: &'a bitmap::Prunable<N>) -> Self {
        Self {
            overlays,
            committed,
        }
    }

    /// Drop the overlays the committed bitmap already contains. Returns `None` when the oldest
    /// remaining overlay was not built on the committed bitmap: a rewind onto an ancestor state
    /// removed an applied overlay from under it, so reads would mix two bitmaps.
    fn trim_committed(mut self) -> Option<Self> {
        let committed = self.committed.len();
        self.overlays.retain(|overlay| overlay.len > committed);
        if self
            .overlays
            .first()
            .is_some_and(|overlay| overlay.parent.len != committed)
        {
            return None;
        }
        Some(self)
    }
}

impl<const N: usize> bitmap::Readable<N> for BitmapView<'_, N> {
    fn complete_chunks(&self) -> usize {
        (self.len() / Self::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        self.overlays
            .iter()
            .rev()
            .find_map(|overlay| overlay.get(idx).copied())
            .unwrap_or_else(|| *self.committed.get_chunk(idx))
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let total = self.len();
        if total == 0 {
            return (bitmap::BitMap::<N>::EMPTY_CHUNK, 0);
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
        self.committed.pruned_chunks()
    }

    fn len(&self) -> u64 {
        self.overlays
            .last()
            .map_or_else(|| self.committed.len(), |overlay| overlay.len)
    }
}

impl<F: Graftable, D: Digest, U: update::Update, const N: usize, S: Strategy>
    MerkleizedBatch<F, D, U, N, S>
{
    /// Return the canonical root.
    pub const fn root(&self) -> D {
        self.canonical_root
    }

    /// Return the QMDB ops-only root.
    pub fn ops_root(&self) -> D {
        self.inner.root()
    }

    /// Return the [`Bounds`] of the batch.
    pub fn bounds(&self) -> &Bounds<F, D> {
        self.inner.bounds()
    }

    /// Return the batch's safe sync boundary.
    ///
    /// This equals the boundary [`super::db::Db::sync_boundary`] reports once this batch is applied.
    pub fn sync_boundary(&self) -> Location<F> {
        // Derive from the commit's chunk-aligned inactivity floor, the same quantity the DB uses
        // after apply. Deliberately not the physical bitmap pruning boundary, which can lag the
        // inactivity floor when pruning has not run.
        super::db::sync_boundary::<F, N>(
            *self.inner.bounds().inactivity_floor / bitmap::Prunable::<N>::CHUNK_SIZE_BITS,
            *self.inner.bounds().tip.size,
        )
    }
}

impl<F: Graftable, D: Digest, U: update::Update, const N: usize, S: Strategy>
    MerkleizedBatch<F, D, U, N, S>
where
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    ///
    /// All uncommitted ancestors in the chain must be kept alive until the child (or any
    /// descendant of it) is merkleized.
    ///
    /// Creating a child from a stale parent is allowed. The child's reads, merkleization,
    /// and apply are refused ([`Error::StaleRead`], [`Error::StaleBatch`]) while the
    /// database remains off this chain's states.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, U, N, S>
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
    ///
    /// Refuses with [`Error::StaleRead`] if a non-ancestor batch was applied since `self`
    /// was merkleized.
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
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: update::Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Create an initial [`MerkleizedBatch`] from the current committed DB state.
    ///
    /// The returned batch is rooted at the current committed prefix, but it is not a persistent
    /// snapshot across later divergent commits. If some other branch is applied afterward,
    /// reading through it (or a descendant of it) refuses with [`Error::StaleRead`]
    /// and applying it is rejected with [`Error::StaleBatch`].
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, U, N, S>> {
        let grafted = self.grafted_snapshot();
        Arc::new(MerkleizedBatch {
            inner: self.any.to_batch(),
            grafted,
            bitmap: Vec::new(),
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
            ApplyBatchResult, BatchableDb, MerkleizedBatch as MerkleizedBatchTrait,
            UnmerkleizedBatch as UnmerkleizedBatchTrait,
        },
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
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
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

        async fn merkleize(
            self,
            db: &CurrentDb<F, E, C, I, H, update::Unordered<K, V>, N, S>,
            metadata: Option<V::Value>,
        ) -> Result<Self::Merkleized, crate::qmdb::Error<F>> {
            self.merkleize(db, metadata).await
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
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
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

        async fn merkleize(
            self,
            db: &CurrentDb<F, E, C, I, H, update::Ordered<K, V>, N, S>,
            metadata: Option<V::Value>,
        ) -> Result<Self::Merkleized, crate::qmdb::Error<F>> {
            self.merkleize(db, metadata).await
        }
    }

    impl<F: Graftable, D: Digest, U: update::Update, const N: usize, S: Strategy>
        MerkleizedBatchTrait for Arc<MerkleizedBatch<F, D, U, N, S>>
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
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
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
            self,
            batch: Self::Merkleized,
        ) -> impl Future<Output = ApplyBatchResult<Self>> {
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
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
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
            self,
            batch: Self::Merkleized,
        ) -> impl Future<Output = ApplyBatchResult<Self>> {
            self.apply_batch(batch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mmb, mmr, qmdb::any::batch::fill_candidates, utils::detached::block_strategy};
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_parallel::Rayon;
    use commonware_utils::{NZUsize, bitmap::Prunable as BitMap};
    use std::{
        future::Future as _,
        task::Context as TaskContext,
        time::{Duration, Instant},
    };

    // N=4 -> CHUNK_SIZE_BITS = 32
    const N: usize = 4;
    type Bm = BitMap<N>;
    type GraftedBatch = Arc<GenericMerkleizedBatch<mmb::Family, <Sha256 as Hasher>::Digest, Rayon>>;
    type Location = mmr::Location;

    fn make_bitmap(bits: &[bool]) -> Bm {
        let mut bm = Bm::new();
        for &b in bits {
            bm.push(b);
        }
        bm
    }

    fn grafted_chain(
        strategy: &Rayon,
        mem: &Arc<Mem<mmb::Family, <Sha256 as Hasher>::Digest>>,
    ) -> (GraftedBatch, GraftedBatch) {
        let hasher = grafting::hasher::<mmb::Family, Sha256>(grafting::height::<1>());
        let a = mem
            .new_batch_with_strategy(strategy.clone())
            .add_leaf_digest(Sha256::hash(&[b"a-0"]))
            .add_leaf_digest(Sha256::hash(&[b"a-1"]))
            .merkleize(mem, &hasher);
        let b = a
            .new_batch()
            .add_leaf_digest(Sha256::hash(&[b"b-0"]))
            .merkleize(mem, &hasher);
        (a, b)
    }

    /// A detached grafted-tree merkleization owns the full ancestor chain after cancellation.
    #[test_traced]
    fn test_grafted_merkleize_retains_ancestors_after_cancellation() {
        let strategy = Rayon::new(NZUsize!(2)).unwrap();
        let mem = Arc::new(Mem::<mmb::Family, <Sha256 as Hasher>::Digest>::new());
        let grafting_height = grafting::height::<1>();
        let graft_inputs = || vec![(0, Sha256::hash(&[b"replacement"]), [1u8; 1])];
        let waker = futures::task::noop_waker();
        let mut context = TaskContext::from_waker(&waker);

        // Observe the worker result so a missing grandparent fails the test directly.
        let (a, b) = grafted_chain(&strategy, &mem);
        let ancestor = Arc::downgrade(&a);
        let release = block_strategy(&strategy, 2);
        let mut merkleize = Box::pin(merkleize_grafted_batch::<mmb::Family, Sha256, _, 1>(
            &strategy,
            Arc::clone(&b),
            &mem,
            graft_inputs(),
            grafting_height,
        ));
        assert!(merkleize.as_mut().poll(&mut context).is_pending());
        drop(b);
        drop(a);
        drop(release);
        let _ = futures::executor::block_on(merkleize);
        assert!(ancestor.upgrade().is_none());

        // Drop the waiter while the worker is queued to prove the guard moved with it.
        let (a, b) = grafted_chain(&strategy, &mem);
        let ancestor = Arc::downgrade(&a);
        let release = block_strategy(&strategy, 2);
        let mut merkleize = Box::pin(merkleize_grafted_batch::<mmb::Family, Sha256, _, 1>(
            &strategy,
            Arc::clone(&b),
            &mem,
            graft_inputs(),
            grafting_height,
        ));
        assert!(merkleize.as_mut().poll(&mut context).is_pending());
        drop(merkleize);
        drop(b);
        drop(a);
        assert!(ancestor.upgrade().is_some());

        drop(release);
        let deadline = Instant::now() + Duration::from_secs(10);
        while ancestor.upgrade().is_some() {
            assert!(
                Instant::now() < deadline,
                "detached grafted merkleization did not release its ancestors"
            );
            std::thread::yield_now();
        }
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

    /// Single-step oracle for [`fill_candidates`]: return the next floor-raise candidate in
    /// `[floor, tip)` over any [`bitmap::Readable`]. `fill_candidates_matches_oracle` proves
    /// the production scan produces exactly this sequence over every overlay shape.
    fn next_candidate<B: bitmap::Readable<N2>, const N2: usize>(
        bitmap: &B,
        floor: Location,
        tip: u64,
    ) -> Option<Location> {
        let floor = *floor;
        let bitmap_len = bitmap.len();
        let committed_end = bitmap_len.min(tip);
        if floor < committed_end
            && let Some(idx) = bitmap.ones_iter_from(floor).next()
            && idx < committed_end
        {
            return Some(Location::new(idx));
        }
        let candidate = floor.max(bitmap_len);
        (candidate < tip).then(|| Location::new(candidate))
    }

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

    #[test]
    fn fill_candidates_matches_oracle() {
        // Sequence parity plus split-resume for one (view, tip): the scan matches
        // single-stepping the oracle over the same view, and any split point resumes
        // seamlessly via the returned continuation.
        fn assert_matches(name: &str, view: &BitmapView<'_, N>, tip: u64) {
            for floor in 0..=tip {
                let mut want = Vec::new();
                let mut scan = Location::new(floor);
                while let Some(c) = next_candidate(view, scan, tip) {
                    want.push(c);
                    scan = c + 1;
                }
                for split in 0..=want.len() {
                    let mut got = Vec::new();
                    let next = fill_candidates(view, Location::new(floor), tip, split, &mut got);
                    fill_candidates(view, next, tip, want.len() + 1, &mut got);
                    assert_eq!(got, want, "{name} floor={floor} split={split}");
                }
            }
        }

        let bits = [true, false, true, true, false, false, true, false];
        let base = make_bitmap(&bits);

        // Flat committed base.
        let flat = Vec::new();

        // One layer: clears committed bits 3 and 6, appends 8..12 (only 9 set).
        let mut overlay = ChunkOverlay::new(&base, 12, 1);
        overlay.clear_bit(&base, 3);
        overlay.clear_bit(&base, 6);
        overlay.set_bit(&base, 9);
        let one_layer = vec![Arc::new(overlay)];

        // Two layers, mirroring `fill_candidates_filters_ancestor_clears`.
        let mut overlay1 = ChunkOverlay::new(&base, 12, 2);
        overlay1.clear_bit(&base, 3);
        overlay1.set_bit(&base, 9);
        let lower = vec![Arc::new(overlay1)];
        let lower_view = BitmapView::over(lower.clone(), &base);
        let mut overlay2 = ChunkOverlay::new(&lower_view, 14, 2);
        overlay2.clear_bit(&lower_view, 6);
        overlay2.clear_bit(&lower_view, 9);
        overlay2.set_bit(&lower_view, 13);
        let mut two_layer = lower;
        two_layer.push(Arc::new(overlay2));

        // Pruned base: 40 bits with chunk 0 pruned (33 and 38 set beyond the pruned
        // boundary), plus a layer clearing 38 and appending 40..46 (41 and 44 set).
        let pruned_base = {
            let mut bits = [false; 40];
            bits[33] = true;
            bits[38] = true;
            let mut bm = make_bitmap(&bits);
            bm.prune_to_bit(32);
            bm
        };
        let mut overlay = ChunkOverlay::new(&pruned_base, 46, 1);
        overlay.clear_bit(&pruned_base, 38);
        overlay.set_bit(&pruned_base, 41);
        overlay.set_bit(&pruned_base, 44);
        let pruned = vec![Arc::new(overlay)];

        for (name, overlays, committed_bitmap, committed) in [
            ("flat", flat, &base, 8),
            ("one-layer", one_layer, &base, 8),
            ("two-layer", two_layer, &base, 8),
            ("pruned-base", pruned, &pruned_base, 40),
        ] {
            let view = BitmapView::over(overlays, committed_bitmap);
            let len = bitmap::Readable::<N>::len(&view);
            for tip in [committed, len, len + 3] {
                assert_matches(name, &view, tip);
            }

            // Prefetch-then-live handoff: the prefetch is clamped to the committed
            // boundary and the live scan resumes from the continuation with the
            // post-batch tip. Nothing the raise must revalidate may be lost across the
            // handoff (false negatives are forbidden): every set bit in `[floor, len)`
            // and every location in `[len, tip)`.
            let tip = len + 3;
            let cap = tip as usize;
            let pruned_bits = bitmap::Readable::<N>::pruned_bits(&view);
            for floor in pruned_bits..=committed {
                let mut got = Vec::new();
                let next = fill_candidates(&view, Location::new(floor), committed, cap, &mut got);
                fill_candidates(&view, next, tip, cap, &mut got);
                assert!(got.is_sorted_by(|a, b| a < b), "{name} floor={floor}");
                for loc in floor..tip {
                    let must_emit = loc >= len || bitmap::Readable::<N>::get_bit(&view, loc);
                    assert!(
                        !must_emit || got.contains(&Location::new(loc)),
                        "{name} floor={floor} lost {loc}"
                    );
                }
            }
        }
    }

    #[test]
    fn fill_candidates_filters_ancestor_clears() {
        let bits = [true, false, true, true, false, false, true, false];
        let base = make_bitmap(&bits);

        // Layer 1 clears committed bit 3 and appends bits 8..12 (only 9 set).
        let mut overlay1 = ChunkOverlay::new(&base, 12, 2);
        overlay1.clear_bit(&base, 3);
        overlay1.set_bit(&base, 9);
        let one = vec![Arc::new(overlay1)];
        let one_view = BitmapView::over(one.clone(), &base);

        // Layer 2 (materialized against the layer-1 view, as `build_chunk_overlay` does)
        // clears bits 6 and 9, and appends bits 12..14 (only 13 set).
        let mut overlay2 = ChunkOverlay::new(&one_view, 14, 2);
        overlay2.clear_bit(&one_view, 6);
        overlay2.clear_bit(&one_view, 9);
        overlay2.set_bit(&one_view, 13);
        let mut two = one;
        two.push(Arc::new(overlay2));
        let two_view = BitmapView::over(two, &base);

        // Bits cleared by any layer are skipped (no wasted log reads), set bits -- committed
        // or appended, from whichever layer materialized the chunk last -- are emitted
        // ascending, and locations at or beyond the layered length up to `tip` are emitted
        // sequentially.
        let scan = |view: &BitmapView<'_, N>, tip: u64| {
            let mut got = Vec::new();
            fill_candidates(view, Location::new(0), tip, 16, &mut got);
            got
        };
        let want = |locs: &[u64]| locs.iter().copied().map(Location::new).collect::<Vec<_>>();
        assert_eq!(scan(&one_view, 12), want(&[0, 2, 6, 9]));
        assert_eq!(scan(&two_view, 14), want(&[0, 2, 13]));
        assert_eq!(scan(&two_view, 16), want(&[0, 2, 13, 14, 15]));
    }

    #[test]
    fn fill_candidates_mixes_overlay_and_base_chunks() {
        // Base spans two chunks (N=4 -> 32-bit chunks): full chunk 0 plus a partial chunk 1.
        let mut bits = [false; 40];
        for i in [1, 30, 33, 35, 38] {
            bits[i] = true;
        }
        let base = make_bitmap(&bits);

        // Layer touches only chunk 1: clears committed bit 35 and appends bits 40..44
        // (only 41 set). Chunk 0 stays unmaterialized, so the scan must fall through to
        // the committed base there.
        let mut overlay = ChunkOverlay::new(&base, 44, 1);
        overlay.clear_bit(&base, 35);
        overlay.set_bit(&base, 41);
        let view = BitmapView::over(vec![Arc::new(overlay)], &base);

        // Chunk 0 bits come from the base, chunk 1 bits from the overlay (35 filtered,
        // the appended 41 emitted).
        let mut got = Vec::new();
        fill_candidates(&view, Location::new(0), 44, 16, &mut got);
        let want: Vec<Location> = [1, 30, 33, 38, 41].into_iter().map(Location::new).collect();
        assert_eq!(got, want);
    }

    // ---- trim_committed tests ----
    //
    // `trim_committed` runs at merkleize to drop the overlays a prior apply has already absorbed
    // into the committed bitmap. These tests cover distinct input shapes directly, without going
    // through the full Db/batch machinery, so the structural output can be asserted.

    /// Build a view over `committed` with one overlay per length in `overlay_lens` (oldest
    /// first), each materialized against the view below it.
    fn make_view<'a>(committed: &'a Bm, overlay_lens: &[u64]) -> BitmapView<'a, N> {
        let mut view = BitmapView::over(Vec::new(), committed);
        for &len in overlay_lens {
            let overlay = ChunkOverlay::new(&view, len, 0);
            view.overlays.push(Arc::new(overlay));
        }
        view
    }

    /// Overlay lengths of a view, oldest first.
    fn overlay_lens(view: &BitmapView<'_, N>) -> Vec<u64> {
        view.overlays.iter().map(|overlay| overlay.len).collect()
    }

    /// No overlays: nothing to drop. Real-world trigger: merkleizing a child of a batch whose
    /// overlays were previously trimmed away (e.g., immediately after an apply absorbed
    /// everything).
    #[test]
    fn trim_committed_already_base() {
        let committed = make_bitmap(&[true; 64]);
        let result = make_view(&committed, &[]).trim_committed().unwrap();
        assert!(result.overlays.is_empty());
    }

    /// Every overlay has been absorbed by prior applies, so all are dropped. This is the
    /// steady-state "extend a just-applied batch" flow: after `apply_batch(A)`, `A`'s own
    /// overlay has `len == committed` and the child's merkleize should start from the committed
    /// bitmap alone.
    #[test]
    fn trim_committed_all_committed() {
        // `committed.len() == 64`; the single overlay's `len == 64`, so it's committed.
        let committed = make_bitmap(&[true; 64]);
        let result = make_view(&committed, &[64]).trim_committed().unwrap();
        assert!(result.overlays.is_empty());
    }

    /// Every overlay is still speculative, so all are kept in order. Real-world trigger:
    /// speculating multiple batches deep (A, then B off A, then C off B) without `apply_batch`
    /// in between.
    #[test]
    fn trim_committed_none_committed() {
        // `committed.len() == 32`; both overlays have `len > 32`, so neither is committed.
        let committed = make_bitmap(&[true; 32]);
        let result = make_view(&committed, &[64, 96]).trim_committed().unwrap();
        assert_eq!(overlay_lens(&result), vec![64, 96]);
    }

    /// Exactly one overlay is uncommitted (the newest) on top of a committed one -- the dominant
    /// pattern in chained growth. Real-world trigger: apply parent A, then B held alive off A,
    /// then merkleize C built off B.
    #[test]
    fn trim_committed_exactly_one_uncommitted() {
        // `committed.len() == 64`; committed overlay (`len == 64`) + uncommitted (`96`).
        let committed = make_bitmap(&[true; 64]);
        let result = make_view(&committed, &[64, 96]).trim_committed().unwrap();
        assert_eq!(overlay_lens(&result), vec![96]);
    }

    /// Two or more uncommitted overlays on top of a committed one. Real-world trigger: build A,
    /// then B off A, then C off B; apply only A; then merkleize a child of C.
    #[test]
    fn trim_committed_multiple_uncommitted() {
        // `committed.len() == 64`; committed overlay (64), then two uncommitted (96, 128).
        let committed = make_bitmap(&[true; 64]);
        let result = make_view(&committed, &[64, 96, 128])
            .trim_committed()
            .unwrap();
        assert_eq!(overlay_lens(&result), vec![96, 128]);
    }

    /// The oldest kept overlay must have been built on the committed bitmap. Viewing overlays
    /// built on a 64-bit bitmap over a 32-bit one is what a rewind onto an ancestor state looks
    /// like, and must be refused.
    #[test]
    fn trim_committed_rejects_rewound_committed() {
        let committed = make_bitmap(&[true; 64]);
        let overlays = make_view(&committed, &[96]).overlays;
        let rewound = make_bitmap(&[true; 32]);
        assert!(
            BitmapView::over(overlays, &rewound)
                .trim_committed()
                .is_none()
        );
    }
}
