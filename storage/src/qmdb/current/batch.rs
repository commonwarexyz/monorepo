//! Batch mutation API for Current QMDBs.
//!
//! Wraps the [`any::batch`] API.

pub use crate::qmdb::any::batch::Slot;
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
            batch::{DiffCursors, DiffEntry, RetainedAncestors, Staged as AnyStaged},
            operation::{Operation, update},
        },
        bitmap::{Candidates, Shared, fill_from},
        chain::Bounds,
        current::{db::compute_ops_root_witness, grafting, proof::OpsRootWitness},
        floor::{Policy, Proportional},
        operation::Key,
    },
};
use ahash::AHashMap;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{
    Widen,
    bitmap::{self, Readable as _},
};
use core::ops::Range;
use std::sync::Arc;

/// Speculative chunk-level bitmap overlay: materialized bytes for every chunk that differs from
/// the parent bitmap, which grafted MMR leaf computation reads directly.
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
/// materialized chunk, and reading each through a `Base` chain costs a lock acquisition on
/// the DB's shared bitmap, so they are read once instead of per touched chunk.
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
    /// `capacity` estimates the number of distinct chunks the overlay will modify,
    /// including appended chunks.
    fn new<B: bitmap::Readable<N>>(base: &B, len: u64, capacity: usize) -> Self {
        // Every dirty chunk is unpruned and below len, including the final partial chunk.
        let parent = Dimensions::of(base);
        let max_chunks =
            usize::try_from(len.div_ceil(Self::CHUNK_BITS) - Widen::widen(parent.pruned_chunks))
                .unwrap_or(usize::MAX);
        Self {
            chunks: AHashMap::with_capacity(capacity.min(max_chunks)),
            len,
            parent,
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

/// Bitmap-accelerated candidate scan over a layered `BitmapBatch` chain. Fills `out` with up to
/// `limit` floor candidates in `[floor, tip)`, returning the next scan location. Skips locations
/// where the layered bitmap bit is unset (including locations superseded by unapplied ancestors),
/// avoiding I/O reads for inactive operations. Produces the same sequence as repeatedly calling the
/// `next_candidate` test oracle over the chain.
///
/// Each fill scans with one set-bit iterator: overlay chunks resolve lock-free and the applied
/// base is locked once per untouched chunk, rather than several times per candidate. The
/// iterator's chunk caching is sound here because bitmap mutators require `&mut` on the
/// database, which cannot coexist with the `&db` a merkleize holds.
impl<F: Graftable, const N: usize> Candidates<F> for &BitmapBatch<N> {
    fn fill(
        &mut self,
        floor: Location<F>,
        tip: u64,
        limit: usize,
        out: &mut Vec<Location<F>>,
    ) -> Location<F> {
        Location::new(fill_from(*self, *floor, tip, limit, out))
    }
}

/// Reads nodes from a batch chain layered over the database's [`Mem`] it extends.
///
/// Nodes the chain appended or updated come from the chain, and every other position comes from
/// the `Mem`.
struct Layered<'a, R: Readable> {
    batch: &'a R,
    mem: &'a Mem<R::Family, R::Digest>,
}

impl<R: Readable> Readable for Layered<'_, R> {
    type Family = R::Family;
    type Digest = R::Digest;

    fn size(&self) -> Position<R::Family> {
        self.batch.size()
    }

    fn get_node(&self, pos: Position<R::Family>) -> Option<R::Digest> {
        if let Some(d) = self.batch.get_node(pos) {
            return Some(d);
        }
        self.mem.get_node(pos)
    }
}

impl<R: Readable> MerkleStorage<R::Family> for Layered<'_, R> {
    type Digest = R::Digest;

    fn size(&self) -> Position<R::Family> {
        Readable::size(self)
    }

    async fn get_node(
        &self,
        pos: Position<R::Family>,
    ) -> Result<Option<R::Digest>, merkle::Error<R::Family>> {
        Ok(Readable::get_node(self, pos))
    }
}

/// Result of merkleizing a batch.
type MerkleizeResult<F, D, U, const N: usize, S> =
    Result<Arc<MerkleizedBatch<F, D, U, N, S>>, Error<F>>;

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
    /// The inner any-layer batch that handles mutations, journal, and floor walk.
    inner: any::batch::UnmerkleizedBatch<F, H, U, S>,

    /// Parent's grafted MMR state.
    grafted_parent: Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,

    /// Parent's bitmap state (COW, Arc-based).
    bitmap_parent: BitmapBatch<N>,
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
    bitmap_parent: BitmapBatch<N>,
}

/// The bitmap chunks and grafted nodes one batch wrote on top of its parent, with the canonical
/// root and witness at the batch's tip.
///
/// Writing a chain's deltas in order over the state the chain was built on reproduces each batch's
/// unpruned chunks and grafted nodes. A delta covers only its own batch, so reproducing the state
/// after [`super::db::Db::apply_batch`] applies a descendant directly also takes each unapplied
/// ancestor's delta. Chunks below [`Self::pruned_chunks`] are all zero, so each one's grafted leaf
/// equals the operations-tree subtree root it covers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta<F: Graftable, D: Digest, const N: usize> {
    /// Canonical current root at the batch's tip.
    pub root: D,
    /// Witness binding the operations root to `root`.
    pub witness: OpsRootWitness<F, D>,
    /// Bitmap chunks below this index were pruned when the batch was merkleized.
    pub pruned_chunks: u64,
    /// Every bitmap chunk the batch wrote, including chunks it completed and its last chunk, in
    /// ascending chunk index. Every index is at least `pruned_chunks`.
    pub chunks: Vec<(u64, [u8; N])>,
    /// Every grafted node the batch appended or overwrote, in ascending operations-tree position.
    pub grafted_nodes: Vec<(Position<F>, D)>,
}

/// Everything a publisher stores for one batch: the operations it appends, the operations-tree
/// frontier they extend, and the [`Delta`] it makes to the current-state commitment.
///
/// Replaying `operations` onto `pinned_nodes` recomputes `ops_root`, and `delta.witness` binds
/// that root to `delta.root`.
#[derive(Clone)]
pub struct Publication<F: Graftable, D: Digest, U: update::Update, const N: usize> {
    /// Location of the first operation.
    pub start: Location<F>,
    /// Operations-tree frontier at `start`, in [`merkle::Family::nodes_to_pin`] order.
    pub pinned_nodes: Vec<D>,
    /// Operations the batch appends from `start`, ending with its commit.
    pub operations: Arc<Vec<Operation<F, U>>>,
    /// Operations-tree root after the batch.
    pub ops_root: D,
    /// What the batch changed in the current-state commitment.
    pub delta: Delta<F, D, N>,
}

/// A speculative batch of operations whose root digest has been computed, in contrast to
/// [`UnmerkleizedBatch`].
///
/// Wraps an [`any::batch::MerkleizedBatch`] and adds the bitmap and grafted MMR state needed to
/// compute the canonical root.
///
/// # Batch validity
///
/// Reads through this batch succeed only while the DB is at a state of the batch's chain: its
/// recorded database boundary, an ancestor's tip, or this batch's own tip once it is applied.
///
/// Once the DB moves to any other state, for example because a sibling or one of this batch's
/// descendants was applied, this batch is stale, as is each of its descendants whose chain does
/// not include the new state. Reads through a stale batch return [`Error::StaleRead`], and
/// applying it or merkleizing a child of it returns [`Error::StaleBatch`] without changing the
/// database (see [`crate::qmdb::chain`]).
pub struct MerkleizedBatch<F: Graftable, D: Digest, U: update::Update, const N: usize, S: Strategy>
{
    /// Inner any-layer batch (ops MMR, diff, floor, commit loc, sizes).
    pub(crate) inner: Arc<any::batch::MerkleizedBatch<F, D, U, S>>,

    /// Grafted MMR state.
    pub(crate) grafted: Arc<merkle::batch::MerkleizedBatch<F, D, S>>,

    /// COW bitmap state (for use as a parent in speculative batches).
    pub(crate) bitmap: BitmapBatch<N>,

    /// The canonical root, including the ops, grafted, pending, and partial contributions.
    pub(crate) canonical_root: D,

    /// Witness binding the ops root to `canonical_root`.
    pub(crate) ops_root_witness: OpsRootWitness<F, D>,

    /// Physical bitmap pruning boundary captured with the root.
    pruned_chunks: u64,
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
        bitmap_parent: BitmapBatch<N>,
    ) -> Self {
        Self {
            inner,
            grafted_parent,
            bitmap_parent,
        }
    }

    /// Set the metadata recorded in this batch's commit. Defaults to `None` and is not inherited by
    /// child batches. Carries over to the batch returned by [`Self::stage`].
    pub fn with_metadata(mut self, metadata: impl Into<Option<U::Value>>) -> Self {
        self.inner = self.inner.with_metadata(metadata);
        self
    }

    /// Record a mutation. Use `Some(value)` for update/create, `None` for delete.
    ///
    /// If the same key is written multiple times within a batch, the last
    /// value wins.
    pub fn write(mut self, key: U::Key, value: Option<U::Value>) -> Self {
        self.inner = self.inner.write(key, value);
        self
    }

    /// Read through: mutations -> ancestor diffs -> database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
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
    /// Returns results in the same order as the input keys. The initial keys occupy staged read
    /// slots `0..keys.len()`, and each [`expand`](Staged::expand) appends another range of slots.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
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
    /// The number of staged read slots: the keys passed to [`stage`](UnmerkleizedBatch::stage)
    /// plus every [`expand`](Self::expand) range. [`merkleize`](Staged::merkleize) takes one
    /// [`Slot`] per staged read.
    pub const fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether no reads are staged.
    pub const fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Set the metadata recorded in the commit, replacing any set before staging.
    pub fn with_metadata(mut self, metadata: impl Into<Option<U::Value>>) -> Self {
        self.inner = self.inner.with_metadata(metadata);
        self
    }

    /// Expand this staged batch with more reads.
    ///
    /// Existing slots keep their positions. Newly read keys are appended to the staged read set
    /// and assigned the returned range of slots. The returned values are in the same order as
    /// `keys`.
    ///
    /// Expansion does not deduplicate against previously staged keys and does not observe values the
    /// caller has computed for earlier staged slots but not yet passed to
    /// [`merkleize`](Staged::merkleize).
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
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
    /// Apply `slots` to staged reads and `unstaged` writes to unread keys, advance the inactivity
    /// floor with [`Proportional`], then merkleize.
    ///
    /// Consumes the staged handle, `slots`, and `unstaged`. Call [`expand`](Staged::expand) before
    /// this method if more keys must be read into the staged read set.
    ///
    /// `slots` holds one [`Slot`] per staged read, in the order of the initial `stage` input
    /// followed by any [`expand`](Staged::expand) ranges. A key staged more than once takes its
    /// last put or delete. Metadata set before or after staging (see [`Self::with_metadata`]) is
    /// committed with the returned batch.
    ///
    /// The root is independent of slot order. Staging the keys in another order, or writing a key
    /// through a different slot, merkleizes to the same root when each key's final put or delete
    /// stays the same.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleBatch`] if `db` is not at a state of this batch's chain, an unapplied
    /// ancestor was dropped, or `db` is not the database instance that created the batch.
    ///
    /// # Panics
    ///
    /// Panics if `slots` does not hold one entry per staged read.
    pub async fn merkleize<E, C, I>(
        self,
        slots: Vec<Slot<V::Value>>,
        unstaged: Vec<(K, Option<V::Value>)>,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
    ) -> MerkleizeResult<F, H::Digest, update::Unordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.merkleize_with(slots, unstaged, db, &mut Proportional)
            .await
    }

    /// Like [`Self::merkleize`], but advances the inactivity floor with `policy` instead of
    /// [`Proportional`]. Has the same errors and panics.
    #[tracing::instrument(
        name = "qmdb.current.unordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(slots = slots.len() as u64, unstaged = unstaged.len() as u64),
    )]
    pub async fn merkleize_with<E, C, I, P>(
        self,
        slots: Vec<Slot<V::Value>>,
        unstaged: Vec<(K, Option<V::Value>)>,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Unordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        P: Policy<F, K, V::Value>,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        bitmap_parent.ensure_based_on(&db.any.bitmap)?;

        let (prepared, staged) = inner
            .resolve_updates_prefetched(slots, unstaged, &db.any, &*policy, &bitmap_parent)
            .await?;
        let (inner, retained_ancestors) = prepared
            .walk_floor_and_merkleize(staged, &bitmap_parent, policy)
            .await?;
        compute_current_layer(
            inner,
            retained_ancestors,
            db,
            &grafted_parent,
            &bitmap_parent,
        )
        .await
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
    /// Apply `slots` to staged reads and `unstaged` writes to unread keys, advance the inactivity
    /// floor with [`Proportional`], then merkleize.
    ///
    /// Consumes the staged handle, `slots`, and `unstaged`. Call [`expand`](Staged::expand) before
    /// this method if more keys must be read into the staged read set.
    ///
    /// `slots` holds one [`Slot`] per staged read, in the order of the initial `stage` input
    /// followed by any [`expand`](Staged::expand) ranges. A key staged more than once takes its
    /// last put or delete. Metadata set before or after staging (see [`Self::with_metadata`]) is
    /// committed with the returned batch.
    ///
    /// The root is independent of slot order. Staging the keys in another order, or writing a key
    /// through a different slot, merkleizes to the same root when each key's final put or delete
    /// stays the same.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleBatch`] if `db` is not at a state of this batch's chain, an unapplied
    /// ancestor was dropped, or `db` is not the database instance that created the batch.
    ///
    /// # Panics
    ///
    /// Panics if `slots` does not hold one entry per staged read.
    pub async fn merkleize<E, C, I>(
        self,
        slots: Vec<Slot<V::Value>>,
        unstaged: Vec<(K, Option<V::Value>)>,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> MerkleizeResult<F, H::Digest, update::Ordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
    {
        self.merkleize_with(slots, unstaged, db, &mut Proportional)
            .await
    }

    /// Like [`Self::merkleize`], but advances the inactivity floor with `policy` instead of
    /// [`Proportional`]. Has the same errors and panics.
    #[tracing::instrument(
        name = "qmdb.current.ordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(slots = slots.len() as u64, unstaged = unstaged.len() as u64),
    )]
    pub async fn merkleize_with<E, C, I, P>(
        self,
        slots: Vec<Slot<V::Value>>,
        unstaged: Vec<(K, Option<V::Value>)>,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Ordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
        P: Policy<F, K, V::Value>,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        bitmap_parent.ensure_based_on(&db.any.bitmap)?;
        let (inner, staged) = inner.resolve_updates(slots, unstaged, db.any.strategy());
        let prepared = inner.prepare(&db.any)?;
        let (inner, retained_ancestors) = prepared
            .walk_floor_and_merkleize(staged, &bitmap_parent, policy)
            .await?;
        compute_current_layer(
            inner,
            retained_ancestors,
            db,
            &grafted_parent,
            &bitmap_parent,
        )
        .await
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
    /// Resolve mutations into operations, advance the inactivity floor with
    /// [`Proportional`], merkleize, and return an `Arc<MerkleizedBatch>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleBatch`] if `db` is not at a state of this batch's chain, an unapplied
    /// ancestor was dropped, or `db` is not the database instance that created the batch.
    pub async fn merkleize<E, C, I>(
        self,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
    ) -> MerkleizeResult<F, H::Digest, update::Unordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        self.merkleize_with(db, &mut Proportional).await
    }

    /// Like [`Self::merkleize`], but advances the inactivity floor with `policy` instead of
    /// [`Proportional`]. Has the same errors.
    #[tracing::instrument(
        name = "qmdb.current.unordered.batch.merkleize",
        level = "info",
        skip_all
    )]
    pub async fn merkleize_with<E, C, I, P>(
        self,
        db: &super::db::Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Unordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        P: Policy<F, K, V::Value>,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        bitmap_parent.ensure_based_on(&db.any.bitmap)?;
        let prepared = inner.prepare(&db.any)?;
        let (inner, retained_ancestors) = prepared
            .walk_floor_and_merkleize(Vec::new(), &bitmap_parent, policy)
            .await?;
        compute_current_layer(
            inner,
            retained_ancestors,
            db,
            &grafted_parent,
            &bitmap_parent,
        )
        .await
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
    /// Resolve mutations into operations, advance the inactivity floor with
    /// [`Proportional`], merkleize, and return an `Arc<MerkleizedBatch>`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleBatch`] if `db` is not at a state of this batch's chain, an unapplied
    /// ancestor was dropped, or `db` is not the database instance that created the batch.
    pub async fn merkleize<E, C, I>(
        self,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> MerkleizeResult<F, H::Digest, update::Ordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
    {
        self.merkleize_with(db, &mut Proportional).await
    }

    /// Like [`Self::merkleize`], but advances the inactivity floor with `policy` instead of
    /// [`Proportional`]. Has the same errors.
    #[tracing::instrument(
        name = "qmdb.current.ordered.batch.merkleize",
        level = "info",
        skip_all
    )]
    pub async fn merkleize_with<E, C, I, P>(
        self,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Ordered<K, V>, N, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>> + 'static,
        P: Policy<F, K, V::Value>,
    {
        let Self {
            inner,
            grafted_parent,
            bitmap_parent,
        } = self;
        bitmap_parent.ensure_based_on(&db.any.bitmap)?;
        let prepared = inner.prepare(&db.any)?;
        let (inner, retained_ancestors) = prepared
            .walk_floor_and_merkleize(Vec::new(), &bitmap_parent, policy)
            .await?;
        compute_current_layer(
            inner,
            retained_ancestors,
            db,
            &grafted_parent,
            &bitmap_parent,
        )
        .await
    }
}

/// Derive all bitmap mutations (pushes + clears) for this batch in a single pass over the diff and
/// ancestor diffs. Avoids iterating raw operations.
///
/// Pushes: one bit per operation in the batch. All false except active diff entries (whose `loc`
/// falls in the batch) and the CommitFloor (last op).
///
/// Clears: previous CommitFloor, plus the most recent superseded location for each mutated key. We
/// search back through ancestors to find the most recent active location, and if none exists, we
/// clear the key's database location (`base_old_loc`).
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

/// Merkleize grafted chunk digests while retaining the reachable ancestors.
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
        .spawn(graft_inputs.len(), move |strategy| {
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
/// The any batch must have been prepared and merkleized against `db`.
///
/// Builds a chunk overlay from the diff, computes grafted MMR leaves from dirty chunks, and
/// produces the `Arc<MerkleizedBatch>` directly.
///
/// `_retained_ancestors` is held only to keep ancestor batches alive while grafting and root
/// computation read their nodes through weak parent links.
async fn compute_current_layer<F, E, U, C, I, H, const N: usize, S>(
    inner: Arc<any::batch::MerkleizedBatch<F, H::Digest, U, S>>,
    _retained_ancestors: RetainedAncestors<F, H::Digest, U, S>,
    db: &super::db::Db<F, E, C, I, H, U, N, S>,
    grafted_parent: &Arc<merkle::batch::MerkleizedBatch<F, H::Digest, S>>,
    bitmap_parent: &BitmapBatch<N>,
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
        bitmap_parent,
        batch_len,
        batch_base,
        &inner.diff,
        &inner.ancestor_diffs,
    );

    let grafting_height = grafting::height::<N>();

    // Merkleization reads ops-tree nodes only from memory. Graft roots of chunks the database has
    // already grafted come from its retained roots, and all other nodes come from the batch chain
    // or the database's `Mem`.
    let ops_tree = Layered {
        batch: &inner.journal_batch,
        mem: db.any.log.merkle.mem(),
    };

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
    let pruned_chunks = overlay.parent.pruned_chunks;
    assert!(
        pruned_chunks <= graftable_parent
            && graftable_parent <= graftable_overlay
            && graftable_overlay <= new_complete_chunks,
        "invariant violated: pruned={pruned_chunks} graftable_parent={graftable_parent} graftable_overlay={graftable_overlay} new_complete={new_complete_chunks}"
    );

    // Collect graft inputs for the chunks whose grafted leaf needs (re)computing:
    //   1) Dirty chunks (bits changed in this batch) already in the parent's grafted tree.
    //   2) Pending -> graftable transitions: chunks newly graftable because the ops tree built
    //      their h=G ancestor in this batch. Their bitmap bytes may not be dirty (the chunk
    //      became graftable via ops growth alone) but they need a grafted-leaf entry now.
    let mut chunk_indices_to_update: Vec<usize> = overlay
        .chunks
        .iter()
        .filter(|&(&idx, _)| idx < graftable_parent && idx >= pruned_chunks)
        .map(|(&idx, _)| idx)
        .collect();
    chunk_indices_to_update.sort_unstable();

    // Newly graftable chunks come last, in ascending order, so they append to the grafted tree as
    // its next leaves.
    let new_chunks = graftable_parent..graftable_overlay;
    let mut graft_inputs = Vec::with_capacity(chunk_indices_to_update.len() + new_chunks.len());
    for idx in chunk_indices_to_update.into_iter().chain(new_chunks) {
        let chunk = overlay
            .get(idx)
            .copied()
            .unwrap_or_else(|| bitmap_parent.get_chunk(idx));
        let digest = db.graft_roots.get_or_read::<F, N>(idx, &ops_tree)?;
        graft_inputs.push((idx, digest, chunk));
    }

    // Run graft hashing and the grafted batch's build and merkleization as one strategy job,
    // against a snapshot of the DB's grafted tree. An empty graft set hashes nothing, so it
    // merkleizes without submitting a job.
    let grafted_batch = if graft_inputs.is_empty() {
        let grafted_hasher = grafting::hasher::<F, H>(grafting_height);
        grafted_parent
            .new_batch()
            .merkleize(&db.grafted_tree, &grafted_hasher)
    } else {
        merkleize_grafted_batch::<F, H, S, N>(
            &db.strategy,
            Arc::clone(grafted_parent),
            &db.grafted_tree,
            graft_inputs,
            grafting_height,
        )
        .await
    };

    // Build the layered bitmap (parent + overlay) before computing the canonical root, so that
    // the root witness sees newly completed chunks. Using bitmap_parent alone would miss chunks
    // that transitioned from partial to complete in this batch.
    let bitmap_batch = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
        parent: bitmap_parent.clone(),
        overlay: Arc::new(overlay),
        shared: Arc::clone(bitmap_parent.shared()),
    }));

    // Compute the canonical root. Grafted nodes the batch chain appended or updated come from the
    // chain, and every other grafted node comes from the database's grafted tree.
    let ops_root = inner.root();
    let grafted_tree = Layered {
        batch: &grafted_batch,
        mem: &*db.grafted_tree,
    };
    let grafted_storage =
        grafting::Storage::<F, H, _, _>::new(&grafted_tree, grafting_height, &ops_tree);

    let ops_root_witness = compute_ops_root_witness::<F, H, _, _, N>(
        &bitmap_batch,
        &grafted_storage,
        overlay_ops_leaves,
        inner.bounds.inactivity_floor,
    )
    .await?;
    let canonical_root = ops_root_witness.root::<H>(&ops_root);

    Ok(Arc::new(MerkleizedBatch {
        inner,
        grafted: grafted_batch,
        bitmap: bitmap_batch,
        canonical_root,
        ops_root_witness,
        pruned_chunks: pruned_chunks as u64,
    }))
}

/// A view of the DB's bitmap plus zero or more speculative overlay `Layer`s.
///
/// The chain terminates in a `Base` that references the DB's shared bitmap. This enum performs no
/// validity check of its own. Merkleization validates the database commitment and the bitmap
/// instance before computing a root (see [`crate::qmdb::chain`]), and child construction may
/// read the shared bitmap's length to trim applied layers without validating the chain.
#[derive(Clone, Debug)]
pub(crate) enum BitmapBatch<const N: usize> {
    /// Chain terminal: shared reference to the DB's bitmap.
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

    /// Return [`Error::StaleBatch`] unless this chain terminates in `bitmap`.
    ///
    /// Each database instance owns one bitmap, so this binds a batch to the instance that created
    /// it. Another instance with the same commitment cannot stand in for it, because the retained
    /// chain reads the originating instance's bitmap.
    fn ensure_based_on<F: Graftable>(&self, bitmap: &Arc<Shared<N>>) -> Result<(), Error<F>> {
        if Arc::ptr_eq(self.shared(), bitmap) {
            Ok(())
        } else {
            Err(Error::StaleBatch)
        }
    }

    /// Return a chain equivalent to `self` with any `Layer` whose overlay is fully applied replaced
    /// by a direct reference to the DB's bitmap. Since `apply_batch` applies contiguous prefixes,
    /// applied `Layer`s are always at the bottom of the chain.
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
        self.shared().pruned_chunks()
    }

    fn len(&self) -> u64 {
        match self {
            Self::Base(shared) => bitmap::Readable::<N>::len(shared.as_ref()),
            Self::Layer(layer) => layer.overlay.len,
        }
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

    /// Return the cached witness binding [`Self::ops_root`] to [`Self::root`].
    ///
    /// This value remains valid when the database advances or the batch becomes stale.
    pub const fn ops_root_witness(&self) -> &OpsRootWitness<F, D> {
        &self.ops_root_witness
    }

    /// Return this batch's [`Delta`].
    ///
    /// It copies state the batch owns, so it returns the same value after the database advances or
    /// prunes, the batch becomes stale, or its ancestors are dropped.
    pub fn delta(&self) -> Delta<F, D, N> {
        // Collect the chunks this batch's overlay wrote. A `Base` bitmap has no overlay, so its
        // batch wrote no chunks. Both lists are sorted so equal deltas compare equal.
        let mut chunks: Vec<(u64, [u8; N])> = match &self.bitmap {
            BitmapBatch::Base(_) => Vec::new(),
            BitmapBatch::Layer(layer) => layer
                .overlay
                .chunks
                .iter()
                .map(|(&index, &chunk)| (index as u64, chunk))
                .collect(),
        };
        chunks.sort_unstable_by_key(|(index, _)| *index);

        // Collect the grafted nodes this batch appended or overwrote, keyed by operations-tree
        // position.
        let mut grafted_nodes: Vec<(Position<F>, D)> = self
            .grafted
            .local_nodes()
            .map(|(pos, digest)| {
                (
                    grafting::grafted_to_ops_pos::<F>(pos, grafting::height::<N>()),
                    digest,
                )
            })
            .collect();
        grafted_nodes.sort_unstable_by_key(|(pos, _)| *pos);
        Delta {
            root: self.canonical_root,
            witness: self.ops_root_witness.clone(),
            pruned_chunks: self.pruned_chunks,
            chunks,
            grafted_nodes,
        }
    }

    /// Return the [`Bounds`] of the batch.
    pub fn bounds(&self) -> &Bounds<F, D> {
        self.inner.bounds()
    }

    /// Return the operations this batch appends to the ops log and the location of the first.
    ///
    /// Delegates to the wrapped ops-level batch. The bitmap state contributes to the canonical
    /// root but appends no log operations. [`Self::publication`] pairs the operations with the
    /// frontier they extend and the batch's [`Delta`].
    pub fn operations(&self) -> (Location<F>, Arc<Vec<Operation<F, U>>>) {
        self.inner.operations()
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
    /// Every unapplied ancestor in the chain must be held until the child (or any descendant) is
    /// merkleized. Otherwise, `merkleize` returns [`Error::StaleBatch`].
    ///
    /// A child can be created from a stale parent. While the database is at none of the chain's
    /// states, the child's reads return [`Error::StaleRead`], and merkleizing it returns
    /// [`Error::StaleBatch`].
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

    /// Return this batch's [`Publication`].
    ///
    /// The frontier has the staleness and retention requirements of
    /// [`any::batch::MerkleizedBatch::pinned_nodes`], so read it before the batch's changes are
    /// flushed. Everything else copies state the batch owns.
    pub fn publication<E, C, I, H>(
        &self,
        db: &super::db::Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Publication<F, D, U, N>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher<Digest = D>,
    {
        let pinned_nodes = self.inner.pinned_nodes(&db.any)?;
        let (start, operations) = self.inner.operations();
        Ok(Publication {
            start,
            pinned_nodes,
            operations,
            ops_root: self.ops_root(),
            delta: self.delta(),
        })
    }

    /// Read through: local diff -> ancestor diffs -> database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
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
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
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

impl<F, K, V, D, const N: usize, S: Strategy> MerkleizedBatch<F, D, update::Ordered<K, V>, N, S>
where
    F: Graftable,
    K: Key,
    V: ValueEncoding,
    D: Digest,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Returns the smallest active key strictly greater than `key` in this batch's view.
    ///
    /// Includes this batch's changes and its ancestors' changes. The query key need not be
    /// active. Returns `None` if there is no greater key, without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
    pub async fn get_next_key<E, C, I, H>(
        &self,
        key: &K,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> Result<Option<K>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>>,
        H: Hasher<Digest = D>,
    {
        self.inner.get_next_key(key, &db.any).await
    }

    /// Returns the largest active key strictly less than `key` in this batch's view.
    ///
    /// Includes this batch's changes and its ancestors' changes. The query key need not be
    /// active. Returns `None` if there is no smaller key, without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleRead`] if `db` is not at a state of this batch's chain.
    pub async fn get_prev_key<E, C, I, H>(
        &self,
        key: &K,
        db: &super::db::Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> Result<Option<K>, Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, update::Ordered<K, V>>>,
        I: crate::index::Ordered<Value = Location<F>>,
        H: Hasher<Digest = D>,
    {
        self.inner.get_prev_key(key, &db.any).await
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
    /// Create a [`MerkleizedBatch`] with no operations at the DB's current state.
    ///
    /// Once the DB moves to another state, reads through it return [`Error::StaleRead`] and
    /// applying it returns [`Error::StaleBatch`].
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, U, N, S>> {
        let grafted = self.grafted_snapshot();
        Arc::new(MerkleizedBatch {
            inner: self.any.to_batch(),
            grafted,
            bitmap: BitmapBatch::Base(Arc::clone(&self.any.bitmap)),
            canonical_root: self.root,
            ops_root_witness: self.ops_root_witness.clone(),
            pruned_chunks: self.any.bitmap.pruned_chunks() as u64,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mmb, mmr,
        qmdb::{
            ProofExt,
            current::{tests::fixed_config, unordered::fixed},
            floor::Hold,
        },
        translator::OneCap,
        utils::detached::block_strategy,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_parallel::{Rayon, Sequential, mocks::Explorer, rayon::ThreadPoolBuilder};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{NZUsize, bitmap::Prunable as BitMap};
    use std::{
        collections::{BTreeMap, BTreeSet},
        future::Future as _,
        task::Context as TaskContext,
        time::{Duration, Instant},
    };

    // N=4 -> CHUNK_SIZE_BITS = 32
    const N: usize = 4;
    type Bm = BitMap<N>;
    type GraftedBatch =
        Arc<GenericMerkleizedBatch<mmb::Family, <Sha256 as Hasher>::Digest, Explorer>>;
    type Location = mmr::Location;

    impl<F, H, U, const BYTES: usize, S: Strategy> Staged<F, H, U, BYTES, S>
    where
        F: Graftable,
        U: update::Update,
        H: Hasher,
        Operation<F, U>: Codec,
    {
        /// The location each staged read slot resolved to, or `None` for an unresolved slot.
        pub(crate) fn resolved_locs(&self) -> Vec<Option<any::batch::StagedLoc<F>>> {
            self.inner.resolved_locs()
        }
    }

    fn make_bitmap(bits: &[bool]) -> Bm {
        let mut bm = Bm::new();
        for &b in bits {
            bm.push(b);
        }
        bm
    }

    fn grafted_chain(
        strategy: &Explorer,
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
        let pool = Rayon::new(ThreadPoolBuilder::new(NZUsize!(2))).unwrap();
        let strategy = Explorer::parallel(&pool);
        let mem = Arc::new(Mem::<mmb::Family, <Sha256 as Hasher>::Digest>::new());
        let grafting_height = grafting::height::<1>();
        let graft_inputs = || vec![(0, Sha256::hash(&[b"replacement"]), [1u8; 1])];
        let waker = futures::task::noop_waker();
        let mut context = TaskContext::from_waker(&waker);

        // Observe the worker result so a missing grandparent fails the test directly.
        let (a, b) = grafted_chain(&strategy, &mem);
        let ancestor = Arc::downgrade(&a);
        let release = block_strategy(&pool, 2);
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
        let release = block_strategy(&pool, 2);
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

    /// Single-step oracle for [`Candidates::fill`]: return the next floor candidate in
    /// `[floor, tip)` over any [`bitmap::Readable`]. `fill_candidates_matches_oracle` checks
    /// that the production scan produces exactly this sequence over its constructed flat, layered,
    /// and pruned chains.
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
        // Sequence parity plus split-resume for one (chain, tip): the scan matches
        // single-stepping the oracle over the same chain, and any split point resumes
        // seamlessly via the returned continuation.
        fn assert_matches(name: &str, mut chain: &BitmapBatch<N>, tip: u64) {
            for floor in 0..=tip {
                let mut want = Vec::new();
                let mut scan = Location::new(floor);
                while let Some(c) = next_candidate(chain, scan, tip) {
                    want.push(c);
                    scan = c + 1;
                }
                for split in 0..=want.len() {
                    let mut got = Vec::new();
                    let next = chain.fill(Location::new(floor), tip, split, &mut got);
                    chain.fill(next, tip, want.len() + 1, &mut got);
                    assert_eq!(got, want, "{name} floor={floor} split={split}");
                }
            }
        }

        let bits = [true, false, true, true, false, false, true, false];
        let base = make_bitmap(&bits);

        // Flat base.
        let flat = BitmapBatch::Base(Arc::new(Shared::new(make_bitmap(&bits))));

        // One layer: clears base bits 3 and 6, appends 8..12 (only 9 set).
        let shared = Arc::new(Shared::new(make_bitmap(&bits)));
        let mut overlay = ChunkOverlay::new(&base, 12, 1);
        overlay.clear_bit(&base, 3);
        overlay.clear_bit(&base, 6);
        overlay.set_bit(&base, 9);
        let one_layer = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
            parent: BitmapBatch::Base(Arc::clone(&shared)),
            overlay: Arc::new(overlay),
            shared,
        }));

        // Two layers, mirroring `fill_candidates_filters_ancestor_clears`.
        let shared = Arc::new(Shared::new(make_bitmap(&bits)));
        let mut overlay1 = ChunkOverlay::new(&base, 12, 2);
        overlay1.clear_bit(&base, 3);
        overlay1.set_bit(&base, 9);
        let chain1 = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
            parent: BitmapBatch::Base(Arc::clone(&shared)),
            overlay: Arc::new(overlay1),
            shared: Arc::clone(&shared),
        }));
        let mut overlay2 = ChunkOverlay::new(&chain1, 14, 2);
        overlay2.clear_bit(&chain1, 6);
        overlay2.clear_bit(&chain1, 9);
        overlay2.set_bit(&chain1, 13);
        let two_layer = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
            parent: chain1,
            overlay: Arc::new(overlay2),
            shared,
        }));

        // Pruned base: 40 bits with chunk 0 pruned (33 and 38 set beyond the pruned
        // boundary), plus a layer clearing 38 and appending 40..46 (41 and 44 set).
        let make_pruned = || {
            let mut bits = [false; 40];
            bits[33] = true;
            bits[38] = true;
            let mut bm = make_bitmap(&bits);
            bm.prune_to_bit(32);
            bm
        };
        let pruned_base = make_pruned();
        let shared = Arc::new(Shared::new(make_pruned()));
        let mut overlay = ChunkOverlay::new(&pruned_base, 46, 1);
        overlay.clear_bit(&pruned_base, 38);
        overlay.set_bit(&pruned_base, 41);
        overlay.set_bit(&pruned_base, 44);
        let pruned = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
            parent: BitmapBatch::Base(Arc::clone(&shared)),
            overlay: Arc::new(overlay),
            shared,
        }));

        for (name, chain, committed) in [
            ("flat", flat, 8),
            ("one-layer", one_layer, 8),
            ("two-layer", two_layer, 8),
            ("pruned-base", pruned, 40),
        ] {
            let len = bitmap::Readable::<N>::len(&chain);
            for tip in [committed, len, len + 3] {
                assert_matches(name, &chain, tip);
            }

            // Prefetch-then-scan handoff: the prefetch is clamped to `committed` and the
            // remaining scan resumes from the continuation with the post-batch tip. The
            // handoff emits exactly every set bit in `[floor, len)` and every location in
            // `[len, tip)`.
            let tip = len + 3;
            let cap = tip as usize;
            let pruned_bits = bitmap::Readable::<N>::pruned_bits(&chain);
            for floor in pruned_bits..=committed {
                let mut got = Vec::new();
                let next = (&chain).fill(Location::new(floor), committed, cap, &mut got);
                (&chain).fill(next, tip, cap, &mut got);
                let want: Vec<Location> = (floor..tip)
                    .filter(|&loc| loc >= len || bitmap::Readable::<N>::get_bit(&chain, loc))
                    .map(Location::new)
                    .collect();
                assert_eq!(got, want, "{name} floor={floor}");
            }
        }
    }

    #[test]
    fn fill_candidates_filters_ancestor_clears() {
        let bits = [true, false, true, true, false, false, true, false];
        let base = make_bitmap(&bits);
        let shared = Arc::new(Shared::new(make_bitmap(&bits)));

        // Layer 1 clears base bit 3 and appends bits 8..12 (only 9 set).
        let mut overlay1 = ChunkOverlay::new(&base, 12, 2);
        overlay1.clear_bit(&base, 3);
        overlay1.set_bit(&base, 9);
        let chain1 = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
            parent: BitmapBatch::Base(Arc::clone(&shared)),
            overlay: Arc::new(overlay1),
            shared: Arc::clone(&shared),
        }));

        // Layer 2 (materialized against the layer-1 view, as `build_chunk_overlay` does)
        // clears bits 6 and 9, and appends bits 12..14 (only 13 set).
        let mut overlay2 = ChunkOverlay::new(&chain1, 14, 2);
        overlay2.clear_bit(&chain1, 6);
        overlay2.clear_bit(&chain1, 9);
        overlay2.set_bit(&chain1, 13);
        let chain2 = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
            parent: chain1.clone(),
            overlay: Arc::new(overlay2),
            shared,
        }));

        // Bits cleared by any layer are skipped (no wasted log reads), set bits (base or appended,
        // from whichever layer materialized the chunk last) are emitted ascending, and locations at
        // or beyond the layered length up to `tip` are emitted sequentially.
        let scan = |mut chain: &BitmapBatch<N>, tip: u64| {
            let mut got = Vec::new();
            chain.fill(Location::new(0), tip, 16, &mut got);
            got
        };
        let want = |locs: &[u64]| locs.iter().copied().map(Location::new).collect::<Vec<_>>();
        assert_eq!(scan(&chain1, 12), want(&[0, 2, 6, 9]));
        assert_eq!(scan(&chain2, 14), want(&[0, 2, 13]));
        assert_eq!(scan(&chain2, 16), want(&[0, 2, 13, 14, 15]));
    }

    #[test]
    fn fill_candidates_mixes_overlay_and_base_chunks() {
        // Base spans two chunks (N=4 -> 32-bit chunks): full chunk 0 plus a partial chunk 1.
        let mut bits = [false; 40];
        for i in [1, 30, 33, 35, 38] {
            bits[i] = true;
        }
        let base = make_bitmap(&bits);
        let shared = Arc::new(Shared::new(make_bitmap(&bits)));

        // Layer touches only chunk 1: clears base bit 35 and appends bits 40..44 (only 41 set).
        // Chunk 0 stays unmaterialized, so the scan must fall through to the base there.
        let mut overlay = ChunkOverlay::new(&base, 44, 1);
        overlay.clear_bit(&base, 35);
        overlay.set_bit(&base, 41);
        let chain = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
            parent: BitmapBatch::Base(Arc::clone(&shared)),
            overlay: Arc::new(overlay),
            shared,
        }));

        // Chunk 0 bits come from the base, chunk 1 bits from the overlay (35 filtered,
        // the appended 41 emitted).
        let mut got = Vec::new();
        (&chain).fill(Location::new(0), 44, 16, &mut got);
        let want: Vec<Location> = [1, 30, 33, 38, 41].into_iter().map(Location::new).collect();
        assert_eq!(got, want);
    }

    //
    // `trim_committed` is called from `MerkleizedBatch::new_batch` to strip any `Layer`s whose
    // overlays have already been absorbed into the DB's shared bitmap by a prior apply. The
    // implementation is a single loop that collects unapplied overlays top-down and rebuilds a
    // fresh chain rooted at `Base`. These tests cover distinct input shapes directly, without going
    // through the full Db/batch machinery, so the function's structural output can be asserted.

    /// Build a chain `Base(shared) -> Layer(len=L1) -> Layer(len=L2) -> ...` from a list of
    /// overlay lengths (bottom to top). Each constructed `Layer` caches `shared` per the
    /// struct's invariant.
    fn make_chain(shared: &Arc<Shared<N>>, overlay_lens: &[u64]) -> BitmapBatch<N> {
        let mut chain = BitmapBatch::Base(Arc::clone(shared));
        for &len in overlay_lens {
            let overlay = Arc::new(ChunkOverlay::new(&chain, len, 0));
            chain = BitmapBatch::Layer(Arc::new(BitmapBatchLayer {
                parent: chain,
                overlay,
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

    /// Input is already a bare `Base` with no speculative layers on top. The loop body never runs,
    /// `kept` stays empty, and the result is a freshly constructed `Base` pointing at the same
    /// `Shared`. Real-world trigger: `MerkleizedBatch::new_batch` on a batch whose chain was
    /// previously trimmed flat (e.g., immediately after an apply collapsed everything).
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

    /// Every layer has been absorbed by prior applies. The loop breaks on the first iteration
    /// and `kept` stays empty, so the result is a bare `Base`. This is the steady-state
    /// "extend a just-applied batch" flow: after `apply_batch(A)`, `A`'s own layer has
    /// `overlay.len == committed` and the next `new_batch` call should start from a clean
    /// terminal.
    #[test]
    fn trim_committed_all_committed() {
        // `shared.len() == 64` and the single layer's `overlay.len == 32 (<= 64)`, so it is
        // applied.
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 64])));
        let chain = make_chain(&shared, &[32]);
        let result = chain.trim_committed();
        // Collapsed to a bare Base, pointing at the original shared.
        match result {
            BitmapBatch::Base(s) => assert!(Arc::ptr_eq(&s, &shared)),
            BitmapBatch::Layer(_) => panic!("expected Base after full trim"),
        }
    }

    /// Every layer is still speculative. The loop walks all the way to `Base` without
    /// breaking, and `kept` holds every overlay. The rebuilt chain is structurally equivalent
    /// to the input (same overlay lens, same shared terminal). Real-world trigger: speculating
    /// multiple batches deep (A, then B off A, then C off B) without `apply_batch` in between.
    #[test]
    fn trim_committed_none_committed() {
        // `shared.len() == 32` and both overlays have `len > 32`, so neither is applied.
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 32])));
        let chain = make_chain(&shared, &[64, 96]);
        let result = chain.trim_committed();
        // Structure must be preserved in bottom-to-top order.
        assert_eq!(chain_overlays(&result), vec![64, 96]);
    }

    /// Exactly one layer is unapplied (the newest) on top of an applied prefix. This is the
    /// dominant pattern in chained growth. The loop collects the one unapplied overlay, and the
    /// rebuild produces `Layer(Base, overlay_B)`. Also verifies the rebuilt layer carries the
    /// cached `shared` reference correctly. Real-world trigger: apply parent A, keep B (built on
    /// A) held, then call `B.new_batch()` to build C.
    #[test]
    fn trim_committed_exactly_one_uncommitted() {
        // `shared.len() == 64`, so the first layer (`overlay.len == 64`) is applied and the second
        // (`96`) is not.
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 64])));
        let chain = make_chain(&shared, &[64, 96]);
        let result = chain.trim_committed();

        // The applied layer is gone, and only the unapplied overlay remains.
        assert_eq!(chain_overlays(&result), vec![96]);

        // And the rebuilt layer's `shared` field still points at the original terminal.
        assert!(Arc::ptr_eq(result.shared(), &shared));
    }

    /// Two or more unapplied layers on top of an applied prefix. This exercises the loop's
    /// iterated `kept.push` and the rebuild's iterated `Arc::new(BitmapBatchLayer)`, including
    /// the cached `shared` wire-through on every reconstructed layer. Real-world trigger:
    /// build A, then B off A, then C off B, apply only A, and call `C.new_batch()`.
    #[test]
    fn trim_committed_multiple_uncommitted() {
        // `shared.len() == 64`, so the first layer (64) is applied and the next two (96, 128)
        // are not.
        let shared = Arc::new(Shared::<N>::new(make_bitmap(&[true; 64])));
        let chain = make_chain(&shared, &[64, 96, 128]);
        let result = chain.trim_committed();

        // The applied layer is gone, and the unapplied pair stays in order.
        assert_eq!(chain_overlays(&result), vec![96, 128]);

        // Every reconstructed layer must still cache the original shared terminal.
        assert!(Arc::ptr_eq(result.shared(), &shared));
    }

    type TestDb<F, const N: usize> =
        fixed::Db<F, deterministic::Context, Digest, Digest, Sha256, OneCap, N, Sequential>;

    type TestUpdate = update::Unordered<Digest, any::value::FixedEncoding<Digest>>;

    /// A mirror of bitmap chunks, by chunk index, and grafted nodes, by operations-tree position,
    /// seeded from the database and advanced only by applying deltas.
    struct Published<F: Graftable, const N: usize> {
        chunks: BTreeMap<u64, [u8; N]>,
        nodes: BTreeMap<Position<F>, Digest>,
    }

    impl<F: Graftable, const N: usize> Published<F, N> {
        /// Seed a mirror with the database's unpruned bitmap chunks and grafted nodes.
        fn from_db(db: &TestDb<F, N>) -> Self {
            // Copy every unpruned chunk, including a trailing partial chunk.
            let bitmap = db.bitmap();
            let chunks = (bitmap.pruned_chunks() as u64..bitmap.len().div_ceil((N * 8) as u64))
                .map(|idx| (idx, bitmap.get_chunk(idx as usize)))
                .collect();

            // Copy every grafted node the database retains, keyed by operations-tree position.
            let nodes = (0..*db.grafted_tree.size())
                .filter_map(|pos| {
                    db.grafted_tree.get_node(Position::new(pos)).map(|digest| {
                        (
                            grafting::grafted_to_ops_pos::<F>(
                                Position::new(pos),
                                grafting::height::<N>(),
                            ),
                            digest,
                        )
                    })
                })
                .collect();
            Self { chunks, nodes }
        }

        /// Overwrite the mirror's entry for every chunk and grafted node in a delta.
        fn apply(&mut self, delta: &Delta<F, Digest, N>) {
            self.chunks.extend(delta.chunks.iter().copied());
            self.nodes.extend(delta.grafted_nodes.iter().copied());
        }

        /// Check `delta` and the mirror against `db`. The database must be at the state that
        /// produced `delta`.
        fn check(&self, db: &TestDb<F, N>, delta: &Delta<F, Digest, N>) {
            // The delta's root, witness, and pruning boundary describe the database's state.
            assert_eq!(delta.root, db.root());
            assert!(delta.witness.verify::<Sha256>(&db.ops_root(), &db.root()));
            assert_eq!(delta.pruned_chunks, db.bitmap().pruned_chunks() as u64);

            // Both lists ascend without repeats, and every chunk index is at least the pruning
            // boundary.
            assert!(delta.chunks.windows(2).all(|pair| pair[0].0 < pair[1].0));
            assert!(
                delta
                    .chunks
                    .iter()
                    .all(|(idx, _)| *idx >= delta.pruned_chunks)
            );
            assert!(
                delta
                    .grafted_nodes
                    .windows(2)
                    .all(|pair| pair[0].0 < pair[1].0)
            );

            // The mirror holds every unpruned chunk and grafted node the database retains.
            let expected = Self::from_db(db);
            for (idx, chunk) in &expected.chunks {
                assert_eq!(self.chunks.get(idx), Some(chunk));
            }
            for (pos, digest) in &expected.nodes {
                assert_eq!(self.nodes.get(pos), Some(digest));
            }
        }
    }

    /// Check that a batch's publication carries its delta and that its operations, proof, and
    /// pinned nodes verify against its operations root.
    fn check_publication<F: Graftable + PartialEq, const N: usize>(
        batch: &MerkleizedBatch<F, Digest, TestUpdate, N, Sequential>,
        db: &TestDb<F, N>,
    ) {
        let publication = batch.publication(db).unwrap();
        assert_eq!(publication.delta, batch.delta());
        assert_eq!(publication.ops_root, batch.ops_root());
        let proof = batch.inner.proof(&db.any).unwrap();
        assert!(proof.verify_with_pinned_nodes::<Sha256, _>(
            publication.start,
            &publication.operations,
            &publication.pinned_nodes,
            &publication.ops_root,
        ));
    }

    /// Write the hash of `round` to the key hashed from each index in `keys`.
    fn write_keys<F: Graftable, const N: usize>(
        mut batch: UnmerkleizedBatch<F, Sha256, TestUpdate, N, Sequential>,
        keys: Range<u64>,
        round: u64,
    ) -> UnmerkleizedBatch<F, Sha256, TestUpdate, N, Sequential> {
        for key in keys {
            batch = batch.write(
                Sha256::hash(&[&key.to_be_bytes()]),
                Some(Sha256::hash(&[&round.to_be_bytes()])),
            );
        }
        batch
    }

    /// Mirror the database from its deltas across three rounds of rewrites and a reopen, checking
    /// the mirror after each step.
    async fn replay<F: Graftable + PartialEq, const N: usize>(ctx: deterministic::Context) {
        // A batch at the database's own state has an empty delta, and the mirror starts from the
        // database's chunks and grafted nodes.
        let mut db = TestDb::<F, N>::init(
            ctx.child("storage"),
            fixed_config::<OneCap>("publication"),
            None,
        )
        .await
        .unwrap();
        let initial = db.to_batch();
        let delta = initial.delta();
        assert!(delta.chunks.is_empty());
        assert!(delta.grafted_nodes.is_empty());
        let mut published = Published::from_db(&db);

        // Each round writes more than two chunks of operations, and every round after the first
        // supersedes the previous round's writes, so deltas clear bits in earlier chunks as well
        // as setting new ones. Each batch's publication verifies against its operations root.
        let count = (N * 16 + 5) as u64;
        for round in 0..3u64 {
            let batch = write_keys(db.new_batch(), 0..count, round)
                .merkleize_with(&db, &mut Hold)
                .await
                .unwrap();
            let delta = batch.delta();
            check_publication(&batch, &db);
            db = db.apply_batch(batch).await.unwrap();
            published.apply(&delta);
            published.check(&db, &delta);
        }

        // Rewriting every key leaves an earlier complete chunk all zero, so its grafted leaf is
        // the operations-tree subtree root (the zero-chunk identity). The mirror must hold that
        // root in place of the nonzero-chunk leaf an earlier round published.
        let zero = published
            .chunks
            .iter()
            .find(|(idx, chunk)| **idx < db.bitmap().complete_chunks() as u64 && **chunk == [0; N])
            .map(|(&idx, _)| idx)
            .expect("a complete chunk must be all zero after every key is rewritten");
        let pos = F::subtree_root_position(
            merkle::Location::new(zero * (N * 8) as u64),
            grafting::height::<N>(),
        );
        let raw = db.any.log.merkle.get_node(pos).await.unwrap().unwrap();
        assert_eq!(published.nodes.get(&pos), Some(&raw));

        // Reopening rebuilds the same root and witness, and the mirror matches the reopened
        // database.
        let root = db.root();
        let witness = db.ops_root_witness().clone();
        db = db.sync().await.unwrap();
        drop(db);
        let db = TestDb::<F, N>::init(
            ctx.child("reopen"),
            fixed_config::<OneCap>("publication"),
            None,
        )
        .await
        .unwrap();
        assert_eq!(db.root(), root);
        let reopened = db.to_batch().delta();
        assert_eq!(reopened.witness, witness);
        published.check(&db, &reopened);
        db.destroy().await.unwrap();
    }

    /// Replaying deltas reproduces MMR and MMB databases and a database with 64-byte chunks.
    #[test_traced]
    fn test_publication_replays_mmr_and_mmb() {
        deterministic::Runner::default().start(|ctx| async move {
            replay::<mmr::Family, 32>(ctx.child("mmr")).await;
            replay::<mmb::Family, 32>(ctx.child("mmb")).await;
            replay::<mmr::Family, 64>(ctx.child("mmr64")).await;
        });
    }

    /// Replay a parent and its child, both merkleized before either is applied, into a mirror.
    async fn replay_chained<F: Graftable, const N: usize>(ctx: deterministic::Context) {
        // The parent writes more than two chunks of operations, so it appends grafted nodes, and
        // the child rewrites every key, so its delta both overwrites nodes the parent appended
        // and appends nodes of its own.
        let mut db = TestDb::<F, N>::init(
            ctx.child("storage"),
            fixed_config::<OneCap>("chained"),
            None,
        )
        .await
        .unwrap();
        let mut published = Published::from_db(&db);
        let count = (N * 16 + 5) as u64;
        let parent = write_keys(db.new_batch(), 0..count, 0)
            .merkleize_with(&db, &mut Hold)
            .await
            .unwrap();
        let child = write_keys(parent.new_batch::<Sha256>(), 0..count, 1)
            .merkleize_with(&db, &mut Hold)
            .await
            .unwrap();
        let parent_delta = parent.delta();
        let child_delta = child.delta();
        let parent_positions: BTreeSet<_> = parent_delta
            .grafted_nodes
            .iter()
            .map(|(pos, _)| *pos)
            .collect();
        assert!(!parent_positions.is_empty());
        assert!(
            child_delta
                .grafted_nodes
                .iter()
                .any(|(pos, _)| parent_positions.contains(pos))
        );
        assert!(
            child_delta
                .grafted_nodes
                .iter()
                .any(|(pos, _)| !parent_positions.contains(pos))
        );

        // The child's nodes are positioned relative to the parent, so applying the two deltas in
        // order keeps the mirror in step with the database.
        db = db.apply_batch(Arc::clone(&parent)).await.unwrap();
        published.apply(&parent_delta);
        published.check(&db, &parent_delta);
        db = db.apply_batch(child).await.unwrap();
        published.apply(&child_delta);
        published.check(&db, &child_delta);
        db.destroy().await.unwrap();
    }

    /// Replaying a chain whose unapplied parent appended grafted nodes places the child's nodes
    /// relative to the parent for both merkle families.
    #[test_traced]
    fn test_publication_replays_chained_batches() {
        deterministic::Runner::default().start(|ctx| async move {
            replay_chained::<mmr::Family, 32>(ctx.child("mmr")).await;
            replay_chained::<mmb::Family, 32>(ctx.child("mmb")).await;
        });
    }

    /// A delta carries the grafted leaf of a chunk that becomes graftable through operations-tree
    /// growth alone.
    #[test_traced]
    fn test_publication_pending_chunk_becomes_graftable_without_bitmap_write() {
        deterministic::Runner::default().start(|ctx| async move {
            // In MMB, chunk 0 becomes graftable only once the operations tree reaches
            // `graftable_at` operations.
            let mut db = TestDb::<mmb::Family, 32>::init(
                ctx.child("pending"),
                fixed_config::<OneCap>("pending"),
                None,
            )
            .await
            .unwrap();
            let mut published = Published::from_db(&db);
            let height = grafting::height::<32>();
            let chunk_root = mmb::Family::subtree_root_position(mmb::Location::new(0), height);
            let graftable_at = mmb::Family::peak_birth_size(chunk_root, height);

            // With the genesis commit and its own commit, the parent ends two operations short
            // of `graftable_at`, leaving chunk 0 complete but pending and a partial chunk after
            // it. Its delta keeps the mirror in step.
            let parent = write_keys(db.new_batch(), 0..graftable_at - 4, 0)
                .merkleize_with(&db, &mut Hold)
                .await
                .unwrap();
            assert_eq!(*parent.bounds().tip.size, graftable_at - 2);
            assert!(parent.ops_root_witness().pending_chunk_digest.is_some());
            assert!(parent.ops_root_witness().partial_chunk.is_some());
            let delta = parent.delta();
            db = db.apply_batch(Arc::clone(&parent)).await.unwrap();
            published.apply(&delta);
            published.check(&db, &delta);

            // Two empty batches add one commit each, so the second reaches `graftable_at` and
            // grafts chunk 0.
            let child = parent
                .new_batch::<Sha256>()
                .merkleize_with(&db, &mut Hold)
                .await
                .unwrap();
            let transition = child
                .new_batch::<Sha256>()
                .merkleize_with(&db, &mut Hold)
                .await
                .unwrap();
            assert_eq!(*transition.bounds().tip.size, graftable_at);
            assert!(transition.ops_root_witness().pending_chunk_digest.is_none());

            // The first empty batch's delta keeps the mirror in step.
            let child_delta = child.delta();
            db = db.apply_batch(Arc::clone(&child)).await.unwrap();
            published.apply(&child_delta);
            published.check(&db, &child_delta);

            // The second writes none of chunk 0's bits, yet chunk 0's grafted leaf is the only
            // grafted node in its delta. The mirror holds no grafted nodes before applying that
            // delta and matches the database after.
            let delta = transition.delta();
            assert!(!delta.chunks.iter().any(|(idx, _)| *idx == 0));
            assert_eq!(delta.grafted_nodes.len(), 1);
            assert!(published.nodes.is_empty());
            db = db.apply_batch(transition).await.unwrap();
            published.apply(&delta);
            published.check(&db, &delta);
            db.destroy().await.unwrap();
        });
    }

    /// A saved delta is unchanged after apply, prune, staleness, and dropped ancestors, and a
    /// batch held unmerkleized across a prune records the new pruning boundary.
    #[test_traced]
    fn test_publication_survives_apply_prune_and_stale_ancestors() {
        deterministic::Runner::default().start(|ctx| async move {
            // Four rounds of rewriting the same 256 keys under a proportional floor policy
            // leave enough inactive operations below the floor for a later prune to remove
            // whole chunks.
            let mut db = TestDb::<mmr::Family, 32>::init(
                ctx.child("lifecycle"),
                fixed_config::<OneCap>("lifecycle"),
                None,
            )
            .await
            .unwrap();
            for round in 0..4u64 {
                let batch = write_keys(db.new_batch(), 0..256, round)
                    .merkleize(&db)
                    .await
                    .unwrap();
                db = db.apply_batch(batch).await.unwrap();
            }

            // Save the deltas of an unapplied parent and a child that rewrites the first 16 keys,
            // and seed a mirror, before anything is pruned.
            let parent = db.new_batch().merkleize(&db).await.unwrap();
            let child = write_keys(parent.new_batch::<Sha256>(), 0..16, 4)
                .merkleize_with(&db, &mut Hold)
                .await
                .unwrap();
            let saved = child.delta();
            let saved_parent = parent.delta();
            let mut published = Published::from_db(&db);
            assert_eq!(saved.pruned_chunks, 0);

            // The parent's saved delta keeps the mirror in step.
            db = db.apply_batch(Arc::clone(&parent)).await.unwrap();
            published.apply(&saved_parent);
            published.check(&db, &saved_parent);

            // Pruning to the sync boundary removes at least one chunk and leaves every saved delta
            // unchanged, including that of a batch at the database's own state, while a fresh batch
            // at the pruned state records the new boundary. A copy of the child is written before
            // the prune and held unmerkleized across it.
            let base = db.to_batch();
            let saved_base = base.delta();
            let held = write_keys(parent.new_batch::<Sha256>(), 0..16, 4);
            let boundary = db.sync_boundary();
            db = db.prune(boundary).await.unwrap();
            assert!(db.bitmap().pruned_chunks() > 0);
            assert_eq!(child.delta(), saved);
            assert_eq!(parent.delta(), saved_parent);
            assert_eq!(base.delta(), saved_base);
            published.check(&db, &db.to_batch().delta());

            // The held copy writes the same 16 keys as the child, so once merkleized after pruning
            // it has the saved child's root, witness, chunks, and grafted nodes. It records the
            // boundary at merkleize, not when it was written, and the saved child's publication
            // still verifies.
            let post_prune = held.merkleize_with(&db, &mut Hold).await.unwrap();
            let post_delta = post_prune.delta();
            assert_eq!(post_prune.root(), child.root());
            assert_eq!(post_delta.chunks, saved.chunks);
            assert_eq!(post_delta.grafted_nodes, saved.grafted_nodes);
            assert_eq!(post_delta.pruned_chunks, db.bitmap().pruned_chunks() as u64);
            assert_eq!(post_prune.ops_root_witness(), child.ops_root_witness());
            check_publication(&child, &db);

            // The post-prune child's delta keeps the mirror in step.
            db = db.apply_batch(Arc::clone(&post_prune)).await.unwrap();
            published.apply(&post_delta);
            published.check(&db, &post_delta);

            // Once the database moves past the saved child's chain, publishing the child fails as
            // stale, but its delta is unchanged after the parent and the post-prune child are
            // dropped and the database is destroyed.
            let successor = db.new_batch().merkleize_with(&db, &mut Hold).await.unwrap();
            db = db.apply_batch(successor).await.unwrap();
            assert!(matches!(child.publication(&db), Err(Error::StaleRead)));
            drop(parent);
            drop(post_prune);
            db.destroy().await.unwrap();
            assert_eq!(child.delta(), saved);
            assert_eq!(base.delta(), saved_base);
        });
    }
}
