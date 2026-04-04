//! Batch mutation API for Any QMDBs.

use crate::{
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable, Reader},
    },
    merkle::{Family, Location},
    qmdb::{
        any::{
            db::Db,
            operation::{update, Operation},
            ordered::{find_next_key, find_prev_key},
            ValueEncoding,
        },
        bitmap::{BitmapBatch, ClearSet},
        delete_known_loc,
        operation::{Key, Operation as OperationTrait},
        update_known_loc,
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_utils::bitmap::{self, Readable as BitmapReadable};
use core::ops::Range;
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tracing::debug;

/// Strategy for finding the next active location during floor raising.
pub(crate) trait FloorScan<F: Family> {
    /// Return the next location at or after `floor` that might be active,
    /// below `tip`. Returns `None` if no candidate exists in `[floor, tip)`.
    fn next_candidate(&mut self, floor: Location<F>, tip: u64) -> Option<Location<F>>;
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

impl<F: Family, B: BitmapReadable<N>, const N: usize> FloorScan<F> for BitmapScan<'_, B, N> {
    fn next_candidate(&mut self, floor: Location<F>, tip: u64) -> Option<Location<F>> {
        let loc = *floor;
        if loc >= tip {
            return None;
        }
        let bitmap_len = self.bitmap.len();
        // Within the bitmap: find the next set bit at or after floor.
        if loc < bitmap_len {
            let bound = bitmap_len.min(tip);
            if let Some(idx) = self.bitmap.ones_iter_from(loc).next() {
                if idx < bound {
                    return Some(Location::new(idx));
                }
            }
        }
        // Beyond the bitmap: uncommitted ops from prior batches in the
        // chain that are not tracked by the bitmap yet. Conservatively
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

/// What happened to a key in this batch.
#[derive(Clone)]
pub(crate) enum DiffEntry<F: Family, V> {
    /// Key was updated (existing) or created (new).
    Active {
        value: V,
        /// Uncommitted location where this operation will be written.
        loc: Location<F>,
        /// The key's location in the committed DB snapshot, not an uncommitted
        /// location from an intermediate batch. `None` if the key is new to
        /// the committed DB. For chained batches, inherited from the base
        /// diff entry.
        base_old_loc: Option<Location<F>>,
    },
    /// Key was deleted.
    Deleted {
        /// The key's location in the committed DB snapshot, not an uncommitted
        /// location from an intermediate batch. `None` if the key was created
        /// by a prior batch and never existed in the committed DB. For
        /// chained batches, inherited from the base diff entry.
        base_old_loc: Option<Location<F>>,
    },
}

impl<F: Family, V> DiffEntry<F, V> {
    /// The key's location in the base DB snapshot, regardless of variant.
    pub(crate) const fn base_old_loc(&self) -> Option<Location<F>> {
        match self {
            Self::Active { base_old_loc, .. } | Self::Deleted { base_old_loc } => *base_old_loc,
        }
    }

    /// The uncommitted location if active, `None` if deleted.
    pub(crate) const fn loc(&self) -> Option<Location<F>> {
        match self {
            Self::Active { loc, .. } => Some(*loc),
            Self::Deleted { .. } => None,
        }
    }

    /// The value if active, `None` if deleted.
    pub(crate) const fn value(&self) -> Option<&V> {
        match self {
            Self::Active { value, .. } => Some(value),
            Self::Deleted { .. } => None,
        }
    }
}

/// A single snapshot index mutation to apply to the base DB's snapshot.
pub(crate) enum SnapshotDiff<F: Family, K> {
    /// Replace key's location: old_loc -> new_loc.
    Update {
        key: K,
        old_loc: Location<F>,
        new_loc: Location<F>,
    },
    /// Insert a new key at new_loc. The key must not exist in the base DB.
    Insert { key: K, new_loc: Location<F> },
    /// Remove key that was at old_loc.
    Delete { key: K, old_loc: Location<F> },
}

/// Shared snapshot of key-level changes accumulated across a batch chain.
type DiffSnapshot<F, U> =
    Arc<BTreeMap<<U as update::Update>::Key, DiffEntry<F, <U as update::Update>::Value>>>;

/// A speculative batch of operations whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Methods that need the committed DB (e.g. `get`, `merkleize`) accept it as a
/// parameter, so the batch is lifetime-free and can be stored independently of the DB.
pub struct UnmerkleizedBatch<F: Family, H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, U>>,

    /// Pending mutations. `Some(value)` for upsert, `None` for delete.
    mutations: BTreeMap<U::Key, Option<U::Value>>,

    /// Uncommitted key-level changes accumulated by prior batches in the chain.
    base_diff: DiffSnapshot<F, U>,

    /// One Arc segment of operations per prior batch in the chain.
    base_operations: Vec<Arc<Vec<Operation<F, U>>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// Inactivity floor location before this batch.
    base_inactivity_floor_loc: Location<F>,

    /// Size of the database when this batch was created.
    db_size: u64,

    /// Active key count before this batch.
    base_active_keys: usize,

    /// Activity bitmap state from the parent (committed DB or prior batch).
    /// Used for `BitmapScan` during floor raising.
    /// `None` when the any layer is embedded inside a `current::Db` that provides its own scan.
    bitmap_parent: Option<BitmapBatch<{ bitmap::DEFAULT_CHUNK_SIZE }>>,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
///
/// Owned and lifetime-free, so instances can be stored in homogeneous collections (e.g.
/// `HashMap<Digest, MerkleizedBatch>`) regardless of chain depth.
pub struct MerkleizedBatch<F: Family, D: Digest, U: update::Update + Send + Sync>
where
    Operation<F, U>: Send + Sync,
{
    /// Merkleized authenticated journal batch (provides the speculative Merkle root).
    pub(crate) journal_batch: authenticated::MerkleizedBatch<F, D, Operation<F, U>>,

    /// All uncommitted key-level changes in this batch chain.
    pub(crate) diff: DiffSnapshot<F, U>,

    /// Inactivity floor location after this batch's floor raise.
    new_inactivity_floor_loc: Location<F>,

    /// Location of the CommitFloor operation appended by this batch.
    pub(crate) new_last_commit_loc: Location<F>,

    /// Total operation count after this batch.
    total_size: u64,

    /// Total active keys after this batch.
    total_active_keys: usize,

    /// The database size when the initial batch was created.
    pub(crate) db_size: u64,

    /// Activity bitmap state after this batch (parent bitmap + this batch's layer).
    /// `None` when the any layer is embedded inside a `current::Db`.
    bitmap: Option<BitmapBatch<{ bitmap::DEFAULT_CHUNK_SIZE }>>,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<F: Family, K, D: Digest, Item: Send> {
    /// The finalized authenticated journal batch (Merkle changeset + item chain).
    journal_finalized: authenticated::Changeset<F, D, Item>,

    /// Snapshot mutations to apply, in order.
    snapshot_diffs: Vec<SnapshotDiff<F, K>>,

    /// Net change in active key count.
    active_keys_delta: isize,

    /// Inactivity floor location after this batch's floor raise.
    new_inactivity_floor_loc: Location<F>,

    /// Location of the CommitFloor operation appended by this batch.
    new_last_commit_loc: Location<F>,

    /// The database size when the batch was created. Used to detect stale changesets.
    db_size: u64,

    /// Activity bitmap: bits pushed by this batch chain.
    pub(crate) bitmap_pushes: Vec<bool>,

    /// Activity bitmap: bit indices cleared by this batch chain, with per-chunk masks.
    pub(crate) bitmap_clears: ClearSet<{ bitmap::DEFAULT_CHUNK_SIZE }>,
}

/// Batch-infrastructure state used during merkleization.
///
/// Created by [`UnmerkleizedBatch::into_parts()`], which separates the pending
/// mutations from the resolution/merkleization machinery. Helpers that need
/// access to the base diff, DB snapshot, or operation chain are methods on this
/// struct, eliminating parameter threading.
struct Merkleizer<F: Family, H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, U>>,
    base_diff: DiffSnapshot<F, U>,
    base_operations: Vec<Arc<Vec<Operation<F, U>>>>,
    base_size: u64,
    db_size: u64,
    base_inactivity_floor_loc: Location<F>,
    base_active_keys: usize,
    bitmap_parent: Option<BitmapBatch<{ bitmap::DEFAULT_CHUNK_SIZE }>>,
}

impl<F: Family, H, U> Merkleizer<F, H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Read an operation at a given location from the correct source.
    ///
    /// The operation space is divided into three contiguous regions:
    ///
    /// ```text
    ///  [0 ........... db_size)  [db_size ..... base_size)  [base_size .. base_size+len)
    ///   DB journal (on disk)    parent chain (in mem)       current_ops (in mem)
    /// ```
    ///
    /// For top-level batches, the parent chain is empty, so db_size == base.
    async fn read_op<E, C, I>(
        &self,
        loc: Location<F>,
        current_ops: &[Operation<F, U>],
        db: &Db<F, E, C, I, H, U>,
    ) -> Result<Operation<F, U>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let loc_val = *loc;

        if loc_val >= self.base_size {
            // This batch's own operations (user mutations, or earlier floor-raise ops).
            Ok(current_ops[(loc_val - self.base_size) as usize].clone())
        } else if loc_val >= self.db_size {
            // Parent batch chain's operations (in-memory). Walk segments to find the right one.
            let mut offset = (loc_val - self.db_size) as usize;
            for segment in &self.base_operations {
                if offset < segment.len() {
                    return Ok(segment[offset].clone());
                }
                offset -= segment.len();
            }
            unreachable!("location within parent chain range but not found in segments");
        } else {
            // Base DB's journal (on-disk async read).
            let reader = db.log.reader().await;
            Ok(reader.read(loc_val).await?)
        }
    }

    /// Gather existing-key locations for all keys in `mutations`.
    ///
    /// For each mutation key, checks the base diff first (returning the
    /// uncommitted location for Active entries, skipping Deleted entries).
    /// Keys not in the base diff fall back to the base DB snapshot.
    ///
    /// When `include_active_collision_siblings` is true, Active entries
    /// also scan the snapshot bucket for collision siblings (other keys
    /// sharing the same translated-key bucket). The ordered path needs
    /// these so their `next_key` pointers are rewritten when a sibling
    /// is deleted; the unordered path can skip them.
    fn gather_existing_locations<E, C, I>(
        &self,
        mutations: &BTreeMap<U::Key, Option<U::Value>>,
        db: &Db<F, E, C, I, H, U>,
        include_active_collision_siblings: bool,
    ) -> Vec<Location<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        // Extra slack (*3/2) avoids re-allocations when index collisions
        // cause more than one location per key.
        let mut locations = Vec::with_capacity(mutations.len() * 3 / 2);
        if self.base_diff.is_empty() {
            for key in mutations.keys() {
                locations.extend(db.snapshot.get(key).copied());
            }
        } else {
            for key in mutations.keys() {
                match self.base_diff.get(key) {
                    Some(DiffEntry::Deleted { .. }) => {
                        // Stale; handled via extract_parent_deleted_creates.
                    }
                    Some(DiffEntry::Active {
                        loc, base_old_loc, ..
                    }) => {
                        // Push the parent's uncommitted location, then scan
                        // the snapshot bucket for collision siblings (excluding
                        // this key's own stale committed location).
                        locations.push(*loc);
                        if include_active_collision_siblings {
                            locations.extend(
                                db.snapshot
                                    .get(key)
                                    .copied()
                                    .filter(move |loc| Some(*loc) != *base_old_loc),
                            );
                        }
                    }
                    None => {
                        locations.extend(db.snapshot.get(key).copied());
                    }
                }
            }
        }
        locations.sort();
        locations.dedup();
        locations
    }

    /// Check if the operation at `loc` for `key` is still active.
    fn is_active_at<E, C, I>(
        &self,
        key: &U::Key,
        loc: Location<F>,
        batch_diff: &BTreeMap<U::Key, DiffEntry<F, U::Value>>,
        db: &Db<F, E, C, I, H, U>,
    ) -> bool
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        if let Some(entry) = batch_diff.get(key).or_else(|| self.base_diff.get(key)) {
            return entry.loc() == Some(loc);
        }
        db.snapshot.get(key).any(|&l| l == loc)
    }

    /// Extract keys that were deleted by a parent batch but are being
    /// re-created by this child batch. Removes those keys from `mutations`
    /// and returns `(key, (value, base_old_loc))` entries.
    #[allow(clippy::type_complexity)]
    fn extract_parent_deleted_creates(
        &self,
        mutations: &mut BTreeMap<U::Key, Option<U::Value>>,
    ) -> BTreeMap<U::Key, (U::Value, Option<Location<F>>)> {
        if self.base_diff.is_empty() {
            return BTreeMap::new();
        }
        let mut creates = BTreeMap::new();
        mutations.retain(|key, value| {
            if let Some(DiffEntry::Deleted { base_old_loc }) = self.base_diff.get(key) {
                if let Some(v) = value.take() {
                    creates.insert(key.clone(), (v, *base_old_loc));
                    return false;
                }
            }
            true
        });
        creates
    }

    /// Scan forward from `floor` to find the next active operation, re-append it at the tip.
    /// The `scan` parameter controls which locations are considered as potentially active,
    /// allowing implementations to skip locations known to be inactive without reading them.
    /// Returns `true` if an active op was found and moved, `false` if the floor reached
    /// `fixed_tip`.
    async fn advance_floor_once<E, C, I, S: FloorScan<F>>(
        &self,
        floor: &mut Location<F>,
        fixed_tip: u64,
        ops: &mut Vec<Operation<F, U>>,
        diff: &mut BTreeMap<U::Key, DiffEntry<F, U::Value>>,
        scan: &mut S,
        db: &Db<F, E, C, I, H, U>,
    ) -> Result<bool, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        loop {
            let Some(candidate) = scan.next_candidate(*floor, fixed_tip) else {
                return Ok(false);
            };
            *floor = Location::new(*candidate + 1);

            let op = self.read_op(candidate, ops, db).await?;
            let Some(key) = op.key().cloned() else {
                continue; // skip CommitFloor and other non-keyed ops
            };

            if self.is_active_at(&key, candidate, diff, db) {
                let new_loc = Location::new(self.base_size + ops.len() as u64);
                let base_old_loc = diff
                    .get(&key)
                    .or_else(|| self.base_diff.get(&key))
                    .map_or(Some(candidate), DiffEntry::base_old_loc);
                let value = extract_update_value(&op);
                ops.push(op);
                diff.insert(
                    key,
                    DiffEntry::Active {
                        value,
                        loc: new_loc,
                        base_old_loc,
                    },
                );
                return Ok(true);
            }
        }
    }

    /// Shared final phases of merkleization: floor raise, CommitFloor, journal
    /// merkleize, diff merge, and `MerkleizedBatch` construction.
    #[allow(clippy::too_many_arguments)]
    async fn finish<E, C, I, S: FloorScan<F>>(
        mut self,
        mut ops: Vec<Operation<F, U>>,
        mut diff: BTreeMap<U::Key, DiffEntry<F, U::Value>>,
        active_keys_delta: isize,
        user_steps: u64,
        metadata: Option<U::Value>,
        mut scan: S,
        db: &Db<F, E, C, I, H, U>,
    ) -> Result<MerkleizedBatch<F, H::Digest, U>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        // Floor raise.
        // Steps = user_steps + 1 (+1 for previous commit becoming inactive).
        let total_steps = user_steps + 1;
        let total_active_keys = self.base_active_keys as isize + active_keys_delta;
        let mut floor = self.base_inactivity_floor_loc;

        if total_active_keys > 0 {
            // Floor raise: advance the inactivity floor by `total_steps` active
            // operations. `fixed_tip` prevents scanning into floor-raise moves
            // just appended, matching `raise_floor_with_bitmap()` semantics.
            let fixed_tip = self.base_size + ops.len() as u64;

            for _ in 0..total_steps {
                if !self
                    .advance_floor_once(&mut floor, fixed_tip, &mut ops, &mut diff, &mut scan, db)
                    .await?
                {
                    break;
                }
            }
        } else {
            // DB is empty after this batch; raise floor to tip.
            floor = Location::new(self.base_size + ops.len() as u64);
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        }

        // CommitFloor operation.
        let commit_loc = Location::new(self.base_size + ops.len() as u64);
        ops.push(Operation::CommitFloor(metadata, floor));

        // Merkleize the journal batch.
        // The journal batch was created eagerly at batch construction time and its
        // parent already contains all prior batches' Merkle state, so we only
        // add THIS batch's operations. Parent operations are never re-cloned,
        // re-encoded, or re-hashed.
        let ops = Arc::new(ops);
        let journal = self.journal_batch.merkleize_with(ops.clone());

        // Build the operation chain: parent segments + this batch's segment.
        self.base_operations.push(ops);

        // Merge with base diff: entries not overridden by this batch.
        // O(K) deep copy (K = distinct keys in parent diff) when the parent MerkleizedBatch or
        // any sibling UnmerkleizedBatch still exists. O(1) when all have been dropped.
        let base_diff = Arc::try_unwrap(self.base_diff).unwrap_or_else(|arc| (*arc).clone());
        for (k, v) in base_diff {
            diff.entry(k).or_insert(v);
        }

        // Compute activity bitmap mutations for this batch (only when bitmap is maintained
        // at this layer, i.e. standalone any::Db, not embedded in current::Db).
        let bitmap = if let Some(mut bitmap_parent) = self.bitmap_parent {
            let this_segment = self
                .base_operations
                .last()
                .expect("chain should not be empty");
            let segment_base = *commit_loc + 1 - this_segment.len() as u64;
            let mut bitmap_pushes = Vec::with_capacity(this_segment.len());
            let mut bitmap_clears = ClearSet::default();

            // Clear the previous commit bit.
            bitmap_clears.push(segment_base - 1);

            // Push one bit per operation in this segment.
            for (i, op) in this_segment.iter().enumerate() {
                let op_loc = Location::new(segment_base + i as u64);
                match op {
                    Operation::Update(update) => {
                        let is_active = diff
                            .get(update.key())
                            .is_some_and(|entry| entry.loc() == Some(op_loc));
                        bitmap_pushes.push(is_active);
                    }
                    Operation::CommitFloor(..) => {
                        bitmap_pushes.push(true);
                    }
                    Operation::Delete(..) => {
                        bitmap_pushes.push(false);
                    }
                }
            }

            // Clear bits for base-DB operations superseded by this chain's diff.
            for entry in diff.values() {
                if let Some(old) = entry.base_old_loc() {
                    bitmap_clears.push(*old);
                }
            }

            // Clear ancestor-segment operations superseded by a later segment (chained batches).
            let chain = &self.base_operations;
            if chain.len() > 1 {
                let mut seg_base = self.db_size;
                for ancestor_seg in &chain[..chain.len() - 1] {
                    for (j, op) in ancestor_seg.iter().enumerate() {
                        if let Some(key) = op.key() {
                            let ancestor_loc = Location::new(seg_base + j as u64);
                            if let Some(entry) = diff.get(key) {
                                if entry.loc() != Some(ancestor_loc) {
                                    bitmap_clears.push(*ancestor_loc);
                                }
                            }
                        }
                    }
                    seg_base += ancestor_seg.len() as u64;
                }
            }

            // Build the bitmap state for this batch by pushing a layer.
            bitmap_parent.push_changeset(bitmap_pushes, bitmap_clears);
            Some(bitmap_parent)
        } else {
            None
        };

        debug_assert!(total_active_keys >= 0, "active_keys underflow");
        Ok(MerkleizedBatch {
            journal_batch: journal,
            diff: Arc::new(diff),
            new_inactivity_floor_loc: floor,
            new_last_commit_loc: commit_loc,
            total_size: *commit_loc + 1,
            total_active_keys: total_active_keys as usize,
            db_size: self.db_size,
            bitmap,
        })
    }
}

impl<F: Family, H, U> UnmerkleizedBatch<F, H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Record a mutation. Use `Some(value)` for update/create, `None` for delete.
    ///
    /// If the same key is written multiple times within a batch, the last
    /// value wins.
    pub fn write(mut self, key: U::Key, value: Option<U::Value>) -> Self {
        self.mutations.insert(key, value);
        self
    }

    /// Split into pending mutations and the merkleization machinery.
    #[allow(clippy::type_complexity)]
    fn into_parts(self) -> (BTreeMap<U::Key, Option<U::Value>>, Merkleizer<F, H, U>) {
        (
            self.mutations,
            Merkleizer {
                journal_batch: self.journal_batch,
                base_diff: self.base_diff,
                base_operations: self.base_operations,
                base_size: self.base_size,
                db_size: self.db_size,
                base_inactivity_floor_loc: self.base_inactivity_floor_loc,
                base_active_keys: self.base_active_keys,
                bitmap_parent: self.bitmap_parent,
            },
        )
    }
}

// Generic get() for both ordered and unordered UnmerkleizedBatch.
impl<F: Family, H, U> UnmerkleizedBatch<F, H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &U::Key,
        db: &Db<F, E, C, I, H, U>,
    ) -> Result<Option<U::Value>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        if let Some(value) = self.mutations.get(key) {
            return Ok(value.clone());
        }
        if let Some(entry) = self.base_diff.get(key) {
            return Ok(entry.value().cloned());
        }
        db.get(key).await
    }
}

// Unordered-specific methods.
impl<F: Family, K, V, H> UnmerkleizedBatch<F, H, update::Unordered<K, V>>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return a [`MerkleizedBatch`].
    ///
    /// Uses the bitmap from `bitmap_parent` (must be `Some`) to create a `BitmapScan` for
    /// floor raising. For callers that supply their own scan (e.g. `current::Db`), use
    /// [`merkleize_with_floor_scan`](Self::merkleize_with_floor_scan) instead.
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>>,
    ) -> Result<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        // Pre-extend the bitmap to cover user ops so the scan has accurate bits
        // for the full [0, fixed_tip) range. The bitmap must be present for
        // standalone any::Db use.
        let bitmap_parent = self
            .bitmap_parent
            .clone()
            .expect("standalone any::Db must have bitmap");
        assert!(
            bitmap_parent.len() >= self.base_size,
            "bitmap ({}) must cover committed range [0, {})",
            bitmap_parent.len(),
            self.base_size,
        );
        let scan = BitmapScan::new(&bitmap_parent);
        self.merkleize_with_floor_scan(metadata, scan, db).await
    }

    /// Like [`merkleize`](Self::merkleize) but accepts a custom [`FloorScan`]
    /// to accelerate floor raising.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, S: FloorScan<F>>(
        self,
        metadata: Option<V::Value>,
        scan: S,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>>,
    ) -> Result<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let (mut mutations, m) = self.into_parts();

        // Resolve existing keys (async I/O, parallelized).
        let locations = m.gather_existing_locations(&mutations, db, false);
        let futures = locations.iter().map(|&loc| m.read_op(loc, &[], db));
        let results = try_join_all(futures).await?;

        // Generate user mutation operations.
        let mut ops: Vec<Operation<F, update::Unordered<K, V>>> =
            Vec::with_capacity(mutations.len() + 1);
        let mut diff: BTreeMap<K, DiffEntry<F, V::Value>> = BTreeMap::new();
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;

        // Process updates/deletes of existing keys in location order.
        // This includes keys from both the base snapshot and the base diff.
        for (op, &old_loc) in results.iter().zip(&locations) {
            let key = op.key().expect("updates should have a key");

            // A key resolved via base_diff must only match at its base_diff
            // location. Without this guard, a stale snapshot collision (the
            // pre-parent DB snapshot still containing the key's old location)
            // can consume the mutation at the wrong sort position, changing
            // the operation order relative to the committed-state path. When
            // the base diff entry does match, use it to trace `base_old_loc`
            // back to the key's location in the base DB snapshot.
            let base_old_loc = if let Some(entry) = m.base_diff.get(key) {
                if entry.loc() != Some(old_loc) {
                    continue;
                }
                entry.base_old_loc()
            } else {
                Some(old_loc)
            };

            let Some(mutation) = mutations.remove(key) else {
                // Snapshot index collision: this operation's key does not match
                // any mutation key. The mutation will be handled as a create below.
                continue;
            };

            // Write the user mutation at the next batch location while
            // preserving the committed-base provenance computed above.
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            match mutation {
                Some(value) => {
                    ops.push(Operation::Update(update::Unordered(
                        key.clone(),
                        value.clone(),
                    )));
                    diff.insert(
                        key.clone(),
                        DiffEntry::Active {
                            value,
                            loc: new_loc,
                            base_old_loc,
                        },
                    );
                    user_steps += 1;
                }
                None => {
                    ops.push(Operation::Delete(key.clone()));
                    diff.insert(key.clone(), DiffEntry::Deleted { base_old_loc });
                    active_keys_delta -= 1;
                    user_steps += 1;
                }
            }
        }

        // Handle parent-deleted keys that the child wants to re-create.
        let parent_deleted_creates = m.extract_parent_deleted_creates(&mut mutations);

        // Process creates: remaining mutations (fresh keys) plus parent-deleted
        // keys being re-created. Both get an Update op and active_keys_delta += 1.
        let fresh = mutations
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| (k, v, None)));
        let recreates = parent_deleted_creates
            .into_iter()
            .map(|(k, (v, loc))| (k, v, loc));
        for (key, value, base_old_loc) in fresh.chain(recreates) {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            ops.push(Operation::Update(update::Unordered(
                key.clone(),
                value.clone(),
            )));
            diff.insert(
                key,
                DiffEntry::Active {
                    value,
                    loc: new_loc,
                    base_old_loc,
                },
            );
            active_keys_delta += 1;
        }

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(ops, diff, active_keys_delta, user_steps, metadata, scan, db)
            .await
    }
}

// Ordered-specific methods.
impl<F: Family, K, V, H> UnmerkleizedBatch<F, H, update::Ordered<K, V>>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return a [`MerkleizedBatch`].
    ///
    /// Uses the bitmap from `bitmap_parent` (must be `Some`) to create a `BitmapScan` for
    /// floor raising. For callers that supply their own scan (e.g. `current::Db`), use
    /// [`merkleize_with_floor_scan`](Self::merkleize_with_floor_scan) instead.
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>>,
    ) -> Result<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        let bitmap_parent = self
            .bitmap_parent
            .clone()
            .expect("standalone any::Db must have bitmap");
        assert!(
            bitmap_parent.len() >= self.base_size,
            "bitmap ({}) must cover committed range [0, {})",
            bitmap_parent.len(),
            self.base_size,
        );
        let scan = BitmapScan::new(&bitmap_parent);
        self.merkleize_with_floor_scan(metadata, scan, db).await
    }

    /// Like [`merkleize`](Self::merkleize) but accepts a custom [`FloorScan`]
    /// to accelerate floor raising.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, S: FloorScan<F>>(
        self,
        metadata: Option<V::Value>,
        scan: S,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>>,
    ) -> Result<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        let (mut mutations, m) = self.into_parts();

        // Resolve existing keys (async I/O).
        let locations = m.gather_existing_locations(&mutations, db, true);

        // Read and unwrap Update operations (snapshot only references Updates).
        let futures = locations.iter().map(|&loc| m.read_op(loc, &[], db));
        let update_results: Vec<_> = try_join_all(futures)
            .await?
            .into_iter()
            .map(|op| match op {
                Operation::Update(data) => data,
                _ => unreachable!("snapshot should only reference Update operations"),
            })
            .collect();

        // Classify mutations into deleted, created, updated.
        let mut next_candidates: BTreeSet<K> = BTreeSet::new();
        let mut prev_candidates: BTreeMap<K, (V::Value, Location<F>)> = BTreeMap::new();

        let mut deleted: BTreeMap<K, Location<F>> = BTreeMap::new();
        let mut updated: BTreeMap<K, (V::Value, Location<F>)> = BTreeMap::new();

        for (key_data, &old_loc) in update_results.into_iter().zip(&locations) {
            let update::Ordered {
                key,
                value,
                next_key,
            } = key_data;
            next_candidates.insert(next_key);

            let mutation = mutations.remove(&key);
            prev_candidates.insert(key.clone(), (value, old_loc));

            let Some(mutation) = mutation else {
                // Snapshot index collision: this operation's key does not match
                // the mutation key (the snapshot uses a compressed translated key
                // that can collide). The mutation will be handled as a create below.
                continue;
            };

            if let Some(new_value) = mutation {
                updated.insert(key, (new_value, old_loc));
            } else {
                deleted.insert(key, old_loc);
            }
        }

        // Handle parent-deleted keys that the child wants to re-create.
        let parent_deleted_creates = m.extract_parent_deleted_creates(&mut mutations);

        // Remaining mutations are creates. Each entry carries the value and
        // base_old_loc (None for fresh creates, Some for parent-deleted recreates).
        let mut created: BTreeMap<K, (V::Value, Option<Location<F>>)> = BTreeMap::new();
        for (key, value) in mutations {
            let Some(value) = value else {
                continue; // delete of non-existent key
            };
            created.insert(key.clone(), (value, None));
            next_candidates.insert(key);
        }
        for (key, (value, base_old_loc)) in parent_deleted_creates {
            next_candidates.insert(key.clone());
            created.insert(key, (value, base_old_loc));
        }

        // Look up prev_translated_key for created/deleted keys.
        let mut prev_locations = Vec::new();
        for key in deleted.keys().chain(created.keys()) {
            let Some((iter, _)) = db.snapshot.prev_translated_key(key) else {
                continue;
            };
            prev_locations.extend(iter.copied());
        }
        prev_locations.sort();
        prev_locations.dedup();

        let prev_results = {
            let reader = db.log.reader().await;
            let futures = prev_locations.iter().map(|loc| reader.read(**loc));
            try_join_all(futures).await?
        };

        for (op, &old_loc) in prev_results.into_iter().zip(&prev_locations) {
            let data = match op {
                Operation::Update(data) => data,
                _ => unreachable!("expected update operation"),
            };
            next_candidates.insert(data.next_key);
            prev_candidates.insert(data.key, (data.value, old_loc));
        }

        // Add base-diff-created keys to candidate sets. These keys may be
        // predecessors or successors of this batch's mutations but are invisible
        // to the base-DB-only prev_translated_key lookup above.
        for (key, entry) in &*m.base_diff {
            // Skip keys already handled by this batch's mutations.
            if updated.contains_key(key) || created.contains_key(key) || deleted.contains_key(key) {
                continue;
            }
            if let DiffEntry::Active { value, loc, .. } = entry {
                let op: Operation<F, update::Ordered<K, V>> = m.read_op(*loc, &[], db).await?;
                let data = match op {
                    Operation::Update(data) => data,
                    _ => unreachable!("base diff Active should reference Update op"),
                };
                next_candidates.insert(key.clone());
                next_candidates.insert(data.next_key);
                prev_candidates.insert(key.clone(), (value.clone(), *loc));
            }
        }

        // Remove all known-deleted keys from possible_* sets. The
        // prev_translated_key lookup already did this for this batch's deletes,
        // but the base diff incorporation may have re-added them via next_key
        // references. Also remove parent-deleted keys that the base DB lookup may
        // have added.
        for key in deleted.keys() {
            prev_candidates.remove(key);
            next_candidates.remove(key);
        }
        for (key, entry) in &*m.base_diff {
            if matches!(entry, DiffEntry::Deleted { .. }) && !created.contains_key(key) {
                prev_candidates.remove(key);
                next_candidates.remove(key);
            }
        }

        // Generate operations.
        let mut ops: Vec<Operation<F, update::Ordered<K, V>>> =
            Vec::with_capacity(deleted.len() + updated.len() + created.len() + 1);
        let mut diff: BTreeMap<K, DiffEntry<F, V::Value>> = BTreeMap::new();
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;
        // Process deletes.
        for (key, old_loc) in &deleted {
            ops.push(Operation::Delete(key.clone()));

            let base_old_loc = m
                .base_diff
                .get(key)
                .map_or(Some(*old_loc), DiffEntry::base_old_loc);

            diff.insert(key.clone(), DiffEntry::Deleted { base_old_loc });
            active_keys_delta -= 1;
            user_steps += 1;
        }

        // Process updates of existing keys.
        for (key, (value, old_loc)) in updated {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            let next_key = find_next_key(&key, &next_candidates);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));

            let base_old_loc = m
                .base_diff
                .get(&key)
                .map_or(Some(old_loc), DiffEntry::base_old_loc);

            diff.insert(
                key,
                DiffEntry::Active {
                    value,
                    loc: new_loc,
                    base_old_loc,
                },
            );
            user_steps += 1;
        }

        // Collect created keys for the predecessor loop before consuming.
        let mut created_keys: Vec<K> = Vec::with_capacity(created.len());

        // Process creates.
        for (key, (value, base_old_loc)) in created {
            created_keys.push(key.clone());
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            let next_key = find_next_key(&key, &next_candidates);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));
            diff.insert(
                key,
                DiffEntry::Active {
                    value,
                    loc: new_loc,
                    base_old_loc,
                },
            );
            active_keys_delta += 1;
        }

        // Update predecessors of created and deleted keys.
        if !prev_candidates.is_empty() {
            for key in created_keys.iter().chain(deleted.keys()) {
                let (prev_key, (prev_value, prev_loc)) = find_prev_key(key, &prev_candidates);
                if diff.contains_key(prev_key) {
                    continue;
                }

                let prev_new_loc = Location::new(m.base_size + ops.len() as u64);
                let prev_next_key = find_next_key(prev_key, &next_candidates);
                ops.push(Operation::Update(update::Ordered {
                    key: prev_key.clone(),
                    value: prev_value.clone(),
                    next_key: prev_next_key,
                }));

                let prev_base_old_loc = m
                    .base_diff
                    .get(prev_key)
                    .map_or(Some(*prev_loc), DiffEntry::base_old_loc);

                diff.insert(
                    prev_key.clone(),
                    DiffEntry::Active {
                        value: prev_value.clone(),
                        loc: prev_new_loc,
                        base_old_loc: prev_base_old_loc,
                    },
                );
                user_steps += 1;
            }
        }

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(ops, diff, active_keys_delta, user_steps, metadata, scan, db)
            .await
    }
}

impl<F: Family, D: Digest, U: update::Update + Send + Sync> MerkleizedBatch<F, D, U>
where
    Operation<F, U>: Send + Sync,
{
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal_batch.root()
    }
}

impl<F: Family, D: Digest, U: update::Update + Send + Sync> MerkleizedBatch<F, D, U>
where
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H>(&self) -> UnmerkleizedBatch<F, H, U>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            mutations: BTreeMap::new(),
            base_diff: Arc::clone(&self.diff),
            base_operations: self.journal_batch.items.clone(),
            base_size: self.total_size,
            db_size: self.db_size,
            base_inactivity_floor_loc: self.new_inactivity_floor_loc,
            base_active_keys: self.total_active_keys,
            bitmap_parent: self.bitmap.clone(),
        }
    }

    /// Read through: diff -> committed DB.
    pub async fn get<E, C, I, H>(
        &self,
        key: &U::Key,
        db: &Db<F, E, C, I, H, U>,
    ) -> Result<Option<U::Value>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher<Digest = D>,
    {
        if let Some(entry) = self.diff.get(key) {
            return Ok(entry.value().cloned());
        }
        db.get(key).await
    }

    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<F, U::Key, D, Operation<F, U>>
    where
        U: 'static,
    {
        // O(K) deep copy (K = distinct keys in diff) when a child UnmerkleizedBatch or
        // MerkleizedBatch still exists. O(1) when all children have been dropped.
        let diff = Arc::try_unwrap(self.diff).unwrap_or_else(|arc| (*arc).clone());
        let snapshot_diffs: Vec<_> = diff
            .into_iter()
            .filter_map(|(key, entry)| match entry {
                // Key was updated; it existed in the base DB at old_loc.
                DiffEntry::Active {
                    loc,
                    base_old_loc: Some(old),
                    ..
                } => Some(SnapshotDiff::Update {
                    key,
                    old_loc: old,
                    new_loc: loc,
                }),
                // Key was created; did not exist in the base DB.
                DiffEntry::Active {
                    loc,
                    base_old_loc: None,
                    ..
                } => Some(SnapshotDiff::Insert { key, new_loc: loc }),
                // Key was deleted; it existed in the base DB at old_loc.
                DiffEntry::Deleted {
                    base_old_loc: Some(old),
                } => Some(SnapshotDiff::Delete { key, old_loc: old }),
                // Key was created then deleted within the batch chain.
                // Net effect on the base DB is nothing.
                DiffEntry::Deleted { base_old_loc: None } => None,
            })
            .collect();

        // Compute active_keys_delta from snapshot diffs. This is always correct
        // regardless of chain depth because the diffs reflect the net effect
        // of the entire batch chain on the base DB.
        let active_keys_delta = snapshot_diffs
            .iter()
            .map(|d| match d {
                SnapshotDiff::Insert { .. } => 1isize,
                SnapshotDiff::Delete { .. } => -1,
                SnapshotDiff::Update { .. } => 0,
            })
            .sum::<isize>();

        let (bitmap_pushes, bitmap_clears) = self
            .bitmap
            .as_ref()
            .map(|bm| bm.collect_mutations())
            .unwrap_or_default();
        Changeset {
            journal_finalized: self.journal_batch.finalize(),
            snapshot_diffs,
            active_keys_delta,
            new_inactivity_floor_loc: self.new_inactivity_floor_loc,
            new_last_commit_loc: self.new_last_commit_loc,
            db_size: self.db_size,
            bitmap_pushes,
            bitmap_clears,
        }
    }

    /// Like [`Self::finalize`], but produces a [`Changeset`] relative to `current_db_size`
    /// instead of the original DB size when this batch chain was created.
    ///
    /// Use this when an ancestor batch in the chain has already been committed, advancing
    /// the DB's operation count past the original fork point. For example, given a chain
    /// `db -> A -> B`, after committing A: call `B.finalize_from(db.bounds().await.end)`
    /// to produce a changeset containing only B's operations and snapshot diffs, with
    /// `old_loc` values adjusted to reflect the current committed DB state.
    ///
    /// # Panics
    ///
    /// Panics if `current_db_size` is less than the DB size when this batch was created.
    pub fn finalize_from(self, current_db_size: u64) -> Changeset<F, U::Key, D, Operation<F, U>>
    where
        U: 'static,
    {
        assert!(
            current_db_size >= self.db_size,
            "current_db_size ({current_db_size}) < batch db_size ({})",
            self.db_size
        );
        let items_to_skip = current_db_size - self.db_size;

        // Scan committed ancestor operations to learn each key's current
        // committed location. `Some(loc)` = active at loc; `None` = deleted.
        let committed_actions = {
            let mut map: BTreeMap<U::Key, Option<Location<F>>> = BTreeMap::new();
            let mut remaining = items_to_skip as usize;
            let mut offset = self.db_size;
            for seg in &self.journal_batch.items {
                let take = remaining.min(seg.len());
                for op in &seg[..take] {
                    let loc = Location::new(offset);
                    if let Some(key) = OperationTrait::key(op) {
                        if op.is_update() {
                            map.insert(key.clone(), Some(loc));
                        } else if op.is_delete() {
                            map.insert(key.clone(), None);
                        }
                    }
                    offset += 1;
                }
                remaining -= take;
                if remaining == 0 {
                    break;
                }
            }
            map
        };

        // O(K) deep copy (K = distinct keys in diff) when a child UnmerkleizedBatch or
        // MerkleizedBatch still exists. O(1) when all children have been dropped.
        let diff = Arc::try_unwrap(self.diff).unwrap_or_else(|arc| (*arc).clone());
        let snapshot_diffs: Vec<_> = diff
            .into_iter()
            .filter_map(|(key, entry)| {
                // Determine the key's current location in the committed DB.
                // Priority: committed ancestor action > original base location.
                let resolve_old_loc = |base_old_loc: Option<Location<F>>| -> Option<Location<F>> {
                    match committed_actions.get(&key) {
                        Some(Some(loc)) => Some(*loc), // ancestor set it here
                        Some(None) => None,            // ancestor deleted it
                        None => base_old_loc,          // ancestor didn't touch it
                    }
                };

                match entry {
                    // Skip entries committed by ancestors.
                    DiffEntry::Active { loc, .. } if *loc < current_db_size => None,
                    DiffEntry::Active {
                        loc, base_old_loc, ..
                    } => {
                        let old = resolve_old_loc(base_old_loc);
                        if let Some(old_loc) = old {
                            Some(SnapshotDiff::Update {
                                key,
                                old_loc,
                                new_loc: loc,
                            })
                        } else {
                            Some(SnapshotDiff::Insert { key, new_loc: loc })
                        }
                    }
                    DiffEntry::Deleted { base_old_loc } => {
                        let old = resolve_old_loc(base_old_loc);
                        old.map(|old_loc| SnapshotDiff::Delete { key, old_loc })
                    }
                }
            })
            .collect();

        let active_keys_delta = snapshot_diffs
            .iter()
            .map(|d| match d {
                SnapshotDiff::Insert { .. } => 1isize,
                SnapshotDiff::Delete { .. } => -1,
                SnapshotDiff::Update { .. } => 0,
            })
            .sum::<isize>();

        // Collect bitmap mutations, skipping pushes for already-committed operations.
        // Clears are kept in full since set_bit(loc, false) is idempotent.
        // When bitmap is None (embedded in current::Db), the any layer has no bitmap
        // mutations -- the current layer manages its own bitmap.
        let (bitmap_pushes, bitmap_clears) =
            self.bitmap
                .as_ref()
                .map_or_else(Default::default, |bm| {
                    let (all_pushes, clears) = bm.collect_mutations();
                    (all_pushes[items_to_skip as usize..].to_vec(), clears)
                });

        let mmr_base = crate::merkle::Position::try_from(Location::new(current_db_size))
            .expect("valid leaf count");
        Changeset {
            journal_finalized: self.journal_batch.finalize_from(mmr_base, items_to_skip),
            snapshot_diffs,
            active_keys_delta,
            new_inactivity_floor_loc: self.new_inactivity_floor_loc,
            new_last_commit_loc: self.new_last_commit_loc,
            db_size: current_db_size,
            bitmap_pushes,
            bitmap_clears,
        }
    }
}

impl<F, E, C, I, H, U> Db<F, E, C, I, H, U>
where
    F: Family,
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, U> {
        // The DB is always committed, so journal size = last_commit_loc + 1.
        let journal_size = *self.last_commit_loc + 1;
        UnmerkleizedBatch {
            journal_batch: self.log.to_merkleized_batch().new_batch::<H>(),
            mutations: BTreeMap::new(),
            base_diff: Arc::new(BTreeMap::new()),
            base_operations: Vec::new(),
            base_size: journal_size,
            db_size: journal_size,
            base_inactivity_floor_loc: self.inactivity_floor_loc,
            base_active_keys: self.active_keys,
            bitmap_parent: self.status.clone(),
        }
    }
}

impl<F, E, C, I, H, U> Db<F, E, C, I, H, U>
where
    F: Family,
    E: Context,
    U: update::Update + Send + Sync + 'static,
    C: Mutable<Item = Operation<F, U>> + crate::Persistable<Error = crate::journal::Error>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Apply a changeset to the database, returning the range of written operations.
    ///
    /// A changeset is only valid if the database has not been modified since the batch that
    /// produced it was created. Multiple batches can be forked from the same parent for speculative
    /// execution, but only one may be applied. Applying a stale changeset returns
    /// [`crate::qmdb::Error::StaleChangeset`].
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal, but
    /// does not durably persist it. Call [`Db::commit`] or [`Db::sync`] to guarantee durability.
    pub async fn apply_batch(
        &mut self,
        batch: Changeset<F, U::Key, H::Digest, Operation<F, U>>,
    ) -> Result<Range<Location<F>>, crate::qmdb::Error<F>> {
        let journal_size = *self.last_commit_loc + 1;
        if batch.db_size != journal_size {
            return Err(crate::qmdb::Error::StaleChangeset {
                expected: batch.db_size,
                actual: journal_size,
            });
        }
        let start_loc = Location::new(journal_size);

        // 1. Write all operations to the authenticated journal + apply Merkle changeset.
        self.log.apply_batch(batch.journal_finalized).await?;

        // 2. Apply snapshot diffs to the in-memory index.
        for diff in batch.snapshot_diffs {
            match diff {
                SnapshotDiff::Update {
                    key,
                    old_loc,
                    new_loc,
                } => {
                    update_known_loc::<F, _>(&mut self.snapshot, &key, old_loc, new_loc);
                }
                SnapshotDiff::Insert { key, new_loc } => {
                    self.snapshot.insert(&key, new_loc);
                }
                SnapshotDiff::Delete { key, old_loc } => {
                    delete_known_loc::<F, _>(&mut self.snapshot, &key, old_loc);
                }
            }
        }

        // 3. Update DB metadata.
        let new_active_keys = self.active_keys as isize + batch.active_keys_delta;
        debug_assert!(
            new_active_keys >= 0,
            "active_keys underflow: base={}, delta={}",
            self.active_keys,
            batch.active_keys_delta
        );
        self.active_keys = new_active_keys as usize;
        self.inactivity_floor_loc = batch.new_inactivity_floor_loc;
        self.last_commit_loc = batch.new_last_commit_loc;

        // 4. Apply bitmap mutations (only when maintaining a bitmap at this layer).
        if let Some(status) = &mut self.status {
            status.push_changeset(batch.bitmap_pushes, batch.bitmap_clears);
        }

        // 5. Return range of operations that were written to the log.
        let end_loc = Location::new(*self.last_commit_loc + 1);
        Ok(start_loc..end_loc)
    }
}

impl<F: Family, E, C, I, H, U> Db<F, E, C, I, H, U>
where
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    ///
    /// This is the starting point for building owned batch chains.
    pub fn to_batch(&self) -> MerkleizedBatch<F, H::Digest, U> {
        let journal_size = *self.last_commit_loc + 1;
        MerkleizedBatch {
            journal_batch: self.log.to_merkleized_batch(),
            diff: Arc::new(BTreeMap::new()),
            new_inactivity_floor_loc: self.inactivity_floor_loc,
            new_last_commit_loc: self.last_commit_loc,
            total_size: journal_size,
            total_active_keys: self.active_keys,
            db_size: journal_size,
            bitmap: self.status.clone(),
        }
    }
}

/// Extract the value from an Update operation via the `Update` trait.
fn extract_update_value<F: Family, U: update::Update>(op: &Operation<F, U>) -> U::Value {
    match op {
        Operation::Update(update) => update.value().clone(),
        _ => unreachable!("floor raise should only re-append Update operations"),
    }
}

#[cfg(any(test, feature = "test-traits"))]
mod trait_impls {
    use super::*;
    use crate::qmdb::any::traits::{
        BatchableDb, MerkleizedBatch as MerkleizedBatchTrait,
        UnmerkleizedBatch as UnmerkleizedBatchTrait,
    };
    use std::future::Future;

    impl<F, K, V, H, E, C, I> UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Unordered<K, V>>>
        for UnmerkleizedBatch<F, H, update::Unordered<K, V>>
    where
        F: Family,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<F, H::Digest, update::Unordered<K, V>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &Db<F, E, C, I, H, update::Unordered<K, V>>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(metadata, db)
        }
    }

    impl<F, K, V, H, E, C, I> UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Ordered<K, V>>>
        for UnmerkleizedBatch<F, H, update::Ordered<K, V>>
    where
        F: Family,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<F, H::Digest, update::Ordered<K, V>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &Db<F, E, C, I, H, update::Ordered<K, V>>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(metadata, db)
        }
    }

    impl<F: Family, D: Digest, U: update::Update + Send + Sync + 'static> MerkleizedBatchTrait
        for MerkleizedBatch<F, D, U>
    where
        Operation<F, U>: Codec,
    {
        type Digest = D;
        type Changeset = Changeset<F, U::Key, D, Operation<F, U>>;

        fn root(&self) -> D {
            self.root()
        }

        fn finalize(self) -> Self::Changeset {
            self.finalize()
        }
    }

    impl<F, E, K, V, C, I, H> BatchableDb for Db<F, E, C, I, H, update::Unordered<K, V>>
    where
        F: Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>
            + crate::Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<F, K, H::Digest, Operation<F, update::Unordered<K, V>>>;
        type Batch = UnmerkleizedBatch<F, H, update::Unordered<K, V>>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<Range<Location<F>>, crate::qmdb::Error<F>>> {
            self.apply_batch(batch)
        }
    }

    impl<F, E, K, V, C, I, H> BatchableDb for Db<F, E, C, I, H, update::Ordered<K, V>>
    where
        F: Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>
            + crate::Persistable<Error = crate::journal::Error>,
        I: OrderedIndex<Value = Location<F>>,
        H: Hasher,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<F, K, H::Digest, Operation<F, update::Ordered<K, V>>>;
        type Batch = UnmerkleizedBatch<F, H, update::Ordered<K, V>>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<Range<Location<F>>, crate::qmdb::Error<F>>> {
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
            ordered::fixed::Db as OrderedFixedDb,
            test::{colliding_digest, fixed_db_config},
            unordered::fixed::Db as UnorderedFixedDb,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{sha256, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    /// Test helper: same logic as `Merkleizer::extract_parent_deleted_creates`
    /// but without requiring a full Merkleizer instance.
    fn extract_parent_deleted_creates<K: Ord + Clone, V: Clone>(
        mutations: &mut BTreeMap<K, Option<V>>,
        base_diff: &BTreeMap<K, DiffEntry<mmr::Family, V>>,
    ) -> BTreeMap<K, (V, Option<crate::mmr::Location>)> {
        let creates: BTreeMap<_, _> = mutations
            .iter()
            .filter_map(|(key, value)| {
                if let Some(DiffEntry::Deleted { base_old_loc }) = base_diff.get(key) {
                    if let Some(value) = value {
                        return Some((key.clone(), (value.clone(), *base_old_loc)));
                    }
                }
                None
            })
            .collect();
        for key in creates.keys() {
            mutations.remove(key);
        }
        creates
    }

    #[test]
    fn extract_parent_deleted_creates_basic() {
        let mut mutations: BTreeMap<u64, Option<u64>> = BTreeMap::new();
        mutations.insert(1, Some(100)); // update over parent-deleted key
        mutations.insert(2, None); // delete (not a create)
        mutations.insert(3, Some(300)); // update, but not in base diff

        let mut base_diff: BTreeMap<u64, DiffEntry<mmr::Family, u64>> = BTreeMap::new();
        base_diff.insert(
            1,
            DiffEntry::Deleted {
                base_old_loc: Some(crate::mmr::Location::new(5)),
            },
        );
        base_diff.insert(
            4,
            DiffEntry::Active {
                value: 400,
                loc: crate::mmr::Location::new(10),
                base_old_loc: None,
            },
        );

        let creates = extract_parent_deleted_creates(&mut mutations, &base_diff);

        // key1 extracted: value=100, base_old_loc=Some(5)
        assert_eq!(creates.len(), 1);
        let (value, base_old_loc) = creates.get(&1).unwrap();
        assert_eq!(*value, 100);
        assert_eq!(*base_old_loc, Some(crate::mmr::Location::new(5)));

        // key1 removed from mutations, key2 and key3 remain.
        assert_eq!(mutations.len(), 2);
        assert!(mutations.contains_key(&2));
        assert!(mutations.contains_key(&3));
    }

    #[test]
    fn extract_parent_deleted_creates_delete_not_extracted() {
        let mut mutations: BTreeMap<u64, Option<u64>> = BTreeMap::new();
        mutations.insert(1, None); // deleting a parent-deleted key

        let mut base_diff: BTreeMap<u64, DiffEntry<mmr::Family, u64>> = BTreeMap::new();
        base_diff.insert(
            1,
            DiffEntry::Deleted {
                base_old_loc: Some(crate::mmr::Location::new(5)),
            },
        );

        let creates = extract_parent_deleted_creates(&mut mutations, &base_diff);

        // Delete of a deleted key is not a create.
        assert!(creates.is_empty());
        // Mutation unchanged.
        assert_eq!(mutations.len(), 1);
        assert!(mutations.contains_key(&1));
    }

    #[test]
    fn child_root_matches_between_pending_and_committed_paths_under_collisions() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
            >;

            let config = fixed_db_config::<OneCap>("batch-collision-regression", &context);
            let mut db = TestDb::init(context, config).await.unwrap();
            let key_a = colliding_digest(0xAA, 1);
            let key_b = colliding_digest(0xAA, 0);

            // Seed four colliding committed keys, then update only key_a.
            // The specific 4 / 1 / 0 shape is a concrete counterexample:
            // key_b remains outside parent.diff and is still resolved through
            // the committed snapshot in the child.
            let mut initial = db.new_batch();
            for i in 0..4 {
                initial = initial.write(colliding_digest(0xAA, i), Some(colliding_digest(0xBB, i)));
            }
            let initial = initial.merkleize(None, &db).await.unwrap().finalize();
            db.apply_batch(initial).await.unwrap();
            db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // parent.diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(None, &db)
                .await
                .unwrap();
            assert!(
                !parent.diff.contains_key(&key_b),
                "regression requires a sibling collision to remain only in the committed snapshot"
            );

            // Build the child while the parent is still pending. The child
            // mutates the parent-updated key plus the colliding sibling that
            // still resolves through the committed snapshot. Without the
            // base_diff-location guard, the stale snapshot entry for key_a can
            // consume key_a's mutation before the actual base_diff location.
            let pending_child = parent
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(None, &db)
                .await
                .unwrap();

            // Commit the parent, then rebuild the same logical child from the
            // committed DB state and compare speculative roots.
            let finalized_parent = parent.finalize();
            db.apply_batch(finalized_parent).await.unwrap();
            db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(None, &db)
                .await
                .unwrap();

            assert_eq!(pending_child.root(), committed_child.root());

            // Rebase the pending child onto the committed parent and ensure the
            // applied root still matches the committed-path child root.
            let current_db_size = *db.bounds().await.end;
            db.apply_batch(pending_child.finalize_from(current_db_size))
                .await
                .unwrap();
            assert_eq!(db.root(), committed_child.root());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn ordered_child_root_matches_between_pending_and_committed_paths_under_collisions() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            type TestDb = OrderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
            >;

            let config = fixed_db_config::<OneCap>("ordered-batch-collision-regression", &context);
            let mut db = TestDb::init(context, config).await.unwrap();
            let key_a = colliding_digest(0xAA, 1);
            let key_b = colliding_digest(0xAA, 0);

            // Match the unordered counterexample shape on the ordered path so
            // both variants exercise the same collision pattern.
            let mut initial = db.new_batch();
            for i in 0..4 {
                initial = initial.write(colliding_digest(0xAA, i), Some(colliding_digest(0xBB, i)));
            }
            let initial = initial.merkleize(None, &db).await.unwrap().finalize();
            db.apply_batch(initial).await.unwrap();
            db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // parent.diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(None, &db)
                .await
                .unwrap();
            assert!(
                !parent.diff.contains_key(&key_b),
                "ordered regression requires a sibling collision to remain only in the committed snapshot"
            );

            // Build the child while the parent is still pending, then rebuild
            // the same logical child after committing the parent.
            let pending_child = parent
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(None, &db)
                .await
                .unwrap();

            let finalized_parent = parent.finalize();
            db.apply_batch(finalized_parent).await.unwrap();
            db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(None, &db)
                .await
                .unwrap();

            assert_eq!(pending_child.root(), committed_child.root());

            // Rebase the pending child onto the committed parent and compare
            // the applied root with the committed-path child root.
            let current_db_size = *db.bounds().await.end;
            db.apply_batch(pending_child.finalize_from(current_db_size))
                .await
                .unwrap();
            assert_eq!(db.root(), committed_child.root());

            db.destroy().await.unwrap();
        });
    }
}
