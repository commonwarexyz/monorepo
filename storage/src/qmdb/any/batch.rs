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
        delete_known_loc,
        operation::{Key, Operation as OperationTrait},
        update_known_loc,
    },
    Context,
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use core::{iter, ops::Range};
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};
use tracing::debug;

/// Strategy for finding the next active location during floor raising.
pub(crate) trait FloorScan<F: Family> {
    /// Return the next location at or after `floor` that might be active,
    /// below `tip`. Returns `None` if no candidate exists in `[floor, tip)`.
    fn next_candidate(&mut self, floor: Location<F>, tip: u64) -> Option<Location<F>>;
}

/// Sequential scan: every location is a candidate.
// TODO(#1829): Always use bitmap for floor raising.
pub(crate) struct SequentialScan;

impl<F: Family> FloorScan<F> for SequentialScan {
    fn next_candidate(&mut self, floor: Location<F>, tip: u64) -> Option<Location<F>> {
        if *floor < tip {
            Some(floor)
        } else {
            None
        }
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
        /// The key's committed location in the DB snapshot, or `None` if the key did not exist
        /// in the committed DB. Resolved during merkleize (either from the snapshot directly,
        /// or inherited from the nearest ancestor that touched this key).
        base_old_loc: Option<Location<F>>,
    },
    /// Key was deleted.
    Deleted {
        /// The key's committed location in the DB snapshot, or `None` if the key was created
        /// by an ancestor batch and never existed in the committed DB.
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

/// Where this batch's inherited state comes from.
enum Base<F: Family, D: Digest, U: update::Update + Send + Sync>
where
    Operation<F, U>: Send + Sync,
{
    /// Created from the DB via `db.new_batch()`.
    Db {
        db_size: u64,
        inactivity_floor_loc: Location<F>,
        active_keys: usize,
    },
    /// Created from a parent batch via `parent.new_batch()`.
    Child(Arc<MerkleizedBatch<F, D, U>>),
}

impl<F: Family, D: Digest, U: update::Update + Send + Sync> Base<F, D, U>
where
    Operation<F, U>: Send + Sync,
{
    /// Total operations before this batch (committed DB + ancestor batches).
    fn base_size(&self) -> u64 {
        match self {
            Self::Db { db_size, .. } => *db_size,
            Self::Child(parent) => parent.total_size,
        }
    }

    /// Effective number of committed DB operations at the base of the batch chain.
    /// For `Db`, this is the DB size when `new_batch()` was called.
    /// For `Child`, this is inherited from the parent (which may be higher than
    /// the original DB size if ancestors were dropped before merkleize).
    fn db_size(&self) -> u64 {
        match self {
            Self::Db { db_size, .. } => *db_size,
            Self::Child(parent) => parent.db_size,
        }
    }

    fn inactivity_floor_loc(&self) -> Location<F> {
        match self {
            Self::Db {
                inactivity_floor_loc,
                ..
            } => *inactivity_floor_loc,
            Self::Child(parent) => parent.new_inactivity_floor_loc,
        }
    }

    fn active_keys(&self) -> usize {
        match self {
            Self::Db { active_keys, .. } => *active_keys,
            Self::Child(parent) => parent.total_active_keys,
        }
    }

    const fn parent(&self) -> Option<&Arc<MerkleizedBatch<F, D, U>>> {
        match self {
            Self::Db { .. } => None,
            Self::Child(parent) => Some(parent),
        }
    }
}

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

    /// The committed DB or parent batch this batch was created from.
    base: Base<F, H::Digest, U>,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
///
/// # Forking
///
/// Multiple children can share the same parent, forming a tree:
///
/// ```text
/// DB <-- B1 <-- B2 <-- B4
///                \
///                 B3
/// ```
///
/// # Committing batches
///
/// [`Db::apply_batch`] applies the batch and any uncommitted ancestors automatically.
///
/// ```text
/// db.apply_batch(b1).await.unwrap();
/// db.apply_batch(b3).await.unwrap();  // Also applies b2's changes.
/// ```
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, U: update::Update + Send + Sync>
where
    Operation<F, U>: Send + Sync,
{
    /// Merkleized authenticated journal batch (provides the speculative Merkle root).
    pub(crate) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, U>>>,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    pub(crate) diff: Arc<BTreeMap<U::Key, DiffEntry<F, U::Value>>>,

    /// The parent batch in the chain, if any.
    parent: Option<Weak<Self>>,

    /// Inactivity floor location after this batch's floor raise.
    pub(crate) new_inactivity_floor_loc: Location<F>,

    /// Location of the CommitFloor operation appended by this batch.
    pub(crate) new_last_commit_loc: Location<F>,

    /// Total operations before this batch's own ops (DB + ancestor batches).
    pub(crate) base_size: u64,

    /// Total operation count after this batch.
    pub(crate) total_size: u64,

    /// Total active keys after this batch.
    pub(crate) total_active_keys: usize,

    /// Effective DB size at the base of this batch's ancestor chain. Equals `base_size`
    /// when all ancestors are alive, but shifts up if ancestors were dropped before
    /// merkleize (to account for the gap left by dead ancestors). Used by `apply_batch`
    /// to validate that the DB hasn't diverged from this batch's chain.
    pub(crate) db_size: u64,

    /// Arc refs to each ancestor's diff, collected during `finish()` while ancestors are
    /// alive. Used by `apply_batch` to apply uncommitted ancestor snapshot diffs.
    /// 1:1 with `ancestor_diff_ends` (same length, same ordering).
    ancestor_diffs: Vec<Arc<BTreeMap<U::Key, DiffEntry<F, U::Value>>>>,

    /// Each ancestor's `total_size` (operation count after that ancestor).
    /// 1:1 with `ancestor_diffs`: `ancestor_diff_ends[i]` is the boundary for
    /// `ancestor_diffs[i]`. A batch is committed when `ancestor_diff_ends[i] <= db_size`.
    pub(crate) ancestor_diff_ends: Vec<u64>,
}

/// Batch-infrastructure state used during merkleization.
///
/// Created by [`UnmerkleizedBatch::into_parts()`], which separates the pending mutations
/// from the resolution/merkleization machinery. Helpers that need access to the parent
/// chain, DB snapshot, or operation log are methods on this struct, eliminating parameter
/// threading.
struct Merkleizer<F: Family, H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, U>>,
    ancestors: Vec<Arc<MerkleizedBatch<F, H::Digest, U>>>,
    base_size: u64,
    db_size: u64,
    base_inactivity_floor_loc: Location<F>,
    base_active_keys: usize,
}

/// Look up a key in the ancestor chain (immediate parent first).
fn resolve_in_ancestors<'a, F: Family, D: Digest, U: update::Update + Send + Sync>(
    ancestors: &'a [Arc<MerkleizedBatch<F, D, U>>],
    key: &U::Key,
) -> Option<&'a DiffEntry<F, U::Value>>
where
    Operation<F, U>: Send + Sync,
{
    for batch in ancestors {
        if let Some(entry) = batch.diff.get(key) {
            return Some(entry);
        }
    }
    None
}

/// Apply a single diff entry to the snapshot index.
fn apply_snapshot_diff<F: Family, V, I: UnorderedIndex<Value = Location<F>>>(
    snapshot: &mut I,
    key: &impl Key,
    entry: &DiffEntry<F, V>,
    base_old_loc: Option<Location<F>>,
) {
    match entry {
        DiffEntry::Active { loc, .. } => match base_old_loc {
            Some(old) => update_known_loc::<F, _>(snapshot, key, old, *loc),
            None => snapshot.insert(key, *loc),
        },
        DiffEntry::Deleted { .. } => {
            if let Some(old) = base_old_loc {
                delete_known_loc::<F, _>(snapshot, key, old);
            }
        }
    }
}

/// Read a single operation item from the ancestor chain at the given location.
///
/// `db_size` is the number of committed operations in the DB. The location must be in
/// `[db_size, tip)` where `tip = ancestors[0].journal_batch.size()`.
fn read_chain_item_from_ancestors<F: Family, D: Digest, U: update::Update + Send + Sync>(
    ancestors: &[Arc<MerkleizedBatch<F, D, U>>],
    loc: u64,
    db_size: u64,
) -> &Operation<F, U>
where
    Operation<F, U>: Send + Sync,
{
    // ancestors is ordered parent-first: [parent, grandparent, ...].
    // Each batch's items span [next_batch.size(), this_batch.size()).
    // The last ancestor's base is db_size (committed DB boundary).
    for (i, batch) in ancestors.iter().enumerate() {
        let batch_base = ancestors
            .get(i + 1)
            .map_or(db_size, |b| b.journal_batch.size());
        let batch_end = batch.journal_batch.size();
        if loc >= batch_base && loc < batch_end {
            return &batch.journal_batch.items()[(loc - batch_base) as usize];
        }
    }
    unreachable!("location {loc} not found in ancestor chain (db_size={db_size})")
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
    ///   committed (on disk)     ancestors (in mem)          this batch (in mem)
    /// ```
    ///
    /// `db_size` here is the Merkleizer's effective boundary between disk and in-memory
    /// ancestors. It equals the original DB size when the full ancestor chain is alive, or a
    /// higher value if ancestors were freed (see `into_parts`).
    ///
    /// For top-level batches, the ancestor region is empty (`db_size == base_size`).
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
            // Parent batch chain's operations (in-memory). Walk the ancestors.
            Ok(read_chain_item_from_ancestors(&self.ancestors, loc_val, self.db_size).clone())
        } else {
            // Base DB's journal (on-disk async read).
            let reader = db.log.reader().await;
            Ok(reader.read(loc_val).await?)
        }
    }

    /// Gather existing-key locations for all keys in `mutations`.
    ///
    /// For each mutation key, checks the ancestor diffs first (returning the uncommitted
    /// location for Active entries, skipping Deleted entries). Keys not in the ancestor diffs
    /// fall back to the committed DB snapshot.
    ///
    /// When `include_active_collision_siblings` is true, Active entries also scan the snapshot
    /// bucket for collision siblings (other keys sharing the same translated-key bucket). The
    /// ordered path needs these so their `next_key` pointers are rewritten when a sibling is
    /// deleted; the unordered path can skip them.
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
        // Extra slack (*3/2) avoids re-allocations when index collisions cause more than one
        // location per key.
        let mut locations = Vec::with_capacity(mutations.len() * 3 / 2);
        if self.ancestors.is_empty() {
            for key in mutations.keys() {
                locations.extend(db.snapshot.get(key).copied());
            }
        } else {
            for key in mutations.keys() {
                match resolve_in_ancestors(&self.ancestors, key) {
                    Some(DiffEntry::Deleted { .. }) => {
                        // Stale; handled via extract_parent_deleted_creates.
                    }
                    Some(DiffEntry::Active {
                        loc, base_old_loc, ..
                    }) => {
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
        if let Some(entry) = batch_diff
            .get(key)
            .or_else(|| resolve_in_ancestors(&self.ancestors, key))
        {
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
        if self.ancestors.is_empty() {
            return BTreeMap::new();
        }
        let mut creates = BTreeMap::new();
        mutations.retain(|key, value| {
            if let Some(DiffEntry::Deleted { base_old_loc }) =
                resolve_in_ancestors(&self.ancestors, key)
            {
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
                    .or_else(|| resolve_in_ancestors(&self.ancestors, &key))
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
        self,
        mut ops: Vec<Operation<F, U>>,
        mut diff: BTreeMap<U::Key, DiffEntry<F, U::Value>>,
        active_keys_delta: isize,
        user_steps: u64,
        metadata: Option<U::Value>,
        mut scan: S,
        db: &Db<F, E, C, I, H, U>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, U>>, crate::qmdb::Error<F>>
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
        let journal = db
            .log
            .with_mem(|base| self.journal_batch.merkleize_with(base, ops));

        let ancestor_diffs: Vec<_> = self.ancestors.iter().map(|a| Arc::clone(&a.diff)).collect();
        let ancestor_diff_ends: Vec<_> = self.ancestors.iter().map(|a| a.total_size).collect();

        debug_assert!(total_active_keys >= 0, "active_keys underflow");
        Ok(Arc::new(MerkleizedBatch {
            journal_batch: journal,
            diff: Arc::new(diff),
            parent: self.ancestors.first().map(Arc::downgrade),
            new_inactivity_floor_loc: floor,
            new_last_commit_loc: commit_loc,
            base_size: self.base_size,
            total_size: *commit_loc + 1,
            total_active_keys: total_active_keys as usize,
            db_size: self.db_size,
            ancestor_diffs,
            ancestor_diff_ends,
        }))
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
        let ancestors: Vec<_> = self.base.parent().map_or_else(Vec::new, |parent| {
            let mut v = vec![Arc::clone(parent)];
            v.extend(parent.ancestors());
            v
        });
        // If the Weak parent chain was truncated (an ancestor was committed and freed), the
        // oldest alive ancestor's items don't start at db_size. Example: chain A -> B -> C,
        // A committed and dropped. ancestors() yields [B] (A's Weak is dead). B's items start
        // at A.size(), not db_size. We use the journal (strong Arcs, always intact) to compute
        // the actual base so read_op falls through to disk for locations in the gap.
        let db_size = self.base.db_size();
        let effective_db_size = ancestors.last().map_or(db_size, |oldest| {
            let oldest_base =
                oldest.journal_batch.size() - oldest.journal_batch.items().len() as u64;
            db_size.max(oldest_base)
        });
        (
            self.mutations,
            Merkleizer {
                journal_batch: self.journal_batch,
                ancestors,
                base_size: self.base.base_size(),
                db_size: effective_db_size,
                base_inactivity_floor_loc: self.base.inactivity_floor_loc(),
                base_active_keys: self.base.active_keys(),
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
    /// Read through: mutations -> ancestor diffs -> committed DB.
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
        if let Some(parent) = self.base.parent() {
            if let Some(entry) = parent.diff.get(key) {
                return Ok(entry.value().cloned());
            }
            for batch in parent.ancestors() {
                if let Some(entry) = batch.diff.get(key) {
                    return Ok(entry.value().cloned());
                }
            }
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
    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub async fn merkleize<E, C, I>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        self.merkleize_with_floor_scan(db, metadata, SequentialScan)
            .await
    }

    /// Like [`merkleize`](Self::merkleize) but accepts a custom [`FloorScan`]
    /// to accelerate floor raising.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, S: FloorScan<F>>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>>,
        metadata: Option<V::Value>,
        scan: S,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>>>, crate::qmdb::Error<F>>
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
        // This includes keys from both the committed snapshot and ancestor diffs.
        for (op, &old_loc) in results.iter().zip(&locations) {
            let key = op.key().expect("updates should have a key");

            // A key resolved via the ancestor diff must only match at its ancestor-diff
            // location. Without this guard, a stale snapshot collision (the pre-parent DB
            // snapshot still containing the key's old location) can consume the mutation at the
            // wrong sort position, changing the operation order relative to the committed-state
            // path. When the ancestor diff entry does match, use it to trace `base_old_loc`
            // back to the key's location in the committed DB snapshot.
            let base_old_loc = if let Some(entry) = resolve_in_ancestors(&m.ancestors, key) {
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
        // Merge into a single sorted Vec so iteration order is deterministic
        // regardless of whether the parent is pending or committed.
        let mut creates: Vec<(K, V::Value, Option<Location<F>>)> =
            Vec::with_capacity(mutations.len() + parent_deleted_creates.len());
        for (key, value) in mutations {
            if let Some(value) = value {
                creates.push((key, value, None));
            }
        }
        for (key, (value, base_old_loc)) in parent_deleted_creates {
            creates.push((key, value, base_old_loc));
        }
        creates.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
        for (key, value, base_old_loc) in creates {
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
    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    pub async fn merkleize<E, C, I>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        self.merkleize_with_floor_scan(db, metadata, SequentialScan)
            .await
    }

    /// Like [`merkleize`](Self::merkleize) but accepts a custom [`FloorScan`]
    /// to accelerate floor raising.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, S: FloorScan<F>>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>>,
        metadata: Option<V::Value>,
        scan: S,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>>>, crate::qmdb::Error<F>>
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
        // Merge into a single sorted Vec so iteration order is deterministic
        // regardless of whether the parent is pending or committed.
        let mut created: Vec<(K, V::Value, Option<Location<F>>)> =
            Vec::with_capacity(mutations.len() + parent_deleted_creates.len());
        for (key, value) in mutations {
            let Some(value) = value else {
                continue; // delete of non-existent key
            };
            next_candidates.insert(key.clone());
            created.push((key, value, None));
        }
        for (key, (value, base_old_loc)) in parent_deleted_creates {
            next_candidates.insert(key.clone());
            created.push((key, value, base_old_loc));
        }
        created.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));

        // Look up prev_translated_key for created/deleted keys.
        let mut prev_locations = Vec::new();
        for key in deleted.keys().chain(created.iter().map(|(k, _, _)| k)) {
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

        // Add ancestor-diff-created keys to candidate sets. These keys may be predecessors
        // or successors of this batch's mutations but are invisible to the base-DB-only
        // prev_translated_key lookup above. Walk the parent chain to collect the effective
        // state for each key (closest ancestor wins).
        let ancestor_entries = {
            let mut entries: BTreeMap<&K, &DiffEntry<F, V::Value>> = BTreeMap::new();
            for batch in &m.ancestors {
                for (key, entry) in batch.diff.iter() {
                    entries.entry(key).or_insert(entry);
                }
            }
            entries
        };

        for (key, entry) in &ancestor_entries {
            // Skip keys already handled by this batch's mutations.
            if updated.contains_key(*key)
                || created.binary_search_by(|(k, _, _)| k.cmp(*key)).is_ok()
                || deleted.contains_key(*key)
            {
                continue;
            }
            if let DiffEntry::Active { value, loc, .. } = entry {
                let op: Operation<F, update::Ordered<K, V>> = m.read_op(*loc, &[], db).await?;
                let data = match op {
                    Operation::Update(data) => data,
                    _ => unreachable!("ancestor diff Active should reference Update op"),
                };
                next_candidates.insert((*key).clone());
                next_candidates.insert(data.next_key);
                prev_candidates.insert((*key).clone(), (value.clone(), *loc));
            }
        }

        // Remove all known-deleted keys from possible_* sets. The prev_translated_key lookup
        // already did this for this batch's deletes, but the ancestor diff incorporation may
        // have re-added them via next_key references. Also remove parent-deleted keys that the
        // base DB lookup may have added.
        for key in deleted.keys() {
            prev_candidates.remove(key);
            next_candidates.remove(key);
        }
        for (key, entry) in &ancestor_entries {
            if matches!(entry, DiffEntry::Deleted { .. })
                && created.binary_search_by(|(k, _, _)| k.cmp(*key)).is_err()
            {
                prev_candidates.remove(*key);
                next_candidates.remove(*key);
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

            let base_old_loc = resolve_in_ancestors(&m.ancestors, key)
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

            let base_old_loc = resolve_in_ancestors(&m.ancestors, &key)
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
        for (key, value, base_old_loc) in created {
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

                let prev_base_old_loc = resolve_in_ancestors(&m.ancestors, prev_key)
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

    /// Iterate over ancestor batches (parent first, then grandparent, etc.). Stops when a
    /// Weak ref fails to upgrade (ancestor was freed).
    pub(crate) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> {
        let mut next = self.parent.as_ref().and_then(Weak::upgrade);
        iter::from_fn(move || {
            let batch = next.take()?;
            next = batch.parent.as_ref().and_then(Weak::upgrade);
            Some(batch)
        })
    }
}

impl<F: Family, D: Digest, U: update::Update + Send + Sync> MerkleizedBatch<F, D, U>
where
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    ///
    /// All uncommitted ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Dropping an uncommitted ancestor causes data
    /// loss detected at `apply_batch` time.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, U>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            journal_batch: self.journal_batch.new_batch::<H>(),
            mutations: BTreeMap::new(),
            base: Base::Child(Arc::clone(self)),
        }
    }

    /// Read through: local diff -> parent chain -> committed DB.
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
        // Walk parent chain. If a parent was freed (committed and dropped), the iterator
        // stops and we fall through to DB.
        for batch in self.ancestors() {
            if let Some(entry) = batch.diff.get(key) {
                return Ok(entry.value().cloned());
            }
        }
        db.get(key).await
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
            journal_batch: self.log.new_batch(),
            mutations: BTreeMap::new(),
            base: Base::Db {
                db_size: journal_size,
                inactivity_floor_loc: self.inactivity_floor_loc,
                active_keys: self.active_keys,
            },
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
    /// Apply a batch to the database, returning the range of written operations.
    ///
    /// A batch is valid only if every batch applied to the database since this batch's
    /// ancestor chain was created is an ancestor of this batch. Applying a batch from a
    /// different fork returns [`crate::qmdb::Error::StaleBatch`].
    ///
    /// This publishes the batch to the in-memory database state and appends it to the
    /// journal, but does not durably persist it. Call [`Db::commit`] or [`Db::sync`] to
    /// guarantee durability.
    pub async fn apply_batch(
        &mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, U>>,
    ) -> Result<Range<Location<F>>, crate::qmdb::Error<F>> {
        let db_size = *self.last_commit_loc + 1;
        // Valid db_size values: batch.db_size (nothing committed), batch.base_size
        // (all ancestors committed), or any ancestor_diff_ends[i] (partial commit).
        let valid = db_size == batch.db_size
            || db_size == batch.base_size
            || batch.ancestor_diff_ends.contains(&db_size);
        if !valid {
            return Err(crate::qmdb::Error::StaleBatch {
                db_size,
                batch_db_size: batch.db_size,
                batch_base_size: batch.base_size,
            });
        }
        let start_loc = Location::new(db_size);

        // 1. Apply journal (handles its own partial ancestor skipping).
        self.log.apply_batch(&batch.journal_batch).await?;

        // 2. Build committed_locs: for each key in a committed ancestor batch,
        //    record the nearest (to child) committed ancestor's final state.
        //    Some(loc) = Active at loc, None = Deleted.
        let mut committed_locs: BTreeMap<&U::Key, Option<Location<F>>> = BTreeMap::new();
        for (i, ancestor_diff) in batch.ancestor_diffs.iter().enumerate() {
            if batch.ancestor_diff_ends[i] <= db_size {
                for (key, entry) in ancestor_diff.iter() {
                    // parent-first order: .or_insert keeps the nearest committed.
                    committed_locs.entry(key).or_insert(entry.loc());
                }
            }
        }

        // 3. Apply child's diff (child wins via seen set).
        let mut seen = BTreeSet::<&U::Key>::new();
        for (key, entry) in batch.diff.iter() {
            seen.insert(key);
            let base_old_loc = committed_locs
                .get(key)
                .copied()
                .unwrap_or_else(|| entry.base_old_loc());
            apply_snapshot_diff(&mut self.snapshot, key, entry, base_old_loc);
        }

        // 4. Apply uncommitted ancestor diffs (skip committed batches, skip seen keys).
        for (i, ancestor_diff) in batch.ancestor_diffs.iter().enumerate() {
            if batch.ancestor_diff_ends[i] <= db_size {
                continue;
            }
            for (key, entry) in ancestor_diff.iter() {
                if !seen.insert(key) {
                    continue;
                }
                let base_old_loc = committed_locs
                    .get(key)
                    .copied()
                    .unwrap_or_else(|| entry.base_old_loc());
                apply_snapshot_diff(&mut self.snapshot, key, entry, base_old_loc);
            }
        }

        // 5. Update DB metadata.
        self.active_keys = batch.total_active_keys;
        self.inactivity_floor_loc = batch.new_inactivity_floor_loc;
        self.last_commit_loc = batch.new_last_commit_loc;

        // 6. Return range of operations that were written to the log.
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
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, U>> {
        // The DB is always committed, so journal size = last_commit_loc + 1.
        let journal_size = *self.last_commit_loc + 1;
        Arc::new(MerkleizedBatch {
            journal_batch: self.log.to_merkleized_batch(),
            diff: Arc::new(BTreeMap::new()),
            parent: None,
            new_inactivity_floor_loc: self.inactivity_floor_loc,
            new_last_commit_loc: self.last_commit_loc,
            base_size: journal_size,
            total_size: journal_size,
            total_active_keys: self.active_keys,
            db_size: journal_size,
            ancestor_diffs: Vec::new(),
            ancestor_diff_ends: Vec::new(),
        })
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
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            db: &Db<F, E, C, I, H, update::Unordered<K, V>>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata)
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
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            db: &Db<F, E, C, I, H, update::Ordered<K, V>>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata)
        }
    }

    impl<F: Family, D: Digest, U: update::Update + Send + Sync + 'static> MerkleizedBatchTrait
        for Arc<MerkleizedBatch<F, D, U>>
    where
        Operation<F, U>: Codec,
    {
        type Digest = D;

        fn root(&self) -> D {
            MerkleizedBatch::root(self)
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
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>>>;
        type Batch = UnmerkleizedBatch<F, H, update::Unordered<K, V>>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Merkleized,
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
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>>>;
        type Batch = UnmerkleizedBatch<F, H, update::Ordered<K, V>>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Merkleized,
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
            let initial = initial.merkleize(&db, None).await.unwrap();
            db.apply_batch(initial).await.unwrap();
            db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // parent.diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert!(
                !parent.diff.contains_key(&key_b),
                "regression requires a sibling collision to remain only in the committed snapshot"
            );

            // Build the child while the parent is still pending. The child
            // mutates the parent-updated key plus the colliding sibling that
            // still resolves through the committed snapshot. Without the
            // ancestor-diff location guard, the stale snapshot entry for key_a
            // can consume key_a's mutation before the actual ancestor location.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            let pending_root = pending_child.root();

            db.apply_batch(parent).await.unwrap();
            db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert_eq!(pending_root, committed_child.root());

            // Apply pending child. The resulting root should match a
            // child built directly from the committed DB.
            db.apply_batch(pending_child).await.unwrap();
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
            let initial = initial.merkleize(&db, None).await.unwrap();
            db.apply_batch(initial).await.unwrap();
            db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // parent.diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert!(
                !parent.diff.contains_key(&key_b),
                "ordered regression requires a sibling collision to remain only in the committed snapshot"
            );

            // Build the child while the parent is still pending, then rebuild
            // the same logical child after committing the parent.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            let pending_root = pending_child.root();

            db.apply_batch(parent).await.unwrap();
            db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert_eq!(pending_root, committed_child.root());

            // Apply pending child. The resulting root should match a
            // child built directly from the committed DB.
            db.apply_batch(pending_child).await.unwrap();
            assert_eq!(db.root(), committed_child.root());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn sequential_commit_basic() {
        // Build DB -> A -> B, commit A, then apply B. Verify B
        // produces the same DB state as building B directly from the committed DB.
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

            let config = fixed_db_config::<OneCap>("seq-commit-basic", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            // Seed an initial key.
            let seed = db
                .new_batch()
                .write(colliding_digest(0x01, 0), Some(colliding_digest(0x01, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            // Build batch A.
            let key_a = colliding_digest(0x02, 0);
            let val_a = colliding_digest(0x02, 1);
            let batch_a = db
                .new_batch()
                .write(key_a, Some(val_a))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Build batch B as child of A.
            let key_b = colliding_digest(0x03, 0);
            let val_b = colliding_digest(0x03, 1);
            let batch_b = batch_a
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(batch_a).await.unwrap();
            db.commit().await.unwrap();

            // Build the same logical B from committed DB for comparison.
            let committed_b = db
                .new_batch()
                .write(key_b, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert_eq!(batch_b.root(), committed_b.root());

            // Apply B.
            db.apply_batch(batch_b).await.unwrap();
            assert_eq!(db.root(), committed_b.root());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn sequential_commit_fixes_base_old_loc() {
        // Build DB -> A -> B where both touch the same key K.
        // Commit A, then apply B. Verify base_old_loc is adjusted.
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

            let config = fixed_db_config::<OneCap>("seq-commit-base-old-loc", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            // Seed an initial key so we have an existing entry.
            let key = colliding_digest(0x10, 0);
            let seed = db
                .new_batch()
                .write(key, Some(colliding_digest(0x10, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            // Build batch A that updates the key.
            let val_a = colliding_digest(0x10, 2);
            let batch_a = db
                .new_batch()
                .write(key, Some(val_a))
                .merkleize(&db, None)
                .await
                .unwrap();

            // A's diff should have base_old_loc pointing to the seed's location.
            let a_entry = batch_a.diff.get(&key).unwrap();
            let a_loc = a_entry.loc();
            assert!(a_loc.is_some());

            // Build batch B as child of A, also updating the same key.
            let val_b = colliding_digest(0x10, 3);
            let batch_b = batch_a
                .new_batch::<Sha256>()
                .write(key, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Commit A. The base_old_loc fixup is deferred to apply_batch,
            // which reads A's diff by reference.
            db.apply_batch(batch_a).await.unwrap();
            db.commit().await.unwrap();

            // Verify B produces the same root as a fresh build.
            let committed_b = db
                .new_batch()
                .write(key, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert_eq!(batch_b.root(), committed_b.root());

            db.apply_batch(batch_b).await.unwrap();
            assert_eq!(db.root(), committed_b.root());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn fork_apply_after_parent_committed() {
        // Fork: DB -> A -> B and DB -> A -> C.
        // Commit A, then apply B and C independently.
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

            let config = fixed_db_config::<OneCap>("fork-after-commit", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            // Seed.
            let seed = db
                .new_batch()
                .write(colliding_digest(0x20, 0), Some(colliding_digest(0x20, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            // Build batch A.
            let key_a = colliding_digest(0x21, 0);
            let val_a = colliding_digest(0x21, 1);
            let batch_a = db
                .new_batch()
                .write(key_a, Some(val_a))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Fork: B and C both derive from A.
            let key_b = colliding_digest(0x22, 0);
            let val_b = colliding_digest(0x22, 1);
            let batch_b = batch_a
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();
            let key_c = colliding_digest(0x23, 0);
            let val_c = colliding_digest(0x23, 1);
            let batch_c = batch_a
                .new_batch::<Sha256>()
                .write(key_c, Some(val_c))
                .merkleize(&db, None)
                .await
                .unwrap();

            db.apply_batch(batch_a).await.unwrap();
            db.commit().await.unwrap();

            // Verify both produce correct roots.
            let committed_b = db
                .new_batch()
                .write(key_b, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert_eq!(batch_b.root(), committed_b.root());

            let committed_c = db
                .new_batch()
                .write(key_c, Some(val_c))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert_eq!(batch_c.root(), committed_c.root());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn sequential_commit_three_deep() {
        // Build DB -> grandparent -> parent -> child, commit each
        // sequentially. Tests applying across batch boundaries.
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

            let config = fixed_db_config::<OneCap>("ff-cross", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            // Grandparent: 2 keys.
            let grandparent = db
                .new_batch()
                .write(colliding_digest(0x01, 0), Some(colliding_digest(0x01, 1)))
                .write(colliding_digest(0x02, 0), Some(colliding_digest(0x02, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Parent: 1 key.
            let parent = grandparent
                .new_batch::<Sha256>()
                .write(colliding_digest(0x03, 0), Some(colliding_digest(0x03, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child: 1 key.
            let child = parent
                .new_batch::<Sha256>()
                .write(colliding_digest(0x04, 0), Some(colliding_digest(0x04, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Commit grandparent.
            db.apply_batch(grandparent).await.unwrap();
            db.commit().await.unwrap();

            // Commit parent.
            db.apply_batch(parent).await.unwrap();
            db.commit().await.unwrap();

            // Commit child.
            db.apply_batch(child).await.unwrap();

            // All 4 keys should be present.
            for i in 1..=4 {
                assert_eq!(
                    db.get(&colliding_digest(i, 0)).await.unwrap(),
                    Some(colliding_digest(i, 1))
                );
            }

            db.destroy().await.unwrap();
        });
    }

    /// Regression test for issue #3519 / #3520: when a parent batch deletes a
    /// key that has a collision sibling and the child re-creates that key, the
    /// `fresh.chain(recreates)` iterator produced operations in a different
    /// order depending on whether the parent was pending or committed.
    #[test]
    fn recreate_deleted_key_with_collision_sibling_root_matches() {
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

            let config = fixed_db_config::<OneCap>("recreate-deleted-collision", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            // Two colliding keys: K0 (suffix 0) and K6 (suffix 6).
            let k0 = colliding_digest(0xAA, 0);
            let k6 = colliding_digest(0xAA, 6);

            // Seed both keys so the snapshot bucket contains two entries.
            let initial = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xBB, 0)))
                .write(k6, Some(colliding_digest(0xBB, 6)))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(initial).await.unwrap();
            db.commit().await.unwrap();

            // Parent: delete K0. K6 remains untouched.
            let parent = db
                .new_batch()
                .write(k0, None)
                .merkleize(&db, None)
                .await
                .unwrap();

            // Child (pending parent): re-create K0 and write a new colliding key K29.
            let k29 = colliding_digest(0xAA, 29);
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(k0, Some(colliding_digest(0xCC, 0)))
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None)
                .await
                .unwrap();

            // Commit the parent, then rebuild the same child.
            db.apply_batch(parent).await.unwrap();
            db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xCC, 0)))
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert_eq!(
                pending_child.root(),
                committed_child.root(),
                "root depended on pending-vs-committed parent path \
                 when re-creating a deleted key with collision siblings"
            );

            db.destroy().await.unwrap();
        });
    }
}
