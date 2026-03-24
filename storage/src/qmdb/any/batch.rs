//! Batch mutation API for Any QMDBs.

use crate::{
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable, Reader},
    },
    mmr::Location,
    qmdb::{
        any::{
            db::Db,
            operation::{update, Operation},
            ordered::{find_next_key, find_prev_key},
            ValueEncoding,
        },
        delete_known_loc,
        operation::{Key, Operation as OperationTrait},
        update_known_loc, Error,
    },
};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use core::ops::Range;
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tracing::debug;

/// Strategy for finding the next active location during floor raising.
pub(crate) trait FloorScan {
    /// Return the next location at or after `floor` that might be active,
    /// below `tip`. Returns `None` if no candidate exists in `[floor, tip)`.
    fn next_candidate(&mut self, floor: Location, tip: u64) -> Option<Location>;
}

/// Sequential scan: every location is a candidate.
// TODO(#1829): Always use bitmap for floor raising.
pub(crate) struct SequentialScan;

impl FloorScan for SequentialScan {
    fn next_candidate(&mut self, floor: Location, tip: u64) -> Option<Location> {
        if *floor < tip {
            Some(floor)
        } else {
            None
        }
    }
}

/// What happened to a key in this batch.
#[derive(Clone)]
pub(crate) enum DiffEntry<V> {
    /// Key was updated (existing) or created (new).
    Active {
        value: V,
        /// Uncommitted location where this operation will be written.
        loc: Location,
        /// The key's location in the committed DB snapshot, not an uncommitted
        /// location from an intermediate batch. `None` if the key is new to
        /// the committed DB. For chained batches, inherited from the base
        /// diff entry.
        base_old_loc: Option<Location>,
    },
    /// Key was deleted.
    Deleted {
        /// The key's location in the committed DB snapshot, not an uncommitted
        /// location from an intermediate batch. `None` if the key was created
        /// by a prior batch and never existed in the committed DB. For
        /// chained batches, inherited from the base diff entry.
        base_old_loc: Option<Location>,
    },
}

impl<V> DiffEntry<V> {
    /// The key's location in the base DB snapshot, regardless of variant.
    pub(crate) const fn base_old_loc(&self) -> Option<Location> {
        match self {
            Self::Active { base_old_loc, .. } | Self::Deleted { base_old_loc } => *base_old_loc,
        }
    }

    /// The uncommitted location if active, `None` if deleted.
    pub(crate) const fn loc(&self) -> Option<Location> {
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
pub(crate) enum SnapshotDiff<K> {
    /// Replace key's location: old_loc -> new_loc.
    Update {
        key: K,
        old_loc: Location,
        new_loc: Location,
    },
    /// Insert a new key at new_loc. The key must not exist in the base DB.
    Insert { key: K, new_loc: Location },
    /// Remove key that was at old_loc.
    Delete { key: K, old_loc: Location },
}

/// A speculative batch of operations whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
///
/// Methods that need the committed DB (e.g. `get`, `merkleize`) accept it as a
/// parameter, so the batch is lifetime-free and can be stored independently of the DB.
pub struct UnmerkleizedBatch<H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Authenticated journal batch for computing the speculative MMR root.
    journal_batch: authenticated::UnmerkleizedBatch<H, Operation<U>>,

    /// Pending mutations. `Some(value)` for upsert, `None` for delete.
    mutations: BTreeMap<U::Key, Option<U::Value>>,

    /// Uncommitted key-level changes accumulated by prior batches in the chain.
    base_diff: Arc<BTreeMap<U::Key, DiffEntry<U::Value>>>,

    /// One Arc segment of operations per prior batch in the chain.
    base_operations: Vec<Arc<Vec<Operation<U>>>>,

    /// Total operation count before this batch (committed DB + prior batches).
    /// This batch's i-th operation lands at location `base_size + i`.
    base_size: u64,

    /// Inactivity floor location before this batch.
    base_inactivity_floor_loc: Location,

    /// Size of the database when this batch was created.
    db_size: u64,

    /// Active key count before this batch.
    base_active_keys: usize,
}

/// A speculative batch of operations whose root digest has been computed,
/// in contrast to [`UnmerkleizedBatch`].
///
/// Owned and lifetime-free, so instances can be stored in homogeneous collections (e.g.
/// `HashMap<Digest, MerkleizedBatch>`) regardless of chain depth.
pub struct MerkleizedBatch<D: Digest, U: update::Update + Send + Sync>
where
    Operation<U>: Send + Sync,
{
    /// Merkleized authenticated journal batch (provides the speculative MMR root).
    pub(crate) journal_batch: authenticated::MerkleizedBatch<D, Operation<U>>,

    /// All uncommitted key-level changes in this batch chain.
    pub(crate) diff: Arc<BTreeMap<U::Key, DiffEntry<U::Value>>>,

    /// Inactivity floor location after this batch's floor raise.
    new_inactivity_floor_loc: Location,

    /// Location of the CommitFloor operation appended by this batch.
    pub(crate) new_last_commit_loc: Location,

    /// Total operation count after this batch.
    total_size: u64,

    /// Total active keys after this batch.
    total_active_keys: usize,

    /// The database size when the initial batch was created.
    pub(crate) db_size: u64,
}

/// An owned changeset that can be applied to the database.
pub struct Changeset<K, D: Digest, Item: Send> {
    /// The finalized authenticated journal batch (MMR changeset + item chain).
    journal_finalized: authenticated::Changeset<D, Item>,

    /// Snapshot mutations to apply, in order.
    snapshot_diffs: Vec<SnapshotDiff<K>>,

    /// Net change in active key count.
    active_keys_delta: isize,

    /// Inactivity floor location after this batch's floor raise.
    new_inactivity_floor_loc: Location,

    /// Location of the CommitFloor operation appended by this batch.
    new_last_commit_loc: Location,

    /// The database size when the batch was created. Used to detect stale changesets.
    db_size: u64,
}

/// Batch-infrastructure state used during merkleization.
///
/// Created by [`UnmerkleizedBatch::into_parts()`], which separates the pending
/// mutations from the resolution/merkleization machinery. Helpers that need
/// access to the base diff, DB snapshot, or operation chain are methods on this
/// struct, eliminating parameter threading.
struct Merkleizer<H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<U>: Codec,
{
    journal_batch: authenticated::UnmerkleizedBatch<H, Operation<U>>,
    base_diff: Arc<BTreeMap<U::Key, DiffEntry<U::Value>>>,
    base_operations: Vec<Arc<Vec<Operation<U>>>>,
    base_size: u64,
    db_size: u64,
    base_inactivity_floor_loc: Location,
    base_active_keys: usize,
}

impl<H, U> Merkleizer<H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<U>: Codec,
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
        loc: Location,
        current_ops: &[Operation<U>],
        db: &Db<E, C, I, H, U>,
    ) -> Result<Operation<U>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location>,
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

    /// Gather the existing-key locations for all keys in `mutations`.
    ///
    /// For each mutation key, checks the base diff first (returning the
    /// uncommitted location for Active entries, skipping Deleted entries), then
    /// falls back to the base DB snapshot.
    fn gather_existing_locations<E, C, I>(
        &self,
        mutations: &BTreeMap<U::Key, Option<U::Value>>,
        db: &Db<E, C, I, H, U>,
    ) -> Vec<Location>
    where
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location>,
    {
        let mut locations = Vec::new();
        if self.base_diff.is_empty() {
            for key in mutations.keys() {
                locations.extend(db.snapshot.get(key).copied());
            }
        } else {
            for key in mutations.keys() {
                if let Some(entry) = self.base_diff.get(key) {
                    if let Some(loc) = entry.loc() {
                        locations.push(loc);
                    }
                    continue;
                }
                locations.extend(db.snapshot.get(key).copied());
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
        loc: Location,
        batch_diff: &BTreeMap<U::Key, DiffEntry<U::Value>>,
        db: &Db<E, C, I, H, U>,
    ) -> bool
    where
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location>,
    {
        if let Some(entry) = batch_diff.get(key).or_else(|| self.base_diff.get(key)) {
            return entry.loc() == Some(loc);
        }
        db.snapshot.get(key).any(|&l| l == loc)
    }

    /// Extract keys that were deleted by a parent batch but are being
    /// re-created by this child batch. Removes those keys from `mutations`
    /// and returns `(key, (value, base_old_loc))` entries.
    fn extract_parent_deleted_creates(
        &self,
        mutations: &mut BTreeMap<U::Key, Option<U::Value>>,
    ) -> BTreeMap<U::Key, (U::Value, Option<Location>)> {
        if self.base_diff.is_empty() {
            return BTreeMap::new();
        }
        let mut creates = BTreeMap::new();
        mutations.retain(|key, value| {
            if let Some(DiffEntry::Deleted { base_old_loc }) = self.base_diff.get(key) {
                if let Some(value) = value {
                    creates.insert(key.clone(), (value.clone(), *base_old_loc));
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
    async fn advance_floor_once<E, C, I, S: FloorScan>(
        &self,
        floor: &mut Location,
        fixed_tip: u64,
        ops: &mut Vec<Operation<U>>,
        diff: &mut BTreeMap<U::Key, DiffEntry<U::Value>>,
        scan: &mut S,
        db: &Db<E, C, I, H, U>,
    ) -> Result<bool, Error>
    where
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location>,
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
    async fn finish<E, C, I, S: FloorScan>(
        mut self,
        mut ops: Vec<Operation<U>>,
        mut diff: BTreeMap<U::Key, DiffEntry<U::Value>>,
        active_keys_delta: isize,
        user_steps: u64,
        metadata: Option<U::Value>,
        mut scan: S,
        db: &Db<E, C, I, H, U>,
    ) -> Result<MerkleizedBatch<H::Digest, U>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location>,
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
        // parent already contains all prior batches' MMR state, so we only
        // add THIS batch's operations. Parent operations are never re-cloned,
        // re-encoded, or re-hashed.
        let mut journal_batch = self.journal_batch;
        for op in &ops {
            journal_batch = journal_batch.add(op.clone());
        }
        let journal = journal_batch.merkleize();

        // Build the operation chain: parent segments + this batch's segment.
        self.base_operations.push(Arc::new(ops));

        // Merge with base diff: entries not overridden by this batch.
        // O(K) deep copy (K = distinct keys in parent diff) when the parent MerkleizedBatch or
        // any sibling UnmerkleizedBatch still exists. O(1) when all have been dropped.
        let base_diff = Arc::try_unwrap(self.base_diff).unwrap_or_else(|arc| (*arc).clone());
        for (k, v) in base_diff {
            diff.entry(k).or_insert(v);
        }

        debug_assert!(total_active_keys >= 0, "active_keys underflow");
        Ok(MerkleizedBatch {
            journal_batch: journal,
            diff: Arc::new(diff),
            new_inactivity_floor_loc: floor,
            new_last_commit_loc: commit_loc,
            total_size: *commit_loc + 1,
            total_active_keys: total_active_keys as usize,
            db_size: self.db_size,
        })
    }
}

impl<H, U> UnmerkleizedBatch<H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<U>: Codec,
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
    fn into_parts(self) -> (BTreeMap<U::Key, Option<U::Value>>, Merkleizer<H, U>) {
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
            },
        )
    }
}

// Generic get() for both ordered and unordered UnmerkleizedBatch.
impl<H, U> UnmerkleizedBatch<H, U>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Read through: mutations -> base diff -> committed DB.
    pub async fn get<E, C, I>(
        &self,
        key: &U::Key,
        db: &Db<E, C, I, H, U>,
    ) -> Result<Option<U::Value>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location> + 'static,
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
impl<K, V, H> UnmerkleizedBatch<H, update::Unordered<K, V>>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<update::Unordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return a [`MerkleizedBatch`].
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &Db<E, C, I, H, update::Unordered<K, V>>,
    ) -> Result<MerkleizedBatch<H::Digest, update::Unordered<K, V>>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location>,
    {
        self.merkleize_with_floor_scan(metadata, SequentialScan, db)
            .await
    }

    /// Like [`merkleize`](Self::merkleize) but accepts a custom [`FloorScan`]
    /// to accelerate floor raising.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, S: FloorScan>(
        self,
        metadata: Option<V::Value>,
        scan: S,
        db: &Db<E, C, I, H, update::Unordered<K, V>>,
    ) -> Result<MerkleizedBatch<H::Digest, update::Unordered<K, V>>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location>,
    {
        let (mut mutations, m) = self.into_parts();

        // Resolve existing keys (async I/O, parallelized).
        let locations = m.gather_existing_locations(&mutations, db);
        let futures = locations.iter().map(|&loc| m.read_op(loc, &[], db));
        let results = try_join_all(futures).await?;

        // Generate user mutation operations.
        let mut ops: Vec<Operation<update::Unordered<K, V>>> = Vec::new();
        let mut diff: BTreeMap<K, DiffEntry<V::Value>> = BTreeMap::new();
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;

        // Process updates/deletes of existing keys in location order.
        // This includes keys from both the base snapshot and the base diff.
        for (op, &old_loc) in results.iter().zip(&locations) {
            let key = op.key().expect("updates should have a key");
            let Some(mutation) = mutations.remove(key) else {
                // Snapshot index collision: this operation's key does not match
                // the mutation key (the snapshot uses a compressed translated key
                // that can collide). The mutation will be handled as a create below.
                continue;
            };

            let new_loc = Location::new(m.base_size + ops.len() as u64);

            // Determine base_old_loc: trace through base diff to find
            // the key's location in the base DB snapshot.
            let base_old_loc = m
                .base_diff
                .get(key)
                .map_or(Some(old_loc), DiffEntry::base_old_loc);

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
impl<K, V, H> UnmerkleizedBatch<H, update::Ordered<K, V>>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<update::Ordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return a [`MerkleizedBatch`].
    pub async fn merkleize<E, C, I>(
        self,
        metadata: Option<V::Value>,
        db: &Db<E, C, I, H, update::Ordered<K, V>>,
    ) -> Result<MerkleizedBatch<H::Digest, update::Ordered<K, V>>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location>,
    {
        self.merkleize_with_floor_scan(metadata, SequentialScan, db)
            .await
    }

    /// Like [`merkleize`](Self::merkleize) but accepts a custom [`FloorScan`]
    /// to accelerate floor raising.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, S: FloorScan>(
        self,
        metadata: Option<V::Value>,
        scan: S,
        db: &Db<E, C, I, H, update::Ordered<K, V>>,
    ) -> Result<MerkleizedBatch<H::Digest, update::Ordered<K, V>>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location>,
    {
        let (mut mutations, m) = self.into_parts();

        // Resolve existing keys (async I/O).
        let locations = m.gather_existing_locations(&mutations, db);

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
        let mut prev_candidates: BTreeMap<K, (V::Value, Location)> = BTreeMap::new();

        let mut deleted: BTreeMap<K, Location> = BTreeMap::new();
        let mut updated: BTreeMap<K, (V::Value, Location)> = BTreeMap::new();

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
        let mut created: BTreeMap<K, (V::Value, Option<Location>)> = BTreeMap::new();
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

        for (op, &old_loc) in prev_results.iter().zip(&prev_locations) {
            let data = match op {
                Operation::Update(data) => data,
                _ => unreachable!("expected update operation"),
            };
            next_candidates.insert(data.next_key.clone());
            prev_candidates.insert(data.key.clone(), (data.value.clone(), old_loc));
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
                let op: Operation<update::Ordered<K, V>> = m.read_op(*loc, &[], db).await?;
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
        let mut ops: Vec<Operation<update::Ordered<K, V>>> = Vec::new();
        let mut diff: BTreeMap<K, DiffEntry<V::Value>> = BTreeMap::new();
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
        let created_keys: Vec<K> = created.keys().cloned().collect();

        // Process creates.
        for (key, (value, base_old_loc)) in created {
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

impl<D: Digest, U: update::Update + Send + Sync> MerkleizedBatch<D, U>
where
    Operation<U>: Send + Sync,
{
    /// Return the speculative root.
    pub fn root(&self) -> D {
        self.journal_batch.root()
    }
}

impl<D: Digest, U: update::Update + Send + Sync> MerkleizedBatch<D, U>
where
    Operation<U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    pub fn new_batch<H>(&self) -> UnmerkleizedBatch<H, U>
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
        }
    }

    /// Read through: diff -> committed DB.
    pub async fn get<E, C, I, H>(
        &self,
        key: &U::Key,
        db: &Db<E, C, I, H, U>,
    ) -> Result<Option<U::Value>, Error>
    where
        E: Storage + Clock + Metrics,
        C: Contiguous<Item = Operation<U>>,
        I: UnorderedIndex<Value = Location> + 'static,
        H: Hasher<Digest = D>,
    {
        if let Some(entry) = self.diff.get(key) {
            return Ok(entry.value().cloned());
        }
        db.get(key).await
    }

    /// Consume this batch, producing an owned [`Changeset`].
    pub fn finalize(self) -> Changeset<U::Key, D, Operation<U>>
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

        Changeset {
            journal_finalized: self.journal_batch.finalize(),
            snapshot_diffs,
            active_keys_delta,
            new_inactivity_floor_loc: self.new_inactivity_floor_loc,
            new_last_commit_loc: self.new_last_commit_loc,
            db_size: self.db_size,
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
    pub fn finalize_from(self, current_db_size: u64) -> Changeset<U::Key, D, Operation<U>>
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
            let mut map: BTreeMap<U::Key, Option<Location>> = BTreeMap::new();
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
                let resolve_old_loc = |base_old_loc: Option<Location>| -> Option<Location> {
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

        let mmr_base = crate::mmr::Position::try_from(Location::new(current_db_size))
            .expect("valid leaf count");
        Changeset {
            journal_finalized: self.journal_batch.finalize_from(mmr_base, items_to_skip),
            snapshot_diffs,
            active_keys_delta,
            new_inactivity_floor_loc: self.new_inactivity_floor_loc,
            new_last_commit_loc: self.new_last_commit_loc,
            db_size: current_db_size,
        }
    }
}

impl<E, C, I, H, U> Db<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<H, U> {
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
        }
    }
}

impl<E, C, I, H, U> Db<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync + 'static,
    C: Mutable<Item = Operation<U>> + crate::Persistable<Error = crate::journal::Error>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Apply a changeset to the database, returning the range of written operations.
    ///
    /// A changeset is only valid if the database has not been modified since the batch that
    /// produced it was created. Multiple batches can be forked from the same parent for speculative
    /// execution, but only one may be applied. Applying a stale changeset returns
    /// [`Error::StaleChangeset`].
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal, but
    /// does not durably persist it. Call [`Db::commit`] or [`Db::sync`] to guarantee durability.
    pub async fn apply_batch(
        &mut self,
        batch: Changeset<U::Key, H::Digest, Operation<U>>,
    ) -> Result<Range<Location>, Error> {
        let journal_size = *self.last_commit_loc + 1;
        if batch.db_size != journal_size {
            return Err(Error::StaleChangeset {
                expected: batch.db_size,
                actual: journal_size,
            });
        }
        let start_loc = Location::new(journal_size);

        // 1. Write all operations to the authenticated journal + apply MMR changeset.
        self.log.apply_batch(batch.journal_finalized).await?;

        // 2. Apply snapshot diffs to the in-memory index.
        for diff in batch.snapshot_diffs {
            match diff {
                SnapshotDiff::Update {
                    key,
                    old_loc,
                    new_loc,
                } => {
                    update_known_loc(&mut self.snapshot, &key, old_loc, new_loc);
                }
                SnapshotDiff::Insert { key, new_loc } => {
                    self.snapshot.insert(&key, new_loc);
                }
                SnapshotDiff::Delete { key, old_loc } => {
                    delete_known_loc(&mut self.snapshot, &key, old_loc);
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

        // 4. Return range of operations that were written to the log.
        let end_loc = Location::new(*self.last_commit_loc + 1);
        Ok(start_loc..end_loc)
    }
}

impl<E, C, I, H, U> Db<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    ///
    /// This is the starting point for building owned batch chains.
    pub fn to_batch(&self) -> MerkleizedBatch<H::Digest, U> {
        let journal_size = *self.last_commit_loc + 1;
        MerkleizedBatch {
            journal_batch: self.log.to_merkleized_batch(),
            diff: Arc::new(BTreeMap::new()),
            new_inactivity_floor_loc: self.inactivity_floor_loc,
            new_last_commit_loc: self.last_commit_loc,
            total_size: journal_size,
            total_active_keys: self.active_keys,
            db_size: journal_size,
        }
    }
}

/// Extract the value from an Update operation via the `Update` trait.
fn extract_update_value<U: update::Update>(op: &Operation<U>) -> U::Value {
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

    impl<K, V, H, E, C, I> UnmerkleizedBatchTrait<Db<E, C, I, H, update::Unordered<K, V>>>
        for UnmerkleizedBatch<H, update::Unordered<K, V>>
    where
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location>,
        Operation<update::Unordered<K, V>>: Codec,
    {
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<H::Digest, update::Unordered<K, V>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &Db<E, C, I, H, update::Unordered<K, V>>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error>> {
            self.merkleize(metadata, db)
        }
    }

    impl<K, V, H, E, C, I> UnmerkleizedBatchTrait<Db<E, C, I, H, update::Ordered<K, V>>>
        for UnmerkleizedBatch<H, update::Ordered<K, V>>
    where
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Storage + Clock + Metrics,
        C: Mutable<Item = Operation<update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location>,
        Operation<update::Ordered<K, V>>: Codec,
    {
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = MerkleizedBatch<H::Digest, update::Ordered<K, V>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            metadata: Option<V::Value>,
            db: &Db<E, C, I, H, update::Ordered<K, V>>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error>> {
            self.merkleize(metadata, db)
        }
    }

    impl<D: Digest, U: update::Update + Send + Sync + 'static> MerkleizedBatchTrait
        for MerkleizedBatch<D, U>
    where
        Operation<U>: Codec,
    {
        type Digest = D;
        type Changeset = Changeset<U::Key, D, Operation<U>>;

        fn root(&self) -> D {
            self.root()
        }

        fn finalize(self) -> Self::Changeset {
            self.finalize()
        }
    }

    impl<E, K, V, C, I, H> BatchableDb for Db<E, C, I, H, update::Unordered<K, V>>
    where
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<update::Unordered<K, V>>>
            + crate::Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        Operation<update::Unordered<K, V>>: Codec,
    {
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<K, H::Digest, Operation<update::Unordered<K, V>>>;
        type Batch = UnmerkleizedBatch<H, update::Unordered<K, V>>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<Range<Location>, crate::qmdb::Error>> {
            self.apply_batch(batch)
        }
    }

    impl<E, K, V, C, I, H> BatchableDb for Db<E, C, I, H, update::Ordered<K, V>>
    where
        E: Storage + Clock + Metrics,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<update::Ordered<K, V>>>
            + crate::Persistable<Error = crate::journal::Error>,
        I: OrderedIndex<Value = Location>,
        H: Hasher,
        Operation<update::Ordered<K, V>>: Codec,
    {
        type K = K;
        type V = V::Value;
        type Changeset = Changeset<K, H::Digest, Operation<update::Ordered<K, V>>>;
        type Batch = UnmerkleizedBatch<H, update::Ordered<K, V>>;

        fn new_batch(&self) -> Self::Batch {
            self.new_batch()
        }

        fn apply_batch(
            &mut self,
            batch: Self::Changeset,
        ) -> impl Future<Output = Result<Range<Location>, crate::qmdb::Error>> {
            self.apply_batch(batch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test helper: same logic as `Merkleizer::extract_parent_deleted_creates`
    /// but without requiring a full Merkleizer instance.
    fn extract_parent_deleted_creates<K: Ord + Clone, V: Clone>(
        mutations: &mut BTreeMap<K, Option<V>>,
        base_diff: &BTreeMap<K, DiffEntry<V>>,
    ) -> BTreeMap<K, (V, Option<Location>)> {
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

        let mut base_diff: BTreeMap<u64, DiffEntry<u64>> = BTreeMap::new();
        base_diff.insert(
            1,
            DiffEntry::Deleted {
                base_old_loc: Some(Location::new(5)),
            },
        );
        base_diff.insert(
            4,
            DiffEntry::Active {
                value: 400,
                loc: Location::new(10),
                base_old_loc: None,
            },
        );

        let creates = extract_parent_deleted_creates(&mut mutations, &base_diff);

        // key1 extracted: value=100, base_old_loc=Some(5)
        assert_eq!(creates.len(), 1);
        let (value, base_old_loc) = creates.get(&1).unwrap();
        assert_eq!(*value, 100);
        assert_eq!(*base_old_loc, Some(Location::new(5)));

        // key1 removed from mutations, key2 and key3 remain.
        assert_eq!(mutations.len(), 2);
        assert!(mutations.contains_key(&2));
        assert!(mutations.contains_key(&3));
    }

    #[test]
    fn extract_parent_deleted_creates_delete_not_extracted() {
        let mut mutations: BTreeMap<u64, Option<u64>> = BTreeMap::new();
        mutations.insert(1, None); // deleting a parent-deleted key

        let mut base_diff: BTreeMap<u64, DiffEntry<u64>> = BTreeMap::new();
        base_diff.insert(
            1,
            DiffEntry::Deleted {
                base_old_loc: Some(Location::new(5)),
            },
        );

        let creates = extract_parent_deleted_creates(&mut mutations, &base_diff);

        // Delete of a deleted key is not a create.
        assert!(creates.is_empty());
        // Mutation unchanged.
        assert_eq!(mutations.len(), 1);
        assert!(mutations.contains_key(&1));
    }
}
