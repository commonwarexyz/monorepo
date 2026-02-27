//! Batch mutation API for Any QMDBs.
//!
//! Provides a collect-then-resolve pattern for QMDB mutations:
//! 1. `db.new_batch()` creates a `Batch` that borrows `&Db`
//! 2. `batch.write(key, value)` records mutations synchronously (BTreeMap insert)
//! 3. `batch.merkleize(metadata)` resolves keys, generates floor-raise ops, and merkleizes
//! 4. `merkleized.root()` returns the exact committed root
//! 5. `merkleized.finalize()` produces an owned `FinalizedBatch`
//! 6. `db.apply_batch(finalized)` writes to journal, flushes, and updates snapshot

use crate::{
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable, Reader},
    },
    mmr::Location,
    qmdb::{
        any::{
            db::{AuthenticatedLog, Db},
            operation::{update, Operation},
            ValueEncoding,
        },
        delete_known_loc,
        operation::{Key, Operation as OperationTrait},
        update_known_loc, Error,
    },
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::{Digest, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use core::ops::Range;
use futures::future::try_join_all;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tracing::debug;

/// What happened to a key in this batch.
///
/// Each entry stores the `base_old_loc`: the key's location in the base DB's snapshot
/// (not a virtual location from an intermediate batch). This ensures `finalize()` always
/// produces snapshot deltas that are valid against the base DB.
pub(crate) enum OverlayEntry<V> {
    /// Key was updated (existing) or created (new).
    Active {
        value: V,
        /// The virtual location where this operation will be written.
        loc: Location,
        /// The key's location in the base DB snapshot. `None` if the key is new
        /// to the base DB (created by this batch or an ancestor batch).
        base_old_loc: Option<Location>,
    },
    /// Key was deleted.
    Deleted {
        /// The key's location in the base DB snapshot. `None` if the key was
        /// created by an ancestor batch and never existed in the base DB.
        base_old_loc: Option<Location>,
    },
}

impl<V: Clone> Clone for OverlayEntry<V> {
    fn clone(&self) -> Self {
        match self {
            Self::Active {
                value,
                loc,
                base_old_loc,
            } => Self::Active {
                value: value.clone(),
                loc: *loc,
                base_old_loc: *base_old_loc,
            },
            Self::Deleted { base_old_loc } => Self::Deleted {
                base_old_loc: *base_old_loc,
            },
        }
    }
}

/// A single snapshot index mutation to apply to the base DB's snapshot.
///
/// Uses pre-computed absolute locations that are always base-DB-relative
/// (never virtual locations from intermediate batches). Applied by
/// `apply_batch()` using `update_known_loc()`, `snapshot.insert()`, and
/// `delete_known_loc()`.
pub(crate) enum SnapshotDelta<K> {
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

/// A QMDB batch that accumulates mutations and can be merkleized.
///
/// Mutations (`write`) are sync -- just BTreeMap inserts, no I/O. All async work
/// (key resolution, floor raise, journal reads) happens in `merkleize()`.
///
/// `JP` is the journal parent type: `AuthenticatedLog` for top-level batches,
/// or `authenticated::MerkleizedBatch` for stacked batches. This type parameter
/// is erased at `finalize()` and never visible to callers of `Db::new_batch()`.
#[allow(clippy::type_complexity)]
pub struct Batch<'a, E, K, V, C, I, H, U, JP>
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
    /// Reference to the underlying DB for journal reads and snapshot access.
    db: &'a Db<E, C, I, H, U>,

    /// The journal parent for creating authenticated journal batches.
    /// For top-level batches: `&Journal` (base MMR).
    /// For stacked batches: `&authenticated::MerkleizedBatch` (inherits parent's MMR state).
    journal_parent: &'a JP,

    /// The user mutations: key -> Some(value) for update/create, None for delete.
    /// Sync inserts only, no I/O.
    mutations: BTreeMap<K, Option<V::Value>>,

    /// Flattened overlay from ancestor MerkleizedBatches (if stacking).
    /// Empty for top-level batches.
    parent_overlay: BTreeMap<K, OverlayEntry<V::Value>>,

    /// Arc segments of operations accumulated by ancestor MerkleizedBatch chain.
    /// Empty for top-level batches. Used for reading operations at virtual locations
    /// during floor raise.
    parent_operation_chain: Vec<Arc<Vec<Operation<K, V, U>>>>,

    /// The base size: db.log journal size for top-level batches;
    /// db.log journal size + parent_operations.len() for stacked batches.
    /// This batch's i-th operation will land at location `parent_total_size + i`.
    parent_total_size: u64,

    /// Parent's inactivity floor location (after parent's floor raise).
    parent_inactivity_floor_loc: Location,

    /// Parent's active key count (adjusted by parent's delta).
    parent_active_keys: usize,
}

/// A resolved and merkleized batch of QMDB operations.
///
/// Includes user mutations + floor raise moves + CommitFloor operation.
/// `root()` returns the exact committed root -- identical to what `db.root()`
/// will return after `apply_batch()`.
///
/// `JP` is the journal parent type, matching the parent `Batch`'s `JP`.
/// It is erased at `finalize()`.
#[allow(clippy::type_complexity)]
pub struct MerkleizedBatch<'a, E, K, V, C, I, H, U, JP>
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
    /// Reference to the parent DB.
    db: &'a Db<E, C, I, H, U>,

    /// The authenticated journal's MerkleizedBatch. Contains only THIS batch's
    /// operations. Parent operations are accessed through the MMR chain via
    /// `JP::MmrParent`, avoiding re-encoding and re-hashing.
    journal_merkleized: authenticated::MerkleizedBatch<'a, H, JP::MmrParent, Operation<K, V, U>>,

    /// Snapshot overlay: for each key touched by this batch chain,
    /// maps to the new state (including floor-raise mutations).
    overlay: BTreeMap<K, OverlayEntry<V::Value>>,

    /// Arc segments of all operations in the entire chain (parent + this batch's).
    /// Stored for stacking: child batches read from them for virtual locations.
    operation_chain: Vec<Arc<Vec<Operation<K, V, U>>>>,

    /// The new inactivity floor location (after this batch's floor raise).
    new_inactivity_floor_loc: Location,

    /// The new last commit location (the CommitFloor operation's location).
    new_last_commit_loc: Location,
}

/// An owned batch ready to be applied. No borrows -- can outlive the Db reference.
pub struct FinalizedBatch<K, D: Digest, Item: Send> {
    /// The finalized authenticated journal batch (MMR changeset + item chain).
    journal_finalized: authenticated::FinalizedBatch<D, Item>,

    /// Snapshot mutations to apply, in order.
    snapshot_deltas: Vec<SnapshotDelta<K>>,

    /// Net change in active_keys count.
    active_keys_delta: isize,

    /// The new inactivity floor location (post floor raise).
    new_inactivity_floor_loc: Location,

    /// The new last commit location (the CommitFloor operation).
    new_last_commit_loc: Location,
}

// ============================================================
// Batch: sync mutations + async merkleize
// ============================================================

impl<'a, E, K, V, C, I, H, U, JP> Batch<'a, E, K, V, C, I, H, U, JP>
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
    /// Record a mutation. Sync -- just inserts into BTreeMap, no I/O.
    /// Use `Some(value)` for update/create, `None` for delete.
    pub fn write(&mut self, key: K, value: Option<V::Value>) {
        self.mutations.insert(key, value);
    }
}

// Unordered-specific methods.
impl<'a, E, K, V, C, I, H, JP> Batch<'a, E, K, V, C, I, H, update::Unordered<K, V>, JP>
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
    /// Read through: mutations -> parent_overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        // Check this batch's pending mutations first.
        if let Some(value) = self.mutations.get(key) {
            return Ok(value.clone());
        }
        // Check parent overlay (for stacked batches).
        if let Some(entry) = self.parent_overlay.get(key) {
            return match entry {
                OverlayEntry::Active { value, .. } => Ok(Some(value.clone())),
                OverlayEntry::Deleted { .. } => Ok(None),
            };
        }
        // Fall through to base DB.
        self.db.get(key).await
    }

    /// Resolve all mutations, perform floor raise, append CommitFloor, and merkleize
    /// everything in a single authenticated journal batch.
    ///
    /// The returned `MerkleizedBatch` has a `root()` that equals the exact committed
    /// root (what `db.root()` will return after `apply_batch()`).
    pub async fn merkleize(
        self,
        metadata: Option<V::Value>,
    ) -> Result<MerkleizedBatch<'a, E, K, V, C, I, H, update::Unordered<K, V>, JP>, Error> {
        let db = self.db;
        let base = self.parent_total_size;

        // ============================================================
        // Phase 1: Resolve existing keys (async I/O)
        // ============================================================
        // Collect all candidate locations for keys in mutation set.
        // For stacked batches, parent overlay Active entries contribute their
        // virtual locations, interleaved with base-snapshot locations. This
        // ensures all existing-key operations are generated in location order,
        // matching the sequential-commit path.
        let mut locations = Vec::new();
        let mut parent_deleted_creates: Vec<(K, V::Value, Option<Location>)> = Vec::new();
        for key in self.mutations.keys() {
            if let Some(entry) = self.parent_overlay.get(key) {
                match entry {
                    OverlayEntry::Active { loc, .. } => {
                        // Parent created/updated this key at a virtual loc.
                        locations.push(*loc);
                    }
                    OverlayEntry::Deleted { .. } => {
                        // Parent deleted this key. If mutation is a create,
                        // handle as a create (nonexistent key). Otherwise skip.
                    }
                }
                continue;
            }
            // Not in parent overlay: look up in base DB snapshot.
            let iter = db.snapshot.get(key);
            locations.extend(iter.copied());
        }
        locations.sort();
        locations.dedup();

        // Batch-read all candidate operations. Uses read_operation_at to
        // handle both on-disk (base DB) and in-memory (parent ops) locations.
        let mut results = Vec::with_capacity(locations.len());
        for &loc in &locations {
            let op =
                read_operation_at(loc, &self.parent_operation_chain, &[], base, &db.log).await?;
            results.push(op);
        }

        // ============================================================
        // Phase 2: Generate user mutation operations
        // ============================================================
        let mut mutations = self.mutations;
        let mut ops: Vec<Operation<K, V, update::Unordered<K, V>>> = Vec::new();
        let mut overlay: BTreeMap<K, OverlayEntry<V::Value>> = BTreeMap::new();
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;

        // Process updates/deletes of existing keys in location order.
        // This includes keys from both the base snapshot and the parent overlay.
        for (op, &old_loc) in results.iter().zip(&locations) {
            let key = op.key().expect("updates should have a key");
            let Some(mutation) = mutations.remove(key) else {
                continue; // translated key collision
            };

            let new_loc = Location::new_unchecked(base + ops.len() as u64);

            // Determine base_old_loc: trace through parent overlay to find
            // the key's location in the base DB snapshot.
            let base_old_loc = self
                .parent_overlay
                .get(key)
                .map_or(Some(old_loc), |parent_entry| match parent_entry {
                    OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                    OverlayEntry::Deleted { .. } => {
                        unreachable!("key found as existing but deleted in parent")
                    }
                });

            match mutation {
                Some(value) => {
                    ops.push(Operation::Update(update::Unordered(
                        key.clone(),
                        value.clone(),
                    )));
                    overlay.insert(
                        key.clone(),
                        OverlayEntry::Active {
                            value,
                            loc: new_loc,
                            base_old_loc,
                        },
                    );
                    user_steps += 1;
                }
                None => {
                    ops.push(Operation::Delete(key.clone()));
                    overlay.insert(key.clone(), OverlayEntry::Deleted { base_old_loc });
                    active_keys_delta -= 1;
                    user_steps += 1;
                }
            }
        }

        // Handle parent-deleted keys that the child wants to re-create.
        for key in mutations.keys() {
            if let Some(OverlayEntry::Deleted { base_old_loc }) = self.parent_overlay.get(key) {
                if let Some(Some(value)) = mutations.get(key) {
                    parent_deleted_creates.push((key.clone(), value.clone(), *base_old_loc));
                }
            }
        }
        for (key, _, _) in &parent_deleted_creates {
            mutations.remove(key);
        }

        // Process creates (remaining mutations not matched to existing keys,
        // plus keys that were deleted by a parent batch and re-created here).
        for (key, value) in mutations {
            let Some(value) = value else {
                continue; // delete nonexistent key = no-op
            };
            let new_loc = Location::new_unchecked(base + ops.len() as u64);
            ops.push(Operation::Update(update::Unordered(
                key.clone(),
                value.clone(),
            )));
            overlay.insert(
                key,
                OverlayEntry::Active {
                    value,
                    loc: new_loc,
                    base_old_loc: None,
                },
            );
            active_keys_delta += 1;
        }
        for (key, value, base_old_loc) in parent_deleted_creates {
            let new_loc = Location::new_unchecked(base + ops.len() as u64);
            ops.push(Operation::Update(update::Unordered(
                key.clone(),
                value.clone(),
            )));
            overlay.insert(
                key,
                OverlayEntry::Active {
                    value,
                    loc: new_loc,
                    base_old_loc,
                },
            );
            if base_old_loc.is_none() {
                active_keys_delta += 1;
            }
        }

        // ============================================================
        // Phase 3: Floor raise
        // ============================================================
        // Steps = user_steps + 1 (+1 for previous commit becoming inactive).
        let total_steps = user_steps + 1;
        let total_active_keys = self.parent_active_keys as isize + active_keys_delta;
        let mut floor = self.parent_inactivity_floor_loc;

        if total_active_keys > 0 {
            for _ in 0..total_steps {
                // Compute current tip dynamically: includes user ops + previously
                // moved floor-raise ops. This matches the old `raise_floor()` behavior
                // which recomputes `self.log.size()` at the start of each step.
                let current_tip = base + ops.len() as u64;

                // Scan forward from floor to find the next active operation.
                loop {
                    if *floor >= current_tip {
                        break; // reached current tip
                    }
                    let op_loc = floor;
                    floor = Location::new_unchecked(*floor + 1);

                    // Read the operation from the appropriate source.
                    let op = read_operation_at(
                        op_loc,
                        &self.parent_operation_chain,
                        &ops,
                        base,
                        &db.log,
                    )
                    .await?;

                    let Some(key) = op.key() else {
                        continue; // skip CommitFloor and other non-keyed ops
                    };
                    // Clone key before potentially moving op.
                    let key = key.clone();

                    // Check if this operation is still active.
                    if is_active_at(&key, op_loc, &overlay, &self.parent_overlay, &db.snapshot) {
                        // Re-append at the next position (move to new location).
                        let new_loc = Location::new_unchecked(base + ops.len() as u64);

                        // Determine base-DB-relative old_loc for this floor-raise move.
                        let base_old_loc = if let Some(entry) = overlay.get(&key) {
                            match entry {
                                OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                                _ => unreachable!("is_active_at returned true"),
                            }
                        } else if let Some(entry) = self.parent_overlay.get(&key) {
                            match entry {
                                OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                                _ => unreachable!("is_active_at returned true"),
                            }
                        } else {
                            Some(op_loc) // op_loc is in base DB
                        };

                        // Extract value from the operation for the overlay.
                        let value = extract_value(&op);
                        ops.push(op);
                        overlay.insert(
                            key,
                            OverlayEntry::Active {
                                value,
                                loc: new_loc,
                                base_old_loc,
                            },
                        );
                        break; // found one active op, advance to next step
                    }
                    // Not active, continue scanning.
                }
            }
        } else {
            // DB is empty after this batch; raise floor to tip.
            floor = Location::new_unchecked(base + ops.len() as u64);
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        }

        // ============================================================
        // Phase 4: CommitFloor operation
        // ============================================================
        let commit_loc = Location::new_unchecked(base + ops.len() as u64);
        ops.push(Operation::CommitFloor(metadata, floor));

        // ============================================================
        // Phase 5: Create and merkleize the journal batch
        // ============================================================
        // Use journal stacking: the journal parent already contains all parent
        // operations' MMR state, so we only need to add THIS batch's operations.
        // Parent operations are never re-cloned, re-encoded, or re-hashed.
        let parent_chain = self.parent_operation_chain;
        let mut journal_batch = self.journal_parent.new_batch();
        for op in &ops {
            journal_batch.add(op.clone());
        }
        let journal_merkleized = journal_batch.merkleize();

        // Build the operation chain: parent segments + this batch's segment.
        let mut operation_chain = parent_chain;
        operation_chain.push(Arc::new(ops));

        // ============================================================
        // Phase 6: Merge with parent overlay
        // ============================================================
        // Parent overlay entries that weren't overridden by this batch.
        for (k, v) in &self.parent_overlay {
            overlay.entry(k.clone()).or_insert_with(|| v.clone());
        }

        Ok(MerkleizedBatch {
            db,
            journal_merkleized,
            overlay,
            operation_chain,
            new_inactivity_floor_loc: floor,
            new_last_commit_loc: commit_loc,
        })
    }
}

// Ordered-specific methods.
impl<'a, E, K, V, C, I, H, JP> Batch<'a, E, K, V, C, I, H, update::Ordered<K, V>, JP>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<K, V, update::Ordered<K, V>>>,
    I: OrderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, update::Ordered<K, V>>: Codec,
    V::Value: Send + Sync,
    JP: authenticated::Batchable<H, Operation<K, V, update::Ordered<K, V>>>,
{
    /// Read through: mutations -> parent_overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        // Check this batch's pending mutations first.
        if let Some(value) = self.mutations.get(key) {
            return Ok(value.clone());
        }
        // Check parent overlay (for stacked batches).
        if let Some(entry) = self.parent_overlay.get(key) {
            return match entry {
                OverlayEntry::Active { value, .. } => Ok(Some(value.clone())),
                OverlayEntry::Deleted { .. } => Ok(None),
            };
        }
        // Fall through to base DB.
        self.db.get(key).await
    }

    /// Resolve all mutations, perform floor raise, append CommitFloor, and merkleize
    /// everything in a single authenticated journal batch.
    ///
    /// This is the ordered variant which maintains the `next_key` linked list.
    pub async fn merkleize(
        self,
        metadata: Option<V::Value>,
    ) -> Result<MerkleizedBatch<'a, E, K, V, C, I, H, update::Ordered<K, V>, JP>, Error> {
        use crate::qmdb::any::ordered::{find_next_key, find_prev_key};

        let db = self.db;
        let base = self.parent_total_size;

        // ============================================================
        // Phase 1: Resolve existing keys (async I/O)
        // ============================================================
        let mut mutations = self.mutations;
        let mut locations = Vec::new();
        let mut parent_deleted_creates: Vec<(K, V::Value, Option<Location>)> = Vec::new();
        for key in mutations.keys() {
            if let Some(entry) = self.parent_overlay.get(key) {
                match entry {
                    OverlayEntry::Active { loc, .. } => {
                        locations.push(*loc);
                    }
                    OverlayEntry::Deleted { .. } => {
                        // Parent deleted this key. Re-creates handled below.
                    }
                }
                continue;
            }
            let iter = db.snapshot.get(key);
            locations.extend(iter.copied());
        }
        locations.sort();
        locations.dedup();

        // Read operations using read_operation_at (handles virtual locations).
        let mut results = Vec::with_capacity(locations.len());
        for &loc in &locations {
            let op: Operation<K, V, update::Ordered<K, V>> =
                read_operation_at(loc, &self.parent_operation_chain, &[], base, &db.log).await?;
            results.push(op);
        }

        // Extract Update data from each result.
        let update_results: Vec<update::Ordered<K, V>> = results
            .into_iter()
            .map(|op| match op {
                Operation::Update(data) => data,
                _ => unreachable!("snapshot should only reference Update operations"),
            })
            .collect();

        // ============================================================
        // Phase 2: Classify mutations into deleted, created, updated
        // ============================================================
        let mut possible_next: BTreeSet<K> = BTreeSet::new();
        let mut possible_previous: BTreeMap<K, (V::Value, Location)> = BTreeMap::new();

        let mut deleted: Vec<K> = Vec::new();
        let mut updated: BTreeMap<K, (V::Value, Location)> = BTreeMap::new();

        for (key_data, &old_loc) in update_results.iter().zip(&locations) {
            possible_previous.insert(key_data.key.clone(), (key_data.value.clone(), old_loc));
            possible_next.insert(key_data.next_key.clone());

            let Some(mutation) = mutations.remove(&key_data.key) else {
                continue; // translated key collision
            };

            if let Some(new_value) = mutation {
                updated.insert(key_data.key.clone(), (new_value, old_loc));
            } else {
                deleted.push(key_data.key.clone());
            }
        }

        // Handle parent-deleted keys that the child wants to re-create.
        for key in mutations.keys() {
            if let Some(OverlayEntry::Deleted { base_old_loc }) = self.parent_overlay.get(key) {
                if let Some(Some(value)) = mutations.get(key) {
                    parent_deleted_creates.push((key.clone(), value.clone(), *base_old_loc));
                }
            }
        }
        for (key, _, _) in &parent_deleted_creates {
            mutations.remove(key);
        }

        // Remaining mutations are creates.
        let mut created: BTreeMap<K, V::Value> = BTreeMap::new();
        for (key, value) in mutations {
            let Some(value) = value else {
                continue; // delete of non-existent key
            };
            created.insert(key.clone(), value);
            possible_next.insert(key);
        }
        let mut recreate_base_locs: BTreeMap<K, Option<Location>> = BTreeMap::new();
        for (key, value, base_old_loc) in parent_deleted_creates {
            possible_next.insert(key.clone());
            recreate_base_locs.insert(key.clone(), base_old_loc);
            created.insert(key, value);
        }

        // ============================================================
        // Phase 3: Look up prev_translated_key for created/deleted keys
        // ============================================================
        let mut prev_locations = Vec::new();
        for key in deleted.iter().chain(created.keys()) {
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
            possible_next.insert(data.next_key.clone());
            possible_previous.insert(data.key.clone(), (data.value.clone(), old_loc));
        }

        // Remove deleted keys from possible_* sets.
        for key in deleted.iter() {
            possible_previous.remove(key);
            possible_next.remove(key);
        }

        // ============================================================
        // Phase 3.5: Incorporate parent overlay into possible_* sets
        // ============================================================
        // Phase 3 only queries the base DB snapshot, which is blind to parent overlay
        // mutations. We must add parent-created keys to possible_next/possible_previous.
        for (key, entry) in &self.parent_overlay {
            // Skip keys already handled by this batch's mutations.
            if updated.contains_key(key) || created.contains_key(key) || deleted.contains(key) {
                continue;
            }
            if let OverlayEntry::Active { value, loc, .. } = entry {
                let op: Operation<K, V, update::Ordered<K, V>> =
                    read_operation_at(*loc, &self.parent_operation_chain, &[], base, &db.log)
                        .await?;
                let data = match op {
                    Operation::Update(data) => data,
                    _ => unreachable!("parent overlay Active should reference Update op"),
                };
                possible_next.insert(key.clone());
                possible_next.insert(data.next_key);
                possible_previous.insert(key.clone(), (value.clone(), *loc));
            }
        }

        // Remove all known-deleted keys from possible_* sets. Phase 3 already did
        // this for this batch's deletes, but Phase 3.5 may have re-added them via
        // parent overlay next_key references. Also remove parent-deleted keys that
        // Phase 3 (which only queries the base DB) may have added.
        for key in deleted.iter() {
            possible_previous.remove(key);
            possible_next.remove(key);
        }
        for (key, entry) in &self.parent_overlay {
            if matches!(entry, OverlayEntry::Deleted { .. }) && !created.contains_key(key) {
                possible_previous.remove(key);
                possible_next.remove(key);
            }
        }

        // ============================================================
        // Phase 4: Generate operations
        // ============================================================
        let mut ops: Vec<Operation<K, V, update::Ordered<K, V>>> = Vec::new();
        let mut overlay: BTreeMap<K, OverlayEntry<V::Value>> = BTreeMap::new();
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;
        let mut already_updated: BTreeSet<K> = BTreeSet::new();

        // 4a. Process deletes.
        for key in deleted.iter() {
            let new_loc = Location::new_unchecked(base + ops.len() as u64);
            ops.push(Operation::Delete(key.clone()));

            // Find the old_loc from the original results.
            let old_loc = update_results
                .iter()
                .zip(&locations)
                .find(|(data, _)| data.key == *key)
                .map(|(_, &loc)| loc)
                .expect("deleted key must have been found in results");

            let base_old_loc =
                self.parent_overlay
                    .get(key)
                    .map_or(Some(old_loc), |entry| match entry {
                        OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                        OverlayEntry::Deleted { .. } => {
                            unreachable!("key found in results but deleted in parent")
                        }
                    });

            overlay.insert(key.clone(), OverlayEntry::Deleted { base_old_loc });
            active_keys_delta -= 1;
            user_steps += 1;
            let _ = new_loc; // used only to record position in ops
        }

        // 4b. Process updates of existing keys.
        for (key, (value, old_loc)) in &updated {
            let new_loc = Location::new_unchecked(base + ops.len() as u64);
            let next_key = find_next_key(key, &possible_next);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));

            let base_old_loc = self
                .parent_overlay
                .get(key)
                .map_or(Some(*old_loc), |entry| match entry {
                    OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                    OverlayEntry::Deleted { .. } => {
                        unreachable!("key found in results but deleted in parent")
                    }
                });

            overlay.insert(
                key.clone(),
                OverlayEntry::Active {
                    value: value.clone(),
                    loc: new_loc,
                    base_old_loc,
                },
            );
            user_steps += 1;
            already_updated.insert(key.clone());
        }

        // 4c. Process creates + update predecessors.
        for (key, value) in &created {
            let new_loc = Location::new_unchecked(base + ops.len() as u64);
            let next_key = find_next_key(key, &possible_next);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));
            let base_old_loc = recreate_base_locs.get(key).copied().flatten();
            overlay.insert(
                key.clone(),
                OverlayEntry::Active {
                    value: value.clone(),
                    loc: new_loc,
                    base_old_loc,
                },
            );
            if base_old_loc.is_none() {
                active_keys_delta += 1;
            }

            // Update the next_key value of its predecessor (unless there are no existing keys).
            if possible_previous.is_empty() {
                continue;
            }
            let (prev_key, (prev_value, prev_loc)) = find_prev_key(key, &possible_previous);
            if already_updated.contains(prev_key) {
                continue;
            }
            already_updated.insert(prev_key.clone());

            let prev_new_loc = Location::new_unchecked(base + ops.len() as u64);
            let prev_next_key = find_next_key(prev_key, &possible_next);
            ops.push(Operation::Update(update::Ordered {
                key: prev_key.clone(),
                value: prev_value.clone(),
                next_key: prev_next_key,
            }));

            let prev_base_old_loc = self.parent_overlay.get(prev_key).map_or_else(
                || {
                    overlay
                        .get(prev_key)
                        .map_or(Some(*prev_loc), |entry| match entry {
                            OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                            _ => unreachable!("prev_key should be active"),
                        })
                },
                |entry| match entry {
                    OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                    _ => unreachable!("prev_key should be active"),
                },
            );

            overlay.insert(
                prev_key.clone(),
                OverlayEntry::Active {
                    value: prev_value.clone(),
                    loc: prev_new_loc,
                    base_old_loc: prev_base_old_loc,
                },
            );
            user_steps += 1;
        }

        // 4d. Update predecessors of deleted keys.
        if !possible_next.is_empty() && !possible_previous.is_empty() {
            for key in deleted.iter() {
                let (prev_key, (prev_value, prev_loc)) = find_prev_key(key, &possible_previous);
                if already_updated.contains(prev_key) {
                    continue;
                }
                already_updated.insert(prev_key.clone());

                let prev_new_loc = Location::new_unchecked(base + ops.len() as u64);
                let prev_next_key = find_next_key(prev_key, &possible_next);
                ops.push(Operation::Update(update::Ordered {
                    key: prev_key.clone(),
                    value: prev_value.clone(),
                    next_key: prev_next_key,
                }));

                let prev_base_old_loc = self.parent_overlay.get(prev_key).map_or_else(
                    || {
                        overlay
                            .get(prev_key)
                            .map_or(Some(*prev_loc), |entry| match entry {
                                OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                                _ => unreachable!("prev_key should be active"),
                            })
                    },
                    |entry| match entry {
                        OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                        _ => unreachable!("prev_key should be active"),
                    },
                );

                overlay.insert(
                    prev_key.clone(),
                    OverlayEntry::Active {
                        value: prev_value.clone(),
                        loc: prev_new_loc,
                        base_old_loc: prev_base_old_loc,
                    },
                );
                user_steps += 1;
            }
        }

        // ============================================================
        // Phase 5: Floor raise (same as unordered)
        // ============================================================
        let total_steps = user_steps + 1;
        let total_active_keys = self.parent_active_keys as isize + active_keys_delta;
        let mut floor = self.parent_inactivity_floor_loc;

        if total_active_keys > 0 {
            for _ in 0..total_steps {
                let current_tip = base + ops.len() as u64;
                loop {
                    if *floor >= current_tip {
                        break;
                    }
                    let op_loc = floor;
                    floor = Location::new_unchecked(*floor + 1);

                    let op = read_operation_at(
                        op_loc,
                        &self.parent_operation_chain,
                        &ops,
                        base,
                        &db.log,
                    )
                    .await?;

                    let Some(key) = op.key() else {
                        continue;
                    };
                    let key = key.clone();

                    if is_active_at(&key, op_loc, &overlay, &self.parent_overlay, &db.snapshot) {
                        let new_loc = Location::new_unchecked(base + ops.len() as u64);
                        let base_old_loc = if let Some(entry) = overlay.get(&key) {
                            match entry {
                                OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                                _ => unreachable!("is_active_at returned true"),
                            }
                        } else if let Some(entry) = self.parent_overlay.get(&key) {
                            match entry {
                                OverlayEntry::Active { base_old_loc, .. } => *base_old_loc,
                                _ => unreachable!("is_active_at returned true"),
                            }
                        } else {
                            Some(op_loc)
                        };

                        let value = extract_ordered_value(&op);
                        ops.push(op);
                        overlay.insert(
                            key,
                            OverlayEntry::Active {
                                value,
                                loc: new_loc,
                                base_old_loc,
                            },
                        );
                        break;
                    }
                }
            }
        } else {
            floor = Location::new_unchecked(base + ops.len() as u64);
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        }

        // ============================================================
        // Phase 6: CommitFloor operation
        // ============================================================
        let commit_loc = Location::new_unchecked(base + ops.len() as u64);
        ops.push(Operation::CommitFloor(metadata, floor));

        // ============================================================
        // Phase 7: Create and merkleize the journal batch
        // ============================================================
        // Use journal stacking: the journal parent already contains all parent
        // operations' MMR state, so we only need to add THIS batch's operations.
        // Parent operations are never re-cloned, re-encoded, or re-hashed.
        let parent_chain = self.parent_operation_chain;
        let mut journal_batch = self.journal_parent.new_batch();
        for op in &ops {
            journal_batch.add(op.clone());
        }
        let journal_merkleized = journal_batch.merkleize();

        // Build the operation chain: parent segments + this batch's segment.
        let mut operation_chain = parent_chain;
        operation_chain.push(Arc::new(ops));

        // Merge parent overlay.
        for (k, v) in &self.parent_overlay {
            overlay.entry(k.clone()).or_insert_with(|| v.clone());
        }

        Ok(MerkleizedBatch {
            db,
            journal_merkleized,
            overlay,
            operation_chain,
            new_inactivity_floor_loc: floor,
            new_last_commit_loc: commit_loc,
        })
    }
}

// Ordered-specific: get() delegates to Db::get() which is only on ordered.
impl<'a, E, K, V, C, I, H, JP> MerkleizedBatch<'a, E, K, V, C, I, H, update::Ordered<K, V>, JP>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<K, V, update::Ordered<K, V>>>,
    I: OrderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, update::Ordered<K, V>>: Codec,
    V::Value: Send + Sync,
    JP: authenticated::Batchable<H, Operation<K, V, update::Ordered<K, V>>>,
{
    /// Read through: overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        if let Some(entry) = self.overlay.get(key) {
            return match entry {
                OverlayEntry::Active { value, .. } => Ok(Some(value.clone())),
                OverlayEntry::Deleted { .. } => Ok(None),
            };
        }
        self.db.get(key).await
    }
}

// ============================================================
// MerkleizedBatch: root, get, finalize
// ============================================================

impl<'a, E, K, V, C, I, H, U, JP> MerkleizedBatch<'a, E, K, V, C, I, H, U, JP>
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
    /// Return the speculative root. This is the exact committed root -- identical
    /// to what `db.root()` will return after `apply_batch()`.
    pub fn root(&self) -> H::Digest {
        self.journal_merkleized.root()
    }

    /// Create a child batch that sees this batch's state.
    ///
    /// The child batch receives a clone of this batch's overlay and Arc refs to
    /// all chain operation segments (O(D) Arc bumps, not O(N) deep clones).
    /// The child's journal parent is `&self.journal_merkleized`, so the child's
    /// `merkleize()` only processes its own new operations -- parent operations
    /// are never re-encoded or re-hashed.
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
        authenticated::MerkleizedBatch<'a, H, JP::MmrParent, Operation<K, V, U>>,
    > {
        let db_journal_size = *self.db.last_commit_loc + 1;
        let chain_ops_len: u64 = self.operation_chain.iter().map(|s| s.len() as u64).sum();
        let total_size = db_journal_size + chain_ops_len;

        // Compute active keys from overlay: base DB active_keys + net delta.
        let overlay_delta: isize = self
            .overlay
            .values()
            .map(|e| match e {
                OverlayEntry::Active {
                    base_old_loc: None, ..
                } => 1isize,
                OverlayEntry::Deleted {
                    base_old_loc: Some(_),
                } => -1,
                _ => 0,
            })
            .sum();
        let parent_active_keys = (self.db.active_keys as isize + overlay_delta) as usize;

        Batch {
            db: self.db,
            journal_parent: &self.journal_merkleized,
            mutations: BTreeMap::new(),
            parent_overlay: self.overlay.clone(),
            parent_operation_chain: self.operation_chain.clone(), // O(D) Arc bumps
            parent_total_size: total_size,
            parent_inactivity_floor_loc: self.new_inactivity_floor_loc,
            parent_active_keys,
        }
    }
}

// Unordered-specific: get() delegates to Db::get() which is only on unordered.
impl<'a, E, K, V, C, I, H, JP> MerkleizedBatch<'a, E, K, V, C, I, H, update::Unordered<K, V>, JP>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    C: Contiguous<Item = Operation<K, V, update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, update::Unordered<K, V>>: Codec,
    JP: authenticated::Batchable<H, Operation<K, V, update::Unordered<K, V>>>,
{
    /// Read through: overlay -> db snapshot + journal.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        if let Some(entry) = self.overlay.get(key) {
            return match entry {
                OverlayEntry::Active { value, .. } => Ok(Some(value.clone())),
                OverlayEntry::Deleted { .. } => Ok(None),
            };
        }
        self.db.get(key).await
    }
}

impl<'a, E, K, V, C, I, H, U, JP> MerkleizedBatch<'a, E, K, V, C, I, H, U, JP>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync + 'static,
    C: Mutable<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
    JP: authenticated::Batchable<H, Operation<K, V, U>>,
{
    /// Consume this batch, producing an owned `FinalizedBatch` that can be
    /// applied to the DB without borrow conflicts.
    ///
    /// Builds snapshot deltas from the merged overlay. Each entry's `base_old_loc`
    /// traces back to the base DB, ensuring deltas are always valid against the
    /// base DB regardless of stacking depth.
    pub fn finalize(self) -> FinalizedBatch<K, H::Digest, Operation<K, V, U>> {
        let snapshot_deltas: Vec<_> = self
            .overlay
            .into_iter()
            .filter_map(|(key, entry)| match entry {
                // Key was updated; it existed in the base DB at old_loc.
                OverlayEntry::Active {
                    loc,
                    base_old_loc: Some(old),
                    ..
                } => Some(SnapshotDelta::Update {
                    key,
                    old_loc: old,
                    new_loc: loc,
                }),
                // Key was created; did not exist in the base DB.
                OverlayEntry::Active {
                    loc,
                    base_old_loc: None,
                    ..
                } => Some(SnapshotDelta::Insert { key, new_loc: loc }),
                // Key was deleted; it existed in the base DB at old_loc.
                OverlayEntry::Deleted {
                    base_old_loc: Some(old),
                } => Some(SnapshotDelta::Delete { key, old_loc: old }),
                // Key was created then deleted within the batch chain.
                // Net effect on the base DB is nothing.
                OverlayEntry::Deleted { base_old_loc: None } => None,
            })
            .collect();

        // Compute active_keys_delta from snapshot deltas. This is always correct
        // regardless of stacking depth because the deltas reflect the net effect
        // of the entire batch chain on the base DB.
        let active_keys_delta = snapshot_deltas
            .iter()
            .map(|d| match d {
                SnapshotDelta::Insert { .. } => 1isize,
                SnapshotDelta::Delete { .. } => -1,
                SnapshotDelta::Update { .. } => 0,
            })
            .sum::<isize>();

        FinalizedBatch {
            journal_finalized: self.journal_merkleized.finalize(),
            snapshot_deltas,
            active_keys_delta,
            new_inactivity_floor_loc: self.new_inactivity_floor_loc,
            new_last_commit_loc: self.new_last_commit_loc,
        }
    }
}

// ============================================================
// Db: new_batch, apply_batch
// ============================================================

impl<E, K, V, C, I, H, U> Db<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Create a new batch. Borrows `&self` immutably so multiple batches can
    /// coexist. The DB must be in committed (Durable) state.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(&self) -> Batch<'_, E, K, V, C, I, H, U, AuthenticatedLog<E, C, H>> {
        // The DB is always committed, so journal size = last_commit_loc + 1.
        let journal_size = *self.last_commit_loc + 1;
        Batch {
            db: self,
            journal_parent: &self.log,
            mutations: BTreeMap::new(),
            parent_overlay: BTreeMap::new(),
            parent_operation_chain: Vec::new(),
            parent_total_size: journal_size,
            parent_inactivity_floor_loc: self.inactivity_floor_loc,
            parent_active_keys: self.active_keys,
        }
    }
}

impl<E, K, V, C, I, H, U> Db<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    K: Key,
    V: ValueEncoding,
    U: update::Update<K, V> + Send + Sync + 'static,
    C: Mutable<Item = Operation<K, V, U>> + crate::Persistable<Error = crate::journal::Error>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Apply a finalized batch to the database.
    ///
    /// This is the single mutation point for the DB. It:
    /// 1. Writes all operations (user + floor raise + CommitFloor) to the journal
    /// 2. Flushes the journal to disk
    /// 3. Updates the in-memory snapshot index
    /// 4. Updates DB metadata (active_keys, floor, last_commit)
    ///
    /// Returns the range of locations written.
    pub async fn apply_batch(
        &mut self,
        batch: FinalizedBatch<K, H::Digest, Operation<K, V, U>>,
    ) -> Result<Range<Location>, Error> {
        let start_loc = Location::new_unchecked(*self.last_commit_loc + 1);

        // 1. Write all operations to the authenticated journal + apply MMR changeset.
        self.log.apply_batch(batch.journal_finalized).await?;

        // 2. Flush journal to disk.
        self.log.commit().await?;

        // 3. Apply snapshot deltas to the in-memory index.
        for delta in batch.snapshot_deltas {
            match delta {
                SnapshotDelta::Update {
                    key,
                    old_loc,
                    new_loc,
                } => {
                    update_known_loc(&mut self.snapshot, &key, old_loc, new_loc);
                }
                SnapshotDelta::Insert { key, new_loc } => {
                    self.snapshot.insert(&key, new_loc);
                }
                SnapshotDelta::Delete { key, old_loc } => {
                    delete_known_loc(&mut self.snapshot, &key, old_loc);
                }
            }
        }

        // 4. Update DB metadata.
        self.active_keys = (self.active_keys as isize + batch.active_keys_delta) as usize;
        self.inactivity_floor_loc = batch.new_inactivity_floor_loc;
        self.last_commit_loc = batch.new_last_commit_loc;

        // 5. Return the committed location range.
        let end_loc = Location::new_unchecked(*self.last_commit_loc + 1);
        Ok(start_loc..end_loc)
    }
}

// ============================================================
// Helper functions
// ============================================================

/// Read an operation at a given location from the correct source.
///
/// The operation space is divided into three contiguous regions:
///
/// ```text
///  [0 ................. db_journal_size) [db_journal_size .......... base) [base ...... base+len)
///   ^-- base DB journal (on disk)        ^-- parent chain (in memory)     ^-- current_ops (in memory)
/// ```
///
/// For top-level batches, the parent chain is empty, so db_journal_size == base.
async fn read_operation_at<E, C, H, Op>(
    loc: Location,
    parent_chain: &[Arc<Vec<Op>>],
    current_ops: &[Op],
    base: u64,
    log: &AuthenticatedLog<E, C, H>,
) -> Result<Op, Error>
where
    E: Storage + Clock + Metrics,
    C: Contiguous<Item = Op>,
    H: Hasher,
    Op: Clone + CodecShared,
{
    let loc_val = *loc;
    let parent_ops_len: u64 = parent_chain.iter().map(|s| s.len() as u64).sum();
    let db_journal_size = base - parent_ops_len;

    if loc_val >= base {
        // This batch's own operations (user mutations, or earlier floor-raise ops).
        Ok(current_ops[(loc_val - base) as usize].clone())
    } else if loc_val >= db_journal_size {
        // Parent batch chain's operations (in-memory). Walk segments to find the right one.
        let mut offset = (loc_val - db_journal_size) as usize;
        for segment in parent_chain {
            if offset < segment.len() {
                return Ok(segment[offset].clone());
            }
            offset -= segment.len();
        }
        unreachable!("location within parent chain range but not found in segments");
    } else {
        // Base DB's journal (on-disk async read).
        let reader = log.reader().await;
        Ok(reader.read(loc_val).await?)
    }
}

/// Check if the operation at `loc` for `key` is still active.
///
/// Active means: the key's current location in the overlay/snapshot matches `loc`.
/// Checks (in order): batch overlay, parent overlay, base DB snapshot.
fn is_active_at<K: Key, V: Clone, I: UnorderedIndex<Value = Location>>(
    key: &K,
    loc: Location,
    batch_overlay: &BTreeMap<K, OverlayEntry<V>>,
    parent_overlay: &BTreeMap<K, OverlayEntry<V>>,
    snapshot: &I,
) -> bool {
    // Check this batch's overlay.
    if let Some(entry) = batch_overlay.get(key) {
        return match entry {
            OverlayEntry::Active {
                loc: current_loc, ..
            } => *current_loc == loc,
            OverlayEntry::Deleted { .. } => false,
        };
    }
    // Check parent overlay.
    if let Some(entry) = parent_overlay.get(key) {
        return match entry {
            OverlayEntry::Active {
                loc: current_loc, ..
            } => *current_loc == loc,
            OverlayEntry::Deleted { .. } => false,
        };
    }
    // Check base DB snapshot.
    snapshot.get(key).any(|&l| l == loc)
}

/// Extract the value from an unordered Update operation.
fn extract_value<K: Key, V: ValueEncoding>(
    op: &Operation<K, V, update::Unordered<K, V>>,
) -> V::Value {
    match op {
        Operation::Update(update::Unordered(_, value)) => value.clone(),
        _ => unreachable!("floor raise should only re-append Update operations"),
    }
}

/// Extract the value from an ordered Update operation.
fn extract_ordered_value<K: Key, V: ValueEncoding>(
    op: &Operation<K, V, update::Ordered<K, V>>,
) -> V::Value {
    match op {
        Operation::Update(data) => data.value.clone(),
        _ => unreachable!("floor raise should only re-append Update operations"),
    }
}
