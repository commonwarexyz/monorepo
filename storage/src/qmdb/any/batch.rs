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
        batch_chain,
        bitmap::Shared,
        delete_known_loc,
        operation::{Key, Operation as OperationTrait},
        update_known_loc,
    },
    Context,
};
use ahash::AHashSet;
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::bitmap;
use core::ops::Range;
use std::{
    collections::BTreeMap,
    iter,
    sync::{Arc, Weak},
};
use tracing::debug;

/// Maximum number of journal reads to issue concurrently during floor raising.
const MAX_CONCURRENT_READS: u64 = 64;

type DiffVec<K, F, V> = Vec<(K, DiffEntry<F, V>)>;
type DiffSlice<K, F, V> = [(K, DiffEntry<F, V>)];

/// Sorted `(key, (value, loc))` vec consulted by `find_prev_key` to find the predecessor
/// of a given key during ordered merkleization.
type PrevCandidates<K, F, V> = Vec<(K, (V, Location<F>))>;

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

/// Binary-search `entries` for `key`. `entries` must be sorted by key with no duplicates.
pub(crate) fn lookup_sorted<'a, K: Ord, V>(entries: &'a [(K, V)], key: &K) -> Option<&'a V> {
    entries
        .binary_search_by(|(candidate, _)| candidate.cmp(key))
        .ok()
        .map(|idx| &entries[idx].1)
}

/// Where this batch's inherited state comes from.
enum Base<F: Family, D: Digest, U: update::Update + Send + Sync, S: Strategy>
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
    Child(Arc<MerkleizedBatch<F, D, U, S>>),
}

impl<F: Family, D: Digest, U: update::Update + Send + Sync, S: Strategy> Base<F, D, U, S>
where
    Operation<F, U>: Send + Sync,
{
    /// Total operations before this batch (committed DB + ancestor batches).
    fn base_size(&self) -> u64 {
        match self {
            Self::Db { db_size, .. } => *db_size,
            Self::Child(parent) => parent.bounds.total_size,
        }
    }

    /// Effective number of committed DB operations at the base of the batch chain.
    /// For `Db`, this is the DB size when `new_batch()` was called.
    /// For `Child`, this is inherited from the parent (which may be higher than
    /// the original DB size if ancestors were dropped before merkleize).
    fn db_size(&self) -> u64 {
        match self {
            Self::Db { db_size, .. } => *db_size,
            Self::Child(parent) => parent.bounds.db_size,
        }
    }

    fn inactivity_floor_loc(&self) -> Location<F> {
        match self {
            Self::Db {
                inactivity_floor_loc,
                ..
            } => *inactivity_floor_loc,
            Self::Child(parent) => parent.bounds.inactivity_floor,
        }
    }

    fn active_keys(&self) -> usize {
        match self {
            Self::Db { active_keys, .. } => *active_keys,
            Self::Child(parent) => parent.total_active_keys,
        }
    }

    const fn parent(&self) -> Option<&Arc<MerkleizedBatch<F, D, U, S>>> {
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
pub struct UnmerkleizedBatch<F: Family, H, U, S: Strategy>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Authenticated journal batch for computing the speculative Merkle root.
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, U>, S>,

    /// Pending mutations. `Some(value)` for upsert, `None` for delete.
    mutations: BTreeMap<U::Key, Option<U::Value>>,

    /// The committed DB or parent batch this batch was created from.
    base: Base<F, H::Digest, U, S>,
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
pub struct MerkleizedBatch<F: Family, D: Digest, U: update::Update + Send + Sync, S: Strategy>
where
    Operation<F, U>: Send + Sync,
{
    /// Merkleized authenticated journal batch (provides the speculative Merkle root).
    pub(crate) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, U>, S>>,

    /// Cached operations root after applying this batch.
    pub(crate) root: D,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    /// Sorted by key with no duplicates; queried via `lookup_sorted` (binary search).
    pub(crate) diff: Arc<DiffVec<U::Key, F, U::Value>>,

    /// The parent batch in the chain, if any.
    parent: Option<Weak<Self>>,

    /// Total active keys after this batch.
    pub(crate) total_active_keys: usize,

    /// Arc refs to each ancestor's diff, collected during `finish()` while ancestors are
    /// alive. Used by `apply_batch` to apply uncommitted ancestor snapshot diffs.
    /// 1:1 with `bounds.ancestors` (same length, same ordering).
    pub(crate) ancestor_diffs: Vec<Arc<DiffVec<U::Key, F, U::Value>>>,

    /// Position and floor bounds for this batch chain.
    pub(crate) bounds: batch_chain::Bounds<F>,
}

/// Strong ref to an ancestor [`MerkleizedBatch`] collected during merkleize.
type AncestorBatch<F, D, U, S> = Arc<MerkleizedBatch<F, D, U, S>>;

/// Batch-infrastructure state used during merkleization.
///
/// Created by [`UnmerkleizedBatch::into_parts()`], which separates the pending mutations
/// from the resolution/merkleization machinery. Helpers that need access to the parent
/// chain, DB snapshot, or operation log are methods on this struct, eliminating parameter
/// threading.
struct Merkleizer<F: Family, H, U, S: Strategy>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, U>, S>,
    ancestors: Vec<AncestorBatch<F, H::Digest, U, S>>,
    base_size: u64,
    db_size: u64,
    base_inactivity_floor_loc: Location<F>,
    base_active_keys: usize,
}

/// Look up a key in the ancestor chain (immediate parent first).
fn resolve_in_ancestors<'a, F: Family, D: Digest, U: update::Update + Send + Sync, S: Strategy>(
    ancestors: &'a [Arc<MerkleizedBatch<F, D, U, S>>],
    key: &U::Key,
) -> Option<&'a DiffEntry<F, U::Value>>
where
    Operation<F, U>: Send + Sync,
{
    for batch in ancestors {
        if let Some(entry) = lookup_sorted(batch.diff.as_slice(), key) {
            return Some(entry);
        }
    }
    None
}

/// Apply a single diff entry to the snapshot index and activity bitmap in lockstep:
/// install the winning `Active` location and clear the prior committed location.
fn apply_diff<F: Family, V, I: UnorderedIndex<Value = Location<F>>, const N: usize>(
    snapshot: &mut I,
    bitmap: &mut bitmap::Prunable<N>,
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
    if let Some(loc) = entry.loc() {
        bitmap.set_bit(*loc, true);
    }
    if let Some(loc) = base_old_loc {
        bitmap.set_bit(*loc, false);
    }
}

/// k-way sorted merge over diff slices in priority order. On equal keys, the lowest-indexed
/// stream wins and all tied cursors are advanced. Each input slice must be sorted by key.
struct DiffMerge<'a, K, F: Family, V> {
    cursors: Vec<(&'a DiffSlice<K, F, V>, usize)>,
}

impl<'a, K: Ord, F: Family, V> DiffMerge<'a, K, F, V> {
    fn new(streams: impl IntoIterator<Item = &'a DiffSlice<K, F, V>>) -> Self {
        Self {
            cursors: streams.into_iter().map(|s| (s, 0)).collect(),
        }
    }
}

impl<'a, K: Ord, F: Family, V> Iterator for DiffMerge<'a, K, F, V> {
    type Item = (&'a K, &'a DiffEntry<F, V>);

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.cursors.len();
        let mut winner: Option<usize> = None;
        for level in 0..n {
            let (slice, pos) = self.cursors[level];
            let Some((k, _)) = slice.get(pos) else {
                continue;
            };
            let better = match winner {
                None => true,
                Some(w) => {
                    let (ws, wpos) = self.cursors[w];
                    *k < ws[wpos].0
                }
            };
            if better {
                winner = Some(level);
            }
        }
        let level = winner?;
        let (slice, pos) = self.cursors[level];
        for inner in 0..n {
            let (s, p) = self.cursors[inner];
            if s.get(p).is_some_and(|(k, _)| *k == slice[pos].0) {
                self.cursors[inner].1 += 1;
            }
        }
        Some((&slice[pos].0, &slice[pos].1))
    }
}

/// Resolves a key's `base_old_loc` by walking parallel cursors over already-applied
/// ancestor diffs (parent-first). Lookups must be issued in ascending key order because
/// cursors only advance forward. Returns `Some(Some(loc))` for an active entry,
/// `Some(None)` for a deletion, and `None` when no already-applied ancestor touched the
/// key.
struct AppliedAncestorResolver<'a, K, F: Family, V> {
    cursors: Vec<(&'a DiffSlice<K, F, V>, usize)>,
}

impl<'a, K: Ord, F: Family, V> AppliedAncestorResolver<'a, K, F, V> {
    fn new(applied: impl IntoIterator<Item = &'a DiffSlice<K, F, V>>) -> Self {
        Self {
            cursors: applied.into_iter().map(|s| (s, 0)).collect(),
        }
    }

    fn lookup(&mut self, key: &K) -> Option<Option<Location<F>>> {
        for (slice, idx) in self.cursors.iter_mut() {
            while *idx < slice.len() && slice[*idx].0 < *key {
                *idx += 1;
            }
            if *idx < slice.len() && slice[*idx].0 == *key {
                return Some(slice[*idx].1.loc());
            }
        }
        None
    }
}

/// Return the next floor-raise candidate in `[floor, tip)`.
///
/// The committed prefix is indexed by `bitmap`, so unset bits can be skipped without reading
/// their operations. Locations beyond the bitmap's length are uncommitted ancestor operations
/// and remain sequential candidates.
///
/// `current::batch::next_candidate` mirrors this contract over a layered `BitmapBatch` chain;
/// both must obey it.
fn next_candidate<F: Family, const N: usize>(
    bitmap: &Shared<N>,
    floor: Location<F>,
    tip: u64,
) -> Option<Location<F>> {
    let floor = *floor;
    let bitmap_len = bitmap::Readable::<N>::len(bitmap);
    let committed_end = bitmap_len.min(tip);
    if floor < committed_end {
        if let Some(idx) = bitmap.next_one_from(floor) {
            if idx < committed_end {
                return Some(Location::new(idx));
            }
        }
    }
    let candidate = floor.max(bitmap_len);
    (candidate < tip).then(|| Location::new(candidate))
}

/// Resolve `loc` to an op within the in-memory ancestor region
/// `[db_size, ancestors[0].journal_batch.size())`, walked parent-first.
///
/// # Panics
///
/// Panics if `loc` cannot be located in the chain: either it falls outside the region (including
/// when `ancestors` is empty), or the ancestor spans are non-contiguous (a bookkeeping invariant
/// violation).
fn read_op_from_ancestors<F: Family, D: Digest, U: update::Update + Send + Sync, S: Strategy>(
    ancestors: &[Arc<MerkleizedBatch<F, D, U, S>>],
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

/// Read helpers on [`Merkleizer`].
///
/// # Operation-location model
///
/// The operation space is divided into three contiguous regions:
///
/// ```text
///  [0 ........... db_size)  [db_size ..... base_size)  [base_size .. base_size+len)
///   committed (on disk)     ancestors (in mem)          this batch (in mem)
/// ```
///
/// `db_size` is the boundary between disk and in-memory ancestors. It equals the original DB size
/// when the full ancestor chain is alive, or a higher value if ancestors were freed (see
/// `into_parts`). For batches created directly from the DB (no uncommitted ancestors), the ancestor
/// region is empty (`db_size == base_size`).
///
/// # Contract for all read methods
///
/// Callers must pass a `loc` that is a valid operation location: specifically `loc < base_size +
/// batch_ops.len()` (i.e., within one of the three regions). Passing an out-of-range `loc` may
/// panic (via `batch_ops` indexing or the ancestor-chain walk) or result in a disk-read error.
/// In-memory locations are resolved synchronously; only disk locations await the `reader`.
impl<F: Family, H, U, S: Strategy> Merkleizer<F, H, U, S>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Returns `Some(op)` if `loc` falls in the batch or ancestor regions, and `None` when `loc` is
    /// in the committed region (`loc < db_size`).
    fn try_read_op_from_uncommitted(
        &self,
        loc: Location<F>,
        batch_ops: &[Operation<F, U>],
    ) -> Option<Operation<F, U>> {
        let loc = *loc;

        if loc >= self.base_size {
            return Some(batch_ops[(loc - self.base_size) as usize].clone());
        }

        if loc >= self.db_size {
            return Some(read_op_from_ancestors(&self.ancestors, loc, self.db_size).clone());
        }

        None
    }

    /// Resolve an operation by its location `loc` if it can be done synchronously (e.g. without
    /// I/O), or return `None` otherwise.
    fn try_read_op_sync<R: Reader<Item = Operation<F, U>>>(
        &self,
        loc: Location<F>,
        batch_ops: &[Operation<F, U>],
        reader: &R,
    ) -> Option<Operation<F, U>> {
        self.try_read_op_from_uncommitted(loc, batch_ops)
            .or_else(|| reader.try_read_sync(*loc))
    }

    /// Read a single operation by location.
    async fn read_op<R: Reader<Item = Operation<F, U>>>(
        &self,
        loc: Location<F>,
        batch_ops: &[Operation<F, U>],
        reader: &R,
    ) -> Result<Operation<F, U>, crate::qmdb::Error<F>> {
        match self.try_read_op_sync(loc, batch_ops, reader) {
            Some(op) => Ok(op),
            None => Ok(reader.read(*loc).await?),
        }
    }

    /// Read multiple operations by location.
    async fn read_ops<R: Reader<Item = Operation<F, U>>>(
        &self,
        locations: &[Location<F>],
        batch_ops: &[Operation<F, U>],
        reader: &R,
    ) -> Result<Vec<Operation<F, U>>, crate::qmdb::Error<F>> {
        // Resolve hits synchronously: batch/ancestor first, then journal page cache.
        let results: Vec<Option<Operation<F, U>>> = locations
            .iter()
            .map(|loc| self.try_read_op_sync(*loc, batch_ops, reader))
            .collect();

        // Batch-read disk misses. Reader::read_many requires sorted, unique positions, while this
        // helper preserves the caller's order and permits duplicates.
        let misses: Vec<(usize, u64)> = locations
            .iter()
            .zip(results.iter())
            .enumerate()
            .filter_map(|(idx, (loc, cached))| cached.is_none().then_some((idx, **loc)))
            .collect();
        if misses.is_empty() {
            return Ok(results.into_iter().map(Option::unwrap).collect());
        }

        let mut miss_positions: Vec<u64> = misses.iter().map(|(_, loc)| *loc).collect();
        miss_positions.sort_unstable();
        miss_positions.dedup();

        let disk_results = reader.read_many(&miss_positions).await?;

        // Merge disk results back in order.
        let mut results = results;
        for (idx, loc) in misses {
            // `miss_positions` is sorted and deduped, and `loc` came from it before deduping, so
            // binary search must find the matching read_many result.
            let result_idx = miss_positions
                .binary_search(&loc)
                .expect("disk result missing for requested location");
            results[idx] = Some(disk_results[result_idx].clone());
        }
        Ok(results
            .into_iter()
            .map(|r| r.expect("operation should be resolved"))
            .collect())
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
    fn gather_existing_locations<E, C, I, const N: usize>(
        &self,
        mutations: &BTreeMap<U::Key, Option<U::Value>>,
        db: &Db<F, E, C, I, H, U, N, S>,
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
    fn is_active_at<E, C, I, const N: usize>(
        &self,
        key: &U::Key,
        loc: Location<F>,
        batch_diff: &DiffSlice<U::Key, F, U::Value>,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> bool
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let diff_entry = lookup_sorted(batch_diff, key);
        if let Some(entry) = diff_entry.or_else(|| resolve_in_ancestors(&self.ancestors, key)) {
            return entry.loc() == Some(loc);
        }
        db.snapshot.get(key).any(|&l| l == loc)
    }

    /// Extract keys that were deleted by a parent batch but are being
    /// re-created by this child batch. Removes those keys from `mutations`
    /// and returns `(key, value, base_old_loc)` entries.
    #[allow(clippy::type_complexity)]
    fn extract_parent_deleted_creates(
        &self,
        mutations: &mut BTreeMap<U::Key, Option<U::Value>>,
    ) -> Vec<(U::Key, U::Value, Option<Location<F>>)> {
        if self.ancestors.is_empty() {
            return Vec::new();
        }
        let mut creates = Vec::new();
        mutations.retain(|key, value| {
            if let Some(DiffEntry::Deleted { base_old_loc }) =
                resolve_in_ancestors(&self.ancestors, key)
            {
                if let Some(v) = value.take() {
                    creates.push((key.clone(), v, *base_old_loc));
                    return false;
                }
            }
            true
        });
        creates
    }

    /// Shared final phases of merkleization: floor raise, CommitFloor, journal
    /// merkleize, diff merge, and `MerkleizedBatch` construction.
    #[allow(clippy::too_many_arguments)]
    async fn finish<E, C, I, R, const N: usize>(
        self,
        mut ops: Vec<Operation<F, U>>,
        mut diff: DiffVec<U::Key, F, U::Value>,
        active_keys_delta: isize,
        user_steps: u64,
        metadata: Option<U::Value>,
        mut next_candidate: impl FnMut(Location<F>, u64) -> Option<Location<F>>,
        reader: R,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, U, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        R: Reader<Item = Operation<F, U>>,
    {
        // Floor raise.
        // Steps = user_steps + 1 (+1 for previous commit becoming inactive).
        let total_steps = user_steps + 1;
        let total_active_keys = self.base_active_keys as isize + active_keys_delta;
        let mut floor = self.base_inactivity_floor_loc;

        if total_active_keys > 0 {
            // Floor raise: advance the inactivity floor by `total_steps` active operations.
            // `fixed_tip` prevents scanning into floor-raise moves just appended.
            let fixed_tip = self.base_size + ops.len() as u64;
            let mut moved = 0u64;
            let mut scan_from = floor;
            let mut floor_diff = Vec::with_capacity(total_steps as usize);

            while moved < total_steps {
                // Collect candidates, capped by the number of active ops still needed.
                // `scan_from` tracks prefetch progress separately from `floor`, so
                // early exit cannot leave `floor` past unprocessed candidates.
                let limit = ((total_steps - moved) as usize).min(MAX_CONCURRENT_READS as usize);
                let mut candidates = Vec::with_capacity(limit);
                while candidates.len() < limit {
                    let Some(candidate) = next_candidate(scan_from, fixed_tip) else {
                        break;
                    };
                    candidates.push(candidate);
                    scan_from = Location::new(*candidate + 1);
                }
                if candidates.is_empty() {
                    break;
                }

                // Batch-read candidates: cache hits resolve synchronously, disk misses
                // are fetched concurrently.
                let resolved = self.read_ops(&candidates, &ops, &reader).await?;

                // Process results in order, moving active ops to the tip.
                for (candidate, op) in candidates.into_iter().zip(resolved) {
                    floor = Location::new(*candidate + 1);
                    let Some(key) = op.key().cloned() else {
                        continue; // skip CommitFloor and other non-keyed ops
                    };
                    // `is_active_at` is required even for set bits in the committed bitmap
                    // range: this batch's own diff or an uncommitted ancestor diff may
                    // supersede the committed location, and neither source is reflected in
                    // the bitmap.
                    if !self.is_active_at(&key, candidate, &diff, db) {
                        continue;
                    }
                    let new_loc = Location::new(self.base_size + ops.len() as u64);
                    let search = diff.binary_search_by(|(k, _)| k.cmp(&key));
                    let base_old_loc = match &search {
                        Ok(idx) => diff[*idx].1.base_old_loc(),
                        Err(_) => resolve_in_ancestors(&self.ancestors, &key)
                            .map_or(Some(candidate), DiffEntry::base_old_loc),
                    };
                    let value = extract_update_value(&op);
                    ops.push(op);

                    let new_entry = (
                        key,
                        DiffEntry::Active {
                            value,
                            loc: new_loc,
                            base_old_loc,
                        },
                    );
                    match search {
                        Ok(idx) => diff[idx] = new_entry,
                        Err(_) => floor_diff.push(new_entry),
                    }
                    moved += 1;
                    if moved >= total_steps {
                        break;
                    }
                }
            }
            if !floor_diff.is_empty() {
                // `floor_diff` only accumulates keys that were not already present in `diff`.
                // A key can only be moved once during this floor raise because, after it is
                // moved, its new location lies above `fixed_tip` and the scan never revisits it.
                diff.extend(floor_diff);
                diff.sort_by(|a, b| a.0.cmp(&b.0));
                debug_assert!(diff.is_sorted_by(|a, b| a.0 < b.0));
            }
        } else {
            // DB is empty after this batch; raise floor to tip.
            floor = Location::new(self.base_size + ops.len() as u64);
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        }

        // Release the reader guard before CPU-only work (merkleization) so
        // concurrent writers are not blocked.
        drop(reader);

        // CommitFloor operation.
        let commit_loc = Location::<F>::new(self.base_size + ops.len() as u64);
        ops.push(Operation::CommitFloor(metadata, floor));

        // Merkleize the journal batch.
        // The journal batch was created eagerly at batch construction time and its
        // parent already contains all prior batches' Merkle state, so we only
        // add THIS batch's operations. Parent operations are never re-cloned,
        // re-encoded, or re-hashed.
        let ops = Arc::new(ops);
        let leaves = Location::new(self.base_size + ops.len() as u64);
        let inactive_peaks = db.inactive_peaks(leaves, floor);
        let journal = db
            .log
            .with_mem(|base| self.journal_batch.merkleize_with(base, ops));
        let root = db
            .log
            .with_mem(|base| journal.root(base, &db.log.hasher, inactive_peaks))?;

        let ancestor_diffs: Vec<_> = self.ancestors.iter().map(|a| Arc::clone(&a.diff)).collect();
        let ancestors: Vec<_> = self
            .ancestors
            .iter()
            .map(|a| batch_chain::AncestorBounds {
                floor: a.bounds.inactivity_floor,
                end: a.bounds.total_size,
            })
            .collect();

        debug_assert!(total_active_keys >= 0, "active_keys underflow");
        Ok(Arc::new(MerkleizedBatch {
            journal_batch: journal,
            root,
            diff: Arc::new(diff),
            parent: self.ancestors.first().map(Arc::downgrade),
            total_active_keys: total_active_keys as usize,
            ancestor_diffs,
            bounds: batch_chain::Bounds {
                base_size: self.base_size,
                db_size: self.db_size,
                total_size: *commit_loc + 1,
                ancestors,
                inactivity_floor: floor,
            },
        }))
    }
}

impl<F: Family, H, U, S: Strategy> UnmerkleizedBatch<F, H, U, S>
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
    fn into_parts(self) -> (BTreeMap<U::Key, Option<U::Value>>, Merkleizer<F, H, U, S>) {
        let ancestors: Vec<_> = self.base.parent().map_or_else(Vec::new, |parent| {
            let mut v = vec![Arc::clone(parent)];
            v.extend(parent.ancestors());
            v
        });
        // If the Weak parent chain was truncated (an ancestor was committed and freed), the
        // oldest alive ancestor's items don't start at db_size. Example: chain A -> B -> C,
        // A committed and dropped. ancestors() yields [B] (A's Weak is dead). B's items start
        // at A.size(), not db_size. We use the journal (strong Arcs, always intact) to compute
        // the actual base so reads fall through to disk for locations in the gap.
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
impl<F: Family, H, U, S: Strategy> UnmerkleizedBatch<F, H, U, S>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Read through: mutations -> ancestor diffs -> committed DB.
    pub async fn get<E, C, I, const N: usize>(
        &self,
        key: &U::Key,
        db: &Db<F, E, C, I, H, U, N, S>,
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
            if let Some(entry) = lookup_sorted(parent.diff.as_slice(), key) {
                return Ok(entry.value().cloned());
            }
            for batch in parent.ancestors() {
                if let Some(entry) = lookup_sorted(batch.diff.as_slice(), key) {
                    return Ok(entry.value().cloned());
                }
            }
        }
        db.get(key).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, I, const N: usize>(
        &self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Vec<Option<U::Value>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut results: Vec<Option<U::Value>> = Vec::with_capacity(keys.len());
        let mut db_indices = Vec::new();
        let mut db_keys = Vec::new();

        for (i, key) in keys.iter().enumerate() {
            // Check local mutations.
            if let Some(value) = self.mutations.get(*key) {
                results.push(value.clone());
                continue;
            }

            // Check parent diff chain.
            let mut found = false;
            if let Some(parent) = self.base.parent() {
                if let Some(entry) = lookup_sorted(parent.diff.as_slice(), *key) {
                    results.push(entry.value().cloned());
                    found = true;
                }
                if !found {
                    for batch in parent.ancestors() {
                        if let Some(entry) = lookup_sorted(batch.diff.as_slice(), *key) {
                            results.push(entry.value().cloned());
                            found = true;
                            break;
                        }
                    }
                }
            }

            if found {
                continue;
            }

            // Need DB fallthrough.
            db_indices.push(i);
            db_keys.push(*key);
            results.push(None);
        }

        if !db_keys.is_empty() {
            let db_results = db.get_many(&db_keys).await?;
            for (slot, value) in db_indices.into_iter().zip(db_results) {
                results[slot] = value;
            }
        }

        Ok(results)
    }
}

// Unordered-specific methods.
impl<F: Family, K, V, H, S: Strategy> UnmerkleizedBatch<F, H, update::Unordered<K, V>, S>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb::any::batch::merkleize",
        level = "info",
        skip_all,
        fields(
            variant = "unordered",
            mutations = self.mutations.len() as u64,
        ),
    )]
    pub async fn merkleize<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        self.merkleize_with_floor_scan(db, metadata, |floor, tip| {
            next_candidate(&db.bitmap, floor, tip)
        })
        .await
    }

    /// Like [`merkleize`](Self::merkleize), but accepts the floor-raise candidate source.
    ///
    /// The callback may skip locations only when it knows they are inactive. The floor-raise
    /// loop revalidates each returned candidate via `is_active_at` because the bitmap reflects
    /// committed state only -- uncommitted ancestor ops aren't tracked, and bits can be set for
    /// locations superseded by an overlay in this chain.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        next_candidate: impl FnMut(Location<F>, u64) -> Option<Location<F>>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let (mut mutations, m) = self.into_parts();

        // Resolve existing keys.
        let locations = m.gather_existing_locations(&mutations, db, false);
        let reader = db.log.reader().await;
        let results = m.read_ops(&locations, &[], &reader).await?;

        // Generate user mutation operations.
        let mut ops: Vec<Operation<F, update::Unordered<K, V>>> =
            Vec::with_capacity(mutations.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> = Vec::with_capacity(mutations.len());
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
                    diff.push((
                        key.clone(),
                        DiffEntry::Active {
                            value,
                            loc: new_loc,
                            base_old_loc,
                        },
                    ));
                    user_steps += 1;
                }
                None => {
                    ops.push(Operation::Delete(key.clone()));
                    diff.push((key.clone(), DiffEntry::Deleted { base_old_loc }));
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
        for (key, value, base_old_loc) in parent_deleted_creates {
            creates.push((key, value, base_old_loc));
        }
        creates.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));
        for (key, value, base_old_loc) in creates {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            ops.push(Operation::Update(update::Unordered(
                key.clone(),
                value.clone(),
            )));
            diff.push((
                key,
                DiffEntry::Active {
                    value,
                    loc: new_loc,
                    base_old_loc,
                },
            ));
            active_keys_delta += 1;
        }

        diff.sort_by(|a, b| a.0.cmp(&b.0));

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(
            ops,
            diff,
            active_keys_delta,
            user_steps,
            metadata,
            next_candidate,
            reader,
            db,
        )
        .await
    }
}

// Ordered-specific methods.
impl<F: Family, K, V, H, S: Strategy> UnmerkleizedBatch<F, H, update::Ordered<K, V>, S>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb::any::batch::merkleize",
        level = "info",
        skip_all,
        fields(
            variant = "ordered",
            mutations = self.mutations.len() as u64,
        ),
    )]
    pub async fn merkleize<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        metadata: Option<V::Value>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        self.merkleize_with_floor_scan(db, metadata, |floor, tip| {
            next_candidate(&db.bitmap, floor, tip)
        })
        .await
    }

    /// Like [`merkleize`](Self::merkleize), but accepts the floor-raise candidate source.
    ///
    /// The callback may skip locations only when it knows they are inactive. The floor-raise
    /// loop revalidates each returned candidate via `is_active_at` because the bitmap reflects
    /// committed state only -- uncommitted ancestor ops aren't tracked, and bits can be set for
    /// locations superseded by an overlay in this chain.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        next_candidate: impl FnMut(Location<F>, u64) -> Option<Location<F>>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        let (mut mutations, m) = self.into_parts();

        // Resolve existing keys.
        let locations = m.gather_existing_locations(&mutations, db, true);
        let reader = db.log.reader().await;

        // Classify mutations into deleted, created, updated. `next_candidates` and
        // `prev_candidates` are built as unsorted `Vec`s here and sorted+deduped once below,
        // before `find_next_key` / `find_prev_key` binary-search them.
        let mut next_candidates: Vec<K> = Vec::new();
        let mut prev_candidates: PrevCandidates<K, F, V::Value> = Vec::new();
        let mut deleted: Vec<(K, Location<F>)> = Vec::new();
        let mut updated: Vec<(K, V::Value, Location<F>)> = Vec::new();

        for (op, &old_loc) in m
            .read_ops(&locations, &[], &reader)
            .await?
            .into_iter()
            .zip(&locations)
        {
            let update::Ordered {
                key,
                value,
                next_key,
            } = match op {
                Operation::Update(data) => data,
                _ => unreachable!("snapshot should only reference Update operations"),
            };
            next_candidates.push(next_key);

            let mutation = mutations.remove(&key);
            prev_candidates.push((key.clone(), (value, old_loc)));

            let Some(mutation) = mutation else {
                // Snapshot index collision: this operation's key does not match
                // the mutation key (the snapshot uses a compressed translated key
                // that can collide). The mutation will be handled as a create below.
                continue;
            };

            if let Some(new_value) = mutation {
                updated.push((key, new_value, old_loc));
            } else {
                deleted.push((key, old_loc));
            }
        }

        deleted.sort_by(|a, b| a.0.cmp(&b.0));
        updated.sort_by(|a, b| a.0.cmp(&b.0));

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
            next_candidates.push(key.clone());
            created.push((key, value, None));
        }
        for (key, value, base_old_loc) in parent_deleted_creates {
            next_candidates.push(key.clone());
            created.push((key, value, base_old_loc));
        }
        created.sort_by(|(a, _, _), (b, _, _)| a.cmp(b));

        // Look up prev_translated_key for created/deleted keys.
        let mut prev_locations = Vec::new();
        for key in deleted
            .iter()
            .map(|(k, _)| k)
            .chain(created.iter().map(|(k, _, _)| k))
        {
            let Some((iter, _)) = db.snapshot.prev_translated_key(key) else {
                continue;
            };
            prev_locations.extend(iter.copied());
        }
        prev_locations.sort();
        prev_locations.dedup();

        let prev_results = m.read_ops(&prev_locations, &[], &reader).await?;

        for (op, &old_loc) in prev_results.into_iter().zip(&prev_locations) {
            let data = match op {
                Operation::Update(data) => data,
                _ => unreachable!("expected update operation"),
            };
            next_candidates.push(data.next_key);
            prev_candidates.push((data.key, (data.value, old_loc)));
        }

        // Add ancestor-diff keys that may be predecessors or successors of this batch's mutations
        // but are invisible to the base-DB-only `prev_translated_key` lookup above.
        //
        // Walk ancestors closest-first; a set tracks keys already seen so each key is processed
        // only once (closest-ancestor's entry wins). We use AHashSet (keyed per-process via
        // runtime-rng) instead of std's default SipHash: ahash is DoS-resistant for adversarial
        // inputs but several times faster on 32-byte Digest keys, where SipHash dominates over
        // the actual probe.
        //
        // Depth-1 chains skip the set entirely — a single ancestor can't shadow itself,
        // and each diff's keys are unique by construction.
        let track_shadow = m.ancestors.len() > 1;
        let seen_cap = if track_shadow {
            m.ancestors.iter().map(|a| a.diff.len()).sum()
        } else {
            0
        };
        let mut seen: AHashSet<&K> = AHashSet::with_capacity(seen_cap);
        let mut ancestor_deleted: Vec<K> = Vec::new();
        for batch in m.ancestors.iter() {
            for (key, entry) in batch.diff.iter() {
                if track_shadow && !seen.insert(key) {
                    continue;
                }
                // Skip keys already handled by this batch's mutations.
                if updated.binary_search_by(|(k, _, _)| k.cmp(key)).is_ok()
                    || created.binary_search_by(|(k, _, _)| k.cmp(key)).is_ok()
                    || deleted.binary_search_by(|(k, _)| k.cmp(key)).is_ok()
                {
                    continue;
                }
                match entry {
                    DiffEntry::Active { value, loc, .. } => {
                        let op = m.read_op(*loc, &[], &reader).await?;
                        let data = match op {
                            Operation::Update(data) => data,
                            _ => unreachable!("ancestor diff Active should reference Update op"),
                        };
                        next_candidates.push(key.clone());
                        next_candidates.push(data.next_key);
                        prev_candidates.push((key.clone(), (value.clone(), *loc)));
                    }
                    DiffEntry::Deleted { .. } => {
                        ancestor_deleted.push(key.clone());
                    }
                }
            }
        }
        ancestor_deleted.sort();
        ancestor_deleted.dedup();

        // Sort + dedup candidate sets now so find_next_key/find_prev_key can binary-search.
        next_candidates.sort();
        next_candidates.dedup();
        // For `prev_candidates`, duplicates can occur when the same key is pushed from multiple
        // sources (main scan, prev_results, ancestor walk). Later pushes carry the freshest state
        // (ancestor walk runs last), so dedup keeps the LAST push per key. `dedup_by` retains the
        // first of each consecutive run; swap so the retained slot holds the later push.
        prev_candidates.sort_by(|a, b| a.0.cmp(&b.0));
        prev_candidates.dedup_by(|a, b| {
            if a.0 == b.0 {
                std::mem::swap(a, b);
                true
            } else {
                false
            }
        });

        // Remove all known-deleted keys from possible_* sets. The prev_translated_key lookup
        // already did this for this batch's deletes, but the ancestor diff incorporation may
        // have re-added them via next_key references. Also remove parent-deleted keys that the
        // base DB lookup may have added.
        let is_deleted = |k: &K| -> bool {
            deleted.binary_search_by(|(dk, _)| dk.cmp(k)).is_ok()
                || (ancestor_deleted.binary_search(k).is_ok()
                    && created.binary_search_by(|(ck, _, _)| ck.cmp(k)).is_err())
        };
        next_candidates.retain(|k| !is_deleted(k));
        prev_candidates.retain(|(k, _)| !is_deleted(k));

        // Generate operations.
        let mut ops: Vec<Operation<F, update::Ordered<K, V>>> =
            Vec::with_capacity(deleted.len() + updated.len() + created.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> =
            Vec::with_capacity(deleted.len() + updated.len() + created.len());
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;
        // Process deletes.
        for (key, old_loc) in &deleted {
            ops.push(Operation::Delete(key.clone()));

            let base_old_loc = resolve_in_ancestors(&m.ancestors, key)
                .map_or(Some(*old_loc), DiffEntry::base_old_loc);

            diff.push((key.clone(), DiffEntry::Deleted { base_old_loc }));
            active_keys_delta -= 1;
            user_steps += 1;
        }

        // Process updates of existing keys.
        for (key, value, old_loc) in &updated {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            let next_key = find_next_key(key, &next_candidates);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));

            let base_old_loc = resolve_in_ancestors(&m.ancestors, key)
                .map_or(Some(*old_loc), DiffEntry::base_old_loc);

            diff.push((
                key.clone(),
                DiffEntry::Active {
                    value: value.clone(),
                    loc: new_loc,
                    base_old_loc,
                },
            ));
            user_steps += 1;
        }

        // Process creates.
        for (key, value, base_old_loc) in &created {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            let next_key = find_next_key(key, &next_candidates);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));
            diff.push((
                key.clone(),
                DiffEntry::Active {
                    value: value.clone(),
                    loc: new_loc,
                    base_old_loc: *base_old_loc,
                },
            ));
            active_keys_delta += 1;
        }

        // Update predecessors of created and deleted keys.
        if !prev_candidates.is_empty() {
            // Safe to use a HashSet here since we don't rely on iteration order.
            let mut rewritten_predecessors = AHashSet::with_capacity(created.len() + deleted.len());
            for key in created
                .iter()
                .map(|(k, _, _)| k)
                .chain(deleted.iter().map(|(k, _)| k))
            {
                let (prev_key, (prev_value, prev_loc)) = find_prev_key(key, &prev_candidates);

                if deleted.binary_search_by(|(k, _)| k.cmp(prev_key)).is_ok()
                    || updated
                        .binary_search_by(|(k, _, _)| k.cmp(prev_key))
                        .is_ok()
                    || created
                        .binary_search_by(|(k, _, _)| k.cmp(prev_key))
                        .is_ok()
                {
                    continue;
                }

                if !rewritten_predecessors.insert(prev_key.clone()) {
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

                diff.push((
                    prev_key.clone(),
                    DiffEntry::Active {
                        value: prev_value.clone(),
                        loc: prev_new_loc,
                        base_old_loc: prev_base_old_loc,
                    },
                ));
                user_steps += 1;
            }
        }

        diff.sort_by(|a, b| a.0.cmp(&b.0));

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(
            ops,
            diff,
            active_keys_delta,
            user_steps,
            metadata,
            next_candidate,
            reader,
            db,
        )
        .await
    }
}

impl<F: Family, D: Digest, U: update::Update + Send + Sync, S: Strategy> MerkleizedBatch<F, D, U, S>
where
    Operation<F, U>: Send + Sync,
{
    /// Return the speculative root.
    pub const fn root(&self) -> D {
        self.root
    }

    /// Iterate over ancestor batches (parent first, then grandparent, etc.). Stops when a
    /// Weak ref fails to upgrade (ancestor was freed).
    pub(crate) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }
}

impl<F: Family, D: Digest, U: update::Update + Send + Sync, S: Strategy> MerkleizedBatch<F, D, U, S>
where
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this batch as its parent.
    ///
    /// All uncommitted ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Dropping an uncommitted ancestor causes data
    /// loss detected at `apply_batch` time.
    #[tracing::instrument(
        name = "qmdb::any::batch::new",
        level = "debug",
        skip_all,
        fields(
            source = "batch",
            base_size = self.bounds.base_size,
            total_size = self.bounds.total_size,
            ancestor_batches = self.ancestor_diffs.len() as u64,
        ),
    )]
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, U, S>
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
    pub async fn get<E, C, I, H, const N: usize>(
        &self,
        key: &U::Key,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Option<U::Value>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher<Digest = D>,
    {
        if let Some(entry) = lookup_sorted(self.diff.as_slice(), key) {
            return Ok(entry.value().cloned());
        }
        // Walk parent chain. If a parent was freed (committed and dropped), the iterator
        // stops and we fall through to DB.
        for batch in self.ancestors() {
            if let Some(entry) = lookup_sorted(batch.diff.as_slice(), key) {
                return Ok(entry.value().cloned());
            }
        }
        db.get(key).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many<E, C, I, H, const N: usize>(
        &self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Vec<Option<U::Value>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
        H: Hasher<Digest = D>,
    {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut results: Vec<Option<U::Value>> = Vec::with_capacity(keys.len());
        let mut db_indices = Vec::new();
        let mut db_keys = Vec::new();

        for (i, key) in keys.iter().enumerate() {
            // Check local diff.
            if let Some(entry) = lookup_sorted(self.diff.as_slice(), *key) {
                results.push(entry.value().cloned());
                continue;
            }

            // Walk parent chain.
            let mut found = false;
            for batch in self.ancestors() {
                if let Some(entry) = lookup_sorted(batch.diff.as_slice(), *key) {
                    results.push(entry.value().cloned());
                    found = true;
                    break;
                }
            }

            if found {
                continue;
            }

            // Need DB fallthrough.
            db_indices.push(i);
            db_keys.push(*key);
            results.push(None);
        }

        if !db_keys.is_empty() {
            let db_results = db.get_many(&db_keys).await?;
            for (slot, value) in db_indices.into_iter().zip(db_results) {
                results[slot] = value;
            }
        }

        Ok(results)
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Create a new speculative batch of operations with this database as its parent.
    #[tracing::instrument(
        name = "qmdb::any::batch::new",
        level = "debug",
        skip_all,
        fields(
            source = "db",
            base_size = *self.last_commit_loc + 1,
            inactivity_floor = *self.inactivity_floor_loc,
            active_keys = self.active_keys as u64,
        ),
    )]
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, U, S> {
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

impl<F, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    U: update::Update + Send + Sync + 'static,
    C: Mutable<Item = Operation<F, U>> + crate::Persistable<Error = crate::journal::Error>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
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
    #[tracing::instrument(
        name = "qmdb::any::Db::apply_batch",
        level = "info",
        skip_all,
        fields(
            batch_total_size = batch.bounds.total_size,
            batch_base_size = batch.bounds.base_size,
            db_size = *self.last_commit_loc + 1,
            ancestor_batches = batch.ancestor_diffs.len() as u64,
        ),
    )]
    pub async fn apply_batch(
        &mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, U, S>>,
    ) -> Result<Range<Location<F>>, crate::qmdb::Error<F>> {
        let _timer = self.metrics.operations.apply_batch_timer();
        self.metrics.operations.apply_batch_calls.inc();
        let db_size = *self.last_commit_loc + 1;
        batch
            .bounds
            .validate_apply_to(db_size, self.inactivity_floor_loc)?;
        let start_loc = Location::new(db_size);

        // Apply journal (handles its own partial ancestor skipping).
        self.log.apply_batch(&batch.journal_batch).await?;

        // Scoped so the bitmap guard drops before later `.await`s (guard is `!Send`).
        {
            let mut bitmap = self.bitmap.write();
            bitmap.extend_to(batch.bounds.total_size);

            if batch.ancestor_diffs.is_empty() {
                // Fast path: no ancestors to merge, no fixups to look up.
                for (key, entry) in batch.diff.iter() {
                    apply_diff(
                        &mut self.snapshot,
                        &mut bitmap,
                        key,
                        entry,
                        entry.base_old_loc(),
                    );
                }
            } else {
                // Partition ancestor diffs into already-applied (provide `base_old_loc` fixups)
                // and pending (still to be applied; merged with the child).
                let mut applied = Vec::with_capacity(batch.ancestor_diffs.len());
                let mut pending = Vec::with_capacity(batch.ancestor_diffs.len());
                for (i, ancestor_diff) in batch.ancestor_diffs.iter().enumerate() {
                    if batch.bounds.ancestors[i].end <= db_size {
                        applied.push(ancestor_diff.as_slice());
                    } else {
                        pending.push(ancestor_diff.as_slice());
                    }
                }
                let mut resolver = AppliedAncestorResolver::new(applied);
                let merge = DiffMerge::new(
                    iter::once(batch.diff.as_slice()).chain(pending.iter().copied()),
                );
                for (key, entry) in merge {
                    let old = resolver.lookup(key).unwrap_or_else(|| entry.base_old_loc());
                    apply_diff(&mut self.snapshot, &mut bitmap, key, entry, old);
                }
            }

            // CommitFloor: bit = 1 only on the current last commit. Demote the previous and
            // set the new; earlier ancestor commits between them are already 0 from
            // `extend_to`.
            bitmap.set_bit(*self.last_commit_loc, false);
            bitmap.set_bit(batch.bounds.total_size - 1, true);
        }

        // Update DB metadata.
        self.active_keys = batch.total_active_keys;
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        self.last_commit_loc = Location::new(batch.bounds.total_size - 1);
        self.root = batch.root;

        // Return range of operations that were written to the log.
        let end_loc = Location::new(*self.last_commit_loc + 1);
        let range = start_loc..end_loc;
        self.update_metrics().await;
        self.metrics
            .operations
            .operations_applied
            .inc_by(*range.end - *range.start);
        Ok(range)
    }
}

impl<F: Family, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    E: Context,
    U: update::Update + Send + Sync,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    ///
    /// This is the starting point for building owned batch chains.
    #[tracing::instrument(
        name = "qmdb::any::Db::to_batch",
        level = "info",
        skip_all,
        fields(
            db_size = *self.last_commit_loc + 1,
            inactivity_floor = *self.inactivity_floor_loc,
            active_keys = self.active_keys as u64,
        ),
    )]
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, U, S>> {
        // The DB is always committed, so journal size = last_commit_loc + 1.
        let journal_size = *self.last_commit_loc + 1;
        Arc::new(MerkleizedBatch {
            journal_batch: self.log.to_merkleized_batch(),
            root: self.root,
            diff: Arc::new(Vec::new()),
            parent: None,
            total_active_keys: self.active_keys,
            ancestor_diffs: Vec::new(),
            bounds: batch_chain::Bounds {
                base_size: journal_size,
                db_size: journal_size,
                total_size: journal_size,
                ancestors: Vec::new(),
                inactivity_floor: self.inactivity_floor_loc,
            },
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

    impl<F, K, V, H, E, C, I, const N: usize, S>
        UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Unordered<K, V>, N, S>>
        for UnmerkleizedBatch<F, H, update::Unordered<K, V>, S>
    where
        F: Family,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
        S: Strategy,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata)
        }
    }

    impl<F, K, V, H, E, C, I, const N: usize, S>
        UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Ordered<K, V>, N, S>>
        for UnmerkleizedBatch<F, H, update::Ordered<K, V>, S>
    where
        F: Family,
        K: Key,
        V: ValueEncoding + 'static,
        H: Hasher,
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
        S: Strategy,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Metadata = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>;

        fn write(mut self, key: K, value: Option<V::Value>) -> Self {
            self.mutations.insert(key, value);
            self
        }

        fn merkleize(
            self,
            db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
            metadata: Option<V::Value>,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata)
        }
    }

    impl<F: Family, D: Digest, U: update::Update + Send + Sync + 'static, S: Strategy>
        MerkleizedBatchTrait for Arc<MerkleizedBatch<F, D, U, S>>
    where
        Operation<F, U>: Codec,
    {
        type Digest = D;

        fn root(&self) -> D {
            MerkleizedBatch::root(self)
        }
    }

    impl<F, E, K, V, C, I, H, const N: usize, S> BatchableDb
        for Db<F, E, C, I, H, update::Unordered<K, V>, N, S>
    where
        F: Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>
            + crate::Persistable<Error = crate::journal::Error>,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher,
        S: Strategy,
        Operation<F, update::Unordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>;
        type Batch = UnmerkleizedBatch<F, H, update::Unordered<K, V>, S>;

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

    impl<F, E, K, V, C, I, H, const N: usize, S> BatchableDb
        for Db<F, E, C, I, H, update::Ordered<K, V>, N, S>
    where
        F: Family,
        E: Context,
        K: Key,
        V: ValueEncoding + 'static,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>
            + crate::Persistable<Error = crate::journal::Error>,
        I: OrderedIndex<Value = Location<F>>,
        H: Hasher,
        S: Strategy,
        Operation<F, update::Ordered<K, V>>: Codec,
    {
        type Family = F;
        type K = K;
        type V = V::Value;
        type Merkleized = Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>;
        type Batch = UnmerkleizedBatch<F, H, update::Ordered<K, V>, S>;

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
            BITMAP_CHUNK_BYTES,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{sha256, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner as _};

    const BITMAP_CHUNK_BITS: u64 = bitmap::Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS;

    fn loc(n: u64) -> Location<mmr::Family> {
        Location::new(n)
    }

    fn shared_with<F>(build: F) -> Shared<BITMAP_CHUNK_BYTES>
    where
        F: FnOnce(&mut bitmap::Prunable<BITMAP_CHUNK_BYTES>),
    {
        let mut bm = bitmap::Prunable::<BITMAP_CHUNK_BYTES>::new();
        build(&mut bm);
        Shared::new(bm)
    }

    fn active(value: u64, location: u64) -> DiffEntry<mmr::Family, u64> {
        DiffEntry::Active {
            value,
            loc: loc(location),
            base_old_loc: None,
        }
    }

    fn deleted(base_old_loc: Option<u64>) -> DiffEntry<mmr::Family, u64> {
        DiffEntry::Deleted {
            base_old_loc: base_old_loc.map(loc),
        }
    }

    #[test]
    fn diff_merge_returns_sorted_newest_entries() {
        let child = vec![(2, active(20, 20)), (5, active(50, 50))];
        let parent = vec![
            (1, active(11, 11)),
            (2, active(12, 12)),
            (4, deleted(Some(4))),
            (7, active(17, 17)),
        ];
        let grandparent = vec![
            (2, active(102, 102)),
            (3, active(103, 103)),
            (4, active(104, 104)),
            (6, active(106, 106)),
        ];

        // Streams are priority ordered: child, parent, then grandparent. Equal keys should
        // yield only the newest entry while preserving ascending key order for resolver lookups.
        let merged: Vec<_> =
            DiffMerge::new([child.as_slice(), parent.as_slice(), grandparent.as_slice()])
                .map(|(key, entry)| (*key, entry.value().copied(), entry.loc()))
                .collect();

        assert_eq!(
            merged,
            vec![
                (1, Some(11), Some(loc(11))),
                (2, Some(20), Some(loc(20))),
                (3, Some(103), Some(loc(103))),
                (4, None, None),
                (5, Some(50), Some(loc(50))),
                (6, Some(106), Some(loc(106))),
                (7, Some(17), Some(loc(17))),
            ]
        );
    }

    #[test]
    fn applied_ancestor_resolver_uses_nearest_touch() {
        let parent = vec![(2, active(20, 20)), (5, deleted(Some(5)))];
        let grandparent = vec![
            (2, active(200, 200)),
            (4, active(40, 40)),
            (5, active(50, 50)),
        ];
        let mut resolver =
            AppliedAncestorResolver::new([parent.as_slice(), grandparent.as_slice()]);

        // Lookups are issued in ascending order, as they are from DiffMerge in apply_batch.
        assert_eq!(resolver.lookup(&1), None);
        assert_eq!(resolver.lookup(&2), Some(Some(loc(20))));
        assert_eq!(resolver.lookup(&4), Some(Some(loc(40))));
        assert_eq!(resolver.lookup(&5), Some(None));
        assert_eq!(resolver.lookup(&9), None);
    }

    #[test]
    fn bitmap_scan_empty() {
        let bitmap = shared_with(|_| {});
        assert_eq!(next_candidate(&bitmap, loc(0), 0), None);
    }

    #[test]
    fn bitmap_scan_uncommitted_tail() {
        let bitmap = shared_with(|_| {});
        assert_eq!(next_candidate(&bitmap, loc(0), 3), Some(loc(0)));
        assert_eq!(next_candidate(&bitmap, loc(1), 3), Some(loc(1)));
        assert_eq!(next_candidate(&bitmap, loc(2), 3), Some(loc(2)));
        assert_eq!(next_candidate(&bitmap, loc(3), 3), None);
    }

    #[test]
    fn bitmap_scan_committed_region() {
        let bitmap = shared_with(|bm| {
            bm.extend_to(10);
            bm.set_bit(*loc(3), true);
            bm.set_bit(*loc(7), true);
        });

        assert_eq!(next_candidate(&bitmap, loc(0), 10), Some(loc(3)));
        assert_eq!(next_candidate(&bitmap, loc(4), 10), Some(loc(7)));
        assert_eq!(next_candidate(&bitmap, loc(8), 10), None);
        assert_eq!(next_candidate(&bitmap, loc(0), 5), Some(loc(3)));
        assert_eq!(next_candidate(&bitmap, loc(4), 5), None);
    }

    #[test]
    fn bitmap_scan_transitions_into_tail() {
        let bitmap = shared_with(|bm| {
            bm.extend_to(5);
            bm.set_bit(*loc(2), true);
        });

        assert_eq!(next_candidate(&bitmap, loc(0), 8), Some(loc(2)));
        assert_eq!(next_candidate(&bitmap, loc(3), 8), Some(loc(5)));
        assert_eq!(next_candidate(&bitmap, loc(6), 8), Some(loc(6)));
        assert_eq!(next_candidate(&bitmap, loc(8), 8), None);
    }

    #[test]
    fn bitmap_scan_after_prune() {
        let bitmap = shared_with(|bm| {
            bm.extend_to(BITMAP_CHUNK_BITS * 3);
            bm.set_bit(*loc(BITMAP_CHUNK_BITS * 2 + 5), true);
            bm.prune_to_bit(BITMAP_CHUNK_BITS * 2);
        });

        assert_eq!(
            commonware_utils::bitmap::Readable::pruned_chunks(&bitmap),
            2
        );
        assert_eq!(
            next_candidate(&bitmap, loc(BITMAP_CHUNK_BITS * 2), BITMAP_CHUNK_BITS * 3),
            Some(loc(BITMAP_CHUNK_BITS * 2 + 5))
        );
    }

    #[test]
    fn bitmap_scan_after_truncate() {
        let bitmap = shared_with(|bm| {
            bm.extend_to(BITMAP_CHUNK_BITS * 2);
            bm.set_bit(*loc(BITMAP_CHUNK_BITS + 3), true);
            bm.truncate(BITMAP_CHUNK_BITS);
        });

        assert_eq!(
            commonware_utils::bitmap::Readable::<BITMAP_CHUNK_BYTES>::len(&bitmap),
            BITMAP_CHUNK_BITS
        );
        assert_eq!(next_candidate(&bitmap, loc(0), BITMAP_CHUNK_BITS), None);
    }

    /// Test helper: same logic as `Merkleizer::extract_parent_deleted_creates`
    /// but without requiring a full Merkleizer instance.
    fn extract_parent_deleted_creates<K: Ord + Clone, V: Clone>(
        mutations: &mut BTreeMap<K, Option<V>>,
        base_diff: &[(K, DiffEntry<mmr::Family, V>)],
    ) -> Vec<(K, V, Option<crate::mmr::Location>)> {
        let creates: Vec<_> = mutations
            .iter()
            .filter_map(|(key, value)| {
                if let Some(DiffEntry::Deleted { base_old_loc }) = lookup_sorted(base_diff, key) {
                    if let Some(value) = value {
                        return Some((key.clone(), value.clone(), *base_old_loc));
                    }
                }
                None
            })
            .collect();
        for (key, _, _) in &creates {
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

        let mut base_diff: Vec<(u64, DiffEntry<mmr::Family, u64>)> = vec![
            (
                1,
                DiffEntry::Deleted {
                    base_old_loc: Some(crate::mmr::Location::new(5)),
                },
            ),
            (
                4,
                DiffEntry::Active {
                    value: 400,
                    loc: crate::mmr::Location::new(10),
                    base_old_loc: None,
                },
            ),
        ];
        base_diff.sort_by_key(|a| a.0);

        let creates = extract_parent_deleted_creates(&mut mutations, &base_diff);

        // key1 extracted: value=100, base_old_loc=Some(5)
        assert_eq!(creates.len(), 1);
        let (key, value, base_old_loc) = creates.first().unwrap();
        assert_eq!(*key, 1);
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

        let base_diff: Vec<(u64, DiffEntry<mmr::Family, u64>)> = vec![(
            1,
            DiffEntry::Deleted {
                base_old_loc: Some(crate::mmr::Location::new(5)),
            },
        )];

        let creates = extract_parent_deleted_creates(&mut mutations, &base_diff);

        // Delete of a deleted key is not a create.
        assert!(creates.is_empty());
        // Mutation unchanged.
        assert_eq!(mutations.len(), 1);
        assert!(mutations.contains_key(&1));
    }

    #[test]
    fn apply_batch_merges_committed_and_uncommitted_overlaps() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;

            let config = fixed_db_config::<OneCap>("mixed-ancestor-overlaps", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            let key_update = Sha256::hash(b"update-through-all-layers");
            let key_recreate_then_delete = Sha256::hash(b"recreate-then-delete");
            let key_delete_from_uncommitted = Sha256::hash(b"delete-from-uncommitted");
            let key_uncommitted_create = Sha256::hash(b"uncommitted-create");

            let seed = db
                .new_batch()
                .write(key_update, Some(Sha256::hash(b"seed-update")))
                .write(
                    key_recreate_then_delete,
                    Some(Sha256::hash(b"seed-recreate")),
                )
                .write(
                    key_delete_from_uncommitted,
                    Some(Sha256::hash(b"seed-delete")),
                )
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();

            let applied = db
                .new_batch()
                .write(key_update, Some(Sha256::hash(b"committed-update")))
                .write(key_recreate_then_delete, None)
                .write(
                    key_delete_from_uncommitted,
                    Some(Sha256::hash(b"committed-delete-base")),
                )
                .merkleize(&db, None)
                .await
                .unwrap();

            let pending = applied
                .new_batch::<Sha256>()
                .write(key_update, Some(Sha256::hash(b"uncommitted-update")))
                .write(
                    key_recreate_then_delete,
                    Some(Sha256::hash(b"uncommitted-recreate")),
                )
                .write(key_delete_from_uncommitted, None)
                .write(
                    key_uncommitted_create,
                    Some(Sha256::hash(b"uncommitted-create")),
                )
                .merkleize(&db, None)
                .await
                .unwrap();

            let final_update = Sha256::hash(b"child-update");
            let child = pending
                .new_batch::<Sha256>()
                .write(key_update, Some(final_update))
                .write(key_recreate_then_delete, None)
                .merkleize(&db, None)
                .await
                .unwrap();
            let expected_root = child.root();

            // Apply only the first ancestor. Applying the child must combine applied
            // fixups from that ancestor with the still-pending parent diff.
            db.apply_batch(applied).await.unwrap();
            db.apply_batch(child).await.unwrap();

            assert_eq!(db.root(), expected_root);
            assert_eq!(db.get(&key_update).await.unwrap(), Some(final_update));
            assert_eq!(db.get(&key_recreate_then_delete).await.unwrap(), None);
            assert_eq!(db.get(&key_delete_from_uncommitted).await.unwrap(), None);
            assert_eq!(
                db.get(&key_uncommitted_create).await.unwrap(),
                Some(Sha256::hash(b"uncommitted-create"))
            );

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn read_ops_resolves_committed_ancestor_and_current_sources() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;

            let config = fixed_db_config::<OneCap>("read-locations-all-sources", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            let key_db = colliding_digest(0x30, 0);
            let value_db = colliding_digest(0x30, 1);
            let key_parent = colliding_digest(0x31, 0);
            let value_parent = colliding_digest(0x31, 1);
            let key_current = colliding_digest(0x32, 0);
            let value_current = colliding_digest(0x32, 1);

            // Commit one key to the DB so it's on disk.
            let seed = db
                .new_batch()
                .write(key_db, Some(value_db))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            let committed_loc = db.snapshot.get(&key_db).next().copied().unwrap();

            // Create a parent batch with a second key (in-memory ancestor).
            let parent = db
                .new_batch()
                .write(key_parent, Some(value_parent))
                .merkleize(&db, None)
                .await
                .unwrap();
            let parent_loc = lookup_sorted(parent.diff.as_slice(), &key_parent)
                .unwrap()
                .loc()
                .unwrap();

            // Create a child batch with a third key (current ops).
            let child = parent
                .new_batch::<Sha256>()
                .write(key_current, Some(value_current));
            let (_mutations, merkleizer) = child.into_parts();

            let current_loc = Location::new(merkleizer.base_size);
            let batch_ops = vec![Operation::Update(update::Unordered(
                key_current,
                value_current,
            ))];

            // read_ops should resolve all three sources correctly while preserving order and
            // duplicates across the disk-backed subset.
            let reader = db.log.reader().await;
            let ops = merkleizer
                .read_ops(
                    &[current_loc, committed_loc, parent_loc, committed_loc],
                    &batch_ops,
                    &reader,
                )
                .await
                .unwrap();
            drop(reader);

            assert_eq!(
                ops,
                vec![
                    Operation::Update(update::Unordered(key_current, value_current)),
                    Operation::Update(update::Unordered(key_db, value_db)),
                    Operation::Update(update::Unordered(key_parent, value_parent)),
                    Operation::Update(update::Unordered(key_db, value_db)),
                ]
            );

            // read_op: single-location reads across all three sources.
            let reader = db.log.reader().await;
            let disk_op = merkleizer
                .read_op(committed_loc, &batch_ops, &reader)
                .await
                .unwrap();
            assert_eq!(
                disk_op,
                Operation::Update(update::Unordered(key_db, value_db))
            );

            let ancestor_op = merkleizer
                .read_op(parent_loc, &batch_ops, &reader)
                .await
                .unwrap();
            assert_eq!(
                ancestor_op,
                Operation::Update(update::Unordered(key_parent, value_parent))
            );

            let current_op = merkleizer
                .read_op(current_loc, &batch_ops, &reader)
                .await
                .unwrap();
            assert_eq!(
                current_op,
                Operation::Update(update::Unordered(key_current, value_current))
            );
            drop(reader);

            db.destroy().await.unwrap();
        });
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
                Sequential,
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
                !parent.diff.iter().any(|(k, _)| k == &key_b),
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
                Sequential,
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
                !parent.diff.iter().any(|(k, _)| k == &key_b),
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
                Sequential,
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
                Sequential,
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
            let a_entry = lookup_sorted(batch_a.diff.as_slice(), &key).unwrap();
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
                Sequential,
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
                Sequential,
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
                Sequential,
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

    #[test]
    fn get_many_resolves_mutation_parent_and_db() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;

            let config = fixed_db_config::<OneCap>("get-many-basic", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            let key_db = colliding_digest(0x40, 0);
            let val_db = colliding_digest(0x40, 1);
            let key_parent = colliding_digest(0x41, 0);
            let val_parent = colliding_digest(0x41, 1);
            let key_batch = colliding_digest(0x42, 0);
            let val_batch = colliding_digest(0x42, 1);
            let key_missing = colliding_digest(0x43, 0);

            // Commit one key to disk.
            let seed = db
                .new_batch()
                .write(key_db, Some(val_db))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            // DB-level get_many.
            let results = db.get_many(&[&key_db, &key_missing]).await.unwrap();
            assert_eq!(results, vec![Some(val_db), None]);

            // Unmerkleized batch: mutation + DB fallthrough.
            let batch = db.new_batch().write(key_batch, Some(val_batch));
            let results = batch
                .get_many(&[&key_batch, &key_db, &key_missing], &db)
                .await
                .unwrap();
            assert_eq!(results, vec![Some(val_batch), Some(val_db), None]);

            // Merkleized parent + child unmerkleized batch.
            let parent = db
                .new_batch()
                .write(key_parent, Some(val_parent))
                .merkleize(&db, None)
                .await
                .unwrap();

            let child = parent
                .new_batch::<Sha256>()
                .write(key_batch, Some(val_batch));
            let results = child
                .get_many(&[&key_batch, &key_parent, &key_db, &key_missing], &db)
                .await
                .unwrap();
            assert_eq!(
                results,
                vec![Some(val_batch), Some(val_parent), Some(val_db), None]
            );

            // Merkleized batch get_many.
            let results = parent
                .get_many(&[&key_parent, &key_db, &key_missing], &db)
                .await
                .unwrap();
            assert_eq!(results, vec![Some(val_parent), Some(val_db), None]);

            // Empty input.
            let results: Vec<Option<sha256::Digest>> =
                db.get_many(&([] as [&sha256::Digest; 0])).await.unwrap();
            assert!(results.is_empty());

            db.destroy().await.unwrap();
        });
    }
}
