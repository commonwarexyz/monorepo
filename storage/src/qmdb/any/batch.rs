//! Batch mutation API for Any QMDBs.

use crate::{
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable},
    },
    merkle::{Family, Location},
    qmdb::{
        any::{
            db::Db,
            operation::{update, Operation},
            ordered::{find_next_key, find_next_key_ascending, find_prev_key},
            ValueEncoding,
        },
        batch_chain::{self, Bounds},
        bitmap::Shared,
        delete_known_loc,
        operation::{Key, Operation as OperationTrait},
        update_known_loc,
    },
    Context,
};
use ahash::{AHashMap, AHashSet};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::bitmap;
use core::{cmp::Ordering, ops::Range};
use std::{
    collections::BTreeMap,
    iter,
    sync::{Arc, Weak},
};
use tracing::debug;

type DiffVec<K, F, V> = Vec<(K, DiffEntry<F, V>)>;
type DiffSlice<K, F, V> = [(K, DiffEntry<F, V>)];

/// One contiguous chunk of floor-raise candidates paired with their resolved operations.
type CandidateChunk<'a, F, U> = (&'a [Location<F>], &'a [Operation<F, U>]);

/// Sorted `(key, (value, loc))` vec consulted by `find_prev_key` to find the predecessor
/// of a given key during ordered merkleization. The value is `None` for staged-resolved
/// keys: the predecessor-rewrite loop only reads a value for keys outside this batch's
/// mutations, and staged-resolved keys are always in `updated`.
type PrevCandidates<K, F, V> = Vec<(K, (Option<V>, Location<F>))>;

type StagedUpdate<F, U> = (
    <U as update::Update>::Key,
    Location<F>,
    <U as update::Update>::Cached,
    Option<<U as update::Update>::Value>,
);

/// Pending mutations whose old committed location was already resolved by a staged read. The
/// value is `Some` for an update and `None` for a delete; only the unordered path stages deletes
/// (the ordered path cannot skip the deleted key's predecessor-bucket scan, so its deletes fall
/// back to normal mutations).
pub(crate) struct StagedUpdates<F: Family, U: update::Update> {
    entries: Vec<StagedUpdate<F, U>>,
}

impl<F: Family, U: update::Update> StagedUpdates<F, U> {
    pub(crate) const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

/// Committed locations resolved by staged reads, keyed by staged read slot.
struct StagedCache<F: Family, U: update::Update> {
    cached: Vec<(usize, Location<F>, U::Cached)>,
}

/// Staged batch returned by [`UnmerkleizedBatch::stage`].
///
/// Owns the batch and the locations its reads resolved, so the staged reads cannot be paired with a
/// different batch.
pub struct Staged<F: Family, H, U: update::Update, S: Strategy>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    batch: UnmerkleizedBatch<F, H, U, S>,
    keys: Vec<U::Key>,
    cache: StagedCache<F, U>,
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

/// Outcome of classifying one floor-raise candidate against the batch diff, ancestor
/// diffs, and committed snapshot.
///
/// Classification is a pure function of the pre-raise state: at most one candidate per key
/// can be active (the bitmap holds exactly one set bit per committed key, and each diff or
/// ancestor entry resolves a key to a single location), and a move only rewrites the moved
/// key's own diff entry to a location above the scan tip. Classifying all candidates
/// against a single snapshot of the diff therefore yields the same outcomes as the
/// interleaved sequential walk, which lets the per-candidate work run sharded across the
/// strategy pool.
enum FloorOutcome<F: Family> {
    /// Not the active op for its key (or not a keyed op); leave in place.
    Inactive,
    /// Active with an existing diff entry at this index; move and rewrite it in place.
    MoveExisting {
        idx: usize,
        base_old_loc: Option<Location<F>>,
    },
    /// Active with no diff entry; move and stage a new entry.
    MoveNew { base_old_loc: Option<Location<F>> },
}

/// Streaming equivalent of [`resolve_in_ancestors`] for an ascending sequence of queries:
/// one cursor per key-sorted diff advances in a linear merge instead of binary-searching
/// each diff per key. Diffs must be ordered closest-first (the first hit wins).
pub(crate) struct DiffCursors<'a, K, F: Family, V> {
    diffs: Vec<(&'a DiffSlice<K, F, V>, usize)>,
}

impl<'a, K: Ord, F: Family, V> DiffCursors<'a, K, F, V> {
    pub(crate) fn new(diffs: impl IntoIterator<Item = &'a DiffSlice<K, F, V>>) -> Self {
        Self {
            diffs: diffs.into_iter().map(|diff| (diff, 0)).collect(),
        }
    }

    /// Resolve `key` against the diffs (closest-first). Queries must be non-decreasing:
    /// cursors only advance, so an out-of-order query could miss entries.
    ///
    /// # Panics
    ///
    /// Panics on any out-of-order query that would return a wrong result (the cursor has
    /// already advanced past an entry at or above the query).
    pub(crate) fn resolve(&mut self, key: &K) -> Option<&'a DiffEntry<F, V>> {
        for (diff, cursor) in &mut self.diffs {
            assert!(
                *cursor == 0 || diff[*cursor - 1].0 < *key,
                "queries must be non-decreasing"
            );
            while *cursor < diff.len() && diff[*cursor].0 < *key {
                *cursor += 1;
            }
            if let Some((k, entry)) = diff.get(*cursor) {
                if k == key {
                    return Some(entry);
                }
            }
        }
        None
    }
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

    fn peek_key(cursor: &(&'a DiffSlice<K, F, V>, usize)) -> Option<&'a K> {
        cursor.0.get(cursor.1).map(|(k, _)| k)
    }

    fn next_general(&mut self) -> Option<(&'a K, &'a DiffEntry<F, V>)> {
        let n = self.cursors.len();
        let mut winner: Option<usize> = None;
        for level in 0..n {
            let Some(k) = Self::peek_key(&self.cursors[level]) else {
                continue;
            };
            let better = match winner {
                None => true,
                Some(w) => *k < *Self::peek_key(&self.cursors[w]).unwrap(),
            };
            if better {
                winner = Some(level);
            }
        }
        let level = winner?;
        let (slice, pos) = self.cursors[level];
        let winning_key = &slice[pos].0;
        for cursor in &mut self.cursors {
            if Self::peek_key(cursor).is_some_and(|k| k == winning_key) {
                cursor.1 += 1;
            }
        }
        Some((&slice[pos].0, &slice[pos].1))
    }
}

impl<'a, K: Ord, F: Family, V> Iterator for DiffMerge<'a, K, F, V> {
    type Item = (&'a K, &'a DiffEntry<F, V>);

    fn next(&mut self) -> Option<Self::Item> {
        match self.cursors.len() {
            0 => None,
            1 => {
                let (slice, pos) = &mut self.cursors[0];
                let (k, entry) = slice.get(*pos)?;
                *pos += 1;
                Some((k, entry))
            }
            2 => {
                let ka = Self::peek_key(&self.cursors[0]);
                let kb = Self::peek_key(&self.cursors[1]);
                let winner = match (ka, kb) {
                    (Some(a), Some(b)) => match a.cmp(b) {
                        Ordering::Less => 0,
                        Ordering::Greater => 1,
                        Ordering::Equal => {
                            self.cursors[1].1 += 1;
                            0
                        }
                    },
                    (Some(_), None) => 0,
                    (None, Some(_)) => 1,
                    (None, None) => return None,
                };
                let (slice, pos) = &mut self.cursors[winner];
                let (k, entry) = &slice[*pos];
                *pos += 1;
                Some((k, entry))
            }
            _ => self.next_general(),
        }
    }
}

/// Fill `out` with up to `limit` floor-raise candidates in `[floor, tip)` under a single bitmap
/// read guard, returning the next `floor`.
fn fill_candidates<F: Family, const N: usize>(
    bitmap: &Shared<N>,
    floor: Location<F>,
    tip: u64,
    limit: usize,
    out: &mut Vec<Location<F>>,
) -> Location<F> {
    let mut raw: Vec<u64> = Vec::with_capacity(limit);
    let next = bitmap.fill_candidates(*floor, tip, limit, &mut raw);
    out.extend(raw.into_iter().map(Location::new));
    Location::new(next)
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

    /// Read multiple operations by location, preserving the caller's order and permitting
    /// duplicates.
    ///
    /// Batch and ancestor regions resolve in memory. All committed locations are served by
    /// one batched read, which serves page-cache hits under a single lock acquisition per
    /// section instead of paying a cache lock acquisition per location.
    async fn read_ops<R: Contiguous<Item = Operation<F, U>>>(
        &self,
        locations: &[Location<F>],
        batch_ops: &[Operation<F, U>],
        reader: &R,
    ) -> Result<Vec<Operation<F, U>>, crate::qmdb::Error<F>> {
        // Resolve the in-memory regions synchronously.
        let mut results: Vec<Option<Operation<F, U>>> = locations
            .iter()
            .map(|loc| self.try_read_op_from_uncommitted(*loc, batch_ops))
            .collect();

        // Batch-read committed locations. Reader::read_many requires sorted, unique positions.
        let committed: Vec<(usize, u64)> = locations
            .iter()
            .zip(results.iter())
            .enumerate()
            .filter_map(|(idx, (loc, resolved))| resolved.is_none().then_some((idx, **loc)))
            .collect();
        if committed.is_empty() {
            return Ok(results.into_iter().map(Option::unwrap).collect());
        }

        // The common callers (floor-raise candidates and depth-0 mutation reads) pass
        // sorted, unique locations, so sorting is usually a no-op worth skipping.
        let mut positions: Vec<u64> = committed.iter().map(|(_, loc)| *loc).collect();
        let presorted = positions.is_sorted_by(|a, b| a < b);
        if !presorted {
            positions.sort_unstable();
            positions.dedup();
        }
        let read = reader.read_many(&positions).await?;

        // A presorted input with nothing resolved in memory was read in caller order
        // already, so the merge below would only re-clone every operation.
        if presorted && positions.len() == locations.len() {
            return Ok(read);
        }

        // Merge read results back in order.
        for (idx, loc) in committed {
            // `positions` is sorted and deduped, and `loc` came from it before deduping, so
            // binary search must find the matching read_many result.
            let result_idx = positions
                .binary_search(&loc)
                .expect("read result missing for requested location");
            results[idx] = Some(read[result_idx].clone());
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
            let mut ancestors = DiffCursors::new(self.ancestors.iter().map(|a| a.diff.as_slice()));
            for key in mutations.keys() {
                match ancestors.resolve(key) {
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
        db.strategy().sort_by(&mut locations, |a, b| a.cmp(b));
        locations.dedup();
        locations
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
        let mut ancestors = DiffCursors::new(self.ancestors.iter().map(|a| a.diff.as_slice()));
        let mut creates = Vec::new();
        mutations.retain(|key, value| {
            if let Some(DiffEntry::Deleted { base_old_loc }) = ancestors.resolve(key) {
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
    async fn finish<E, C, I, const N: usize>(
        self,
        mut ops: Vec<Operation<F, U>>,
        mut diff: DiffVec<U::Key, F, U::Value>,
        active_keys_delta: isize,
        user_steps: u64,
        metadata: Option<U::Value>,
        mut fill_candidates: impl FnMut(Location<F>, u64, usize, &mut Vec<Location<F>>) -> Location<F>,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, U, S>>, crate::qmdb::Error<F>>
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
            // Floor raise: advance the inactivity floor by `total_steps` active operations.
            // `fixed_tip` prevents scanning into floor-raise moves just appended.
            let strategy = db.strategy();
            let fixed_tip = self.base_size + ops.len() as u64;
            let mut moved = 0u64;
            let mut scan_from = floor;
            let mut floor_diff = Vec::with_capacity(total_steps as usize);

            while moved < total_steps {
                // Collect candidates, capped by the number of active ops still needed.
                // `scan_from` tracks prefetch progress separately from `floor`, so
                // early exit cannot leave `floor` past unprocessed candidates.
                let limit = (total_steps - moved) as usize;
                let mut candidates = Vec::with_capacity(limit);
                scan_from = fill_candidates(scan_from, fixed_tip, limit, &mut candidates);
                if candidates.is_empty() {
                    break;
                }

                // Batch-read candidates: page-cache hits are served by one batched read,
                // disk misses are fetched concurrently.
                let resolved = self.read_ops(&candidates, &ops, &db.log).await?;

                // Classify every candidate against the pre-raise state (see [`FloorOutcome`]).
                // Revalidation is required even for candidates whose committed bitmap bit is
                // set: this batch's diff or an uncommitted ancestor diff may supersede the
                // committed location, and neither source is reflected in the bitmap.
                let classify = |candidate: Location<F>, op: &Operation<F, U>| {
                    let Some(key) = op.key() else {
                        return FloorOutcome::Inactive; // CommitFloor and other non-keyed ops
                    };
                    match diff.binary_search_by(|(k, _)| k.cmp(key)) {
                        Ok(idx) => {
                            let entry = &diff[idx].1;
                            if entry.loc() == Some(candidate) {
                                FloorOutcome::MoveExisting {
                                    idx,
                                    base_old_loc: entry.base_old_loc(),
                                }
                            } else {
                                FloorOutcome::Inactive
                            }
                        }
                        Err(_) => resolve_in_ancestors(&self.ancestors, key).map_or_else(
                            || {
                                if db.snapshot.get(key).any(|&l| l == candidate) {
                                    FloorOutcome::MoveNew {
                                        base_old_loc: Some(candidate),
                                    }
                                } else {
                                    FloorOutcome::Inactive
                                }
                            },
                            |entry| {
                                if entry.loc() == Some(candidate) {
                                    FloorOutcome::MoveNew {
                                        base_old_loc: entry.base_old_loc(),
                                    }
                                } else {
                                    FloorOutcome::Inactive
                                }
                            },
                        ),
                    }
                };
                let chunk_len = candidates.len().div_ceil(strategy.parallelism_hint());
                let chunks: Vec<CandidateChunk<'_, F, U>> = candidates
                    .chunks(chunk_len)
                    .zip(resolved.chunks(chunk_len))
                    .collect();
                let outcomes: Vec<Vec<FloorOutcome<F>>> =
                    strategy.map_collect_vec(chunks, |(chunk_locs, chunk_ops)| {
                        chunk_locs
                            .iter()
                            .zip(chunk_ops)
                            .map(|(loc, op)| classify(*loc, op))
                            .collect()
                    });

                // Apply in candidate order, moving active ops to the tip.
                let mut outcomes = outcomes.into_iter().flatten();
                for (candidate, op) in candidates.into_iter().zip(resolved) {
                    let outcome = outcomes.next().expect("one outcome per candidate");
                    floor = Location::new(*candidate + 1);
                    match outcome {
                        FloorOutcome::Inactive => continue,
                        FloorOutcome::MoveExisting { idx, base_old_loc } => {
                            let new_loc = Location::new(self.base_size + ops.len() as u64);
                            let value = extract_update_value(&op);
                            ops.push(op);
                            diff[idx].1 = DiffEntry::Active {
                                value,
                                loc: new_loc,
                                base_old_loc,
                            };
                        }
                        FloorOutcome::MoveNew { base_old_loc } => {
                            let key = op.key().cloned().expect("moved op has a key");
                            let new_loc = Location::new(self.base_size + ops.len() as u64);
                            let value = extract_update_value(&op);
                            ops.push(op);
                            floor_diff.push((
                                key,
                                DiffEntry::Active {
                                    value,
                                    loc: new_loc,
                                    base_old_loc,
                                },
                            ));
                        }
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
                strategy.sort_by(&mut diff, |a, b| a.0.cmp(&b.0));
                assert!(diff.is_sorted_by(|a, b| a.0 < b.0));
            }
        } else {
            // DB is empty after this batch; raise floor to tip.
            floor = Location::new(self.base_size + ops.len() as u64);
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        }

        // CommitFloor operation.
        let commit_loc = Location::<F>::new(self.base_size + ops.len() as u64);
        ops.push(Operation::CommitFloor(metadata, floor));

        // Merkleize the journal batch.
        // The journal batch was created eagerly at batch construction time and its
        // parent already contains all prior batches' Merkle state, so we only
        // add THIS batch's operations. Parent operations are never re-cloned,
        // re-encoded, or re-hashed.
        let leaves = Location::new(self.base_size + ops.len() as u64);
        let inactive_peaks = db.inactive_peaks(leaves, floor);

        // Hash before `with_mem` borrows committed Merkle state under its read lock.
        let journal_batch = self.journal_batch.add_many(ops);
        let journal = db.log.with_mem(|base| journal_batch.merkleize(base));
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

        assert!(total_active_keys >= 0, "active_keys underflow");
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
    /// If the same key is written multiple times within a batch, the last value wins.
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
        let m = Merkleizer {
            journal_batch: self.journal_batch,
            ancestors,
            base_size: self.base.base_size(),
            db_size: effective_db_size,
            base_inactivity_floor_loc: self.base.inactivity_floor_loc(),
            base_active_keys: self.base.active_keys(),
        };
        (self.mutations, m)
    }
}

impl<F: Family, H, U, S: Strategy> Staged<F, H, U, S>
where
    U: update::Update + Send + Sync,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Expand this staged batch with more reads.
    ///
    /// Existing read indices remain stable. Newly read keys are appended to the staged read set and
    /// assigned the returned range. The returned values are in the same order as `keys`.
    ///
    /// Expansion does not deduplicate against previously staged keys. Reading the same key again
    /// creates another staged slot in the returned range; if both slots are later updated,
    /// [`merkleize`](Staged::merkleize) applies the update list's normal last-write-wins
    /// semantics.
    ///
    /// Expansion reads through the underlying batch, ancestor batches, and committed database state.
    /// Values the caller has computed for earlier staged slots are not visible until they are passed
    /// to [`merkleize`](Staged::merkleize). Callers that need speculative read-your-writes behavior
    /// should maintain their own overlay while deciding which staged slots to update.
    pub async fn expand<E, C, I, const N: usize>(
        mut self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<(Range<usize>, Vec<Option<U::Value>>, Self), crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let start = self.keys.len();
        let end = start
            .checked_add(keys.len())
            .expect("staged read index overflow");
        let (values, keys, mut cache) = self.batch.stage_reads(keys, db, start).await?;
        self.keys.extend(keys);
        self.cache.cached.append(&mut cache.cached);
        if !self.cache.cached.is_empty() {
            db.strategy()
                .sort_by(&mut self.cache.cached, |a, b| a.1.cmp(&b.1));
        }
        Ok((start..end, values, self))
    }

    fn apply_upserts(
        mut batch: UnmerkleizedBatch<F, H, U, S>,
        upserts: Vec<(U::Key, Option<U::Value>)>,
    ) -> UnmerkleizedBatch<F, H, U, S> {
        for (key, value) in upserts {
            batch = batch.write(key, value);
        }
        batch
    }

    /// Build the inputs for staged merkleization represented by this staged handle.
    ///
    /// Each update is `(read_index, value)`, where `read_index` is the position of the key in the
    /// staged read set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) inputs. `value` is `Some(v)` for an upsert or `None` for a
    /// delete. Duplicate keys retain last-write-wins semantics according to the update order.
    /// Upserts are `(key, value)` writes (`None` deletes) for keys outside the staged read set.
    /// Upserts are applied last; if a caller passes an overlapping key, the upsert follows normal
    /// `write` semantics and wins.
    ///
    /// Committed-resolved updates reuse the staged location. Committed-resolved deletes reuse it
    /// only when `stage_deletes` is set (the unordered path): an unordered delete just emits a
    /// `Delete` at the cached location, whereas an ordered delete must rewrite the deleted key's
    /// predecessor via a snapshot-bucket scan the cached location cannot skip, so ordered passes
    /// `stage_deletes = false` and its deletes fall back to normal mutations. Keys resolved from
    /// ancestors or missing from committed state always fall back.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub(crate) fn into_parts(
        mut self,
        mut updates: Vec<(usize, Option<U::Value>)>,
        upserts: Vec<(U::Key, Option<U::Value>)>,
        stage_deletes: bool,
    ) -> (UnmerkleizedBatch<F, H, U, S>, StagedUpdates<F, U>) {
        let mut staged_updates = StagedUpdates::new();
        if updates.is_empty() {
            return (Self::apply_upserts(self.batch, upserts), staged_updates);
        }

        let upsert_keys = if upserts.is_empty() {
            None
        } else {
            Some(
                upserts
                    .iter()
                    .map(|(key, _)| key.clone())
                    .collect::<AHashSet<_>>(),
            )
        };

        // Each update value is consumed at most once: last-write-wins means at most one update
        // index survives per read slot, so values are moved out with `Option::take` rather than
        // cloned.
        let mut latest = vec![None; self.keys.len()];
        let mut seen = AHashMap::with_capacity(updates.len());
        for (update_idx, (slot, _)) in updates.iter().enumerate() {
            assert!(
                *slot < self.keys.len(),
                "update index out of staged read range"
            );
            if let Some(prev) = seen.insert(&self.keys[*slot], update_idx) {
                latest[updates[prev].0] = None;
            }
            latest[*slot] = Some(update_idx);
        }

        // Upserts are applied last, so matching staged updates can be ignored.
        if let Some(upsert_keys) = &upsert_keys {
            for (slot, update_idx) in latest.iter_mut().enumerate() {
                if update_idx.is_some() && upsert_keys.contains(&self.keys[slot]) {
                    *update_idx = None;
                }
            }
        }

        // Committed-resolved updates (and, when `stage_deletes`, deletes) reuse the staged
        // location/payload. Ordered deletes, keys resolved from ancestors, and keys missing from
        // committed state fall back to normal mutations: leaving `latest[slot]` set routes them to
        // the fallback loop below.
        let selected_count = latest.iter().filter(|idx| idx.is_some()).count();
        staged_updates.entries.reserve(selected_count);
        for (slot, loc, payload) in self.cache.cached {
            let Some(update_idx) = latest[slot] else {
                continue;
            };
            if updates[update_idx].1.is_none() && !stage_deletes {
                continue;
            }
            latest[slot] = None;
            let value = updates[update_idx].1.take();
            staged_updates
                .entries
                .push((self.keys[slot].clone(), loc, payload, value));
        }
        for (slot, update_idx) in latest.into_iter().enumerate() {
            let Some(update_idx) = update_idx else {
                continue;
            };
            let value = updates[update_idx].1.take();
            self.batch.mutations.insert(self.keys[slot].clone(), value);
        }
        (Self::apply_upserts(self.batch, upserts), staged_updates)
    }
}

impl<F: Family, K, V, H, S: Strategy> Staged<F, H, update::Unordered<K, V>, S>
where
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
    /// A `Some` value is an upsert; `None` is a delete. Update indices refer to the staged read
    /// set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) ranges. `metadata` is committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize<E, C, I, const N: usize>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        metadata: Option<V::Value>,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        // Unordered deletes emit a `Delete` at the cached location, so they may be staged.
        let (batch, staged_updates) = self.into_parts(updates, upserts, true);
        batch
            .merkleize_with_floor_scan(
                db,
                metadata,
                Some(staged_updates),
                |floor, tip, limit, out| fill_candidates(&db.bitmap, floor, tip, limit, out),
            )
            .await
    }
}

impl<F: Family, K, V, H, S: Strategy> Staged<F, H, update::Ordered<K, V>, S>
where
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
    /// A `Some` value is an upsert; `None` is a delete. Update indices refer to the staged read
    /// set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) ranges. `metadata` is committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize<E, C, I, const N: usize>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        metadata: Option<V::Value>,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        // Ordered deletes must rewrite the deleted key's predecessor, so they fall back to normal
        // mutations rather than reusing the cached location.
        let (batch, staged_updates) = self.into_parts(updates, upserts, false);
        batch
            .merkleize_with_floor_scan(
                db,
                metadata,
                Some(staged_updates),
                |floor, tip, limit, out| fill_candidates(&db.bitmap, floor, tip, limit, out),
            )
            .await
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
        let mut values = self.get_many(&[key], db).await?;
        Ok(values.pop().expect("one result per key"))
    }

    /// Batch read multiple keys (mutations -> ancestor diffs -> committed DB).
    ///
    /// Returns results in the same order as the input keys, with `None` for absent or deleted
    /// keys.
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
            for (slot, result) in db_indices.into_iter().zip(db_results) {
                results[slot] = result;
            }
        }

        Ok(results)
    }

    /// Batch read multiple keys and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys. The staged batch records updates by
    /// read index: the initial keys occupy `0..keys.len()`, and each
    /// [`expand`](Staged::expand) appends another index range.
    pub async fn stage<E, C, I, const N: usize>(
        self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<(Vec<Option<U::Value>>, Staged<F, H, U, S>), crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let (results, keys, cache) = self.stage_reads(keys, db, 0).await?;
        Ok((
            results,
            Staged {
                batch: self,
                keys,
                cache,
            },
        ))
    }

    async fn stage_reads<E, C, I, const N: usize>(
        &self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, N, S>,
        offset: usize,
    ) -> Result<(Vec<Option<U::Value>>, Vec<U::Key>, StagedCache<F, U>), crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let mut results: Vec<Option<U::Value>> = Vec::with_capacity(keys.len());
        let mut db_indices = Vec::new();
        let mut db_keys = Vec::new();
        let mut cache = StagedCache { cached: Vec::new() };

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
            let db_results = db
                .get_many_map(&db_keys, |data, loc| {
                    (data.value().clone(), loc, data.cached())
                })
                .await?;
            cache.cached.reserve(db_keys.len());
            for (slot, result) in db_indices.into_iter().zip(db_results) {
                results[slot] = result.map(|(value, loc, cached)| {
                    cache.cached.push((offset + slot, loc, cached));
                    value
                });
            }
        }
        if !cache.cached.is_empty() {
            db.strategy()
                .sort_by(&mut cache.cached, |a, b| a.1.cmp(&b.1));
        }

        Ok((
            results,
            keys.iter().map(|key| (*key).to_owned()).collect(),
            cache,
        ))
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
    ///
    /// Consumes updates recorded by [`Staged::merkleize`], allowing loaded keys to skip the
    /// journal re-read their resolution would otherwise require.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.any.unordered.batch.merkleize",
        level = "info",
        skip_all,
        fields(mutations = self.mutations.len() as u64),
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
        self.merkleize_with_floor_scan(db, metadata, None, |floor, tip, limit, out| {
            fill_candidates(&db.bitmap, floor, tip, limit, out)
        })
        .await
    }

    /// Like [`merkleize`](Self::merkleize), but accepts optional staged updates and the floor-raise
    /// candidate source.
    ///
    /// The callback may skip locations only when it knows they are inactive. The floor-raise
    /// loop revalidates each returned candidate against the batch diff, ancestor diffs, and
    /// snapshot because the bitmap reflects committed state only -- uncommitted ancestor ops
    /// aren't tracked, and bits can be set for locations superseded by an overlay in this chain.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        staged_updates: Option<StagedUpdates<F, update::Unordered<K, V>>>,
        fill_candidates: impl FnMut(Location<F>, u64, usize, &mut Vec<Location<F>>) -> Location<F>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        // `value` is `Some` for a staged update and `None` for a staged delete; `emit` maps each
        // to an `Update`/`Delete` at the cached location.
        let (mut mutations, m) = self.into_parts();
        let staged_entries = staged_updates.map_or_else(Vec::new, |staged| staged.entries);
        let mut cached: Vec<(K, Location<F>, Option<V::Value>)> =
            Vec::with_capacity(staged_entries.len());
        for (key, loc, (), value) in staged_entries {
            cached.push((key, loc, value));
        }

        // Resolve existing keys.
        let locations = m.gather_existing_locations(&mutations, db, false);
        let results = m.read_ops(&locations, &[], &db.log).await?;

        // Generate user mutation operations.
        let mut ops: Vec<Operation<F, update::Unordered<K, V>>> =
            Vec::with_capacity(mutations.len() + cached.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> = Vec::with_capacity(mutations.len() + cached.len());
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;

        // Write a user mutation at the next batch location, preserving the previous committed
        // location of the key it supersedes.
        let mut emit = |key: K, base_old_loc: Option<Location<F>>, mutation: Option<V::Value>| {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            match mutation {
                Some(value) => {
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
                }
                None => {
                    ops.push(Operation::Delete(key.clone()));
                    diff.push((key, DiffEntry::Deleted { base_old_loc }));
                    active_keys_delta -= 1;
                }
            }
            user_steps += 1;
        };

        // Process updates/deletes of existing keys in location order, merging cached entries
        // into the read results. This includes keys from both the committed snapshot and ancestor
        // diffs.
        let mut cached = cached.into_iter().peekable();
        for (op, &old_loc) in results.iter().zip(&locations) {
            while cached.peek().is_some_and(|&(_, loc, _)| loc < old_loc) {
                let (key, loc, mutation) = cached.next().expect("peeked entry exists");
                emit(key, Some(loc), mutation);
            }

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

            emit(key.clone(), base_old_loc, mutation);
        }
        for (key, loc, mutation) in cached {
            emit(key, Some(loc), mutation);
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
        db.strategy()
            .sort_by(&mut creates, |(a, _, _), (b, _, _)| a.cmp(b));
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

        db.strategy().sort_by(&mut diff, |a, b| a.0.cmp(&b.0));

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(
            ops,
            diff,
            active_keys_delta,
            user_steps,
            metadata,
            fill_candidates,
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
    ///
    /// Consumes updates recorded by [`Staged::merkleize`], allowing loaded keys to skip the index probe
    /// and journal re-read their resolution would otherwise require (the caller's new value and the
    /// cached next key feed op generation directly). Deletes never consume staged updates. Deleting
    /// a key requires rewriting its predecessor, which may be a colliding key in the deleted key's
    /// snapshot bucket, so that bucket must be scanned regardless and the cached location saves
    /// nothing.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.any.ordered.batch.merkleize",
        level = "info",
        skip_all,
        fields(mutations = self.mutations.len() as u64),
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
        self.merkleize_with_floor_scan(db, metadata, None, |floor, tip, limit, out| {
            fill_candidates(&db.bitmap, floor, tip, limit, out)
        })
        .await
    }

    /// Like [`merkleize`](Self::merkleize), but accepts optional staged updates and the floor-raise
    /// candidate source.
    ///
    /// The callback may skip locations only when it knows they are inactive. The floor-raise
    /// loop revalidates each returned candidate against the batch diff, ancestor diffs, and
    /// snapshot because the bitmap reflects committed state only -- uncommitted ancestor ops
    /// aren't tracked, and bits can be set for locations superseded by an overlay in this chain.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        staged_updates: Option<StagedUpdates<F, update::Ordered<K, V>>>,
        fill_candidates: impl FnMut(Location<F>, u64, usize, &mut Vec<Location<F>>) -> Location<F>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        let (mut mutations, m) = self.into_parts();

        // Staged updates skip the index probe and journal re-read, and their old op's next key
        // feeds the candidate sets directly. The ordered path never stages deletes (see
        // `Staged::into_parts`), so every staged entry carries a value.
        let staged_entries = staged_updates.map_or_else(Vec::new, |staged| staged.entries);
        let mut cached: Vec<(K, V::Value, Location<F>, K)> =
            Vec::with_capacity(staged_entries.len());
        for (key, loc, old_next, value) in staged_entries {
            let value = value.expect("ordered path never stages deletes");
            cached.push((key, value, loc, old_next));
        }

        // Resolve existing keys.
        let locations = m.gather_existing_locations(&mutations, db, true);

        // Classify mutations into deleted, created, updated. `next_candidates` and
        // `prev_candidates` are built as unsorted `Vec`s here and sorted+deduped once below,
        // before `find_next_key` / `find_prev_key` binary-search them.
        let mut next_candidates: Vec<K> = Vec::new();
        let mut prev_candidates: PrevCandidates<K, F, V::Value> = Vec::new();
        let mut deleted: Vec<(K, Location<F>)> = Vec::new();
        let mut updated: Vec<(K, V::Value, Location<F>)> = Vec::new();

        for (op, &old_loc) in m
            .read_ops(&locations, &[], &db.log)
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
            prev_candidates.push((key.clone(), (Some(value), old_loc)));

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

        // Merge staged-resolved updates: their old op's next_key and (key, loc) feed the
        // candidate sets exactly as the skipped journal read would have. No prev-candidate
        // value is stored: it is only consumed when the predecessor-rewrite loop emits an op
        // for the key, and that loop skips every key present in `updated`.
        for (key, value, loc, old_next) in cached {
            next_candidates.push(old_next);
            prev_candidates.push((key.clone(), (None, loc)));
            updated.push((key, value, loc));
        }

        db.strategy().sort_by(&mut deleted, |a, b| a.0.cmp(&b.0));
        db.strategy().sort_by(&mut updated, |a, b| a.0.cmp(&b.0));

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
        db.strategy()
            .sort_by(&mut created, |(a, _, _), (b, _, _)| a.cmp(b));

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

        let prev_results = m.read_ops(&prev_locations, &[], &db.log).await?;

        for (op, &old_loc) in prev_results.into_iter().zip(&prev_locations) {
            let data = match op {
                Operation::Update(data) => data,
                _ => unreachable!("expected update operation"),
            };
            next_candidates.push(data.next_key);
            prev_candidates.push((data.key, (Some(data.value), old_loc)));
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
        //
        // Each diff is key-sorted, as are `updated`/`created`/`deleted`, so the handled check
        // advances three cursors in a sorted merge instead of three binary searches per key.
        // Active entries are collected and read in one batch below instead of one awaited
        // read per key.
        let track_shadow = m.ancestors.len() > 1;
        let seen_cap = if track_shadow {
            m.ancestors.iter().map(|a| a.diff.len()).sum()
        } else {
            0
        };
        let mut seen: AHashSet<&K> = AHashSet::with_capacity(seen_cap);
        let mut ancestor_deleted: Vec<K> = Vec::new();
        let mut ancestor_active: Vec<(&K, &V::Value, Location<F>)> = Vec::new();
        for batch in m.ancestors.iter() {
            let (mut ui, mut ci, mut di) = (0, 0, 0);
            for (key, entry) in batch.diff.iter() {
                if track_shadow && !seen.insert(key) {
                    continue;
                }
                // Skip keys already handled by this batch's mutations.
                while ui < updated.len() && updated[ui].0 < *key {
                    ui += 1;
                }
                while ci < created.len() && created[ci].0 < *key {
                    ci += 1;
                }
                while di < deleted.len() && deleted[di].0 < *key {
                    di += 1;
                }
                if updated.get(ui).is_some_and(|(k, ..)| k == key)
                    || created.get(ci).is_some_and(|(k, ..)| k == key)
                    || deleted.get(di).is_some_and(|(k, _)| k == key)
                {
                    continue;
                }
                match entry {
                    DiffEntry::Active { value, loc, .. } => {
                        ancestor_active.push((key, value, *loc));
                    }
                    DiffEntry::Deleted { .. } => {
                        ancestor_deleted.push(key.clone());
                    }
                }
            }
        }
        ancestor_deleted.sort();
        ancestor_deleted.dedup();

        // Batch-read the collected active entries' ops and emit their candidates.
        let ancestor_locs: Vec<Location<F>> =
            ancestor_active.iter().map(|&(_, _, loc)| loc).collect();
        for (op, (key, value, loc)) in m
            .read_ops(&ancestor_locs, &[], &db.log)
            .await?
            .into_iter()
            .zip(ancestor_active)
        {
            let data = match op {
                Operation::Update(data) => data,
                _ => unreachable!("ancestor diff Active should reference Update op"),
            };
            next_candidates.push(key.clone());
            next_candidates.push(data.next_key);
            prev_candidates.push((key.clone(), (Some(value.clone()), loc)));
        }

        // Sort + dedup candidate sets now so find_next_key/find_prev_key can binary-search.
        db.strategy().sort_by(&mut next_candidates, |a, b| a.cmp(b));
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
        let mut ancestors = DiffCursors::new(m.ancestors.iter().map(|a| a.diff.as_slice()));
        for (key, old_loc) in &deleted {
            ops.push(Operation::Delete(key.clone()));

            let base_old_loc = ancestors
                .resolve(key)
                .map_or(Some(*old_loc), DiffEntry::base_old_loc);

            diff.push((key.clone(), DiffEntry::Deleted { base_old_loc }));
            active_keys_delta -= 1;
            user_steps += 1;
        }

        // Process updates of existing keys.
        let mut ancestors = DiffCursors::new(m.ancestors.iter().map(|a| a.diff.as_slice()));
        let mut next_idx = 0;
        for (key, value, old_loc) in &updated {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            let next_key = find_next_key_ascending(key, &next_candidates, &mut next_idx);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));

            let base_old_loc = ancestors
                .resolve(key)
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
        let mut next_idx = 0;
        for (key, value, base_old_loc) in &created {
            let new_loc = Location::new(m.base_size + ops.len() as u64);
            let next_key = find_next_key_ascending(key, &next_candidates, &mut next_idx);
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

                let prev_value = prev_value
                    .as_ref()
                    .expect("staged-resolved keys are skipped as updated");
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

        db.strategy().sort_by(&mut diff, |a, b| a.0.cmp(&b.0));

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(
            ops,
            diff,
            active_keys_delta,
            user_steps,
            metadata,
            fill_candidates,
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

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F> {
        &self.bounds
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
        name = "qmdb.any.batch.new.from_batch",
        level = "debug",
        skip_all,
        fields(
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
        name = "qmdb.any.batch.new.from_db",
        level = "debug",
        skip_all,
        fields(
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
    C: Mutable<Item = Operation<F, U>>,
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
        name = "qmdb.any.db.apply_batch",
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
                let mut resolver = DiffCursors::new(applied);
                let merge = DiffMerge::new(
                    iter::once(batch.diff.as_slice()).chain(pending.iter().copied()),
                );
                for (key, entry) in merge {
                    let old = resolver
                        .resolve(key)
                        .map(DiffEntry::loc)
                        .unwrap_or_else(|| entry.base_old_loc());
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
        self.update_metrics();
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
        name = "qmdb.any.db.to_batch",
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

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
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

        fn write(self, key: K, value: Option<V::Value>) -> Self {
            Self::write(self, key, value)
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
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
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
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
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
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_utils::test_rng;
    use rand::Rng;

    const BITMAP_CHUNK_BITS: u64 = bitmap::Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS;

    fn loc(n: u64) -> Location<mmr::Family> {
        Location::new(n)
    }

    fn trait_write<B, Db>(batch: B, key: sha256::Digest, value: sha256::Digest) -> B
    where
        B: crate::qmdb::any::traits::UnmerkleizedBatch<Db, K = sha256::Digest, V = sha256::Digest>,
        Db: ?Sized,
    {
        <B as crate::qmdb::any::traits::UnmerkleizedBatch<Db>>::write(batch, key, Some(value))
    }

    fn shared_with<F>(build: F) -> Shared<BITMAP_CHUNK_BYTES>
    where
        F: FnOnce(&mut bitmap::Prunable<BITMAP_CHUNK_BYTES>),
    {
        let mut bm = bitmap::Prunable::<BITMAP_CHUNK_BYTES>::new();
        build(&mut bm);
        Shared::new(bm)
    }

    /// [`DiffCursors`] must resolve exactly like per-key `lookup_sorted` over the same diffs
    /// (closest-first) for any ascending query sequence, including queries absent from every
    /// diff and diffs with disjoint or overlapping key ranges.
    #[test]
    fn diff_cursors_matches_lookup_sorted() {
        let mut rng = test_rng();
        for _ in 0..50 {
            // Build 1-4 sorted diffs over a small key universe so overlaps are common.
            let num_diffs = rng.gen_range(1..=4);
            let diffs: Vec<DiffVec<u64, mmr::Family, u64>> = (0..num_diffs)
                .map(|d| {
                    let mut keys: Vec<u64> = (0..rng.gen_range(0..30))
                        .map(|_| rng.gen_range(0..50u64))
                        .collect();
                    keys.sort_unstable();
                    keys.dedup();
                    keys.into_iter()
                        .map(|k| {
                            (
                                k,
                                DiffEntry::Active {
                                    value: k * 1000 + d,
                                    loc: loc(k * 1000 + d),
                                    base_old_loc: None,
                                },
                            )
                        })
                        .collect()
                })
                .collect();

            // Ascending queries spanning the universe (with gaps and duplicates).
            let mut queries: Vec<u64> = (0..rng.gen_range(1..60))
                .map(|_| rng.gen_range(0..55u64))
                .collect();
            queries.sort_unstable();

            let mut cursors = DiffCursors::new(diffs.iter().map(|d| d.as_slice()));
            for q in queries {
                let expected = diffs.iter().find_map(|d| lookup_sorted(d.as_slice(), &q));
                let actual = cursors.resolve(&q);
                assert_eq!(
                    expected.map(DiffEntry::loc),
                    actual.map(DiffEntry::loc),
                    "query {q} diverged"
                );
            }
        }
    }

    /// An out-of-order query that would return a wrong result must panic instead.
    #[test]
    #[should_panic(expected = "queries must be non-decreasing")]
    fn diff_cursors_rejects_out_of_order_query() {
        let diff: DiffVec<u64, mmr::Family, u64> = vec![1, 5]
            .into_iter()
            .map(|k| {
                (
                    k,
                    DiffEntry::Active {
                        value: k,
                        loc: loc(k),
                        base_old_loc: None,
                    },
                )
            })
            .collect();
        let mut cursors = DiffCursors::new([diff.as_slice()]);
        assert!(cursors.resolve(&5).is_some());
        cursors.resolve(&1);
    }

    /// Single-step oracle for [`fill_candidates`]: return the next floor-raise candidate in
    /// `[floor, tip)`. `bitmap_fill_candidates_matches_oracle` proves the production batch
    /// fill produces this exact sequence.
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
    fn diff_merge_two_way_priority() {
        let a = vec![
            (1, active(10, 10)),
            (3, active(30, 30)),
            (5, deleted(Some(5))),
        ];
        let b = vec![
            (2, active(20, 20)),
            (3, active(300, 300)),
            (4, active(40, 40)),
            (5, active(50, 50)),
        ];

        let merged: Vec<_> = DiffMerge::new([a.as_slice(), b.as_slice()])
            .map(|(key, entry)| (*key, entry.value().copied(), entry.loc()))
            .collect();

        assert_eq!(
            merged,
            vec![
                (1, Some(10), Some(loc(10))),
                (2, Some(20), Some(loc(20))),
                (3, Some(30), Some(loc(30))),
                (4, Some(40), Some(loc(40))),
                (5, None, None),
            ]
        );
    }

    #[test]
    fn diff_merge_single_stream() {
        let a = vec![(1, active(10, 10)), (3, active(30, 30))];

        let merged: Vec<_> = DiffMerge::new([a.as_slice()])
            .map(|(key, entry)| (*key, entry.value().copied()))
            .collect();

        assert_eq!(merged, vec![(1, Some(10)), (3, Some(30))]);
    }

    #[test]
    fn diff_cursors_use_nearest_touch() {
        let parent = vec![(2, active(20, 20)), (5, deleted(Some(5)))];
        let grandparent = vec![
            (2, active(200, 200)),
            (4, active(40, 40)),
            (5, active(50, 50)),
        ];
        let mut cursors = DiffCursors::new([parent.as_slice(), grandparent.as_slice()]);

        // Lookups are issued in ascending order, as they are from DiffMerge in apply_batch.
        assert_eq!(cursors.resolve(&1).map(DiffEntry::loc), None);
        assert_eq!(cursors.resolve(&2).map(DiffEntry::loc), Some(Some(loc(20))));
        assert_eq!(cursors.resolve(&4).map(DiffEntry::loc), Some(Some(loc(40))));
        assert_eq!(cursors.resolve(&5).map(DiffEntry::loc), Some(None));
        assert_eq!(cursors.resolve(&9).map(DiffEntry::loc), None);
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

    /// `fill_candidates` must produce the exact candidate sequence of repeatedly calling the
    /// `next_candidate` oracle, across committed bits, the committed-to-tail transition, pruned
    /// and truncated bitmaps, every batch limit, and tips below the bitmap length.
    #[test]
    fn bitmap_fill_candidates_matches_oracle() {
        let shapes: Vec<(&str, Shared<BITMAP_CHUNK_BYTES>)> = vec![
            ("empty", shared_with(|_| {})),
            (
                "committed_bits",
                shared_with(|bm| {
                    bm.extend_to(10);
                    bm.set_bit(3, true);
                    bm.set_bit(7, true);
                }),
            ),
            (
                "transition_into_tail",
                shared_with(|bm| {
                    bm.extend_to(5);
                    bm.set_bit(2, true);
                }),
            ),
            (
                "pruned",
                shared_with(|bm| {
                    bm.extend_to(BITMAP_CHUNK_BITS * 3);
                    bm.set_bit(BITMAP_CHUNK_BITS * 2 + 5, true);
                    bm.prune_to_bit(BITMAP_CHUNK_BITS * 2);
                }),
            ),
            (
                "truncated",
                shared_with(|bm| {
                    bm.extend_to(BITMAP_CHUNK_BITS * 2);
                    bm.set_bit(BITMAP_CHUNK_BITS + 3, true);
                    bm.truncate(BITMAP_CHUNK_BITS);
                }),
            ),
        ];

        for (name, bitmap) in shapes {
            let bitmap_len = bitmap::Readable::<BITMAP_CHUNK_BYTES>::len(&bitmap);
            let start = commonware_utils::bitmap::Readable::pruned_chunks(&bitmap) as u64
                * BITMAP_CHUNK_BITS;
            for tip in [
                start,
                bitmap_len.saturating_sub(2),
                bitmap_len,
                bitmap_len + 6,
            ] {
                // Oracle sequence: advance the floor one candidate at a time.
                let mut expected = Vec::new();
                let mut floor = loc(start);
                while let Some(candidate) = next_candidate(&bitmap, floor, tip) {
                    expected.push(candidate);
                    floor = loc(*candidate + 1);
                }

                for limit in 1..=expected.len().max(1) + 1 {
                    let mut actual = Vec::new();
                    let mut scan = loc(start);
                    loop {
                        let mut batch = Vec::new();
                        scan = fill_candidates(&bitmap, scan, tip, limit, &mut batch);
                        if batch.is_empty() {
                            break;
                        }
                        actual.extend(batch);
                    }
                    assert_eq!(
                        actual, expected,
                        "shape={name} tip={tip} limit={limit} diverged from oracle"
                    );
                }
            }
        }
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
    fn unordered_bulk_update_paths_match_explicit_writes() {
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

            let config = fixed_db_config::<OneCap>("unordered-bulk-load-update", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            let k0 = colliding_digest(0x40, 0);
            let k1 = colliding_digest(0x40, 1);
            let k2 = colliding_digest(0x41, 0);
            let missing = colliding_digest(0x40, 9);
            let read_only = colliding_digest(0x41, 1);
            let unread_existing = colliding_digest(0x41, 2);
            let unread_missing = colliding_digest(0x40, 10);
            let del_read = colliding_digest(0x41, 3);
            let del_unread = colliding_digest(0x41, 4);
            let v0 = colliding_digest(0x50, 0);
            let v1 = colliding_digest(0x50, 1);
            let v2 = colliding_digest(0x51, 0);
            let read_only_value = colliding_digest(0x51, 1);
            let unread_existing_value = colliding_digest(0x51, 2);
            let del_read_value = colliding_digest(0x51, 3);
            let del_unread_value = colliding_digest(0x51, 4);

            let seed = db
                .new_batch()
                .write(k0, Some(v0))
                .write(k1, Some(v1))
                .write(k2, Some(v2))
                .write(read_only, Some(read_only_value))
                .write(unread_existing, Some(unread_existing_value))
                .write(del_read, Some(del_read_value))
                .write(del_unread, Some(del_unread_value))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            // Read set with duplicate slots for k0 (0,4) and missing (2,5), plus del_read at 7.
            let read_keys = [k0, read_only, missing, k1, k0, missing, k2, del_read];
            let keys: Vec<_> = read_keys.iter().collect();
            // (read_slot, Some=upsert | None=delete). Slot 7 deletes a committed-resolved read
            // key; duplicate slots exercise last-write-wins by update order.
            let indexed_updates = vec![
                (0, Some(colliding_digest(0x60, 0))),
                (2, Some(colliding_digest(0x60, 1))),
                (3, Some(colliding_digest(0x60, 2))),
                (4, Some(colliding_digest(0x60, 3))),
                (5, Some(colliding_digest(0x60, 4))),
                (6, Some(colliding_digest(0x60, 5))),
                (7, None),
            ];
            // Upserts for unread keys: set two, override k0 (overlaps slots 0/4), delete one.
            let upserts = vec![
                (unread_existing, Some(colliding_digest(0x60, 6))),
                (unread_missing, Some(colliding_digest(0x60, 7))),
                (k0, Some(colliding_digest(0x60, 8))),
                (del_unread, None),
            ];
            let loaded_values = vec![
                Some(v0),
                Some(read_only_value),
                None,
                Some(v1),
                Some(v0),
                None,
                Some(v2),
                Some(del_read_value),
            ];

            // Explicit path: read, then apply the same logical writes in the same order (updates
            // by read-slot key, then upserts). Must produce a byte-identical root to the staged
            // path, which skips the journal re-read for committed-resolved updated keys.
            let mut explicit = db.new_batch();
            let explicit_values = explicit.get_many(&keys, &db).await.unwrap();
            for (slot, value) in &indexed_updates {
                explicit = explicit.write(read_keys[*slot], *value);
            }
            for (key, value) in &upserts {
                explicit = explicit.write(*key, *value);
            }
            let explicit = explicit.merkleize(&db, None).await.unwrap();

            let (staged_values, staged) = db.new_batch().stage(&keys, &db).await.unwrap();
            let staged_merkleized = staged
                .merkleize(indexed_updates.clone(), upserts.clone(), None, &db)
                .await
                .unwrap();

            let split = 3;
            let (mut expanded_values, staged) =
                db.new_batch().stage(&keys[..split], &db).await.unwrap();
            let (range, suffix_values, staged) = staged.expand(&keys[split..], &db).await.unwrap();
            assert_eq!(range, split..keys.len());
            expanded_values.extend(suffix_values);
            let expanded = staged
                .merkleize(indexed_updates.clone(), upserts.clone(), None, &db)
                .await
                .unwrap();

            assert_eq!(explicit_values, loaded_values);
            assert_eq!(explicit_values, staged_values);
            assert_eq!(explicit_values, expanded_values);

            assert_eq!(explicit.root(), staged_merkleized.root());
            assert_eq!(explicit.root(), expanded.root());

            db.apply_batch(expanded).await.unwrap();
            assert_eq!(db.get(&k0).await.unwrap(), upserts[2].1);
            assert_eq!(db.get(&missing).await.unwrap(), indexed_updates[4].1);
            assert_eq!(db.get(&k1).await.unwrap(), indexed_updates[2].1);
            assert_eq!(db.get(&k2).await.unwrap(), indexed_updates[5].1);
            assert_eq!(db.get(&read_only).await.unwrap(), Some(read_only_value));
            assert_eq!(db.get(&unread_existing).await.unwrap(), upserts[0].1);
            assert_eq!(db.get(&unread_missing).await.unwrap(), upserts[1].1);
            assert_eq!(db.get(&del_read).await.unwrap(), None);
            assert_eq!(db.get(&del_unread).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn ordered_bulk_update_paths_match_explicit_writes() {
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

            let config = fixed_db_config::<OneCap>("ordered-bulk-load-update", &context);
            let mut db = TestDb::init(context, config).await.unwrap();

            let k0 = colliding_digest(0x42, 0);
            let k1 = colliding_digest(0x42, 1);
            let k2 = colliding_digest(0x43, 0);
            let missing = colliding_digest(0x42, 9);
            let read_only = colliding_digest(0x43, 1);
            let unread_existing = colliding_digest(0x43, 2);
            let unread_missing = colliding_digest(0x42, 10);
            let del_read = colliding_digest(0x43, 3);
            let del_unread = colliding_digest(0x43, 4);
            let v0 = colliding_digest(0x52, 0);
            let v1 = colliding_digest(0x52, 1);
            let v2 = colliding_digest(0x53, 0);
            let read_only_value = colliding_digest(0x53, 1);
            let unread_existing_value = colliding_digest(0x53, 2);
            let del_read_value = colliding_digest(0x53, 3);
            let del_unread_value = colliding_digest(0x53, 4);

            let seed = db
                .new_batch()
                .write(k0, Some(v0))
                .write(k1, Some(v1))
                .write(k2, Some(v2))
                .write(read_only, Some(read_only_value))
                .write(unread_existing, Some(unread_existing_value))
                .write(del_read, Some(del_read_value))
                .write(del_unread, Some(del_unread_value))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            // Read set with duplicate slots for k0 (0,4) and missing (2,5), plus del_read at 7.
            let read_keys = [k0, read_only, missing, k1, k0, missing, k2, del_read];
            let keys: Vec<_> = read_keys.iter().collect();
            // Slot 7 deletes a committed-resolved read key. For the ordered path a staged delete
            // must fall back to a normal mutation (the deleted key's predecessor is rewritten via
            // a snapshot-bucket scan the cached location cannot skip), exercised here alongside
            // staged updates that share del_read's collision bucket.
            let indexed_updates = vec![
                (0, Some(colliding_digest(0x62, 0))),
                (2, Some(colliding_digest(0x62, 1))),
                (3, Some(colliding_digest(0x62, 2))),
                (4, Some(colliding_digest(0x62, 3))),
                (5, Some(colliding_digest(0x62, 4))),
                (6, Some(colliding_digest(0x62, 5))),
                (7, None),
            ];
            let upserts = vec![
                (unread_existing, Some(colliding_digest(0x62, 6))),
                (unread_missing, Some(colliding_digest(0x62, 7))),
                (k0, Some(colliding_digest(0x62, 8))),
                (del_unread, None),
            ];
            let loaded_values = vec![
                Some(v0),
                Some(read_only_value),
                None,
                Some(v1),
                Some(v0),
                None,
                Some(v2),
                Some(del_read_value),
            ];
            let mut explicit = db.new_batch();
            let explicit_values = explicit.get_many(&keys, &db).await.unwrap();
            for (slot, value) in &indexed_updates {
                explicit = explicit.write(read_keys[*slot], *value);
            }
            for (key, value) in &upserts {
                explicit = explicit.write(*key, *value);
            }
            let explicit = explicit.merkleize(&db, None).await.unwrap();

            let (staged_values, staged) = db.new_batch().stage(&keys, &db).await.unwrap();
            let staged_merkleized = staged
                .merkleize(indexed_updates.clone(), upserts.clone(), None, &db)
                .await
                .unwrap();

            let split = 3;
            let (mut expanded_values, staged) =
                db.new_batch().stage(&keys[..split], &db).await.unwrap();
            let (range, suffix_values, staged) = staged.expand(&keys[split..], &db).await.unwrap();
            assert_eq!(range, split..keys.len());
            expanded_values.extend(suffix_values);
            let expanded = staged
                .merkleize(indexed_updates.clone(), upserts.clone(), None, &db)
                .await
                .unwrap();

            assert_eq!(explicit_values, loaded_values);
            assert_eq!(explicit_values, staged_values);
            assert_eq!(explicit_values, expanded_values);

            assert_eq!(explicit.root(), staged_merkleized.root());
            assert_eq!(explicit.root(), expanded.root());

            db.apply_batch(expanded).await.unwrap();
            assert_eq!(db.get(&k0).await.unwrap(), upserts[2].1);
            assert_eq!(db.get(&missing).await.unwrap(), indexed_updates[4].1);
            assert_eq!(db.get(&k1).await.unwrap(), indexed_updates[2].1);
            assert_eq!(db.get(&k2).await.unwrap(), indexed_updates[5].1);
            assert_eq!(db.get(&read_only).await.unwrap(), Some(read_only_value));
            assert_eq!(db.get(&unread_existing).await.unwrap(), upserts[0].1);
            assert_eq!(db.get(&unread_missing).await.unwrap(), upserts[1].1);
            assert_eq!(db.get(&del_read).await.unwrap(), None);
            assert_eq!(db.get(&del_unread).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// An update whose read-index is outside the staged read set is a caller-contract violation
    /// and must panic rather than silently misapply.
    #[test]
    #[should_panic(expected = "update index out of staged read range")]
    fn staged_merkleize_rejects_out_of_range_update_index() {
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

            let config = fixed_db_config::<OneCap>("staged-bad-index", &context);
            let db = TestDb::init(context, config).await.unwrap();

            let k0 = colliding_digest(0x40, 0);
            let keys = vec![&k0];
            let (_values, staged) = db.new_batch().stage(&keys, &db).await.unwrap();
            // Slot 1 is out of range for a single-key read set.
            let _ = staged
                .merkleize(
                    vec![(1, Some(colliding_digest(0x50, 0)))],
                    Vec::new(),
                    None,
                    &db,
                )
                .await;
        });
    }

    #[test]
    fn trait_write_dispatches_to_batch_write() {
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

            let config = fixed_db_config::<OneCap>("trait-write-dispatch", &context);
            let mut db = TestDb::init(context, config).await.unwrap();
            let key = Sha256::hash(b"trait-write-key");
            let value = Sha256::hash(b"trait-write-value");

            let batch = trait_write::<_, TestDb>(db.new_batch(), key, value);
            let batch = batch.merkleize(&db, None).await.unwrap();
            db.apply_batch(batch).await.unwrap();

            assert_eq!(db.get(&key).await.unwrap(), Some(value));
            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn unordered_staged_updates_survive_ancestor_commit() {
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

            let key = |i| colliding_digest(0x80, i);
            let val = |i| colliding_digest(0x81, i);
            let suffixes: Vec<u64> = (0..10).chain(20..30).collect();
            let indexed_updates: Vec<_> = suffixes
                .iter()
                .enumerate()
                .map(|(slot, suffix)| (slot, Some(val(suffix + 3_000))))
                .collect();
            let mut roots = Vec::new();

            for staged_read in [false, true] {
                let label = if staged_read {
                    "unordered_staged_ancestor_read"
                } else {
                    "unordered_staged_ancestor_write"
                };
                let context = context.child(label);
                let config = fixed_db_config::<OneCap>(label, &context);
                let mut db = TestDb::init(context, config).await.unwrap();

                let mut seed = db.new_batch();
                for i in 0..100u64 {
                    seed = seed.write(key(i), Some(val(i)));
                }
                let seed = seed.merkleize(&db, None).await.unwrap();
                db.apply_batch(seed).await.unwrap();
                db.commit().await.unwrap();

                let mut grandparent = db.new_batch();
                for i in 0..10u64 {
                    grandparent = grandparent.write(key(i), Some(val(i + 1_000)));
                }
                let grandparent = grandparent.merkleize(&db, None).await.unwrap();

                let mut parent = grandparent.new_batch::<Sha256>();
                for i in 50..60u64 {
                    parent = parent.write(key(i), Some(val(i + 2_000)));
                }
                let parent = parent.merkleize(&db, None).await.unwrap();

                let child = if staged_read {
                    let read_keys: Vec<_> = suffixes.iter().map(|suffix| key(*suffix)).collect();
                    let keys: Vec<_> = read_keys.iter().collect();
                    let child = parent.new_batch::<Sha256>();
                    let (values, staged) = child.stage(&keys, &db).await.unwrap();
                    for (slot, suffix) in suffixes.iter().enumerate() {
                        let expected = if *suffix < 10 {
                            val(suffix + 1_000)
                        } else {
                            val(*suffix)
                        };
                        assert_eq!(values[slot], Some(expected));
                    }

                    db.apply_batch(grandparent).await.unwrap();
                    db.commit().await.unwrap();
                    staged
                        .merkleize(indexed_updates.clone(), Vec::new(), None, &db)
                        .await
                        .unwrap()
                } else {
                    let mut child = parent.new_batch::<Sha256>();
                    db.apply_batch(grandparent).await.unwrap();
                    db.commit().await.unwrap();
                    for suffix in &suffixes {
                        child = child.write(key(*suffix), Some(val(suffix + 3_000)));
                    }
                    child.merkleize(&db, None).await.unwrap()
                };

                db.apply_batch(parent).await.unwrap();
                db.apply_batch(child).await.unwrap();
                db.commit().await.unwrap();

                for suffix in &suffixes {
                    assert_eq!(
                        db.get(&key(*suffix)).await.unwrap(),
                        Some(val(suffix + 3_000))
                    );
                }
                roots.push(db.root());
                db.destroy().await.unwrap();
            }

            assert_eq!(roots[0], roots[1]);
        });
    }

    #[test]
    fn ordered_staged_updates_survive_ancestor_commit() {
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

            let key = |i| colliding_digest(0x82, i);
            let val = |i| colliding_digest(0x83, i);
            let suffixes: Vec<u64> = (0..10).chain(20..30).collect();
            let indexed_updates: Vec<_> = suffixes
                .iter()
                .enumerate()
                .map(|(slot, suffix)| (slot, Some(val(suffix + 3_000))))
                .collect();
            let mut roots = Vec::new();

            for staged_read in [false, true] {
                let label = if staged_read {
                    "ordered_staged_ancestor_read"
                } else {
                    "ordered_staged_ancestor_write"
                };
                let context = context.child(label);
                let config = fixed_db_config::<OneCap>(label, &context);
                let mut db = TestDb::init(context, config).await.unwrap();

                let mut seed = db.new_batch();
                for i in 0..100u64 {
                    seed = seed.write(key(i), Some(val(i)));
                }
                let seed = seed.merkleize(&db, None).await.unwrap();
                db.apply_batch(seed).await.unwrap();
                db.commit().await.unwrap();

                let mut grandparent = db.new_batch();
                for i in 0..10u64 {
                    grandparent = grandparent.write(key(i), Some(val(i + 1_000)));
                }
                let grandparent = grandparent.merkleize(&db, None).await.unwrap();

                let mut parent = grandparent.new_batch::<Sha256>();
                for i in 50..60u64 {
                    parent = parent.write(key(i), Some(val(i + 2_000)));
                }
                let parent = parent.merkleize(&db, None).await.unwrap();

                let child = if staged_read {
                    let read_keys: Vec<_> = suffixes.iter().map(|suffix| key(*suffix)).collect();
                    let keys: Vec<_> = read_keys.iter().collect();
                    let child = parent.new_batch::<Sha256>();
                    let (values, staged) = child.stage(&keys, &db).await.unwrap();
                    for (slot, suffix) in suffixes.iter().enumerate() {
                        let expected = if *suffix < 10 {
                            val(suffix + 1_000)
                        } else {
                            val(*suffix)
                        };
                        assert_eq!(values[slot], Some(expected));
                    }

                    db.apply_batch(grandparent).await.unwrap();
                    db.commit().await.unwrap();
                    staged
                        .merkleize(indexed_updates.clone(), Vec::new(), None, &db)
                        .await
                        .unwrap()
                } else {
                    let mut child = parent.new_batch::<Sha256>();
                    db.apply_batch(grandparent).await.unwrap();
                    db.commit().await.unwrap();
                    for suffix in &suffixes {
                        child = child.write(key(*suffix), Some(val(suffix + 3_000)));
                    }
                    child.merkleize(&db, None).await.unwrap()
                };

                db.apply_batch(parent).await.unwrap();
                db.apply_batch(child).await.unwrap();
                db.commit().await.unwrap();

                for suffix in &suffixes {
                    assert_eq!(
                        db.get(&key(*suffix)).await.unwrap(),
                        Some(val(suffix + 3_000))
                    );
                }
                roots.push(db.root());
                db.destroy().await.unwrap();
            }

            assert_eq!(roots[0], roots[1]);
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
            let ops = merkleizer
                .read_ops(
                    &[current_loc, committed_loc, parent_loc, committed_loc],
                    &batch_ops,
                    &db.log,
                )
                .await
                .unwrap();

            assert_eq!(
                ops,
                vec![
                    Operation::Update(update::Unordered(key_current, value_current)),
                    Operation::Update(update::Unordered(key_db, value_db)),
                    Operation::Update(update::Unordered(key_parent, value_parent)),
                    Operation::Update(update::Unordered(key_db, value_db)),
                ]
            );

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
