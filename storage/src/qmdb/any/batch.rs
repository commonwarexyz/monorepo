//! Batch mutation API for Any QMDBs.

use crate::{
    Context,
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable},
    },
    merkle::{Family, Location},
    qmdb::{
        any::{
            ValueEncoding,
            db::Db,
            operation::{Operation, update},
            ordered::{find_next_key, find_next_key_ascending, find_prev_key},
        },
        batch_chain::{self, Bounds, Commitment},
        bitmap::Shared,
        delete_known_loc,
        operation::{Key, Operation as OperationTrait},
        update_known_loc,
    },
};
use ahash::{AHashMap, AHashSet};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::bitmap;
use core::{cmp::Ordering, ops::Range};
use std::{
    collections::{BTreeMap, hash_map},
    iter, mem,
    sync::{Arc, OnceLock, Weak},
};
use tracing::debug;

type DiffVec<K, F, V> = Vec<(K, DiffEntry<F, V>)>;
type DiffSlice<K, F, V> = [(K, DiffEntry<F, V>)];

const DIFF_INDEX_STRIDE: usize = 8;

/// Sorted locations at the retained batch chain's committed boundary.
type AncestorBaseLocs<K, F> = Vec<(K, Option<Location<F>>)>;

/// One contiguous chunk of floor-raise candidates paired with their resolved operations.
type CandidateChunk<'a, F, U> = (&'a [Location<F>], &'a [Operation<F, U>]);

/// Floor-raise candidates prefetched from the committed prefix of the raise's candidate
/// source, with their resolved operations. The candidate sequence depends only on the base
/// floor and that source, so a staged merkleize reads it before its serial bookkeeping
/// runs. `finish` drains this buffer, then resumes the live scan at `next_scan`, producing
/// exactly the sequence the live scan alone would have.
pub(crate) struct PrefetchedCandidates<F: Family, U: update::Update>
where
    Operation<F, U>: Codec,
{
    /// Ascending committed candidate locations.
    locs: Vec<Location<F>>,
    /// The operation resolved for each location, chunk-partitioned as the reader probed
    /// them. The chunks' concatenation matches `locs` order.
    shards: Vec<Vec<Operation<F, U>>>,
    /// Continuation point for the live scan after `locs`.
    next_scan: Location<F>,
}

/// Sorted `(key, (value, loc))` vec consulted by `find_prev_key` to find the predecessor
/// of a given key during ordered merkleization. The value is `None` for staged-resolved
/// keys: the predecessor-rewrite loop only reads a value for keys outside this batch's
/// mutations, and staged-resolved keys are always in `updated`.
type PrevCandidates<K, F, V> = Vec<(K, (Option<V>, Location<F>))>;

/// Where a staged read resolved: in the committed snapshot, or in an uncommitted
/// ancestor's diff. Either way, the resolved location orders the staged write among this
/// batch's emitted operations. The variants differ in which committed location the write
/// supersedes: `Committed` supersedes the resolved location itself, while `Ancestor`
/// supersedes the committed location it recorded at stage time. The recorded base stays
/// valid while the resolving ancestor is alive at merkleize, because the ancestor's diff
/// travels with this batch and `apply_batch` re-resolves the base if the ancestor commits
/// first. If the ancestor instead commits and is freed before merkleize, its apply has
/// made `loc` the key's committed location, so merkleize supersedes `loc` whenever it lies
/// below the merkleize-time committed boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StagedLoc<F: Family> {
    /// Resolved directly in the committed DB snapshot. The location doubles as the
    /// superseded committed location.
    Committed(Location<F>),
    /// Resolved in an uncommitted ancestor's diff at `loc`, superseding the key's committed
    /// snapshot location `base_old_loc` (`None` when an ancestor created the key).
    Ancestor {
        loc: Location<F>,
        base_old_loc: Option<Location<F>>,
    },
}

impl<F: Family> StagedLoc<F> {
    /// The resolved location: orders the staged write among the batch's emitted operations.
    const fn loc(&self) -> Location<F> {
        match self {
            Self::Committed(loc) | Self::Ancestor { loc, .. } => *loc,
        }
    }
}

/// Staged update entry: key, resolved location, cached payload from the old update, and
/// replacement value (`None` for delete).
type StagedUpdate<F, U> = (
    <U as update::Update>::Key,
    StagedLoc<F>,
    <U as update::Update>::Cached,
    Option<<U as update::Update>::Value>,
);

/// Unresolved read slot paired with its original key.
type PendingRead<'a, K> = (usize, &'a K);

/// Values resolved from uncommitted batches plus the slots that still need DB reads.
type UncommittedReadResolution<'a, K, V> = (Vec<Option<V>>, Vec<PendingRead<'a, K>>);

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

/// A compact directory over a large sorted diff. Each strictly increasing order hint identifies
/// the first key in a fixed-size range. A lookup verifies the hinted range with `K::cmp`, so key
/// types whose byte prefixes do not preserve their ordering transparently fall back to a full
/// binary search.
#[derive(Default)]
struct DiffIndex {
    hints: OnceLock<Box<[u32]>>,
}

impl DiffIndex {
    fn hint(key: &impl AsRef<[u8]>) -> u32 {
        let bytes = key.as_ref();
        let mut prefix = [0; 4];
        let len = bytes.len().min(prefix.len());
        prefix[..len].copy_from_slice(&bytes[..len]);
        u32::from_be_bytes(prefix)
    }

    fn build<K: AsRef<[u8]>, V>(entries: &[(K, V)]) -> Box<[u32]> {
        if entries.len() <= DIFF_INDEX_STRIDE * 2 {
            return Box::new([]);
        }

        let hints: Vec<_> = entries
            .iter()
            .step_by(DIFF_INDEX_STRIDE)
            .map(|(key, _)| Self::hint(key))
            .collect();
        if hints.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Box::new([]);
        }
        hints.into_boxed_slice()
    }

    const fn should_initialize(entry_count: usize, query_count: usize) -> bool {
        // Building samples one entry per stride, so require at least as many actual probes as
        // sampled entries before paying the construction and retention cost.
        entry_count > DIFF_INDEX_STRIDE * 2
            && query_count >= entry_count.div_ceil(DIFF_INDEX_STRIDE)
    }

    fn hints<K: AsRef<[u8]>, V>(&self, entries: &[(K, V)]) -> &[u32] {
        self.hints.get_or_init(|| Self::build(entries))
    }

    fn lookup_with_hints<'a, K: Ord + AsRef<[u8]>, V>(
        entries: &'a [(K, V)],
        key: &K,
        hints: &[u32],
    ) -> Option<&'a V> {
        if hints.is_empty() {
            return lookup_sorted(entries, key);
        }

        let hint = Self::hint(key);
        let Some(range) = hints
            .partition_point(|candidate| *candidate <= hint)
            .checked_sub(1)
        else {
            return if entries.first().is_none_or(|(first, _)| key < first) {
                None
            } else {
                lookup_sorted(entries, key)
            };
        };
        let start = range * DIFF_INDEX_STRIDE;
        let end = (start + DIFF_INDEX_STRIDE).min(entries.len());

        // The byte hint is only an accelerator. These comparisons prove that the queried key
        // belongs to this exact range under the key type's authoritative ordering.
        if key < &entries[start].0 || (end < entries.len() && key >= &entries[end].0) {
            return lookup_sorted(entries, key);
        }
        entries[start..end]
            .binary_search_by(|(candidate, _)| candidate.cmp(key))
            .ok()
            .map(|index| &entries[start + index].1)
    }

    /// Use a previously initialized directory, preserving binary search as the cold point-read
    /// path.
    fn lookup<'a, K: Ord + AsRef<[u8]>, V>(&self, entries: &'a [(K, V)], key: &K) -> Option<&'a V> {
        let Some(hints) = self.hints.get() else {
            return lookup_sorted(entries, key);
        };
        Self::lookup_with_hints(entries, key, hints)
    }

    fn lookup_or_initialize<'a, K: Ord + AsRef<[u8]>, V>(
        &self,
        entries: &'a [(K, V)],
        key: &K,
    ) -> Option<&'a V> {
        Self::lookup_with_hints(entries, key, self.hints(entries))
    }
}

struct DiffSource<'a, K, F: Family, V> {
    entries: &'a DiffSlice<K, F, V>,
    index: &'a DiffIndex,
}

impl<'a, K: Ord + AsRef<[u8]>, F: Family, V> DiffSource<'a, K, F, V> {
    fn lookup(&self, key: &K) -> Option<&'a DiffEntry<F, V>> {
        self.index.lookup(self.entries, key)
    }

    fn lookup_or_initialize(&self, key: &K) -> Option<&'a DiffEntry<F, V>> {
        self.index.lookup_or_initialize(self.entries, key)
    }
}

/// Returns whether sorted, deduplicated `items` contains `target`, advancing `cursor` past
/// entries below it. Successive calls must use non-decreasing `target`s.
fn sorted_contains<T: Ord>(items: &[T], cursor: &mut usize, target: &T) -> bool {
    while items.get(*cursor).is_some_and(|item| item < target) {
        *cursor += 1;
    }
    items.get(*cursor) == Some(target)
}

/// Merge two key-sorted diffs with disjoint keys into one sorted diff.
fn merge_sorted_diffs<K: Ord, F: Family, V>(
    a: DiffVec<K, F, V>,
    b: DiffVec<K, F, V>,
) -> DiffVec<K, F, V> {
    let mut merged = Vec::with_capacity(a.len() + b.len());
    let mut a = a.into_iter().peekable();
    let mut b = b.into_iter().peekable();
    while let (Some(x), Some(y)) = (a.peek(), b.peek()) {
        if x.0 < y.0 {
            merged.push(a.next().expect("peeked"));
        } else {
            merged.push(b.next().expect("peeked"));
        }
    }
    merged.extend(a);
    merged.extend(b);
    merged
}

/// Where this batch's inherited state comes from.
enum Base<F: Family, D: Digest, U: update::Update, S: Strategy> {
    /// Created from the DB via `db.new_batch()`.
    Db {
        state: Commitment<F, D>,
        inactivity_floor_loc: Location<F>,
        active_keys: usize,
    },
    /// Created from a parent batch via `parent.new_batch()`.
    Child(Arc<MerkleizedBatch<F, D, U, S>>),
}

impl<F: Family, D: Digest, U: update::Update, S: Strategy> Base<F, D, U, S> {
    /// The [Commitment] for the state off which this batch was created.
    fn base_state(&self) -> Commitment<F, D> {
        match self {
            Self::Db { state, .. } => *state,
            Self::Child(parent) => parent.commitment(),
        }
    }

    /// The database boundary for this batch chain.
    ///
    /// For `Db`, this is its state. For `Child`, it is inherited from the parent
    /// (which may be higher than the original DB size if ancestors were dropped before merkleize).
    fn db(&self) -> Commitment<F, D> {
        match self {
            Self::Db { state, .. } => *state,
            Self::Child(parent) => parent.bounds.db,
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
    U: update::Update,
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

/// Pending mutations whose old locations were already resolved by staged reads, sorted
/// by location. Each value is `Some` for an update and `None` for a delete. Only the unordered
/// path stages deletes (an ordered delete cannot skip the deleted key's predecessor-bucket scan,
/// so its deletes fall back to normal mutations).
pub(crate) type StagedUpdates<F, U> = Vec<StagedUpdate<F, U>>;

/// A staged read slot's resolution: the location and cached payload the read resolved to,
/// or `None` when it resolved from batch mutations (or missed). Ancestor-diff resolutions
/// are recorded only when the update kind stages them (see
/// [`update::Update::STAGES_ANCESTORS`]). Otherwise those slots stay `None` and fall back
/// to normal mutations.
type StagedResolution<F, U> = Option<(StagedLoc<F>, <U as update::Update>::Cached)>;

/// Staged batch returned by [`UnmerkleizedBatch::stage`].
///
/// Owns the batch and the locations its reads resolved, so the staged reads cannot be paired with a
/// different batch.
pub struct Staged<F: Family, H, U, S: Strategy>
where
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    batch: UnmerkleizedBatch<F, H, U, S>,
    keys: Vec<U::Key>,
    resolutions: Vec<StagedResolution<F, U>>,
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
///
/// # Branch validity
///
/// A `MerkleizedBatch` is a branch-scoped view rooted at a specific committed prefix of the DB,
/// not an immutable snapshot. Reads through the chain, constructing child batches, and applying
/// the batch later are only valid while every batch applied to the DB since this batch was
/// merkleized is an ancestor of this batch. Applying a batch from a different fork is rejected
/// with [`crate::qmdb::Error::StaleBatch`] (see [`crate::qmdb::batch_chain`] for more details).
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, U: update::Update, S: Strategy> {
    /// Merkleized authenticated journal batch (provides the speculative Merkle root).
    pub(crate) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, U>, S>>,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    /// Sorted by key with no duplicates.
    pub(crate) diff: Arc<DiffVec<U::Key, F, U::Value>>,

    /// Clone-shared sparse directory for lookups in `diff`.
    diff_index: Arc<DiffIndex>,

    /// The parent batch in the chain, if any.
    parent: Option<Weak<Self>>,

    /// Total active keys after this batch.
    pub(crate) total_active_keys: usize,

    /// Arc refs to each ancestor's diff, collected during `finish()` while ancestors are
    /// alive. Used by `apply_batch` to apply uncommitted ancestor snapshot diffs.
    /// 1:1 with `bounds.ancestors` (same length, same ordering).
    pub(crate) ancestor_diffs: Vec<Arc<DiffVec<U::Key, F, U::Value>>>,

    /// Locations at `bounds.db` for keys whose retained ancestor diffs cross a dropped prefix.
    /// Only overlapping keys are retained, bounding this by the live speculative suffix rather
    /// than the committed history.
    ancestor_base_locs: AncestorBaseLocs<U::Key, F>,

    /// Position and floor bounds for this batch chain.
    pub(crate) bounds: batch_chain::Bounds<F, D>,
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
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    journal_batch: authenticated::UnmerkleizedBatch<F, H, Operation<F, U>, S>,
    ancestors: Vec<AncestorBatch<F, H::Digest, U, S>>,
    base_state: Commitment<F, H::Digest>,
    db_state: Commitment<F, H::Digest>,
    base_inactivity_floor_loc: Location<F>,
    base_active_keys: usize,
}

/// Look up a key in the ancestor chain (immediate parent first).
fn resolve_in_ancestors<'a, F: Family, D: Digest, U: update::Update, S: Strategy>(
    ancestors: &'a [Arc<MerkleizedBatch<F, D, U, S>>],
    key: &U::Key,
) -> Option<&'a DiffEntry<F, U::Value>> {
    for batch in ancestors {
        if let Some(entry) = batch.diff_index.lookup(batch.diff.as_slice(), key) {
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
            if let Some((k, entry)) = diff.get(*cursor)
                && k == key
            {
                return Some(entry);
            }
        }
        None
    }
}

/// Resolve unresolved input slots against ancestor diffs, preserving final results by original
/// input slot. The caller keeps `pending` in input order so DB fallthrough can do the same.
///
/// `on_hit` is invoked (serially, in `pending` order) with each resolving diff entry, so
/// staged reads can record ancestor resolutions alongside the values.
fn resolve_pending_from_diffs<'k, 'd, K, F: Family, V: Clone + Send + Sync + 'd, S: Strategy>(
    pending: &[PendingRead<'k, K>],
    diffs: &[DiffSource<'d, K, F, V>],
    strategy: &S,
    resolved: &mut [bool],
    results: &mut [Option<V>],
    mut on_hit: impl FnMut(usize, &DiffEntry<F, V>),
) where
    K: Ord + AsRef<[u8]> + Send + Sync,
{
    if pending.is_empty() || diffs.is_empty() {
        return;
    }
    if let [(slot, key)] = pending {
        if let Some(entry) = diffs.iter().find_map(|diff| diff.lookup(key)) {
            resolved[*slot] = true;
            results[*slot] = entry.value().cloned();
            on_hit(*slot, entry);
        }
        return;
    }

    if !diffs
        .iter()
        .any(|diff| DiffIndex::should_initialize(diff.entries.len(), pending.len()))
    {
        let resolve = |chunk: &[PendingRead<'k, K>]| -> Vec<(usize, &'d DiffEntry<F, V>)> {
            chunk
                .iter()
                .filter_map(|(slot, key)| {
                    diffs
                        .iter()
                        .find_map(|diff| diff.lookup(key))
                        .map(|entry| (*slot, entry))
                })
                .collect()
        };
        let hits = strategy.run(
            pending.len(),
            || resolve(pending),
            || {
                let manual = strategy.manual();
                let chunk_len = pending.len().div_ceil(manual.parallelism());
                let chunks: Vec<_> = pending.chunks(chunk_len).collect();
                manual
                    .map_collect_vec(chunks, &resolve)
                    .into_iter()
                    .flatten()
                    .collect()
            },
        );
        for (slot, entry) in hits {
            resolved[slot] = true;
            results[slot] = entry.value().cloned();
            on_hit(slot, entry);
        }
        return;
    }

    let mut remaining: Vec<_> = pending
        .iter()
        .enumerate()
        .map(|(ordinal, (_, key))| (ordinal, *key))
        .collect();
    let mut entries_by_ordinal = vec![None; pending.len()];
    for diff in diffs {
        if remaining.is_empty() {
            break;
        }
        let initialize = DiffIndex::should_initialize(diff.entries.len(), remaining.len());
        let resolve = |chunk: &[(usize, &'k K)]| -> Vec<(usize, &'d DiffEntry<F, V>)> {
            chunk
                .iter()
                .filter_map(|(ordinal, key)| {
                    let entry = if initialize {
                        diff.lookup_or_initialize(key)
                    } else {
                        diff.lookup(key)
                    };
                    entry.map(|entry| (*ordinal, entry))
                })
                .collect()
        };
        let hits = strategy.run(
            remaining.len(),
            || resolve(&remaining),
            || {
                let manual = strategy.manual();
                let chunk_len = remaining.len().div_ceil(manual.parallelism());
                let chunks: Vec<_> = remaining.chunks(chunk_len).collect();
                manual
                    .map_collect_vec(chunks, &resolve)
                    .into_iter()
                    .flatten()
                    .collect()
            },
        );

        for (ordinal, entry) in hits {
            let slot = pending[ordinal].0;
            resolved[slot] = true;
            entries_by_ordinal[ordinal] = Some(entry);
        }
        remaining.retain(|(ordinal, _)| entries_by_ordinal[*ordinal].is_none());
    }

    for (ordinal, (slot, _)) in pending.iter().enumerate() {
        if let Some(entry) = entries_by_ordinal[ordinal] {
            results[*slot] = entry.value().cloned();
            on_hit(*slot, entry);
        }
    }
}

/// Resolve `keys` against a local source (`local` returns `Some` when it owns the key, with the
/// inner `Option` distinguishing a live value from a delete) and then against `diffs`, returning
/// per-slot results and the slots that still need committed DB reads.
///
/// `on_diff_hit` is invoked with each slot resolved by a diff entry (see
/// [`resolve_pending_from_diffs`]). Slots resolved by `local` do not report.
fn resolve_reads<'k, 'd, K, F: Family, V, S: Strategy>(
    keys: &[&'k K],
    local: impl Fn(&K) -> Option<Option<V>>,
    diffs: &[DiffSource<'d, K, F, V>],
    strategy: &S,
    on_diff_hit: impl FnMut(usize, &DiffEntry<F, V>),
) -> UncommittedReadResolution<'k, K, V>
where
    K: Ord + AsRef<[u8]> + Send + Sync,
    V: Clone + Send + Sync + 'd,
{
    let mut results = vec![None; keys.len()];
    let mut resolved = vec![false; keys.len()];
    let mut pending = Vec::new();

    for (i, key) in keys.iter().enumerate() {
        if let Some(value) = local(key) {
            results[i] = value;
            resolved[i] = true;
        } else {
            pending.push((i, *key));
        }
    }
    resolve_pending_from_diffs(
        &pending,
        diffs,
        strategy,
        &mut resolved,
        &mut results,
        on_diff_hit,
    );

    let unresolved = pending.into_iter().filter(|(i, _)| !resolved[*i]).collect();
    (results, unresolved)
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
            cursors: streams.into_iter().map(|slice| (slice, 0)).collect(),
        }
    }

    fn peek_key(cursor: &(&'a DiffSlice<K, F, V>, usize)) -> Option<&'a K> {
        cursor.0.get(cursor.1).map(|(key, _)| key)
    }

    fn next_fixed<const N: usize>(&mut self) -> Option<(&'a K, &'a DiffEntry<F, V>)> {
        debug_assert_eq!(self.cursors.len(), N);
        let mut winner = None;
        let mut tied = 0u8;
        for level in 0..N {
            let Some(key) = Self::peek_key(&self.cursors[level]) else {
                continue;
            };
            let Some(current) = winner else {
                winner = Some(level);
                tied = 1u8 << level;
                continue;
            };
            match key.cmp(Self::peek_key(&self.cursors[current]).unwrap()) {
                Ordering::Less => {
                    winner = Some(level);
                    tied = 1u8 << level;
                }
                Ordering::Equal => tied |= 1u8 << level,
                Ordering::Greater => {}
            }
        }

        // Streams are visited in priority order, so retaining the first equal head selects the
        // newest entry. Every stream tied at that final minimum must advance exactly once.
        let level = winner?;
        let (slice, pos) = self.cursors[level];
        for (level, cursor) in self.cursors.iter_mut().enumerate() {
            if tied & (1u8 << level) != 0 {
                cursor.1 += 1;
            }
        }
        Some((&slice[pos].0, &slice[pos].1))
    }

    fn next_general(&mut self) -> Option<(&'a K, &'a DiffEntry<F, V>)> {
        let mut winner: Option<usize> = None;
        for level in 0..self.cursors.len() {
            let Some(key) = Self::peek_key(&self.cursors[level]) else {
                continue;
            };
            if winner.is_none_or(|current| key < Self::peek_key(&self.cursors[current]).unwrap()) {
                winner = Some(level);
            }
        }
        let level = winner?;
        let (slice, pos) = self.cursors[level];
        let winning_key = &slice[pos].0;
        for cursor in &mut self.cursors {
            if Self::peek_key(cursor).is_some_and(|key| key == winning_key) {
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
                let (key, entry) = slice.get(*pos)?;
                *pos += 1;
                Some((key, entry))
            }
            2 => {
                let left = Self::peek_key(&self.cursors[0]);
                let right = Self::peek_key(&self.cursors[1]);
                let winner = match (left, right) {
                    (Some(left), Some(right)) => match left.cmp(right) {
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
                let (key, entry) = &slice[*pos];
                *pos += 1;
                Some((key, entry))
            }
            3 => self.next_fixed::<3>(),
            4 => self.next_fixed::<4>(),
            _ => self.next_general(),
        }
    }
}

/// Publish `batch`'s key-level changes to the in-memory snapshot index and activity bitmap.
///
/// `snapshot` and `bitmap` must hold the state already applied through `last_commit_loc`, the
/// location of the commit operation they currently end at. On return they reflect `batch.bounds.tip`.
fn apply_batch_to_index<F, D, I, U, S, const N: usize>(
    snapshot: &mut I,
    bitmap: &mut bitmap::Prunable<N>,
    batch: &MerkleizedBatch<F, D, U, S>,
    last_commit_loc: Location<F>,
) where
    F: Family,
    D: Digest,
    I: UnorderedIndex<Value = Location<F>>,
    U: update::Update,
    S: Strategy,
    Operation<F, U>: Send + Sync,
{
    let db_size = *last_commit_loc + 1;
    let tip = *batch.bounds.tip.size;
    bitmap.extend_to(tip);

    if batch.ancestor_diffs.is_empty() {
        // Fast path: no ancestors to merge, no fixups to look up.
        for (key, entry) in batch.diff.iter() {
            apply_diff(snapshot, bitmap, key, entry, entry.base_old_loc());
        }
    } else {
        // Partition ancestor diffs into already-applied (provide `base_old_loc` fixups) and pending
        // (still to be applied; merged with the child).
        let mut applied = Vec::with_capacity(batch.ancestor_diffs.len());
        let mut pending = Vec::with_capacity(batch.ancestor_diffs.len());
        for (ancestor, diff) in batch.bounds.ancestors.iter().zip(&batch.ancestor_diffs) {
            if ancestor.state.size <= db_size {
                applied.push(diff.as_slice());
            } else {
                pending.push(diff.as_slice());
            }
        }
        let mut resolver = DiffCursors::new(applied);
        let mut base_locs = batch.ancestor_base_locs.iter().peekable();
        let merge =
            DiffMerge::new(iter::once(batch.diff.as_slice()).chain(pending.iter().copied()));
        for (key, entry) in merge {
            // Merged keys ascend, so the boundary cursor only moves forward.
            while base_locs
                .peek()
                .is_some_and(|(candidate, _)| candidate < key)
            {
                base_locs.next();
            }

            // The key's location before this batch: from an already-applied ancestor, else the
            // location recorded at the retained chain's boundary, else the batch's own record.
            let old = resolver.resolve(key).map_or_else(
                || {
                    base_locs
                        .next_if(|(candidate, _)| candidate == key)
                        .map_or_else(|| entry.base_old_loc(), |(_, loc)| *loc)
                },
                |ancestor_entry| ancestor_entry.loc(),
            );
            apply_diff(snapshot, bitmap, key, entry, old);
        }
    }

    // Maintain the invariant that only the most recent CommitFloor operation can be active.
    bitmap.set_bit(*last_commit_loc, false);
    bitmap.set_bit(tip - 1, true);
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
    Location::new(bitmap.fill_candidates(*floor, tip, limit, out))
}

/// Resolve `loc` to an op within the in-memory ancestor region
/// `[db_size, ancestors[0].journal_batch.size())`, walked parent-first.
///
/// # Panics
///
/// Panics if `loc` cannot be located in the chain: either it falls outside the region (including
/// when `ancestors` is empty), or the ancestor spans are non-contiguous (a bookkeeping invariant
/// violation).
fn read_op_from_ancestors<F: Family, D: Digest, U: update::Update, S: Strategy>(
    ancestors: &[Arc<MerkleizedBatch<F, D, U, S>>],
    loc: u64,
    db_size: u64,
) -> &Operation<F, U> {
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
    U: update::Update,
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

        if loc >= self.base_state.size {
            return Some(batch_ops[(loc - *self.base_state.size) as usize].clone());
        }

        if loc >= self.db_state.size {
            return Some(read_op_from_ancestors(&self.ancestors, loc, *self.db_state.size).clone());
        }

        None
    }

    /// Whether `locations` is strictly ascending and entirely within the committed region,
    /// the shape a single batched reader call serves with no in-memory resolution.
    fn all_committed_ascending(&self, locations: &[Location<F>]) -> bool {
        locations.is_sorted_by(|a, b| a < b)
            && locations
                .last()
                .is_some_and(|last| **last < self.db_state.size)
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
        // Fast path: a strictly ascending batch entirely within the committed region needs no
        // in-memory resolution, reordering, or per-location bookkeeping, so the positions can
        // be handed to the reader directly. Depth-0 mutation reads take this path. Floor-raise
        // candidate reads hit the same predicate in read_ops_sharded and reach here only when
        // candidates cross into the uncommitted region.
        if self.all_committed_ascending(locations) {
            let positions: Vec<u64> = locations.iter().map(|loc| **loc).collect();
            return Ok(reader.read_many(&positions).await?);
        }

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

        // Batches reaching here contain uncommitted locations or arrived unsorted, but the
        // committed subset is often still presorted (e.g. floor-raise candidates that cross
        // the committed boundary), so the sort is worth skipping when possible.
        let mut positions: Vec<u64> = committed.iter().map(|(_, loc)| *loc).collect();
        let presorted = positions.is_sorted_by(|a, b| a < b);
        if !presorted {
            positions.sort_unstable();
            positions.dedup();
        }
        let read = reader.read_many(&positions).await?;

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

    /// Like [`read_ops`](Self::read_ops), but returns chunk-partitioned results whose
    /// concatenation preserves `locations` order. A strictly ascending batch entirely
    /// within the committed region (the typical floor-raise candidate read) stays
    /// partitioned as the reader probed it, skipping serial reassembly on the calling
    /// task. Other shapes resolve through [`read_ops`](Self::read_ops) as a single chunk.
    async fn read_ops_sharded<E, C>(
        &self,
        locations: &[Location<F>],
        batch_ops: &[Operation<F, U>],
        reader: &authenticated::Journal<F, E, C, H, S>,
    ) -> Result<Vec<Vec<Operation<F, U>>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        Operation<F, U>: Codec,
    {
        if self.all_committed_ascending(locations) {
            let positions: Vec<u64> = locations.iter().map(|loc| **loc).collect();
            return Ok(reader.read_many_sharded(&positions).await?);
        }
        Ok(vec![self.read_ops(locations, batch_ops, reader).await?])
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
            if let Some(DiffEntry::Deleted { base_old_loc }) = ancestors.resolve(key)
                && let Some(v) = value.take()
            {
                creates.push((key.clone(), v, *base_old_loc));
                return false;
            }
            true
        });
        creates
    }

    /// Shared final phases of merkleization: floor raise, CommitFloor, journal
    /// merkleize, diff merge, and `MerkleizedBatch` construction.
    ///
    /// `diff` may arrive in any order: it is key-sorted on the strategy pool, overlapping the
    /// first floor-raise candidate read. `superseded_locs` holds the committed locations
    /// superseded by `diff` (every `Some` `base_old_loc`), in any order. The floor raise
    /// skips re-reading them. `prefetched` optionally holds committed-prefix candidates the
    /// caller gathered and read ahead of time, consumed by the raise before scanning live.
    #[allow(clippy::too_many_arguments)]
    async fn finish<E, C, I, const N: usize>(
        self,
        mut ops: Vec<Operation<F, U>>,
        mut diff: DiffVec<U::Key, F, U::Value>,
        mut superseded_locs: Vec<Location<F>>,
        active_keys_delta: isize,
        user_steps: u64,
        metadata: Option<U::Value>,
        mut prefetched: Option<PrefetchedCandidates<F, U>>,
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

        // Key-sort the diff as one job on the strategy: candidate classification (after the
        // first floor-raise read below) is the earliest consumer that needs it sorted, so the
        // sort overlaps the candidate gathering and read instead of the calling task. An
        // empty diff is already sorted and skips the job. While the job runs, `diff` is
        // empty. It is replaced by the sorted diff at the first `diff_sort` await.
        let mut diff_sort = None;
        if !diff.is_empty() {
            let unsorted = mem::take(&mut diff);
            diff_sort = Some(db.strategy().spawn(move |strategy| {
                let mut diff = unsorted;
                strategy.sort_by(&mut diff, |a, b| a.0.cmp(&b.0));
                diff
            }));
        }

        // New diff entries for keys moved by the floor raise, merged into `diff` below.
        let mut floor_diff = Vec::new();
        if total_active_keys > 0 {
            // Floor raise: advance the inactivity floor by `total_steps` active operations.
            // `fixed_tip` prevents scanning into floor-raise moves just appended.
            let strategy = db.strategy();
            let fixed_tip = *self.base_state.size + ops.len() as u64;
            let mut moved = 0u64;
            let mut scan_from = floor;
            floor_diff.reserve(total_steps as usize);

            // Locations are unique (each committed location belongs to exactly one key), so a
            // presorted collection needs neither the sort nor the dedup.
            if !superseded_locs.is_sorted_by(|a, b| a < b) {
                strategy.sort_by(&mut superseded_locs, |a, b| a.cmp(b));
                superseded_locs.dedup();
            }

            // The raise appends at most `total_steps` moved ops plus the CommitFloor. Reserve
            // once instead of growing mid-loop.
            ops.reserve(total_steps as usize + 1);

            // `fill_candidates` yields ascending locations, so superseded checks advance a
            // monotonic cursor.
            let mut superseded_cursor = 0;

            // Scan active operations in `[floor, fixed_tip)` and move them to the tip.
            while moved < total_steps {
                // Collect candidates, capped by the number of active ops still needed.
                // `scan_from` tracks prefetch progress separately from `floor`, so
                // early exit cannot leave `floor` past unprocessed candidates.
                let limit = (total_steps - moved) as usize;

                // Consume the prefetched committed prefix whole: it was gathered from the
                // same floor with the same bitmap, so it is a prefix of the sequence the
                // live scan would produce, and `next_scan` hands the live scan its
                // continuation point. Handing the raise more candidates than `limit` is
                // outcome-identical to fetching them across rounds: classification is pure
                // per candidate and the apply loop stops advancing once enough ops moved.
                let (mut candidates, pf_shards) = match prefetched.take() {
                    Some(pf) => {
                        scan_from = pf.next_scan;
                        (pf.locs, pf.shards)
                    }
                    None => (Vec::with_capacity(limit), Vec::new()),
                };
                if candidates.len() < limit {
                    scan_from = fill_candidates(
                        scan_from,
                        fixed_tip,
                        limit - candidates.len(),
                        &mut candidates,
                    );
                }
                if candidates.is_empty() {
                    break;
                }

                // The `sorted_contains` cursor relies on the candidate sequence ascending
                // across the whole raise. `floor` is one past the last processed candidate.
                assert!(candidates[0] >= floor);
                assert!(candidates.is_sorted_by(|a, b| a < b));

                // `read_candidates` omits locations already superseded by this diff, saving
                // their read. Keep `resolved` and `outcomes` in that filtered order, then
                // walk `candidates` below so superseded locations still advance the floor in
                // scan order. Prefetched candidates skip the filter -- their ops were read
                // ahead of time, and a superseded candidate's key always resolves in the
                // diff to a different location, classifying it `Inactive`.
                let pf_count: usize = pf_shards.iter().map(Vec::len).sum();
                assert!(pf_count <= candidates.len());
                let mut read_candidates: Vec<Location<F>> = Vec::with_capacity(candidates.len());
                read_candidates.extend_from_slice(&candidates[..pf_count]);
                for candidate in &candidates[pf_count..] {
                    if !sorted_contains(&superseded_locs, &mut superseded_cursor, candidate) {
                        read_candidates.push(*candidate);
                    }
                }
                let (resolved, outcomes): (_, Vec<Vec<FloorOutcome<F>>>) =
                    if read_candidates.is_empty() {
                        (Vec::new(), Vec::new())
                    } else {
                        // Batch-read candidates: page-cache hits are served by one batched read,
                        // disk misses are fetched concurrently. Prefetched shards enter as the
                        // reader probed them, ahead of the live suffix's read.
                        let live = &read_candidates[pf_count..];
                        let mut resolved = pf_shards;
                        if !live.is_empty() {
                            resolved.extend(self.read_ops_sharded(live, &ops, &db.log).await?);
                        }

                        // Classification is the first consumer of the sorted diff. By now the
                        // sort has overlapped the fill and read above.
                        if let Some(job) = diff_sort.take() {
                            diff = job.await;
                        }

                        // Classify read candidates against the pre-raise state (see
                        // [`FloorOutcome`]). Revalidation is required even for candidates whose
                        // committed bitmap bit is set: an uncommitted ancestor diff may supersede
                        // the committed location, and that is not reflected in the bitmap.
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

                        // Classification is already partitioned by candidate chunk, so use
                        // manual strategy execution and keep each location aligned with the
                        // operation resolved for the same filtered candidate. Chunks are
                        // subdivided past the pool parallelism because the snapshot probes
                        // that dominate classification have variable latency, so finer
                        // chunks balance the tail.
                        let manual = strategy.manual();
                        let target = read_candidates
                            .len()
                            .div_ceil(manual.parallelism() * 4)
                            .max(1);
                        let mut chunks: Vec<CandidateChunk<'_, F, U>> = Vec::new();
                        let mut offset = 0;
                        for chunk in &resolved {
                            let locs = &read_candidates[offset..offset + chunk.len()];
                            offset += chunk.len();
                            chunks.extend(locs.chunks(target).zip(chunk.chunks(target)));
                        }
                        let outcomes = manual.map_collect_vec(chunks, |(chunk_locs, chunk_ops)| {
                            chunk_locs
                                .iter()
                                .zip(chunk_ops)
                                .map(|(loc, op)| classify(*loc, op))
                                .collect()
                        });
                        (resolved, outcomes)
                    };

                // Apply in candidate order, moving active ops to the tip. `read_candidates`
                // preserves candidate order, so a candidate that does not match the next
                // pending read was superseded and only advances the floor.
                let mut outcomes = outcomes.into_iter().flatten();
                let mut reads = resolved.into_iter().flatten();
                let mut pending = read_candidates.iter().peekable();
                for candidate in candidates {
                    floor = candidate + 1;
                    if pending.next_if(|&&pending| pending == candidate).is_none() {
                        continue;
                    }
                    let op = reads.next().expect("one read per candidate");
                    let outcome = outcomes.next().expect("one outcome per read candidate");
                    match outcome {
                        FloorOutcome::Inactive => continue,
                        FloorOutcome::MoveExisting { idx, base_old_loc } => {
                            let new_loc = self.base_state.size + ops.len() as u64;
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
                            let new_loc = self.base_state.size + ops.len() as u64;
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
        } else {
            // DB is empty after this batch; raise floor to tip.
            floor = self.base_state.size + ops.len() as u64;
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        }

        // The floor raise may have exited without classifying any candidate (or been skipped
        // entirely). Every path below needs the sorted diff.
        if let Some(job) = diff_sort.take() {
            diff = job.await;
        }

        // Merge the floor raise's new diff entries as one job on the strategy: nothing below
        // reads `diff` until after the journal merkleization, so the merge overlaps the
        // hashing instead of the calling task. `floor_diff` only accumulates keys that were
        // not already present in `diff` (a key can only be moved once during this floor raise
        // because, after it is moved, its new location lies above `fixed_tip` and the scan
        // never revisits it), so the merge inputs are disjoint.
        let mut diff_merge = None;
        if !floor_diff.is_empty() {
            diff_merge = Some(db.strategy().spawn(move |strategy| {
                let mut floor_diff = floor_diff;
                strategy.sort_by(&mut floor_diff, |a, b| a.0.cmp(&b.0));
                let diff = merge_sorted_diffs(diff, floor_diff);
                assert!(diff.is_sorted_by(|a, b| a.0 < b.0));
                diff
            }));
            diff = Vec::new();
        }

        // CommitFloor operation.
        let commit_loc = self.base_state.size + ops.len() as u64;
        ops.push(Operation::CommitFloor(metadata, floor));

        // Merkleize the journal batch.
        // The journal batch was created eagerly at batch construction time and its
        // parent already contains all prior batches' Merkle state, so we only
        // add THIS batch's operations. Parent operations are never re-cloned,
        // re-encoded, or re-hashed.
        let leaves = self.base_state.size + ops.len() as u64;
        let inactive_peaks = db.inactive_peaks(leaves, floor);

        // Leaf and node hashing dominate merkleization, so run them as one job on the
        // strategy instead of occupying the calling task (see `Journal::merkleize`).
        let (journal, root) = db
            .log
            .merkleize(self.journal_batch, ops, inactive_peaks)
            .await?;
        if let Some(job) = diff_merge.take() {
            diff = job.await;
        }

        // A retained ancestor's `base_old_loc` traces back to the DB boundary at which its chain
        // was originally created. If an older committed prefix has since dropped out of the Weak
        // chain, resolve keys touched on both sides of that boundary to their location after the
        // dropped prefix. Keeping only the intersection avoids retaining the prefix's value diffs.
        let ancestor_base_locs = self.ancestors.last().map_or_else(Vec::new, |oldest| {
            if oldest.ancestor_diffs.iter().all(|diff| diff.is_empty()) {
                return Vec::new();
            }
            let mut dropped =
                DiffCursors::new(oldest.ancestor_diffs.iter().map(|diff| diff.as_slice()));
            DiffMerge::new(
                self.ancestors
                    .iter()
                    .map(|ancestor| ancestor.diff.as_slice()),
            )
            .filter_map(|(key, _)| dropped.resolve(key).map(|entry| (key.clone(), entry.loc())))
            .collect()
        });
        let ancestor_diffs: Vec<_> = self.ancestors.iter().map(|a| Arc::clone(&a.diff)).collect();
        let ancestors: Vec<_> = self
            .ancestors
            .iter()
            .map(|a| batch_chain::AncestorBounds {
                floor: a.bounds.inactivity_floor,
                state: a.commitment(),
            })
            .collect();

        assert!(total_active_keys >= 0, "active_keys underflow");
        Ok(Arc::new(MerkleizedBatch {
            journal_batch: journal,
            diff: Arc::new(diff),
            diff_index: Arc::new(DiffIndex::default()),
            parent: self.ancestors.first().map(Arc::downgrade),
            total_active_keys: total_active_keys as usize,
            ancestor_diffs,
            ancestor_base_locs,
            bounds: batch_chain::Bounds {
                base: self.base_state,
                db: self.db_state,
                tip: Commitment::new(commit_loc + 1, root),
                ancestors,
                inactivity_floor: floor,
            },
        }))
    }
}

impl<F: Family, H, U, S: Strategy> UnmerkleizedBatch<F, H, U, S>
where
    U: update::Update,
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
        let db_state = batch_chain::effective_boundary(
            self.base.db(),
            ancestors.last().map(|oldest| oldest.bounds.base),
        );
        let m = Merkleizer {
            journal_batch: self.journal_batch,
            ancestors,
            base_state: self.base.base_state(),
            db_state,
            base_inactivity_floor_loc: self.base.inactivity_floor_loc(),
            base_active_keys: self.base.active_keys(),
        };
        (self.mutations, m)
    }
}

impl<F: Family, H, U, S: Strategy> Staged<F, H, U, S>
where
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Expand this staged batch with more reads.
    ///
    /// Existing read indices remain stable. Newly read keys are appended to the staged read set and
    /// assigned the returned range. The returned values are in the same order as `keys`.
    ///
    /// Expansion does not deduplicate against previously staged keys. Reading the same key again
    /// creates another staged slot in the returned range. If both slots are later updated,
    /// [`merkleize`](Staged::merkleize) applies the update list's normal last-write-wins
    /// semantics.
    ///
    /// Expansion reads through the underlying batch, ancestor batches, and committed database state.
    /// Values the caller has computed for earlier staged slots are not visible until they are passed
    /// to [`merkleize`](Staged::merkleize). Callers that need speculative read-your-writes behavior
    /// should maintain their own overlay while deciding which staged slots to update.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.any.batch.expand",
        level = "info",
        skip_all,
        fields(keys = keys.len() as u64, staged = self.keys.len() as u64),
    )]
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
        let (values, keys, mut resolutions) = self.batch.stage_reads(keys, db).await?;
        self.keys.extend(keys);
        self.resolutions.append(&mut resolutions);
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

    /// Resolve the caller's updates and upserts against the staged read set, returning the
    /// underlying batch (with fallback mutations recorded) and the staged updates to consume at
    /// merkleize.
    ///
    /// Each update is `(read_index, value)`, where `read_index` is the position of the key in the
    /// staged read set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) inputs. `value` is `Some(v)` for an upsert or `None` for a
    /// delete. Duplicate keys retain last-write-wins semantics according to the update order.
    /// Upserts are `(key, value)` writes (`None` deletes) for keys outside the staged read set.
    /// Upserts are applied last. If a caller passes an overlapping key, the upsert follows normal
    /// `write` semantics and wins.
    ///
    /// Location-resolved updates (committed, or ancestor-diff when the update kind stages
    /// those -- see [`update::Update::STAGES_ANCESTORS`]) reuse the staged location. Resolved
    /// deletes reuse it only when [`update::Update::STAGES_DELETES`] is set (the unordered
    /// kind). Unresolved keys (missing from committed state, resolved through this batch's
    /// own mutations, or ancestor-resolved for a kind that does not stage those) always fall
    /// back to normal mutations.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub(crate) fn resolve_updates(
        self,
        updates: Vec<(usize, Option<U::Value>)>,
        upserts: Vec<(U::Key, Option<U::Value>)>,
        strategy: &S,
    ) -> (UnmerkleizedBatch<F, H, U, S>, StagedUpdates<F, U>) {
        let Self {
            mut batch,
            keys,
            mut resolutions,
        } = self;
        let mut staged_updates = StagedUpdates::<F, U>::new();
        if updates.is_empty() {
            return (Self::apply_upserts(batch, upserts), staged_updates);
        }

        // Resolve last-write-wins per distinct key: a forward walk keyed on the staged key leaves
        // each key's final write, the same winner as a newest-first scan. Later writes overwrite
        // their key's entry in place, so `winners` holds one entry per distinct key written. A
        // distinct key needs a staged slot, so the staged read set caps the reservation that a
        // duplicate-heavy update list would otherwise inflate.
        let capacity = updates.len().min(keys.len());
        let mut winner_of: AHashMap<&U::Key, usize> = AHashMap::with_capacity(capacity);
        let mut winners: Vec<Option<(usize, Option<U::Value>)>> = Vec::with_capacity(capacity);
        for (slot, value) in updates {
            assert!(slot < keys.len(), "update index out of staged read range");
            match winner_of.entry(&keys[slot]) {
                hash_map::Entry::Vacant(vacant) => {
                    vacant.insert(winners.len());
                    winners.push(Some((slot, value)));
                }
                hash_map::Entry::Occupied(occupied) => {
                    winners[*occupied.get()] = Some((slot, value))
                }
            }
        }

        // Upserts are applied last and win over overlapping staged updates. Only updated keys can
        // overlap, so this probes the winner index rather than the whole staged read set.
        for (key, _) in &upserts {
            if let Some(&entry) = winner_of.get(key) {
                winners[entry] = None;
            }
        }
        drop(winner_of);

        // Split the winners: updates whose slot resolved to a location become staged
        // updates, the rest fall back to batch mutations. A surviving staged write must not
        // also emit an older batch mutation for the same key, so it is removed here. The
        // probe is skipped when the batch had no mutations before this call: each distinct
        // key is visited at most once (winners are per key), so a staged winner can never
        // chase a fallback inserted by this same loop.
        let had_mutations = !batch.mutations.is_empty();
        let mut order: Vec<(Location<F>, usize)> = Vec::with_capacity(winners.len());
        for (entry, winner) in winners.iter_mut().enumerate() {
            let Some((slot, value)) = winner else {
                continue;
            };
            let key = &keys[*slot];
            match &resolutions[*slot] {
                Some((sloc, _)) if value.is_some() || U::STAGES_DELETES => {
                    if had_mutations {
                        batch.mutations.remove(key);
                    }
                    order.push((sloc.loc(), entry));
                }
                _ => {
                    let (_, value) = winner.take().expect("winner checked above");
                    batch.mutations.insert(key.clone(), value);
                }
            }
        }

        // Locations are unique after last-write-wins dedup (each key resolves to exactly one
        // location, committed or ancestor), so the parallel sort is deterministic. Sorting
        // compact `(location, winner)` pairs instead of the staged tuples keeps its memory
        // traffic low. The tuples are then drained in sorted order, moving each winner's
        // payload and value instead of cloning them.
        strategy.sort_by(&mut order, |a, b| a.0.cmp(&b.0));
        staged_updates = order
            .iter()
            .map(|&(_, entry)| {
                let (slot, value) = winners[entry]
                    .take()
                    .expect("winner recorded for staged slot");
                let (sloc, payload) = resolutions[slot].take().expect("resolution checked above");
                (keys[slot].clone(), sloc, payload, value)
            })
            .collect();
        (Self::apply_upserts(batch, upserts), staged_updates)
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
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) ranges. `metadata` is committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.any.unordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(updates = updates.len() as u64, upserts = upserts.len() as u64),
    )]
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
        let (batch, staged_updates, prefetched) = self
            .resolve_updates_prefetched(updates, upserts, db, |floor, tip, limit, out| {
                fill_candidates(&db.bitmap, floor, tip, limit, out)
            })
            .await?;
        batch
            .merkleize_with_floor_scan(
                db,
                metadata,
                staged_updates,
                Some(prefetched),
                |floor, tip, limit, out| fill_candidates(&db.bitmap, floor, tip, limit, out),
            )
            .await
    }

    /// Resolve the caller's updates on the strategy pool while gathering and reading the
    /// committed prefix of the floor-raise candidates, overlapping the two. Returns the
    /// resolved batch, the staged updates, and the prefetched candidates to seed
    /// [`merkleize_with_floor_scan`](UnmerkleizedBatch::merkleize_with_floor_scan) with.
    ///
    /// `fill_candidates` must be the same candidate source the subsequent floor raise
    /// scans, so the prefetched prefix continues seamlessly into the live scan (see
    /// [`PrefetchedCandidates`]). The gather is clamped to the committed boundary: a
    /// speculative source (e.g. the current variant's parent bitmap) extends past it, but
    /// its candidate sequence below the boundary is identical and only committed locations
    /// are servable by the log read.
    ///
    /// On early exhaustion of the committed set bits, sources may hand back either one past
    /// the last emitted candidate or the committed boundary as the continuation point. Both
    /// are correct: the skipped span holds no set bits, and the source cannot change during
    /// the call (commits and prunes take `&mut` on the database).
    #[allow(clippy::type_complexity)]
    pub(crate) async fn resolve_updates_prefetched<E, C, I, const N: usize>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        mut fill_candidates: impl FnMut(Location<F>, u64, usize, &mut Vec<Location<F>>) -> Location<F>,
    ) -> Result<
        (
            UnmerkleizedBatch<F, H, update::Unordered<K, V>, S>,
            StagedUpdates<F, update::Unordered<K, V>>,
            PrefetchedCandidates<F, update::Unordered<K, V>>,
        ),
        crate::qmdb::Error<F>,
    >
    where
        E: Context,
        C: Contiguous<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        // Bound the steps the floor raise can take: only emitted ops consume steps, and an
        // op is emitted per location-resolved update plus per upsert or prior mutation on a
        // key alive in the committed snapshot. Fresh-key creates never consume a step, so
        // unresolved update slots and writes missing from the snapshot are excluded (one
        // in-memory probe per key). The bound is approximate in both directions. Surplus
        // candidates (a translated-key collision, or a key an ancestor already deleted) are
        // dropped by the raise once it moves enough ops, and a shortfall (a write resolving
        // only through an ancestor diff) makes the raise fall back to the live scan when
        // the prefetched prefix runs out.
        let resolved_updates = updates
            .iter()
            .filter(|(slot, _)| self.resolutions.get(*slot).is_some_and(Option::is_some))
            .count()
            .min(self.keys.len());
        let existing_writes = upserts
            .iter()
            .map(|(key, _)| key)
            .chain(self.batch.mutations.keys())
            .filter(|&key| db.snapshot.get(key).next().is_some())
            .count();
        let steps_bound = resolved_updates + existing_writes + 1;

        // Overlap the serial update resolution with the candidate prefetch: the
        // committed-prefix candidate set depends only on the base floor, the candidate
        // source, and the step bound, none of which depend on the resolution. The batch
        // moves into the job, so its floor is captured first.
        let scan_from = self.batch.base.inactivity_floor_loc();
        let resolve = db
            .strategy()
            .spawn(move |strategy| self.resolve_updates(updates, upserts, &strategy));

        // Gather the committed-prefix candidates and read their operations, sharded, while
        // the resolution job runs.
        let committed_tip = bitmap::Readable::<N>::len(&*db.bitmap);
        let mut locs: Vec<Location<F>> = Vec::with_capacity(steps_bound);
        let next_scan = fill_candidates(scan_from, committed_tip, steps_bound, &mut locs);
        let raw: Vec<u64> = locs.iter().map(|loc| **loc).collect();
        let read = db.log.read_many_sharded(&raw).await;

        // Join the resolution and surface any read failure.
        let (batch, staged_updates) = resolve.await;
        let prefetched = PrefetchedCandidates {
            locs,
            shards: read?,
            next_scan,
        };
        Ok((batch, staged_updates, prefetched))
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
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) ranges. `metadata` is committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.any.ordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(updates = updates.len() as u64, upserts = upserts.len() as u64),
    )]
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
        let (batch, staged_updates) = self.resolve_updates(updates, upserts, db.strategy());
        batch
            .merkleize_with_floor_scan(db, metadata, staged_updates, |floor, tip, limit, out| {
                fill_candidates(&db.bitmap, floor, tip, limit, out)
            })
            .await
    }
}

// Generic get() for both ordered and unordered UnmerkleizedBatch.
impl<F: Family, H, U, S: Strategy> UnmerkleizedBatch<F, H, U, S>
where
    U: update::Update,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Return true when reads can bypass uncommitted overlay resolution and go directly to the DB.
    fn reads_committed_only(&self) -> bool {
        self.mutations.is_empty() && self.base.parent().is_none()
    }

    /// Resolve keys against this batch's mutations and any live ancestor diffs, returning partial
    /// results and the unresolved slots that still need committed DB reads.
    ///
    /// `on_diff_hit` is invoked with each slot resolved by an ancestor diff entry (slots
    /// resolved by this batch's mutations do not report), so staged reads can record
    /// ancestor resolutions.
    fn resolve_uncommitted_reads<'a>(
        &self,
        keys: &[&'a U::Key],
        strategy: &S,
        on_diff_hit: impl FnMut(usize, &DiffEntry<F, U::Value>),
    ) -> UncommittedReadResolution<'a, U::Key, U::Value>
    where
        U::Value: Send + Sync,
    {
        let ancestors = self.base.parent().map(|parent| {
            let mut ancestors = vec![Arc::clone(parent)];
            ancestors.extend(parent.ancestors());
            ancestors
        });
        let diffs: Vec<_> = ancestors
            .iter()
            .flatten()
            .map(|batch| DiffSource {
                entries: batch.diff.as_slice(),
                index: &batch.diff_index,
            })
            .collect();
        resolve_reads(
            keys,
            |key| self.mutations.get(key).cloned(),
            &diffs,
            strategy,
            on_diff_hit,
        )
    }

    /// Read unresolved slots from the committed DB and merge them back into `results`.
    async fn fill_committed_reads<E, C, I, T: Send, const N: usize>(
        unresolved: Vec<PendingRead<'_, U::Key>>,
        db: &Db<F, E, C, I, H, U, N, S>,
        results: &mut [Option<U::Value>],
        map: impl Fn(&U, Location<F>) -> T + Send + Sync,
        mut apply: impl FnMut(usize, T) -> U::Value,
    ) -> Result<(), crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        if unresolved.is_empty() {
            return Ok(());
        }

        let db_keys: Vec<_> = unresolved.iter().map(|(_, key)| *key).collect();
        let db_results = db.get_many_map(&db_keys, map).await?;
        for ((slot, _), result) in unresolved.into_iter().zip(db_results) {
            results[slot] = result.map(|value| apply(slot, value));
        }
        Ok(())
    }

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
    /// keys. Resolved locations are not retained, so writing a key read only through `get_many`
    /// requires an index re-probe and journal re-read during merkleize. Use
    /// [`stage`](Self::stage) for keys that may be written. When the writable subset is known and
    /// much smaller than the full read set, call `get_many` for the read-only keys first, then
    /// [`stage`](Self::stage) only the writable keys.
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
        if self.reads_committed_only() {
            return db.get_many(keys).await;
        }

        let (mut results, unresolved) =
            self.resolve_uncommitted_reads(keys, db.strategy(), |_, _| {});
        Self::fill_committed_reads(
            unresolved,
            db,
            &mut results,
            |data, _| data.value().clone(),
            |_, value| value,
        )
        .await?;

        Ok(results)
    }

    /// Batch read multiple keys and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys. The staged batch records updates by
    /// read index: the initial keys occupy `0..keys.len()`, and each
    /// [`expand`](Staged::expand) appends another index range. Unlike
    /// [`get_many`](Self::get_many), the resolved locations are reused at merkleize, so keys
    /// that are read and then written skip the index re-probe and journal re-read.
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(
        name = "qmdb.any.batch.stage",
        level = "info",
        skip_all,
        fields(keys = keys.len() as u64),
    )]
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
        let (results, keys, resolutions) = self.stage_reads(keys, db).await?;
        Ok((
            results,
            Staged {
                batch: self,
                keys,
                resolutions,
            },
        ))
    }

    /// Read keys through this batch and return the values plus one owned key and resolution per
    /// staged slot. Location-resolved slots (committed, or ancestor-diff when the update kind
    /// stages those) carry the location and cached payload they resolved to.
    #[allow(clippy::type_complexity)]
    async fn stage_reads<E, C, I, const N: usize>(
        &self,
        keys: &[&U::Key],
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<
        (
            Vec<Option<U::Value>>,
            Vec<U::Key>,
            Vec<StagedResolution<F, U>>,
        ),
        crate::qmdb::Error<F>,
    >
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>> + 'static,
    {
        let mut resolutions: Vec<StagedResolution<F, U>> =
            iter::repeat_with(|| None).take(keys.len()).collect();

        // Record ancestor-diff resolutions when the update kind stages them: the staged
        // write then reuses the resolved location at merkleize instead of falling back to a
        // normal mutation (whose cost -- location gathering, a journal re-read, and
        // per-key ancestor re-resolution -- otherwise grows with ancestor overlap).
        let (mut results, unresolved) =
            self.resolve_uncommitted_reads(keys, db.strategy(), |slot, entry| {
                let Some(cached) = U::STAGES_ANCESTORS else {
                    return;
                };
                if let DiffEntry::Active {
                    loc, base_old_loc, ..
                } = entry
                {
                    resolutions[slot] = Some((
                        StagedLoc::Ancestor {
                            loc: *loc,
                            base_old_loc: *base_old_loc,
                        },
                        cached,
                    ));
                }
            });
        Self::fill_committed_reads(
            unresolved,
            db,
            &mut results,
            |data, loc| (data.value().clone(), loc, data.cached()),
            |slot, (value, loc, payload)| {
                resolutions[slot] = Some((StagedLoc::Committed(loc), payload));
                value
            },
        )
        .await?;
        Ok((
            results,
            keys.iter().map(|key| (*key).to_owned()).collect(),
            resolutions,
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
        self.merkleize_with_floor_scan(
            db,
            metadata,
            StagedUpdates::<F, update::Unordered<K, V>>::new(),
            None,
            |floor, tip, limit, out| fill_candidates(&db.bitmap, floor, tip, limit, out),
        )
        .await
    }

    /// Like [`merkleize`](Self::merkleize), but consumes staged updates recorded by
    /// [`Staged::merkleize`] (loaded keys skip the journal re-read their resolution would
    /// otherwise require) and accepts the floor-raise candidate source, optionally seeded
    /// with prefetched committed-prefix candidates that must come from the same floor and
    /// the same candidate source the callback scans (see [`PrefetchedCandidates`]).
    ///
    /// The callback must yield candidates in ascending location order, both within one call
    /// and across successive calls (the floor raise asserts this). It may skip locations only
    /// when it knows they are inactive. The floor-raise loop revalidates each returned
    /// candidate against the batch diff, ancestor diffs, and snapshot because the bitmap
    /// reflects committed state only -- uncommitted ancestor ops aren't tracked, and bits can
    /// be set for locations superseded by an overlay in this chain.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        staged_updates: StagedUpdates<F, update::Unordered<K, V>>,
        prefetched: Option<PrefetchedCandidates<F, update::Unordered<K, V>>>,
        fill_candidates: impl FnMut(Location<F>, u64, usize, &mut Vec<Location<F>>) -> Location<F>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Unordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let (mut mutations, m) = self.into_parts();

        // Resolve existing keys.
        let locations = m.gather_existing_locations(&mutations, db, false);
        let results = m.read_ops(&locations, &[], &db.log).await?;

        // Generate user mutation operations.
        let mut ops: Vec<Operation<F, update::Unordered<K, V>>> =
            Vec::with_capacity(mutations.len() + staged_updates.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> =
            Vec::with_capacity(mutations.len() + staged_updates.len());

        // Committed locations superseded by this batch, collected for the floor raise (which
        // skips re-reading them). Emission order is ascending in `base_old_loc` except for
        // entries resolved through ancestor diffs, so `finish` usually skips its sort.
        let mut superseded_locs: Vec<Location<F>> = Vec::with_capacity(diff.capacity());
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;

        // Write a user mutation at the next batch location, preserving the previous committed
        // location of the key it supersedes.
        let mut emit = |key: K, base_old_loc: Option<Location<F>>, mutation: Option<V::Value>| {
            let new_loc = m.base_state.size + ops.len() as u64;
            superseded_locs.extend(base_old_loc);
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

        // Process updates/deletes of existing keys in location order, merging staged entries
        // into the read results. This includes keys from both the committed snapshot and ancestor
        // diffs. A staged entry's `value` is `Some` for an update and `None` for a delete, and
        // `emit` writes it as an `Update`/`Delete` at the staged location. An ancestor-staged
        // entry orders by its ancestor location but supersedes the key's committed base
        // location, exactly as its mutation-fallback path would have.
        //
        // A staged location below the merkleize-time committed boundary means the resolving
        // ancestor has committed and dropped out of the alive chain, retiring the recorded
        // base (see [`StagedLoc`]). The location itself is then the committed location this
        // write supersedes, matching what the fallback path's live-snapshot resolution would
        // produce. Resolutions whose ancestor is still alive keep their recorded base. If
        // that ancestor commits before this batch is applied, `apply_batch` resolves the
        // key in the ancestor's traveling diff and supersedes its entry's location instead.
        let staged_base_old_loc = |sloc: StagedLoc<F>| match sloc {
            StagedLoc::Committed(loc) => Some(loc),
            StagedLoc::Ancestor { loc, .. } if *loc < m.db_state.size => Some(loc),
            StagedLoc::Ancestor { base_old_loc, .. } => base_old_loc,
        };
        let mut cached = staged_updates.into_iter().peekable();
        for (op, &old_loc) in results.iter().zip(&locations) {
            while cached
                .peek()
                .is_some_and(|&(_, sloc, (), _)| sloc.loc() < old_loc)
            {
                let (key, sloc, (), mutation) = cached.next().expect("peeked entry exists");
                emit(key, staged_base_old_loc(sloc), mutation);
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
        for (key, sloc, (), mutation) in cached {
            emit(key, staged_base_old_loc(sloc), mutation);
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
        creates.extend(parent_deleted_creates);
        db.strategy()
            .sort_by(&mut creates, |(a, _, _), (b, _, _)| a.cmp(b));
        for (key, value, base_old_loc) in creates {
            let new_loc = m.base_state.size + ops.len() as u64;
            superseded_locs.extend(base_old_loc);
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

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(
            ops,
            diff,
            superseded_locs,
            active_keys_delta,
            user_steps,
            metadata,
            prefetched,
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
        self.merkleize_with_floor_scan(
            db,
            metadata,
            StagedUpdates::<F, update::Ordered<K, V>>::new(),
            |floor, tip, limit, out| fill_candidates(&db.bitmap, floor, tip, limit, out),
        )
        .await
    }

    /// Like [`merkleize`](Self::merkleize), but consumes staged updates recorded by
    /// [`Staged::merkleize`] (loaded keys skip the index probe and journal re-read their
    /// resolution would otherwise require: the caller's new value and the cached next key feed
    /// op generation directly) and accepts the floor-raise candidate source.
    ///
    /// The callback must yield candidates in ascending location order, both within one call
    /// and across successive calls (the floor raise asserts this). It may skip locations only
    /// when it knows they are inactive. The floor-raise loop revalidates each returned
    /// candidate against the batch diff, ancestor diffs, and snapshot because the bitmap
    /// reflects committed state only -- uncommitted ancestor ops aren't tracked, and bits can
    /// be set for locations superseded by an overlay in this chain.
    pub(crate) async fn merkleize_with_floor_scan<E, C, I, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        staged_updates: StagedUpdates<F, update::Ordered<K, V>>,
        fill_candidates: impl FnMut(Location<F>, u64, usize, &mut Vec<Location<F>>) -> Location<F>,
    ) -> Result<Arc<MerkleizedBatch<F, H::Digest, update::Ordered<K, V>, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        let (mut mutations, m) = self.into_parts();

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

        // Merge staged-resolved updates: they skip the index probe and journal re-read, and
        // their old op's next_key and (key, loc) feed the candidate sets exactly as the skipped
        // journal read would have. No prev-candidate value is stored: it is only consumed when
        // the predecessor-rewrite loop emits an op for the key, and that loop skips every key
        // present in `updated`. The ordered path never stages deletes (see
        // `Staged::resolve_updates`), so every staged entry carries a value.
        for (key, sloc, old_next, value) in staged_updates {
            let value = value.expect("ordered path never stages deletes");
            let StagedLoc::Committed(loc) = sloc else {
                unreachable!("ordered path never stages ancestor resolutions")
            };
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
            let new_loc = m.base_state.size + ops.len() as u64;
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
            let new_loc = m.base_state.size + ops.len() as u64;
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
                let prev_new_loc = m.base_state.size + ops.len() as u64;
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

        // Committed locations superseded by this batch, for the floor raise (`finish` sorts
        // the diff itself).
        let superseded_locs: Vec<_> = diff
            .iter()
            .filter_map(|(_, entry)| entry.base_old_loc())
            .collect();

        // Remaining phases: floor raise, CommitFloor, journal, diff merge.
        m.finish(
            ops,
            diff,
            superseded_locs,
            active_keys_delta,
            user_steps,
            metadata,
            None,
            fill_candidates,
            db,
        )
        .await
    }
}

impl<F: Family, D: Digest, U: update::Update, S: Strategy> MerkleizedBatch<F, D, U, S> {
    /// Return the speculative root.
    pub const fn root(&self) -> D {
        self.bounds.tip.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F, D> {
        &self.bounds
    }

    /// Iterate over ancestor batches (parent first, then grandparent, etc.). Stops when a
    /// Weak ref fails to upgrade (ancestor was freed).
    pub(crate) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, U, S> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }

    /// The [`Commitment`] this batch commits to.
    pub(crate) const fn commitment(&self) -> Commitment<F, D> {
        self.bounds.tip
    }
}

impl<F: Family, D: Digest, U: update::Update, S: Strategy> MerkleizedBatch<F, D, U, S>
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
            base_size = *self.bounds.base.size,
            total_size = *self.bounds.tip.size,
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
        if let Some(entry) = self.diff_index.lookup(self.diff.as_slice(), key) {
            return Ok(entry.value().cloned());
        }
        // Walk parent chain. If a parent was freed (committed and dropped), the iterator
        // stops and we fall through to DB.
        for batch in self.ancestors() {
            if let Some(entry) = batch.diff_index.lookup(batch.diff.as_slice(), key) {
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

        let ancestors: Vec<_> = self.ancestors().collect();
        let diffs: Vec<_> = ancestors
            .iter()
            .map(|batch| DiffSource {
                entries: batch.diff.as_slice(),
                index: &batch.diff_index,
            })
            .collect();
        let initialize = DiffIndex::should_initialize(self.diff.len(), keys.len());
        let (mut results, unresolved) = resolve_reads(
            keys,
            |key| {
                let entry = if initialize {
                    self.diff_index
                        .lookup_or_initialize(self.diff.as_slice(), key)
                } else {
                    self.diff_index.lookup(self.diff.as_slice(), key)
                };
                entry.map(|entry| entry.value().cloned())
            },
            &diffs,
            db.strategy(),
            |_, _| {},
        );

        if !unresolved.is_empty() {
            let db_keys: Vec<_> = unresolved.iter().map(|(_, key)| *key).collect();
            let db_results = db.get_many(&db_keys).await?;
            for ((slot, _), value) in unresolved.into_iter().zip(db_results) {
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
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: update::Update,
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
        UnmerkleizedBatch {
            journal_batch: self.log.new_batch(),
            mutations: BTreeMap::new(),
            base: Base::Db {
                state: self.commitment(),
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
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    U: update::Update,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Check that `batch` can be applied to the database in its current state, without
    /// applying it.
    ///
    /// [`Self::apply_batch`] runs the same validation but consumes the database when it
    /// fails; callers that want to reject a bad batch and keep the handle can check first.
    pub fn validate_batch(
        &self,
        batch: &MerkleizedBatch<F, H::Digest, U, S>,
    ) -> Result<(), crate::qmdb::Error<F>> {
        batch
            .bounds
            .validate_apply_to(self.commitment(), self.inactivity_floor_loc)
    }

    /// Apply a batch to the database, returning the range of written operations.
    ///
    /// A batch is valid only if every batch applied to the database since this batch's
    /// ancestor chain was created is an ancestor of this batch. Applying a batch from a
    /// different fork returns [`crate::qmdb::Error::StaleBatch`] (see
    /// [`crate::qmdb::batch_chain`] for more details).
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal,
    /// but does not durably persist it. Call [`Db::commit`] or [`Db::sync`], or await the handle
    /// returned by [`Db::start_sync`], to guarantee durability.
    #[tracing::instrument(
        name = "qmdb.any.db.apply_batch",
        level = "info",
        skip_all,
        fields(
            batch_total_size = *batch.bounds.tip.size,
            batch_base_size = *batch.bounds.base.size,
            db_size = *self.last_commit_loc + 1,
            ancestor_batches = batch.ancestor_diffs.len() as u64,
        ),
    )]
    pub async fn apply_batch(
        mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, U, S>>,
    ) -> Result<(Self, Range<Location<F>>), crate::qmdb::Error<F>> {
        let _timer = self.metrics.apply_batch_timer();
        self.metrics.apply_batch_calls.inc();
        self.validate_batch(&batch)?;
        let db_size = *self.last_commit_loc + 1;
        let start_loc = Location::new(db_size);

        // The journal append and the in-memory index application touch disjoint state (the log vs
        // the snapshot and bitmap), so run them concurrently. The index application is spawned as a
        // job on the strategy while the journal append proceeds on this task. A journal failure
        // leaves the instance unusable either way (mutable storage failures are fatal and consume
        // the database), so the index job's effects on error do not need to be rolled back.
        let strategy = self.strategy().clone();
        let log = self.log;
        let snapshot = self.snapshot;
        let index_batch = Arc::clone(&batch);
        let index_bitmap = Arc::clone(&self.bitmap);
        let last_commit_loc = self.last_commit_loc;

        let index_job = strategy.spawn(move |_| {
            let mut snapshot = snapshot;
            apply_batch_to_index(
                &mut snapshot,
                &mut index_bitmap.write(),
                &index_batch,
                last_commit_loc,
            );
            snapshot
        });

        // Apply journal (handles its own partial ancestor skipping) while the index job runs.
        let (log, snapshot) = futures::join!(log.apply_batch(&batch.journal_batch), index_job);
        self.log = log?;
        self.snapshot = snapshot;

        // Update DB metadata.
        self.active_keys = batch.total_active_keys;
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        self.last_commit_loc = batch.bounds.tip.size - 1;
        self.root = batch.root();

        // Return range of operations that were written to the log.
        let end_loc = self.last_commit_loc + 1;
        let range = start_loc..end_loc;
        self.update_metrics();
        self.metrics
            .operations_applied
            .inc_by(*range.end - *range.start);
        Ok((self, range))
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: update::Update,
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
        Arc::new(MerkleizedBatch {
            journal_batch: self.log.to_merkleized_batch(),
            diff: Arc::new(Vec::new()),
            diff_index: Arc::new(DiffIndex::default()),
            parent: None,
            total_active_keys: self.active_keys,
            ancestor_diffs: Vec::new(),
            ancestor_base_locs: Vec::new(),
            bounds: batch_chain::Bounds::from_db(self.commitment(), self.inactivity_floor_loc),
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
        ApplyBatchResult, BatchableDb, MerkleizedBatch as MerkleizedBatchTrait,
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

    impl<F: Family, D: Digest, U: update::Update, S: Strategy> MerkleizedBatchTrait
        for Arc<MerkleizedBatch<F, D, U, S>>
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
        I: UnorderedIndex<Value = Location<F>> + 'static,
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
            self,
            batch: Self::Merkleized,
        ) -> impl Future<Output = ApplyBatchResult<Self>> {
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
        I: OrderedIndex<Value = Location<F>> + 'static,
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
    use crate::{
        mmr,
        qmdb::any::{
            BITMAP_CHUNK_BYTES,
            ordered::fixed::Db as OrderedFixedDb,
            test::{colliding_digest, fixed_db_config},
            unordered::fixed::Db as UnorderedFixedDb,
            value::FixedEncoding,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::test_rng;
    use rand::RngExt as _;
    use std::{
        sync::{
            Barrier, Weak as ArcWeak,
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
        },
        thread,
    };

    const BITMAP_CHUNK_BITS: u64 = bitmap::Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS;

    fn loc(n: u64) -> Location<mmr::Family> {
        Location::new(n)
    }

    fn committed(n: u64) -> StagedLoc<mmr::Family> {
        StagedLoc::Committed(loc(n))
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
            let num_diffs = rng.random_range(1..=4);
            let diffs: Vec<DiffVec<u64, mmr::Family, u64>> = (0..num_diffs)
                .map(|d| {
                    let mut keys: Vec<u64> = (0..rng.random_range(0..30))
                        .map(|_| rng.random_range(0..50u64))
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
            let mut queries: Vec<u64> = (0..rng.random_range(1..60))
                .map(|_| rng.random_range(0..55u64))
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

    /// Sparse lookup must preserve full binary search for hits, misses, and queries around every
    /// sampled range boundary.
    #[test]
    fn diff_index_matches_lookup_sorted() {
        for len in [0, 1, 16, 17, 10_000] {
            let entries: Vec<_> = (0..len as u64)
                .map(|key| (((key * 2) << 32).to_be_bytes().to_vec(), key * 3))
                .collect();
            let index = DiffIndex::default();

            for key in 0..(len as u64 * 2 + 2) {
                let key = (key << 32).to_be_bytes().to_vec();
                let expected = lookup_sorted(&entries, &key).copied();
                let actual = index.lookup_or_initialize(&entries, &key).copied();
                assert_eq!(actual, expected, "len {len}, query {key:?} diverged");
            }
        }
    }

    /// A directory whose hints cannot distinguish any sampled ranges must use the full lookup
    /// path without retaining one redundant hint per stride.
    #[test]
    fn diff_index_declines_constant_prefixes() {
        let entries: Vec<_> = (0..10_000u64)
            .map(|key| (key.to_be_bytes().to_vec(), key * 3))
            .collect();
        let index = DiffIndex::default();

        assert!(index.hints(&entries).is_empty());
        for key in [0u64, 1, 4_999, 9_999, 10_000] {
            let key = key.to_be_bytes().to_vec();
            let expected = lookup_sorted(&entries, &key).copied();
            let actual = index.lookup(&entries, &key).copied();
            assert_eq!(actual, expected);
        }
    }

    /// A directory with almost no distinct sampled prefixes cannot narrow enough ranges to
    /// amortize its retained memory and must use the full lookup path.
    #[test]
    fn diff_index_declines_duplicate_heavy_prefixes() {
        let entries: Vec<_> = (0..10_000u64)
            .map(|key| {
                let prefix = u32::from(key >= 9_992);
                let mut bytes = Vec::with_capacity(12);
                bytes.extend_from_slice(&prefix.to_be_bytes());
                bytes.extend_from_slice(&key.to_be_bytes());
                (bytes, key)
            })
            .collect();
        let index = DiffIndex::default();

        assert!(index.hints(&entries).is_empty());
        for key in [0u64, 4_999, 9_991, 9_992, 9_999] {
            let prefix = u32::from(key >= 9_992);
            let mut query = Vec::with_capacity(12);
            query.extend_from_slice(&prefix.to_be_bytes());
            query.extend_from_slice(&key.to_be_bytes());
            assert_eq!(index.lookup(&entries, &query).copied(), Some(key));
        }
    }

    /// Closest-first resolution must not initialize a deeper directory after every query was
    /// resolved by a nearer active entry or tombstone.
    #[test]
    fn nearest_hits_leave_deeper_diff_index_cold() {
        let key = |value: u32| value.to_be_bytes().to_vec();
        let nearest: DiffVec<_, mmr::Family, u64> = (0..64u32)
            .map(|value| {
                let entry = if value == 24 {
                    DiffEntry::Deleted { base_old_loc: None }
                } else {
                    DiffEntry::Active {
                        value: value as u64 + 1_000,
                        loc: loc(value as u64 + 1_000),
                        base_old_loc: None,
                    }
                };
                (key(value), entry)
            })
            .collect();
        let deeper: DiffVec<_, mmr::Family, u64> = (0..64u32)
            .map(|value| {
                (
                    key(value),
                    DiffEntry::Active {
                        value: value as u64 + 2_000,
                        loc: loc(value as u64 + 2_000),
                        base_old_loc: None,
                    },
                )
            })
            .collect();
        let nearest_index = DiffIndex::default();
        let deeper_index = DiffIndex::default();
        let sources = [
            DiffSource {
                entries: nearest.as_slice(),
                index: &nearest_index,
            },
            DiffSource {
                entries: deeper.as_slice(),
                index: &deeper_index,
            },
        ];
        let active = key(16);
        let deleted = key(24);
        let pending = [(0, &active), (1, &deleted)];
        let mut resolved = [false; 2];
        let mut results = [None; 2];

        resolve_pending_from_diffs(
            &pending,
            &sources,
            &Sequential,
            &mut resolved,
            &mut results,
            |_, _| {},
        );

        assert_eq!(resolved, [true, true]);
        assert_eq!(results, [Some(1_016), None]);
        assert!(deeper_index.hints.get().is_none());
    }

    /// One key falling through a large nearest hit set must not allocate a directory for the
    /// deeper diff solely because the original request contained many keys.
    #[test]
    fn one_deep_fallthrough_leaves_deeper_diff_index_cold() {
        let key = |value: u32| value.to_be_bytes().to_vec();
        let nearest: DiffVec<_, mmr::Family, u64> = (0..63u32)
            .map(|value| {
                (
                    key(value),
                    DiffEntry::Active {
                        value: value as u64 + 1_000,
                        loc: loc(value as u64 + 1_000),
                        base_old_loc: None,
                    },
                )
            })
            .collect();
        let deeper: DiffVec<_, mmr::Family, u64> = (0..64u32)
            .map(|value| {
                (
                    key(value),
                    DiffEntry::Active {
                        value: value as u64 + 2_000,
                        loc: loc(value as u64 + 2_000),
                        base_old_loc: None,
                    },
                )
            })
            .collect();
        let nearest_index = DiffIndex::default();
        let deeper_index = DiffIndex::default();
        let sources = [
            DiffSource {
                entries: nearest.as_slice(),
                index: &nearest_index,
            },
            DiffSource {
                entries: deeper.as_slice(),
                index: &deeper_index,
            },
        ];
        let keys: Vec<_> = (0..64u32).map(key).collect();
        let pending: Vec<_> = keys.iter().enumerate().collect();
        let mut resolved = vec![false; keys.len()];
        let mut results = vec![None; keys.len()];

        resolve_pending_from_diffs(
            &pending,
            &sources,
            &Sequential,
            &mut resolved,
            &mut results,
            |_, _| {},
        );

        assert!(resolved.iter().all(|resolved| *resolved));
        assert_eq!(results[0], Some(1_000));
        assert_eq!(results[62], Some(1_062));
        assert_eq!(results[63], Some(2_063));
        assert!(nearest_index.hints.get().is_some());
        assert!(deeper_index.hints.get().is_none());
    }

    /// Level-wise lookup must replay interleaved parent/grandparent hits in input order, with a
    /// nearer tombstone suppressing an older active entry for the same key.
    #[test]
    fn multi_depth_resolution_replays_input_order() {
        let key = |value: u32| value.to_be_bytes().to_vec();
        let nearest: DiffVec<_, mmr::Family, u64> = (0..64u32)
            .step_by(2)
            .map(|value| {
                let entry = if value == 24 {
                    DiffEntry::Deleted { base_old_loc: None }
                } else {
                    DiffEntry::Active {
                        value: value as u64 + 1_000,
                        loc: loc(value as u64 + 1_000),
                        base_old_loc: None,
                    }
                };
                (key(value), entry)
            })
            .collect();
        let deeper: DiffVec<_, mmr::Family, u64> = (0..64u32)
            .map(|value| {
                (
                    key(value),
                    DiffEntry::Active {
                        value: value as u64 + 2_000,
                        loc: loc(value as u64 + 2_000),
                        base_old_loc: None,
                    },
                )
            })
            .collect();
        let nearest_index = DiffIndex::default();
        let deeper_index = DiffIndex::default();
        let sources = [
            DiffSource {
                entries: nearest.as_slice(),
                index: &nearest_index,
            },
            DiffSource {
                entries: deeper.as_slice(),
                index: &deeper_index,
            },
        ];
        let keys: Vec<_> = (0..64u32).map(key).collect();
        let pending: Vec<_> = keys.iter().enumerate().collect();
        let mut resolved = vec![false; keys.len()];
        let mut results = vec![None; keys.len()];
        let mut hit_order = Vec::new();

        resolve_pending_from_diffs(
            &pending,
            &sources,
            &Sequential,
            &mut resolved,
            &mut results,
            |slot, _| hit_order.push(slot),
        );

        assert_eq!(hit_order, (0..64).collect::<Vec<_>>());
        for (slot, result) in results.into_iter().enumerate() {
            let expected = if slot == 24 {
                None
            } else if slot.is_multiple_of(2) {
                Some(slot as u64 + 1_000)
            } else {
                Some(slot as u64 + 2_000)
            };
            assert_eq!(result, expected, "slot {slot} diverged");
        }
    }

    /// Concurrent first use of one directory must publish exactly one shared hint payload.
    #[test]
    fn diff_index_concurrent_first_initialization_is_shared() {
        const READERS: usize = 8;
        let entries = Arc::new(
            (0..10_000u64)
                .map(|key| ((key << 32).to_be_bytes().to_vec(), key))
                .collect::<Vec<_>>(),
        );
        let index = Arc::new(DiffIndex::default());
        let barrier = Arc::new(Barrier::new(READERS));
        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                let entries = Arc::clone(&entries);
                let index = Arc::clone(&index);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    index.hints(entries.as_slice()).as_ptr() as usize
                })
            })
            .collect();
        let pointers: Vec<_> = readers
            .into_iter()
            .map(|reader| reader.join().expect("reader must not panic"))
            .collect();

        assert!(pointers.iter().all(|pointer| *pointer == pointers[0]));
        assert_eq!(index.hints.get().expect("initialized").len(), 1_250);
    }

    /// A byte hint may narrow a lookup only when the narrowed range agrees with `K::cmp`.
    #[test]
    fn diff_index_falls_back_for_non_byte_ordered_keys() {
        #[derive(Clone, Debug, Eq, PartialEq)]
        struct Key {
            order: u32,
            bytes: [u8; 4],
        }

        impl AsRef<[u8]> for Key {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl Ord for Key {
            fn cmp(&self, other: &Self) -> core::cmp::Ordering {
                self.order.cmp(&other.order)
            }
        }

        impl PartialOrd for Key {
            fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
                Some(self.cmp(other))
            }
        }

        let mut entries: Vec<_> = (0..32u32)
            .map(|index| {
                let order = index * 2;
                (
                    Key {
                        order,
                        bytes: order.to_be_bytes(),
                    },
                    index,
                )
            })
            .collect();
        entries[5].0.bytes = u32::MAX.to_be_bytes();
        let index = DiffIndex::default();

        for order in [10, 11] {
            let query = Key {
                order,
                bytes: u32::MAX.to_be_bytes(),
            };
            let expected = lookup_sorted(&entries, &query).copied();
            let actual = index.lookup_or_initialize(&entries, &query).copied();
            assert_eq!(actual, expected);
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

    /// `sorted_contains` matches `binary_search` for ascending queries over sorted, deduped
    /// items.
    #[test]
    fn sorted_contains_matches_binary_search() {
        let mut rng = test_rng();
        for _ in 0..50 {
            let mut items: Vec<u64> = (0..rng.random_range(0..40))
                .map(|_| rng.random_range(0..100u64))
                .collect();
            items.sort_unstable();
            items.dedup();

            let mut queries: Vec<u64> = (0..rng.random_range(1..80))
                .map(|_| rng.random_range(0..110u64))
                .collect();
            queries.sort_unstable();

            let mut cursor = 0;
            for q in queries {
                assert_eq!(
                    sorted_contains(&items, &mut cursor, &q),
                    items.binary_search(&q).is_ok(),
                    "query {q} diverged"
                );
            }
        }
    }

    /// `merge_sorted_diffs` matches `extend` + `sort_by_key` for disjoint, sorted diffs.
    #[test]
    fn merge_sorted_diffs_matches_sort() {
        let mut rng = test_rng();
        for _ in 0..50 {
            // Disjoint key sets: evens on one side, odds on the other.
            let mut build = |offset: u64| -> DiffVec<u64, mmr::Family, u64> {
                let mut keys: Vec<u64> = (0..rng.random_range(0..30))
                    .map(|_| rng.random_range(0..50u64) * 2 + offset)
                    .collect();
                keys.sort_unstable();
                keys.dedup();
                keys.into_iter().map(|k| (k, active(k, k))).collect()
            };
            let a = build(0);
            let b = build(1);

            let mut reference = a.clone();
            reference.extend(b.clone());
            reference.sort_by_key(|x| x.0);

            let merged = merge_sorted_diffs(a, b);
            assert_eq!(merged.len(), reference.len());
            for ((mk, me), (rk, re)) in merged.iter().zip(&reference) {
                assert_eq!(mk, rk);
                assert_eq!(me.loc(), re.loc());
                assert_eq!(me.value(), re.value());
            }
        }
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
        if floor < committed_end
            && let Some(idx) = bitmap.next_one_from(floor)
            && idx < committed_end
        {
            return Some(Location::new(idx));
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
    fn diff_merge_four_way_preserves_priority_and_exhaustion() {
        let child = vec![(4, deleted(Some(40))), (9, active(90, 90))];
        let parent = vec![
            (1, active(11, 11)),
            (4, active(14, 14)),
            (5, deleted(Some(50))),
            (8, active(18, 18)),
        ];
        let grandparent = vec![
            (2, active(22, 22)),
            (4, deleted(Some(44))),
            (6, active(26, 26)),
            (8, deleted(Some(80))),
        ];
        let oldest = vec![
            (0, active(30, 30)),
            (3, active(33, 33)),
            (4, active(34, 34)),
            (5, active(35, 35)),
            (6, deleted(Some(60))),
            (7, active(37, 37)),
        ];
        let mut merge = DiffMerge::new([
            child.as_slice(),
            parent.as_slice(),
            grandparent.as_slice(),
            oldest.as_slice(),
        ]);

        let merged: Vec<_> = merge
            .by_ref()
            .map(|(key, entry)| (*key, entry.value().copied(), entry.loc()))
            .collect();

        assert_eq!(
            merged,
            vec![
                (0, Some(30), Some(loc(30))),
                (1, Some(11), Some(loc(11))),
                (2, Some(22), Some(loc(22))),
                (3, Some(33), Some(loc(33))),
                (4, None, None),
                (5, None, None),
                (6, Some(26), Some(loc(26))),
                (7, Some(37), Some(loc(37))),
                (8, Some(18), Some(loc(18))),
                (9, Some(90), Some(loc(90))),
            ]
        );
        assert!(merge.next().is_none());
        assert!(merge.next().is_none());
    }

    #[test]
    fn diff_merge_general_path_preserves_priority() {
        let newest = vec![(4, deleted(Some(40)))];
        let second = vec![(1, active(11, 11)), (4, active(14, 14))];
        let empty = Vec::new();
        let fourth = vec![
            (0, active(30, 30)),
            (1, deleted(Some(10))),
            (4, active(34, 34)),
        ];
        let oldest = vec![(2, active(42, 42)), (4, active(44, 44))];
        let mut merge = DiffMerge::new([
            newest.as_slice(),
            second.as_slice(),
            empty.as_slice(),
            fourth.as_slice(),
            oldest.as_slice(),
        ]);

        let merged: Vec<_> = merge
            .by_ref()
            .map(|(key, entry)| (*key, entry.value().copied(), entry.loc()))
            .collect();

        assert_eq!(
            merged,
            vec![
                (0, Some(30), Some(loc(30))),
                (1, Some(11), Some(loc(11))),
                (2, Some(42), Some(loc(42))),
                (4, None, None),
            ]
        );
        assert!(merge.next().is_none());
    }

    #[test]
    fn diff_merge_three_and_four_way_scan_live_heads_once() {
        #[derive(Clone, Debug)]
        struct CountedKey {
            value: usize,
            comparisons: Arc<AtomicUsize>,
        }

        impl PartialEq for CountedKey {
            fn eq(&self, other: &Self) -> bool {
                self.cmp(other).is_eq()
            }
        }

        impl Eq for CountedKey {}

        impl PartialOrd for CountedKey {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }

        impl Ord for CountedKey {
            fn cmp(&self, other: &Self) -> Ordering {
                self.comparisons.fetch_add(1, AtomicOrdering::Relaxed);
                self.value.cmp(&other.value)
            }
        }

        for stream_count in [3, 4] {
            let comparisons = Arc::new(AtomicUsize::new(0));
            let streams: Vec<DiffVec<_, mmr::Family, u64>> = (0..stream_count)
                .map(|stream| {
                    (0..256)
                        .map(|offset| {
                            let value = offset * stream_count + stream;
                            (
                                CountedKey {
                                    value,
                                    comparisons: Arc::clone(&comparisons),
                                },
                                active(value as u64, value as u64),
                            )
                        })
                        .collect()
                })
                .collect();
            comparisons.store(0, AtomicOrdering::Relaxed);

            let emitted = DiffMerge::new(streams.iter().map(Vec::as_slice)).count();
            let actual = comparisons.load(AtomicOrdering::Relaxed);
            let expected = stream_count * 256;
            let expected_comparisons = match stream_count {
                3 => 6 * 256 - 3,
                4 => 12 * 256 - 6,
                _ => unreachable!(),
            };

            assert_eq!(emitted, expected);
            assert_eq!(
                actual, expected_comparisons,
                "{stream_count}-way merge comparison count diverged"
            );
        }
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
                if let Some(DiffEntry::Deleted { base_old_loc }) = lookup_sorted(base_diff, key)
                    && let Some(value) = value
                {
                    return Some((key.clone(), value.clone(), *base_old_loc));
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
            let db = TestDb::init(context, config).await.unwrap();

            let key_update = Sha256::hash(&[b"update-through-all-layers"]);
            let key_recreate_then_delete = Sha256::hash(&[b"recreate-then-delete"]);
            let key_delete_from_uncommitted = Sha256::hash(&[b"delete-from-uncommitted"]);
            let key_uncommitted_create = Sha256::hash(&[b"uncommitted-create"]);

            let seed = db
                .new_batch()
                .write(key_update, Some(Sha256::hash(&[b"seed-update"])))
                .write(
                    key_recreate_then_delete,
                    Some(Sha256::hash(&[b"seed-recreate"])),
                )
                .write(
                    key_delete_from_uncommitted,
                    Some(Sha256::hash(&[b"seed-delete"])),
                )
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            let applied = db
                .new_batch()
                .write(key_update, Some(Sha256::hash(&[b"committed-update"])))
                .write(key_recreate_then_delete, None)
                .write(
                    key_delete_from_uncommitted,
                    Some(Sha256::hash(&[b"committed-delete-base"])),
                )
                .merkleize(&db, None)
                .await
                .unwrap();

            let pending = applied
                .new_batch::<Sha256>()
                .write(key_update, Some(Sha256::hash(&[b"uncommitted-update"])))
                .write(
                    key_recreate_then_delete,
                    Some(Sha256::hash(&[b"uncommitted-recreate"])),
                )
                .write(key_delete_from_uncommitted, None)
                .write(
                    key_uncommitted_create,
                    Some(Sha256::hash(&[b"uncommitted-create"])),
                )
                .merkleize(&db, None)
                .await
                .unwrap();

            let final_update = Sha256::hash(&[b"child-update"]);
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
            let (db, _) = db.apply_batch(applied).await.unwrap();
            let (db, _) = db.apply_batch(child).await.unwrap();

            assert_eq!(db.root(), expected_root);
            assert_eq!(db.get(&key_update).await.unwrap(), Some(final_update));
            assert_eq!(db.get(&key_recreate_then_delete).await.unwrap(), None);
            assert_eq!(db.get(&key_delete_from_uncommitted).await.unwrap(), None);
            assert_eq!(
                db.get(&key_uncommitted_create).await.unwrap(),
                Some(Sha256::hash(&[b"uncommitted-create"]))
            );

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn apply_batch_merges_three_dropped_pending_ancestors() {
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

            let config = fixed_db_config::<OneCap>("three-pending-ancestors", &context);
            let db = TestDb::init(context, config).await.unwrap();
            let key = |name: &[u8]| Sha256::hash(&[b"three-pending-key", name]);
            let value = |generation: u8, name: &[u8]| {
                Sha256::hash(&[b"three-pending-value", &[generation], name])
            };
            let all = key(b"all");
            let near_delete = key(b"near-delete");
            let near_active = key(b"near-active");
            let old_only = key(b"old-only");
            let grandparent_create = key(b"grandparent-create");
            let parent_only = key(b"parent-only");
            let child_only = key(b"child-only");
            let leaf_only = key(b"leaf-only");

            let seed = db
                .new_batch()
                .write(all, Some(value(0, b"all")))
                .write(near_delete, Some(value(0, b"near-delete")))
                .write(near_active, Some(value(0, b"near-active")))
                .write(old_only, Some(value(0, b"old-only")))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

            let grandparent = db
                .new_batch()
                .write(all, Some(value(1, b"all")))
                .write(near_delete, Some(value(1, b"near-delete")))
                .write(near_active, None)
                .write(old_only, Some(value(1, b"old-only")))
                .write(grandparent_create, Some(value(1, b"grandparent-create")))
                .merkleize(&db, None)
                .await
                .unwrap();
            let parent = grandparent
                .new_batch::<Sha256>()
                .write(all, Some(value(2, b"all")))
                .write(near_delete, Some(value(2, b"near-delete")))
                .write(grandparent_create, None)
                .write(parent_only, Some(value(2, b"parent-only")))
                .merkleize(&db, None)
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .write(all, Some(value(3, b"all")))
                .write(near_delete, Some(value(3, b"near-delete")))
                .write(near_active, Some(value(3, b"near-active")))
                .write(child_only, Some(value(3, b"child-only")))
                .merkleize(&db, None)
                .await
                .unwrap();
            let leaf = child
                .new_batch::<Sha256>()
                .write(all, Some(value(4, b"all")))
                .write(near_delete, None)
                .write(leaf_only, Some(value(4, b"leaf-only")))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert_eq!(leaf.bounds.ancestors.len(), 3);
            let expected_root = leaf.root();
            let grandparent_diff = Arc::downgrade(&grandparent.diff);
            let parent_diff = Arc::downgrade(&parent.diff);
            let child_diff = Arc::downgrade(&child.diff);
            drop(grandparent);
            drop(parent);
            drop(child);
            assert!(grandparent_diff.upgrade().is_some());
            assert!(parent_diff.upgrade().is_some());
            assert!(child_diff.upgrade().is_some());

            let (db, _) = db.apply_batch(leaf).await.unwrap();
            assert_eq!(db.root(), expected_root);
            assert!(grandparent_diff.upgrade().is_none());
            assert!(parent_diff.upgrade().is_none());
            assert!(child_diff.upgrade().is_none());
            let db = db.commit().await.unwrap();

            let keys = [
                &all,
                &near_delete,
                &near_active,
                &old_only,
                &grandparent_create,
                &parent_only,
                &child_only,
                &leaf_only,
            ];
            assert_eq!(
                db.get_many(&keys).await.unwrap(),
                vec![
                    Some(value(4, b"all")),
                    None,
                    Some(value(3, b"near-active")),
                    Some(value(1, b"old-only")),
                    None,
                    Some(value(2, b"parent-only")),
                    Some(value(3, b"child-only")),
                    Some(value(4, b"leaf-only")),
                ]
            );

            db.destroy().await.unwrap();
        });
    }

    /// Instantiate the staged-vs-explicit bulk-update parity test for one `any` DB kind.
    ///
    /// The staged path (`stage` + `Staged::merkleize`) must produce a byte-identical root to an
    /// explicit `get_many` + `write` + `merkleize` applying the same logical writes in the same
    /// order (updates by read-slot key, then upserts), while skipping the journal re-read for
    /// committed-resolved updated keys. `$shift` offsets the colliding-digest prefixes so each
    /// instantiation uses disjoint key material.
    macro_rules! bulk_update_paths_match_explicit_writes_test {
        ($name:ident, $db:ident, $partition:literal, $shift:literal) => {
            #[test]
            fn $name() {
                let runner = deterministic::Runner::default();
                runner.start(|context| async move {
                    type TestDb = $db<
                        mmr::Family,
                        deterministic::Context,
                        sha256::Digest,
                        sha256::Digest,
                        Sha256,
                        OneCap,
                        Sequential,
                    >;

                    let config = fixed_db_config::<OneCap>($partition, &context);
                    let db = TestDb::init(context, config).await.unwrap();

                    let k0 = colliding_digest(0x40 + $shift, 0);
                    let k1 = colliding_digest(0x40 + $shift, 1);
                    let k2 = colliding_digest(0x41 + $shift, 0);
                    let missing = colliding_digest(0x40 + $shift, 9);
                    let read_only = colliding_digest(0x41 + $shift, 1);
                    let unread_existing = colliding_digest(0x41 + $shift, 2);
                    let unread_missing = colliding_digest(0x40 + $shift, 10);
                    let del_read = colliding_digest(0x41 + $shift, 3);
                    let del_unread = colliding_digest(0x41 + $shift, 4);
                    let v0 = colliding_digest(0x50 + $shift, 0);
                    let v1 = colliding_digest(0x50 + $shift, 1);
                    let v2 = colliding_digest(0x51 + $shift, 0);
                    let read_only_value = colliding_digest(0x51 + $shift, 1);
                    let unread_existing_value = colliding_digest(0x51 + $shift, 2);
                    let del_read_value = colliding_digest(0x51 + $shift, 3);
                    let del_unread_value = colliding_digest(0x51 + $shift, 4);

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
                    let (db, _) = db.apply_batch(seed).await.unwrap();
                    let db = db.commit().await.unwrap();

                    // Read set with duplicate slots for k0 (0,4) and missing (2,5), plus del_read at 7.
                    let read_keys = [k0, read_only, missing, k1, k0, missing, k2, del_read];
                    let keys: Vec<_> = read_keys.iter().collect();
                    // (read_slot, Some=upsert | None=delete). Slot 7 deletes a committed-resolved read
                    // key. Duplicate slots exercise last-write-wins by update order. For the
                    // ordered kind a staged delete must fall back to a normal mutation (the deleted
                    // key's predecessor is rewritten via a snapshot-bucket scan the cached location
                    // cannot skip), exercised alongside staged updates that share del_read's
                    // collision bucket.
                    let indexed_updates = vec![
                        (0, Some(colliding_digest(0x60 + $shift, 0))),
                        (2, Some(colliding_digest(0x60 + $shift, 1))),
                        (3, Some(colliding_digest(0x60 + $shift, 2))),
                        (4, Some(colliding_digest(0x60 + $shift, 3))),
                        (5, Some(colliding_digest(0x60 + $shift, 4))),
                        (6, Some(colliding_digest(0x60 + $shift, 5))),
                        (7, None),
                    ];
                    // Upserts for unread keys: set two, override k0 (overlaps slots 0/4), delete one.
                    let upserts = vec![
                        (unread_existing, Some(colliding_digest(0x60 + $shift, 6))),
                        (unread_missing, Some(colliding_digest(0x60 + $shift, 7))),
                        (k0, Some(colliding_digest(0x60 + $shift, 8))),
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
                    let (range, suffix_values, staged) =
                        staged.expand(&keys[split..], &db).await.unwrap();
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

                    let (db, _) = db.apply_batch(expanded).await.unwrap();
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
        };
    }

    bulk_update_paths_match_explicit_writes_test!(
        unordered_bulk_update_paths_match_explicit_writes,
        UnorderedFixedDb,
        "unordered-bulk-load-update",
        0
    );

    bulk_update_paths_match_explicit_writes_test!(
        ordered_bulk_update_paths_match_explicit_writes,
        OrderedFixedDb,
        "ordered-bulk-load-update",
        2
    );

    /// Build a [`Staged`] handle with the keys and resolutions `stage`/`expand` would produce.
    fn staged_with<F: Family, H: Hasher, U: update::Update, S: Strategy>(
        batch: UnmerkleizedBatch<F, H, U, S>,
        keys: Vec<U::Key>,
        resolutions: Vec<StagedResolution<F, U>>,
    ) -> Staged<F, H, U, S>
    where
        Operation<F, U>: Codec,
    {
        Staged {
            batch,
            keys,
            resolutions,
        }
    }

    #[test]
    fn unordered_staged_resolve_updates_collapses_duplicates_before_sorting() {
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
            type TestUpdate = update::Unordered<sha256::Digest, FixedEncoding<sha256::Digest>>;

            let config = fixed_db_config::<OneCap>("unordered-staged-resolve-updates", &context);
            let db = TestDb::init(context, config).await.unwrap();

            let k0 = colliding_digest(0x90, 0);
            let k1 = colliding_digest(0x90, 1);
            let k2 = colliding_digest(0x90, 2);
            let k3 = colliding_digest(0x90, 3);
            let old0 = colliding_digest(0x91, 0);
            let old1 = colliding_digest(0x91, 1);
            let new0 = colliding_digest(0x91, 2);
            let staged_k2 = colliding_digest(0x91, 3);
            let fallback = colliding_digest(0x91, 4);
            let upsert = colliding_digest(0x91, 5);

            let staged = staged_with::<mmr::Family, Sha256, TestUpdate, Sequential>(
                db.new_batch(),
                vec![k0, k1, k0, k2, k1, k3],
                vec![
                    Some((committed(30), ())),
                    Some((committed(10), ())),
                    Some((committed(30), ())),
                    Some((committed(40), ())),
                    Some((committed(10), ())),
                    None,
                ],
            );

            let (batch, staged_updates) = staged.resolve_updates(
                vec![
                    (0, Some(old0)),
                    (1, Some(old1)),
                    (2, Some(new0)),
                    (3, Some(staged_k2)),
                    (4, None),
                    (5, Some(fallback)),
                ],
                vec![(k2, Some(upsert))],
                &Sequential,
            );

            assert_eq!(
                staged_updates,
                vec![
                    (k1, committed(10), (), None),
                    (k0, committed(30), (), Some(new0))
                ]
            );
            assert_eq!(batch.mutations.len(), 2);
            assert_eq!(batch.mutations.get(&k2), Some(&Some(upsert)));
            assert_eq!(batch.mutations.get(&k3), Some(&Some(fallback)));
            assert!(!batch.mutations.contains_key(&k0));
            assert!(!batch.mutations.contains_key(&k1));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn unordered_staged_resolve_updates_collapses_duplicates_at_scale() {
        // The small collapse test above sits under the sort's insertion-sort threshold. This
        // one pins the same semantics at a size that exercises the real sort machinery: every
        // key written twice through duplicate slots (last write must win), a key whose newest
        // write is unresolved (the mutation must win over an older staged occurrence), a key
        // whose newest write is staged (the staged update must win and clear the older
        // mutation), and an upsert overlapping a staged key (the upsert must win).
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
            type TestUpdate = update::Unordered<sha256::Digest, FixedEncoding<sha256::Digest>>;

            let config =
                fixed_db_config::<OneCap>("unordered-staged-resolve-updates-scale", &context);
            let db = TestDb::init(context, config).await.unwrap();

            let n: usize = 512;
            let keys: Vec<_> = (0..n).map(|i| colliding_digest(0xA0, i as u64)).collect();
            let old_values: Vec<_> = (0..n).map(|i| colliding_digest(0xB0, i as u64)).collect();
            let new_values: Vec<_> = (0..n).map(|i| colliding_digest(0xB1, i as u64)).collect();
            let mut_newer = colliding_digest(0xB2, 0);
            let staged_newer = colliding_digest(0xB2, 1);
            let overlapped = colliding_digest(0xB2, 2);
            let mut_old = colliding_digest(0xB3, 0);
            let mut_new = colliding_digest(0xB3, 1);
            let staged_old = colliding_digest(0xB3, 2);
            let staged_new = colliding_digest(0xB3, 3);
            let overlapped_write = colliding_digest(0xB3, 4);
            let upsert = colliding_digest(0xB3, 5);

            // Each key occupies two slots carrying the same resolution. The three special keys
            // append after them: `mut_newer` resolved at slot 2n and unresolved at 2n+1,
            // `staged_newer` unresolved at 2n+2 and resolved at 2n+3, `overlapped` resolved at
            // 2n+4.
            let mut staged_keys = keys.clone();
            staged_keys.extend(keys.iter().cloned());
            staged_keys.extend([mut_newer, mut_newer, staged_newer, staged_newer, overlapped]);
            let mut resolutions: Vec<Option<(StagedLoc<mmr::Family>, ())>> = (0..2 * n)
                .map(|slot| Some((committed(1_000 + (slot % n) as u64), ())))
                .collect();
            resolutions.extend([
                Some((committed(500), ())),
                None,
                None,
                Some((committed(501), ())),
                Some((committed(502), ())),
            ]);

            let staged = staged_with::<mmr::Family, Sha256, TestUpdate, Sequential>(
                db.new_batch(),
                staged_keys,
                resolutions,
            );

            // Update order is oldest first: the resolved `mut_newer` write and the unresolved
            // `staged_newer` write come first so newer writes through the other arm must beat
            // them, then every key's old value, the overlapped write, every key's new value,
            // and finally the unresolved `mut_newer` write and the resolved `staged_newer`
            // write.
            let mut updates: Vec<(usize, Option<sha256::Digest>)> =
                vec![(2 * n, Some(mut_old)), (2 * n + 2, Some(staged_old))];
            updates.extend((0..n).map(|i| (i, Some(old_values[i]))));
            updates.push((2 * n + 4, Some(overlapped_write)));
            updates.extend((0..n).map(|i| (n + i, Some(new_values[i]))));
            updates.extend([(2 * n + 1, Some(mut_new)), (2 * n + 3, Some(staged_new))]);

            let (batch, staged_updates) =
                staged.resolve_updates(updates, vec![(overlapped, Some(upsert))], &Sequential);

            let mut expected = vec![(staged_newer, committed(501), (), Some(staged_new))];
            expected.extend((0..n).map(|i| {
                (
                    keys[i],
                    committed(1_000 + i as u64),
                    (),
                    Some(new_values[i]),
                )
            }));
            assert_eq!(staged_updates, expected);
            assert_eq!(batch.mutations.len(), 2);
            assert_eq!(batch.mutations.get(&mut_newer), Some(&Some(mut_new)));
            assert_eq!(batch.mutations.get(&overlapped), Some(&Some(upsert)));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn unordered_staged_merkleize_discards_prior_mutation_for_cached_update() {
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
            type TestUpdate = update::Unordered<sha256::Digest, FixedEncoding<sha256::Digest>>;

            let config = fixed_db_config::<OneCap>("unordered-staged-prior-mutation", &context);
            let db = TestDb::init(context, config).await.unwrap();

            let key = colliding_digest(0x95, 0);
            let old = colliding_digest(0x95, 1);
            let prior = colliding_digest(0x95, 2);
            let replacement = colliding_digest(0x95, 3);

            let seed = db
                .new_batch()
                .write(key, Some(old))
                .merkleize(&db, None)
                .await
                .unwrap();
            let old_loc = lookup_sorted(seed.diff.as_slice(), &key)
                .and_then(DiffEntry::loc)
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

            let explicit = db
                .new_batch()
                .write(key, Some(prior))
                .write(key, Some(replacement))
                .merkleize(&db, None)
                .await
                .unwrap();

            let staged = staged_with::<mmr::Family, Sha256, TestUpdate, Sequential>(
                db.new_batch().write(key, Some(prior)),
                vec![key],
                vec![Some((StagedLoc::Committed(old_loc), ()))],
            );
            let staged = staged
                .merkleize(vec![(0, Some(replacement))], Vec::new(), None, &db)
                .await
                .unwrap();

            assert_eq!(explicit.root(), staged.root());

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn ordered_staged_resolve_updates_keeps_deletes_as_mutations() {
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
            type TestUpdate = update::Ordered<sha256::Digest, FixedEncoding<sha256::Digest>>;

            let config = fixed_db_config::<OneCap>("ordered-staged-resolve-updates", &context);
            let db = TestDb::init(context, config).await.unwrap();

            let delete_key = colliding_digest(0x92, 0);
            let update_a = colliding_digest(0x92, 1);
            let update_b = colliding_digest(0x92, 2);
            let next_delete = colliding_digest(0x93, 0);
            let next_a = colliding_digest(0x93, 1);
            let next_b = colliding_digest(0x93, 2);
            let value_a = colliding_digest(0x94, 0);
            let value_b = colliding_digest(0x94, 1);

            let staged = staged_with::<mmr::Family, Sha256, TestUpdate, Sequential>(
                db.new_batch(),
                vec![delete_key, update_a, update_b],
                vec![
                    Some((committed(11), next_delete)),
                    Some((committed(30), next_a)),
                    Some((committed(7), next_b)),
                ],
            );

            let (batch, staged_updates) = staged.resolve_updates(
                vec![(0, None), (1, Some(value_a)), (2, Some(value_b))],
                Vec::new(),
                &Sequential,
            );

            assert_eq!(
                staged_updates,
                vec![
                    (update_b, committed(7), next_b, Some(value_b)),
                    (update_a, committed(30), next_a, Some(value_a)),
                ]
            );
            assert_eq!(batch.mutations.len(), 1);
            assert_eq!(batch.mutations.get(&delete_key), Some(&None));
            assert!(!batch.mutations.contains_key(&update_a));
            assert!(!batch.mutations.contains_key(&update_b));

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

    /// Instantiate the staged-updates-survive-ancestor-commit test for one `any` DB kind.
    ///
    /// One staged handle stages a prefix before an ancestor batch commits and expands with the
    /// rest after it, so the handle holds cache entries resolved against both committed
    /// snapshots. Merkleizing its updates must produce the same root and final state as explicit
    /// writes. `$key_prefix`/`$val_prefix` pick disjoint colliding-digest key material per
    /// instantiation, and `$read_label`/`$write_label` isolate each variant's storage.
    macro_rules! staged_updates_survive_ancestor_commit_test {
        (
            $name:ident, $db:ident, $key_prefix:literal, $val_prefix:literal,
            $read_label:literal, $write_label:literal
        ) => {
            #[test]
            fn $name() {
                let runner = deterministic::Runner::default();
                runner.start(|context| async move {
                    type TestDb = $db<
                        mmr::Family,
                        deterministic::Context,
                        sha256::Digest,
                        sha256::Digest,
                        Sha256,
                        OneCap,
                        Sequential,
                    >;

                    let key = |i| colliding_digest($key_prefix, i);
                    let val = |i| colliding_digest($val_prefix, i);
                    // Slots 0..9 are grandparent-touched keys, 9..19 are committed-only keys, and the
                    // final slot revisits a grandparent-touched key so the post-commit expansion below
                    // reads it from the freshly committed state.
                    let suffixes: Vec<u64> = (1..10).chain(20..30).chain([0]).collect();
                    let indexed_updates: Vec<_> = suffixes
                        .iter()
                        .enumerate()
                        .map(|(slot, suffix)| (slot, Some(val(suffix + 3_000))))
                        .collect();
                    let mut roots = Vec::new();

                    for staged_read in [false, true] {
                        let label = if staged_read {
                            $read_label
                        } else {
                            $write_label
                        };
                        let context = context.child(label);
                        let config = fixed_db_config::<OneCap>(label, &context);
                        let db = TestDb::init(context, config).await.unwrap();

                        let mut seed = db.new_batch();
                        for i in 0..100u64 {
                            seed = seed.write(key(i), Some(val(i)));
                        }
                        let seed = seed.merkleize(&db, None).await.unwrap();
                        let (db, _) = db.apply_batch(seed).await.unwrap();
                        let mut db = db.commit().await.unwrap();

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
                            let read_keys: Vec<_> =
                                suffixes.iter().map(|suffix| key(*suffix)).collect();
                            let keys: Vec<_> = read_keys.iter().collect();
                            let child = parent.new_batch::<Sha256>();
                            // Stage a prefix before the ancestor commit and expand with the rest after
                            // it, so one staged handle holds cache entries resolved against both
                            // committed snapshots.
                            let split = 15;
                            let (mut values, staged) =
                                child.stage(&keys[..split], &db).await.unwrap();

                            (db, _) = db.apply_batch(grandparent).await.unwrap();
                            db = db.commit().await.unwrap();

                            let (range, suffix_values, staged) =
                                staged.expand(&keys[split..], &db).await.unwrap();
                            assert_eq!(range, split..keys.len());
                            values.extend(suffix_values);
                            for (slot, suffix) in suffixes.iter().enumerate() {
                                let expected = if *suffix < 10 {
                                    val(suffix + 1_000)
                                } else {
                                    val(*suffix)
                                };
                                assert_eq!(values[slot], Some(expected));
                            }
                            staged
                                .merkleize(indexed_updates.clone(), Vec::new(), None, &db)
                                .await
                                .unwrap()
                        } else {
                            let mut child = parent.new_batch::<Sha256>();
                            (db, _) = db.apply_batch(grandparent).await.unwrap();
                            db = db.commit().await.unwrap();
                            for suffix in &suffixes {
                                child = child.write(key(*suffix), Some(val(suffix + 3_000)));
                            }
                            child.merkleize(&db, None).await.unwrap()
                        };

                        let (db, _) = db.apply_batch(parent).await.unwrap();
                        let (db, _) = db.apply_batch(child).await.unwrap();
                        let db = db.commit().await.unwrap();

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
        };
    }

    staged_updates_survive_ancestor_commit_test!(
        unordered_staged_updates_survive_ancestor_commit,
        UnorderedFixedDb,
        0x80,
        0x81,
        "unordered_staged_ancestor_read",
        "unordered_staged_ancestor_write"
    );

    staged_updates_survive_ancestor_commit_test!(
        ordered_staged_updates_survive_ancestor_commit,
        OrderedFixedDb,
        0x82,
        0x83,
        "ordered_staged_ancestor_read",
        "ordered_staged_ancestor_write"
    );

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
            let db = TestDb::init(context, config).await.unwrap();

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
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

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

            let current_loc = merkleizer.base_state.size;
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
            let db = TestDb::init(context, config).await.unwrap();
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
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

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

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

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
            let (db, _) = db.apply_batch(pending_child).await.unwrap();
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
            let db = TestDb::init(context, config).await.unwrap();
            let key_a = colliding_digest(0xAA, 1);
            let key_b = colliding_digest(0xAA, 0);

            // Match the unordered counterexample shape on the ordered path so
            // both variants exercise the same collision pattern.
            let mut initial = db.new_batch();
            for i in 0..4 {
                initial = initial.write(colliding_digest(0xAA, i), Some(colliding_digest(0xBB, i)));
            }
            let initial = initial.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

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

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

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
            let (db, _) = db.apply_batch(pending_child).await.unwrap();
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
            let db = TestDb::init(context, config).await.unwrap();

            // Seed an initial key.
            let seed = db
                .new_batch()
                .write(colliding_digest(0x01, 0), Some(colliding_digest(0x01, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

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

            let (db, _) = db.apply_batch(batch_a).await.unwrap();
            let db = db.commit().await.unwrap();

            // Build the same logical B from committed DB for comparison.
            let committed_b = db
                .new_batch()
                .write(key_b, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert_eq!(batch_b.root(), committed_b.root());

            // Apply B.
            let (db, _) = db.apply_batch(batch_b).await.unwrap();
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
            let db = TestDb::init(context, config).await.unwrap();

            // Seed an initial key so we have an existing entry.
            let key = colliding_digest(0x10, 0);
            let seed = db
                .new_batch()
                .write(key, Some(colliding_digest(0x10, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

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
            let (db, _) = db.apply_batch(batch_a).await.unwrap();
            let db = db.commit().await.unwrap();

            // Verify B produces the same root as a fresh build.
            let committed_b = db
                .new_batch()
                .write(key, Some(val_b))
                .merkleize(&db, None)
                .await
                .unwrap();
            assert_eq!(batch_b.root(), committed_b.root());

            let (db, _) = db.apply_batch(batch_b).await.unwrap();
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
            let db = TestDb::init(context, config).await.unwrap();

            // Seed.
            let seed = db
                .new_batch()
                .write(colliding_digest(0x20, 0), Some(colliding_digest(0x20, 1)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

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

            let (db, _) = db.apply_batch(batch_a).await.unwrap();
            let db = db.commit().await.unwrap();

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
            let db = TestDb::init(context, config).await.unwrap();

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
            let (db, _) = db.apply_batch(grandparent).await.unwrap();
            let db = db.commit().await.unwrap();

            // Commit parent.
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            // Commit child.
            let (db, _) = db.apply_batch(child).await.unwrap();

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
            let db = TestDb::init(context, config).await.unwrap();

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
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

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
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

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
            let db = TestDb::init(context, config).await.unwrap();

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
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

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

    /// A single point read must retain the cold binary-search path instead of constructing a
    /// directory whose cost can only be amortized by a larger read set.
    #[test]
    fn merkleized_get_keeps_cold_diff_index_uninitialized() {
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

            let config = fixed_db_config::<OneCap>("cold-point-diff-index", &context);
            let db = TestDb::init(context, config).await.unwrap();
            let key = |index: u32| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                sha256::Digest::from(bytes)
            };
            let mut batch = db.new_batch();
            for index in 0..64 {
                batch = batch.write(key(index), Some(colliding_digest(0x70, index as u64)));
            }
            let batch = batch.merkleize(&db, None).await.unwrap();
            let query = key(17);

            assert!(batch.diff_index.hints.get().is_none());
            assert_eq!(
                batch.get(&query, &db).await.unwrap(),
                Some(colliding_digest(0x70, 17))
            );
            assert!(batch.diff_index.hints.get().is_none());

            db.destroy().await.unwrap();
        });
    }

    /// Cloning a cold sealed batch must preserve one lazy directory owner for its shared immutable
    /// diff, regardless of which clone performs the first lookup.
    #[test]
    fn merkleized_batch_clones_share_cold_diff_index() {
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

            let config = fixed_db_config::<OneCap>("clone-shared-diff-index", &context);
            let db = TestDb::init(context, config).await.unwrap();
            let key = |index: u32| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                sha256::Digest::from(bytes)
            };
            let mut batch = db.new_batch();
            for index in 0..64 {
                batch = batch.write(key(index), Some(colliding_digest(0x71, index as u64)));
            }
            let batch = batch.merkleize(&db, None).await.unwrap();
            let cloned = batch.as_ref().clone();

            assert!(Arc::ptr_eq(&batch.diff, &cloned.diff));
            assert!(Arc::ptr_eq(&batch.diff_index, &cloned.diff_index));
            let original_hints = batch.diff_index.hints(batch.diff.as_slice());
            let cloned_hints = cloned.diff_index.hints(cloned.diff.as_slice());
            assert!(!original_hints.is_empty());
            assert_eq!(original_hints.as_ptr(), cloned_hints.as_ptr());

            db.destroy().await.unwrap();
        });
    }

    /// Descendants retain raw ancestor diffs for reads and apply, but lookup directories remain
    /// owned by the batch whose diff they index and are released with that batch.
    #[test]
    fn descendants_do_not_retain_ancestor_diff_indexes() {
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

            let config = fixed_db_config::<OneCap>("ancestor-diff-index-ownership", &context);
            let db = TestDb::init(context, config).await.unwrap();
            let key = |index: u32| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                sha256::Digest::from(bytes)
            };

            let mut parent = db.new_batch();
            for index in 0..512 {
                parent = parent.write(key(index), Some(colliding_digest(0x72, index as u64)));
            }
            let parent = parent.merkleize(&db, None).await.unwrap();

            let mut child = parent.new_batch::<Sha256>();
            for index in 512..1_024 {
                child = child.write(key(index), Some(colliding_digest(0x73, index as u64)));
            }
            let child = child.merkleize(&db, None).await.unwrap();
            let grandchild = child
                .new_batch::<Sha256>()
                .write(key(1_024), Some(colliding_digest(0x74, 1_024)))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert!(!parent.diff_index.hints(parent.diff.as_slice()).is_empty());
            assert!(!child.diff_index.hints(child.diff.as_slice()).is_empty());
            let parent_index = Arc::downgrade(&parent.diff_index);
            let parent_diff = Arc::downgrade(&parent.diff);
            let child_index = Arc::downgrade(&child.diff_index);
            let child_diff = Arc::downgrade(&child.diff);

            drop(parent);
            assert!(parent_index.upgrade().is_none());
            assert!(parent_diff.upgrade().is_some());

            drop(child);
            assert!(child_index.upgrade().is_none());
            assert!(child_diff.upgrade().is_some());
            assert!(parent_diff.upgrade().is_some());

            drop(grandchild);
            assert!(child_diff.upgrade().is_none());
            assert!(parent_diff.upgrade().is_none());

            db.destroy().await.unwrap();
        });
    }

    /// Applied ancestors may release their lookup sidecars while descendants retain only the raw
    /// diffs needed for later apply and fall through to the newly committed database state.
    #[test]
    fn initialized_ancestor_commit_drop_preserves_reads_and_apply() {
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

            let config = fixed_db_config::<OneCap>("indexed-ancestor-commit-drop", &context);
            let db = TestDb::init(context, config).await.unwrap();
            let key = |index: u32| {
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&index.to_be_bytes());
                sha256::Digest::from(bytes)
            };
            let value = |generation: u8, index: u32| {
                Sha256::hash(&[
                    b"indexed-ancestor-value",
                    &[generation],
                    &index.to_be_bytes(),
                ])
            };

            let mut seed = db.new_batch();
            for index in 0..8_192 {
                seed = seed.write(key(index), Some(value(0, index)));
            }
            let seed = seed.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

            let mut grandparent = db.new_batch();
            for index in 0..4_096 {
                grandparent = grandparent.write(key(index), Some(value(1, index)));
            }
            let grandparent = grandparent.merkleize(&db, None).await.unwrap();

            let mut parent = grandparent.new_batch::<Sha256>();
            for index in 0..4_096 {
                parent = parent.write(key(index), (index != 16).then(|| value(2, index)));
            }
            let parent = parent.merkleize(&db, None).await.unwrap();
            let child_key = key(8_192);
            let child_value = value(3, 8_192);
            let child = parent
                .new_batch::<Sha256>()
                .write(child_key, Some(child_value))
                .merkleize(&db, None)
                .await
                .unwrap();

            assert!(
                !grandparent
                    .diff_index
                    .hints(grandparent.diff.as_slice())
                    .is_empty()
            );
            assert!(!parent.diff_index.hints(parent.diff.as_slice()).is_empty());
            let grandparent_index: ArcWeak<DiffIndex> = Arc::downgrade(&grandparent.diff_index);
            let parent_index: ArcWeak<DiffIndex> = Arc::downgrade(&parent.diff_index);
            let parent_diff = Arc::downgrade(&parent.diff);
            let missing = key(8_193);
            let queries = [&child_key, &key(8), &key(16), &key(6_000), &missing];
            assert_eq!(
                child.get_many(&queries, &db).await.unwrap(),
                vec![
                    Some(child_value),
                    Some(value(2, 8)),
                    None,
                    Some(value(0, 6_000)),
                    None,
                ]
            );
            let child_root = child.root();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();
            drop(grandparent);
            assert!(grandparent_index.upgrade().is_none());
            assert!(parent_index.upgrade().is_none());
            assert!(parent_diff.upgrade().is_some());
            assert_eq!(
                child.get_many(&queries, &db).await.unwrap(),
                vec![
                    Some(child_value),
                    Some(value(2, 8)),
                    None,
                    Some(value(0, 6_000)),
                    None,
                ]
            );

            let (db, _) = db.apply_batch(child).await.unwrap();
            assert_eq!(db.root(), child_root);
            assert_eq!(db.get(&child_key).await.unwrap(), Some(child_value));
            assert_eq!(db.get(&key(8)).await.unwrap(), Some(value(2, 8)));
            assert_eq!(db.get(&key(16)).await.unwrap(), None);
            assert!(parent_diff.upgrade().is_none());

            db.destroy().await.unwrap();
        });
    }
}
