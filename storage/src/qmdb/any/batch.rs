//! Batch mutation API for Any QMDBs.

#[cfg(test)]
use crate::qmdb::bitmap::FnCandidates;
use crate::{
    Context,
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable},
    },
    merkle::{Family, Location, Proof},
    qmdb::{
        any::{
            ValueEncoding,
            db::Db,
            operation::{Operation, update},
            ordered::{Neighbors, find_next_key_ascending},
        },
        bitmap::{Candidates, Shared},
        chain::{self, Bounds, Commitment, Onchain},
        delete_known_loc,
        floor::{Action, Entry, Limits, Policy, Walk},
        operation::{Key, Operation as OperationTrait},
        update_known_loc,
    },
};
use ahash::{AHashMap, AHashSet};
use commonware_codec::Codec;
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use commonware_utils::{Widen, bitmap, iter::zip_eq, range::contains_cyclic};
use core::{
    cmp::Ordering,
    ops::{
        Bound::{Excluded, Included},
        Range,
    },
};
use std::{
    borrow::Cow,
    collections::{BTreeMap, hash_map},
    iter, mem,
    sync::{Arc, Weak},
};
use tracing::debug;

type DiffVec<K, F, V> = Vec<(K, DiffEntry<F, V>)>;
type DiffSlice<K, F, V> = [(K, DiffEntry<F, V>)];

/// Sorted locations at the retained batch chain's committed boundary.
type AncestorBaseLocs<K, F> = Vec<(K, Option<Location<F>>)>;

/// A round of committed floor candidates a staged merkleize selected and read while it resolved
/// its updates, and the location its selection stopped at. The floor walk takes it whole as its
/// first round.
type Prefetched<F, U> = (Round<F, U>, Location<F>);

/// Where a staged read or the floor walk's classification resolved its key's live operation: in
/// the committed DB, or in an uncommitted ancestor's diff. Either way, the resolved location
/// orders a staged write among this batch's emitted operations.
///
/// The variants differ in which committed location the write supersedes: `Committed` supersedes
/// the resolved location itself, while `Ancestor` supersedes the committed location it recorded
/// when it was resolved.
///
/// The recorded base stays valid while the resolving ancestor is alive at merkleize, because the
/// ancestor's diff travels with this batch and `apply_batch` re-resolves the base if the ancestor
/// is applied first. If the ancestor is instead applied and freed before merkleize, its
/// application has made `loc` the key's committed location, so merkleize supersedes `loc`
/// whenever it lies below the merkleize-time committed boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StagedLoc<F: Family> {
    /// Resolved in the committed DB. The location doubles as the superseded committed
    /// location.
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

    /// The committed location a write at this resolution supersedes. `boundary` is the committed
    /// boundary at merkleize.
    fn superseded(&self, boundary: Location<F>) -> Option<Location<F>> {
        match *self {
            Self::Committed(loc) => Some(loc),
            Self::Ancestor { loc, .. } if loc < boundary => Some(loc),
            Self::Ancestor { base_old_loc, .. } => base_old_loc,
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
        /// The key's committed location in the DB snapshot, or `None` if the key never existed in
        /// the committed DB: an ancestor batch created it, or this batch created and then evicted
        /// it.
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

/// Returns whether `items`, sorted and unique by `key`, holds an item keyed `target`, advancing
/// `cursor` past items keyed below it. Successive calls must use non-decreasing `target`s.
fn sorted_contains_by<T, Q: Ord>(
    items: &[T],
    cursor: &mut usize,
    target: &Q,
    key: impl Fn(&T) -> &Q,
) -> bool {
    while items.get(*cursor).is_some_and(|item| key(item) < target) {
        *cursor += 1;
    }
    items.get(*cursor).is_some_and(|item| key(item) == target)
}

/// Returns whether `staged` holds an update resolved at `target`, advancing `cursor` past updates
/// resolved below it. Successive calls must use non-decreasing `target`s.
fn contains_staged<F: Family, U: update::Update>(
    staged: &StagedUpdates<F, U>,
    cursor: &mut usize,
    target: &Location<F>,
) -> bool {
    while staged
        .get(*cursor)
        .is_some_and(|(_, sloc, _, _)| sloc.loc() < *target)
    {
        *cursor += 1;
    }
    staged
        .get(*cursor)
        .is_some_and(|(_, sloc, _, _)| sloc.loc() == *target)
}

/// Merge the `less`-sorted vectors `a` and `b` into one sorted vector. On ties, the element from
/// `b` comes first.
fn merge_by<T>(a: Vec<T>, b: Vec<T>, less: impl Fn(&T, &T) -> bool) -> Vec<T> {
    if b.is_empty() {
        return a;
    }
    if a.is_empty() {
        return b;
    }
    let mut merged = Vec::with_capacity(a.len() + b.len());
    let mut a = a.into_iter().peekable();
    let mut b = b.into_iter().peekable();
    while let (Some(x), Some(y)) = (a.peek(), b.peek()) {
        if less(x, y) {
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

/// Pending mutations whose old locations were already resolved by staged reads. Entries are
/// sorted by location. Each value is `Some` for an update and `None` for a delete.
///
/// When a [collision sibling can hold a deleted key's predecessor link](update::Parts::SIBLINGS),
/// the deleted key is also a batch delete so that merkleize gathers its translated-key bucket. The entry's location and cached payload still spare merkleize a
/// read of the deleted update.
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

/// One round of floor candidates selected by [`Merkleizer::read_round`].
struct Round<F: Family, U: update::Update> {
    /// The selected candidates outside the inactive set, in ascending order.
    candidates: Vec<Location<F>>,
    /// The operations at the committed `candidates`, which precede the uncommitted ones. The
    /// chunks' concatenation follows candidate order.
    committed: Vec<Vec<Operation<F, U>>>,
}

/// A decision a walk collected for emission after it: the decided
/// update's key and cached payload, how it moves in the diff, and the value to write for the
/// key, or `None` to delete it.
struct Decided<F: Family, U: update::Update> {
    key: U::Key,
    cached: U::Cached,
    mv: Move<F>,
    value: Option<U::Value>,
}

/// The batch's resolved state, which the floor walk and the emission of its decisions advance.
struct Walked<F: Family, U: update::Update> {
    /// The operations the batch appends, in location order.
    ops: Vec<Operation<F, U>>,
    /// This batch's key-level changes, key-sorted once the walk has run.
    diff: DiffVec<U::Key, F, U::Value>,
    /// New entries for keys `diff` lacks, in any order. A key appears in at most one of the two.
    floor_diff: DiffVec<U::Key, F, U::Value>,
    /// The change in active keys since the base.
    active_keys_delta: isize,
}

impl<F: Family, U: update::Update> Walked<F, U> {
    const fn new(
        ops: Vec<Operation<F, U>>,
        diff: DiffVec<U::Key, F, U::Value>,
        active_keys_delta: isize,
    ) -> Self {
        Self {
            ops,
            diff,
            floor_diff: Vec::new(),
            active_keys_delta,
        }
    }
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
/// not an immutable snapshot. Reads through it pass only while the DB sits on one of the chain's
/// own states: the state the chain forked from, an ancestor's tip, or this batch's own tip (once
/// it is applied). After any other batch is applied (a sibling fork, or one of this batch's own
/// descendants), reads refuse with [`crate::qmdb::Error::StaleRead`], and applying the batch or
/// merkleizing a child of it is rejected with [`crate::qmdb::Error::StaleBatch`] (see
/// [`crate::qmdb::chain`] for more details).
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, U: update::Update, S: Strategy> {
    /// Merkleized authenticated journal batch (provides the speculative Merkle root).
    pub(crate) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, U>, S>>,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    /// Sorted by key with no duplicates; queried via `lookup_sorted` (binary search).
    pub(crate) diff: Arc<DiffVec<U::Key, F, U::Value>>,

    /// The parent batch in the chain, if any.
    parent: Option<Weak<Self>>,

    /// Total active keys after this batch.
    pub(crate) total_active_keys: usize,

    /// Arc refs to each ancestor's diff, collected during `finish()` while ancestors are
    /// alive. Reads consult them, and `apply_batch` applies the uncommitted ones.
    /// 1:1 with `bounds.ancestors` (same length, same ordering).
    pub(crate) ancestor_diffs: Vec<Arc<DiffVec<U::Key, F, U::Value>>>,

    /// Locations at `bounds.db` for keys whose retained ancestor diffs cross a dropped prefix.
    /// Only overlapping keys are retained, bounding this by the live speculative suffix rather
    /// than the committed history.
    ancestor_base_locs: AncestorBaseLocs<U::Key, F>,

    /// Position and floor bounds for this batch chain.
    pub(crate) bounds: chain::Bounds<F, D>,
}

/// Strong ref to an ancestor [`MerkleizedBatch`] collected during merkleize.
pub(crate) type AncestorBatch<F, D, U, S> = Arc<MerkleizedBatch<F, D, U, S>>;

/// Ancestors retained while a batch is merkleized, immediate parent first.
pub(crate) type RetainedAncestors<F, D, U, S> = Vec<AncestorBatch<F, D, U, S>>;

/// Result of merkleizing a batch.
type MerkleizeResult<F, D, U, S> = Result<Arc<MerkleizedBatch<F, D, U, S>>, crate::qmdb::Error<F>>;

/// Result of a prepared merkleization: the batch and the ancestors retained while building it.
pub(crate) type RetainedMerkleizeResult<F, D, U, S> = Result<
    (
        Arc<MerkleizedBatch<F, D, U, S>>,
        RetainedAncestors<F, D, U, S>,
    ),
    crate::qmdb::Error<F>,
>;

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

/// A batch whose live chain was validated against the database it will read.
///
/// Keeping the database borrow and retained ancestors together prevents later phases from
/// substituting a different database after validation.
#[allow(clippy::type_complexity)]
pub(crate) struct Prepared<'a, F, E, C, I, H, U, const N: usize, S>
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
    /// The database the batch was validated against.
    db: Onchain<'a, Db<F, E, C, I, H, U, N, S>>,
    /// Pending mutations. `Some(value)` for upsert, `None` for delete.
    mutations: BTreeMap<U::Key, Option<U::Value>>,
    /// Merkleization state, including the retained ancestor chain.
    merkleizer: Merkleizer<F, H, U, S>,
    /// The committed floor candidates a staged merkleize read while it resolved its updates.
    prefetched: Option<Prefetched<F, U>>,
}

/// Result of validating a batch and binding it to the database it will read.
type PrepareResult<'a, F, E, C, I, H, U, const N: usize, S> =
    Result<Prepared<'a, F, E, C, I, H, U, N, S>, crate::qmdb::Error<F>>;

/// Look up a key in the ancestor chain (immediate parent first).
fn resolve_in_ancestors<'a, F: Family, D: Digest, U: update::Update, S: Strategy>(
    ancestors: &'a [Arc<MerkleizedBatch<F, D, U, S>>],
    key: &U::Key,
) -> Option<&'a DiffEntry<F, U::Value>> {
    for batch in ancestors {
        if let Some(entry) = lookup_sorted(batch.diff.as_slice(), key) {
            return Some(entry);
        }
    }
    None
}

/// Resolve `key`'s operation at `loc` against the ancestor chain (immediate parent first).
/// Returns `None` when the nearest ancestor entry for `key` is not an update at `loc`. When no
/// ancestor writes `key`, `loc` must have its activity bit set, and the result is
/// [`StagedLoc::Committed`].
fn locate<F: Family, D: Digest, U: update::Update, S: Strategy>(
    ancestors: &[AncestorBatch<F, D, U, S>],
    loc: Location<F>,
    key: &U::Key,
) -> Option<StagedLoc<F>> {
    let Some(entry) = resolve_in_ancestors(ancestors, key) else {
        return Some(StagedLoc::Committed(loc));
    };
    (entry.loc() == Some(loc)).then(|| StagedLoc::Ancestor {
        loc,
        base_old_loc: entry.base_old_loc(),
    })
}

/// How an active floor candidate records its move when it is rewritten at the tip.
/// [`Merkleizer::classify`] yields it for a keyed operation when the nearest diff entry for its
/// key points at it, or when no diff holds its key. The latter holds for a candidate because,
/// below the database's size, candidates are only locations whose activity bit is set, and that
/// bit marks a key's live update.
///
/// Classification is a pure function of the state after the batch's writes: at most one
/// candidate per key can be active (the database's bitmap holds exactly one set bit per active
/// key, and each diff or ancestor entry resolves a key to a single location), and a move only
/// rewrites the moved key's own diff entry to a location above the walk's end.
///
/// Classifying all candidates against a single snapshot of the diff therefore yields the same
/// outcomes as the interleaved sequential walk, which lets the per-candidate work run sharded
/// across the strategy pool. Decisions that change other keys' entries are emitted after the
/// walk.
enum Move<F: Family> {
    /// The key has a diff entry at this index; rewrite it in place.
    Existing {
        idx: usize,
        base_old_loc: Option<Location<F>>,
    },
    /// The key has no diff entry; stage a new one.
    New { base_old_loc: Option<Location<F>> },
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

/// The keys nearer ancestors hold while the ancestor diffs are walked nearest first: a key's
/// nearest entry, including a deletion, shadows the older entries for it.
///
/// A single ancestor cannot shadow itself and each diff's keys are unique, so a depth-1 chain
/// keeps no set. The set hashes with ahash, which resists adversarial keys yet runs several times
/// faster than SipHash on digest-sized keys, where hashing dominates the probe.
struct Shadow<'a, K> {
    seen: Option<AHashSet<&'a K>>,
}

impl<'a, K: Key> Shadow<'a, K> {
    /// Prepare to walk `diffs`, ordered nearest first.
    fn new<F: Family, V: 'a>(diffs: impl ExactSizeIterator<Item = &'a DiffSlice<K, F, V>>) -> Self {
        let seen =
            (diffs.len() > 1).then(|| AHashSet::with_capacity(diffs.map(|diff| diff.len()).sum()));
        Self { seen }
    }

    /// The updates in `diff`, the next diff of the walk, for keys no nearer diff holds.
    fn updates<F: Family, V>(
        &mut self,
        diff: &'a DiffSlice<K, F, V>,
    ) -> impl Iterator<Item = (&'a K, Location<F>)> {
        diff.iter().filter_map(move |(key, entry)| {
            if self.seen.as_mut().is_some_and(|seen| !seen.insert(key)) {
                return None;
            }
            entry.loc().map(|loc| (key, loc))
        })
    }
}

/// Resolve unresolved input slots against ancestor diffs, preserving final results by original
/// input slot. The caller keeps `pending` in input order so DB fallthrough can do the same.
///
/// `on_hit` is invoked (serially, in `pending` order) with each resolving diff entry, so
/// staged reads can record ancestor resolutions alongside the values.
fn resolve_pending_from_diffs<'a, K, F: Family, V: Clone + Send + Sync + 'a, S: Strategy>(
    pending: &[PendingRead<'a, K>],
    diffs: &[&'a DiffSlice<K, F, V>],
    strategy: &S,
    resolved: &mut [bool],
    results: &mut [Option<V>],
    mut on_hit: impl FnMut(usize, &DiffEntry<F, V>),
) where
    K: Ord + Sync,
{
    if pending.is_empty() || diffs.is_empty() {
        return;
    }

    let resolve = |chunk: &[PendingRead<'a, K>]| -> Vec<(usize, &'a DiffEntry<F, V>)> {
        chunk
            .iter()
            .filter_map(|(slot, key)| {
                diffs
                    .iter()
                    .find_map(|diff| lookup_sorted(diff, key))
                    .map(|entry| (*slot, entry))
            })
            .collect()
    };
    let hits: Vec<(usize, &'a DiffEntry<F, V>)> = strategy.run(
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
}

/// Resolve `keys` against a local source (`local` returns `Some` when it owns the key, with the
/// inner `Option` distinguishing a live value from a delete) and then against `diffs`, returning
/// per-slot results and the slots that still need committed DB reads.
///
/// `on_diff_hit` is invoked with each slot resolved by a diff entry (see
/// [`resolve_pending_from_diffs`]). Slots resolved by `local` do not report.
fn resolve_reads<'a, K, F: Family, V, S: Strategy>(
    keys: &[&'a K],
    local: impl Fn(&K) -> Option<Option<V>>,
    diffs: &[&DiffSlice<K, F, V>],
    strategy: &S,
    on_diff_hit: impl FnMut(usize, &DiffEntry<F, V>),
) -> UncommittedReadResolution<'a, K, V>
where
    K: Ord + Sync,
    V: Clone + Send + Sync,
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
    /// The operation at `loc` in the batch or ancestor regions (`loc` at or past `db_size`).
    fn peek_uncommitted<'o>(
        &'o self,
        loc: Location<F>,
        batch_ops: &'o [Operation<F, U>],
    ) -> &'o Operation<F, U> {
        if loc >= self.base_state.size {
            return &batch_ops[(*loc - *self.base_state.size) as usize];
        }
        read_op_from_ancestors(&self.ancestors, *loc, *self.db_state.size)
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
        // be handed to the reader directly. Depth-0 mutation reads take this path.
        if self.all_committed_ascending(locations) {
            let positions: Vec<u64> = locations.iter().map(|loc| **loc).collect();
            return Ok(reader.read_many(&positions).await?);
        }

        // Resolve the in-memory regions synchronously.
        let mut results: Vec<Option<Operation<F, U>>> = locations
            .iter()
            .map(|loc| {
                (*loc >= self.db_state.size).then(|| self.peek_uncommitted(*loc, batch_ops).clone())
            })
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
        // committed subset is often still presorted (e.g. existing-key locations that cross
        // the committed boundary), so the sort is worth skipping when possible.
        let mut positions: Vec<u64> = committed.iter().map(|(_, loc)| *loc).collect();
        let presorted = positions.is_sorted_by(|a, b| a < b);
        if !presorted {
            positions.sort_unstable();
            positions.dedup();
        }
        let read = reader.read_many(&positions).await?;

        // Merge read results back in order.
        if presorted {
            for ((idx, _), op) in zip_eq(committed, read) {
                results[idx] = Some(op);
            }
        } else {
            for (idx, loc) in committed {
                // `positions` is sorted and deduped, and `loc` came from it before deduping, so
                // binary search must find the matching read_many result.
                let result_idx = positions
                    .binary_search(&loc)
                    .expect("read result missing for requested location");
                results[idx] = Some(read[result_idx].clone());
            }
        }
        Ok(results
            .into_iter()
            .map(|r| r.expect("operation should be resolved"))
            .collect())
    }

    /// Read the updates at `locations`, dropping those an ancestor has superseded.
    ///
    /// The snapshot index reflects the committed state, so a location it holds is stale once a
    /// live ancestor wrote the key elsewhere or deleted it. Admitting a stale update would
    /// misclassify the key's mutation (a re-creation as an update, a redundant delete as live)
    /// or steer the ordered neighbor search with a dead link; the ancestor's diff supplies the
    /// key's live state instead. Every location must hold an update, as snapshot and
    /// ancestor-diff locations do.
    async fn read_live<R: Contiguous<Item = Operation<F, U>>>(
        &self,
        locations: &[Location<F>],
        reader: &R,
    ) -> Result<impl Iterator<Item = (U, Location<F>)>, crate::qmdb::Error<F>> {
        let ops = self.read_ops(locations, &[], reader).await?;
        let live = zip_eq(ops, locations.iter().copied()).filter_map(|(op, loc)| {
            let Operation::Update(update) = op else {
                unreachable!("snapshot locations hold updates");
            };
            locate(&self.ancestors, loc, update.key())
                .is_some()
                .then_some((update, loc))
        });
        Ok(live)
    }

    /// Select the next round of floor candidates from `scan` and read the committed ones. Floor
    /// walks and staged prefetches both read candidates through here.
    ///
    /// The round fills candidates below `last` from `source` until `need` of them may be active,
    /// passing the sorted `inactive` locations without counting them toward `need`. It reads the
    /// committed candidates it selects in one batch. `scan` moves past the round.
    async fn read_round<E, C>(
        &self,
        log: &authenticated::Journal<F, E, C, H, S>,
        scan: &mut Location<F>,
        last: Location<F>,
        need: usize,
        inactive: &[Location<F>],
        source: &mut impl Candidates<F>,
    ) -> Result<Round<F, U>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
    {
        // Reserve for the base's active keys plus the last commit below the database's size, and
        // for every location above it, since a retained log can be far longer than either, and
        // never for more than the locations left below `last`. Set bits of keys that pending
        // ancestors deleted can exceed the reservation, and the selection still asks `source`
        // for the full `need`.
        let uncommitted = (*last).saturating_sub((*self.db_state.size).max(**scan));
        let hint = self
            .base_active_keys
            .saturating_add(1)
            .saturating_add(usize::try_from(uncommitted).unwrap_or(usize::MAX));
        let remaining = usize::try_from((*last).saturating_sub(**scan)).unwrap_or(usize::MAX);
        let mut candidates = Vec::with_capacity(need.min(hint).min(remaining));
        let mut inactive_at = inactive.partition_point(|loc| *loc < *scan);
        while candidates.len() < need && *scan < last {
            let kept = candidates.len();
            let next = source.fill(*scan, *last, need, &mut candidates);
            if candidates.len() == kept {
                // No candidate remains below `last`.
                *scan = last;
                break;
            }
            assert!(candidates[kept..].is_sorted_by(|a, b| a < b));
            *scan = next;

            // With no listed location left ahead, every new candidate counts.
            if inactive_at == inactive.len() {
                continue;
            }

            // Keep the new candidates outside `inactive` in place, compacted after the earlier
            // ones.
            let mut write = kept;
            for at in kept..candidates.len() {
                let loc = candidates[at];
                if sorted_contains_by(inactive, &mut inactive_at, &loc, |item| item) {
                    continue;
                }
                candidates[write] = loc;
                write += 1;
            }
            candidates.truncate(write);
        }

        // Read the committed candidates in one batch.
        let split = candidates.partition_point(|loc| *loc < self.db_state.size);
        let positions: Vec<u64> = candidates[..split].iter().map(|loc| **loc).collect();
        let committed = log.read_many_sharded(&positions).await?;
        Ok(Round {
            candidates,
            committed,
        })
    }

    /// Gather existing-key locations for all keys in `mutations`.
    ///
    /// For each mutation key, checks the ancestor diffs first (returning the uncommitted
    /// location for Active entries, skipping Deleted entries). Keys not in the ancestor diffs
    /// fall back to the committed DB snapshot.
    ///
    /// When [`update::Parts::SIBLINGS`] is set, Active entries also scan the snapshot bucket for
    /// collision siblings (other keys sharing the same translated-key bucket). The ordered path
    /// needs these so their `next_key` pointers are rewritten when a sibling is deleted. The
    /// unordered path skips them.
    fn gather_existing_locations<E, C, I, const N: usize>(
        &self,
        mutations: &BTreeMap<U::Key, Option<U::Value>>,
        db: Onchain<'_, Db<F, E, C, I, H, U, N, S>>,
    ) -> Vec<Location<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        U: update::Parts,
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
                        // No live operation remains. resolve_creates handles any recreation.
                    }
                    Some(DiffEntry::Active {
                        loc, base_old_loc, ..
                    }) => {
                        locations.push(*loc);
                        if U::SIBLINGS {
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

    /// Resolve remaining mutations into creates in key order. Re-created keys inherit
    /// the base location of the nearest ancestor deletion. Existing keys must already
    /// be resolved and removed from `mutations`. Deletes of absent keys are ignored.
    #[allow(clippy::type_complexity)]
    fn resolve_creates(
        &self,
        mutations: BTreeMap<U::Key, Option<U::Value>>,
    ) -> impl Iterator<Item = (U::Key, U::Value, Option<Location<F>>)> {
        let mut ancestors = DiffCursors::new(self.ancestors.iter().map(|a| a.diff.as_slice()));
        mutations.into_iter().filter_map(move |(key, value)| {
            let value = value?;
            let base_old_loc = match ancestors.resolve(&key) {
                Some(DiffEntry::Deleted { base_old_loc }) => *base_old_loc,
                _ => None,
            };
            Some((key, value, base_old_loc))
        })
    }

    /// Classify the operation on `key` at `loc` against the key-sorted batch `diff` and the
    /// ancestor diffs: `None` when it is not its key's active update, else how it moves (see
    /// [`Move`]).
    fn classify(
        &self,
        diff: &DiffSlice<U::Key, F, U::Value>,
        loc: Location<F>,
        key: &U::Key,
    ) -> Option<Move<F>> {
        match diff.binary_search_by(|(k, _)| k.cmp(key)) {
            Ok(idx) if diff[idx].1.loc() == Some(loc) => Some(Move::Existing {
                idx,
                base_old_loc: diff[idx].1.base_old_loc(),
            }),
            Ok(_) => None,
            Err(_) => locate(&self.ancestors, loc, key).map(|sloc| Move::New {
                base_old_loc: sloc.superseded(self.db_state.size),
            }),
        }
    }

    /// Append `update` at the tip and record its new location in the diff or the floor diff of
    /// `walked` as `mv` directs.
    fn relocate(&self, walked: &mut Walked<F, U>, update: U, mv: Move<F>) {
        let loc = self.base_state.size + Widen::widen(walked.ops.len());
        match mv {
            Move::Existing { idx, base_old_loc } => {
                walked.diff[idx].1 = DiffEntry::Active {
                    value: update.value().clone(),
                    loc,
                    base_old_loc,
                };
            }
            Move::New { base_old_loc } => walked.floor_diff.push((
                update.key().clone(),
                DiffEntry::Active {
                    value: update.value().clone(),
                    loc,
                    base_old_loc,
                },
            )),
        }
        walked.ops.push(Operation::Update(update));
    }

    /// Walk the floor from the inherited location over the operations below the tip of
    /// `walked.ops` under the limits `policy` sets for the writes, returning the floor it reached
    /// and the decisions it collected in ascending location order.
    ///
    /// `policy` decides each active update the walk reaches. The walk applies the decisions of a
    /// policy that never evicts as it makes them. Otherwise they wait for the caller to emit
    /// them: an ordered batch folds the link repairs its evictions require into the updates it
    /// emits, and an unordered batch emits them as they are. An empty state has no active
    /// update, so the walk does not run.
    ///
    /// `superseded_locs` holds the committed locations the batch's writes supersede, in any order.
    /// The walk passes them and the last committed commit without reading them. Every other
    /// candidate it meets is read and classified, including updates that pending ancestors
    /// superseded.
    ///
    /// `walked.diff` may arrive in any order: it is key-sorted on the strategy pool, overlapping
    /// the first candidate read. The walk takes the `prefetched` round whole as its first, and
    /// `source` supplies the rest under the [`Candidates`] contract.
    #[allow(clippy::type_complexity)]
    async fn walk<E, C, I, P, const N: usize>(
        &self,
        walked: &mut Walked<F, U>,
        mut superseded_locs: Vec<Location<F>>,
        policy: &mut P,
        mut prefetched: Option<Prefetched<F, U>>,
        mut source: impl Candidates<F>,
        db: Onchain<'_, Db<F, E, C, I, H, U, N, S>>,
    ) -> Result<(Location<F>, Vec<Decided<F, U>>), crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        U: update::Parts,
        P: Policy<F, U::Key, U::Value>,
    {
        // Key-sort the diff as one job on the strategy: candidate classification is the earliest
        // consumer that needs it sorted, so the sort overlaps the first candidate read instead of
        // the calling task. An empty diff is already sorted and skips the job. While the job
        // runs, `walked.diff` is empty; the sorted diff replaces it at the first await.
        let mut diff_sort = None;
        if !walked.diff.is_empty() {
            let unsorted = mem::take(&mut walked.diff);
            diff_sort = Some(db.strategy().spawn(unsorted.len(), move |strategy| {
                let mut diff = unsorted;
                strategy.sort_by(&mut diff, |a, b| a.0.cmp(&b.0));
                diff
            }));
        }

        // Every write supersedes one update except a create, and a delete is itself inactive, so
        // the writes made `ops.len() - active_keys_delta` operations inactive: one per superseded
        // update and two per delete. The policy's limits follow from that count. The walk's own
        // effects lie above the tip, which it never reaches, and each moves one of the active keys.
        let active_keys =
            usize::try_from(self.base_active_keys as isize + walked.active_keys_delta)
                .expect("active_keys underflow");
        let made_inactive = usize::try_from(walked.ops.len() as isize - walked.active_keys_delta)
            .expect("a batch creates at most one key per write");
        let Limits { entries, skips } = policy.limits(made_inactive);
        let evicts = policy.evicts();
        let tip = self.base_state.size + Widen::widen(walked.ops.len());
        let mut walk = Walk::new(self.base_inactivity_floor_loc, tip, entries, skips);
        let strategy = db.strategy();
        if !evicts {
            // The walk appends at most one moved op per entry or active key, plus the CommitFloor.
            let moves = entries.min(active_keys);
            walked.ops.reserve(moves + 1);
            walked.floor_diff.reserve(moves);
        }

        // The unread inactive list is built only for a walk that runs. Locations are unique (each
        // committed location belongs to exactly one key), so a presorted collection needs no sort,
        // and the last committed commit lies past every superseded location.
        let runs = active_keys > 0 && walk.entries > 0;
        let mut inactive = Vec::new();
        if runs {
            if !superseded_locs.is_sorted_by(|a, b| a < b) {
                strategy.sort_by(&mut superseded_locs, |a, b| a.cmp(b));
            }
            superseded_locs.push(self.db_state.size - 1);
            inactive = superseded_locs;
        }

        let mut decided = Vec::new();
        let mut scan = walk.floor;
        'walk: while runs && walk.entries > 0 {
            let round = match prefetched.take() {
                Some((round, next)) => {
                    scan = next;
                    round
                }
                None if scan < walk.end => {
                    self.read_round(
                        &db.log,
                        &mut scan,
                        walk.end,
                        walk.entries,
                        &inactive,
                        &mut source,
                    )
                    .await?
                }
                None => {
                    walk.exhaust();
                    break;
                }
            };

            // Uncommitted candidates, in the ancestors or this batch, resolve in memory by
            // reference, and their operations follow the committed ones.
            let split = round
                .candidates
                .partition_point(|loc| *loc < self.db_state.size);
            let memory: Vec<&Operation<F, U>> = round.candidates[split..]
                .iter()
                .map(|loc| self.peek_uncommitted(*loc, &walked.ops))
                .collect();

            // Classification is the first consumer of the sorted diff. By now the sort has
            // overlapped the fill and read above.
            if let Some(job) = diff_sort.take() {
                walked.diff = job.await;
            }

            // Classify each candidate, as a [`Move`], against the state after the writes. A
            // CommitFloor has no key and is inactive.
            let diff = &walked.diff;
            let moves: Vec<Option<Move<F>>> = strategy.map_collect_vec(
                zip_eq(
                    round.candidates.iter(),
                    round.committed.iter().flatten().chain(memory),
                ),
                |(loc, op)| op.key().and_then(|key| self.classify(diff, *loc, key)),
            );

            // The round decides at most its candidates, the remaining entries, and the active
            // keys not yet decided.
            if evicts {
                decided.reserve(
                    round
                        .candidates
                        .len()
                        .min(walk.entries)
                        .min(active_keys - decided.len()),
                );
            }

            // Reach each active candidate in order, moving committed operations out of the read
            // and cloning in-memory ones.
            let mut reads = round.committed.into_iter().flatten();
            for (at, (loc, mv)) in zip_eq(round.candidates, moves).enumerate() {
                let read =
                    (at < split).then(|| reads.next().expect("one read per committed candidate"));
                let Some(mv) = mv else {
                    continue;
                };
                if !walk.reach(loc) {
                    break 'walk;
                }
                let op = read.unwrap_or_else(|| self.peek_uncommitted(loc, &walked.ops).clone());
                let Operation::Update(update) = op else {
                    unreachable!("active operations are updates")
                };
                let (key, value, cached) = update.into_parts();
                let action = policy.decide(Entry::new(loc, &key, value)).into_action();
                if evicts {
                    let value = match action {
                        Action::Write(value) => Some(value),
                        Action::Evict => None,
                        Action::Stop => break 'walk,
                    };
                    decided.push(Decided {
                        key,
                        cached,
                        mv,
                        value,
                    });
                } else {
                    match action {
                        Action::Write(value) => {
                            self.relocate(walked, U::from_parts(key, value, cached), mv)
                        }
                        Action::Stop => break 'walk,
                        Action::Evict => unreachable!("a policy that never evicts returned Evict"),
                    }
                }
                walk.decide();
                if walk.entries == 0 {
                    break 'walk;
                }
            }
        }

        // Every later phase needs the sorted diff.
        if let Some(job) = diff_sort.take() {
            walked.diff = job.await;
        }
        Ok((walk.floor, decided))
    }

    /// Append the effect of `decided` at the tip and record it in the diff: a value is written for
    /// the key as [`relocate`](Self::relocate) moves an update, and `None` deletes the key.
    fn emit(&self, walked: &mut Walked<F, U>, decided: Decided<F, U>)
    where
        U: update::Parts,
    {
        let Decided {
            key,
            cached,
            mv,
            value,
        } = decided;
        let Some(value) = value else {
            walked.active_keys_delta -= 1;
            match mv {
                Move::Existing { idx, base_old_loc } => {
                    walked.ops.push(Operation::Delete(key));
                    walked.diff[idx].1 = DiffEntry::Deleted { base_old_loc };
                }
                Move::New { base_old_loc } => {
                    walked.ops.push(Operation::Delete(key.clone()));
                    walked
                        .floor_diff
                        .push((key, DiffEntry::Deleted { base_old_loc }));
                }
            }
            return;
        };
        self.relocate(walked, U::from_parts(key, value, cached), mv);
    }

    /// Shared final phases of merkleization: the empty-state floor, the merge of the walk's new
    /// diff entries, the CommitFloor, the journal merkleize, and the `MerkleizedBatch`. `floor`
    /// is the floor the walk reached.
    async fn finish<E, C, I, const N: usize>(
        self,
        walked: Walked<F, U>,
        mut floor: Location<F>,
        metadata: Option<U::Value>,
        db: Onchain<'_, Db<F, E, C, I, H, U, N, S>>,
    ) -> RetainedMerkleizeResult<F, H::Digest, U, S>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let Walked {
            mut ops,
            mut diff,
            floor_diff,
            active_keys_delta,
        } = walked;
        let total_active_keys = self.base_active_keys as isize + active_keys_delta;
        assert!(total_active_keys >= 0, "active_keys underflow");
        if total_active_keys == 0 {
            // DB is empty after this batch; raise floor to tip.
            floor = self.base_state.size + Widen::widen(ops.len());
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        }

        // Merge the walk's new diff entries as one job on the strategy: nothing below reads `diff`
        // until after the journal merkleization, so the merge overlaps the hashing instead of the
        // calling task. [`Walked`] keeps `floor_diff` to keys absent from `diff`, so the merge
        // inputs are disjoint.
        let mut diff_merge = None;
        if !floor_diff.is_empty() {
            let merge_len = floor_diff.len() + diff.len();
            diff_merge = Some(db.strategy().spawn(merge_len, move |strategy| {
                let mut floor_diff = floor_diff;
                strategy.sort_by(&mut floor_diff, |a, b| a.0.cmp(&b.0));
                let diff = merge_by(diff, floor_diff, |a, b| a.0 < b.0);
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

        // Leaf and node hashing dominate merkleization, so run them as one job through the
        // strategy (see `Journal::merkleize`).
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
        let ancestors: Vec<_> = self.ancestors.iter().map(|a| a.commitment()).collect();

        let batch = Arc::new(MerkleizedBatch {
            journal_batch: journal,
            diff: Arc::new(diff),
            parent: self.ancestors.first().map(Arc::downgrade),
            total_active_keys: total_active_keys as usize,
            ancestor_diffs,
            ancestor_base_locs,
            bounds: chain::Bounds {
                base: self.base_state,
                db: self.db_state,
                tip: Commitment::new(commit_loc + 1, root),
                ancestors,
                inactivity_floor: floor,
            },
        });
        Ok((batch, self.ancestors))
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
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on the batch's chain.
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
        let db = self.batch.onchain(db)?;
        let (values, keys, mut resolutions) = self.batch.stage_reads(keys, db).await?;
        self.keys.extend(keys);
        self.resolutions.append(&mut resolutions);
        Ok((start..end, values, self))
    }

    fn apply_upserts(
        mut mutations: BTreeMap<U::Key, Option<U::Value>>,
        upserts: Vec<(U::Key, Option<U::Value>)>,
    ) -> BTreeMap<U::Key, Option<U::Value>> {
        for (key, value) in upserts {
            mutations.insert(key, value);
        }
        mutations
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
    /// Location-resolved updates and deletes (committed, or ancestor-diff when the update kind
    /// [stages those](update::Update::STAGES_ANCESTORS)) reuse the staged location.
    /// Unresolved keys (missing from committed state, resolved through this batch's own
    /// mutations, or ancestor-resolved for a kind that does not stage those) always fall back to
    /// normal mutations.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub(crate) fn resolve_updates(
        self,
        updates: Vec<(usize, Option<U::Value>)>,
        upserts: Vec<(U::Key, Option<U::Value>)>,
        strategy: &S,
    ) -> (UnmerkleizedBatch<F, H, U, S>, StagedUpdates<F, U>)
    where
        U: update::Parts,
    {
        let Self {
            mut batch,
            keys,
            resolutions,
        } = self;
        let mutations = mem::take(&mut batch.mutations);
        let (mutations, staged_updates) =
            Self::resolve_update_parts(mutations, keys, resolutions, updates, upserts, strategy);
        batch.mutations = mutations;
        (batch, staged_updates)
    }

    /// Resolve staged updates using only owned data, allowing the work to run on a detached
    /// strategy job while the prepared batch retains its database borrow and ancestor chain.
    #[allow(clippy::type_complexity)]
    fn resolve_update_parts(
        mut mutations: BTreeMap<U::Key, Option<U::Value>>,
        keys: Vec<U::Key>,
        mut resolutions: Vec<StagedResolution<F, U>>,
        updates: Vec<(usize, Option<U::Value>)>,
        upserts: Vec<(U::Key, Option<U::Value>)>,
        strategy: &S,
    ) -> (BTreeMap<U::Key, Option<U::Value>>, StagedUpdates<F, U>)
    where
        U: update::Parts,
    {
        let mut staged_updates = StagedUpdates::<F, U>::new();
        if updates.is_empty() {
            return (Self::apply_upserts(mutations, upserts), staged_updates);
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

        // Split the winners: writes whose slot resolved to a location become staged updates, and
        // the rest fall back to batch mutations.
        //
        // A staged write must not also emit an older batch mutation for its key, so that mutation
        // is removed, except that a staged delete is also written as a batch delete when a
        // collision sibling can hold its predecessor link, the [`StagedUpdates`] case.
        //
        // The removal probe is skipped when the batch had no mutations before this call: each
        // distinct key is visited at most once (winners are per key), so a staged winner can never
        // chase a fallback inserted by this same loop.
        let had_mutations = !mutations.is_empty();
        let mut order: Vec<(Location<F>, usize)> = Vec::with_capacity(winners.len());
        for (entry, winner) in winners.iter_mut().enumerate() {
            let Some((slot, value)) = winner else {
                continue;
            };
            let key = &keys[*slot];
            match &resolutions[*slot] {
                Some((sloc, _)) => {
                    if value.is_none() && U::SIBLINGS {
                        mutations.insert(key.clone(), None);
                    } else if had_mutations {
                        mutations.remove(key);
                    }
                    order.push((sloc.loc(), entry));
                }
                None => {
                    let (_, value) = winner.take().expect("winner checked above");
                    mutations.insert(key.clone(), value);
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
        (Self::apply_upserts(mutations, upserts), staged_updates)
    }
}

impl<F: Family, K, V, H, S: Strategy> Staged<F, H, update::Unordered<K, V>, S>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, advance the inactivity floor
    /// with [`Policy`], then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](Staged::expand) before this
    /// method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) ranges. `metadata` is committed with the returned batch.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleBatch`] if `db` is not on the batch's live chain.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    #[tracing::instrument(
        name = "qmdb.any.unordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(updates = updates.len() as u64, upserts = upserts.len() as u64),
    )]
    pub async fn merkleize<E, C, I, P, const N: usize>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        metadata: Option<V::Value>,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Unordered<K, V>, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
        P: Policy<F, K, V::Value>,
    {
        let fill: &Shared<N> = &db.bitmap;
        let (prepared, staged) = self
            .resolve_updates_prefetched(updates, upserts, db, &*policy, fill)
            .await?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_walk(metadata, staged, fill, policy)
            .await?;
        Ok(batch)
    }

    /// Resolve the caller's updates on the strategy pool while selecting and reading committed
    /// floor candidates under `policy`'s limits, overlapping the two. Returns the prepared batch,
    /// holding the prefetched round, and the staged updates.
    ///
    /// Preparation validates and retains the live chain before any supplied-database read.
    ///
    /// The prefetch selects candidates with [`Merkleizer::read_round`] from the base floor and the
    /// `source` the floor walk scans, without knowing which locations the resolution makes
    /// inactive, so it asks `policy` for the limits of an estimated count and may read locations the
    /// walk then passes. It selects up to those `entries` candidates below the walk's window end.
    /// The walk takes the round whole as its first and resumes where the prefetch stopped.
    ///
    /// The selection is clamped to the committed boundary: a speculative source (e.g. the current
    /// variant's parent bitmap) extends past it, but its candidate sequence below the boundary is
    /// identical and only committed locations need the log read.
    pub(crate) async fn resolve_updates_prefetched<'a, E, C, I, const N: usize>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        db: &'a Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        policy: &impl Policy<F, K, V::Value>,
        mut source: impl Candidates<F>,
    ) -> Result<
        (
            Prepared<'a, F, E, C, I, H, update::Unordered<K, V>, N, S>,
            StagedUpdates<F, update::Unordered<K, V>>,
        ),
        crate::qmdb::Error<F>,
    >
    where
        E: Context,
        C: Contiguous<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let Self {
            batch,
            keys,
            resolutions,
        } = self;
        let mut prepared = batch.prepare(db)?;
        let db = prepared.db;
        let floor = prepared.merkleizer.base_inactivity_floor_loc;
        let db_size = prepared.merkleizer.db_state.size;

        // Estimate the operations the writes will make inactive, which sets the policy's limits
        // for this prefetch: one per update of an existing key and two per delete of one.
        //
        // An op is emitted per location-resolved staged slot plus per upsert or prior mutation on
        // a key alive in the committed snapshot. A slot written more than once counts only its
        // final write. Fresh-key creates make nothing inactive, so unresolved slots and writes
        // missing from the snapshot are excluded (one in-memory probe per key).
        //
        // The estimate is approximate in both directions. Surplus candidates (a translated-key
        // collision, a key an ancestor already deleted, or a key that another slot or an upsert
        // also writes) are dropped by the walk once its entries run out. A shortfall (an upsert
        // or prior mutation whose key is live only in an ancestor's diff) makes the walk read
        // further rounds when the prefetched prefix runs out.
        let made_inactive = |value: &Option<V::Value>| if value.is_some() { 1 } else { 2 };
        let mut counted = vec![false; resolutions.len()];
        let mut staged = 0;
        for (slot, value) in updates.iter().rev() {
            if resolutions.get(*slot).is_some_and(Option::is_some) && !counted[*slot] {
                counted[*slot] = true;
                staged += made_inactive(value);
            }
        }
        let existing: usize = upserts
            .iter()
            .map(|(key, value)| (key, value))
            .chain(&prepared.mutations)
            .filter(|&(key, _)| db.snapshot.get(key).next().is_some())
            .map(|(_, value)| made_inactive(value))
            .sum();
        let Limits { entries, skips } = policy.limits(staged + existing);

        // The walk reads nothing at or past the end of its window. Below the committed boundary
        // the activity bitmap has one set bit per active key plus the last commit, which the walk
        // passes unread.
        let last = Walk::new(floor, db_size, entries, skips).end;
        let need = entries.min(db.active_keys);
        let inactive = [db_size - 1];

        // Overlap the serial update resolution with the candidate prefetch, which depends only on
        // the base floor, the candidate source, and the limits. Only owned update data moves into
        // the job; the prepared batch retains the live ancestor chain.
        let resolve_len = updates.len() + upserts.len();
        let mutations = mem::take(&mut prepared.mutations);
        let resolve = db.strategy().spawn(resolve_len, move |strategy| {
            Self::resolve_update_parts(mutations, keys, resolutions, updates, upserts, &strategy)
        });

        // Select and read the committed candidates while the resolution job runs.
        let mut scan = floor;
        let round = prepared
            .merkleizer
            .read_round(&db.log, &mut scan, last, need, &inactive, &mut source)
            .await;

        // Join the resolution and surface any read failure.
        let (mutations, staged_updates) = resolve.await;
        prepared.mutations = mutations;
        prepared.prefetched = Some((round?, scan));
        Ok((prepared, staged_updates))
    }
}

impl<F: Family, K, V, H, S: Strategy> Staged<F, H, update::Ordered<K, V>, S>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, advance the inactivity floor
    /// with [`Policy`], then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](Staged::expand) before this
    /// method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial [`stage`](UnmerkleizedBatch::stage) input followed by any
    /// [`expand`](Staged::expand) ranges. `metadata` is committed with the returned batch.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleBatch`] if `db` is not on the batch's live chain.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    #[tracing::instrument(
        name = "qmdb.any.ordered.batch.merkleize.staged",
        level = "info",
        skip_all,
        fields(updates = updates.len() as u64, upserts = upserts.len() as u64),
    )]
    pub async fn merkleize<E, C, I, P, const N: usize>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        metadata: Option<V::Value>,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Ordered<K, V>, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
        P: Policy<F, K, V::Value>,
    {
        let fill: &Shared<N> = &db.bitmap;
        let (batch, staged) = self.resolve_updates(updates, upserts, db.strategy());
        let prepared = batch.prepare(db)?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_walk(metadata, staged, fill, policy)
            .await?;
        Ok(batch)
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

    /// Collect the currently-live ancestor chain, immediate parent first.
    fn retain_ancestors(&self) -> Vec<AncestorBatch<F, H::Digest, U, S>> {
        self.base.parent().map_or_else(Vec::new, |parent| {
            let mut ancestors = vec![Arc::clone(parent)];
            ancestors.extend(parent.ancestors());
            ancestors
        })
    }

    /// Split into pending mutations and the merkleization machinery.
    #[allow(clippy::type_complexity)]
    fn into_parts(self) -> (BTreeMap<U::Key, Option<U::Value>>, Merkleizer<F, H, U, S>) {
        let ancestors = self.retain_ancestors();
        let db_state = chain::effective_boundary(
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

    /// Prove the live database is on this chain's own states, returning the witness
    /// committed reads require (see [`Bounds::onchain`]).
    #[allow(clippy::type_complexity)]
    pub(crate) fn onchain<'a, E, C, I, const N: usize>(
        &self,
        db: &'a Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Onchain<'a, Db<F, E, C, I, H, U, N, S>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        match &self.base {
            Base::Db { state, .. } => state.onchain(db, db.commitment()),
            Base::Child(parent) => parent.bounds.onchain(db, db.commitment()),
        }
    }

    /// Validate this batch and bind its retained chain to the exact database used by all
    /// subsequent merkleization reads.
    pub(crate) fn prepare<'a, E, C, I, const N: usize>(
        self,
        db: &'a Db<F, E, C, I, H, U, N, S>,
    ) -> PrepareResult<'a, F, E, C, I, H, U, N, S>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        let (mutations, merkleizer) = self.into_parts();
        let db = chain::merkleizable(
            db,
            db.commitment(),
            merkleizer.db_state,
            merkleizer
                .ancestors
                .iter()
                .map(|ancestor| ancestor.commitment()),
        )?;
        Ok(Prepared {
            db,
            mutations,
            merkleizer,
            prefetched: None,
        })
    }

    /// Return true when reads can bypass uncommitted overlay resolution and go directly to the DB.
    fn reads_committed_only(&self) -> bool {
        self.mutations.is_empty() && self.base.parent().is_none()
    }

    /// Resolve keys against this batch's mutations and ancestor diffs, returning partial
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
    ) -> UncommittedReadResolution<'a, U::Key, U::Value> {
        let diffs: Vec<_> = self.base.parent().map_or_else(Vec::new, |parent| {
            let mut diffs = vec![parent.diff.as_slice()];
            diffs.extend(parent.ancestor_diffs.iter().map(|diff| diff.as_slice()));
            diffs
        });
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
        db: Onchain<'_, Db<F, E, C, I, H, U, N, S>>,
        results: &mut [Option<U::Value>],
        map: impl Fn(U, Location<F>) -> T + Send + Sync,
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
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on the batch's chain.
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
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on the batch's chain.
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
        let db = self.onchain(db)?;
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
            |data, _| data.into_value(),
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
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on the batch's chain.
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
        let (results, keys, resolutions) = self.stage_reads(keys, self.onchain(db)?).await?;
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
        db: Onchain<'_, Db<F, E, C, I, H, U, N, S>>,
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
            |data, loc| {
                let payload = data.cached();
                (data.into_value(), loc, payload)
            },
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
    /// Resolve mutations into operations, advance the inactivity floor with [`Policy`], merkleize,
    /// and return an `Arc<MerkleizedBatch>`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleBatch`] if `db` is not on the batch's live chain.
    #[tracing::instrument(
        name = "qmdb.any.unordered.batch.merkleize",
        level = "info",
        skip_all,
        fields(mutations = self.mutations.len() as u64),
    )]
    pub async fn merkleize<E, C, I, P, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Unordered<K, V>, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
        I: UnorderedIndex<Value = Location<F>>,
        P: Policy<F, K, V::Value>,
    {
        let fill: &Shared<N> = &db.bitmap;
        let prepared = self.prepare(db)?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_walk(metadata, Vec::new(), fill, policy)
            .await?;
        Ok(batch)
    }
}

impl<'a, F, K, V, E, C, I, H, const N: usize, S>
    Prepared<'a, F, E, C, I, H, update::Unordered<K, V>, N, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    E: Context,
    C: Mutable<Item = Operation<F, update::Unordered<K, V>>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, update::Unordered<K, V>>: Codec,
{
    /// Complete a prepared merkleization, consuming staged updates recorded by
    /// [`Staged::merkleize`] (loaded keys skip the journal re-read their resolution would otherwise
    /// require) and walking the floor with `policy` over the candidates `source` supplies under
    /// the [`Candidates`] contract.
    pub(crate) async fn merkleize_with_floor_walk<T: Candidates<F>, P>(
        self,
        metadata: Option<V::Value>,
        staged_updates: StagedUpdates<F, update::Unordered<K, V>>,
        source: T,
        policy: &mut P,
    ) -> RetainedMerkleizeResult<F, H::Digest, update::Unordered<K, V>, S>
    where
        P: Policy<F, K, V::Value>,
    {
        let Self {
            db,
            mut mutations,
            merkleizer: m,
            prefetched,
        } = self;

        // Resolve existing keys. Staged records already resolved their exact locations, so those
        // need no read.
        let mut locations = m.gather_existing_locations(&mutations, db);
        if !staged_updates.is_empty() {
            let mut staged_at = 0;
            locations.retain(|loc| {
                !contains_staged::<F, update::Unordered<K, V>>(&staged_updates, &mut staged_at, loc)
            });
        }
        let results = m.read_ops(&locations, &[], &db.log).await?;

        // Generate user mutation operations.
        let mut ops: Vec<Operation<F, update::Unordered<K, V>>> =
            Vec::with_capacity(mutations.len() + staged_updates.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> =
            Vec::with_capacity(mutations.len() + staged_updates.len());

        // Committed locations superseded by this batch, which the floor walk passes without reading
        // them. Emission order is ascending in `base_old_loc` except for entries resolved through
        // ancestor diffs, so the walk usually skips sorting them.
        let mut superseded_locs: Vec<Location<F>> = Vec::with_capacity(diff.capacity());
        let mut active_keys_delta: isize = 0;

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
        };

        // Process updates/deletes of existing keys in location order, merging staged entries
        // into the read results. This includes keys from both the committed snapshot and ancestor
        // diffs. A staged entry's `value` is `Some` for an update and `None` for a delete; the staged
        // location orders the write, and `emit` appends its `Update`/`Delete` at the next batch
        // location. An ancestor-staged
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
        let mut cached = staged_updates.into_iter().peekable();
        for (op, &old_loc) in zip_eq(results, &locations) {
            while cached
                .peek()
                .is_some_and(|&(_, sloc, (), _)| sloc.loc() < old_loc)
            {
                let (key, sloc, (), mutation) = cached.next().expect("peeked entry exists");
                emit(key, sloc.superseded(m.db_state.size), mutation);
            }

            let key = op.into_key().expect("updates should have a key");

            // A key resolved via the ancestor diff must only match at its ancestor-diff
            // location. Without this guard, a stale snapshot collision (the pre-parent DB
            // snapshot still containing the key's old location) can consume the mutation at the
            // wrong sort position, changing the operation order relative to the committed-state
            // path. When the ancestor diff entry does match, use it to trace `base_old_loc`
            // back to the key's location in the committed DB snapshot.
            let base_old_loc = if let Some(entry) = resolve_in_ancestors(&m.ancestors, &key) {
                if entry.loc() != Some(old_loc) {
                    continue;
                }
                entry.base_old_loc()
            } else {
                Some(old_loc)
            };

            let Some(mutation) = mutations.remove(&key) else {
                // Snapshot index collision: this operation's key does not match
                // any mutation key. The mutation will be handled as a create below.
                continue;
            };

            emit(key, base_old_loc, mutation);
        }
        for (key, sloc, (), mutation) in cached {
            emit(key, sloc.superseded(m.db_state.size), mutation);
        }

        // Process all creates in key order, including parent-deleted keys being
        // re-created, so operation order is independent of ancestor commit state.
        for (key, value, base_old_loc) in m.resolve_creates(mutations) {
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

        // Remaining phases: floor walk, its decisions, CommitFloor, journal, diff merge. Each
        // decision appends one operation, and the CommitFloor follows.
        let mut walked = Walked::new(ops, diff, active_keys_delta);
        let (floor, decided) = m
            .walk(&mut walked, superseded_locs, policy, prefetched, source, db)
            .await?;
        walked.ops.reserve(decided.len() + 1);
        walked.floor_diff.reserve(decided.len());
        for decided in decided {
            m.emit(&mut walked, decided);
        }
        m.finish(walked, floor, metadata, db).await
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
    /// Resolve mutations into operations, advance the inactivity floor with [`Policy`], merkleize,
    /// and return an `Arc<MerkleizedBatch>`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleBatch`] if `db` is not on the batch's live chain.
    #[tracing::instrument(
        name = "qmdb.any.ordered.batch.merkleize",
        level = "info",
        skip_all,
        fields(mutations = self.mutations.len() as u64),
    )]
    pub async fn merkleize<E, C, I, P, const N: usize>(
        self,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
        metadata: Option<V::Value>,
        policy: &mut P,
    ) -> MerkleizeResult<F, H::Digest, update::Ordered<K, V>, S>
    where
        E: Context,
        C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
        P: Policy<F, K, V::Value>,
    {
        let fill: &Shared<N> = &db.bitmap;
        let prepared = self.prepare(db)?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_walk(metadata, Vec::new(), fill, policy)
            .await?;
        Ok(batch)
    }
}

impl<'a, F, K, V, E, C, I, H, const N: usize, S>
    Prepared<'a, F, E, C, I, H, update::Ordered<K, V>, N, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    E: Context,
    C: Mutable<Item = Operation<F, update::Ordered<K, V>>>,
    I: OrderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Complete a prepared merkleization, consuming staged updates recorded by
    /// [`Staged::merkleize`] (loaded keys skip the journal re-read their resolution would otherwise
    /// require: the caller's new value and the cached next key feed op generation directly, and
    /// updates also skip the index probe) and walking the floor with `policy` over the candidates
    /// `source` supplies under the [`Candidates`] contract.
    pub(crate) async fn merkleize_with_floor_walk<T: Candidates<F>, P>(
        self,
        metadata: Option<V::Value>,
        staged_updates: StagedUpdates<F, update::Ordered<K, V>>,
        source: T,
        policy: &mut P,
    ) -> RetainedMerkleizeResult<F, H::Digest, update::Ordered<K, V>, S>
    where
        P: Policy<F, K, V::Value>,
    {
        let Self {
            db,
            mut mutations,
            merkleizer: m,
            prefetched,
        } = self;

        // Resolve existing keys. Staged records already resolved their exact locations, so those
        // need no read. Other locations in their buckets still hold collision siblings.
        let mut locations = m.gather_existing_locations(&mutations, db);
        if !staged_updates.is_empty() {
            let mut staged_at = 0;
            locations.retain(|loc| {
                !contains_staged::<F, update::Ordered<K, V>>(&staged_updates, &mut staged_at, loc)
            });
        }

        // Classify mutations into deleted, created, updated, collecting the successor and
        // predecessor candidates the link rewrites consult once they are sorted below.
        let mut neighbors: Neighbors<K, (Cow<'_, V::Value>, Location<F>)> = Neighbors::new();
        let mut deleted: Vec<(K, Location<F>)> = Vec::new();
        let mut updated: Vec<(K, V::Value, Location<F>)> = Vec::new();
        for (update, old_loc) in m.read_live(&locations, &db.log).await? {
            let update::Ordered {
                key,
                value,
                next_key,
            } = update;
            neighbors.next.push(next_key);
            neighbors
                .prev
                .push((key.clone(), Some((Cow::Owned(value), old_loc))));

            let Some(mutation) = mutations.remove(&key) else {
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

        // Keep creates in key order for candidate lookups and operation emission,
        // including keys re-created after an ancestor deleted them.
        let mut created: Vec<(K, V::Value, Option<Location<F>>)> =
            Vec::with_capacity(mutations.len());
        for (key, value, base_old_loc) in m.resolve_creates(mutations) {
            neighbors.next.push(key.clone());
            created.push((key, value, base_old_loc));
        }

        // Look up prev_translated_key for created/deleted keys, including staged deletes.
        let mut prev_locations = Vec::new();
        for key in deleted
            .iter()
            .map(|(k, _)| k)
            .chain(created.iter().map(|(k, _, _)| k))
            .chain(
                staged_updates
                    .iter()
                    .filter(|(.., value)| value.is_none())
                    .map(|(key, ..)| key),
            )
        {
            let Some((iter, _)) = db.snapshot.prev_translated_key(key) else {
                continue;
            };
            prev_locations.extend(iter.copied());
        }
        prev_locations.sort();
        prev_locations.dedup();
        if !staged_updates.is_empty() {
            let mut staged_at = 0;
            prev_locations.retain(|loc| {
                !contains_staged::<F, update::Ordered<K, V>>(&staged_updates, &mut staged_at, loc)
            });
        }

        // Those updates may precede the created and deleted keys, and their successors may
        // follow the created keys.
        for (update, old_loc) in m.read_live(&prev_locations, &db.log).await? {
            neighbors.next.push(update.next_key);
            neighbors
                .prev
                .push((update.key, Some((Cow::Owned(update.value), old_loc))));
        }

        // Merge staged-resolved records: they skip the journal re-read, and updates also skip the
        // index probe. Each record's cached successor feeds the successor candidates as the skipped
        // read would have.
        //
        // An update is a predecessor candidate without a rewrite source: its own operation carries
        // its link, and the predecessor rewrites skip every key present in `updated`. A deleted
        // key is never a predecessor.
        //
        // An ancestor-resolved record's superseded base is re-resolved through the live ancestor
        // diffs when its operation is emitted below.
        for (key, sloc, old_next, value) in staged_updates {
            let loc = sloc.loc();
            neighbors.next.push(old_next);
            if let Some(value) = value {
                neighbors.prev.push((key.clone(), None));
                updated.push((key, value, loc));
            } else {
                deleted.push((key, loc));
            }
        }
        db.strategy().sort_by(&mut deleted, |a, b| a.0.cmp(&b.0));
        db.strategy().sort_by(&mut updated, |a, b| a.0.cmp(&b.0));

        // Add the ancestors' live updates of keys this batch leaves alone: they may precede or
        // follow this batch's mutations but are invisible to the base-DB-only
        // `prev_translated_key` lookup above. Existing-key updates preserve membership, so their
        // resolved successors suffice and no predecessor is rewritten.
        //
        // Each diff is key-sorted, as are `updated`/`created`/`deleted`, so the held check
        // advances three cursors in a sorted merge instead of three binary searches per key.
        let changes_membership = !created.is_empty() || !deleted.is_empty();
        if changes_membership {
            let mut shadow = Shadow::new(m.ancestors.iter().map(|a| a.diff.as_slice()));
            for batch in &m.ancestors {
                let (mut ui, mut ci, mut di) = (0, 0, 0);
                for (key, loc) in shadow.updates(&batch.diff) {
                    if sorted_contains_by(&updated, &mut ui, key, |(k, ..)| k)
                        || sorted_contains_by(&created, &mut ci, key, |(k, ..)| k)
                        || sorted_contains_by(&deleted, &mut di, key, |(k, _)| k)
                    {
                        continue;
                    }
                    let data = batch.update_at(loc);
                    neighbors.next.push(data.key.clone());
                    neighbors.next.push(data.next_key.clone());
                    neighbors
                        .prev
                        .push((data.key.clone(), Some((Cow::Borrowed(&data.value), loc))));
                }
            }
        }

        // Resolved operations can still reference keys deleted by this batch. Only membership
        // changes consult the predecessor candidates.
        let is_deleted = |key: &K| deleted.binary_search_by(|(k, _)| k.cmp(key)).is_ok();
        neighbors.finish_next(db.strategy(), is_deleted);
        if changes_membership {
            neighbors.finish_prev(db.strategy(), is_deleted);
        }

        // Generate operations.
        let mut ops: Vec<Operation<F, update::Ordered<K, V>>> =
            Vec::with_capacity(deleted.len() + updated.len() + created.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> =
            Vec::with_capacity(deleted.len() + updated.len() + created.len());
        let mut active_keys_delta: isize = 0;

        // Process deletes.
        let mut ancestors = DiffCursors::new(m.ancestors.iter().map(|a| a.diff.as_slice()));
        for (key, old_loc) in deleted {
            ops.push(Operation::Delete(key.clone()));

            let base_old_loc = ancestors
                .resolve(&key)
                .map_or(Some(old_loc), DiffEntry::base_old_loc);

            diff.push((key, DiffEntry::Deleted { base_old_loc }));
            active_keys_delta -= 1;
        }
        let deleted_range = 0..diff.len();

        // Process updates of existing keys.
        let updated_range = diff.len()..diff.len() + updated.len();
        let mut ancestors = DiffCursors::new(m.ancestors.iter().map(|a| a.diff.as_slice()));
        let mut next_idx = 0;
        for (key, value, old_loc) in updated {
            let new_loc = m.base_state.size + ops.len() as u64;
            let next_key = find_next_key_ascending(&key, &neighbors.next, &mut next_idx);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));

            let base_old_loc = ancestors
                .resolve(&key)
                .map_or(Some(old_loc), DiffEntry::base_old_loc);

            diff.push((
                key,
                DiffEntry::Active {
                    value,
                    loc: new_loc,
                    base_old_loc,
                },
            ));
        }

        // Process creates.
        let created_range = diff.len()..diff.len() + created.len();
        let mut next_idx = 0;
        for (key, value, base_old_loc) in created {
            let new_loc = m.base_state.size + ops.len() as u64;
            let next_key = find_next_key_ascending(&key, &neighbors.next, &mut next_idx);
            ops.push(Operation::Update(update::Ordered {
                key: key.clone(),
                value: value.clone(),
                next_key,
            }));
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

        // Update predecessors of created and deleted keys.
        if !neighbors.prev.is_empty() {
            // The create/delete ranges stay fixed as predecessor rewrites are appended.
            for idx in created_range.chain(deleted_range) {
                let Some((prev_key, (prev_value, prev_loc), prev_next_key)) =
                    neighbors.claim(&diff[idx].0)
                else {
                    continue;
                };

                // Only updated mutation keys can be candidates: creates have no live
                // operation before this batch, and deletes are excluded from candidates. An
                // update's own operation carries its link.
                if lookup_sorted(&diff[updated_range.clone()], prev_key).is_some() {
                    continue;
                }
                let prev_value = prev_value.into_owned();

                // Preserve the ordered links across creates and deletes by rewriting the
                // predecessor with its existing value and its successor in the final key set.
                let prev_new_loc = m.base_state.size + ops.len() as u64;
                ops.push(Operation::Update(update::Ordered {
                    key: prev_key.clone(),
                    value: prev_value.clone(),
                    next_key: prev_next_key,
                }));

                let prev_base_old_loc = resolve_in_ancestors(&m.ancestors, prev_key)
                    .map_or(Some(prev_loc), DiffEntry::base_old_loc);

                diff.push((
                    prev_key.clone(),
                    DiffEntry::Active {
                        value: prev_value,
                        loc: prev_new_loc,
                        base_old_loc: prev_base_old_loc,
                    },
                ));
            }
        }

        // Release the candidate keys and values before the remaining phases run.
        drop(neighbors);

        // Committed locations superseded by this batch, which the floor walk sorts itself.
        let superseded_locs: Vec<_> = diff
            .iter()
            .filter_map(|(_, entry)| entry.base_old_loc())
            .collect();

        // Remaining phases: floor walk, its decisions and link repairs, CommitFloor, journal, diff
        // merge.
        let mut walked = Walked::new(ops, diff, active_keys_delta);
        let (floor, decided) = m
            .walk(&mut walked, superseded_locs, policy, prefetched, source, db)
            .await?;
        let decided = m.repair_links(&walked, decided, db).await?;
        walked.ops.reserve(decided.len() + 1);
        walked.floor_diff.reserve(decided.len());
        for decided in decided {
            m.emit(&mut walked, decided);
        }
        m.finish(walked, floor, metadata, db).await
    }
}

/// Where an evicted key's possible predecessor holds its value: a committed update read for the
/// repair, an update in memory in this batch or an ancestor, or a decision the walk collected.
enum Prev<F: Family, V> {
    Committed(V, Location<F>),
    Memory(Location<F>),
    Decided(usize),
}

impl<F: Family, K, V, H, S: Strategy> Merkleizer<F, H, update::Ordered<K, V>, S>
where
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Extend the walk's `decided` updates with the rewrite of each evicted key's predecessor, so
    /// that its link passes the key.
    ///
    /// An evicted key's predecessor in the final key set is the largest surviving key below it,
    /// wrapping to the largest key. It lies among the active updates that may precede the evicted
    /// keys: the committed updates in their translated-key buckets and the buckets before those
    /// (stale ones excluded, as during write resolution), this batch's writes, the live
    /// ancestors' updates, and the updates the walk kept or replaced. Each evicted key's
    /// successor is in its cached link, so the predecessor's new successor is the first surviving
    /// key after it among those.
    ///
    /// A kept or replaced predecessor's rewrite folds into its decision. Every other predecessor
    /// is decided once as a kept update with its new link, in key order after the walk's
    /// decisions.
    #[allow(clippy::type_complexity)]
    async fn repair_links<E, C, I, const N: usize>(
        &self,
        walked: &Walked<F, update::Ordered<K, V>>,
        mut decided: Vec<Decided<F, update::Ordered<K, V>>>,
        db: Onchain<'_, Db<F, E, C, I, H, update::Ordered<K, V>, N, S>>,
    ) -> Result<Vec<Decided<F, update::Ordered<K, V>>>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
    {
        // The evicted keys and their surviving successors. No successor survives when the walk
        // evicted nothing or every key, and neither needs a link.
        let mut evicted: Vec<K> = Vec::new();
        let mut neighbors: Neighbors<K, Prev<F, V::Value>> = Neighbors::new();
        for decided in &decided {
            if decided.value.is_none() {
                evicted.push(decided.key.clone());
                neighbors.next.push(decided.cached.clone());
            }
        }
        evicted.sort();
        let is_evicted = |key: &K| evicted.binary_search(key).is_ok();
        neighbors.finish_next(db.strategy(), is_evicted);
        if neighbors.next.is_empty() {
            return Ok(decided);
        }

        // Committed updates in each evicted key's bucket and the previous bucket, for keys this
        // batch leaves alone.
        let mut locations = Vec::new();
        for key in &evicted {
            locations.extend(db.snapshot.get(key).copied());
            if let Some((bucket, _)) = db.snapshot.prev_translated_key(key) {
                locations.extend(bucket.copied());
            }
        }
        locations.sort_unstable();
        locations.dedup();
        for (update, loc) in self.read_live(&locations, &db.log).await? {
            if lookup_sorted(&walked.diff, &update.key).is_none() {
                neighbors
                    .prev
                    .push((update.key, Some(Prev::Committed(update.value, loc))));
            }
        }

        // This batch's writes.
        for (key, entry) in &walked.diff {
            if let Some(loc) = entry.loc() {
                neighbors.prev.push((key.clone(), Some(Prev::Memory(loc))));
            }
        }

        // Live ancestors' updates of keys this batch leaves alone. Each diff is key-sorted, as is
        // this batch's, so one cursor per diff skips the keys this batch holds.
        let mut shadow = Shadow::new(self.ancestors.iter().map(|a| a.diff.as_slice()));
        for batch in &self.ancestors {
            let mut at = 0;
            for (key, loc) in shadow.updates(&batch.diff) {
                if !sorted_contains_by(&walked.diff, &mut at, key, |(held, _)| held) {
                    neighbors.prev.push((key.clone(), Some(Prev::Memory(loc))));
                }
            }
        }

        // The updates the walk kept or replaced come last so they win the deduplication
        // below, which keeps the last push per key.
        for (idx, decided) in decided.iter().enumerate() {
            if decided.value.is_some() {
                neighbors
                    .prev
                    .push((decided.key.clone(), Some(Prev::Decided(idx))));
            }
        }
        neighbors.finish_prev(db.strategy(), is_evicted);

        // Rewrite each evicted key's predecessor once. An undecided predecessor is an active
        // update the walk left in place, so its rewrite joins the decisions as a kept update
        // with its new link. Classifying it now reads the same state as classifying it after
        // the walk's decisions emit, since emitting a decision changes only the decided key's
        // own entry.
        let walked_decisions = decided.len();
        for key in &evicted {
            let Some((prev_key, source, next_key)) = neighbors.claim(key) else {
                continue;
            };
            let (value, loc) = match source {
                Prev::Decided(idx) => {
                    decided[idx].cached = next_key;
                    continue;
                }
                Prev::Committed(value, loc) => (value, loc),
                Prev::Memory(loc) => match self.peek_uncommitted(loc, &walked.ops) {
                    Operation::Update(update) => (update.value.clone(), loc),
                    _ => unreachable!("active operations are updates"),
                },
            };
            let mv = self
                .classify(&walked.diff, loc, prev_key)
                .expect("rewritten predecessor is active");
            decided.push(Decided {
                key: prev_key.clone(),
                cached: next_key,
                mv,
                value: Some(value),
            });
        }
        decided[walked_decisions..].sort_by(|a, b| a.key.cmp(&b.key));
        Ok(decided)
    }
}

impl<F, K, V, D, S> MerkleizedBatch<F, D, update::Ordered<K, V>, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    D: Digest,
    S: Strategy,
    Operation<F, update::Ordered<K, V>>: Codec,
{
    /// Returns the smallest active key strictly greater than `key` in this batch's view.
    ///
    /// Includes this batch's changes and its ancestors' changes. The query key need not be
    /// active. Returns `None` if there is no greater key, without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on this batch's chain.
    pub async fn get_next_key<E, C, I, H, const N: usize>(
        &self,
        key: &K,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> Result<Option<K>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
        H: Hasher<Digest = D>,
    {
        let db = self.bounds.onchain(db, db.commitment())?;
        if self.total_active_keys == 0 {
            return Ok(None);
        }
        if let Some(next) = self.find_cyclic_neighbor::<true>(key) {
            return Ok((next > *key).then_some(next));
        }
        db.get_next_key(key).await
    }

    /// Returns the largest active key strictly less than `key` in this batch's view.
    ///
    /// Includes this batch's changes and its ancestors' changes. The query key need not be
    /// active. Returns `None` if there is no smaller key, without wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on this batch's chain.
    pub async fn get_prev_key<E, C, I, H, const N: usize>(
        &self,
        key: &K,
        db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
    ) -> Result<Option<K>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, update::Ordered<K, V>>>,
        I: OrderedIndex<Value = Location<F>>,
        H: Hasher<Digest = D>,
    {
        let db = self.bounds.onchain(db, db.commitment())?;
        if self.total_active_keys == 0 {
            return Ok(None);
        }
        if let Some(prev) = self.find_cyclic_neighbor::<false>(key) {
            return Ok((prev < *key).then_some(prev));
        }
        db.get_prev_key(key).await
    }

    /// Find a cyclic neighbor from the retained diff chain, if it owns the query's span.
    fn find_cyclic_neighbor<const NEXT: bool>(&self, key: &K) -> Option<K> {
        // Diffs and their operation chunks are both visited newest-first. Retained items
        // keep ordered links available even after the ancestor batch handles are dropped.
        let mut end = *self.bounds.tip.size;
        let mut layers = iter::once(self.journal_batch.items())
            .chain(self.journal_batch.ancestor_items.iter().rev())
            .map(|items| {
                end -= items.len() as u64;
                (end, items)
            });
        let find = |diff: &Arc<DiffVec<K, F, V::Value>>| {
            let end = diff.partition_point(|(candidate, _)| {
                if NEXT {
                    candidate <= key
                } else {
                    candidate < key
                }
            });

            // Search below the query first, wrapping only when that side has no active entry.
            // An earlier key cannot own the span past a later active key in this layer.
            let loc = diff[..end]
                .iter()
                .rev()
                .chain(diff[end..].iter().rev())
                .find_map(|(_, entry)| entry.loc())?;

            // Each diff references its own operation chunk. Skipping empty diffs may
            // leave newer chunks unvisited, so advance to the one containing this location.
            let (base, items) = layers
                .find(|(base, _)| *loc >= *base)
                .expect("retained diff must have retained operations");
            let Operation::Update(data) = &items[(*loc - base) as usize] else {
                unreachable!("active diff entry must reference an update");
            };

            // Successor queries use [start, end). Predecessor queries use (start, end].
            // Match the cyclic owner before the public methods suppress linear wraparound.
            let bounds = if NEXT {
                (Included(&data.key), Excluded(&data.next_key))
            } else {
                (Excluded(&data.key), Included(&data.next_key))
            };
            contains_cyclic(bounds, key).then(|| {
                if NEXT {
                    data.next_key.clone()
                } else {
                    data.key.clone()
                }
            })
        };

        // Membership changes emit affected predecessors and created keys, so the newest
        // matching layer owns the query's span in the final batch view.
        iter::once(&self.diff)
            .chain(&self.ancestor_diffs)
            .find_map(find)
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

    /// Return the operations this batch appends to the log and the location of the first.
    ///
    /// Includes the floor walk's operations and the trailing commit.
    pub fn operations(&self) -> (Location<F>, Arc<Vec<Operation<F, U>>>) {
        (
            self.bounds.base.size,
            Arc::clone(self.journal_batch.items()),
        )
    }

    /// The update this batch wrote at `loc`, an active location in its diff.
    fn update_at(&self, loc: Location<F>) -> &U {
        let Operation::Update(update) =
            &self.journal_batch.items()[(*loc - *self.bounds.base.size) as usize]
        else {
            unreachable!("active diff entries reference updates");
        };
        update
    }

    /// Iterate over ancestor batches (parent first, then grandparent, etc.). Stops when a
    /// Weak ref fails to upgrade (ancestor was freed).
    pub(crate) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, U, S> {
        chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
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
    /// All unapplied ancestors in the chain must be kept alive until the child (or any
    /// descendant) is merkleized. Otherwise, `merkleize` returns
    /// [`crate::qmdb::Error::StaleBatch`].
    ///
    /// Creating a child from a stale parent is allowed. The child's reads, merkleization, and
    /// apply are refused ([`crate::qmdb::Error::StaleRead`], [`crate::qmdb::Error::StaleBatch`])
    /// while the database remains off this chain's states.
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

    /// Inclusion proof for the operations returned by [`Self::operations`], anchored at
    /// this batch's tip. The pair verifies against [`Self::root`] via
    /// [`crate::qmdb::verify_proof`]. Together with [`Self::pinned_nodes`] they verify via
    /// [`crate::qmdb::verify_proof_and_pinned_nodes`].
    ///
    /// Nodes of unapplied ancestors are read through the chain, so those ancestors must still be
    /// alive. Nodes below the chain are read from `db`'s
    /// [Merkle store][crate::merkle::mem::Mem], which retains them at least until
    /// this batch's changes are flushed (by a commit or sync after apply).
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is off this batch's chain,
    /// [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or belongs to a
    /// dropped unapplied ancestor, and [`crate::merkle::Error::Empty`] if the batch has no
    /// operations (a [`Db::to_batch`] snapshot).
    pub fn proof<E, C, I, H, const N: usize>(
        &self,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Proof<F, D>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher<Digest = D>,
    {
        let db = self.bounds.onchain(db, db.commitment())?;
        let inactive_peaks = F::inactive_peaks(self.bounds.tip.size, self.bounds.inactivity_floor);
        db.log
            .speculative_proof(&self.journal_batch, inactive_peaks)
            .map_err(Into::into)
    }

    /// The Merkle frontier at the first operation returned by [`Self::operations`]
    /// ([`Family::nodes_to_pin`]), which lets a consumer holding only this batch's base rebuild
    /// compact state and replay the operations. The operations, [`Self::proof`], and pinned
    /// nodes verify against [`Self::root`] via [`crate::qmdb::verify_proof_and_pinned_nodes`].
    ///
    /// Nodes of unapplied ancestors are read through the chain, so those ancestors must still be
    /// alive. Nodes below the chain are read from `db`'s
    /// [Merkle store][crate::merkle::mem::Mem], which retains them at least until
    /// this batch's changes are flushed (by a commit or sync after apply).
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is off this batch's chain, and
    /// [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or belongs to a
    /// dropped unapplied ancestor.
    pub fn pinned_nodes<E, C, I, H, const N: usize>(
        &self,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> Result<Vec<D>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
        H: Hasher<Digest = D>,
    {
        let db = self.bounds.onchain(db, db.commitment())?;
        db.log
            .speculative_pinned_nodes(&self.journal_batch)
            .map_err(Into::into)
    }

    /// Read through: local diff -> retained ancestor diffs -> committed DB.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on the batch's chain.
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
        let db = self.bounds.onchain(db, db.commitment())?;
        if let Some(entry) = lookup_sorted(self.diff.as_slice(), key) {
            return Ok(entry.value().cloned());
        }
        for diff in &self.ancestor_diffs {
            if let Some(entry) = lookup_sorted(diff.as_slice(), key) {
                return Ok(entry.value().cloned());
            }
        }
        db.get(key).await
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::StaleRead`] if `db` is not on the batch's chain.
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
        let db = self.bounds.onchain(db, db.commitment())?;
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let diffs: Vec<_> = self
            .ancestor_diffs
            .iter()
            .map(|diff| diff.as_slice())
            .collect();
        let (mut results, unresolved) = resolve_reads(
            keys,
            |key| lookup_sorted(self.diff.as_slice(), key).map(|entry| entry.value().cloned()),
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
            base_size = *self.log.size(),
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

    /// Create an initial [`MerkleizedBatch`] from the committed DB state.
    ///
    /// This is the starting point for building owned batch chains.
    #[tracing::instrument(
        name = "qmdb.any.db.to_batch",
        level = "info",
        skip_all,
        fields(
            db_size = *self.log.size(),
            inactivity_floor = *self.inactivity_floor_loc,
            active_keys = self.active_keys as u64,
        ),
    )]
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, U, S>> {
        Arc::new(MerkleizedBatch {
            journal_batch: self.log.to_merkleized_batch(),
            diff: Arc::new(Vec::new()),
            parent: None,
            total_active_keys: self.active_keys,
            ancestor_diffs: Vec::new(),
            ancestor_base_locs: Vec::new(),
            bounds: chain::Bounds::from_db(self.commitment(), self.inactivity_floor_loc),
        })
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Db<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
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
        batch.bounds.validate_apply_to(self.commitment())
    }

    /// Apply a batch to the database, returning the range of written operations.
    ///
    /// A batch is valid only if every batch applied to the database since this batch's
    /// ancestor chain was created is an ancestor of this batch. Applying a batch from a
    /// different fork returns [`crate::qmdb::Error::StaleBatch`] (see
    /// [`crate::qmdb::chain`] for more details).
    ///
    /// This publishes the batch to the in-memory database state and appends it to the journal.
    /// Call [`Db::commit`] or [`Db::sync`], or await the handle returned by [`Db::start_sync`], to
    /// make the applied state durable.
    #[tracing::instrument(
        name = "qmdb.any.db.apply_batch",
        level = "info",
        skip_all,
        fields(
            batch_total_size = *batch.bounds.tip.size,
            batch_base_size = *batch.bounds.base.size,
            db_size = *self.log.size(),
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
        let db_size = *self.log.size();
        let start_loc = Location::new(db_size);

        // Apply journal (handles its own partial ancestor skipping).
        self.log = self.log.apply_batch(&batch.journal_batch).await?;

        // Scoped so the bitmap guard drops before later `.await`s (guard is `!Send`).
        {
            let mut bitmap = self.bitmap.write();
            bitmap.extend_to(*batch.bounds.tip.size);

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
                    if batch.bounds.ancestors[i].size <= db_size {
                        applied.push(ancestor_diff.as_slice());
                    } else {
                        pending.push(ancestor_diff.as_slice());
                    }
                }
                let mut resolver = DiffCursors::new(applied);
                if batch.ancestor_base_locs.is_empty() {
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
                } else {
                    let mut ancestor_base_locs = batch.ancestor_base_locs.iter().peekable();
                    let merge = DiffMerge::new(
                        iter::once(batch.diff.as_slice()).chain(pending.iter().copied()),
                    );
                    for (key, entry) in merge {
                        let old = resolver.resolve(key).map_or_else(
                            || {
                                while ancestor_base_locs
                                    .peek()
                                    .is_some_and(|(candidate, _)| candidate < key)
                                {
                                    ancestor_base_locs.next();
                                }
                                if ancestor_base_locs
                                    .peek()
                                    .is_some_and(|(candidate, _)| candidate == key)
                                {
                                    ancestor_base_locs.next().expect("peeked entry exists").1
                                } else {
                                    entry.base_old_loc()
                                }
                            },
                            DiffEntry::loc,
                        );
                        apply_diff(&mut self.snapshot, &mut bitmap, key, entry, old);
                    }
                }
            }

            // CommitFloor: bit = 1 only on the current last commit. Demote the previous and
            // set the new; earlier ancestor commits between them are already 0 from
            // `extend_to`.
            bitmap.set_bit(db_size - 1, false);
            bitmap.set_bit(*batch.bounds.tip.size - 1, true);
        }

        // Update DB metadata.
        self.active_keys = batch.total_active_keys;
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        self.root = batch.root();

        // Return range of operations that were written to the log.
        let range = start_loc..batch.bounds.tip.size;
        self.update_metrics();
        self.metrics
            .operations_applied
            .inc_by(*range.end - *range.start);
        Ok((self, range))
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
        V: ValueEncoding,
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

        fn merkleize<P: Policy<F, K, V::Value> + Send>(
            self,
            db: &Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
            metadata: Option<V::Value>,
            policy: &mut P,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata, policy)
        }
    }

    impl<F, K, V, H, E, C, I, const N: usize, S>
        UnmerkleizedBatchTrait<Db<F, E, C, I, H, update::Ordered<K, V>, N, S>>
        for UnmerkleizedBatch<F, H, update::Ordered<K, V>, S>
    where
        F: Family,
        K: Key,
        V: ValueEncoding,
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

        fn merkleize<P: Policy<F, K, V::Value> + Send>(
            self,
            db: &Db<F, E, C, I, H, update::Ordered<K, V>, N, S>,
            metadata: Option<V::Value>,
            policy: &mut P,
        ) -> impl Future<Output = Result<Self::Merkleized, crate::qmdb::Error<F>>> {
            self.merkleize(db, metadata, policy)
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
        V: ValueEncoding,
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
        V: ValueEncoding,
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
            self,
            batch: Self::Merkleized,
        ) -> impl Future<Output = ApplyBatchResult<Self>> {
            self.apply_batch(batch)
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        mmr,
        qmdb::{
            any::{
                BITMAP_CHUNK_BYTES,
                ordered::fixed::Db as OrderedFixedDb,
                test::{
                    Choice, Inspect as _, Script, assert_links, assert_same, colliding_digest,
                    fixed_db_config,
                },
                traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
                unordered::fixed::Db as UnorderedFixedDb,
                value::FixedEncoding,
            },
            current,
            floor::{Bounded, Decision, Entry, Hold, Limits, Policy, Proportional},
        },
        translator::OneCap,
    };
    use commonware_codec::{Buf, FixedSize, Read, Write};
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::test_rng;
    use rand::RngExt as _;
    use std::{
        cell::Cell,
        sync::atomic::{AtomicUsize, Ordering as AtomicOrdering},
    };

    type AnyUnorderedOf<V> = UnorderedFixedDb<
        mmr::Family,
        deterministic::Context,
        sha256::Digest,
        V,
        Sha256,
        OneCap,
        Sequential,
    >;
    type AnyOrderedOf<V> = OrderedFixedDb<
        mmr::Family,
        deterministic::Context,
        sha256::Digest,
        V,
        Sha256,
        OneCap,
        Sequential,
    >;
    type CurrentUnorderedOf<V> = current::unordered::fixed::Db<
        mmr::Family,
        deterministic::Context,
        sha256::Digest,
        V,
        Sha256,
        OneCap,
        32,
        Sequential,
    >;
    type CurrentOrderedOf<V> = current::ordered::fixed::Db<
        mmr::Family,
        deterministic::Context,
        sha256::Digest,
        V,
        Sha256,
        OneCap,
        32,
        Sequential,
    >;
    type AnyUnordered = AnyUnorderedOf<sha256::Digest>;
    type AnyOrdered = AnyOrderedOf<sha256::Digest>;
    type CurrentUnordered = CurrentUnorderedOf<sha256::Digest>;
    type CurrentOrdered = CurrentOrderedOf<sha256::Digest>;

    /// A tagged value that counts the clones of its original. A decoded value starts a new
    /// count.
    pub(crate) struct CountedValue(pub(crate) u8, Arc<AtomicUsize>);

    impl CountedValue {
        pub(crate) fn new(tag: u8) -> Self {
            Self(tag, Arc::new(AtomicUsize::new(0)))
        }

        pub(crate) fn clones(&self) -> usize {
            self.1.load(AtomicOrdering::Relaxed)
        }
    }

    impl Clone for CountedValue {
        fn clone(&self) -> Self {
            self.1.fetch_add(1, AtomicOrdering::Relaxed);
            Self(self.0, self.1.clone())
        }
    }

    impl FixedSize for CountedValue {
        const SIZE: usize = 1;
    }

    impl Write for CountedValue {
        fn write(&self, buf: &mut impl bytes::BufMut) {
            self.0.write(buf);
        }
    }

    impl Read for CountedValue {
        type Cfg = ();

        fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, commonware_codec::Error> {
            Ok(Self::new(u8::read_cfg(buf, &())?))
        }
    }

    /// Keeps every update and records each decided key with its value's clone count at the
    /// decision.
    struct Probe {
        decided: Vec<(sha256::Digest, usize)>,
    }

    impl Policy<mmr::Family, sha256::Digest, CountedValue> for Probe {
        fn evicts(&self) -> bool {
            true
        }

        fn limits(&self, _: usize) -> Limits {
            Limits {
                entries: usize::MAX,
                skips: u64::MAX,
            }
        }

        fn decide<'a>(
            &mut self,
            entry: Entry<'a, mmr::Family, sha256::Digest, CountedValue>,
        ) -> Decision<'a, CountedValue> {
            self.decided.push((*entry.key(), entry.value().clones()));
            entry.keep()
        }
    }

    /// A walk over a pending ancestor's operations clones only the active update it decides: once
    /// at the decision and once for the diff entry of its move.
    #[test]
    fn policy_clones_only_decided_ancestor_update() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("policy-clones", &context);
            let db = AnyUnorderedOf::<CountedValue>::init(context, config, None)
                .await
                .unwrap();
            let first = sha256::Digest::from([0; 32]);
            let second = sha256::Digest::from([1; 32]);
            let (first_value, second_value) = (CountedValue::new(0), CountedValue::new(1));
            let counts = [first_value.1.clone(), second_value.1.clone()];

            // A pending parent writes both keys and holds the floor. Writing clones each value
            // once for its operation.
            let parent = db
                .new_batch()
                .write(first, Some(first_value))
                .write(second, Some(second_value))
                .merkleize(&db, Some(CountedValue::new(2)), &mut Hold)
                .await
                .unwrap();
            for count in &counts {
                assert_eq!(count.swap(0, AtomicOrdering::Relaxed), 1);
            }

            // The child deletes the first key, so only the second key's update is active.
            // Resolving the delete reads the first key's operation from the parent once, and the
            // walk clones the second key's update once when the policy decides it and once more
            // for the diff entry of its move.
            let mut policy = Probe {
                decided: Vec::new(),
            };
            let child = parent
                .new_batch::<Sha256>()
                .write(first, None)
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(policy.decided, [(second, 1)]);
            let clones = counts.map(|count| count.load(AtomicOrdering::Relaxed));
            assert_eq!(clones, [1, 2]);

            // The walk passes the parent's commit and the child's delete to the tip after the
            // writes.
            assert_eq!(
                child.bounds().inactivity_floor,
                parent.bounds().tip.size + 1
            );
            drop((child, parent));
            db.destroy().await.unwrap();
        });
    }

    /// Evicts every update it reaches. Records each eviction's location, key, and value with the
    /// value's clone count before and after the eviction.
    #[derive(Default)]
    pub(crate) struct Evict {
        #[allow(clippy::type_complexity)]
        pub(crate) evicted: Vec<(
            Location<mmr::Family>,
            sha256::Digest,
            CountedValue,
            usize,
            usize,
        )>,
    }

    impl Policy<mmr::Family, sha256::Digest, CountedValue> for Evict {
        fn evicts(&self) -> bool {
            true
        }

        fn limits(&self, _: usize) -> Limits {
            Limits {
                entries: usize::MAX,
                skips: u64::MAX,
            }
        }

        fn decide<'a>(
            &mut self,
            entry: Entry<'a, mmr::Family, sha256::Digest, CountedValue>,
        ) -> Decision<'a, CountedValue> {
            let location = entry.location();
            let key = *entry.key();
            let before = entry.value().clones();
            let (decision, value) = entry.evict();
            let after = value.clones();
            self.evicted.push((location, key, value, before, after));
            decision
        }
    }

    /// A policy that evicts committed, pending-parent, colliding-key, and the batch's own updates
    /// owns each evicted value and receives them in location order. A committed value arrives
    /// unshared, a parent value carries only the walk's clone, and the batch's own value carries
    /// its write's clone and the walk's. The evicted keys read `None` once the batch applies.
    async fn policy_evicts_owned<D>(db: D, child: fn(&D::Merkleized) -> D::Batch)
    where
        D: DbAny<mmr::Family, Key = sha256::Digest, Value = CountedValue>,
    {
        let colliding = |i| colliding_digest(0xAA, i);
        let other = colliding_digest(0xBB, 0);

        // Commit three keys in one translated-key bucket and one other key with a held floor.
        let seed = [colliding(0), colliding(1), colliding(2), other]
            .into_iter()
            .zip(0u8..)
            .fold(db.new_batch(), |batch, (key, tag)| {
                batch.write(key, Some(CountedValue::new(tag)))
            })
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(seed).await.unwrap();
        let db = db.commit().await.unwrap();
        let size = db.size();

        // A pending parent rewrites a colliding key and the other key with a held floor.
        let pending = [
            (colliding(2), CountedValue::new(12)),
            (other, CountedValue::new(13)),
        ];
        let counts: Vec<_> = pending.iter().map(|(_, value)| value.1.clone()).collect();
        let parent = pending
            .into_iter()
            .fold(db.new_batch(), |batch, (key, value)| {
                batch.write(key, Some(value))
            })
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();

        // The child rewrites the first colliding key, and the policy evicts every active update,
        // the rewrite among them.
        for count in &counts {
            count.store(0, AtomicOrdering::Relaxed);
        }
        let written = CountedValue::new(20);
        let written_count = written.1.clone();
        let mut policy = Evict::default();
        let merkleized = child(&parent)
            .write(colliding(0), Some(written))
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();

        // Merkleize clones each pending value only for the walk's read, and the written value for
        // its operation and the walk's read.
        for count in &counts {
            assert_eq!(count.load(AtomicOrdering::Relaxed), 1);
        }
        assert_eq!(written_count.load(AtomicOrdering::Relaxed), 2);

        // Evictions arrive in location order with the committed update first. Evicting clones
        // nothing.
        assert!(policy.evicted.is_sorted_by(|a, b| a.0 < b.0));
        let mut evicted: Vec<_> = policy
            .evicted
            .iter()
            .map(|(loc, key, value, before, after)| (*loc >= size, *key, value.0, *before, *after))
            .collect();
        evicted[1..].sort();
        assert_eq!(
            evicted,
            [
                (false, colliding(1), 1, 0, 0),
                (true, colliding(0), 20, 2, 2),
                (true, colliding(2), 12, 1, 1),
                (true, other, 13, 1, 1),
            ]
        );

        // Applying the batch deletes every key and moves the floor to the commit.
        let (db, range) = db.apply_batch(merkleized).await.unwrap();
        drop(parent);
        for (_, key, ..) in &policy.evicted {
            assert!(db.get(key).await.unwrap().is_none());
        }
        assert_eq!(db.inactivity_floor_loc() + 1, range.end);
        db.destroy().await.unwrap();
    }

    /// [`policy_evicts_owned`] on unordered and ordered Any and Current databases.
    #[test]
    fn policy_evicts_owned_every_variant() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("evict-any-unordered", &context);
            let db =
                AnyUnorderedOf::<CountedValue>::init(context.child("any_unordered"), config, None)
                    .await
                    .unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
            let config = fixed_db_config::<OneCap>("evict-any-ordered", &context);
            let db = AnyOrderedOf::<CountedValue>::init(context.child("any_ordered"), config, None)
                .await
                .unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
            let config =
                current::tests::fixed_config::<OneCap>("evict-current-unordered", &context);
            let db = CurrentUnorderedOf::<CountedValue>::init(
                context.child("current_unordered"),
                config,
                None,
            )
            .await
            .unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
            let config = current::tests::fixed_config::<OneCap>("evict-current-ordered", &context);
            let db = CurrentOrderedOf::<CountedValue>::init(
                context.child("current_ordered"),
                config,
                None,
            )
            .await
            .unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// A round below the database's size reserves at most one candidate per live key plus one for
    /// the last commit, and no more than the locations it has left to scan. Over a log of 388
    /// operations with two live keys and the floor at 0, an ordinary round that may select every
    /// candidate, the staged prefetch, and a round after the prefetch over an inactive tail each
    /// reserve at most three. A staged child of a retained parent whose walk reached the
    /// database's size has nothing left to scan and reserves nothing.
    #[test]
    fn walk_reserves_candidates_by_live_keys() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("prefetch-capacity", &context);
            let mut db = AnyUnordered::init(context, config, None).await.unwrap();

            // Write two keys, rewrite the second in each of 128 batches, then apply 128 empty
            // batches, all with a held floor.
            let keys = [colliding_digest(0xAA, 0), colliding_digest(0xAA, 1)];
            let batch = db
                .new_batch()
                .write(keys[0], Some(keys[0]))
                .write(keys[1], Some(keys[1]))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            for round in 0..256 {
                let batch = if round < 128 {
                    db.new_batch().write(keys[1], Some(keys[1]))
                } else {
                    db.new_batch()
                };
                let batch = batch.merkleize(&db, None, &mut Hold).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
            }
            assert_eq!(db.active_keys, 2);
            assert_eq!((*db.inactivity_floor_loc(), *db.size()), (0, 388));
            let last = db.size();
            let inactive = [last - 1];

            // An ordinary round selects both live updates and passes the last commit.
            let prepared = db.new_batch().prepare(&db).unwrap();
            let mut scan = db.inactivity_floor_loc();
            let mut source = db.bitmap.as_ref();
            let round = prepared
                .merkleizer
                .read_round(&db.log, &mut scan, last, usize::MAX, &inactive, &mut source)
                .await
                .unwrap();
            assert_eq!(round.candidates.len(), 2);
            assert!(
                round.candidates.capacity() <= 3,
                "ordinary capacity {}",
                round.candidates.capacity()
            );
            drop((round, prepared));

            // The staged prefetch selects both live updates.
            let policy = Bounded {
                entries: usize::MAX,
                skips: u64::MAX,
            };
            let (_, staged) = db.new_batch().stage(&[], &db).await.unwrap();
            let (prepared, _) = staged
                .resolve_updates_prefetched(
                    Vec::new(),
                    Vec::new(),
                    &db,
                    &policy,
                    db.bitmap.as_ref(),
                )
                .await
                .unwrap();
            let (round, scan) = prepared.prefetched.as_ref().unwrap();
            let mut scan = *scan;
            assert_eq!(round.candidates.len(), 2);
            assert!(
                round.candidates.capacity() <= 3,
                "prefetch capacity {}",
                round.candidates.capacity()
            );

            // The round after the prefetch finds only inactive locations.
            let need = usize::MAX - round.candidates.len();
            let mut source = db.bitmap.as_ref();
            let tail = prepared
                .merkleizer
                .read_round(&db.log, &mut scan, last, need, &inactive, &mut source)
                .await
                .unwrap();
            assert!(tail.candidates.is_empty());
            assert!(
                tail.candidates.capacity() <= 3,
                "tail capacity {}",
                tail.candidates.capacity()
            );
            drop((tail, prepared));

            // A retained parent moves both keys, so its child's prefetch starts at the database's
            // size.
            let parent = db
                .new_batch()
                .merkleize(
                    &db,
                    None,
                    &mut Bounded {
                        entries: usize::MAX,
                        skips: u64::MAX,
                    },
                )
                .await
                .unwrap();
            assert_eq!(parent.bounds().inactivity_floor, last);
            let (_, staged) = parent.new_batch().stage(&[], &db).await.unwrap();
            let (prepared, _) = staged
                .resolve_updates_prefetched(
                    Vec::new(),
                    Vec::new(),
                    &db,
                    &policy,
                    db.bitmap.as_ref(),
                )
                .await
                .unwrap();
            let (round, scan) = prepared.prefetched.as_ref().unwrap();
            assert_eq!(*scan, last);
            assert!(round.candidates.is_empty());
            assert_eq!(round.candidates.capacity(), 0, "empty prefetch capacity");
            drop((prepared, parent));
            db.destroy().await.unwrap();
        });
    }

    /// Returns one entry from its `exact`th [`Policy::limits`] call and unbounded limits from every
    /// other call. Keeps every update and counts the limits calls and the decisions.
    pub(crate) struct Growing {
        pub(crate) exact: usize,
        pub(crate) reads: Cell<usize>,
        pub(crate) decided: usize,
    }

    impl Policy<mmr::Family, sha256::Digest, sha256::Digest> for Growing {
        fn evicts(&self) -> bool {
            false
        }

        fn limits(&self, _: usize) -> Limits {
            let reads = self.reads.get() + 1;
            self.reads.set(reads);
            let entries = if reads == self.exact { 1 } else { usize::MAX };
            Limits {
                entries,
                skips: u64::MAX,
            }
        }

        fn decide<'a>(
            &mut self,
            entry: Entry<'a, mmr::Family, sha256::Digest, sha256::Digest>,
        ) -> Decision<'a, sha256::Digest> {
            self.decided += 1;
            entry.keep()
        }
    }

    /// Seed four keys with a held floor, then merkleize an empty batch with [`Growing`] and return
    /// the database and the policy.
    async fn limits_read_unstaged<D>(db: D) -> (D, Growing)
    where
        D: DbAny<mmr::Family, Key = sha256::Digest, Value = sha256::Digest>,
    {
        let seed = (0..4u8)
            .map(|i| sha256::Digest::from([i; 32]))
            .fold(db.new_batch(), |batch, key| batch.write(key, Some(key)))
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(seed).await.unwrap();
        let mut policy = Growing {
            exact: 1,
            reads: Cell::new(0),
            decided: 0,
        };
        drop(
            db.new_batch()
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap(),
        );
        (db, policy)
    }

    /// Every merkleize entry point, unstaged and staged over unordered and ordered Any and Current
    /// databases, reads its policy's limits for the exact count once before the walk and decides
    /// under them. The unordered staged entry points read them once more before that, with an
    /// estimate for the prefetch; ordered staging has no prefetch.
    ///
    /// Four keys lie at 1..5 with a held floor, and the staged batch rewrites the first. The limits
    /// read for the exact count allow one entry, which decides the first live update. Any other
    /// read would allow every update.
    #[test]
    fn policy_reads_limits_per_phase() {
        deterministic::Runner::default().start(|context| async move {
            let key = sha256::Digest::from([0; 32]);
            let mut policies = Vec::new();

            // Merkleize the unstaged and the staged batch on `db` and record both policies.
            macro_rules! limits_read {
                ($label:literal, $db:expr, $staged_reads:literal) => {{
                    let (db, policy) = limits_read_unstaged($db).await;
                    policies.push((concat!($label, " unstaged"), policy));
                    let mut policy = Growing {
                        exact: $staged_reads,
                        reads: Cell::new(0),
                        decided: 0,
                    };
                    let (_, staged) = db.new_batch().stage(&[&key], &db).await.unwrap();
                    let updates = vec![(0, Some(key))];
                    drop(
                        staged
                            .merkleize(updates, Vec::new(), None, &db, &mut policy)
                            .await
                            .unwrap(),
                    );
                    policies.push((concat!($label, " staged"), policy));
                    db.destroy().await.unwrap();
                }};
            }

            let config = fixed_db_config::<OneCap>("limits-any-unordered", &context);
            limits_read!(
                "any unordered",
                AnyUnordered::init(context.child("any_unordered"), config, None)
                    .await
                    .unwrap(),
                2
            );
            let config = fixed_db_config::<OneCap>("limits-any-ordered", &context);
            limits_read!(
                "any ordered",
                AnyOrdered::init(context.child("any_ordered"), config, None)
                    .await
                    .unwrap(),
                1
            );
            let config =
                current::tests::fixed_config::<OneCap>("limits-current-unordered", &context);
            limits_read!(
                "current unordered",
                CurrentUnordered::init(context.child("current_unordered"), config, None)
                    .await
                    .unwrap(),
                2
            );
            let config = current::tests::fixed_config::<OneCap>("limits-current-ordered", &context);
            limits_read!(
                "current ordered",
                CurrentOrdered::init(context.child("current_ordered"), config, None)
                    .await
                    .unwrap(),
                1
            );

            for (path, policy) in policies {
                assert_eq!(
                    (policy.reads.get(), policy.decided),
                    (policy.exact, 1),
                    "{path}: limits reads and decisions"
                );
            }
        });
    }

    /// The staged prefetch covers every entry of the [`Proportional`] walk for each upsert or
    /// earlier write to a live key: one per update and two per delete, plus one for the previous
    /// commit.
    #[test]
    fn staged_prefetch_counts_upserts_and_earlier_writes() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("staged-prefetch", &context);
            let db = AnyUnordered::init(context, config, None).await.unwrap();

            // Seed 64 keys with a held floor, and stage the last eight.
            let keys: Vec<_> = (0..64u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let staged_keys: Vec<_> = keys[56..].iter().collect();

            // An earlier delete, an updating upsert, and a deleting upsert of live keys.
            let (_, staged) = db
                .new_batch()
                .write(keys[0], None)
                .stage(&staged_keys, &db)
                .await
                .unwrap();
            let update = Some(sha256::Digest::from([0xFF; 32]));
            let upserts = vec![(keys[1], update), (keys[2], None)];
            let (prepared, _) = staged
                .resolve_updates_prefetched(
                    Vec::new(),
                    upserts,
                    &db,
                    &Proportional,
                    db.bitmap.as_ref(),
                )
                .await
                .unwrap();
            assert_eq!(
                prepared.prefetched.as_ref().unwrap().0.candidates.len(),
                1 + 2 + 1 + 2
            );
            drop(prepared);
            db.destroy().await.unwrap();
        });
    }

    /// A fixed policy that keeps the updates the [`Proportional`] walk moves produces the same
    /// batch with the same journal reads when the batch's writes supersede updates in its window:
    /// with keys in their own translated-key buckets, all in one bucket, or a few in the written
    /// key's bucket, and when a pending parent rewrote the written keys.
    ///
    /// Each batch reads its resolution's reads, which a [`Hold`] batch with the same writes makes
    /// alone, plus one read for each of its entries: every scenario's walk moves only applied
    /// updates, and it passes the applied updates the batch's writes supersede, directly or
    /// through the parent's rewrites, without reading them.
    async fn policy_reads_writes_once<D, Fut>(
        context: deterministic::Context,
        open: impl Fn(deterministic::Context, &'static str) -> Fut,
        child: fn(&D::Merkleized) -> D::Batch,
    ) where
        D: DbAny<mmr::Family, Key = sha256::Digest, Value = sha256::Digest>,
        Fut: core::future::Future<Output = D>,
    {
        // Each scenario names its keys, the indices of the keys a pending parent rewrites and of
        // those the batch writes, the updates the proportional walk moves for the batch, and the
        // applied updates its resolution reads: one in each written key's bucket, all 64 in the
        // shared bucket, the four in the written key's bucket, and none for keys the parent wrote.
        let distinct: Vec<_> = (0..32u8).map(|i| sha256::Digest::from([i; 32])).collect();
        let colliding: Vec<_> = (0..64).map(|i| colliding_digest(0xAA, i)).collect();
        let crowded: Vec<_> = (0..4)
            .map(|i| colliding_digest(0xAA, i))
            .chain([0xBB, 0xCC].map(|byte| sha256::Digest::from([byte; 32])))
            .collect();
        let scenarios = [
            ("distinct", distinct.clone(), vec![], vec![1, 3, 5, 7], 5, 4),
            ("colliding", colliding, vec![], vec![63], 2, 64),
            ("crowded", crowded, vec![], vec![3], 2, 4),
            ("pending", distinct, vec![1, 3], vec![1, 3], 3, 0),
        ];
        let items = || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
        let rewrite = sha256::Digest::from([0xDD; 32]);
        let value = sha256::Digest::from([0xEE; 32]);
        for (partition, keys, rewritten, written, entries, resolution) in scenarios {
            // Seed the keys. The proportional walk moves the first one, so the floor is 2.
            let db = open(context.child(partition), partition).await;
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            assert_eq!(*db.inactivity_floor_loc(), 2);

            // A pending parent, if any, rewrites keys with a held floor.
            let parent = if rewritten.is_empty() {
                None
            } else {
                let parent = rewritten
                    .iter()
                    .fold(db.new_batch(), |batch, &i| {
                        batch.write(keys[i], Some(rewrite))
                    })
                    .merkleize(&db, None, &mut Hold)
                    .await
                    .unwrap();
                Some(parent)
            };

            // Keeping as many updates as the proportional walk moves produces the same batch.
            let write = || {
                let batch = parent.as_ref().map_or_else(|| db.new_batch(), child);
                written
                    .iter()
                    .fold(batch, |batch, &i| batch.write(keys[i], Some(value)))
            };
            let before = items();
            drop(write().merkleize(&db, None, &mut Hold).await.unwrap());
            assert_eq!(
                items() - before,
                resolution,
                "{partition}: resolution reads"
            );
            let before = items();
            let proportional = write()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let proportional_reads = items() - before;
            let before = items();
            let mut policy = Bounded {
                entries,
                skips: u64::MAX,
            };
            let kept = write().merkleize(&db, None, &mut policy).await.unwrap();
            assert_eq!(kept.root(), proportional.root(), "{partition}");
            let reads = items() - before;
            let expected = resolution + Widen::widen(entries);
            assert_eq!(
                (proportional_reads, reads),
                (expected, expected),
                "{partition}: reads"
            );
            drop((proportional, kept, parent));
            db.destroy().await.unwrap();
        }
    }

    /// [`policy_reads_writes_once`] on an unordered Any database.
    #[test]
    fn policy_reads_writes_once_unordered() {
        deterministic::Runner::default().start(|context| async move {
            let open = |context, partition| async move {
                let config = fixed_db_config::<OneCap>(partition, &context);
                AnyUnordered::init(context, config, None).await.unwrap()
            };
            policy_reads_writes_once(context, open, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// [`policy_reads_writes_once`] on an ordered Any database.
    #[test]
    fn policy_reads_writes_once_ordered() {
        deterministic::Runner::default().start(|context| async move {
            let open = |context, partition| async move {
                let config = fixed_db_config::<OneCap>(partition, &context);
                AnyOrdered::init(context, config, None).await.unwrap()
            };
            policy_reads_writes_once(context, open, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// A write a window walk merkleizes over: none, or a direct or staged write of the indexed
    /// seeded key.
    #[derive(Clone, Copy)]
    enum WindowWrite {
        None,
        Direct(usize),
        Staged(usize),
    }

    fn distinct(n: u8) -> Vec<sha256::Digest> {
        (1..=n).map(|i| sha256::Digest::from([i; 32])).collect()
    }

    /// A fixed walk reads only the candidates in its window, never past its end, and a staged
    /// walk decides what the unstaged walk with the same write decides. Each case seeds its keys
    /// at 1.. with a held floor, so the seed commit follows them.
    ///
    /// The staged prefetch reads the window's candidates even when the walk decides nothing,
    /// since the limits bound decisions and passed locations rather than reads. A staged write's
    /// applied location among the prefetched candidates is passed as inactive, never decided.
    #[rstest::rstest]
    // The window is [0, 100): the walk reads the 99 updates below it, finds the first beyond its
    // skips, and leaves the floor at the initial commit.
    #[case::within_window(distinct(100), WindowWrite::None, (100, 0, Choice::Keep), 99, Some(vec![]), Some(0))]
    // The staged write supersedes the update at 1, and one skip cannot also pass the initial
    // commit to reach the update at 2, so the floor advances by the skip. The prefetch reads both
    // candidates below the window's end at 3.
    #[case::past_staged_reach(distinct(4), WindowWrite::Staged(0), (2, 1, Choice::Keep), 2, Some(vec![]), Some(1))]
    // Rewriting the first key supersedes its update at 1. The prefetch reads it, and the walk
    // decides the following updates without reading the prefetched round again: one prefetched
    // inactive update plus exactly the updates the walk decides.
    #[case::passes_prefetched_write_1(distinct(4), WindowWrite::Staged(0), (1, u64::MAX, Choice::Keep), 2, Some(vec![2]), None)]
    #[case::passes_prefetched_write_3(distinct(4), WindowWrite::Staged(0), (3, u64::MAX, Choice::Keep), 4, Some(vec![2, 3, 4]), None)]
    // Resolving a write beside an update in its translated-key bucket reads both updates, and the
    // walk reads the first again to evict it.
    #[case::evicts_beside_write(vec![colliding_digest(0xAA, 0), colliding_digest(0xAA, 1)], WindowWrite::Direct(1), (1, u64::MAX, Choice::Evict), 3, None, None)]
    fn policy_reads_window(
        #[case] keys: Vec<sha256::Digest>,
        #[case] write: WindowWrite,
        #[case] (entries, skips, choice): (usize, u64, Choice),
        #[case] reads: u64,
        #[case] decided: Option<Vec<u64>>,
        #[case] floor: Option<u64>,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("window", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            let value = Some(sha256::Digest::from([0xEE; 32]));
            let decide = move |_: &sha256::Digest| choice;
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let mut policy = Script::new(entries, skips, decide);
            let merkleized = if let WindowWrite::Staged(i) = write {
                let (_, staged) = db.new_batch().stage(&[&keys[i]], &db).await.unwrap();
                let before = items();
                let merkleized = staged
                    .merkleize(vec![(0, value)], Vec::new(), None, &db, &mut policy)
                    .await
                    .unwrap();
                assert_eq!(items() - before, reads);

                // The unstaged walk with the same write decides the same updates.
                let mut twin = Script::new(entries, skips, decide);
                let written = db
                    .new_batch()
                    .write(keys[i], value)
                    .merkleize(&db, None, &mut twin)
                    .await
                    .unwrap();
                assert_eq!(policy.visited, twin.visited);
                assert_eq!(merkleized.root(), written.root());
                drop(written);
                merkleized
            } else {
                let batch = match write {
                    WindowWrite::Direct(i) => db.new_batch().write(keys[i], value),
                    _ => db.new_batch(),
                };
                let before = items();
                let merkleized = batch.merkleize(&db, None, &mut policy).await.unwrap();
                assert_eq!(items() - before, reads);
                merkleized
            };
            if let Some(decided) = decided {
                let decided: Vec<_> = decided.into_iter().map(loc).collect();
                assert_eq!(policy.locations(), decided);
            }
            if let Some(floor) = floor {
                assert_eq!(merkleized.bounds().inactivity_floor, loc(floor));
            }
            drop(merkleized);
            db.destroy().await.unwrap();
        });
    }

    /// A staged fixed walk matches the unstaged walk's decisions, root, and floor for each policy
    /// action and at its entries, skips, or window. A pending parent, an earlier write, and an
    /// upsert overriding a staged slot cover resolutions the prefetch cannot see.
    ///
    /// For each action, the staged batch decided under unbounded limits is also applied to its
    /// own database: every key holds the value the twin's decisions leave it, the activity bitmap
    /// is exact, and the root, floor, and values survive a sync and reopen.
    macro_rules! staged_fixed_walk_matches_unstaged_test {
        ($name:ident, $db:ty, $config:expr) => {
            #[test]
            fn $name() {
                deterministic::Runner::default().start(|context| async move {
                    let keys: Vec<_> = (0..16u8).map(|i| sha256::Digest::from([i; 32])).collect();
                    let rewrite = Some(sha256::Digest::from([0xDD; 32]));
                    let value = Some(sha256::Digest::from([0xEE; 32]));
                    let other = Some(sha256::Digest::from([0xEF; 32]));

                    // Commit 16 keys with a held floor. A pending parent rewrites the second and
                    // seventh keys.
                    let seed_keys = keys.clone();
                    let seed = move |db: $db| {
                        let keys = seed_keys.clone();
                        async move {
                            let seed = keys
                                .iter()
                                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                                .merkleize(&db, None, &mut Hold)
                                .await
                                .unwrap();
                            let (db, _) = db.apply_batch(seed).await.unwrap();
                            let parent = db
                                .new_batch()
                                .write(keys[1], rewrite)
                                .write(keys[6], rewrite)
                                .merkleize(&db, None, &mut Hold)
                                .await
                                .unwrap();
                            (db, parent)
                        }
                    };
                    let config = $config("staged-fixed-unstaged", &context);
                    let (db, parent) = seed(
                        <$db>::init(context.child("db"), config, None)
                            .await
                            .unwrap(),
                    )
                    .await;

                    // A child writes the tenth key and stages the first, second, fourth, and fifth.
                    // It updates or deletes each staged key, then upserts the fifth and twelfth.
                    let read = [&keys[0], &keys[1], &keys[3], &keys[4]];
                    let updates = vec![(0, value), (1, value), (2, None), (3, value)];
                    let upserts = vec![(keys[4], other), (keys[11], value)];
                    let written = [
                        (keys[9], value),
                        (keys[0], value),
                        (keys[1], value),
                        (keys[3], None),
                        (keys[4], other),
                        (keys[11], value),
                    ];
                    let actions = [
                        (Choice::Keep, "apply_keep", "reopen_keep"),
                        (Choice::Evict, "apply_evict", "reopen_evict"),
                        (Choice::Replace(keys[15]), "apply_replace", "reopen_replace"),
                        (Choice::Stop, "apply_stop", "reopen_stop"),
                    ];
                    for (choice, apply_label, reopen_label) in actions {
                        for entries in [0, 1, 3, 8, usize::MAX] {
                            for skips in [0, 2, 5, u64::MAX] {
                                let label =
                                    format!("choice={choice:?} entries={entries} skips={skips}");
                                let (_, staged) = parent
                                    .new_batch::<Sha256>()
                                    .write(keys[9], value)
                                    .stage(&read, &db)
                                    .await
                                    .unwrap();
                                let mut policy =
                                    Script::new(entries, skips, |_: &sha256::Digest| choice);
                                let staged = staged
                                    .merkleize(
                                        updates.clone(),
                                        upserts.clone(),
                                        None,
                                        &db,
                                        &mut policy,
                                    )
                                    .await
                                    .unwrap();
                                let mut twin =
                                    Script::new(entries, skips, |_: &sha256::Digest| choice);
                                let twin_batch = written
                                    .into_iter()
                                    .fold(parent.new_batch::<Sha256>(), |batch, (key, value)| {
                                        batch.write(key, value)
                                    })
                                    .merkleize(&db, None, &mut twin)
                                    .await
                                    .unwrap();
                                assert_eq!(policy.visited, twin.visited, "{label}");
                                assert_eq!(staged.root(), twin_batch.root(), "{label}");
                                assert_eq!(
                                    staged.bounds().inactivity_floor,
                                    twin_batch.bounds().inactivity_floor,
                                    "{label}"
                                );
                                if entries != usize::MAX || skips != u64::MAX {
                                    continue;
                                }

                                // The state after the writes, then the twin's decisions.
                                let mut expected: BTreeMap<_, _> =
                                    keys.iter().map(|key| (*key, *key)).collect();
                                expected.insert(keys[1], rewrite.unwrap());
                                expected.insert(keys[6], rewrite.unwrap());
                                for (key, value) in written {
                                    match value {
                                        Some(value) => expected.insert(key, value),
                                        None => expected.remove(&key),
                                    };
                                }
                                for (_, key, _) in &twin.visited {
                                    match choice {
                                        Choice::Keep | Choice::Stop => {}
                                        Choice::Evict => {
                                            expected.remove(key);
                                        }
                                        Choice::Replace(value) => {
                                            expected.insert(*key, value);
                                        }
                                    }
                                }
                                drop((twin_batch, staged));

                                // Apply the same staged batch on a fresh database, then sync and
                                // reopen it.
                                let partition = format!("staged-fixed-{apply_label}");
                                let config = $config(&partition, &context);
                                let (fresh, fresh_parent) = seed(
                                    <$db>::init(context.child(apply_label), config, None)
                                        .await
                                        .unwrap(),
                                )
                                .await;
                                let (_, staged) = fresh_parent
                                    .new_batch::<Sha256>()
                                    .write(keys[9], value)
                                    .stage(&read, &fresh)
                                    .await
                                    .unwrap();
                                let mut policy =
                                    Script::new(entries, skips, |_: &sha256::Digest| choice);
                                let staged = staged
                                    .merkleize(
                                        updates.clone(),
                                        upserts.clone(),
                                        None,
                                        &fresh,
                                        &mut policy,
                                    )
                                    .await
                                    .unwrap();
                                assert_eq!(policy.visited, twin.visited, "{label}");
                                drop(fresh_parent);
                                let (fresh, _) = fresh.apply_batch(staged).await.unwrap();
                                let check = |db: $db| {
                                    let keys = keys.clone();
                                    let expected = expected.clone();
                                    let label = label.clone();
                                    async move {
                                        for key in &keys {
                                            assert_eq!(
                                                db.get(key).await.unwrap(),
                                                expected.get(key).copied(),
                                                "{label}: value of key {key:?}"
                                            );
                                        }
                                        db.assert_exact().await;
                                        db
                                    }
                                };
                                let fresh = check(fresh).await;
                                let (root, floor) = (fresh.root(), fresh.inactivity_floor_loc());
                                drop(fresh.sync().await.unwrap());
                                let config = $config(&partition, &context);
                                let reopened =
                                    <$db>::init(context.child(reopen_label), config, None)
                                        .await
                                        .unwrap();
                                assert_eq!(reopened.root(), root, "{label}: root after reopen");
                                assert_eq!(
                                    reopened.inactivity_floor_loc(),
                                    floor,
                                    "{label}: floor after reopen"
                                );
                                check(reopened).await.destroy().await.unwrap();
                            }
                        }
                    }
                    drop(parent);
                    db.destroy().await.unwrap();
                });
            }
        };
    }

    staged_fixed_walk_matches_unstaged_test!(
        staged_fixed_walk_matches_unstaged,
        AnyUnordered,
        fixed_db_config::<OneCap>
    );

    staged_fixed_walk_matches_unstaged_test!(
        current_staged_fixed_walk_matches_unstaged,
        CurrentUnordered,
        current::tests::fixed_config::<OneCap>
    );

    /// A [`Proportional`] child of a pending parent that rewrote keys reads the applied
    /// locations the parent superseded and finds them inactive, reaches the parent's own updates,
    /// and produces the same batch whether it merkleizes directly or through a staged read set, as
    /// a fixed policy that keeps as many updates as it moves, and as a twin merkleized after the
    /// parent is applied. Each case seeds `n` keys at 1.. with a held floor, rewrites the
    /// `rewritten` ones in a held parent, and writes the `written` ones again in the child.
    ///
    /// `reads` pins, where a case states them, the journal reads of the direct and staged
    /// proportional walks and of the staged fixed walk. `moved` names the key whose parent
    /// update the walk moves first.
    #[rstest::rstest]
    // The previous commit's entry moves the update at 5. The walk reads the parent's superseded
    // updates at 1..5 one round at a time, since each round selects as many candidates as moves
    // remain, and then the update it moves.
    #[case::reads_superseded(8, &[0, 1, 2, 3], &[], 1, [Some(5), Some(5), None], None)]
    // No committed update below the parent at 4 and 5 is active, so the previous commit's entry
    // moves the parent's update at 4.
    #[case::reaches_parent(2, &[0, 1], &[], 1, [None, None, None], Some(0))]
    // The proportional walk moves three updates. A policy that keeps three prefetches 1, 2, and
    // 3, since the prefetch selects candidates before the resolution learns which ones the writes
    // supersede, finds 1 and 3 inactive, and reads 4 and 5 for its remaining entries.
    #[case::staged_prefetch(8, &[0, 2], &[0, 2], 3, [None, None, Some(5)], None)]
    fn proportional_over_pending_parent(
        #[case] n: u8,
        #[case] rewritten: &'static [usize],
        #[case] written: &'static [usize],
        #[case] entries: usize,
        #[case] reads: [Option<u64>; 3],
        #[case] moved: Option<usize>,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("proportional-parent", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();
            let keys = distinct(n);
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let rewrite = sha256::Digest::from([0xDD; 32]);
            let parent = rewritten
                .iter()
                .fold(db.new_batch(), |batch, &i| {
                    batch.write(keys[i], Some(rewrite))
                })
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();

            let value = Some(sha256::Digest::from([0xEE; 32]));
            let direct = || {
                written
                    .iter()
                    .fold(parent.new_batch::<Sha256>(), |batch, &i| {
                        batch.write(keys[i], value)
                    })
            };
            let staged_keys: Vec<_> = written.iter().map(|&i| &keys[i]).collect();
            let updates: Vec<_> = (0..written.len()).map(|slot| (slot, value)).collect();
            let mut fixed = Bounded {
                entries,
                skips: u64::MAX,
            };
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let before = items();
            let proportional = direct()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let mut measured = [items() - before; 3];
            let (_, batch) = parent
                .new_batch::<Sha256>()
                .stage(&staged_keys, &db)
                .await
                .unwrap();
            let before = items();
            let staged = batch
                .merkleize(updates.clone(), Vec::new(), None, &db, &mut Proportional)
                .await
                .unwrap();
            measured[1] = items() - before;
            let (_, batch) = parent
                .new_batch::<Sha256>()
                .stage(&staged_keys, &db)
                .await
                .unwrap();
            let before = items();
            let staged_kept = batch
                .merkleize(updates, Vec::new(), None, &db, &mut fixed)
                .await
                .unwrap();
            measured[2] = items() - before;
            let pinned = [0, 1, 2].map(|i| reads[i].map(|_| measured[i]));
            assert_eq!(pinned, reads);
            let kept = direct().merkleize(&db, None, &mut fixed).await.unwrap();
            for root in [staged.root(), staged_kept.root(), kept.root()] {
                assert_eq!(root, proportional.root());
            }
            if let Some(i) = moved {
                let (_, operations) = proportional.operations();
                assert_eq!(
                    operations[0],
                    Operation::Update(update::Unordered(keys[i], rewrite))
                );
            }
            drop((staged, staged_kept, kept));

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let twin = written
                .iter()
                .fold(db.new_batch(), |batch, &i| batch.write(keys[i], value))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(twin.root(), proportional.root());
            drop((proportional, twin));
            db.destroy().await.unwrap();
        });
    }

    /// The staged prefetch covers every entry of the [`Proportional`] walk for the final write to
    /// each staged slot: one per update and two per delete, plus one for the previous commit.
    /// Writing every slot again reads the same operations during the merkleize as writing only
    /// the final values, whether the earlier and final writes are updates or deletes.
    #[rstest::rstest]
    #[case::update(&[Some(0xFF)], 1)]
    #[case::delete(&[None], 2)]
    #[case::update_update(&[Some(0xFF), Some(0xFF)], 1)]
    #[case::delete_update(&[None, Some(0xFF)], 1)]
    #[case::update_delete(&[Some(0xFF), None], 2)]
    #[case::delete_delete(&[None, None], 2)]
    fn staged_prefetch_counts_final_writes(
        #[case] writes: &'static [Option<u8>],
        #[case] entries: usize,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("staged-prefetch", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed 64 keys with a held floor, and stage the last eight.
            let keys: Vec<_> = (0..64u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let staged_keys: Vec<_> = keys[56..].iter().collect();
            let updates = |writes: &[Option<u8>]| -> Vec<_> {
                writes
                    .iter()
                    .flat_map(|write| {
                        let value = write.map(|byte| sha256::Digest::from([byte; 32]));
                        (0..staged_keys.len()).map(move |slot| (slot, value))
                    })
                    .collect()
            };

            let (_, staged) = db.new_batch().stage(&staged_keys, &db).await.unwrap();
            let (prepared, _) = staged
                .resolve_updates_prefetched(
                    updates(writes),
                    Vec::new(),
                    &db,
                    &Proportional,
                    db.bitmap.as_ref(),
                )
                .await
                .unwrap();
            assert_eq!(
                prepared.prefetched.as_ref().unwrap().0.candidates.len(),
                1 + entries * staged_keys.len()
            );
            drop(prepared);

            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let mut reads = Vec::new();
            for writes in [writes, &writes[writes.len() - 1..]] {
                let (_, staged) = db.new_batch().stage(&staged_keys, &db).await.unwrap();
                let before = items();
                let merkleized = staged
                    .merkleize(updates(writes), Vec::new(), None, &db, &mut Proportional)
                    .await
                    .unwrap();
                reads.push(items() - before);
                drop(merkleized);
            }
            assert_eq!(reads[0], reads[1]);
            db.destroy().await.unwrap();
        });
    }

    /// A [`Proportional`] walk past updates its batch supersedes, interleaved with the updates it
    /// moves, reads exactly the updates it moves in one batched read.
    #[test]
    fn proportional_reads_past_superseded_updates_in_one_read() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "proportional-one-read";
            let config = fixed_db_config::<OneCap>(partition, &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed 64 keys in key order at 1..65 with a held floor, then commit and reopen so no
            // operation is cached.
            let keys: Vec<_> = (0..64u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            drop(db.commit().await.unwrap());
            let config = fixed_db_config::<OneCap>(partition, &context);
            let db = AnyUnordered::init(context.child("cold"), config, None)
                .await
                .unwrap();

            // Updating every other one of the first 32 keys supersedes their updates at the odd
            // locations 1..32 and takes 17 entries with the previous commit. After one batched read
            // of the 16 written keys, the walk moves the updates at the even locations 2..=32 and
            // at 33 with one more.
            let names = [
                "log_journal_read_many_calls_total",
                "log_journal_items_read_total",
            ];
            let counters = || names.map(|name| crate::qmdb::any::test::counter(&context, name));
            let [batched, items] = counters();
            let value = Some(sha256::Digest::from([0xEE; 32]));
            let merkleized = keys[..32]
                .iter()
                .step_by(2)
                .fold(db.new_batch(), |batch, key| batch.write(*key, value))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(counters(), [batched + 2, items + 16 + 17]);
            assert_eq!(merkleized.bounds().inactivity_floor, Location::new(34));
            drop(merkleized);
            db.destroy().await.unwrap();
        });
    }

    /// A proportional walk whose candidates run out passes the superseded locations it skips
    /// unread after its last move and reaches the tip after the batch's writes.
    #[test]
    fn proportional_floor_passes_trailing_superseded_candidates() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("proportional-trailing", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed four keys at 1..5 with a held floor.
            let keys: Vec<_> = (1..5u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            // Deleting the last two keys supersedes their updates at 3 and 4 and takes five
            // entries. A source of only the applied updates (the commit at 5 and the deletes at 6
            // and 7 hold none) runs out after them, so the walk moves the updates at 1 and 2 and
            // its floor passes 3, 4, the commit, and both deletes to the tip at 8.
            let prepared = db
                .new_batch()
                .write(keys[2], None)
                .write(keys[3], None)
                .prepare(&db)
                .unwrap();
            let (merkleized, _) = prepared
                .merkleize_with_floor_walk(
                    None,
                    Vec::new(),
                    FnCandidates(|floor, tip: u64, limit, out: &mut Vec<_>| {
                        db.bitmap.as_ref().fill(floor, tip.min(5), limit, out)
                    }),
                    &mut Proportional,
                )
                .await
                .unwrap();
            assert_eq!(merkleized.bounds().inactivity_floor, Location::new(8));
            let (_, operations) = merkleized.operations();
            assert_eq!(
                operations[2..4],
                [keys[0], keys[1]].map(|key| Operation::Update(update::Unordered(key, key)))
            );
            drop(merkleized);
            db.destroy().await.unwrap();
        });
    }

    /// Evicting a key the walk reaches before its predecessor produces the same batch whether
    /// the two share a candidate round or not, and the predecessor links past the evicted key,
    /// whether it is an applied update or the batch's own write. Decisions are collected during
    /// the walk, so a round's classification never sees another round's link repair.
    #[test]
    fn eviction_before_predecessor_matches_across_rounds() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("eviction-rounds", &context);
            let db = AnyOrdered::init(context.child("db"), config, None)
                .await
                .unwrap();
            let [a, b, c] = [1u8, 2, 3].map(|byte| sha256::Digest::from([byte; 32]));

            // Seed the keys in key order at 1..4, then update the smallest so its active update
            // at 5 lies above the others: the walk reaches the evicted middle key at 2 before its
            // predecessor.
            let seed = [a, b, c]
                .into_iter()
                .fold(db.new_batch(), |batch, key| batch.write(key, Some(key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let moved = sha256::Digest::from([0xAA; 32]);
            let update = db
                .new_batch()
                .write(a, Some(moved))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(update).await.unwrap();
            assert_eq!(db.size(), Location::new(7));
            let choose = |key: &sha256::Digest| {
                if *key == b {
                    Choice::Evict
                } else {
                    Choice::Keep
                }
            };
            let link = |key, value, next_key| {
                Operation::Update(update::Ordered {
                    key,
                    value,
                    next_key,
                })
            };

            // The predecessor is the applied update at 5, then the batch's own write at 7.
            // Each scenario walks once over one round holding every candidate, and once with a
            // prefetched round holding only the evicted key, so its predecessor is classified in
            // a later round.
            let again = sha256::Digest::from([0xBB; 32]);
            let mut applied = None;
            for write in [None, Some(again)] {
                let mut batches = Vec::new();
                for split in [false, true] {
                    let mut policy = Script::new(usize::MAX, u64::MAX, choose);
                    let batch = write.map_or_else(
                        || db.new_batch(),
                        |value| db.new_batch().write(a, Some(value)),
                    );
                    let mut prepared = batch.prepare(&db).unwrap();
                    if split {
                        prepared.prefetched = Some((
                            Round {
                                candidates: vec![loc(2)],
                                committed: db.log.read_many_sharded(&[2]).await.unwrap(),
                            },
                            loc(3),
                        ));
                    }
                    let (merkleized, _) = prepared
                        .merkleize_with_floor_walk(
                            None,
                            Vec::new(),
                            db.bitmap.as_ref(),
                            &mut policy,
                        )
                        .await
                        .unwrap();
                    let predecessor = if write.is_some() { 7 } else { 5 };
                    assert_eq!(policy.locations(), [loc(2), loc(3), loc(predecessor)]);
                    batches.push(merkleized);
                }
                assert_same(&db, &batches[0], &batches[1]);

                // After its write, if any, the batch deletes the evicted key and rewrites the
                // kept update and the predecessor, which now links past the evicted key. The
                // floor lands at the tip after the writes.
                let merkleized = batches.pop().unwrap();
                drop(batches);
                let (start, ops) = merkleized.operations();
                assert_eq!(start, Location::new(7));
                let writes = usize::from(write.is_some());
                assert_eq!(
                    ops[writes..writes + 3],
                    [
                        Operation::Delete(b),
                        link(c, c, a),
                        link(a, write.unwrap_or(moved), c),
                    ]
                );
                assert_eq!(
                    merkleized.bounds().inactivity_floor,
                    Location::new(7 + Widen::widen(writes))
                );
                assert_eq!(merkleized.get_next_key(&a, &db).await.unwrap(), Some(c));
                assert_eq!(merkleized.get_prev_key(&c, &db).await.unwrap(), Some(a));
                applied = Some(merkleized);
            }
            let (db, _) = db.apply_batch(applied.unwrap()).await.unwrap();
            assert_links(&db, &BTreeMap::from([(a, again), (c, c)]), &[b]).await;
            db.destroy().await.unwrap();
        });
    }

    /// Evicting an ordered key whose predecessor lies in the previous translated-key bucket, with
    /// its update above the window end, reads the window's candidate, then the applied updates in
    /// the evicted key's bucket and in the previous bucket. The batch deletes the key and rewrites
    /// the predecessor to link past it.
    #[test]
    fn policy_ordered_eviction_reads_only_buckets() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("ordered-eviction-reads", &context);
            let db = AnyOrdered::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed the predecessor, the evicted key and its sibling, and a larger key in key order
            // at 1..5, then rewrite the predecessor at 6. Each prefix is a translated-key bucket.
            let predecessor = colliding_digest(0x10, 0);
            let evicted = colliding_digest(0x20, 0);
            let sibling = colliding_digest(0x20, 1);
            let larger = colliding_digest(0x30, 0);
            let seed = [predecessor, evicted, sibling, larger]
                .into_iter()
                .fold(db.new_batch(), |batch, key| batch.write(key, Some(key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let moved = sha256::Digest::from([0xAA; 32]);
            let rewrite = db
                .new_batch()
                .write(predecessor, Some(moved))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(rewrite).await.unwrap();
            assert_eq!(db.size(), Location::new(8));

            // Two skips pass the initial commit and the superseded update at 1, and one entry
            // evicts the key at 2, so the window ends at 3, below the predecessor's update at 6.
            // The walk reads the evicted update. The repair reads the evicted key's bucket (2 and
            // 3) and the previous bucket (6).
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let before = items();
            let mut policy = Script::new(1, 2, |key: &sha256::Digest| {
                if *key == evicted {
                    Choice::Evict
                } else {
                    Choice::Keep
                }
            });
            let merkleized = db
                .new_batch()
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(items() - before, 4);
            assert_eq!(policy.locations(), [loc(2)]);
            assert_eq!(merkleized.bounds().inactivity_floor, loc(3));
            let (start, ops) = merkleized.operations();
            assert_eq!(start, loc(8));
            assert_eq!(
                ops[..2],
                [
                    Operation::Delete(evicted),
                    Operation::Update(update::Ordered {
                        key: predecessor,
                        value: moved,
                        next_key: sibling,
                    }),
                ]
            );
            assert_eq!(ops.len(), 3);
            drop(merkleized);
            db.destroy().await.unwrap();
        });
    }

    /// A key the batch creates and the walk evicts ends deleted with no base location, leaving
    /// the active-key count unchanged.
    #[test]
    fn created_then_evicted_key_has_no_base() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("created-evicted", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();
            let [kept, created] = [1u8, 2].map(|byte| sha256::Digest::from([byte; 32]));
            let seed = db
                .new_batch()
                .write(kept, Some(kept))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            // The walk keeps the applied update and evicts the create at 3.
            let mut policy = Script::new(usize::MAX, u64::MAX, |key: &sha256::Digest| {
                if *key == created {
                    Choice::Evict
                } else {
                    Choice::Keep
                }
            });
            let merkleized = db
                .new_batch()
                .write(created, Some(created))
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(policy.locations(), [loc(1), loc(3)]);
            let diff: Vec<_> = merkleized
                .diff
                .iter()
                .map(|(key, entry)| (*key, entry.loc(), entry.base_old_loc()))
                .collect();
            assert_eq!(
                diff,
                [(kept, Some(loc(4)), Some(loc(1))), (created, None, None)]
            );
            assert_eq!(merkleized.total_active_keys, 1);
            let (_, ops) = merkleized.operations();
            assert_eq!(
                ops[..3],
                [
                    Operation::Update(update::Unordered(created, created)),
                    Operation::Update(update::Unordered(kept, kept)),
                    Operation::Delete(created),
                ]
            );
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            assert_eq!(db.get(&created).await.unwrap(), None);
            assert_eq!(db.get(&kept).await.unwrap(), Some(kept));
            assert_eq!(db.active_keys, 1);
            db.destroy().await.unwrap();
        });
    }

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

    /// `sorted_contains_by` matches `binary_search` for ascending queries over sorted, deduped
    /// items.
    #[test]
    fn sorted_contains_by_matches_binary_search() {
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
                    sorted_contains_by(&items, &mut cursor, &q, |item| item),
                    items.binary_search(&q).is_ok(),
                    "query {q} diverged"
                );
            }
        }
    }

    /// `merge_by` on keys matches `extend` + `sort_by_key` for disjoint, sorted diffs.
    #[test]
    fn merge_by_matches_sort() {
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

            let merged = merge_by(a, b, |x, y| x.0 < y.0);
            assert_eq!(merged.len(), reference.len());
            for ((mk, me), (rk, re)) in merged.iter().zip(&reference) {
                assert_eq!(mk, rk);
                assert_eq!(me.loc(), re.loc());
                assert_eq!(me.value(), re.value());
            }
        }
    }

    /// Single-step oracle for [`Candidates::fill`]: return the next floor candidate in
    /// `[floor, tip)`. `bitmap_fill_candidates_matches_oracle` checks that the production batch
    /// fill produces this exact sequence over its constructed chains.
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

    /// [`Candidates::fill`] must produce the exact candidate sequence of repeatedly calling the
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
                        scan = (&bitmap).fill(scan, tip, limit, &mut batch);
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

    // Recreated keys replace their committed locations when a pending chain is applied.
    // Fresh and recreated keys share key order. Absent deletes do not change the batch.
    macro_rules! recreated_keys_apply_pending_chain_test {
        ($name:ident, $db:ident) => {
            #[test]
            fn $name() {
                deterministic::Runner::default().start(|context| async move {
                    type TestDb = $db<
                        mmr::Family,
                        deterministic::Context,
                        sha256::Digest,
                        sha256::Digest,
                        Sha256,
                        OneCap,
                        Sequential,
                    >;

                    for existed in [false, true] {
                        let context = context.child("db").with_attribute("existed", existed);
                        let config = fixed_db_config::<OneCap>(stringify!($name), &context);
                        let db = TestDb::init(context, config, None).await.unwrap();
                        let key = |i| colliding_digest(0xA0, i);
                        let value = |i| colliding_digest(0xB0, i);

                        let mut seed = db
                            .new_batch()
                            .write(key(6), Some(value(6)))
                            .write(key(8), Some(value(8)));
                        if existed {
                            seed = seed.write(key(2), Some(value(2)));
                        }
                        let seed = seed.merkleize(&db, None, &mut Proportional).await.unwrap();
                        let base_loc = lookup_sorted(&seed.diff, &key(2)).and_then(DiffEntry::loc);
                        assert_eq!(base_loc.is_some(), existed);
                        let (db, _) = db.apply_batch(seed).await.unwrap();

                        // The nearest ancestor deletes a key that an older ancestor updated
                        // or created. Its recreation must retain the original committed base.
                        let grandparent = db
                            .new_batch()
                            .write(key(2), Some(value(20)))
                            .merkleize(&db, None, &mut Proportional)
                            .await
                            .unwrap();
                        let parent = grandparent
                            .new_batch::<Sha256>()
                            .write(key(2), None)
                            .write(key(6), None)
                            .merkleize(&db, None, &mut Proportional)
                            .await
                            .unwrap();
                        let creates = || {
                            parent
                                .new_batch::<Sha256>()
                                .write(key(4), Some(value(34)))
                                .write(key(2), Some(value(32)))
                                .write(key(0), Some(value(30)))
                        };
                        let without_deletes = creates()
                            .merkleize(&db, None, &mut Proportional)
                            .await
                            .unwrap();
                        let child = creates()
                            .write(key(3), None)
                            .write(key(6), None)
                            .merkleize(&db, None, &mut Proportional)
                            .await
                            .unwrap();

                        let (_, ops) = child.operations();
                        assert_eq!(child.root(), without_deletes.root());
                        assert_eq!(*ops, *without_deletes.operations().1);
                        assert_eq!(
                            ops[..3].iter().map(OperationTrait::key).collect::<Vec<_>>(),
                            vec![Some(&key(0)), Some(&key(2)), Some(&key(4))]
                        );
                        assert!(!ops.iter().any(OperationTrait::is_delete));

                        // Apply the entire pending chain at once: applying the deletion first
                        // would remove the committed location and mask a lost base location.
                        let (db, _) = db.apply_batch(Arc::clone(&child)).await.unwrap();
                        for i in [0, 2, 4] {
                            assert_eq!(db.get(&key(i)).await.unwrap(), Some(value(30 + i)));
                        }
                        assert_eq!(db.get(&key(8)).await.unwrap(), Some(value(8)));
                        for i in [3, 6] {
                            assert_eq!(db.get(&key(i)).await.unwrap(), None);
                        }
                        assert_eq!(db.active_keys, 4);
                        assert_eq!(db.snapshot.items(), 4);
                        if let Some(base_loc) = base_loc {
                            assert!(!db.bitmap.get_bit(*base_loc));
                        }
                        for (i, expected_base) in [(0, None), (2, base_loc), (4, None)] {
                            let entry = lookup_sorted(&child.diff, &key(i)).unwrap();
                            assert_eq!(entry.base_old_loc(), expected_base);
                        }
                        db.destroy().await.unwrap();
                    }
                });
            }
        };
    }

    recreated_keys_apply_pending_chain_test!(
        unordered_recreated_keys_apply_pending_chain,
        UnorderedFixedDb
    );
    recreated_keys_apply_pending_chain_test!(
        ordered_recreated_keys_apply_pending_chain,
        OrderedFixedDb
    );

    /// `operations()` must cover exactly the batch's own applied range and match the
    /// operations a post-apply `historical_proof` recovers from the log, including
    /// the floor walk's moves and the trailing commit, for a db-based batch and for a chained
    /// batch applied after its ancestor.
    #[test]
    fn operations_match_applied_log() {
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

            let config = fixed_db_config::<OneCap>("operations-match-applied-log", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let key_a = Sha256::hash(&[b"operations-a"]);
            let key_b = Sha256::hash(&[b"operations-b"]);

            let seed = db
                .new_batch()
                .write(key_a, Some(Sha256::hash(&[b"seed-a"])))
                .write(key_b, Some(Sha256::hash(&[b"seed-b"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (seed_start, seed_ops) = seed.operations();
            let seed_root = seed.root();
            let seed_proof = seed.proof(&db).unwrap();
            let seed_pins = seed.pinned_nodes(&db).unwrap();
            let (db, seed_range) = db.apply_batch(seed).await.unwrap();
            assert_eq!(seed_start, seed_range.start);
            assert_eq!(*seed_start + seed_ops.len() as u64, *seed_range.end);

            // A chained batch's operations are its own suffix only, even though it was
            // merkleized on top of a pending ancestor.
            let parent = db
                .new_batch()
                .write(key_a, Some(Sha256::hash(&[b"parent-a"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let child = parent
                .new_batch::<Sha256>()
                .write(key_b, Some(Sha256::hash(&[b"child-b"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (parent_start, parent_ops) = parent.operations();
            let (child_start, child_ops) = child.operations();
            let (parent_root, child_root) = (parent.root(), child.root());
            let (parent_proof, child_proof) =
                (parent.proof(&db).unwrap(), child.proof(&db).unwrap());
            let (parent_pins, child_pins) = (
                parent.pinned_nodes(&db).unwrap(),
                child.pinned_nodes(&db).unwrap(),
            );
            let (db, parent_range) = db.apply_batch(parent).await.unwrap();
            // At the parent's tip, the child proves from the live store with the same result.
            assert_eq!(child.proof(&db).unwrap(), child_proof);
            assert_eq!(child.pinned_nodes(&db).unwrap(), child_pins);
            let (db, child_range) = db.apply_batch(child).await.unwrap();
            assert_eq!(parent_start, parent_range.start);
            assert_eq!(*parent_start + parent_ops.len() as u64, *parent_range.end);
            assert_eq!(child_start, child_range.start);
            assert_eq!(*child_start + child_ops.len() as u64, *child_range.end);

            // A write-free batch still captures its commit-only suffix.
            let empty = db
                .new_batch()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (empty_start, empty_ops) = empty.operations();
            let (empty_root, empty_proof) = (empty.root(), empty.proof(&db).unwrap());
            let empty_pins = empty.pinned_nodes(&db).unwrap();
            let (db, empty_range) = db.apply_batch(empty).await.unwrap();
            assert_eq!(empty_start, empty_range.start);
            assert_eq!(*empty_start + empty_ops.len() as u64, *empty_range.end);

            // Every captured delta and proof must match what the log recovers for its
            // range, and verify against the batch's own root with and without the pins.
            for (start, ops, proof, pins, root) in [
                (seed_start, seed_ops, seed_proof, seed_pins, seed_root),
                (
                    parent_start,
                    parent_ops,
                    parent_proof,
                    parent_pins,
                    parent_root,
                ),
                (child_start, child_ops, child_proof, child_pins, child_root),
                (empty_start, empty_ops, empty_proof, empty_pins, empty_root),
            ] {
                let len = core::num::NonZeroU64::new(ops.len() as u64).unwrap();
                let end = Location::new(*start + ops.len() as u64);
                let (log_proof, log_ops) = db.historical_proof(end, start, len).await.unwrap();
                assert_eq!(log_ops, *ops);
                assert_eq!(log_proof, proof);
                assert!(crate::qmdb::verify_proof::<Sha256, _, _>(
                    &proof, start, &ops, &root
                ));
                assert!(crate::qmdb::verify_proof_and_pinned_nodes::<Sha256, _, _>(
                    &proof, start, &ops, &pins, &root
                ));
            }

            // Flushing the applied batch prunes the store to its peaks. The late batch's base is
            // mid-mountain, so its artifacts are refused rather than returned unverifiable.
            let late = db
                .new_batch()
                .write(key_a, Some(Sha256::hash(&[b"late-a"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(Arc::clone(&late)).await.unwrap();
            let db = db.commit().await.unwrap();
            assert!(matches!(
                late.proof(&db),
                Err(crate::qmdb::Error::Merkle(
                    crate::merkle::Error::ElementPruned(_)
                ))
            ));
            assert!(matches!(
                late.pinned_nodes(&db),
                Err(crate::qmdb::Error::Merkle(
                    crate::merkle::Error::ElementPruned(_)
                ))
            ));

            // A batch built on the flushed store reads every node below it from the pinned peaks.
            let flushed = db
                .new_batch()
                .write(key_b, Some(Sha256::hash(&[b"flushed-b"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (flushed_start, flushed_ops) = flushed.operations();
            let flushed_root = flushed.root();
            let flushed_proof = flushed.proof(&db).unwrap();
            let flushed_pins = flushed.pinned_nodes(&db).unwrap();
            assert!(crate::qmdb::verify_proof_and_pinned_nodes::<Sha256, _, _>(
                &flushed_proof,
                flushed_start,
                &flushed_ops,
                &flushed_pins,
                &flushed_root
            ));
            let (db, flushed_range) = db.apply_batch(flushed).await.unwrap();
            assert_eq!(flushed_start, flushed_range.start);
            assert_eq!(
                *flushed_start + flushed_ops.len() as u64,
                *flushed_range.end
            );

            db.destroy().await.unwrap();
        });
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
            let db = TestDb::init(context, config, None).await.unwrap();

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
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let final_update = Sha256::hash(&[b"child-update"]);
            let child = pending
                .new_batch::<Sha256>()
                .write(key_update, Some(final_update))
                .write(key_recreate_then_delete, None)
                .merkleize(&db, None, &mut Proportional)
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

    /// A compatible child batch must read and merkleize identically whether its
    /// ancestor is still pending or already applied.
    #[test]
    fn merkleize_after_compatible_ancestor_apply_matches() {
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

            let config = fixed_db_config::<OneCap>("resume-after-apply", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed with churn so floor maintenance has real work at every
            // later merkleize.
            let hot = Sha256::hash(&[b"hot"]);
            let cold = Sha256::hash(&[b"cold"]);
            let doomed = Sha256::hash(&[b"doomed"]);
            let untouched = Sha256::hash(&[b"untouched"]);
            let untouched_value = Sha256::hash(&[b"untouched-value"]);
            let mut db = db;
            for round in 0u64..4 {
                let batch = db
                    .new_batch()
                    .write(hot, Some(Sha256::hash(&[&round.to_be_bytes()])))
                    .write(cold, Some(Sha256::hash(&[b"cold-value"])))
                    .write(doomed, (round % 2 == 0).then_some(Sha256::hash(&[b"d"])))
                    .write(untouched, Some(untouched_value))
                    .merkleize(&db, None, &mut Proportional)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
            }

            // The parent the child forks from, merkleized but not yet applied.
            let parent_write = Sha256::hash(&[b"parent-write"]);
            let parent = db
                .new_batch()
                .write(hot, Some(parent_write))
                .write(doomed, None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Two identical children forked from the pending parent.
            let child_write = Sha256::hash(&[b"child-write"]);
            let build = |parent: &Arc<MerkleizedBatch<_, _, _, _>>| {
                parent
                    .new_batch::<Sha256>()
                    .write(cold, Some(child_write))
                    .write(hot, Some(child_write))
            };

            // Path A. The child merkleizes while its parent is still pending.
            // Capture its root and a fallback read of a key no batch in
            // the chain touches, which resolves from committed state.
            let child_pre = build(&parent);
            let read_pre = child_pre.get(&untouched, &db).await.unwrap();
            assert_eq!(read_pre, Some(untouched_value));
            let root_pre = child_pre
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap()
                .root();

            // Apply the parent.
            let (db, _) = db.apply_batch(parent.clone()).await.unwrap();

            // Path B. An identical child reads and merkleizes
            // against the post-apply database.
            let child_post = build(&parent);
            let read_post = child_post.get(&untouched, &db).await.unwrap();
            assert_eq!(read_pre, read_post, "fallback reads must not change");
            let child_post = child_post
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(
                root_pre,
                child_post.root(),
                "merkleize must be order-independent for compatible batches",
            );

            // The post-merkleized child applies cleanly and lands the same root.
            let (db, _) = db.apply_batch(child_post).await.unwrap();
            assert_eq!(db.root(), root_pre);
            assert_eq!(db.get(&hot).await.unwrap(), Some(child_write));
            assert_eq!(db.get(&cold).await.unwrap(), Some(child_write));
            assert_eq!(db.get(&doomed).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Pruning happens while batches are live, so a batch must keep reading and
    /// merkleizing across one. Pruning only discards operations below the
    /// inactivity floor, which are superseded, and leaves the root untouched.
    #[test]
    fn batch_reads_and_merkleizes_across_a_prune() {
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

            let config = fixed_db_config::<OneCap>("prune-under-batch", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Churn so the inactivity floor advances and history is prunable.
            let hot = Sha256::hash(&[b"hot"]);
            let cold = Sha256::hash(&[b"cold"]);
            let mut db = db;
            for round in 0u64..8 {
                let batch = db
                    .new_batch()
                    .write(hot, Some(Sha256::hash(&[&round.to_be_bytes()])))
                    .write(cold, Some(Sha256::hash(&[b"cold-value"])))
                    .merkleize(&db, None, &mut Proportional)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
            }
            let floor = db.inactivity_floor_loc();
            assert!(*floor > 0, "the test needs prunable history");

            // A batch built before the prune, plus the reference values it must
            // still produce afterward.
            let write = Sha256::hash(&[b"write"]);
            let build = || db.new_batch().write(hot, Some(write));
            let reference = build();
            let read_before = reference.get(&cold, &db).await.unwrap();
            let root_before = reference
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap()
                .root();
            let batch = build();

            let db = db.prune(floor).await.unwrap();
            assert!(*db.bounds().start > 0, "the prune must drop history");

            assert_eq!(
                batch.get(&cold, &db).await.unwrap(),
                read_before,
                "a fallback read must survive pruning",
            );
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            assert_eq!(
                merkleized.root(),
                root_before,
                "pruning must not change what a live batch merkleizes to",
            );

            // It still applies, because pruning is not a competing batch.
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            assert_eq!(db.get(&hot).await.unwrap(), Some(write));

            db.destroy().await.unwrap();
        });
    }

    /// A batch on a losing fork refuses reads and merkleization once a competing batch is
    /// applied. Reads return `StaleRead` and merkleization returns `StaleBatch` instead of
    /// using a state the chain does not account for. The forks write the same key with different
    /// values, the shape where an unchecked read would silently tear.
    #[test]
    fn stale_fork_reads_and_merkleizes_refuse() {
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

            let config = fixed_db_config::<OneCap>("stale-fork", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let hot = Sha256::hash(&[b"hot"]);
            let cold = Sha256::hash(&[b"cold"]);
            let winner_only = Sha256::hash(&[b"winner-only"]);
            let mut db = db;
            for round in 0u64..4 {
                let batch = db
                    .new_batch()
                    .write(hot, Some(Sha256::hash(&[&round.to_be_bytes()])))
                    .write(cold, Some(Sha256::hash(&[b"cold-value"])))
                    .merkleize(&db, None, &mut Proportional)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
            }

            // Two competing batches off the same committed prefix. Only the
            // winner touches `winner_only`.
            let winner_write = Sha256::hash(&[b"winner"]);
            let winner = db
                .new_batch()
                .write(hot, Some(winner_write))
                .write(winner_only, Some(winner_write))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let loser_write = Sha256::hash(&[b"loser"]);
            let loser = db
                .new_batch()
                .write(hot, Some(loser_write))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // The loser's child, forked before anything is applied, reads and
            // merkleizes normally.
            let child_write = Sha256::hash(&[b"child"]);
            let build = || loser.new_batch::<Sha256>().write(cold, Some(child_write));
            let before = build();
            assert_eq!(before.get(&hot, &db).await.unwrap(), Some(loser_write));
            assert_eq!(before.get(&winner_only, &db).await.unwrap(), None);
            before
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // The winner lands. The loser's chain is now stale, and every operation
            // through it refuses, covered and uncovered keys alike.
            let child = build();
            let (db, _) = db.apply_batch(winner).await.unwrap();
            assert!(matches!(
                child.get(&hot, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                child.get(&winner_only, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                child.get_many(&[&hot, &cold], &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                child.stage(&[&hot], &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            let child = build();
            assert!(matches!(
                child.merkleize(&db, None, &mut Proportional).await,
                Err(crate::qmdb::Error::StaleBatch)
            ));

            // The merkleized loser refuses reads too, and applying it stays
            // separately rejected (see `chain`).
            assert!(matches!(
                loser.get(&hot, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                db.validate_batch(&loser),
                Err(crate::qmdb::Error::StaleBatch)
            ));

            db.destroy().await.unwrap();
        });
    }

    /// Applying a batch's child moves the database past the parent's own states, so reads
    /// through the parent refuse while the child keeps reading.
    #[test]
    fn descendant_apply_makes_parent_reads_stale() {
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

            let config = fixed_db_config::<OneCap>("descendant-apply", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let key = Sha256::hash(&[b"key"]);
            let parent_write = Sha256::hash(&[b"parent"]);
            let parent = db
                .new_batch()
                .write(key, Some(parent_write))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(parent.get(&key, &db).await.unwrap(), Some(parent_write));
            let child_write = Sha256::hash(&[b"child"]);
            let child = parent
                .new_batch::<Sha256>()
                .write(key, Some(child_write))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(child.clone()).await.unwrap();
            assert_eq!(child.get(&key, &db).await.unwrap(), Some(child_write));
            assert!(matches!(
                parent.get(&key, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                parent.get_many(&[&key], &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));

            db.destroy().await.unwrap();
        });
    }

    /// A staged handle crossing a foreign apply refuses at expand and merkleize,
    /// and the gate runs before empty-input early returns.
    #[test]
    fn staged_and_empty_reads_refuse_on_stale_fork() {
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

            let config = fixed_db_config::<OneCap>("staged-stale-fork", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let hot = Sha256::hash(&[b"hot"]);
            let seed = db
                .new_batch()
                .write(hot, Some(Sha256::hash(&[b"seed"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            // Two competing batches off the same committed prefix, with staged
            // handles and an idle child taken through the loser beforehand.
            let winner = db
                .new_batch()
                .write(hot, Some(Sha256::hash(&[b"winner"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let loser = db
                .new_batch()
                .write(hot, Some(Sha256::hash(&[b"loser"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (_, staged_expand) = loser
                .new_batch::<Sha256>()
                .stage(&[&hot], &db)
                .await
                .unwrap();
            let (_, staged_merkleize) = loser
                .new_batch::<Sha256>()
                .stage(&[&hot], &db)
                .await
                .unwrap();
            let idle = loser.new_batch::<Sha256>();

            let (db, _) = db.apply_batch(winner).await.unwrap();

            // The staged handles refuse at expand and at merkleize.
            assert!(matches!(
                staged_expand.expand(&[&hot], &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                staged_merkleize
                    .merkleize(vec![], vec![], None, &db, &mut Proportional)
                    .await,
                Err(crate::qmdb::Error::StaleBatch)
            ));

            // Empty inputs still surface the staleness.
            let no_keys: [&sha256::Digest; 0] = [];
            assert!(matches!(
                idle.get_many(&no_keys, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                idle.stage(&no_keys, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));

            db.destroy().await.unwrap();
        });
    }

    /// Sibling forks with the same operation count still refuse because the check compares
    /// full commitments, never sizes alone.
    #[test]
    fn equal_size_sibling_reads_refuse() {
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

            let config = fixed_db_config::<OneCap>("equal-size-sibling", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let hot = Sha256::hash(&[b"hot"]);
            let winner = db
                .new_batch()
                .write(hot, Some(Sha256::hash(&[b"winner"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let loser = db
                .new_batch()
                .write(hot, Some(Sha256::hash(&[b"loser"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(winner.bounds().tip.size, loser.bounds().tip.size);
            assert_ne!(winner.root(), loser.root());

            let (db, _) = db.apply_batch(winner).await.unwrap();
            assert!(matches!(
                loser.get(&hot, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                loser
                    .new_batch::<Sha256>()
                    .merkleize(&db, None, &mut Proportional)
                    .await,
                Err(crate::qmdb::Error::StaleBatch)
            ));

            db.destroy().await.unwrap();
        });
    }

    /// A batch's proof and pinned nodes are refused once a sibling is applied.
    #[test]
    fn proof_refused_after_sibling_apply() {
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

            let config = fixed_db_config::<OneCap>("proof-sibling", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Two siblings write the same key with different values.
            let key = Sha256::hash(&[b"key"]);
            let batch = db
                .new_batch()
                .write(key, Some(Sha256::hash(&[b"batch"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let sibling = db
                .new_batch()
                .write(key, Some(Sha256::hash(&[b"sibling"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert!(batch.proof(&db).is_ok());
            assert!(batch.pinned_nodes(&db).is_ok());

            // Applying the sibling moves the database off the batch's chain.
            let (db, _) = db.apply_batch(sibling).await.unwrap();
            assert!(matches!(
                batch.proof(&db),
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert!(matches!(
                batch.pinned_nodes(&db),
                Err(crate::qmdb::Error::StaleRead)
            ));
            db.destroy().await.unwrap();
        });
    }

    /// Reads stay exact after the ancestor batches are dropped, because merkleization
    /// retains their diffs. Every ancestor write (including a delete) must resolve from
    /// the retained overlays instead of falling through to committed state.
    #[test]
    fn dropped_ancestor_reads_stay_exact() {
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

            let config = fixed_db_config::<OneCap>("dropped-ancestors", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Commit a key the chain deletes and one it never touches.
            let doomed = Sha256::hash(&[b"doomed"]);
            let untouched = Sha256::hash(&[b"untouched"]);
            let untouched_value = Sha256::hash(&[b"untouched-value"]);
            let seed = db
                .new_batch()
                .write(doomed, Some(Sha256::hash(&[b"doomed-value"])))
                .write(untouched, Some(untouched_value))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            // A three-level uncommitted chain. A deletes the committed key.
            let key_a = Sha256::hash(&[b"key-a"]);
            let value_a = Sha256::hash(&[b"value-a"]);
            let key_b = Sha256::hash(&[b"key-b"]);
            let value_b = Sha256::hash(&[b"value-b"]);
            let key_c = Sha256::hash(&[b"key-c"]);
            let value_c = Sha256::hash(&[b"value-c"]);
            let a = db
                .new_batch()
                .write(key_a, Some(value_a))
                .write(doomed, None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let b = a
                .new_batch::<Sha256>()
                .write(key_b, Some(value_b))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let c = b
                .new_batch::<Sha256>()
                .write(key_c, Some(value_c))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let child = c.new_batch::<Sha256>();
            drop(a);
            drop(b);

            // The merkleized batch and its unmerkleized child both resolve every
            // ancestor write from the retained overlays.
            for (key, expected) in [
                (key_a, Some(value_a)),
                (doomed, None),
                (key_b, Some(value_b)),
                (key_c, Some(value_c)),
                (untouched, Some(untouched_value)),
            ] {
                assert_eq!(c.get(&key, &db).await.unwrap(), expected);
                assert_eq!(child.get(&key, &db).await.unwrap(), expected);
            }
            let keys = [&key_a, &doomed, &key_b, &key_c, &untouched];
            let expected = vec![
                Some(value_a),
                None,
                Some(value_b),
                Some(value_c),
                Some(untouched_value),
            ];
            assert_eq!(c.get_many(&keys, &db).await.unwrap(), expected);
            assert_eq!(child.get_many(&keys, &db).await.unwrap(), expected);

            // Staging and expansion also read retained diffs. Merkleization still requires
            // the missing ancestors' operations until that prefix has been applied.
            let (values, staged) = child.stage(&keys, &db).await.unwrap();
            assert_eq!(values, expected);
            let (_, values, staged) = staged.expand(&keys, &db).await.unwrap();
            assert_eq!(values, expected);
            assert!(matches!(
                staged
                    .merkleize(vec![], vec![], None, &db, &mut Proportional)
                    .await,
                Err(crate::qmdb::Error::StaleBatch)
            ));
            assert!(matches!(
                c.new_batch::<Sha256>()
                    .merkleize(&db, None, &mut Proportional)
                    .await,
                Err(crate::qmdb::Error::StaleBatch)
            ));
            let child = c.new_batch::<Sha256>();

            // Applying the chain lands the same values the reads reported.
            let (db, _) = db.apply_batch(c).await.unwrap();
            assert_eq!(db.get(&key_a).await.unwrap(), Some(value_a));
            assert_eq!(db.get(&doomed).await.unwrap(), None);
            assert_eq!(db.get(&key_b).await.unwrap(), Some(value_b));
            assert_eq!(db.get(&key_c).await.unwrap(), Some(value_c));
            assert_eq!(db.get(&untouched).await.unwrap(), Some(untouched_value));
            child.merkleize(&db, None, &mut Proportional).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    /// Bounded initialization moves the database off a tip chain's states, so its reads
    /// refuse. A chain forked at the recovered target reads again because a commitment
    /// identifies state by content.
    #[test]
    fn bounded_initialization_stales_tip_chains_and_revives_target_chains() {
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

            let config = fixed_db_config::<OneCap>("bounded-init-stale", &context);
            let db = TestDb::init(context.child("initial"), config.clone(), None)
                .await
                .unwrap();

            let hot = Sha256::hash(&[b"hot"]);
            let old_write = Sha256::hash(&[b"old"]);
            let first = db
                .new_batch()
                .write(hot, Some(old_write))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(first).await.unwrap();
            let db = db.commit().await.unwrap();
            let target = db.bounds().end;
            let old_chain = db.new_batch();

            let second = db
                .new_batch()
                .write(hot, Some(Sha256::hash(&[b"new"])))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(second).await.unwrap();
            let db = db.commit().await.unwrap();
            let tip_chain = db.new_batch();
            assert!(matches!(
                old_chain.get(&hot, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));

            drop(db);
            let db = TestDb::init(context, config, Some(target)).await.unwrap();
            assert!(matches!(
                tip_chain.get(&hot, &db).await,
                Err(crate::qmdb::Error::StaleRead)
            ));
            assert_eq!(old_chain.get(&hot, &db).await.unwrap(), Some(old_write));

            db.destroy().await.unwrap();
        });
    }

    /// A surviving child chain merkleizes across a prune whose floor passed the chain
    /// base without losing the nodes its graft needs.
    #[test]
    fn merkleize_across_prune_past_chain_base() {
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

            let config = fixed_db_config::<OneCap>("across-prune", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed committed keys.
            let key = |i: u8| Sha256::hash(&[&[i]]);
            let mut seed = db.new_batch();
            for i in 0..100u8 {
                seed = seed.write(key(i), Some(Sha256::fill(i)));
            }
            let seed = seed.merkleize(&db, None, &mut Proportional).await.unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();
            let base_floor = db.sync_boundary();

            // The parent rewrites every live key, so its floor raise moves past the
            // whole committed prefix.
            let mut parent = db.new_batch();
            for i in 0..100u8 {
                parent = parent.write(key(i), Some(Sha256::fill(i + 10)));
            }
            let parent = parent
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert!(
                parent.bounds().inactivity_floor > db.bounds().end,
                "parent floor must pass the chain base for this test to bite"
            );

            // Two identical children forked before the apply, writing enough fresh
            // keys that their merkleize merges deep over the committed prefix.
            let build = |parent: &Arc<MerkleizedBatch<_, _, _, _>>| {
                let mut child = parent.new_batch::<Sha256>();
                for i in 100..200u8 {
                    child = child.write(key(i), Some(Sha256::fill(i)));
                }
                child
            };
            let child = build(&parent);
            let expected = build(&parent)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap()
                .root();

            // Apply the parent and prune past the old chain base.
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();
            let floor = db.sync_boundary();
            assert!(floor > base_floor);
            let db = db.prune(floor).await.unwrap();
            assert!(*db.bounds().start > 0, "the prune must drop history");

            // The surviving child still merkleizes to the same root.
            let merkleized = child.merkleize(&db, None, &mut Proportional).await.unwrap();
            assert_eq!(merkleized.root(), expected);

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
                    let db = TestDb::init(context, config, None).await.unwrap();

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
                        .merkleize(&db, None, &mut Proportional)
                        .await
                        .unwrap();
                    let (db, _) = db.apply_batch(seed).await.unwrap();
                    let db = db.commit().await.unwrap();

                    // Read set with duplicate slots for k0 (0,4) and missing (2,5), plus del_read at 7.
                    let read_keys = [k0, read_only, missing, k1, k0, missing, k2, del_read];
                    let keys: Vec<_> = read_keys.iter().collect();
                    // (read_slot, Some=upsert | None=delete). Slot 7 deletes a committed-resolved read
                    // key that shares its collision bucket with a staged update, an upsert, and an
                    // upserted delete. Duplicate slots exercise last-write-wins by update order.
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
                    let explicit = explicit
                        .merkleize(&db, None, &mut Proportional)
                        .await
                        .unwrap();

                    let (staged_values, staged) = db.new_batch().stage(&keys, &db).await.unwrap();
                    let staged_merkleized = staged
                        .merkleize(
                            indexed_updates.clone(),
                            upserts.clone(),
                            None,
                            &db,
                            &mut Proportional,
                        )
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
                        .merkleize(
                            indexed_updates.clone(),
                            upserts.clone(),
                            None,
                            &db,
                            &mut Proportional,
                        )
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
            let db = TestDb::init(context, config, None).await.unwrap();

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
            let db = TestDb::init(context, config, None).await.unwrap();

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
            let db = TestDb::init(context, config, None).await.unwrap();

            let key = colliding_digest(0x95, 0);
            let old = colliding_digest(0x95, 1);
            let prior = colliding_digest(0x95, 2);
            let replacement = colliding_digest(0x95, 3);

            let seed = db
                .new_batch()
                .write(key, Some(old))
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let staged = staged_with::<mmr::Family, Sha256, TestUpdate, Sequential>(
                db.new_batch().write(key, Some(prior)),
                vec![key],
                vec![Some((StagedLoc::Committed(old_loc), ()))],
            );
            let staged = staged
                .merkleize(
                    vec![(0, Some(replacement))],
                    Vec::new(),
                    None,
                    &db,
                    &mut Proportional,
                )
                .await
                .unwrap();

            assert_eq!(explicit.root(), staged.root());

            db.destroy().await.unwrap();
        });
    }

    /// An ordered staged delete is recorded at its resolved location and also stays a batch
    /// delete, so merkleize gathers its translated-key bucket.
    #[test]
    fn ordered_staged_resolve_updates_records_deletes() {
        let runner = deterministic::Runner::default();
        runner.start(|context| async move {
            type TestUpdate = update::Ordered<sha256::Digest, FixedEncoding<sha256::Digest>>;

            let config = fixed_db_config::<OneCap>("ordered-staged-resolve-updates", &context);
            let db = AnyOrdered::init(context, config, None).await.unwrap();

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
                    (delete_key, committed(11), next_delete, None),
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
            let db = TestDb::init(context, config, None).await.unwrap();

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
                    &mut Proportional,
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
                        let db = TestDb::init(context, config, None).await.unwrap();

                        let mut seed = db.new_batch();
                        for i in 0..100u64 {
                            seed = seed.write(key(i), Some(val(i)));
                        }
                        let seed = seed.merkleize(&db, None, &mut Proportional).await.unwrap();
                        let (db, _) = db.apply_batch(seed).await.unwrap();
                        let mut db = db.commit().await.unwrap();

                        let mut grandparent = db.new_batch();
                        for i in 0..10u64 {
                            grandparent = grandparent.write(key(i), Some(val(i + 1_000)));
                        }
                        let grandparent = grandparent
                            .merkleize(&db, None, &mut Proportional)
                            .await
                            .unwrap();

                        let mut parent = grandparent.new_batch::<Sha256>();
                        for i in 50..60u64 {
                            parent = parent.write(key(i), Some(val(i + 2_000)));
                        }
                        let parent = parent
                            .merkleize(&db, None, &mut Proportional)
                            .await
                            .unwrap();

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
                                .merkleize(
                                    indexed_updates.clone(),
                                    Vec::new(),
                                    None,
                                    &db,
                                    &mut Proportional,
                                )
                                .await
                                .unwrap()
                        } else {
                            let mut child = parent.new_batch::<Sha256>();
                            (db, _) = db.apply_batch(grandparent).await.unwrap();
                            db = db.commit().await.unwrap();
                            for suffix in &suffixes {
                                child = child.write(key(*suffix), Some(val(suffix + 3_000)));
                            }
                            child.merkleize(&db, None, &mut Proportional).await.unwrap()
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
            let db = TestDb::init(context, config, None).await.unwrap();

            let key_db = colliding_digest(0x30, 0);
            let value_db = colliding_digest(0x30, 1);
            let key_db_second = colliding_digest(0x33, 0);
            let value_db_second = colliding_digest(0x33, 1);
            let key_parent = colliding_digest(0x31, 0);
            let value_parent = colliding_digest(0x31, 1);
            let key_current = colliding_digest(0x32, 0);
            let value_current = colliding_digest(0x32, 1);

            // Commit two keys to the DB so they're on disk.
            let seed = db
                .new_batch()
                .write(key_db, Some(value_db))
                .write(key_db_second, Some(value_db_second))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_loc = db.snapshot.get(&key_db).next().copied().unwrap();
            let committed_loc_second = db.snapshot.get(&key_db_second).next().copied().unwrap();

            // Create a parent batch with an in-memory ancestor key.
            let parent = db
                .new_batch()
                .write(key_parent, Some(value_parent))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let parent_loc = lookup_sorted(parent.diff.as_slice(), &key_parent)
                .unwrap()
                .loc()
                .unwrap();

            // Create a child batch with a current-ops key.
            let child = parent
                .new_batch::<Sha256>()
                .write(key_current, Some(value_current));
            let (_mutations, merkleizer) = child.into_parts();

            let current_loc = merkleizer.base_state.size;
            let batch_ops = vec![Operation::Update(update::Unordered(
                key_current,
                value_current,
            ))];

            // Interleave in-memory sources with a sorted or reversed committed subset.
            for reverse in [false, true] {
                let mut committed = [
                    (committed_loc, key_db, value_db),
                    (committed_loc_second, key_db_second, value_db_second),
                ];
                committed.sort_unstable_by_key(|&(loc, _, _)| loc);
                if reverse {
                    committed.reverse();
                }
                let [
                    (first_loc, first_key, first_value),
                    (second_loc, second_key, second_value),
                ] = committed;
                let ops = merkleizer
                    .read_ops(
                        &[current_loc, first_loc, parent_loc, second_loc],
                        &batch_ops,
                        &db.log,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    ops,
                    vec![
                        Operation::Update(update::Unordered(key_current, value_current)),
                        Operation::Update(update::Unordered(first_key, first_value)),
                        Operation::Update(update::Unordered(key_parent, value_parent)),
                        Operation::Update(update::Unordered(second_key, second_value)),
                    ]
                );
            }

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
            let db = TestDb::init(context, config, None).await.unwrap();
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
            let initial = initial
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // parent.diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let pending_root = pending_child.root();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None, &mut Proportional)
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
            let db = TestDb::init(context, config, None).await.unwrap();
            let key_a = colliding_digest(0xAA, 1);
            let key_b = colliding_digest(0xAA, 0);

            // Match the unordered counterexample shape on the ordered path so
            // both variants exercise the same collision pattern.
            let mut initial = db.new_batch();
            for i in 0..4 {
                initial = initial.write(colliding_digest(0xAA, i), Some(colliding_digest(0xBB, i)));
            }
            let initial = initial.merkleize(&db, None, &mut Proportional).await.unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Update only key_a so the colliding sibling key_b remains outside
            // parent.diff and must still be resolved through the committed
            // snapshot in the child.
            let parent = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xCC, 1)))
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let pending_root = pending_child.root();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(key_a, Some(colliding_digest(0xDD, 1)))
                .write(key_b, Some(colliding_digest(0xDD, 0)))
                .merkleize(&db, None, &mut Proportional)
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
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed an initial key.
            let seed = db
                .new_batch()
                .write(colliding_digest(0x01, 0), Some(colliding_digest(0x01, 1)))
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Build batch B as child of A.
            let key_b = colliding_digest(0x03, 0);
            let val_b = colliding_digest(0x03, 1);
            let batch_b = batch_a
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(batch_a).await.unwrap();
            let db = db.commit().await.unwrap();

            // Build the same logical B from committed DB for comparison.
            let committed_b = db
                .new_batch()
                .write(key_b, Some(val_b))
                .merkleize(&db, None, &mut Proportional)
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
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed an initial key so we have an existing entry.
            let key = colliding_digest(0x10, 0);
            let seed = db
                .new_batch()
                .write(key, Some(colliding_digest(0x10, 1)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

            // Build batch A that updates the key.
            let val_a = colliding_digest(0x10, 2);
            let batch_a = db
                .new_batch()
                .write(key, Some(val_a))
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
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
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed.
            let seed = db
                .new_batch()
                .write(colliding_digest(0x20, 0), Some(colliding_digest(0x20, 1)))
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Fork: B and C both derive from A.
            let key_b = colliding_digest(0x22, 0);
            let val_b = colliding_digest(0x22, 1);
            let batch_b = batch_a
                .new_batch::<Sha256>()
                .write(key_b, Some(val_b))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let key_c = colliding_digest(0x23, 0);
            let val_c = colliding_digest(0x23, 1);
            let batch_c = batch_a
                .new_batch::<Sha256>()
                .write(key_c, Some(val_c))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(batch_a).await.unwrap();
            let db = db.commit().await.unwrap();

            // Verify both produce correct roots.
            let committed_b = db
                .new_batch()
                .write(key_b, Some(val_b))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(batch_b.root(), committed_b.root());

            let committed_c = db
                .new_batch()
                .write(key_c, Some(val_c))
                .merkleize(&db, None, &mut Proportional)
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
            let db = TestDb::init(context, config, None).await.unwrap();

            // Grandparent: 2 keys.
            let grandparent = db
                .new_batch()
                .write(colliding_digest(0x01, 0), Some(colliding_digest(0x01, 1)))
                .write(colliding_digest(0x02, 0), Some(colliding_digest(0x02, 1)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Parent: 1 key.
            let parent = grandparent
                .new_batch::<Sha256>()
                .write(colliding_digest(0x03, 0), Some(colliding_digest(0x03, 1)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child: 1 key.
            let child = parent
                .new_batch::<Sha256>()
                .write(colliding_digest(0x04, 0), Some(colliding_digest(0x04, 1)))
                .merkleize(&db, None, &mut Proportional)
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
            let db = TestDb::init(context, config, None).await.unwrap();

            // Two colliding keys: K0 (suffix 0) and K6 (suffix 6).
            let k0 = colliding_digest(0xAA, 0);
            let k6 = colliding_digest(0xAA, 6);

            // Seed both keys so the snapshot bucket contains two entries.
            let initial = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xBB, 0)))
                .write(k6, Some(colliding_digest(0xBB, 6)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete K0. K6 remains untouched.
            let parent = db
                .new_batch()
                .write(k0, None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child (pending parent): re-create K0 and write a new colliding key K29.
            let k29 = colliding_digest(0xAA, 29);
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(k0, Some(colliding_digest(0xCC, 0)))
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Commit the parent, then rebuild the same child.
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xCC, 0)))
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None, &mut Proportional)
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

    /// Ordered mirror of [`recreate_deleted_key_with_collision_sibling_root_matches`]:
    /// re-creating a key deleted by a pending parent must match the applied-parent
    /// path even though a colliding sibling's bucket scan exposes the deleted key's
    /// stale committed location to the classifier.
    #[test]
    fn ordered_recreate_deleted_key_with_collision_sibling_root_matches() {
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

            let config = fixed_db_config::<OneCap>("ordered-recreate-deleted-collision", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let k0 = colliding_digest(0xAA, 0);
            let k6 = colliding_digest(0xAA, 6);
            let k29 = colliding_digest(0xAA, 29);

            // Seed both keys so the snapshot bucket contains two entries.
            let initial = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xBB, 0)))
                .write(k6, Some(colliding_digest(0xBB, 6)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete k0. k6 remains untouched.
            let parent = db
                .new_batch()
                .write(k0, None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child (pending parent): re-create k0 and write a new colliding key k29.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(k0, Some(colliding_digest(0xCC, 0)))
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Commit the parent, then rebuild the same child.
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xCC, 0)))
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            assert_eq!(pending_child.root(), committed_child.root());
            assert_eq!(
                pending_child.total_active_keys,
                committed_child.total_active_keys
            );

            // Apply the pending child; the resulting DB must match a child built
            // directly from the committed DB.
            let (db, _) = db.apply_batch(pending_child).await.unwrap();
            assert_eq!(db.root(), committed_child.root());

            db.destroy().await.unwrap();
        });
    }

    /// Deleting a key already deleted by a pending parent must be a no-op: same root
    /// as the applied-parent path and no double decrement of the active-key count,
    /// even though the sibling update's bucket scan exposes the key's stale committed
    /// location.
    #[test]
    fn ordered_redundant_delete_with_collision_sibling_root_matches() {
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

            let config = fixed_db_config::<OneCap>("ordered-redundant-delete-collision", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let k0 = colliding_digest(0xAA, 0);
            let k6 = colliding_digest(0xAA, 6);

            let initial = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xBB, 0)))
                .write(k6, Some(colliding_digest(0xBB, 6)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete k0.
            let parent = db
                .new_batch()
                .write(k0, None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child (pending parent): delete k0 again and update the colliding sibling k6.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(k0, None)
                .write(k6, Some(colliding_digest(0xCC, 6)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(k0, None)
                .write(k6, Some(colliding_digest(0xCC, 6)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            assert_eq!(pending_child.root(), committed_child.root());
            assert_eq!(pending_child.total_active_keys, 1);
            assert_eq!(committed_child.total_active_keys, 1);

            db.destroy().await.unwrap();
        });
    }

    /// Reduced from a fuzzer counterexample: a parent deletes keys whose buckets the child
    /// later touches, and building the child on the pending parent must produce the same
    /// root as building it on the committed parent. The final key-value state is identical
    /// either way; a divergence means the emitted operation streams (next-key pointers or
    /// floor moves) depended on whether the parent was pending.
    #[test]
    fn ordered_stale_ancestor_candidates_root_matches() {
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

            let config = fixed_db_config::<OneCap>("ordered-stale-candidates", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let v = |n| colliding_digest(0xB0, n);
            let initial = db
                .new_batch()
                .write(colliding_digest(2, 23), Some(v(0)))
                .write(colliding_digest(3, 31), Some(v(1)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete the bucket-3 key and create in bucket 1.
            let parent = db
                .new_batch()
                .write(colliding_digest(3, 31), None)
                .write(colliding_digest(1, 9), Some(v(2)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child: re-create the parent-deleted key and create in buckets 1 and 0.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(colliding_digest(3, 31), Some(v(3)))
                .write(colliding_digest(1, 20), Some(v(4)))
                .write(colliding_digest(0, 0), Some(v(5)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(colliding_digest(3, 31), Some(v(3)))
                .write(colliding_digest(1, 20), Some(v(4)))
                .write(colliding_digest(0, 0), Some(v(5)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            assert_eq!(
                pending_child.root(),
                committed_child.root(),
                "child root depended on pending-vs-committed parent path"
            );
            assert_eq!(
                pending_child.total_active_keys,
                committed_child.total_active_keys
            );

            let (db, _) = db.apply_batch(pending_child).await.unwrap();
            assert_eq!(
                db.root(),
                committed_child.root(),
                "applied pending child root diverged"
            );

            db.destroy().await.unwrap();
        });
    }

    /// Pins the stale-ancestor guard's position above the classifier's candidate pushes.
    ///
    /// The classifier resolves each mutated key's prior state by scanning its translated
    /// bucket in the committed snapshot, and the same loop pushes each entry it examines
    /// into the next/prev candidate sets that stitch the ordered links. In this scenario the
    /// child updates a sibling that collides with a parent-deleted key, so the scan pulls
    /// the deleted key's stale committed location into the loop. Excluding that operation
    /// before candidate insertion keeps predecessor selection and operation order identical
    /// between the pending and committed parent paths.
    #[test]
    fn ordered_stale_classifier_candidates_root_matches() {
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

            let config = fixed_db_config::<OneCap>("ordered-stale-classifier", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let v = |n| colliding_digest(0xB0, n);
            let initial = db
                .new_batch()
                .write(colliding_digest(1, 9), Some(v(0)))
                .write(colliding_digest(3, 10), Some(v(1)))
                .write(colliding_digest(3, 20), Some(v(2)))
                .write(colliding_digest(3, 31), Some(v(3)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete the last key of bucket 3.
            let parent = db
                .new_batch()
                .write(colliding_digest(3, 31), None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child: update a colliding sibling (pulling the deleted key's stale committed
            // location into the classifier's read set), re-create the deleted key, and
            // create keys whose predecessor searches consult the candidate sets.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(colliding_digest(3, 10), Some(v(4)))
                .write(colliding_digest(3, 31), Some(v(5)))
                .write(colliding_digest(1, 20), Some(v(6)))
                .write(colliding_digest(0, 0), Some(v(7)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(colliding_digest(3, 10), Some(v(4)))
                .write(colliding_digest(3, 31), Some(v(5)))
                .write(colliding_digest(1, 20), Some(v(6)))
                .write(colliding_digest(0, 0), Some(v(7)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            assert_eq!(
                pending_child.root(),
                committed_child.root(),
                "child root depended on pending-vs-committed parent path"
            );
            assert_eq!(
                pending_child.total_active_keys,
                committed_child.total_active_keys
            );

            let (db, _) = db.apply_batch(pending_child).await.unwrap();
            assert_eq!(
                db.root(),
                committed_child.root(),
                "applied pending child root diverged"
            );

            db.destroy().await.unwrap();
        });
    }

    /// While the parent's delete is pending, the deleted key's op remains in the
    /// pre-parent snapshot, so a child write to the same bucket reads it during the
    /// bucket scan. That stale op must contribute no candidates: they reorder the
    /// predecessor rewrites, so the root differs from the applied-parent path.
    #[test]
    fn ordered_stale_sibling_scan_candidates_root_matches() {
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
            let config = fixed_db_config::<OneCap>("ordered-stale-sibling-scan", &context);
            let db = TestDb::init(context, config, None).await.unwrap();
            let v = |n| colliding_digest(0xB0, n);
            let initial = db
                .new_batch()
                .write(colliding_digest(3, 1), Some(v(1)))
                .write(colliding_digest(3, 23), Some(v(2)))
                .write(colliding_digest(3, 31), Some(v(4)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete the bucket's largest key.
            let parent = db
                .new_batch()
                .write(colliding_digest(3, 31), None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child: write a colliding sibling (its bucket scan reads the deleted
            // key's stale committed op), re-create the deleted key, and create a
            // new smallest key so the wraparound predecessor search consults the
            // candidate set.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(colliding_digest(3, 7), Some(v(5)))
                .write(colliding_digest(3, 31), Some(v(6)))
                .write(colliding_digest(0, 0), Some(v(7)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(colliding_digest(3, 7), Some(v(5)))
                .write(colliding_digest(3, 31), Some(v(6)))
                .write(colliding_digest(0, 0), Some(v(7)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            assert_eq!(
                pending_child.root(),
                committed_child.root(),
                "child root depended on pending-vs-committed parent path"
            );
            let (db, _) = db.apply_batch(pending_child).await.unwrap();
            assert_eq!(db.root(), committed_child.root());

            db.destroy().await.unwrap();
        });
    }

    /// Redundant deletes of two parent-deleted keys must not drive the active-key
    /// count negative while a colliding create pulls their stale committed locations
    /// into the classifier's read set.
    #[test]
    fn ordered_redundant_delete_underflow_regression() {
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

            let config = fixed_db_config::<OneCap>("ordered-redundant-delete-underflow", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let k0 = colliding_digest(0xAA, 0);
            let k6 = colliding_digest(0xAA, 6);
            let k29 = colliding_digest(0xAA, 29);

            let initial = db
                .new_batch()
                .write(k0, Some(colliding_digest(0xBB, 0)))
                .write(k6, Some(colliding_digest(0xBB, 6)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete both keys.
            let parent = db
                .new_batch()
                .write(k0, None)
                .write(k6, None)
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child (pending parent): delete both again and create the colliding k29,
            // whose bucket scan reintroduces both stale committed locations.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(k0, None)
                .write(k6, None)
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(k0, None)
                .write(k6, None)
                .write(k29, Some(colliding_digest(0xCC, 29)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            assert_eq!(pending_child.root(), committed_child.root());
            assert_eq!(pending_child.total_active_keys, 1);
            assert_eq!(committed_child.total_active_keys, 1);

            db.destroy().await.unwrap();
        });
    }

    /// An update-only child skips ancestor neighbor discovery, so the successors it emits
    /// must come from the resolved operations alone even when the pending parent changed
    /// membership around the updated keys.
    #[test]
    fn ordered_update_only_child_on_membership_changing_parent_root_matches() {
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

            let config = fixed_db_config::<OneCap>("ordered-update-only-child", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            let v = |n| colliding_digest(0xB0, n);
            let initial = db
                .new_batch()
                .write(colliding_digest(1, 9), Some(v(0)))
                .write(colliding_digest(3, 10), Some(v(1)))
                .write(colliding_digest(3, 20), Some(v(2)))
                .write(colliding_digest(3, 31), Some(v(3)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(initial).await.unwrap();
            let db = db.commit().await.unwrap();

            // Parent: delete the middle bucket-3 key and create a new smallest key, rewriting
            // the successors of both remaining bucket-3 keys.
            let parent = db
                .new_batch()
                .write(colliding_digest(3, 20), None)
                .write(colliding_digest(0, 0), Some(v(4)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child: overwrite only existing keys. Its bucket scan encounters the deleted
            // key's stale committed op alongside keys created or rewritten by the parent.
            let pending_child = parent
                .new_batch::<Sha256>()
                .write(colliding_digest(0, 0), Some(v(5)))
                .write(colliding_digest(1, 9), Some(v(6)))
                .write(colliding_digest(3, 10), Some(v(7)))
                .write(colliding_digest(3, 31), Some(v(8)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let db = db.commit().await.unwrap();

            let committed_child = db
                .new_batch()
                .write(colliding_digest(0, 0), Some(v(5)))
                .write(colliding_digest(1, 9), Some(v(6)))
                .write(colliding_digest(3, 10), Some(v(7)))
                .write(colliding_digest(3, 31), Some(v(8)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            assert_eq!(
                pending_child.root(),
                committed_child.root(),
                "child root depended on pending-vs-committed parent path"
            );
            assert_eq!(
                pending_child.total_active_keys,
                committed_child.total_active_keys
            );

            let (db, _) = db.apply_batch(pending_child).await.unwrap();
            assert_eq!(
                db.root(),
                committed_child.root(),
                "applied pending child root diverged"
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
            let db = TestDb::init(context, config, None).await.unwrap();

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
                .merkleize(&db, None, &mut Proportional)
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
                .merkleize(&db, None, &mut Proportional)
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

    /// Define `$name` to run the staged ordered eviction differential on a `$db` opened with
    /// `$config`.
    macro_rules! staged_policy_matches_writes {
        ($name:ident, $db:ty, $($config:ident)::+) => {
            /// Staged writes under a policy that evicts and replaces updates in their keys'
            /// collision and predecessor buckets, and decides the batch's own writes, serve the
            /// same state as explicit writes of the decisions, from the database and from a child
            /// of a pending parent. Replacing an update keeps the key that shares its
            /// translated-key bucket available as a deleted key's predecessor.
            #[test]
            fn $name() {
                deterministic::Runner::default().start(|context| async move {
                    let value = |i| colliding_digest(0xA0, i);
                    let keys = [
                        (0x10, 0),
                        (0x10, 1),
                        (0x20, 0),
                        (0x20, 1),
                        (0x30, 0),
                        (0x30, 1),
                        (0x40, 0),
                        (0x50, 0),
                    ]
                    .map(|(prefix, suffix)| colliding_digest(prefix, suffix));
                    let [a0, a1, b0, b1, c0, c1, d, z] = keys;
                    let new = colliding_digest(0x21, 0);
                    let choose = |key: &sha256::Digest| {
                        if [a1, b1, z].contains(key) {
                            Choice::Evict
                        } else if *key == b0 {
                            Choice::Replace(value(102))
                        } else {
                            Choice::Keep
                        }
                    };
                    for pending in [false, true] {
                        let (label, partition) = if pending {
                            ("pending", "staged-policy-pending")
                        } else {
                            ("applied", "staged-policy")
                        };
                        let ctx = context.child(label);
                        let config = $($config)::+::<OneCap>(partition, &ctx);
                        let db = <$db>::init(ctx, config, None).await.unwrap();

                        // Seed every key with a held floor.
                        let seed = keys
                            .iter()
                            .zip(0..)
                            .fold(db.new_batch(), |batch, (key, i)| {
                                batch.write(*key, Some(value(i)))
                            })
                            .merkleize(&db, None, &mut Hold)
                            .await
                            .unwrap();
                        let (db, _) = db.apply_batch(seed).await.unwrap();

                        // A pending parent, if any, updates a1, b0, and z with a held floor, so
                        // their decisions resolve in its diff.
                        let parent = if pending {
                            let parent = db
                                .new_batch()
                                .write(a1, Some(value(201)))
                                .write(b0, Some(value(202)))
                                .write(z, Some(value(207)))
                                .merkleize(&db, None, &mut Hold)
                                .await
                                .unwrap();
                            Some(parent)
                        } else {
                            None
                        };
                        let start = || {
                            parent
                                .as_ref()
                                .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>())
                        };

                        // Stage an update of a0, which collides with the evicted a1, and a delete
                        // of c0, whose predecessor bucket holds the replaced b0 and the evicted b1.
                        // Upsert a key that sorts between that bucket and c0, so its predecessor
                        // lies there too. The policy decides the newest update of every live key,
                        // including the batch's update of a0, its create of the new key, and its
                        // rewrite of b1 as the new key's predecessor.
                        let (_, staged) = start().stage(&[&a0, &c0], &db).await.unwrap();
                        let mut policy = Script::new(usize::MAX, u64::MAX, choose);
                        let decided = staged
                            .merkleize(
                                vec![(0, Some(value(100))), (1, None)],
                                vec![(new, Some(value(101)))],
                                None,
                                &db,
                                &mut policy,
                            )
                            .await
                            .unwrap();
                        let mut visited: Vec<_> = policy
                            .visited
                            .iter()
                            .map(|(_, key, value)| (*key, *value))
                            .collect();
                        visited.sort();
                        let newest = |seed, parent| value(if pending { parent } else { seed });
                        assert_eq!(
                            visited,
                            [
                                (a0, value(100)),
                                (a1, newest(1, 201)),
                                (b0, newest(2, 202)),
                                (b1, value(3)),
                                (new, value(101)),
                                (c1, value(5)),
                                (d, value(6)),
                                (z, newest(7, 207)),
                            ]
                        );

                        // A twin writes the same keys and the decisions and keeps every update. It
                        // serves the same value for every key.
                        let written = [
                            (a0, Some(value(100))),
                            (c0, None),
                            (new, Some(value(101))),
                            (a1, None),
                            (b1, None),
                            (z, None),
                            (b0, Some(value(102))),
                        ]
                        .into_iter()
                        .fold(start(), |batch, (key, value)| batch.write(key, value))
                        .merkleize(
                            &db,
                            None,
                            &mut Bounded {
                                entries: usize::MAX,
                                skips: u64::MAX,
                            },
                        )
                        .await
                        .unwrap();
                        for key in keys.iter().chain([&new]) {
                            assert_eq!(
                                db.read(&decided, key).await,
                                db.read(&written, key).await,
                                "{key} diverged from the twin"
                            );
                        }
                        drop(written);

                        // Apply the chain. The live keys link in key order, and the evicted and
                        // deleted keys are absent.
                        let db = match parent {
                            Some(parent) => db.apply_batch(parent).await.unwrap().0,
                            None => db,
                        };
                        let (db, _) = db.apply_batch(decided).await.unwrap();
                        let live = BTreeMap::from([
                            (a0, value(100)),
                            (b0, value(102)),
                            (new, value(101)),
                            (c1, value(5)),
                            (d, value(6)),
                        ]);
                        assert_links(&db, &live, &[a1, b1, c0, z]).await;

                        // Recreate b1 with a held floor. A batch that deletes the new key under a
                        // policy that replaces b0 rewrites b1, which shares b0's translated-key
                        // bucket, as the new key's predecessor.
                        let recreate = db
                            .new_batch()
                            .write(b1, Some(value(3)))
                            .merkleize(&db, None, &mut Hold)
                            .await
                            .unwrap();
                        let (db, _) = db.apply_batch(recreate).await.unwrap();
                        let choose = |key: &sha256::Digest| {
                            if *key == b0 {
                                Choice::Replace(value(103))
                            } else {
                                Choice::Keep
                            }
                        };
                        let mut policy = Script::new(usize::MAX, u64::MAX, choose);
                        let decided = db
                            .new_batch()
                            .write(new, None)
                            .merkleize(&db, None, &mut policy)
                            .await
                            .unwrap();
                        let written = db
                            .new_batch()
                            .write(new, None)
                            .write(b0, Some(value(103)))
                            .merkleize(
                                &db,
                                None,
                                &mut Bounded {
                                    entries: usize::MAX,
                                    skips: u64::MAX,
                                },
                            )
                            .await
                            .unwrap();
                        for key in keys.iter().chain([&new]) {
                            assert_eq!(
                                db.read(&decided, key).await,
                                db.read(&written, key).await,
                                "{key} diverged from the twin"
                            );
                        }
                        drop(written);
                        let (db, _) = db.apply_batch(decided).await.unwrap();
                        let live = BTreeMap::from([
                            (a0, value(100)),
                            (b0, value(103)),
                            (b1, value(3)),
                            (c1, value(5)),
                            (d, value(6)),
                        ]);
                        assert_links(&db, &live, &[a1, c0, new, z]).await;
                        db.destroy().await.unwrap();
                    }
                });
            }
        };
    }

    staged_policy_matches_writes!(
        policy_staged_evictions_match_writes_any_ordered,
        OrderedFixedDb<
            mmr::Family,
            deterministic::Context,
            sha256::Digest,
            sha256::Digest,
            Sha256,
            OneCap,
            Sequential,
        >,
        fixed_db_config
    );
    staged_policy_matches_writes!(
        policy_staged_evictions_match_writes_current_ordered,
        current::ordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            sha256::Digest,
            sha256::Digest,
            Sha256,
            OneCap,
            32,
            Sequential,
        >,
        current::tests::fixed_config
    );

    /// A policy that keeps every entry walks the direct path, and for every pair of limits, with
    /// and without writes, its batch matches the batch of a scripted policy that keeps each entry
    /// it decides.
    async fn compact_matches_scripted_keep<D>(db: D)
    where
        D: DbAny<mmr::Family, Key = sha256::Digest, Value = sha256::Digest>
            + crate::qmdb::any::test::Inspect<mmr::Family>,
        Operation<mmr::Family, <D as crate::qmdb::any::test::Inspect<mmr::Family>>::Update>:
            commonware_codec::Codec,
    {
        let keys = distinct(6);
        let seed = keys
            .iter()
            .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(seed).await.unwrap();
        let value = Some(sha256::Digest::from([0xEE; 32]));
        let writes: [&[(usize, Option<sha256::Digest>)]; 3] =
            [&[], &[(1, value)], &[(2, None), (4, value)]];
        for entries in [0, 1, 3, usize::MAX] {
            for skips in [0, 2, u64::MAX] {
                for writes in writes {
                    let batch = || {
                        writes.iter().fold(db.new_batch(), |batch, &(i, value)| {
                            batch.write(keys[i], value)
                        })
                    };
                    let compact = batch()
                        .merkleize(&db, None, &mut Bounded { entries, skips })
                        .await
                        .unwrap();
                    let mut keep = Script::new(entries, skips, crate::qmdb::any::test::keep);
                    let scripted = batch().merkleize(&db, None, &mut keep).await.unwrap();
                    assert_same(&db, &compact, &scripted);
                }
            }
        }
        db.destroy().await.unwrap();
    }

    /// [`compact_matches_scripted_keep`] on an unordered Any database.
    #[test]
    fn compact_matches_scripted_keep_unordered() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("compact-keep", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();
            compact_matches_scripted_keep(db).await;
        });
    }

    /// [`compact_matches_scripted_keep`] on an ordered Any database.
    #[test]
    fn compact_matches_scripted_keep_ordered() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("compact-keep", &context);
            let db = AnyOrdered::init(context.child("db"), config, None)
                .await
                .unwrap();
            compact_matches_scripted_keep(db).await;
        });
    }

    /// Keeps every update it decides under limits that shrink with the operations the batch made
    /// inactive, so the limits the prefetch reads under differ from the limits the walk runs
    /// under.
    struct Shrinking {
        from: usize,
        visited: Vec<u64>,
    }

    impl Policy<mmr::Family, sha256::Digest, sha256::Digest> for Shrinking {
        fn evicts(&self) -> bool {
            false
        }

        fn limits(&self, made_inactive: usize) -> Limits {
            Limits {
                entries: self.from.saturating_sub(made_inactive),
                skips: u64::MAX,
            }
        }

        fn decide<'a>(
            &mut self,
            entry: Entry<'a, mmr::Family, sha256::Digest, sha256::Digest>,
        ) -> Decision<'a, sha256::Digest> {
            self.visited.push(*entry.location());
            entry.keep()
        }
    }

    /// A staged walk under limits that depend on the exact count decides what the direct walk
    /// decides, including when the exact limits allow nothing after a nonempty prefetch. The
    /// child upserts a key live only in its pending parent, which the prefetch's estimate leaves
    /// out and the exact count includes.
    #[rstest::rstest]
    // The prefetch reads under two entries; the walk gets one and moves the update at 1.
    #[case::one_entry(2, vec![1], 2)]
    // The prefetch reads under one entry; the walk gets none and leaves the floor inherited.
    #[case::no_entry(1, vec![], 0)]
    fn argument_dependent_limits_match_direct(
        #[case] from: usize,
        #[case] visited: Vec<u64>,
        #[case] floor: u64,
    ) {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("shrinking", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();
            let keys = distinct(4);
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let created = sha256::Digest::from([0xCC; 32]);
            let parent = db
                .new_batch()
                .write(created, Some(created))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();

            let value = Some(sha256::Digest::from([0xEE; 32]));
            let mut policy = Shrinking {
                from,
                visited: Vec::new(),
            };
            let (_, batch) = parent.new_batch::<Sha256>().stage(&[], &db).await.unwrap();
            let staged = batch
                .merkleize(Vec::new(), vec![(created, value)], None, &db, &mut policy)
                .await
                .unwrap();
            let mut twin = Shrinking {
                from,
                visited: Vec::new(),
            };
            let direct = parent
                .new_batch::<Sha256>()
                .write(created, value)
                .merkleize(&db, None, &mut twin)
                .await
                .unwrap();
            assert_eq!(policy.visited, visited);
            assert_eq!(twin.visited, visited);
            assert_eq!(staged.bounds().inactivity_floor, loc(floor));
            assert_eq!(staged.root(), direct.root());
            drop((staged, direct, parent));
            db.destroy().await.unwrap();
        });
    }

    fn balance(n: u64) -> sha256::Digest {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&n.to_be_bytes());
        sha256::Digest::from(bytes)
    }

    fn held(value: &sha256::Digest) -> u64 {
        u64::from_be_bytes(value.as_ref()[..8].try_into().unwrap())
    }

    /// Charges `rent` to each active update it walks, which holds a key the database keeps around
    /// without a recent write. A balance that covers the rent is replaced by the remainder. One
    /// that does not is evicted, or zeroed by a policy that only debits.
    struct Rent {
        rent: u64,
        entries: usize,
        evicts: bool,
        /// Each charged key with the balance it held.
        charged: Vec<(sha256::Digest, u64)>,
    }

    impl Policy<mmr::Family, sha256::Digest, sha256::Digest> for Rent {
        fn evicts(&self) -> bool {
            self.evicts
        }

        fn limits(&self, _: usize) -> Limits {
            Limits {
                entries: self.entries,
                skips: u64::MAX,
            }
        }

        fn decide<'a>(
            &mut self,
            entry: Entry<'a, mmr::Family, sha256::Digest, sha256::Digest>,
        ) -> Decision<'a, sha256::Digest> {
            let balance_held = held(entry.value());
            self.charged.push((*entry.key(), balance_held));
            match balance_held.checked_sub(self.rent) {
                Some(left) => entry.replace(balance(left)),
                None if self.evicts => entry.evict().0,
                None => entry.replace(balance(0)),
            }
        }
    }

    /// A rent policy charges the keys the database keeps around without recent writes: each
    /// batch walks the oldest live updates first, so its entries land on the keys written longest
    /// ago, and a charged key moves to the tip behind the untouched ones. Evicting the broke keys
    /// takes the deferred path; zeroing them takes the direct one.
    async fn rent_charges_untouched_keys<D>(db: D, evicts: bool)
    where
        D: DbAny<mmr::Family, Key = sha256::Digest, Value = sha256::Digest>,
    {
        let keys = distinct(5);
        let seed = keys
            .iter()
            .zip([12, 3, 7, 0, 20])
            .fold(db.new_batch(), |batch, (key, balance_held)| {
                batch.write(*key, Some(balance(balance_held)))
            })
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(seed).await.unwrap();
        let broke = if evicts { None } else { Some(balance(0)) };

        // The first batch charges the three oldest keys.
        let mut rent = Rent {
            rent: 5,
            entries: 3,
            evicts,
            charged: Vec::new(),
        };
        let batch = db
            .new_batch()
            .merkleize(&db, None, &mut rent)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        assert_eq!(rent.charged, [(keys[0], 12), (keys[1], 3), (keys[2], 7)]);
        for (key, expected) in keys.iter().zip([
            Some(balance(7)),
            broke,
            Some(balance(2)),
            Some(balance(0)),
            Some(balance(20)),
        ]) {
            assert_eq!(db.get(key).await.unwrap(), expected, "after one charge");
        }

        // The second batch reaches the two keys it has not charged before the charged ones,
        // which the first walk moved to the tip.
        let mut rent = Rent {
            rent: 5,
            entries: 3,
            evicts,
            charged: Vec::new(),
        };
        let batch = db
            .new_batch()
            .merkleize(&db, None, &mut rent)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(batch).await.unwrap();
        assert_eq!(rent.charged, [(keys[3], 0), (keys[4], 20), (keys[0], 7)]);
        for (key, expected) in keys.iter().zip([
            Some(balance(2)),
            broke,
            Some(balance(2)),
            broke,
            Some(balance(15)),
        ]) {
            assert_eq!(db.get(key).await.unwrap(), expected, "after two charges");
        }
        db.destroy().await.unwrap();
    }

    /// [`rent_charges_untouched_keys`] on an unordered Any database.
    #[rstest::rstest]
    #[case::evicting(true)]
    #[case::debiting(false)]
    fn rent_charges_untouched_keys_unordered(#[case] evicts: bool) {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("rent", &context);
            let db = AnyUnordered::init(context.child("db"), config, None)
                .await
                .unwrap();
            rent_charges_untouched_keys(db, evicts).await;
        });
    }

    /// [`rent_charges_untouched_keys`] on an ordered Any database, whose evictions relink neighbors.
    #[rstest::rstest]
    #[case::evicting(true)]
    #[case::debiting(false)]
    fn rent_charges_untouched_keys_ordered(#[case] evicts: bool) {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_db_config::<OneCap>("rent", &context);
            let db = AnyOrdered::init(context.child("db"), config, None)
                .await
                .unwrap();
            rent_charges_untouched_keys(db, evicts).await;
        });
    }
}
