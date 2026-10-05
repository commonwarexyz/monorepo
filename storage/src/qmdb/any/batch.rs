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
            ordered::{find_next_key, find_next_key_ascending, find_prev_key_mut},
        },
        bitmap::{Candidates, Shared},
        chain::{self, Bounds, Commitment},
        delete_known_loc,
        floor::{Action, Entry, Limits, Policy},
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
    collections::{BTreeMap, VecDeque, hash_map},
    iter, mem,
    sync::{Arc, Weak},
};
use tracing::debug;

type DiffVec<K, F, V> = Vec<(K, DiffEntry<F, V>)>;
type DiffSlice<K, F, V> = [(K, DiffEntry<F, V>)];

/// Sorted locations at the retained batch chain's committed boundary.
type AncestorBaseLocs<K, F> = Vec<(K, Option<Location<F>>)>;

/// A round of committed floor candidates a staged merkleize selected and read while it resolved
/// its updates, and the location its selection stopped at.
type Prefetched<F, U> = (Round<F, U>, Location<F>);

/// Sorted `(key, (value, loc))` vec consulted by `find_prev_key_mut` during ordered merkleization.
/// Values are `None` for staged-resolved keys (skipped as updates) and for predecessors whose
/// values have already been consumed by a rewrite. Candidate keys remain unchanged.
type PrevCandidates<K, F, V> = Vec<(K, (Option<V>, Location<F>))>;

/// Where a staged read or a policy decision resolved its key's live operation: in the
/// committed DB, or in an uncommitted ancestor's diff. Either way, the resolved
/// location orders the staged write among this batch's emitted operations. The variants
/// differ in which committed location the write supersedes: `Committed` supersedes the
/// resolved location itself, while `Ancestor` supersedes the committed location it recorded
/// when it was resolved. The recorded base stays valid while the resolving ancestor is alive
/// at merkleize, because the ancestor's diff travels with this batch and `apply_batch`
/// re-resolves the base if the ancestor commits first. If the ancestor instead commits and
/// is freed before merkleize, its apply has made `loc` the key's committed location, so
/// merkleize supersedes `loc` whenever it lies below the merkleize-time committed boundary.
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

/// Returns whether sorted, deduplicated `items` contains `target`, advancing `cursor` past
/// entries below it. Successive calls must use non-decreasing `target`s.
fn sorted_contains<T: Ord>(items: &[T], cursor: &mut usize, target: &T) -> bool {
    while items.get(*cursor).is_some_and(|item| item < target) {
        *cursor += 1;
    }
    items.get(*cursor) == Some(target)
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

/// Removes from ascending `locations` those holding one of the ascending `retained` updates,
/// passing each removed location and its update to `feed`.
fn take_retained<'a, F: Family, U>(
    locations: &mut Vec<Location<F>>,
    retained: &'a [(Location<F>, U)],
    mut feed: impl FnMut(Location<F>, &'a U),
) {
    let mut at = 0;
    locations.retain(|loc| {
        while retained.get(at).is_some_and(|(next, _)| next < loc) {
            at += 1;
        }
        match retained.get(at) {
            Some((next, update)) if next == loc => {
                feed(*loc, update);
                false
            }
            _ => true,
        }
    });
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

/// The floor a policy pass reached and the updates it kept or stopped at.
struct Frozen<F: Family, U: update::Update> {
    floor: Location<F>,
    /// The kept updates below the floor, then the update the pass stopped at, if any, in
    /// ascending location order. Each was active when the policy decided it. Merkleize moves the
    /// kept ones and reuses all of them instead of reading their locations again.
    retained: Vec<(Location<F>, U)>,
}

/// Pending mutations whose old locations were already resolved by staged reads or policy decisions.
/// Entries are sorted by location. Each value is `Some` for an update and `None` for a delete. When
/// a collision sibling can hold a deleted key's predecessor link (see [`update::Parts::SIBLINGS`]),
/// the deleted key is also a batch delete so that merkleize gathers its translated-key bucket. The
/// entry's location and cached payload still spare merkleize a read of the deleted update.
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

/// A policy pass's position, limits, and read-ahead.
struct Cursor<F: Family, U: update::Update> {
    /// Every location below the floor is inactive or decided.
    floor: Location<F>,
    /// The scan position. Every location in `[floor, scan)` is inactive or buffered.
    scan: Location<F>,
    /// The read window's end. No location at or past it is read.
    end: Location<F>,
    /// Entries left to decide.
    entries: usize,
    /// Inactive locations left to pass.
    skips: u64,
    /// Active updates read ahead in ascending location order.
    buffer: VecDeque<(StagedLoc<F>, U)>,
}

/// One round of floor candidates selected by [`Merkleizer::read_round`].
struct Round<F: Family, U: update::Update> {
    /// The selected candidates outside the inactive set, in ascending order.
    candidates: Vec<Location<F>>,
    /// The operations at the committed `candidates`, which precede the uncommitted ones. The
    /// chunks' concatenation follows candidate order.
    committed: Vec<Vec<Operation<F, U>>>,
    /// The last candidate the round passed, inside the inactive set or not.
    passed: Option<Location<F>>,
    /// The first candidate the skip budget cannot reach, if the round stopped there.
    cut: Option<Location<F>>,
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
/// with [`crate::qmdb::Error::StaleBatch`] (see [`crate::qmdb::chain`] for more details).
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, U: update::Update, S: Strategy> {
    /// Merkleized authenticated journal batch (provides the speculative Merkle root).
    pub(crate) journal_batch: Arc<authenticated::MerkleizedBatch<F, D, Operation<F, U>, S>>,

    /// This batch's local key-level changes only (not accumulated from ancestors).
    /// Sorted by key with no duplicates; queried via `lookup_sorted` (binary search).
    pub(crate) diff: Arc<DiffVec<U::Key, F, U::Value>>,

    /// The committed locations this batch's writes supersede (their `base_old_loc`s), sorted and
    /// deduplicated. While this batch is in a descendant's retained chain, the descendant's floor
    /// candidates exclude them. Empty when [`Candidates::EXCLUDES_SUPERSEDED`] is true, as for
    /// Current's layered bitmap.
    superseded: Vec<Location<F>>,

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

/// Validate `current` against an effective database boundary and retained ancestor chain.
fn validate_ancestor_chain<F: Family, D: Digest, U: update::Update, S: Strategy>(
    current: Commitment<F, D>,
    db_state: Commitment<F, D>,
    ancestors: &[AncestorBatch<F, D, U, S>],
) -> Result<(), crate::qmdb::Error<F>> {
    chain::validate_batch_applicable(
        current,
        db_state,
        ancestors.iter().map(|ancestor| ancestor.commitment()),
    )
}

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
    frozen: Option<Frozen<F, U>>,
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
    db: &'a Db<F, E, C, I, H, U, N, S>,
    /// Pending mutations. `Some(value)` for upsert, `None` for delete.
    mutations: BTreeMap<U::Key, Option<U::Value>>,
    /// Merkleization state, including the retained ancestor chain.
    merkleizer: Merkleizer<F, H, U, S>,
    /// Locations a policy pass gathered for the existing keys in `mutations`.
    existing: Option<Vec<Location<F>>>,
    /// Committed operations a policy pass read at existing-key locations without deciding them, in
    /// ascending location order. Merkleize resolves the batch's writes from them instead of reading
    /// them again.
    decoded: Vec<(Location<F>, Operation<F, U>)>,
    /// The committed candidates a staged merkleize read while it resolved its updates. The floor
    /// raise takes them whole as its first round, and a policy pass selects from them first.
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
/// ancestor writes `key`, `loc` must have its committed bit set, and the result is
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

/// Outcome of classifying one floor-raise candidate or policy-kept update against the batch diff
/// and the ancestor diffs. A keyed operation is active when the nearest diff entry for its key
/// points at it, or when no diff holds its key. The latter holds for a candidate because, below
/// the database's size, candidates are only locations whose committed bit is set, and that bit
/// marks a key's live update. It holds for a kept update because the update was active when the
/// policy decided it.
///
/// Classification is a pure function of the pre-raise state: at most one candidate per key
/// can be active (the committed bitmap holds exactly one set bit per active key, and each diff
/// or ancestor entry resolves a key to a single location), and a move only rewrites the moved
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
    /// Validate `current` against the boundary and ancestor chain retained by this merkleizer.
    fn validate_commitment(
        &self,
        current: Commitment<F, H::Digest>,
    ) -> Result<(), crate::qmdb::Error<F>> {
        validate_ancestor_chain(current, self.db_state, &self.ancestors)
    }

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
        // be handed to the reader directly. Depth-0 mutation reads take this path.
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

    /// Read the operations at the ascending existing-key `locations`, committed or in memory, like
    /// [`read_ops`](Self::read_ops), but take each one a policy pass already decoded from the
    /// ascending `decoded` operations instead of reading it again.
    async fn read_existing<R: Contiguous<Item = Operation<F, U>>>(
        &self,
        locations: &[Location<F>],
        decoded: Vec<(Location<F>, Operation<F, U>)>,
        reader: &R,
    ) -> Result<Vec<Operation<F, U>>, crate::qmdb::Error<F>> {
        if decoded.is_empty() {
            return self.read_ops(locations, &[], reader).await;
        }
        let mut decoded = decoded.into_iter().peekable();
        let mut missing = Vec::new();
        let reused: Vec<_> = locations
            .iter()
            .map(|loc| {
                while decoded.next_if(|(at, _)| at < loc).is_some() {}
                let op = decoded.next_if(|(at, _)| at == loc).map(|(_, op)| op);
                if op.is_none() {
                    missing.push(*loc);
                }
                op
            })
            .collect();
        let mut read = self.read_ops(&missing, &[], reader).await?.into_iter();
        Ok(reused
            .into_iter()
            .map(|op| op.unwrap_or_else(|| read.next().expect("one read per missing location")))
            .collect())
    }

    /// Fill `out` from `fill` with up to `limit` floor candidates in `[floor, tip)`, excluding the
    /// committed locations the retained ancestors' writes superseded, and return where the scan
    /// stopped.
    ///
    /// When [`Candidates::EXCLUDES_SUPERSEDED`] is true, candidates pass through without filtering.
    /// Otherwise, the sorted `superseded` lists in retained [`MerkleizedBatch`]es are excluded.
    ///
    /// None of the excluded locations holds an active update for this batch. Each was its key's
    /// committed location when an ancestor superseded it, so it lies below the committed boundary,
    /// while the key's nearest diff entry, in this batch or a retained ancestor, points at or above
    /// the boundary or deletes the key.
    ///
    /// A list goes stale when an older ancestor commits and moves a key the list's batch wrote:
    /// the key's new committed location is missing from the list, so it is read and found
    /// inactive, and every listed location stays inactive.
    ///
    /// Excluding these locations leaves floors and roots unchanged. Classification would find them
    /// inactive, so the same updates move in the same order, and a move still sets the floor just
    /// past its location.
    ///
    /// A raise that runs out of candidates passes the last one its source yields. A production
    /// source yields every location up to the batch's tip, none of which is excluded, so the floor
    /// still reaches the tip. A custom source that stops at excluded locations leaves the floor
    /// before them.
    fn fill_excluding_superseded<C: Candidates<F>>(
        &self,
        fill: &mut C,
        floor: Location<F>,
        tip: u64,
        limit: usize,
        out: &mut Vec<Location<F>>,
    ) -> Location<F> {
        if C::EXCLUDES_SUPERSEDED {
            return fill.fill(floor, tip, limit, out);
        }

        // Each pass fills from where the previous one stopped, then filters only what it appended.
        let mut scan = floor;
        loop {
            let start = out.len();
            let next = fill.fill(scan, tip, limit, out);
            let filled = out.len();

            // Remove the new candidates that any retained ancestor's list holds, stopping once
            // none remain.
            for ancestor in &self.ancestors {
                let list = ancestor.superseded.as_slice();
                let end = out.len();
                if end == start {
                    break;
                }

                // Skip a list with no location between the first and last new candidates.
                let mut at = list.partition_point(|loc| *loc < out[start]);
                if list.get(at).is_none_or(|first| *first > out[end - 1]) {
                    continue;
                }

                // Drop the listed locations from the new candidates, compacting the rest in place.
                // Once the list runs out, the remaining candidates move down in one copy.
                let mut kept = start;
                let mut read = start;
                while read < end && at < list.len() {
                    let loc = out[read];
                    if !sorted_contains(list, &mut at, &loc) {
                        out[kept] = loc;
                        kept += 1;
                    }
                    read += 1;
                }
                out.copy_within(read..end, kept);
                out.truncate(kept + (end - read));
            }

            // Refill only for what the lists removed, so an unfiltered scan calls `fill` once. A
            // refill past the source's last candidate appends nothing and ends the loop.
            if out.len() == filled {
                return next;
            }
            scan = next;
        }
    }

    /// Select the next round of floor candidates from `scan` and read the committed ones. Policy
    /// passes, floor raises, and staged prefetches all read candidates through here.
    ///
    /// The round fills candidates below `last` with [`Self::fill_excluding_superseded`] until
    /// `need` of them may be active. It passes the sorted `inactive` locations without counting
    /// them toward `need`. A location in the sorted `existing` may hold an active collision
    /// sibling, so it is selected and counts as possibly active, but not toward `need`.
    ///
    /// Under a skip `budget` of a floor and the skips left to it, the round stops at the first
    /// candidate the floor cannot reach even if every earlier candidate outside `inactive` is
    /// active.
    ///
    /// The round selects from the committed candidates of a `head` round first, keeping the
    /// operations already read for those it selects, and then fills from `scan`, which must lie
    /// past them. It reads the other committed candidates it selects in one batch. `scan` moves
    /// past the round.
    #[allow(clippy::too_many_arguments)]
    async fn read_round<E, C>(
        &self,
        log: &authenticated::Journal<F, E, C, H, S>,
        scan: &mut Location<F>,
        last: Location<F>,
        mut need: usize,
        budget: Option<(Location<F>, u64)>,
        inactive: &[Location<F>],
        existing: &[Location<F>],
        fill: &mut impl Candidates<F>,
        head: Option<Round<F, U>>,
    ) -> Result<Round<F, U>, crate::qmdb::Error<F>>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
    {
        let head = head.filter(|head| !head.candidates.is_empty());
        let start = head
            .as_ref()
            .map_or(*scan, |head| head.candidates[0].min(*scan));
        let mut candidates = Vec::new();
        if budget.is_none() {
            let room = usize::try_from((*last).saturating_sub(*start)).unwrap_or(usize::MAX);
            candidates.reserve(need.min(room));
        }
        let mut passed: Option<Location<F>> = None;
        let mut cut = None;
        let mut inactive_at = inactive.partition_point(|loc| *loc < start);
        let mut existing_at = existing.partition_point(|loc| *loc < start);
        let mut possible = 0;
        let mut filled = 0;
        let mut pending = head.as_ref().map(|head| head.candidates.as_slice());
        let mut from_head = 0;
        loop {
            let kept = candidates.len();
            let in_head = pending.is_some();
            let next = if let Some(pending) = pending.take() {
                candidates.extend_from_slice(pending);
                *scan
            } else {
                if need == 0 || *scan >= last {
                    break;
                }

                // Without a skip budget, a request asks for every candidate still needed. Under
                // one, each request adds at most the larger of the candidates filled so far and 64,
                // so a round fills at most 64 more than twice the candidates it passes before a
                // cut.
                let request = match budget {
                    Some(_) => need.min(filled.max(64)),
                    None => need,
                };
                let next = self.fill_excluding_superseded(
                    fill,
                    *scan,
                    *last,
                    kept.saturating_add(request),
                    &mut candidates,
                );
                if candidates.len() == kept {
                    // No candidate remains below `last`.
                    *scan = last;
                    break;
                }
                next
            };
            filled += candidates.len() - kept;

            // The cursors rely on candidates ascending across the round.
            assert!(passed.map_or(start <= candidates[kept], |passed| passed
                < candidates[kept]));

            // With no skip budget and no listed location left ahead, every new candidate counts.
            if budget.is_none() && inactive_at == inactive.len() && existing_at == existing.len() {
                assert!(candidates[kept..].is_sorted_by(|a, b| a < b));
                need -= candidates.len() - kept;
                passed = candidates.last().copied();
                if in_head {
                    from_head = candidates.len();
                }
                *scan = next;
                continue;
            }

            // Keep the new candidates outside `inactive` in place, compacted after the earlier
            // ones.
            let mut write = kept;
            let mut stop = None;
            for at in kept..candidates.len() {
                let loc = candidates[at];
                assert!(passed.is_none_or(|passed| passed < loc));
                if sorted_contains(inactive, &mut inactive_at, &loc) {
                    passed = Some(loc);
                    continue;
                }
                if let Some((floor, skips)) = budget
                    && *loc - *floor - possible > skips
                {
                    stop = Some(loc);
                    break;
                }
                possible += 1;
                if !sorted_contains(existing, &mut existing_at, &loc) {
                    need -= 1;
                }
                candidates[write] = loc;
                write += 1;
                passed = Some(loc);
            }
            candidates.truncate(write);
            if in_head {
                from_head = write;
            }
            if let Some(loc) = stop {
                // Later candidates stay out of reach whatever the earlier ones hold.
                *scan = loc;
                cut = Some(loc);
                break;
            }
            *scan = next;
        }

        // Read the committed candidates past the head in one batch, and append their operations
        // to those already read at the selected head candidates.
        let split = candidates.partition_point(|loc| *loc < self.db_state.size);
        let positions: Vec<u64> = candidates[from_head..split]
            .iter()
            .map(|loc| **loc)
            .collect();
        let read = log.read_many_sharded(&positions).await?;
        let committed = match head {
            Some(Round {
                candidates: head,
                committed: mut ops,
                ..
            }) => {
                let mut locs = head.iter();
                let mut selected = candidates[..from_head].iter().peekable();
                for chunk in &mut ops {
                    chunk.retain(|_| {
                        let loc = locs.next().expect("one operation per head candidate");
                        selected.next_if_eq(&loc).is_some()
                    });
                }
                ops.extend(read);
                ops
            }
            None => read,
        };
        Ok(Round {
            candidates,
            committed,
            passed,
            cut,
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
        db: &Db<F, E, C, I, H, U, N, S>,
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
    /// ancestor diffs (see [`FloorOutcome`]).
    fn classify(
        &self,
        diff: &DiffSlice<U::Key, F, U::Value>,
        loc: Location<F>,
        key: &U::Key,
    ) -> FloorOutcome<F> {
        match diff.binary_search_by(|(k, _)| k.cmp(key)) {
            Ok(idx) if diff[idx].1.loc() == Some(loc) => FloorOutcome::MoveExisting {
                idx,
                base_old_loc: diff[idx].1.base_old_loc(),
            },
            Ok(_) => FloorOutcome::Inactive,
            Err(_) => locate(&self.ancestors, loc, key).map_or(FloorOutcome::Inactive, |sloc| {
                FloorOutcome::MoveNew {
                    base_old_loc: sloc.superseded(self.db_state.size),
                }
            }),
        }
    }

    /// Append `op` at the tip as `outcome` directs and record its new location in `diff` or
    /// `floor_diff`. Returns whether `op` moved.
    fn relocate(
        &self,
        ops: &mut Vec<Operation<F, U>>,
        diff: &mut DiffSlice<U::Key, F, U::Value>,
        floor_diff: &mut DiffVec<U::Key, F, U::Value>,
        op: Operation<F, U>,
        outcome: FloorOutcome<F>,
    ) -> bool {
        match outcome {
            FloorOutcome::Inactive => return false,
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
        true
    }

    /// Shared final phases of merkleization: floor raise, CommitFloor, journal
    /// merkleize, diff merge, and `MerkleizedBatch` construction.
    ///
    /// `diff` may arrive in any order: it is key-sorted on the strategy pool, overlapping the
    /// first floor-raise candidate read. `superseded_locs` holds the committed locations
    /// superseded by `diff` (every `Some` `base_old_loc`), in any order. The floor raise passes
    /// them without reading them, and an Any batch records them sorted for its descendants. The
    /// raise takes the `prefetched` round whole as its first.
    ///
    /// Under [`Limits::Fixed`], the raise is skipped and each kept update is classified and moved
    /// as the raise would move it. The floor stays where the policy pass left it. If the final
    /// state is empty, the floor moves to the new commit location.
    #[allow(clippy::too_many_arguments)]
    async fn finish<E, C, I, T: Candidates<F>, const N: usize>(
        mut self,
        mut ops: Vec<Operation<F, U>>,
        mut diff: DiffVec<U::Key, F, U::Value>,
        mut superseded_locs: Vec<Location<F>>,
        active_keys_delta: isize,
        user_steps: u64,
        metadata: Option<U::Value>,
        mut prefetched: Option<Prefetched<F, U>>,
        mut fill_candidates: T,
        db: &Db<F, E, C, I, H, U, N, S>,
    ) -> RetainedMerkleizeResult<F, H::Digest, U, S>
    where
        E: Context,
        C: Contiguous<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = Location<F>>,
    {
        // Floor raise: one step per operation the batch makes inactive. `user_steps` counts the
        // updates it supersedes and the deletes it appends, and the previous commit adds one.
        let total_steps = user_steps + 1;
        let total_active_keys = self.base_active_keys as isize + active_keys_delta;

        // A policy pass has already chosen the floor. Otherwise the raise starts from the
        // inherited floor.
        let frozen = self.frozen.take();
        let mut floor = frozen
            .as_ref()
            .map_or(self.base_inactivity_floor_loc, |frozen| frozen.floor);

        // Key-sort the diff as one job on the strategy: candidate classification (after the
        // first floor-raise read below, or of a policy pass's kept updates) is the earliest
        // consumer that needs it sorted, so under the raise the sort overlaps the candidate
        // gathering and read instead of the calling task. An empty diff is already sorted and
        // skips the job. While the job runs, `diff` is empty. It is replaced by the sorted diff
        // at the first `diff_sort` await.
        let mut diff_sort = None;
        if !diff.is_empty() {
            let unsorted = mem::take(&mut diff);
            diff_sort = Some(db.strategy().spawn(unsorted.len(), move |strategy| {
                let mut diff = unsorted;
                strategy.sort_by(&mut diff, |a, b| a.0.cmp(&b.0));
                diff
            }));
        }

        // The raise below passes the committed locations this batch supersedes in ascending order,
        // and an Any batch records them in that order for its descendants. Locations are unique
        // (each committed location belongs to exactly one key), so a presorted collection needs
        // neither the sort nor the dedup.
        let raises = total_active_keys > 0 && frozen.is_none();
        if (raises || !T::EXCLUDES_SUPERSEDED) && !superseded_locs.is_sorted_by(|a, b| a < b) {
            db.strategy().sort_by(&mut superseded_locs, |a, b| a.cmp(b));
            superseded_locs.dedup();
        }

        // New diff entries for keys moved by the floor raise, merged into `diff` below.
        let mut floor_diff = Vec::new();
        if raises {
            // Floor raise: advance the inactivity floor by `total_steps` active operations.
            // `fixed_tip` prevents scanning into floor-raise moves just appended.
            let strategy = db.strategy();
            let fixed_tip = self.base_state.size + ops.len() as u64;
            let mut moved = 0u64;
            let mut scan = floor;
            floor_diff.reserve(total_steps as usize);

            // The raise appends at most `total_steps` moved ops plus the CommitFloor. Reserve
            // once instead of growing mid-loop.
            ops.reserve(total_steps as usize + 1);

            // Scan active operations in `[floor, fixed_tip)` and move them to the tip, passing the
            // committed locations this batch supersedes without reading them. Each round selects
            // as many candidates outside `superseded_locs` as moves remain, so the raise needs
            // another round only for candidates it reads and finds inactive.
            //
            // A staged prefetch is the first round, taken whole and resumed from where its
            // selection stopped. It selected from the same floor and source, and classification
            // finds any of this batch's superseded locations it holds inactive.
            while moved < total_steps {
                let mut round = match prefetched.take() {
                    Some((round, next)) => {
                        scan = next;
                        round
                    }
                    None => {
                        let round = self
                            .read_round(
                                &db.log,
                                &mut scan,
                                fixed_tip,
                                (total_steps - moved) as usize,
                                None,
                                &superseded_locs,
                                &[],
                                &mut fill_candidates,
                                None,
                            )
                            .await?;
                        if round.passed.is_none() {
                            break;
                        }
                        round
                    }
                };

                // Uncommitted candidates, in the ancestors or this batch, resolve in memory, and
                // their operations follow the committed ones as one more chunk.
                let split = round
                    .candidates
                    .partition_point(|loc| *loc < self.db_state.size);
                if split < round.candidates.len() {
                    let memory = round.candidates[split..]
                        .iter()
                        .map(|loc| {
                            self.try_read_op_from_uncommitted(*loc, &ops)
                                .expect("candidate is uncommitted")
                        })
                        .collect();
                    round.committed.push(memory);
                }

                // Classification is the first consumer of the sorted diff. By now the sort has
                // overlapped the fill and read above.
                if let Some(job) = diff_sort.take() {
                    diff = job.await;
                }

                // Classify each candidate against the pre-raise state in candidate order (see
                // [`FloorOutcome`]). A CommitFloor has no key and is inactive.
                let outcomes: Vec<FloorOutcome<F>> = strategy.map_collect_vec(
                    zip_eq(round.candidates.iter(), round.committed.iter().flatten()),
                    |(loc, op)| {
                        op.key().map_or(FloorOutcome::Inactive, |key| {
                            self.classify(&diff, *loc, key)
                        })
                    },
                );

                // Apply in candidate order, moving active ops to the tip. The floor passes every
                // location the round selected, including the inactive ones it skipped, unless
                // the last move comes first.
                if let Some(passed) = round.passed {
                    floor = passed + 1;
                }
                let mut reads = round.committed.into_iter().flatten();
                let mut outcomes = outcomes.into_iter();
                for loc in round.candidates {
                    let op = reads.next().expect("one read per candidate");
                    let outcome = outcomes.next().expect("one outcome per candidate");
                    if !self.relocate(&mut ops, &mut diff, &mut floor_diff, op, outcome) {
                        continue;
                    }
                    moved += 1;
                    if moved >= total_steps {
                        floor = loc + 1;
                        break;
                    }
                }
            }
        } else if total_active_keys == 0 {
            // DB is empty after this batch; raise floor to tip.
            floor = self.base_state.size + ops.len() as u64;
            debug!(tip = ?floor, "db is empty, raising floor to tip");
        } else if let Some(Frozen { mut retained, .. }) = frozen {
            // A stopped update stays at the floor.
            assert!(retained.is_sorted_by(|a, b| a.0 < b.0));
            if retained.last().is_some_and(|(loc, _)| *loc == floor) {
                retained.pop();
            }
            assert!(retained.last().is_none_or(|(loc, _)| *loc < floor));

            // Move each still-active kept update in location order as the raise would move it.
            // Each update classifies against the diffs independently of the others (see
            // [`FloorOutcome`]), so all of them classify in one parallel pass before any moves.
            if let Some(job) = diff_sort.take() {
                diff = job.await;
            }
            let outcomes: Vec<FloorOutcome<F>> = db
                .strategy()
                .map_collect_vec(retained.iter(), |(loc, update)| {
                    self.classify(&diff, *loc, update.key())
                });
            ops.reserve(retained.len() + 1);
            floor_diff.reserve(retained.len());
            for ((_, update), outcome) in zip_eq(retained, outcomes) {
                self.relocate(
                    &mut ops,
                    &mut diff,
                    &mut floor_diff,
                    Operation::Update(update),
                    outcome,
                );
            }
        }

        // The floor raise may have exited without classifying any candidate (or been skipped
        // entirely). Every path below needs the sorted diff.
        if let Some(job) = diff_sort.take() {
            diff = job.await;
        }

        // Merge the floor raise's new diff entries as one job on the strategy: nothing below reads
        // `diff` until after the journal merkleization, so the merge overlaps the hashing instead
        // of the calling task. `floor_diff` only accumulates keys that were not already present in
        // `diff` (the raise moves a key at most once because its new location lies above
        // `fixed_tip` and the scan never revisits it, and a policy pass keeps at most one update
        // per key), so the merge inputs are disjoint.
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
        let ancestors: Vec<_> = self
            .ancestors
            .iter()
            .map(|a| chain::AncestorBounds {
                floor: a.bounds.inactivity_floor,
                state: a.commitment(),
            })
            .collect();

        assert!(total_active_keys >= 0, "active_keys underflow");
        let batch = Arc::new(MerkleizedBatch {
            journal_batch: journal,
            diff: Arc::new(diff),
            superseded: if !T::EXCLUDES_SUPERSEDED {
                superseded_locs
            } else {
                Vec::new()
            },
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
    /// Returns [`crate::qmdb::Error::StaleBatch`] if `db` is not on the batch's live chain.
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
    /// stages those -- see [`update::Update::STAGES_ANCESTORS`]) reuse the staged location.
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
        // collision sibling can hold its predecessor link (see [`StagedUpdates`]).
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
        let limits = policy.limits();
        let (prepared, staged) = self
            .resolve_updates_prefetched(updates, upserts, db, limits, fill)
            .await?;
        let (prepared, staged) = prepared.advance(staged, policy, limits, fill).await?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_scan(metadata, staged, fill)
            .await?;
        Ok(batch)
    }

    /// Resolve the caller's updates on the strategy pool while selecting and reading committed
    /// floor candidates under `limits`, overlapping the two.
    /// Returns the prepared batch, holding the prefetched round, and the staged updates.
    /// Preparation validates and retains the live chain before any supplied-database read.
    ///
    /// The prefetch selects candidates with [`Merkleizer::read_round`] from the base floor and the
    /// `fill_candidates` source the floor advance scans, without knowing which locations the
    /// resolution makes inactive, so it may read locations the advance then passes. Under
    /// [`Limits::Proportional`] it selects up to an estimate of the raise's steps, and the raise
    /// takes the round whole as its first. Under [`Limits::Fixed`] it selects up to `entries`
    /// candidates below the pass's window, and the pass applies its own selection to them as the
    /// head of its candidate stream. Either way the scan resumes where the prefetch stopped.
    ///
    /// The selection is clamped to the committed boundary: a speculative source (e.g. the current
    /// variant's parent bitmap) extends past it, but its candidate sequence below the boundary is
    /// identical and only committed locations need the log read. On early exhaustion of the
    /// committed set bits, sources may hand back either one past the last emitted candidate or the
    /// committed boundary as the continuation point. Both are correct: the skipped span holds no
    /// set bits, and the source cannot change during the call (commits and prunes take `&mut` on
    /// the database).
    #[allow(clippy::type_complexity)]
    pub(crate) async fn resolve_updates_prefetched<'a, E, C, I, const N: usize>(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
        db: &'a Db<F, E, C, I, H, update::Unordered<K, V>, N, S>,
        limits: Limits,
        mut fill_candidates: impl Candidates<F>,
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
        let floor = prepared.merkleizer.base_inactivity_floor_loc;
        let db_size = prepared.merkleizer.db_state.size;

        let (need, last) = match limits {
            Limits::Proportional => {
                // Bound the steps the floor raise can take: the previous commit takes one, and
                // each emitted op takes one for an update or two for a delete.
                //
                // An op is emitted per location-resolved staged slot plus per upsert or prior
                // mutation on a key alive in the committed snapshot. A slot written more than once
                // counts only its final write. Fresh-key creates never consume a step, so
                // unresolved slots and writes missing from the snapshot are excluded (one
                // in-memory probe per key).
                //
                // The bound is approximate in both directions. Surplus candidates (a translated-key
                // collision, a key an ancestor already deleted, or a key that another slot or an
                // upsert also writes) are dropped by the raise once it moves enough ops. A
                // shortfall (an upsert or prior mutation whose key is live only in an ancestor's
                // diff) makes the raise fall back to the live scan when the prefetched prefix runs
                // out.
                let steps = |value: &Option<V::Value>| if value.is_some() { 1 } else { 2 };
                let mut counted = vec![false; resolutions.len()];
                let mut staged_steps = 0;
                for (slot, value) in updates.iter().rev() {
                    if resolutions.get(*slot).is_some_and(Option::is_some) && !counted[*slot] {
                        counted[*slot] = true;
                        staged_steps += steps(value);
                    }
                }
                let existing_steps: usize = upserts
                    .iter()
                    .map(|(key, value)| (key, value))
                    .chain(&prepared.mutations)
                    .filter(|&(key, _)| db.snapshot.get(key).next().is_some())
                    .map(|(_, value)| steps(value))
                    .sum();
                (staged_steps + existing_steps + 1, db_size)
            }
            Limits::Fixed { entries, skips } => {
                // The pass decides or passes nothing at or past the floor plus its limits, nor at
                // the previous commit.
                let reach = (*floor)
                    .saturating_add(skips)
                    .saturating_add(Widen::widen(entries));
                let tip = prepared.merkleizer.base_state.size;
                (entries, Location::new(reach).min(tip - 1).min(db_size))
            }
        };

        // The committed bitmap has one candidate per active key and its last commit.
        let need = need.min(db.active_keys.saturating_add(1));

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
            .read_round(
                &db.log,
                &mut scan,
                last,
                need,
                None,
                &[],
                &[],
                &mut fill_candidates,
                None,
            )
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
        let limits = policy.limits();
        let (prepared, staged) = prepared.advance(staged, policy, limits, fill).await?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_scan(metadata, staged, fill)
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

    /// Validate that `current` is a state on this batch's live chain, returning strong ancestor
    /// references that keep the validated chain stable through subsequent asynchronous work.
    pub(crate) fn validate_commitment(
        &self,
        current: Commitment<F, H::Digest>,
    ) -> Result<RetainedAncestors<F, H::Digest, U, S>, crate::qmdb::Error<F>> {
        let ancestors = self.retain_ancestors();
        let db_state = chain::effective_boundary(
            self.base.db(),
            ancestors.last().map(|oldest| oldest.bounds.base),
        );
        validate_ancestor_chain(current, db_state, &ancestors)?;
        Ok(ancestors)
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
            frozen: None,
            base_active_keys: self.base.active_keys(),
        };
        (self.mutations, m)
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
        merkleizer.validate_commitment(db.commitment())?;
        Ok(Prepared {
            db,
            mutations,
            merkleizer,
            existing: None,
            decoded: Vec::new(),
            prefetched: None,
        })
    }

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
    ) -> UncommittedReadResolution<'a, U::Key, U::Value> {
        let ancestors = self.retain_ancestors();
        self.resolve_uncommitted_reads_with_ancestors(keys, &ancestors, strategy, on_diff_hit)
    }

    /// Resolve uncommitted reads through an already-retained ancestor chain.
    fn resolve_uncommitted_reads_with_ancestors<'a>(
        &self,
        keys: &[&'a U::Key],
        ancestors: &[AncestorBatch<F, H::Digest, U, S>],
        strategy: &S,
        on_diff_hit: impl FnMut(usize, &DiffEntry<F, U::Value>),
    ) -> UncommittedReadResolution<'a, U::Key, U::Value> {
        let diffs: Vec<_> = ancestors
            .iter()
            .map(|batch| batch.diff.as_slice())
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
    /// Returns [`crate::qmdb::Error::StaleBatch`] if `db` is not on the batch's live chain.
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
        let validated_ancestors = self.validate_commitment(db.commitment())?;
        let mut resolutions: Vec<StagedResolution<F, U>> =
            iter::repeat_with(|| None).take(keys.len()).collect();

        // Record ancestor-diff resolutions when the update kind stages them: the staged
        // write then reuses the resolved location at merkleize instead of falling back to a
        // normal mutation (whose cost -- location gathering, a journal re-read, and
        // per-key ancestor re-resolution -- otherwise grows with ancestor overlap).
        let (mut results, unresolved) = self.resolve_uncommitted_reads_with_ancestors(
            keys,
            &validated_ancestors,
            db.strategy(),
            |slot, entry| {
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
            },
        );
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
        drop(validated_ancestors);
        Ok((
            results,
            keys.iter().map(|key| (*key).to_owned()).collect(),
            resolutions,
        ))
    }
}

impl<'a, F, E, C, I, H, U, const N: usize, S> Prepared<'a, F, E, C, I, H, U, N, S>
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
    /// Under [`Limits::Fixed`], run `policy` over the active updates from the batch's inherited
    /// floor and freeze the floor the pass reached for merkleize. Updates that the batch's writes
    /// or `staged` supersede count as inactive. The pass decides at most `entries` updates and
    /// passes at most `skips` inactive locations, and reads nothing at or past the floor plus both,
    /// though it may read candidates it then passes or never reaches. A staged pass selects from
    /// its prefetched candidates first. `fill` supplies the rest and must meet the candidate
    /// contract of [`Candidates`]. Under [`Limits::Proportional`], return the batch
    /// and `staged` unchanged.
    ///
    /// Returns `staged` merged with the policy's evictions and replacements and sorted by location.
    /// No earlier write shares their keys because the pass never decides a written key.
    pub(crate) async fn advance<P>(
        mut self,
        staged: StagedUpdates<F, U>,
        policy: &mut P,
        limits: Limits,
        mut fill: impl Candidates<F>,
    ) -> Result<(Self, StagedUpdates<F, U>), crate::qmdb::Error<F>>
    where
        U: update::Parts,
        P: Policy<F, U::Key, U::Value>,
    {
        let Limits::Fixed { entries, skips } = limits else {
            return Ok((self, staged));
        };
        let floor = self.merkleizer.base_inactivity_floor_loc;
        let tip = self.merkleizer.base_state.size;
        let reach = (*floor)
            .saturating_add(skips)
            .saturating_add(Widen::widen(entries));
        let end = Location::new(reach).min(tip);
        let mut prefetched = self.prefetched.take();

        // Only a pass with entries needs the locations the batch's writes supersede.
        let mut existing = (entries > 0).then(|| {
            self.merkleizer
                .gather_existing_locations(&self.mutations, self.db)
        });

        // Staged write locations in the window are inactive and already sorted. Classification
        // sees mutations and ancestor diffs, so it cannot exclude these writes by key. The
        // candidate source excludes committed locations superseded by pending ancestors.
        let mut inactive = Vec::new();
        if entries > 0 {
            inactive.extend(
                staged
                    .iter()
                    .map(|(_, sloc, _, _)| sloc.loc())
                    .filter(|loc| (floor..end).contains(loc)),
            );
        }
        let mut decoded = Vec::new();
        let mut cursor = Cursor {
            floor,
            scan: floor,
            end,
            entries,
            skips,
            buffer: VecDeque::new(),
        };

        // Decided updates in ascending location order. Merkleize moves kept updates to the tip and
        // leaves a stopped one in place, and the records of evictions (value `None`) and
        // replacements resolve as writes to their keys.
        let mut retained = Vec::new();
        let mut records: StagedUpdates<F, U> = Vec::new();
        while cursor.entries > 0 {
            if cursor.buffer.is_empty() && cursor.scan < cursor.end {
                let existing = existing.as_deref().unwrap_or_default();
                self.read(
                    &mut cursor,
                    existing,
                    &inactive,
                    &mut decoded,
                    &mut prefetched,
                    &mut fill,
                )
                .await?;
            }
            let Some((sloc, update)) = cursor.pop() else {
                break;
            };
            let (key, value, cached) = update.into_parts();
            let decision = policy.decide(Entry::new(sloc.loc(), &key, value));
            match decision.into_action() {
                Action::Keep(value) => {
                    retained.push((sloc.loc(), U::from_parts(key, value, cached)))
                }
                Action::Replace(value) => records.push((key, sloc, cached, Some(value))),
                Action::Evict => records.push((key, sloc, cached, None)),
                Action::Stop(value) => {
                    retained.push((sloc.loc(), U::from_parts(key, value, cached)));
                    break;
                }
            }
            cursor.entries -= 1;
            cursor.floor = sloc.loc() + 1;
        }

        // Evicted keys join the batch's writes under the same rule as staged deletes (see
        // [`StagedUpdates`]), so the gathered existing-key locations no longer cover the writes.
        if U::SIBLINGS {
            for (key, ..) in records.iter().filter(|(.., value)| value.is_none()) {
                self.mutations.insert(key.clone(), None);
                existing = None;
            }
        }
        self.existing = existing;
        self.decoded = decoded;
        self.merkleizer.frozen = Some(Frozen {
            floor: cursor.floor,
            retained,
        });
        let staged = merge_by(staged, records, |a, b| a.1.loc() < b.1.loc());
        Ok((self, staged))
    }

    /// Read rounds of candidates from the scan position into the read-ahead buffer until one
    /// holds an active update or the window ends.
    ///
    /// Each round comes from [`Merkleizer::read_round`] with the cursor's entries and skips. Its
    /// cut, if any, becomes the window's end. The first round selects from the `prefetched`
    /// candidates, which start at the floor, before it fills, and their operations move out of the
    /// prefetch without another read. Other committed candidates are read in one batch, and
    /// ancestor candidates resolve in memory. Committed operations read at `existing` locations
    /// that the read-ahead does not keep go to `decoded`.
    async fn read(
        &self,
        cursor: &mut Cursor<F, U>,
        existing: &[Location<F>],
        inactive: &[Location<F>],
        decoded: &mut Vec<(Location<F>, Operation<F, U>)>,
        prefetched: &mut Option<Prefetched<F, U>>,
        fill: &mut impl Candidates<F>,
    ) -> Result<(), crate::qmdb::Error<F>> {
        let ancestors = self.merkleizer.ancestors.as_slice();
        let mutations = &self.mutations;
        let db_size = self.merkleizer.db_state.size;
        let tip = self.merkleizer.base_state.size;

        let mut scan = cursor.scan;
        let mut end = cursor.end;
        let mut found = Vec::new();
        let mut decoded_at = existing.partition_point(|loc| *loc < scan);
        loop {
            // The batch's commit supersedes the last commit at `tip - 1`, so candidates
            // stop before it.
            let last = end.min(tip - 1);
            let head = prefetched.take();
            if head.is_none() && scan >= last {
                scan = end;
                break;
            }

            // The prefetched candidates head the first round's stream, and the round fills on from
            // where the prefetch stopped.
            let head = head.map(|(round, next)| {
                scan = next;
                round
            });

            // Only candidates outside `inactive` may hold active updates. The remaining skips
            // bound which candidates the floor can reach.
            let Round {
                candidates,
                committed: shards,
                cut,
                ..
            } = self
                .merkleizer
                .read_round(
                    &self.db.log,
                    &mut scan,
                    last,
                    cursor.entries,
                    Some((cursor.floor, cursor.skips)),
                    inactive,
                    existing,
                    fill,
                    head,
                )
                .await?;
            if let Some(cut) = cut {
                end = cut;
            }
            let split = candidates.partition_point(|loc| *loc < db_size);

            // Classify against this batch's writes, then the ancestor diffs. A committed
            // candidate whose key appears in neither is active.
            let memory: Vec<&Operation<F, U>> = candidates[split..]
                .iter()
                .map(|loc| read_op_from_ancestors(ancestors, **loc, *db_size))
                .collect();
            let mut ops: Vec<(Location<F>, &Operation<F, U>)> =
                Vec::with_capacity(candidates.len());
            ops.extend(zip_eq(
                candidates.iter().copied(),
                shards.iter().flatten().chain(memory.iter().copied()),
            ));
            let outcomes: Vec<Option<StagedLoc<F>>> =
                self.db
                    .strategy()
                    .map_collect_vec(ops, |(loc, op)| match op {
                        Operation::Update(update) if !mutations.contains_key(update.key()) => {
                            locate(ancestors, loc, update.key())
                        }
                        _ => None,
                    });

            // Move committed active updates out of the read and clone in-memory ones. Candidates
            // at write locations do not count toward `need`, so a round can find more active
            // updates than the remaining entries. The read-ahead keeps at most the first `entries`
            // of them, since the pass decides no more, and resumes at the next. Merkleize resolves
            // the batch's writes at the existing-key locations, so it reuses every other committed
            // operation read there.
            let mut owned = shards.into_iter().flatten();
            let mut resume = None;
            for (i, (loc, outcome)) in zip_eq(&candidates, outcomes).enumerate() {
                let op = (i < split).then(|| owned.next().expect("one read per candidate"));
                if let Some(sloc) = outcome
                    && resume.is_none()
                {
                    if found.len() < cursor.entries {
                        let op = op.unwrap_or_else(|| memory[i - split].clone());
                        let Operation::Update(update) = op else {
                            unreachable!("active operations are updates");
                        };
                        found.push((sloc, update));
                        continue;
                    }
                    resume = Some(*loc);
                }
                if let Some(op) = op
                    && sorted_contains(existing, &mut decoded_at, loc)
                {
                    decoded.push((*loc, op));
                }
            }
            if let Some(loc) = resume {
                scan = loc;
            }
            if !found.is_empty() {
                break;
            }
        }
        cursor.buffer = VecDeque::from(found);
        cursor.scan = scan;
        cursor.end = end;
        Ok(())
    }
}

impl<F: Family, U: update::Update> Cursor<F, U> {
    /// Move the floor to the next read-ahead update and return it. Each inactive location passed
    /// costs a skip. Without a read-ahead update, the floor moves to the scan position and `None`
    /// is returned. When the target lies beyond the remaining skips, the floor advances by them
    /// and `None` is returned.
    fn pop(&mut self) -> Option<(StagedLoc<F>, U)> {
        // Every location between the floor and the frontier is inactive, and passing each one
        // costs a skip, so the floor reached depends only on which locations are active, not on
        // how candidates were read.
        let frontier = self
            .buffer
            .front()
            .map_or(self.scan, |(sloc, _)| sloc.loc());
        let gap = *frontier - *self.floor;
        if gap > self.skips {
            self.floor += self.skips;
            self.skips = 0;
            return None;
        }
        self.floor = frontier;
        self.skips -= gap;
        self.buffer.pop_front()
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
        let limits = policy.limits();
        let (prepared, staged) = prepared.advance(Vec::new(), policy, limits, fill).await?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_scan(metadata, staged, fill)
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
    /// [`Staged::merkleize`] or a policy pass (loaded keys skip the journal re-read
    /// their resolution would otherwise require) and accepting the floor-raise candidate
    /// source. The floor raise takes the candidates the batch prefetched as its first round.
    ///
    /// The source must meet the [`Candidates`] contract: ascending candidates that cover every
    /// location that may hold an active update in this chain (see [`FloorOutcome`]), and only
    /// committed set bits below the database's size.
    pub(crate) async fn merkleize_with_floor_scan(
        self,
        metadata: Option<V::Value>,
        staged_updates: StagedUpdates<F, update::Unordered<K, V>>,
        fill_candidates: impl Candidates<F>,
    ) -> RetainedMerkleizeResult<F, H::Digest, update::Unordered<K, V>, S> {
        let Self {
            db,
            mut mutations,
            merkleizer: m,
            existing,
            decoded,
            prefetched,
        } = self;

        // Resolve existing keys. Reuse their locations when a policy pass gathered them, and the
        // committed operations it already read there. Staged records already resolved their exact
        // locations, so those need no read. Neither do the updates the pass retained, since the
        // batch writes none of their keys.
        let mut locations = existing.unwrap_or_else(|| m.gather_existing_locations(&mutations, db));
        if !staged_updates.is_empty() {
            let mut staged_at = 0;
            locations.retain(|loc| {
                !contains_staged::<F, update::Unordered<K, V>>(&staged_updates, &mut staged_at, loc)
            });
        }
        if let Some(frozen) = &m.frozen {
            take_retained(&mut locations, &frozen.retained, |_, _| {});
        }
        let results = m.read_existing(&locations, decoded, &db.log).await?;

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
                    user_steps += 1;
                }
                None => {
                    ops.push(Operation::Delete(key.clone()));
                    diff.push((key, DiffEntry::Deleted { base_old_loc }));
                    active_keys_delta -= 1;
                    user_steps += 2;
                }
            }
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
        let limits = policy.limits();
        let (prepared, staged) = prepared.advance(Vec::new(), policy, limits, fill).await?;
        let (batch, _retained_ancestors) = prepared
            .merkleize_with_floor_scan(metadata, staged, fill)
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
    /// [`Staged::merkleize`] or a policy pass (loaded keys skip the journal re-read their
    /// resolution would otherwise require: the caller's new value and the cached next key feed op
    /// generation directly, and updates also skip the index probe) and accepting the floor-raise
    /// candidate source.
    ///
    /// The source must meet the [`Candidates`] contract: ascending candidates that cover every
    /// location that may hold an active update in this chain (see [`FloorOutcome`]), and only
    /// committed set bits below the database's size.
    pub(crate) async fn merkleize_with_floor_scan(
        self,
        metadata: Option<V::Value>,
        staged_updates: StagedUpdates<F, update::Ordered<K, V>>,
        fill_candidates: impl Candidates<F>,
    ) -> RetainedMerkleizeResult<F, H::Digest, update::Ordered<K, V>, S> {
        let Self {
            db,
            mut mutations,
            merkleizer: m,
            existing,
            decoded,
            prefetched,
        } = self;

        // Resolve existing keys. Reuse their locations when a policy pass gathered them, and the
        // committed operations it already read there. Staged records already resolved their exact
        // locations, so those need no read. Other locations in their buckets still hold collision
        // siblings.
        let mut locations = existing.unwrap_or_else(|| m.gather_existing_locations(&mutations, db));
        if !staged_updates.is_empty() {
            let mut staged_at = 0;
            locations.retain(|loc| {
                !contains_staged::<F, update::Ordered<K, V>>(&staged_updates, &mut staged_at, loc)
            });
        }

        // Classify mutations into deleted, created, updated. `next_candidates` and
        // `prev_candidates` are built as unsorted `Vec`s here and sorted+deduped once below,
        // before `find_next_key` / `find_prev_key_mut` binary-search them.
        let mut next_candidates: Vec<K> = Vec::new();
        let mut prev_candidates: PrevCandidates<K, F, Cow<'_, V::Value>> = Vec::new();
        let mut deleted: Vec<(K, Location<F>)> = Vec::new();
        let mut updated: Vec<(K, V::Value, Location<F>)> = Vec::new();

        // A retained update is the active operation the pass read at its location, and the batch
        // writes none of the retained keys, so it feeds the candidate sets as a read there would.
        let retained = m
            .frozen
            .as_ref()
            .map_or(&[][..], |frozen| frozen.retained.as_slice());
        take_retained(&mut locations, retained, |loc, update| {
            next_candidates.push(update.next_key.clone());
            prev_candidates.push((
                update.key.clone(),
                (Some(Cow::Borrowed(&update.value)), loc),
            ));
        });
        let ops = m.read_existing(&locations, decoded, &db.log).await?;
        for (op, &old_loc) in zip_eq(ops, &locations) {
            let update::Ordered {
                key,
                value,
                next_key,
            } = match op {
                Operation::Update(data) => data,
                _ => unreachable!("snapshot should only reference Update operations"),
            };

            // A key resolved via the ancestor diff must only match at its ancestor-diff
            // location. A stale snapshot collision (the pre-parent DB snapshot still
            // containing the key's old location) must contribute nothing: consuming its
            // mutation would misclassify a parent-deleted key's re-creation as an update
            // (or its redundant delete as a live delete), and feeding its next_key or
            // (key, old_loc) into the candidate sets would steer predecessor rewrites
            // only on the pending-ancestor path (the applied-ancestor path never reads
            // the superseded op).
            if let Some(entry) = resolve_in_ancestors(&m.ancestors, &key)
                && entry.loc() != Some(old_loc)
            {
                continue;
            }

            next_candidates.push(next_key);
            prev_candidates.push((key.clone(), (Some(Cow::Owned(value)), old_loc)));

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
            next_candidates.push(key.clone());
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
        take_retained(&mut prev_locations, retained, |loc, update| {
            next_candidates.push(update.next_key.clone());
            prev_candidates.push((
                update.key.clone(),
                (Some(Cow::Borrowed(&update.value)), loc),
            ));
        });

        let prev_results = m.read_ops(&prev_locations, &[], &db.log).await?;

        for (op, &old_loc) in zip_eq(prev_results, &prev_locations) {
            let data = match op {
                Operation::Update(data) => data,
                _ => unreachable!("expected update operation"),
            };

            // Same stale-location guard as the mutation classifier above: the snapshot scan
            // sees only applied state, so a key the ancestor diff supersedes at another
            // location (or deletes) is stale here and must not steer the predecessor search.
            // The ancestor-diff walk below contributes the live version of such keys.
            if let Some(entry) = resolve_in_ancestors(&m.ancestors, &data.key)
                && entry.loc() != Some(old_loc)
            {
                continue;
            }
            next_candidates.push(data.next_key);
            prev_candidates.push((data.key, (Some(Cow::Owned(data.value)), old_loc)));
        }

        // Merge staged-resolved records: they skip the journal re-read, and updates also skip the
        // index probe. Each record's cached successor feeds the successor candidates as the skipped
        // read would have. An update also feeds its (key, loc) to the predecessor candidates
        // without a value: the value is only consumed when the predecessor-rewrite loop emits an op
        // for the key, and that loop skips every key present in `updated`. A deleted key is never a
        // predecessor. An ancestor-resolved record's superseded base is re-resolved through the
        // live ancestor diffs when its operation is emitted below.
        for (key, sloc, old_next, value) in staged_updates {
            let loc = sloc.loc();
            next_candidates.push(old_next);
            if let Some(value) = value {
                prev_candidates.push((key.clone(), (None, loc)));
                updated.push((key, value, loc));
            } else {
                deleted.push((key, loc));
            }
        }
        db.strategy().sort_by(&mut deleted, |a, b| a.0.cmp(&b.0));
        db.strategy().sort_by(&mut updated, |a, b| a.0.cmp(&b.0));

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
        // Each diff records only its owning batch's changes, so active operations can be read
        // directly from that batch's journal suffix.
        //
        // Existing-key updates preserve membership, so their resolved successors suffice and
        // no predecessor is rewritten.
        let changes_membership = !created.is_empty() || !deleted.is_empty();
        let candidate_ancestors = if changes_membership {
            m.ancestors.as_slice()
        } else {
            &[][..]
        };
        let track_shadow = candidate_ancestors.len() > 1;
        let seen_cap = if track_shadow {
            candidate_ancestors.iter().map(|a| a.diff.len()).sum()
        } else {
            0
        };
        let mut seen: AHashSet<&K> = AHashSet::with_capacity(seen_cap);
        for batch in candidate_ancestors.iter() {
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
                let DiffEntry::Active { loc, .. } = entry else {
                    continue;
                };
                let index = (**loc - *batch.bounds.base.size) as usize;
                let data = match &batch.journal_batch.items()[index] {
                    Operation::Update(data) => data,
                    _ => unreachable!("ancestor diff Active should reference Update op"),
                };
                next_candidates.push(data.key.clone());
                next_candidates.push(data.next_key.clone());
                prev_candidates.push((data.key.clone(), (Some(Cow::Borrowed(&data.value)), *loc)));
            }
        }

        // Sort and deduplicate successor candidates for binary search.
        db.strategy().sort_by(&mut next_candidates, |a, b| a.cmp(b));
        next_candidates.dedup();

        // Only membership changes require filtering deleted successors and preparing
        // predecessor candidates for rewrites.
        if changes_membership {
            // Resolved operations can still reference keys deleted by this batch.
            let is_deleted = |k: &K| deleted.binary_search_by(|(dk, _)| dk.cmp(k)).is_ok();
            next_candidates.retain(|k| !is_deleted(k));

            // `prev_candidates` is consulted only by the predecessor rewrites below. Duplicates
            // can occur when the same key is pushed from multiple sources (main scan,
            // prev_results, ancestor walk). Later pushes carry the freshest state (ancestor
            // walk runs last), so dedup keeps the LAST push per key. `dedup_by` retains the
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
            prev_candidates.retain(|(k, _)| !is_deleted(k));
        }

        // Generate operations.
        let mut ops: Vec<Operation<F, update::Ordered<K, V>>> =
            Vec::with_capacity(deleted.len() + updated.len() + created.len() + 1);
        let mut diff: DiffVec<K, F, V::Value> =
            Vec::with_capacity(deleted.len() + updated.len() + created.len());
        let mut active_keys_delta: isize = 0;
        let mut user_steps: u64 = 0;

        // Process deletes.
        let mut ancestors = DiffCursors::new(m.ancestors.iter().map(|a| a.diff.as_slice()));
        for (key, old_loc) in deleted {
            ops.push(Operation::Delete(key.clone()));

            let base_old_loc = ancestors
                .resolve(&key)
                .map_or(Some(old_loc), DiffEntry::base_old_loc);

            diff.push((key, DiffEntry::Deleted { base_old_loc }));
            active_keys_delta -= 1;
            user_steps += 2;
        }
        let deleted_range = 0..diff.len();

        // Process updates of existing keys.
        let updated_range = diff.len()..diff.len() + updated.len();
        let mut ancestors = DiffCursors::new(m.ancestors.iter().map(|a| a.diff.as_slice()));
        let mut next_idx = 0;
        for (key, value, old_loc) in updated {
            let new_loc = m.base_state.size + ops.len() as u64;
            let next_key = find_next_key_ascending(&key, &next_candidates, &mut next_idx);
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
            user_steps += 1;
        }

        // Process creates.
        let created_range = diff.len()..diff.len() + created.len();
        let mut next_idx = 0;
        for (key, value, base_old_loc) in created {
            let new_loc = m.base_state.size + ops.len() as u64;
            let next_key = find_next_key_ascending(&key, &next_candidates, &mut next_idx);
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
        if !prev_candidates.is_empty() {
            // The create/delete ranges stay fixed as predecessor rewrites are appended.
            for idx in created_range.chain(deleted_range) {
                let key = &diff[idx].0;
                let (prev_key, (prev_value, prev_loc)) =
                    find_prev_key_mut(key, &mut prev_candidates);

                // Only updated mutation keys can be candidates: creates have no live
                // operation before this batch, and deletes are excluded from candidates.
                if lookup_sorted(&diff[updated_range.clone()], prev_key).is_some() {
                    continue;
                }

                // Taking the value ensures a shared predecessor is rewritten only once.
                let Some(prev_value) = prev_value.take() else {
                    continue;
                };
                let prev_value = prev_value.into_owned();

                // Preserve the ordered links across creates and deletes by rewriting the
                // predecessor with its existing value and its successor in the final key set.
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
                        value: prev_value,
                        loc: prev_new_loc,
                        base_old_loc: prev_base_old_loc,
                    },
                ));
                user_steps += 1;
            }
        }

        // Release the candidate keys and values before the remaining phases run.
        drop(prev_candidates);

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
            prefetched,
            fill_candidates,
            db,
        )
        .await
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
        if self.total_active_keys == 0 {
            return Ok(None);
        }
        if let Some(prev) = self.find_cyclic_neighbor::<false>(key) {
            return Ok((prev < *key).then_some(prev));
        }
        db.get_prev_key(key).await
    }

    /// Find a cyclic neighbor from the live batch chain, if it owns the query's span.
    fn find_cyclic_neighbor<const NEXT: bool>(&self, key: &K) -> Option<K> {
        let find = |batch: &Self| {
            let diff = batch.diff.as_slice();
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

            // Active entries reference operations in their owning batch's journal suffix.
            let index = (*loc - *batch.bounds.base.size) as usize;
            let Operation::Update(data) = &batch.journal_batch.items()[index] else {
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
        find(self).or_else(|| self.ancestors().find_map(|batch| find(&batch)))
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
    /// Includes floor-raise moves and the trailing commit.
    pub fn operations(&self) -> (Location<F>, Arc<Vec<Operation<F, U>>>) {
        (
            self.bounds.base.size,
            Arc::clone(self.journal_batch.items()),
        )
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
    /// Returns [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or
    /// belongs to a dropped unapplied ancestor, and [`crate::merkle::Error::Empty`] if the batch
    /// has no operations (a [`Db::to_batch`] snapshot).
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
    /// Returns [`crate::merkle::Error::ElementPruned`] if a required node has been pruned or
    /// belongs to a dropped unapplied ancestor.
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
        db.log
            .speculative_pinned_nodes(&self.journal_batch)
            .map_err(Into::into)
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

        let ancestors: Vec<_> = self.ancestors().collect();
        let diffs: Vec<_> = ancestors
            .iter()
            .map(|batch| batch.diff.as_slice())
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
            superseded: Vec::new(),
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
        batch
            .bounds
            .validate_apply_to(self.commitment(), self.inactivity_floor_loc)
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
                    if batch.bounds.ancestors[i].state.size <= db_size {
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
                    Choice, Script, assert_links, assert_same, colliding_digest, fixed_db_config,
                },
                traits::{DbAny, MerkleizedBatch as _, UnmerkleizedBatch as _},
                unordered::fixed::Db as UnorderedFixedDb,
                value::FixedEncoding,
            },
            current,
            floor::{Compact, Decision, Entry, Hold, Proportional},
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

    /// Keeps every update and records each decided key with the clone count at its decision.
    struct Probe {
        clones: Arc<AtomicUsize>,
        decided: Vec<(sha256::Digest, usize)>,
    }

    impl Policy<mmr::Family, sha256::Digest, CountedValue> for Probe {
        fn limits(&self) -> Limits {
            Limits::Fixed {
                entries: usize::MAX,
                skips: u64::MAX,
            }
        }

        fn decide<'a>(
            &mut self,
            entry: Entry<'a, mmr::Family, sha256::Digest, CountedValue>,
        ) -> Decision<'a, CountedValue> {
            self.decided
                .push((*entry.key(), self.clones.load(AtomicOrdering::Relaxed)));
            entry.keep()
        }
    }

    /// A policy pass over a pending ancestor's operations clones only the active update it
    /// decides.
    #[test]
    fn policy_clones_only_decided_ancestor_update() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                CountedValue,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("policy-clones", &context);
            let db = TestDb::init(context, config, None).await.unwrap();
            let clones = Arc::new(AtomicUsize::new(0));
            let first = sha256::Digest::from([0; 32]);
            let second = sha256::Digest::from([1; 32]);

            // A pending parent writes both keys and holds the floor.
            let parent = db
                .new_batch()
                .write(first, Some(CountedValue(0, clones.clone())))
                .write(second, Some(CountedValue(1, clones.clone())))
                .merkleize(&db, Some(CountedValue(2, clones.clone())), &mut Hold)
                .await
                .unwrap();

            // The child deletes the first key, so only the second key's update is active. The
            // pass has cloned only that update when the policy decides it.
            let mut policy = Probe {
                clones: clones.clone(),
                decided: Vec::new(),
            };
            clones.store(0, AtomicOrdering::Relaxed);
            let child = parent
                .new_batch::<Sha256>()
                .write(first, None)
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(policy.decided, [(second, 1)]);

            // The pass reaches the parent's tip.
            assert_eq!(child.bounds().inactivity_floor, parent.bounds().tip.size);
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
        fn limits(&self) -> Limits {
            Limits::Fixed {
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

    /// A policy that evicts committed, pending-parent, and colliding-key updates owns each
    /// evicted value and receives them in location order with no clone beyond the parent's read.
    /// The evicted keys read `None` once the batch applies.
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

        // The child rewrites the first colliding key and evicts every other active update.
        for count in &counts {
            count.store(0, AtomicOrdering::Relaxed);
        }
        let mut policy = Evict::default();
        let merkleized = child(&parent)
            .write(colliding(0), Some(CountedValue::new(20)))
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();

        // Merkleize clones each pending value only for the pass's read.
        for count in &counts {
            assert_eq!(count.load(AtomicOrdering::Relaxed), 1);
        }

        // Evictions arrive in location order with the committed update first. Evicting clones
        // nothing, committed values arrive unshared, and parent values carry only the clone their
        // read takes.
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
                (true, colliding(2), 12, 1, 1),
                (true, other, 13, 1, 1),
            ]
        );

        // Applying the batch deletes every evicted key and keeps the rewritten one.
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        drop(parent);
        for (_, key, ..) in &policy.evicted {
            assert!(db.get(key).await.unwrap().is_none());
        }
        let kept = db.get(&colliding(0)).await.unwrap();
        assert_eq!(kept.map(|value| value.0), Some(20));
        db.destroy().await.unwrap();
    }

    /// [`policy_evicts_owned`] on an unordered Any database.
    #[test]
    fn policy_evicts_owned_any_unordered() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                CountedValue,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("evict-unordered", &context);
            let db = TestDb::init(context, config, None).await.unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// [`policy_evicts_owned`] on an ordered Any database.
    #[test]
    fn policy_evicts_owned_any_ordered() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = OrderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                CountedValue,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("evict-ordered", &context);
            let db = TestDb::init(context, config, None).await.unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// [`policy_evicts_owned`] on an unordered current database.
    #[test]
    fn policy_evicts_owned_current_unordered() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = current::unordered::fixed::Db<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                CountedValue,
                Sha256,
                OneCap,
                32,
                Sequential,
            >;
            let config = current::tests::fixed_config::<OneCap>("evict-unordered", &context);
            let db = TestDb::init(context, config, None).await.unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// [`policy_evicts_owned`] on an ordered current database.
    #[test]
    fn policy_evicts_owned_current_ordered() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = current::ordered::fixed::Db<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                CountedValue,
                Sha256,
                OneCap,
                32,
                Sequential,
            >;
            let config = current::tests::fixed_config::<OneCap>("evict-ordered", &context);
            let db = TestDb::init(context, config, None).await.unwrap();
            policy_evicts_owned(db, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// A staged prefetch sizes its candidate buffer by the database's active keys, not by the span
    /// of a fixed pass's window.
    #[test]
    fn staged_prefetch_capacity_tracks_active_keys() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("prefetch-capacity", &context);
            let mut db = TestDb::init(context, config, None).await.unwrap();
            let keys = [colliding_digest(0xAA, 0), colliding_digest(0xAA, 1)];
            let batch = db
                .new_batch()
                .write(keys[0], Some(keys[0]))
                .write(keys[1], Some(keys[1]))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            (db, _) = db.apply_batch(batch).await.unwrap();
            for _ in 0..128 {
                let batch = db
                    .new_batch()
                    .write(keys[1], Some(keys[1]))
                    .merkleize(&db, None, &mut Hold)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
            }
            assert_eq!(db.active_keys(), 2);
            assert_eq!(*db.inactivity_floor_loc(), 0);
            let (_, staged) = db.new_batch().stage(&[], &db).await.unwrap();
            let (prepared, _) = staged
                .resolve_updates_prefetched(
                    Vec::new(),
                    Vec::new(),
                    &db,
                    Limits::Fixed {
                        entries: usize::MAX,
                        skips: u64::MAX,
                    },
                    db.bitmap.as_ref(),
                )
                .await
                .unwrap();
            let candidates = &prepared.prefetched.as_ref().unwrap().0.candidates;
            assert_eq!(candidates.len(), 2);
            assert!(
                candidates.capacity() <= 64,
                "capacity {}",
                candidates.capacity()
            );
            drop(prepared);
            db.destroy().await.unwrap();
        });
    }

    /// A policy pass buffers at most its remaining entries when a write shares a translated-key
    /// bucket with every active update.
    #[test]
    fn policy_buffers_at_most_entries() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("policy-read-ahead", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed four colliding keys at 1..5 with a held floor.
            let keys: Vec<_> = (0..4).map(|i| colliding_digest(0xAA, i)).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            // Deleting the last key leaves three active updates in its bucket. A read with two
            // entries left holds the first two and resumes at the third.
            let tip = db.bounds().end;
            let prepared = db.new_batch().write(keys[3], None).prepare(&db).unwrap();
            let existing = prepared
                .merkleizer
                .gather_existing_locations(&prepared.mutations, &db);
            let mut cursor = Cursor {
                floor: loc(0),
                scan: loc(0),
                end: tip,
                entries: 2,
                skips: u64::MAX,
                buffer: VecDeque::new(),
            };
            prepared
                .read(
                    &mut cursor,
                    &existing,
                    &[],
                    &mut Vec::new(),
                    &mut None,
                    &mut db.bitmap.as_ref(),
                )
                .await
                .unwrap();
            let found: Vec<_> = cursor
                .buffer
                .iter()
                .map(|(sloc, update)| (sloc.loc(), *update::Update::key(update)))
                .collect();
            assert_eq!(found, [(loc(1), keys[0]), (loc(2), keys[1])]);
            assert_eq!(cursor.scan, loc(3));
            drop(prepared);
            db.destroy().await.unwrap();
        });
    }

    /// A live round without an entry limit fills at most 64 candidates when its first candidate
    /// is already out of reach.
    #[test]
    fn policy_gathers_bounded_before_cut() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("policy-gather", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed 200 keys with a held floor, then supersede the 100 written first.
            let mut keys: Vec<_> = (0..200u64)
                .map(|i| Sha256::hash(&[&i.to_be_bytes()]))
                .collect();
            keys.sort();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let churn = keys[..100]
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(churn).await.unwrap();

            // The first active update lies past the skips, so the cut falls at the first
            // candidate.
            let tip = db.bounds().end;
            let prepared = db.new_batch().prepare(&db).unwrap();
            let mut cursor = Cursor {
                floor: Location::new(0),
                scan: Location::new(0),
                end: tip,
                entries: usize::MAX,
                skips: 10,
                buffer: VecDeque::new(),
            };
            let mut gathered = 0;
            prepared
                .read(
                    &mut cursor,
                    &[],
                    &[],
                    &mut Vec::new(),
                    &mut None,
                    &mut FnCandidates(|floor, tip, limit, out: &mut Vec<_>| {
                        let start = out.len();
                        let next = db.bitmap.as_ref().fill(floor, tip, limit, out);
                        gathered += out.len() - start;
                        next
                    }),
                )
                .await
                .unwrap();
            assert!(cursor.buffer.is_empty());
            assert_eq!(cursor.end, Location::new(101));
            assert!(gathered <= 64, "gathered {gathered}");
            drop(prepared);
            db.destroy().await.unwrap();
        });
    }

    /// Returns one entry from its first [`Policy::limits`] call and unbounded limits from later
    /// calls. Keeps every update and counts the limits calls and the decisions.
    pub(crate) struct Growing {
        pub(crate) reads: Cell<usize>,
        pub(crate) decided: usize,
    }

    impl Policy<mmr::Family, sha256::Digest, sha256::Digest> for Growing {
        fn limits(&self) -> Limits {
            let reads = self.reads.get();
            self.reads.set(reads + 1);
            let entries = if reads == 0 { 1 } else { usize::MAX };
            Limits::Fixed {
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

    /// A policy pass reads its limits once and decides under them.
    #[test]
    fn policy_reads_limits_once() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("policy-limits", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

            // Seed four keys with a held floor.
            let seed = (0..4u8)
                .map(|i| sha256::Digest::from([i; 32]))
                .fold(db.new_batch(), |batch, key| batch.write(key, Some(key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            // The first limits allow one entry, and later calls would allow every update.
            let mut policy = Growing {
                reads: Cell::new(0),
                decided: 0,
            };
            let merkleized = db
                .new_batch()
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(policy.reads.get(), 1);
            assert_eq!(policy.decided, 1);
            drop(merkleized);
            db.destroy().await.unwrap();
        });
    }

    /// Writing every staged slot twice reads the same operations during a proportional merkleize as
    /// writing each slot once, whether the earlier and final writes are updates or deletes.
    #[test]
    fn staged_duplicate_writes_read_like_single_writes() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("staged-duplicate-writes", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed 64 keys in key order at locations 1..65 with a held floor, and stage the last
            // eight.
            let keys: Vec<_> = (0..64u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let staged: Vec<_> = keys[56..].iter().collect();

            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let update = Some(sha256::Digest::from([0xFF; 32]));
            for last in [update, None] {
                let mut reads = Vec::new();
                for values in [vec![last], vec![update, last], vec![None, last]] {
                    let (_, batch) = db.new_batch().stage(&staged, &db).await.unwrap();
                    let updates: Vec<_> = values
                        .iter()
                        .flat_map(|value| (0..staged.len()).map(move |slot| (slot, *value)))
                        .collect();
                    let before = items();
                    let merkleized = batch
                        .merkleize(updates, Vec::new(), None, &db, &mut Proportional)
                        .await
                        .unwrap();
                    reads.push(items() - before);
                    drop(merkleized);
                }
                assert!(
                    reads.iter().all(|r| *r == reads[0]),
                    "last={last:?} reads={reads:?}"
                );
            }
            db.destroy().await.unwrap();
        });
    }

    /// A fixed policy that keeps the updates the [`Proportional`] raise moves produces the same
    /// batch with no more journal reads when the batch's writes supersede updates in its window:
    /// with keys in their own translated-key buckets, all in one bucket, or a few in the written
    /// key's bucket, and when a pending parent rewrote the written keys.
    async fn policy_reads_writes_once<D, Fut>(
        context: deterministic::Context,
        open: impl Fn(deterministic::Context, &'static str) -> Fut,
        child: fn(&D::Merkleized) -> D::Batch,
    ) where
        D: DbAny<mmr::Family, Key = sha256::Digest, Value = sha256::Digest>,
        Fut: core::future::Future<Output = D>,
    {
        // Each scenario names its keys, the indices of the keys a pending parent rewrites and of
        // those the batch writes, and the updates the raise moves for the batch.
        let distinct: Vec<_> = (0..32u8).map(|i| sha256::Digest::from([i; 32])).collect();
        let colliding: Vec<_> = (0..64).map(|i| colliding_digest(0xAA, i)).collect();
        let crowded: Vec<_> = (0..4)
            .map(|i| colliding_digest(0xAA, i))
            .chain([0xBB, 0xCC].map(|byte| sha256::Digest::from([byte; 32])))
            .collect();
        let scenarios = [
            ("distinct", distinct.clone(), vec![], vec![1, 3, 5, 7], 5),
            ("colliding", colliding, vec![], vec![63], 2),
            ("crowded", crowded, vec![], vec![3], 2),
            ("pending", distinct, vec![1, 3], vec![1, 3], 3),
        ];
        let items = || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
        let rewrite = sha256::Digest::from([0xDD; 32]);
        let value = sha256::Digest::from([0xEE; 32]);
        for (partition, keys, rewritten, written, entries) in scenarios {
            // Seed the keys. The raise moves the first one, so the floor is 2.
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

            // Keeping as many updates as the raise moves produces the same batch.
            let write = || {
                let batch = parent.as_ref().map_or_else(|| db.new_batch(), child);
                written
                    .iter()
                    .fold(batch, |batch, &i| batch.write(keys[i], Some(value)))
            };
            let before = items();
            let raised = write()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let raise_reads = items() - before;
            let before = items();
            let mut policy = Compact {
                entries,
                skips: u64::MAX,
            };
            let kept = write().merkleize(&db, None, &mut policy).await.unwrap();
            assert_eq!(kept.root(), raised.root(), "{partition}");
            let reads = items() - before;
            assert!(reads <= raise_reads, "{partition}: {reads} > {raise_reads}");
            drop((raised, kept, parent));
            db.destroy().await.unwrap();
        }
    }

    /// [`policy_reads_writes_once`] on an unordered Any database.
    #[test]
    fn policy_reads_writes_once_unordered() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let open = |context, partition| async move {
                let config = fixed_db_config::<OneCap>(partition, &context);
                TestDb::init(context, config, None).await.unwrap()
            };
            policy_reads_writes_once(context, open, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// [`policy_reads_writes_once`] on an ordered Any database.
    #[test]
    fn policy_reads_writes_once_ordered() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = OrderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let open = |context, partition| async move {
                let config = fixed_db_config::<OneCap>(partition, &context);
                TestDb::init(context, config, None).await.unwrap()
            };
            policy_reads_writes_once(context, open, |batch| batch.new_batch::<Sha256>()).await;
        });
    }

    /// An ordered batch that rewrites the link of an update its fixed policy keeps reads that
    /// update no more often than the [`Proportional`] raise, whether the update lies in the
    /// predecessor bucket of the created key or shares its translated-key bucket.
    #[test]
    fn policy_reads_kept_predecessor_once() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = OrderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");

            // Keys in even translated-key buckets. The created key follows the third key, either
            // in an empty bucket or in that key's bucket.
            let keys: Vec<_> = (0..16u8)
                .map(|i| sha256::Digest::from([2 * i; 32]))
                .collect();
            let mut shared = [4; 32];
            shared[1] = 5;
            let created = [
                ("empty", sha256::Digest::from([5; 32])),
                ("shared", sha256::Digest::from(shared)),
            ];
            for (partition, created) in created {
                // Seed the keys. The raise moves the first one, so the floor is 2 and the third
                // key, which precedes the created key, lies at 3.
                let config = fixed_db_config::<OneCap>(partition, &context);
                let db = TestDb::init(context.child(partition), config, None)
                    .await
                    .unwrap();
                let seed = keys
                    .iter()
                    .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                    .merkleize(&db, None, &mut Proportional)
                    .await
                    .unwrap();
                let (db, _) = db.apply_batch(seed).await.unwrap();
                assert_eq!(*db.inactivity_floor_loc(), 2);

                // Rewriting the third key's link and the previous commit each move one update. A
                // policy keeping the first three, the third key among them, reaches the same batch.
                let before = items();
                let raised = db
                    .new_batch()
                    .write(created, Some(created))
                    .merkleize(&db, None, &mut Proportional)
                    .await
                    .unwrap();
                let raise_reads = items() - before;
                let before = items();
                let mut policy = Compact {
                    entries: 3,
                    skips: u64::MAX,
                };
                let kept = db
                    .new_batch()
                    .write(created, Some(created))
                    .merkleize(&db, None, &mut policy)
                    .await
                    .unwrap();
                assert_eq!(kept.root(), raised.root(), "{partition}");
                let reads = items() - before;
                assert!(reads <= raise_reads, "{partition}: {reads} > {raise_reads}");
                drop((raised, kept));
                db.destroy().await.unwrap();
            }
        });
    }

    /// An ordered batch that rewrites the link of the update its fixed policy stops at reads that
    /// update no more often than the [`Proportional`] raise.
    #[test]
    fn policy_reads_stopped_predecessor_once() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = OrderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("stopped-predecessor", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let keys = [2u8, 4, 6, 8, 10].map(|byte| sha256::Digest::from([byte; 32]));
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            assert_eq!(*db.inactivity_floor_loc(), 2);

            // The new key rewrites the fourth key's link. Two moves keep the second and third
            // keys, leaving the fourth key at the floor.
            let created = sha256::Digest::from([9; 32]);
            let write = || db.new_batch().write(created, Some(created));
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let before = items();
            let raised = write()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(items() - before, 3);
            let before = items();
            let compact = write()
                .merkleize(
                    &db,
                    None,
                    &mut Compact {
                        entries: 2,
                        skips: u64::MAX,
                    },
                )
                .await
                .unwrap();
            assert_eq!(items() - before, 3);
            assert_same(&db, &raised, &compact);

            let mut policy = Script::new(3, u64::MAX, |key: &sha256::Digest| {
                if *key == keys[3] {
                    Choice::Stop
                } else {
                    Choice::Keep
                }
            });
            let before = items();
            let stopped = write().merkleize(&db, None, &mut policy).await.unwrap();
            let reads = items() - before;
            assert_eq!(policy.locations(), [loc(2), loc(3), loc(4)]);
            assert_eq!(*stopped.bounds().inactivity_floor, 4);
            assert_same(&db, &raised, &stopped);
            assert_eq!(reads, 3, "the stopped predecessor was read again");
            drop((raised, compact, stopped));
            db.destroy().await.unwrap();
        });
    }

    /// An ordered batch that rewrites the link of a key a pending parent rewrote reads the key's
    /// superseded committed update no more often under a fixed policy than under the
    /// [`Proportional`] raise.
    #[test]
    fn policy_reads_parent_rewritten_predecessor_once() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = OrderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("parent-predecessor", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed three keys in their own translated-key buckets at 1..4 with a held floor, and
            // rewrite the first in a pending parent.
            let keys = [2u8, 4, 6].map(|byte| sha256::Digest::from([byte; 32]));
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let parent = db
                .new_batch()
                .write(keys[0], Some(sha256::Digest::from([0xDD; 32])))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();

            // Creating a key after the first rewrites its link, so the raise passes the first
            // key's committed update at 1 and moves the two at 2 and 3. A policy that keeps two
            // reaches the same batch.
            let created = sha256::Digest::from([3; 32]);
            let write = || parent.new_batch::<Sha256>().write(created, Some(created));
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let before = items();
            let raised = write()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let raise_reads = items() - before;
            let before = items();
            let mut policy = Compact {
                entries: 2,
                skips: u64::MAX,
            };
            let kept = write().merkleize(&db, None, &mut policy).await.unwrap();
            assert_eq!(kept.root(), raised.root());
            let reads = items() - before;
            assert!(reads <= raise_reads, "{reads} > {raise_reads}");
            drop((raised, kept, parent));
            db.destroy().await.unwrap();
        });
    }

    /// A pass whose remaining skips cannot reach the update behind a staged write decides nothing,
    /// and its floor advances by its skips. The staged prefetch still reads the window's
    /// candidates, since the limits bound decisions and passed locations rather than reads.
    #[test]
    fn policy_decides_nothing_past_staged_reach() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("staged-reach", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed four keys at 1..5 with a held floor, and stage the first.
            let keys: Vec<_> = (1..5u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let (_, staged) = db.new_batch().stage(&[&keys[0]], &db).await.unwrap();

            // The staged write supersedes the update at 1, and one skip cannot also pass the
            // initial commit to reach the update at 2. The prefetch reads both candidates below the
            // window's end at 3.
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let before = items();
            let mut policy = Script::new(2, 1, |_: &sha256::Digest| Choice::Keep);
            let merkleized = staged
                .merkleize(vec![(0, Some(keys[1]))], Vec::new(), None, &db, &mut policy)
                .await
                .unwrap();
            assert!(policy.visited.is_empty());
            assert_eq!(items() - before, 2);
            assert_eq!(merkleized.bounds().inactivity_floor, Location::new(1));
            drop(merkleized);
            db.destroy().await.unwrap();
        });
    }

    /// A staged write's committed location among the prefetched candidates is passed as inactive,
    /// never decided, so a staged pass decides what the unstaged pass with the same write decides.
    #[test]
    fn staged_pass_passes_prefetched_write_location() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("staged-prefetched-write", &context);
            let db = TestDb::init(context.child("db"), config, None)
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

            // Rewriting the first key supersedes its update at 1. The prefetch reads it, and the
            // pass decides the following updates without reading its selected head again.
            let value = Some(sha256::Digest::from([0xEE; 32]));
            let keep = |_: &sha256::Digest| Choice::Keep;
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            for entries in [1, 3] {
                let (_, staged) = db.new_batch().stage(&[&keys[0]], &db).await.unwrap();
                let before = items();
                let mut policy = Script::new(entries, u64::MAX, keep);
                let staged = staged
                    .merkleize(vec![(0, value)], Vec::new(), None, &db, &mut policy)
                    .await
                    .unwrap();
                let reads = items() - before;
                let mut twin = Script::new(entries, u64::MAX, keep);
                let written = db
                    .new_batch()
                    .write(keys[0], value)
                    .merkleize(&db, None, &mut twin)
                    .await
                    .unwrap();
                let decided: Vec<_> = (2..2 + Widen::widen(entries)).map(Location::new).collect();
                assert_eq!(policy.locations(), decided);
                assert_eq!(policy.visited, twin.visited);
                assert_eq!(staged.root(), written.root());

                // One prefetched inactive update plus exactly the updates the pass decides.
                assert_eq!(reads, Widen::widen(entries + 1));
                drop((staged, written));
            }
            db.destroy().await.unwrap();
        });
    }

    /// A staged fixed pass matches the unstaged pass's decisions, root, and floor for each policy
    /// action and at its entries, skips, or window. A pending parent, an earlier write, and an
    /// upsert overriding a staged slot cover resolutions the prefetch cannot see.
    macro_rules! staged_fixed_pass_matches_unstaged_test {
        ($name:ident, $db:ty, $config:expr) => {
            #[test]
            fn $name() {
                deterministic::Runner::default().start(|context| async move {
                    let config = $config("staged-fixed-unstaged", &context);
                    let db = <$db>::init(context.child("db"), config, None)
                        .await
                        .unwrap();

                    // Commit 16 keys with a held floor. A pending parent rewrites the second and
                    // seventh keys.
                    let keys: Vec<_> = (0..16u8).map(|i| sha256::Digest::from([i; 32])).collect();
                    let seed = keys
                        .iter()
                        .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                        .merkleize(&db, None, &mut Hold)
                        .await
                        .unwrap();
                    let (db, _) = db.apply_batch(seed).await.unwrap();
                    let rewrite = Some(sha256::Digest::from([0xDD; 32]));
                    let parent = db
                        .new_batch()
                        .write(keys[1], rewrite)
                        .write(keys[6], rewrite)
                        .merkleize(&db, None, &mut Hold)
                        .await
                        .unwrap();

                    // A child writes the tenth key and stages the first, second, fourth, and fifth.
                    // It updates or deletes each staged key, then upserts the fifth and twelfth.
                    let value = Some(sha256::Digest::from([0xEE; 32]));
                    let other = Some(sha256::Digest::from([0xEF; 32]));
                    let read = [&keys[0], &keys[1], &keys[3], &keys[4]];
                    let updates = vec![(0, value), (1, value), (2, None), (3, value)];
                    let upserts = vec![(keys[4], other), (keys[11], value)];
                    for choice in [
                        Choice::Keep,
                        Choice::Evict,
                        Choice::Replace(keys[15]),
                        Choice::Stop,
                    ] {
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
                                let written = [
                                    (keys[9], value),
                                    (keys[0], value),
                                    (keys[1], value),
                                    (keys[3], None),
                                    (keys[4], other),
                                    (keys[11], value),
                                ]
                                .into_iter()
                                .fold(parent.new_batch::<Sha256>(), |batch, (key, value)| {
                                    batch.write(key, value)
                                })
                                .merkleize(&db, None, &mut twin)
                                .await
                                .unwrap();
                                assert_eq!(policy.visited, twin.visited, "{label}");
                                assert_eq!(staged.root(), written.root(), "{label}");
                                assert_eq!(
                                    staged.bounds().inactivity_floor,
                                    written.bounds().inactivity_floor,
                                    "{label}"
                                );
                            }
                        }
                    }
                    drop(parent);
                    db.destroy().await.unwrap();
                });
            }
        };
    }

    staged_fixed_pass_matches_unstaged_test!(
        staged_fixed_pass_matches_unstaged,
        UnorderedFixedDb<
            mmr::Family,
            deterministic::Context,
            sha256::Digest,
            sha256::Digest,
            Sha256,
            OneCap,
            Sequential,
        >,
        fixed_db_config::<OneCap>
    );

    staged_fixed_pass_matches_unstaged_test!(
        current_staged_fixed_pass_matches_unstaged,
        current::unordered::fixed::Db<
            mmr::Family,
            deterministic::Context,
            sha256::Digest,
            sha256::Digest,
            Sha256,
            OneCap,
            32,
            Sequential,
        >,
        current::tests::fixed_config::<OneCap>
    );

    /// A pass over staged writes to keys that a pending parent rewrote passes the committed
    /// locations the parent superseded without reading them, and keeping as many updates as the
    /// [`Proportional`] raise moves produces the same batch.
    #[test]
    fn policy_passes_parent_superseded_locations_unread() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("staged-parent", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed eight keys at 1..9 with a held floor, and rewrite the first and third in a
            // pending parent.
            let keys: Vec<_> = (1..9u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let rewrite = Some(sha256::Digest::from([0xDD; 32]));
            let parent = db
                .new_batch()
                .write(keys[0], rewrite)
                .write(keys[2], rewrite)
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();

            // A child stages both keys and writes them again. The raise moves three updates, and a
            // policy that keeps three passes locations 1 and 3 and reads only the updates it keeps
            // at 2, 4, and 5.
            let staged = [&keys[0], &keys[2]];
            let value = Some(sha256::Digest::from([0xEE; 32]));
            let updates = vec![(0, value), (1, value)];
            let (_, batch) = parent
                .new_batch::<Sha256>()
                .stage(&staged, &db)
                .await
                .unwrap();
            let raised = batch
                .merkleize(updates.clone(), Vec::new(), None, &db, &mut Proportional)
                .await
                .unwrap();
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let (_, batch) = parent
                .new_batch::<Sha256>()
                .stage(&staged, &db)
                .await
                .unwrap();
            let before = items();
            let mut policy = Compact {
                entries: 3,
                skips: u64::MAX,
            };
            let kept = batch
                .merkleize(updates, Vec::new(), None, &db, &mut policy)
                .await
                .unwrap();
            assert_eq!(items() - before, 3);
            assert_eq!(kept.root(), raised.root());
            drop((raised, kept, parent));
            db.destroy().await.unwrap();
        });
    }

    /// The staged prefetch covers every move the raise takes for the final write to each staged
    /// slot and for each upsert or earlier write to a live key: one per update and two per
    /// delete, plus one for the previous commit.
    #[test]
    fn staged_prefetch_counts_final_writes() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("staged-prefetch", &context);
            let db = TestDb::init(context, config, None).await.unwrap();

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
            let fill = db.bitmap.as_ref();

            let update = Some(sha256::Digest::from([0xFF; 32]));
            for (values, steps) in [
                (vec![update], 1),
                (vec![None], 2),
                (vec![None, update], 1),
                (vec![update, None], 2),
            ] {
                let (_, staged) = db.new_batch().stage(&staged_keys, &db).await.unwrap();
                let updates: Vec<_> = values
                    .iter()
                    .flat_map(|value| (0..staged_keys.len()).map(move |slot| (slot, *value)))
                    .collect();
                let (prepared, _) = staged
                    .resolve_updates_prefetched(
                        updates,
                        Vec::new(),
                        &db,
                        Limits::Proportional,
                        fill,
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    prepared.prefetched.as_ref().unwrap().0.candidates.len(),
                    1 + steps * staged_keys.len(),
                    "{values:?}"
                );
                drop(prepared);
            }

            // An earlier delete, an updating upsert, and a deleting upsert of live keys.
            let (_, staged) = db
                .new_batch()
                .write(keys[0], None)
                .stage(&staged_keys, &db)
                .await
                .unwrap();
            let upserts = vec![(keys[1], update), (keys[2], None)];
            let (prepared, _) = staged
                .resolve_updates_prefetched(Vec::new(), upserts, &db, Limits::Proportional, fill)
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

    /// A floor raise over a pending parent passes the committed locations the parent superseded
    /// without reading them, whether the batch merkleizes directly or through a staged read set,
    /// and produces the same batch as a fixed policy that keeps the update it moves.
    #[test]
    fn raise_passes_parent_superseded_locations_unread() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("raise-parent", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed eight keys at 1..9 with a held floor, and rewrite the first four in a pending
            // parent.
            let keys: Vec<_> = (1..9u8).map(|i| sha256::Digest::from([i; 32])).collect();
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let rewrite = Some(sha256::Digest::from([0xDD; 32]));
            let parent = keys[..4]
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, rewrite))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();

            // The previous commit's step moves the update at 5. The raise passes the parent's
            // superseded updates at 1..5 and reads only the update it moves.
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let before = items();
            let direct = parent
                .new_batch::<Sha256>()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(items() - before, 1);
            let (_, staged) = parent.new_batch::<Sha256>().stage(&[], &db).await.unwrap();
            let before = items();
            let staged = staged
                .merkleize(Vec::new(), Vec::new(), None, &db, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(items() - before, 1);
            let mut policy = Compact {
                entries: 1,
                skips: u64::MAX,
            };
            let kept = parent
                .new_batch::<Sha256>()
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(direct.root(), kept.root());
            assert_eq!(staged.root(), kept.root());
            drop((direct, staged, kept, parent));
            db.destroy().await.unwrap();
        });
    }

    /// A floor raise past updates its batch supersedes, interleaved with the updates it moves,
    /// reads exactly the updates it moves in one batched read.
    #[test]
    fn raise_reads_past_superseded_updates_in_one_read() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let partition = "raise-one-read";
            let config = fixed_db_config::<OneCap>(partition, &context);
            let db = TestDb::init(context.child("db"), config, None)
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
            let db = TestDb::init(context.child("cold"), config, None)
                .await
                .unwrap();

            // Updating every other one of the first 32 keys supersedes their updates at the odd
            // locations 1..32 and takes 17 steps with the previous commit. After one batched read
            // of the 16 written keys, the raise moves the updates at the even locations 2..=32 and
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

    /// A floor raise whose candidates run out passes every candidate it selected, including the
    /// superseded ones it skips unread after its last move.
    #[test]
    fn raise_floor_passes_trailing_superseded_candidates() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("raise-trailing", &context);
            let db = TestDb::init(context.child("db"), config, None)
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

            // Deleting the last two keys supersedes their updates at 3 and 4 and takes five steps.
            // A source of only the committed updates (the commit at 5 and the deletes after it
            // hold none) runs out after them, so the raise moves the updates at 1 and 2 and its
            // floor passes 4.
            let prepared = db
                .new_batch()
                .write(keys[2], None)
                .write(keys[3], None)
                .prepare(&db)
                .unwrap();
            let (merkleized, _) = prepared
                .merkleize_with_floor_scan(
                    None,
                    Vec::new(),
                    FnCandidates(|floor, tip: u64, limit, out: &mut Vec<_>| {
                        db.bitmap.as_ref().fill(floor, tip.min(5), limit, out)
                    }),
                )
                .await
                .unwrap();
            assert_eq!(merkleized.bounds().inactivity_floor, Location::new(5));
            let (_, operations) = merkleized.operations();
            assert_eq!(
                operations[2..4],
                [keys[0], keys[1]].map(|key| Operation::Update(update::Unordered(key, key)))
            );
            drop(merkleized);
            db.destroy().await.unwrap();
        });
    }

    /// Evicting an update that shares a translated-key bucket with a written key reads each
    /// committed operation once.
    #[test]
    fn policy_evicts_beside_write_reads_once() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("evicts-beside-write", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed two keys in one translated-key bucket with a held floor.
            let evicted = colliding_digest(0xAA, 0);
            let written = colliding_digest(0xAA, 1);
            let seed = [evicted, written]
                .into_iter()
                .fold(db.new_batch(), |batch, key| batch.write(key, Some(key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();

            // The pass reads both updates and evicts the first. Merkleize resolves the write from
            // the pass's read and needs no read for the eviction.
            let items =
                || crate::qmdb::any::test::counter(&context, "log_journal_items_read_total");
            let before = items();
            let mut policy = Script::new(1, u64::MAX, |_: &sha256::Digest| Choice::Evict);
            let merkleized = db
                .new_batch()
                .write(written, Some(evicted))
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(items() - before, 2);
            drop(merkleized);
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

    /// Single-step oracle for [`Candidates::fill`]: return the next floor-raise candidate in
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
    /// floor-raise moves and the trailing commit, for a db-based batch and for a chained
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
            let db = TestDb::init(context, config, None).await.unwrap();

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

    /// A child's floor raise over a pending parent reaches the parent's updates, through either
    /// merkleize path, and matches a twin merkleized after the parent is applied.
    #[test]
    fn raise_reaches_pending_parent_updates() {
        deterministic::Runner::default().start(|context| async move {
            type TestDb = UnorderedFixedDb<
                mmr::Family,
                deterministic::Context,
                sha256::Digest,
                sha256::Digest,
                Sha256,
                OneCap,
                Sequential,
            >;
            let config = fixed_db_config::<OneCap>("raise-pending-parent", &context);
            let db = TestDb::init(context.child("db"), config, None)
                .await
                .unwrap();

            // Seed two keys at 1 and 2 with a held floor, and rewrite both in a pending parent at
            // 4 and 5, so no committed update below the parent is active.
            let keys = [1u8, 2].map(|byte| sha256::Digest::from([byte; 32]));
            let seed = keys
                .iter()
                .fold(db.new_batch(), |batch, key| batch.write(*key, Some(*key)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let rewrite = sha256::Digest::from([0xDD; 32]);
            let parent = keys
                .iter()
                .fold(db.new_batch(), |batch, key| {
                    batch.write(*key, Some(rewrite))
                })
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();

            // The previous commit's step moves the parent's update at 4, whether the child
            // merkleizes directly or through a staged read set.
            let direct = parent
                .new_batch::<Sha256>()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (_, staged) = parent.new_batch::<Sha256>().stage(&[], &db).await.unwrap();
            let staged = staged
                .merkleize(Vec::new(), Vec::new(), None, &db, &mut Proportional)
                .await
                .unwrap();
            let (_, operations) = direct.operations();
            assert_eq!(
                operations[0],
                Operation::Update(update::Unordered(keys[0], rewrite))
            );
            assert_eq!(staged.root(), direct.root());

            // A twin merkleized after the parent is applied produces the same root.
            let (db, _) = db.apply_batch(parent).await.unwrap();
            let twin = db
                .new_batch()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(twin.root(), direct.root());
            drop((direct, staged, twin));
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
    /// `$config`. `$ops_root` names the method returning a merkleized batch's ops-only root.
    macro_rules! staged_policy_matches_writes {
        ($name:ident, $db:ty, $($config:ident)::+, $ops_root:ident) => {
            /// Staged writes under a policy that evicts and replaces updates in their keys'
            /// collision and predecessor buckets produce the same batch as explicit writes of the
            /// decisions, from the database and from a child of a pending parent. Replacing an
            /// update keeps the key that shares its translated-key bucket available as a deleted
            /// key's predecessor.
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
                        // lies there too. The policy decides the newest update of every other key.
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
                                (a1, newest(1, 201)),
                                (b0, newest(2, 202)),
                                (b1, value(3)),
                                (c1, value(5)),
                                (d, value(6)),
                                (z, newest(7, 207)),
                            ]
                        );

                        // A twin writes the same keys and the decisions and keeps every update.
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
                            &mut Compact {
                                entries: usize::MAX,
                                skips: u64::MAX,
                            },
                        )
                        .await
                        .unwrap();
                        assert_same(&db, &decided, &written);
                        assert_eq!(decided.$ops_root(), written.$ops_root());
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
                                &mut Compact {
                                    entries: usize::MAX,
                                    skips: u64::MAX,
                                },
                            )
                            .await
                            .unwrap();
                        assert_same(&db, &decided, &written);
                        assert_eq!(decided.$ops_root(), written.$ops_root());
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
        fixed_db_config,
        root
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
        current::tests::fixed_config,
        ops_root
    );
}
