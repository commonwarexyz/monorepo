//! Versioned applied state for QMDBs.
//!
//! [`Applied`] owns the shared-mutable core of a database: the key index, the activity
//! bitmap, and a window of undo records describing what recent applies displaced. All of
//! it is guarded by one synchronous lock with a single coherence rule: an apply mutates
//! the index and bitmap, records what it displaced, and bumps the generation under one
//! write hold; a read resolves entirely under one read hold. Guards never cross journal
//! I/O, hashing, or an await.
//!
//! Mutation goes through two doors. [`Applied::apply`] hands its closure an
//! [`ApplyGuard`] whose primitives record each displaced index entry and bitmap chunk
//! into the apply's undo record, so capture cannot be forgotten. [`Applied::begin_epoch`]
//! hands out raw access instead: it begins a new incarnation (rewind, sync handoff),
//! clearing the window, so epoch mutations record no history and views minted under the
//! old epoch become permanently [`Stale`]. Pruning is neither: it is physical GC below
//! the inactivity floor that views survive ([`Applied::prune`]).
//!
//! Reads as of an old generation are exact, not approximate: an undo record stores a
//! key's index entry at the instant an apply displaced it, so the oldest record at or
//! after a view's generation is that key's state at the view. A key with no record is
//! untouched since the view, so the live index filtered to the view's size answers (the
//! journal is append-only). The same argument covers bitmap chunks.
//!
//! The bitmap physically stays in its own [`Shared`] lock so the `current` family's
//! grafted readers can keep an `Arc` to it, but every bitmap write happens while the
//! applied write hold is held, so a reader under the applied read hold observes a frozen
//! bitmap. Independent readers of the bitmap lock alone get the same per-call atomicity
//! they get today.
//!
//! Splitting the write hold, or reading the index and window under separate holds,
//! breaks exactness. Do not "optimize" the locking here.

use crate::{
    index::Unordered as UnorderedIndex,
    merkle::{Family, Location},
    qmdb::{bitmap::Shared, delete_known_loc, operation::Key, update_known_loc},
};
use ahash::AHashSet;
use commonware_utils::{
    bitmap,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};
use std::{
    collections::VecDeque,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

/// Displaced index entries, sorted by key bytes: each key's active location before an
/// apply, or `None` when the key was absent.
type UndoKeys<F> = Vec<(Box<[u8]>, Option<Location<F>>)>;

/// Epochs are unique across every [`Applied`] instance in the process, so a view can
/// never match a database it was not minted from (e.g. across a sync handoff swap).
static NEXT_EPOCH: AtomicU64 = AtomicU64::new(0);

fn next_epoch() -> u64 {
    NEXT_EPOCH.fetch_add(1, Ordering::Relaxed)
}

/// Maximum undo records retained. Applies always evict past this depth, bounding memory
/// even for owners that never set a retention floor; views older than the cap go
/// [`Stale`].
const MAX_WINDOW_DEPTH: usize = 64;

/// A logical apply count paired with the incarnation it belongs to.
///
/// `sequence` increments once per applied batch. `epoch` is process-unique per
/// incarnation: it changes on rewind and sync handoff, and no two databases ever share
/// one, so a generation from an ended incarnation (or another database) never matches
/// the state again. Generations support equality and window-coverage checks only; they
/// carry no arithmetic and are never interchangeable with physical locations.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Generation {
    epoch: u64,
    sequence: u64,
}

/// The state has moved past what a view can answer: the view's epoch ended, its undo
/// records were evicted, or a read that requires live own-chain state (an ordered scan,
/// or the current family's merkleize) found the state moved by a foreign apply.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("view is stale")]
pub struct Stale;

/// What one apply displaced, captured at the instant of displacement.
struct ApplyUndo<F: Family, const N: usize> {
    /// The generation the displaced state belonged to.
    before: Generation,
    keys: UndoKeys<F>,
    /// Pre-images of the below-boundary bitmap chunks this apply dirtied.
    chunks: Vec<(usize, [u8; N])>,
}

impl<F: Family, const N: usize> ApplyUndo<F, N> {
    fn resolve(&self, key: &[u8]) -> Option<Option<Location<F>>> {
        self.keys
            .binary_search_by(|(k, _)| (**k).cmp(key))
            .ok()
            .map(|i| self.keys[i].1)
    }

    fn chunk(&self, idx: usize) -> Option<&[u8; N]> {
        self.chunks
            .binary_search_by_key(&idx, |(i, _)| *i)
            .ok()
            .map(|i| &self.chunks[i].1)
    }
}

/// How [`Applied::resolve`] answered a point lookup.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Resolution<F: Family> {
    /// An undo record answered for this exact key: its active location at the view's
    /// generation (`None` = absent). No journal disambiguation needed.
    Exact(Option<Location<F>>),
    /// The key is untouched since the view's generation: live index candidates filtered
    /// to the view's size. Collision candidates; disambiguate against the journal.
    Candidates(Vec<Location<F>>),
}

struct State<F: Family, I, const N: usize> {
    index: I,
    bitmap: Arc<Shared<N>>,
    /// Undo records, oldest first. Covers generations `[front.before, generation)`.
    window: VecDeque<Arc<ApplyUndo<F, N>>>,
    generation: Generation,
}

/// Handle to the shared-mutable core of a database. Cheap to clone; all clones see the
/// same state. See the module docs for the coherence rules.
pub(crate) struct Applied<F: Family, I, const N: usize> {
    inner: Arc<RwLock<State<F, I, N>>>,
}

impl<F: Family, I, const N: usize> Clone for Applied<F, I, N> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<F: Family, I, const N: usize> std::fmt::Debug for Applied<F, I, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // try_read: formatting while the write hold is held must not deadlock.
        let mut s = f.debug_struct("Applied");
        match self.inner.try_read() {
            Some(state) => s
                .field("generation", &state.generation)
                .field("window_depth", &state.window.len())
                .finish(),
            None => s.finish_non_exhaustive(),
        }
    }
}

/// The only handle to the index and bitmap during an apply. Every mutation primitive
/// records what it displaces into the apply's undo record, so capture cannot be skipped.
pub(crate) struct ApplyGuard<'a, F: Family, I, const N: usize> {
    index: &'a mut I,
    bitmap: RwLockWriteGuard<'a, bitmap::Prunable<N>>,
    /// First location this apply appends; displaced state lives below it.
    boundary: u64,
    keys: UndoKeys<F>,
    chunks: Vec<(usize, [u8; N])>,
    touched: AHashSet<usize>,
}

impl<F: Family, I: UnorderedIndex<Value = Location<F>>, const N: usize> ApplyGuard<'_, F, I, N> {
    /// Move `key` from `old` to `new` in the index.
    pub(crate) fn update(&mut self, key: &impl Key, old: Location<F>, new: Location<F>) {
        update_known_loc::<F, _>(self.index, key, old, new);
        self.keys.push((key.as_ref().into(), Some(old)));
    }

    /// Insert `key` at `new`; the key must be absent.
    pub(crate) fn insert(&mut self, key: &impl Key, new: Location<F>) {
        self.index.insert(key.as_ref(), new);
        self.keys.push((key.as_ref().into(), None));
    }

    /// Remove `key`, known to be at `old`.
    pub(crate) fn delete(&mut self, key: &impl Key, old: Location<F>) {
        delete_known_loc::<F, _>(self.index, key, old);
        self.keys.push((key.as_ref().into(), Some(old)));
    }

    /// Set the activity bit at `loc`, capturing the chunk's pre-image if the bit
    /// predates this apply.
    pub(crate) fn set_bit(&mut self, loc: u64, value: bool) {
        if loc < self.boundary {
            let idx = (loc / bitmap::Prunable::<N>::CHUNK_SIZE_BITS) as usize;
            if self.touched.insert(idx) {
                self.chunks
                    .push((idx, *self.bitmap.get_chunk_containing(loc)));
            }
        }
        self.bitmap.set_bit(loc, value);
    }

    /// Zero-extend the bitmap to `size` bits.
    pub(crate) fn extend_to(&mut self, size: u64) {
        self.bitmap.extend_to(size);
    }
}

impl<F: Family, I, const N: usize> Applied<F, I, N> {
    pub(crate) fn new(index: I, bitmap: Arc<Shared<N>>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(State {
                index,
                bitmap,
                window: VecDeque::new(),
                generation: Generation {
                    epoch: next_epoch(),
                    sequence: 0,
                },
            })),
        }
    }

    fn read(&self) -> RwLockReadGuard<'_, State<F, I, N>> {
        self.inner.read()
    }

    /// The current generation.
    pub(crate) fn generation(&self) -> Generation {
        self.read().generation
    }

    /// Apply one batch's index and bitmap mutations, record what they displaced, and
    /// bump the generation, all under one write hold.
    pub(crate) fn apply<R>(&self, f: impl FnOnce(&mut ApplyGuard<'_, F, I, N>) -> R) -> R {
        let mut state = self.inner.write();
        let state = &mut *state;
        let bitmap = state.bitmap.write();
        let boundary = bitmap::Readable::<N>::len(&*bitmap);
        let mut guard = ApplyGuard {
            index: &mut state.index,
            bitmap,
            boundary,
            keys: Vec::new(),
            chunks: Vec::new(),
            touched: AHashSet::new(),
        };
        let out = f(&mut guard);
        let ApplyGuard {
            mut keys,
            mut chunks,
            ..
        } = guard;
        keys.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        chunks.sort_unstable_by_key(|(i, _)| *i);
        state.window.push_back(Arc::new(ApplyUndo {
            before: state.generation,
            keys,
            chunks,
        }));
        if state.window.len() > MAX_WINDOW_DEPTH {
            state.window.pop_front();
        }
        state.generation.sequence += 1;
        out
    }

    /// Prune the bitmap to `prune_loc`, rounded down to a chunk boundary. Physical GC,
    /// not a logical state transition: the generation does not move and views survive.
    /// Sound because callers never prune past the inactivity floor (enforced upstream by
    /// `Db::prune`) and as-of reads of a pruned chunk answer from undo pre-images or
    /// (provably all-zero) default chunks.
    pub(crate) fn prune(&self, prune_loc: u64) {
        let state = self.inner.write();
        state.bitmap.write().prune_to_bit(prune_loc);
    }

    /// Begin a new incarnation (rewind, sync handoff): clear the undo window, mint a
    /// fresh epoch, and hand the closure raw access to rebuild the index and bitmap.
    /// Views minted under the old epoch become permanently stale.
    pub(crate) fn begin_epoch<R>(
        &self,
        f: impl FnOnce(&mut I, &mut bitmap::Prunable<N>) -> R,
    ) -> R {
        let mut state = self.inner.write();
        let state = &mut *state;
        state.window.clear();
        state.generation.epoch = next_epoch();
        let mut bitmap = state.bitmap.write();
        f(&mut state.index, &mut bitmap)
    }

    /// Evict undo records older than `floor` (the oldest generation any live view still
    /// needs). A floor from an ended epoch is ignored; the epoch bump already cleared
    /// the window.
    #[allow(dead_code)] // consumed once the owner tracks live views
    pub(crate) fn set_retention_floor(&self, floor: Generation) {
        let mut state = self.inner.write();
        if floor.epoch != state.generation.epoch {
            return;
        }
        while state
            .window
            .front()
            .is_some_and(|undo| undo.before.sequence < floor.sequence)
        {
            state.window.pop_front();
        }
    }

    /// Whether the window can answer reads as of `generation`.
    fn covers(state: &State<F, I, N>, generation: Generation) -> bool {
        if generation.epoch != state.generation.epoch
            || generation.sequence > state.generation.sequence
        {
            return false;
        }
        if generation.sequence == state.generation.sequence {
            return true;
        }
        state
            .window
            .front()
            .is_some_and(|front| front.before.sequence <= generation.sequence)
    }

    /// Run `f` against the live index under a read hold. For reads at the current tip
    /// only (the owner's own lookups, and chain reads validated against the frozen
    /// `&Db` first); versioned reads go through [`Self::resolve`].
    pub(crate) fn with_index<R>(&self, f: impl FnOnce(&I) -> R) -> R {
        f(&self.read().index)
    }
}

impl<F: Family, I: UnorderedIndex<Value = Location<F>>, const N: usize> Applied<F, I, N> {
    /// Resolve `key`'s active location as of the view identified by `generation` and
    /// `size` (the journal size at that generation). See [`Resolution`] for the two
    /// answer shapes.
    pub(crate) fn resolve(
        &self,
        generation: Generation,
        size: u64,
        key: &impl Key,
    ) -> Result<Resolution<F>, Stale> {
        let state = self.read();
        if !Self::covers(&state, generation) {
            return Err(Stale);
        }
        for undo in &state.window {
            if undo.before.sequence < generation.sequence {
                continue;
            }
            if let Some(loc) = undo.resolve(key.as_ref()) {
                return Ok(Resolution::Exact(loc));
            }
        }
        Ok(Resolution::Candidates(
            state
                .index
                .get(key.as_ref())
                .copied()
                .filter(|loc| **loc < size)
                .collect(),
        ))
    }

    /// Resolve many keys as of the view identified by `generation` and `size` under one
    /// read hold, visiting each key's candidate locations as `(key index, location)`.
    /// Undo-record answers and live candidates both report through `visit`; absent keys
    /// report nothing.
    pub(crate) fn resolve_many<K: Key>(
        &self,
        generation: Generation,
        size: u64,
        keys: &[&K],
        mut visit: impl FnMut(usize, Location<F>),
    ) -> Result<(), Stale> {
        let state = self.read();
        if !Self::covers(&state, generation) {
            return Err(Stale);
        }
        'keys: for (key_idx, key) in keys.iter().enumerate() {
            for undo in &state.window {
                if undo.before.sequence < generation.sequence {
                    continue;
                }
                if let Some(loc) = undo.resolve(key.as_ref()) {
                    if let Some(loc) = loc {
                        visit(key_idx, loc);
                    }
                    continue 'keys;
                }
            }
            for loc in state.index.get(key.as_ref()) {
                if **loc < size {
                    visit(key_idx, *loc);
                }
            }
        }
        Ok(())
    }

    /// The content of bitmap chunk `idx` as of the view identified by `generation`.
    /// Bits at or beyond the view's size may reflect later appends; consumers must
    /// bound iteration by the view's size, never by chunk content.
    #[cfg(test)]
    fn chunk(&self, generation: Generation, idx: usize) -> Result<[u8; N], Stale> {
        let state = self.read();
        if !Self::covers(&state, generation) {
            return Err(Stale);
        }
        let bitmap = state.bitmap.read();
        let chunks = AsOfChunks {
            state: &state,
            bitmap: &bitmap,
            generation,
            // Point reads have no length contract to enforce.
            size: u64::MAX,
        };
        Ok(bitmap::Readable::<N>::get_chunk(&chunks, idx))
    }

    /// Fill `out` with up to `limit` floor-raise candidates in `[scan_from, tip)` as of
    /// the view identified by `generation` and `size`, holding one read guard for the
    /// whole batch. Returns the next `scan_from`.
    ///
    /// The candidate sequence is what [`crate::qmdb::bitmap::fill_from`] would produce
    /// over the bitmap at the view's generation, truncated to the view's size.
    pub(crate) fn fill_candidates_at<T: From<u64>>(
        &self,
        generation: Generation,
        size: u64,
        scan_from: u64,
        tip: u64,
        limit: usize,
        out: &mut Vec<T>,
    ) -> Result<u64, Stale> {
        let state = self.read();
        if !Self::covers(&state, generation) {
            return Err(Stale);
        }
        let bitmap = state.bitmap.read();
        let chunks = AsOfChunks {
            state: &state,
            bitmap: &bitmap,
            generation,
            size,
        };
        Ok(crate::qmdb::bitmap::fill_from(
            &chunks, scan_from, tip, limit, out,
        ))
    }
}

/// The oldest undo record at or after `generation` that captured chunk `idx`, if any.
fn window_chunk<F: Family, I, const N: usize>(
    state: &State<F, I, N>,
    generation: Generation,
    idx: usize,
) -> Option<[u8; N]> {
    state
        .window
        .iter()
        .filter(|undo| undo.before.sequence >= generation.sequence)
        .find_map(|undo| undo.chunk(idx).copied())
}

/// Bitmap chunks as of a view: undo pre-images first, live chunks otherwise, with the
/// length frozen at the view's size. Bits at or beyond that size carry no contract;
/// consumers bound iteration by `len()`. Constructed under the applied read hold, so the
/// bitmap cannot move for its lifetime.
struct AsOfChunks<'a, F: Family, I, const N: usize> {
    state: &'a State<F, I, N>,
    bitmap: &'a bitmap::Prunable<N>,
    generation: Generation,
    size: u64,
}

impl<F: Family, I, const N: usize> bitmap::Readable<N> for AsOfChunks<'_, F, I, N> {
    fn complete_chunks(&self) -> usize {
        (self.size / bitmap::Prunable::<N>::CHUNK_SIZE_BITS) as usize
    }

    fn get_chunk(&self, idx: usize) -> [u8; N] {
        if let Some(chunk) = window_chunk(self.state, self.generation, idx) {
            return chunk;
        }
        // A pruned chunk with no pre-image was all-zero at every covered generation:
        // pruning never passes the inactivity floor, so a bit set at the view's
        // generation was cleared by a later apply, which captured the pre-image.
        if idx < self.bitmap.pruned_chunks() {
            return [0; N];
        }
        *self.bitmap.get_chunk(idx)
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let bits = self.size % bitmap::Prunable::<N>::CHUNK_SIZE_BITS;
        let idx = if bits == 0 && self.size > 0 {
            self.complete_chunks() - 1
        } else {
            self.complete_chunks()
        };
        let bits = if bits == 0 && self.size > 0 {
            bitmap::Prunable::<N>::CHUNK_SIZE_BITS
        } else {
            bits
        };
        (bitmap::Readable::<N>::get_chunk(self, idx), bits)
    }

    fn pruned_chunks(&self) -> usize {
        // Never clamp scans to the live pruned boundary: a view may scan from a floor
        // that has since been pruned past, and those chunks answer exactly (pre-image
        // or zero).
        0
    }

    fn len(&self) -> u64 {
        self.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{index::unordered::Index, merkle::mmr, translator::TwoCap};
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

    type L = Location<mmr::Family>;
    type TestIndex = Index<TwoCap, L>;
    const N: usize = 4;
    type TestApplied = Applied<mmr::Family, TestIndex, N>;

    fn key(bytes: &[u8]) -> Vec<u8> {
        bytes.to_vec()
    }

    fn with_applied(f: impl FnOnce(TestApplied)) {
        deterministic::Runner::default().start(|context| async move {
            let index = TestIndex::new(context, TwoCap);
            let bitmap = Arc::new(Shared::new(bitmap::Prunable::<N>::default()));
            f(Applied::new(index, bitmap));
        });
    }

    fn exact(resolution: Resolution<mmr::Family>) -> Option<L> {
        match resolution {
            Resolution::Exact(loc) => loc,
            Resolution::Candidates(_) => panic!("expected a window answer"),
        }
    }

    fn candidates(resolution: Resolution<mmr::Family>) -> Vec<L> {
        match resolution {
            Resolution::Exact(_) => panic!("expected live candidates"),
            Resolution::Candidates(locs) => locs,
        }
    }

    /// One apply: extend the bitmap to `size` and run `f` against the guard.
    fn apply(
        applied: &TestApplied,
        size: u64,
        f: impl FnOnce(&mut ApplyGuard<'_, mmr::Family, TestIndex, N>),
    ) -> Generation {
        applied.apply(|guard| {
            guard.extend_to(size);
            f(guard);
        });
        applied.generation()
    }

    #[test]
    fn resolve_walks_the_window_exactly() {
        with_applied(|applied| {
            let (a, b, c) = (key(&[1, 1]), key(&[2, 2]), key(&[3, 3]));

            // Gen 1: a@0, b@1.
            let g1 = apply(&applied, 2, |g| {
                g.insert(&a, L::new(0));
                g.set_bit(0, true);
                g.insert(&b, L::new(1));
                g.set_bit(1, true);
            });

            // Gen 2: rewrite a to 2, delete b, create c@3.
            let g2 = apply(&applied, 4, |g| {
                g.update(&a, L::new(0), L::new(2));
                g.set_bit(2, true);
                g.set_bit(0, false);
                g.delete(&b, L::new(1));
                g.set_bit(1, false);
                g.insert(&c, L::new(3));
                g.set_bit(3, true);
            });

            // As of g1: a@0, b@1, c absent. All answered by gen-2's record.
            assert_eq!(exact(applied.resolve(g1, 2, &a).unwrap()), Some(L::new(0)));
            assert_eq!(exact(applied.resolve(g1, 2, &b).unwrap()), Some(L::new(1)));
            assert_eq!(exact(applied.resolve(g1, 2, &c).unwrap()), None);

            // As of g2 (current): no record is newer, so the live index answers.
            assert_eq!(candidates(applied.resolve(g2, 4, &a).unwrap()), [L::new(2)]);
            assert!(candidates(applied.resolve(g2, 4, &b).unwrap()).is_empty());
            assert_eq!(candidates(applied.resolve(g2, 4, &c).unwrap()), [L::new(3)]);

            // Gen 3: rewrite a again. The OLDEST record at or after g1 must win for g1.
            apply(&applied, 5, |g| {
                g.update(&a, L::new(2), L::new(4));
                g.set_bit(4, true);
                g.set_bit(2, false);
            });
            assert_eq!(exact(applied.resolve(g1, 2, &a).unwrap()), Some(L::new(0)));
            assert_eq!(exact(applied.resolve(g2, 4, &a).unwrap()), Some(L::new(2)));
        });
    }

    #[test]
    fn untouched_keys_fall_through_with_the_size_filter() {
        with_applied(|applied| {
            let (a, b) = (key(&[1, 1]), key(&[9, 9]));
            let g1 = apply(&applied, 1, |g| {
                g.insert(&a, L::new(0));
                g.set_bit(0, true);
            });
            apply(&applied, 2, |g| {
                g.insert(&b, L::new(1));
                g.set_bit(1, true);
            });

            // `a` is untouched since g1: live candidates answer. `b` was created after
            // g1; its record answers absent.
            assert_eq!(candidates(applied.resolve(g1, 1, &a).unwrap()), [L::new(0)]);
            assert_eq!(exact(applied.resolve(g1, 1, &b).unwrap()), None);

            // A collision sibling created after the view is filtered by size, not by a
            // record: `c` collides with `a` under TwoCap.
            let c = key(&[1, 1, 7]);
            let g2 = applied.generation();
            apply(&applied, 3, |g| {
                g.insert(&c, L::new(2));
                g.set_bit(2, true);
            });
            // As of g2, `a`'s bucket now holds locations 0 and 2; the filter drops 2.
            assert_eq!(candidates(applied.resolve(g2, 2, &a).unwrap()), [L::new(0)]);
        });
    }

    /// Bits `[0, size)` of a chunk; bits past a view's size carry no contract.
    fn bits(chunk: [u8; N], size: u64) -> Vec<bool> {
        (0..size)
            .map(|bit| chunk[(bit / 8) as usize] & (1 << (bit % 8)) != 0)
            .collect()
    }

    #[test]
    fn chunks_answer_from_pre_images() {
        with_applied(|applied| {
            // Chunk 0 covers bits [0, 32). Fill a few bits.
            let a = key(&[1, 1]);
            let g1 = apply(&applied, 3, |g| {
                g.insert(&a, L::new(0));
                g.set_bit(0, true);
                g.set_bit(2, true);
            });
            let bits_at_g1 = bits(applied.chunk(g1, 0).unwrap(), 3);
            assert_eq!(bits_at_g1, [true, false, true]);

            // Clearing bit 0 dirties chunk 0; the pre-image must keep answering for g1
            // even though the same apply also set bit 3 (above g1's size) in that chunk.
            let g2 = apply(&applied, 4, |g| {
                g.update(&a, L::new(0), L::new(3));
                g.set_bit(3, true);
                g.set_bit(0, false);
            });
            assert_eq!(bits(applied.chunk(g1, 0).unwrap(), 3), bits_at_g1);
            assert_eq!(
                bits(applied.chunk(g2, 0).unwrap(), 4),
                [false, false, true, true]
            );
        });
    }

    #[test]
    fn eviction_and_epochs_make_views_stale() {
        with_applied(|applied| {
            let a = key(&[1, 1]);
            let g1 = apply(&applied, 1, |g| {
                g.insert(&a, L::new(0));
                g.set_bit(0, true);
            });
            let g2 = apply(&applied, 2, |g| {
                g.update(&a, L::new(0), L::new(1));
                g.set_bit(1, true);
                g.set_bit(0, false);
            });

            // Evict records older than g2: g1 loses coverage, g2 keeps it.
            applied.set_retention_floor(g2);
            assert_eq!(applied.resolve(g1, 1, &a), Err(Stale));
            assert_eq!(applied.chunk(g1, 0), Err(Stale));
            assert!(applied.resolve(g2, 2, &a).is_ok());

            // An epoch bump stales every prior generation, including the tip.
            applied.begin_epoch(|_, _| {});
            let g3 = applied.generation();
            assert_eq!(applied.resolve(g2, 2, &a), Err(Stale));
            assert!(applied.resolve(g3, 2, &a).is_ok());

            // A retention floor from the ended epoch is ignored.
            applied.set_retention_floor(g2);
            assert!(applied.resolve(g3, 2, &a).is_ok());
        });
    }

    #[test]
    fn window_cap_evicts_old_generations() {
        with_applied(|applied| {
            let a = key(&[1, 1]);
            let g0 = apply(&applied, 1, |g| {
                g.insert(&a, L::new(0));
                g.set_bit(0, true);
            });
            let mut loc = 0;
            for i in 0..MAX_WINDOW_DEPTH as u64 + 1 {
                apply(&applied, i + 2, |g| {
                    g.update(&a, L::new(loc), L::new(i + 1));
                    g.set_bit(i + 1, true);
                    g.set_bit(loc, false);
                });
                loc = i + 1;
            }
            // g0's records were evicted by the cap; the tip still answers.
            assert_eq!(applied.resolve(g0, 1, &a), Err(Stale));
            assert!(applied.resolve(applied.generation(), loc + 1, &a).is_ok());
        });
    }

    #[test]
    fn views_never_match_a_foreign_database() {
        deterministic::Runner::default().start(|context| async move {
            let mut instances = Vec::new();
            for label in ["a", "b"] {
                let index = TestIndex::new(context.child(label), TwoCap);
                let bitmap = Arc::new(Shared::new(bitmap::Prunable::<N>::default()));
                instances.push(Applied::<mmr::Family, _, N>::new(index, bitmap));
            }
            let a = key(&[1, 1]);
            let g = apply(&instances[0], 1, |guard| {
                g_insert(guard, &a);
            });
            apply(&instances[1], 1, |guard| {
                g_insert(guard, &a);
            });
            // Same sequence, different instance: epochs are process-unique, so the
            // foreign database can never answer for this view.
            assert_eq!(instances[1].resolve(g, 1, &a), Err(Stale));
            assert!(instances[0].resolve(g, 1, &a).is_ok());
        });
    }

    fn g_insert(guard: &mut ApplyGuard<'_, mmr::Family, TestIndex, N>, key: &[u8]) {
        guard.insert(&key.to_vec(), L::new(0));
        guard.set_bit(0, true);
    }
}
