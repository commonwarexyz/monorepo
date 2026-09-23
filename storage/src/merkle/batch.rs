//! A lightweight batch layer over a merkleized structure.
//!
//! # Overview
//!
//! [`UnmerkleizedBatch`] accumulates mutations (appends and overwrites) against a parent
//! [`MerkleizedBatch`]. Calling [`UnmerkleizedBatch::merkleize`] computes dirty Merkle nodes and
//! produces a new [`MerkleizedBatch`]. Batches can be stacked to arbitrary depth
//! via `Arc`-backed parent pointers, so multiple forks can coexist on the same parent.
//!
//! # Lifecycle
//!
//! ```text
//!                          Mem
//!                           |
//!              MerkleizedBatch::from_mem()      (root batch, no data)
//!                           |
//!                      new_batch()
//!                           |
//!                           v
//!                    UnmerkleizedBatch          (accumulate mutations)
//!                           |
//!                  merkleize(&mem, hasher)
//!                           |
//!                           v
//!                 Arc<MerkleizedBatch>           (immutable, merkleized nodes)
//!                           |
//!                  mem.apply_batch(&batch)
//!                           |
//!                           v
//!                          Mem                   (committed)
//! ```
//!
//! # Parent chain and memory
//!
//! Each [`MerkleizedBatch`] stores its own local data (appended nodes and overwrites)
//! plus `Arc` refs to each retained ancestor's data, collected during
//! [`UnmerkleizedBatch::merkleize`]. These ancestor batches' data are used by
//! [`Mem::apply_batch`] to replay uncommitted ancestors without requiring the
//! ancestor batches to still be alive.
//!
//! A `Weak` pointer to the parent is kept for [`MerkleizedBatch::get_node`] lookups
//! (used during a child's merkleize) and for walking the chain to collect ancestor
//! batch data. Committed-and-dropped ancestors truncate the `Weak` walk, leaving their
//! data in the committed [`Mem`]. `ancestor_base_size` records the position before the
//! oldest retained ancestor so the remaining suffix is replayed at the correct offset.
//!
//! During [`UnmerkleizedBatch::merkleize`], the parent is held as a strong `Arc`
//! (keeping it alive for the walk), and the `Weak` chain is walked to collect
//! ancestor data. After merkleize, the parent is downgraded to `Weak`.
//!
//! In a pipelining pattern (build next batch from prev, apply prev, repeat), each batch
//! holds at most one ancestor batch (its immediate parent's data, as an `Arc` ref).
//! When that batch is applied and dropped, the ancestor data is freed. Memory per
//! batch is O(batch size), never growing with chain depth.
//!
//! [`MerkleizedBatch::get_node`] resolves positions stored in the batch chain only.
//! For positions in the committed structure, callers fall through to [`Mem::get_node`]
//! (or an adapter that layers a batch over a `Mem`).
//!
//! # Batch invalidation
//!
//! A batch becomes _invalid_ when an unapplied ancestor is dropped, or a sibling fork has been
//! applied. Invalid batches must not be used: their methods may return incorrect data rather than
//! erroring.
//!
//! Pruning the base after a batch has been merkleized does not invalidate it: prune and apply
//! commute (see [`Mem::apply_batch`]). An unmerkleized batch still reads sibling digests from the
//! base while merkleizing, so it must be merkleized before the base is pruned past any leaf it
//! updates.
//!
//! # Parallel appends
//!
//! [`UnmerkleizedBatch::add_many`] splits its leaves into contiguous ranges, one per worker. A
//! range's positions run from its first leaf up to the next range's first leaf. Each worker hashes
//! its leaves and then, from the lowest height up, computes every node in its positions whose
//! leaves all belong to its range. The remaining nodes in its positions depend on earlier leaves
//! (at most two per height) and are computed by [`UnmerkleizedBatch::merkleize`]. In an MMB,
//! delayed merging can also place a node built only from one range's leaves after the next range
//! starts, so that node is left for `merkleize` too.
//!
//! # Example (MMR)
//!
//! ```ignore
//! let hasher = StandardHasher::<Sha256>::new(ForwardFold);
//! let mut mmr = Mmr::new();
//!
//! // Fork two independent speculative chains from the same base.
//! let a1 = mmr.new_batch()
//!     .add(&hasher, b"a1")
//!     .merkleize(&mmr, &hasher);
//! let b1 = mmr.new_batch()
//!     .add(&hasher, b"b1")
//!     .merkleize(&mmr, &hasher);
//!
//! // Commit A1.
//! mmr.apply_batch(&a1).unwrap();
//! ```

use crate::merkle::{
    Error, Family, Location, Position, Readable, hasher::Hasher, mem::Mem, path, proof::Proof,
};
use ahash::RandomState;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
#[cfg(feature = "std")]
use commonware_codec::Write;
use commonware_cryptography::Digest;
use commonware_parallel::{Sequential, Strategy};
#[cfg(feature = "std")]
use commonware_utils::NZUsize;
#[cfg(feature = "std")]
use core::num::NonZeroUsize;
use core::ops::Range;

/// Overwritten node digests keyed by position.
pub(crate) type Overwrites<F, D> = hashbrown::HashMap<Position<F>, D, RandomState>;

/// Fewest leaves each `add_many` worker hashes. Smaller ranges leave more nodes to `merkleize`.
#[cfg(feature = "std")]
const MIN_RANGE_LEAVES: NonZeroUsize = NZUsize!(64);

/// Push a dirty node position into its height bucket, growing the outer Vec as needed.
fn push_dirty<F: Family>(buckets: &mut Vec<Vec<Position<F>>>, height: u32, pos: Position<F>) {
    let h = height as usize;
    if buckets.len() <= h {
        buckets.resize_with(h + 1, Vec::new);
    }
    buckets[h].push(pos);
}

// ---------------------------------------------------------------------------
// UnmerkleizedBatch
// ---------------------------------------------------------------------------

/// A speculative batch whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    parent: Arc<MerkleizedBatch<F, D, S>>,
    appended: Vec<D>,
    overwrites: Overwrites<F, D>,
    /// Dirty internal node positions bucketed by height. Outer index is height; inner Vec
    /// holds positions at that height in push order (monotonically increasing for
    /// `add_leaf_digest` and `add_many`; may contain duplicates from interleaved `mark_dirty`
    /// walks, deduped in `merkleize`). Avoids the BTreeSet insert cost and a final global sort.
    dirty_nodes: Vec<Vec<Position<F>>>,
}

impl<F: Family, D: Digest, S: Strategy> UnmerkleizedBatch<F, D, S> {
    /// Create a new batch from `parent`.
    pub fn new(parent: Arc<MerkleizedBatch<F, D, S>>) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: Overwrites::default(),
            dirty_nodes: Vec::new(),
        }
    }

    /// Return a reference to the batch's strategy.
    pub fn strategy(&self) -> &S {
        &self.parent.strategy
    }

    /// Retain the live parent chain up to the first dropped weak link.
    ///
    /// Nodes beyond that link are read from committed state.
    #[cfg(feature = "std")]
    pub(crate) fn retain_ancestors(&self) -> Vec<Arc<MerkleizedBatch<F, D, S>>> {
        let mut ancestors = Vec::new();
        let mut current = Some(Arc::clone(&self.parent));
        while let Some(batch) = current {
            current = batch.parent.as_ref().and_then(Weak::upgrade);
            ancestors.push(batch);
        }
        ancestors
    }

    /// The total number of nodes visible through this batch.
    pub(crate) fn size(&self) -> Position<F> {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location<F> {
        Location::try_from(self.size()).expect("invalid size")
    }

    /// Resolve a node: own data -> parent chain -> `base` fallback.
    fn get_node(&self, base: &Mem<F, D>, pos: Position<F>) -> Option<D> {
        if pos >= self.size() {
            return None;
        }
        if let Some(d) = self.overwrites.get(&pos) {
            return Some(*d);
        }
        let parent_size = self.parent.size();
        if pos >= parent_size {
            let index = (*pos - *parent_size) as usize;
            return self.appended.get(index).copied();
        }
        if let Some(d) = self.parent.get_node(pos) {
            return Some(d);
        }
        base.get_node(pos)
    }

    /// Store a digest at the given position.
    fn store_node(&mut self, pos: Position<F>, digest: D) {
        let parent_size = self.parent.size();
        if pos >= parent_size {
            let index = (*pos - *parent_size) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }

    /// Mark ancestors of the leaf at `loc` as dirty up to its peak.
    ///
    /// Walks from peak to leaf (top-down) using [`path::Iterator`], then inserts dirty markers
    /// bottom-up. Bottom-up ordering enables a best-effort early exit: if the node at a given
    /// height matches the most recently pushed entry for that bucket, we stop walking since
    /// the walk that pushed it already marked everything above. This catches consecutive
    /// shared-path walks in O(1); non-consecutive duplicates (a prior walk for a different
    /// subtree landed in the bucket after the shared ancestors) are not detected here and are
    /// collapsed by the per-bucket sort+dedup in `merkleize`.
    fn mark_dirty(&mut self, loc: Location<F>) {
        let mut first_leaf = Location::new(0);
        for (peak_pos, height) in F::peaks(self.size()) {
            let leaves_in_peak = 1u64 << height;
            if loc >= first_leaf + leaves_in_peak {
                first_leaf += leaves_in_peak;
                continue;
            }

            let mut buf = [(Position::new(0), Position::new(0), 0u32); path::MAX_PATH_LEN];
            let mut len = 0;
            for item in path::Iterator::new(peak_pos, height, first_leaf, loc) {
                buf[len] = item;
                len += 1;
            }
            for &(parent_pos, _, h) in buf[..len].iter().rev() {
                let h_idx = h as usize;
                if self.dirty_nodes.get(h_idx).and_then(|b| b.last()) == Some(&parent_pos) {
                    break;
                }
                push_dirty(&mut self.dirty_nodes, h, parent_pos);
            }
            return;
        }

        panic!("leaf {loc} not found (size: {})", self.size());
    }

    /// Add a pre-computed leaf digest.
    pub fn add_leaf_digest(mut self, digest: D) -> Self {
        self.append_leaf_digest(digest, self.leaves(), self.size());
        self
    }

    /// Append a leaf digest and any parent placeholders.
    ///
    /// `leaves` is the leaf index this digest occupies and `size` is the starting node count.
    /// Returns the new size.
    fn append_leaf_digest(
        &mut self,
        digest: D,
        leaves: Location<F>,
        mut size: Position<F>,
    ) -> Position<F> {
        self.appended.push(digest);
        size += 1;

        for height in F::parent_heights(leaves) {
            self.appended.push(D::EMPTY);
            push_dirty(&mut self.dirty_nodes, height, size);
            size += 1;
        }

        size
    }

    /// Add a run of pre-computed leaf digests, in order.
    #[cfg(feature = "std")]
    pub fn add_leaf_digests(mut self, digests: impl IntoIterator<Item = D>) -> Self {
        // Each leaf also appends its parent placeholders, so reserve for the full node count.
        let digests = digests.into_iter();
        let n = digests.size_hint().0 as u64;
        let leaves = self.leaves();
        let mut size = self.size();
        let end = leaves.checked_add(n).expect("leaf count overflow");
        let additional = (*Position::try_from(end).expect("size overflow") - *size) as usize;
        self.appended.reserve(additional);

        // Maintain leaf position and location incrementally to avoid recomputation on every iteration.
        for (i, digest) in (0u64..).zip(digests) {
            size = self.append_leaf_digest(digest, leaves + i, size);
        }
        self
    }

    /// Hash `element` and add it as a leaf.
    pub fn add(self, hasher: &impl Hasher<F, Digest = D>, element: &[u8]) -> Self {
        let digest = hasher.leaf_digest(self.size(), element);
        self.add_leaf_digest(digest)
    }

    /// Encode and hash `items` across the strategy, adding their leaf digests in order.
    ///
    /// Equivalent to calling [`add`](Self::add) with each item's encoding.
    ///
    /// # Panics
    ///
    /// Panics if the leaf count would exceed [`Family::MAX_LEAVES`].
    #[cfg(feature = "std")]
    pub fn add_many<Item: Write + Sync>(
        mut self,
        hasher: &impl Hasher<F, Digest = D>,
        items: &[Item],
    ) -> Self {
        if items.is_empty() {
            return self;
        }
        let first = self.leaves();
        let start = self.size();
        let end = first
            .checked_add(items.len() as u64)
            .expect("leaf count overflow");
        let size = Position::try_from(end).expect("size overflow");
        let parent_size = self.parent.size();
        let strategy = &self.parent.strategy;
        self.appended
            .resize((*size - *parent_size) as usize, D::EMPTY);
        let nodes = &mut self.appended[(*start - *parent_size) as usize..];

        let deferred = strategy.run_batches(items.len(), MIN_RANGE_LEAVES, 1, |batches| {
            let Some(batches) = batches else {
                return vec![build_range(hasher, items, first, start, nodes)];
            };
            batches.map_collect_vec(
                |ranges| {
                    // Slices are split off in order, so the ranges must cover `items` in order.
                    let mut rest = nodes;
                    let mut base = start;
                    let mut covered = 0;
                    let prepared = ranges
                        .into_iter()
                        .map(|range| {
                            assert!(
                                range.start == covered && range.start < range.end,
                                "batches must cover the items in order"
                            );
                            covered = range.end;
                            let range_first = first + range.start as u64;
                            let range_items = &items[range];
                            let next =
                                F::location_to_position(range_first + range_items.len() as u64);
                            let slice = rest
                                .split_off_mut(..(*next - *base) as usize)
                                .expect("range ends within the batch");
                            let batch = (range_first, range_items, base, slice);
                            base = next;
                            batch
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(
                        covered,
                        items.len(),
                        "batches must cover the items in order"
                    );
                    prepared
                },
                |(first, items, base, nodes)| build_range(hasher, items, first, base, nodes),
            )
        });
        for (height, pos) in deferred.into_iter().flatten() {
            push_dirty(&mut self.dirty_nodes, height, pos);
        }
        self
    }

    /// Validate that `loc` refers to an in-bounds, non-pruned leaf and return its position.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeafOutOfBounds`] if `loc` is beyond the current leaf count, or
    /// [`Error::ElementPruned`] if the leaf has been pruned.
    fn validate_loc(&self, loc: Location<F>) -> Result<Position<F>, Error<F>> {
        if loc >= self.leaves() {
            return Err(Error::LeafOutOfBounds(loc));
        }
        if loc < self.parent.pruning_boundary() {
            return Err(Error::ElementPruned(Position::try_from(loc)?));
        }
        Position::try_from(loc)
    }

    /// Update the leaf at `loc` to `element`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeafOutOfBounds`] if `loc` is not an existing leaf.
    /// Returns [`Error::ElementPruned`] if the leaf has been pruned.
    pub fn update_leaf(
        mut self,
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
        element: &[u8],
    ) -> Result<Self, Error<F>> {
        let pos = self.validate_loc(loc)?;
        let digest = hasher.leaf_digest(pos, element);
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(self)
    }

    /// Overwrite the digest of an existing leaf and mark ancestors dirty.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(mut self, loc: Location<F>, digest: D) -> Result<Self, Error<F>> {
        let pos = self.validate_loc(loc)?;
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(self)
    }

    /// Batch update multiple leaf digests.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_batched(mut self, updates: &[(Location<F>, D)]) -> Result<Self, Error<F>> {
        // Validate all first so a later failure can't leave a partially-applied batch.
        for (loc, _) in updates {
            self.validate_loc(*loc)?;
        }
        for (loc, digest) in updates {
            let pos = Position::try_from(*loc).expect("validated above");
            self.store_node(pos, *digest);
            self.mark_dirty(*loc);
        }
        Ok(self)
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed dirty nodes.
    /// `base` provides committed node data as fallback during hash computation.
    pub fn merkleize(
        mut self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<MerkleizedBatch<F, D, S>> {
        // Each bucket accumulates positions in push order, which for `add_leaf_digest` and
        // `add_many` is already ascending; the stable `sort` is cheap on such near-sorted input.
        // The dedup then collapses any duplicates that slipped past `mark_dirty`'s last-entry
        // check.
        let mut buckets = core::mem::take(&mut self.dirty_nodes);
        for bucket in &mut buckets {
            bucket.sort();
            bucket.dedup();
        }
        for (height, positions) in buckets.iter().enumerate() {
            if positions.is_empty() {
                continue;
            }
            self.merkleize_bucket(base, hasher, positions, height as u32);
        }

        // Collect ancestor data by walking the parent chain (strong Arc + Weak walk).
        let (ancestor_base_size, ancestor_appended, ancestor_overwrites) =
            collect_ancestor_batches(&self.parent);

        let parent_size = self.parent.size();
        Arc::new(MerkleizedBatch {
            parent: Some(Arc::downgrade(&self.parent)),
            appended: Arc::new(self.appended),
            overwrites: Arc::new(self.overwrites),
            parent_size,
            base_size: self.parent.base_size,
            ancestor_base_size,
            pruning_boundary: self.parent.pruning_boundary(),
            ancestor_appended,
            ancestor_overwrites,
            strategy: self.parent.strategy.clone(),
        })
    }

    /// Fetch the child digests of the node at `pos`.
    fn child_digests(&self, base: &Mem<F, D>, pos: Position<F>, height: u32) -> (D, D) {
        let (left, right) = F::children(pos, height);
        let left = self.get_node(base, left).expect("left child missing");
        let right = self.get_node(base, right).expect("right child missing");
        (left, right)
    }

    /// Compute the digests of `positions` two at a time so the hasher can make progress on both
    /// concurrently, appending `(position, digest)` results to `output`.
    fn zip_nodes(
        &self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        positions: &[Position<F>],
        height: u32,
        output: &mut Vec<(Position<F>, D)>,
    ) {
        let (pairs, remainder) = positions.as_chunks::<2>();
        for pair in pairs {
            let (left, right) = (pair[0], pair[1]);
            let (ll, lr) = self.child_digests(base, left, height);
            let (rl, rr) = self.child_digests(base, right, height);
            let (left_digest, right_digest) =
                hasher.node_digest_pair([(left, &ll, &lr), (right, &rl, &rr)]);
            output.push((left, left_digest));
            output.push((right, right_digest));
        }
        if let [pos] = remainder {
            let (left, right) = self.child_digests(base, *pos, height);
            output.push((*pos, hasher.node_digest(*pos, &left, &right)));
        }
    }

    /// Compute digests for one height's dirty nodes via the configured strategy.
    ///
    /// Positions are split evenly across the strategy's workers so each worker can pair
    /// adjacent nodes for [`Hasher::node_digest_pair`]. The chunk size is rounded up to
    /// even so no pair straddles a chunk boundary.
    fn merkleize_bucket(
        &mut self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        positions: &[Position<F>],
        height: u32,
    ) {
        let chunk = positions
            .len()
            .div_ceil(self.parent.strategy.manual().parallelism())
            .max(1)
            .next_multiple_of(2);
        let computed: Vec<Vec<(Position<F>, D)>> =
            self.parent.strategy.map_init_collect_vec_with_multiplier(
                positions.chunks(chunk),
                chunk,
                || hasher.clone(),
                |hasher, positions| {
                    let mut computed = Vec::with_capacity(positions.len());
                    self.zip_nodes(base, &*hasher, positions, height, &mut computed);
                    computed
                },
            );
        for nodes in computed {
            for (pos, digest) in nodes {
                self.store_node(pos, digest);
            }
        }
    }
}

/// Hash `items` into the leaves starting at `first` and compute every node in `nodes` (the
/// positions from `base`) whose leaves are all among them. Returns the height and position of
/// each remaining node in `nodes`.
#[cfg(feature = "std")]
fn build_range<F: Family, D: Digest, Item: Write>(
    hasher: &impl Hasher<F, Digest = D>,
    items: &[Item],
    first: Location<F>,
    base: Position<F>,
    nodes: &mut [D],
) -> Vec<(u32, Position<F>)> {
    // A node is in `nodes` when one of these leaves creates it: `first < birth <= leaves_end`.
    let leaves_end = first + items.len() as u64;
    let index = |pos: Position<F>| (*pos - *base) as usize;

    let mut buf = Vec::new();
    for (loc, item) in (*first..).zip(items) {
        let pos = F::location_to_position(Location::new(loc));
        buf.clear();
        item.write(&mut buf);
        nodes[index(pos)] = hasher.leaf_digest(pos, &buf);
    }

    for height in 1..=(items.len() as u64).ilog2() {
        let width = 1u64 << height;
        let children = |nodes: &[D], leaf: Location<F>| {
            let left = F::subtree_root_position(leaf, height - 1);
            let right = F::subtree_root_position(leaf + width / 2, height - 1);
            (nodes[index(left)], nodes[index(right)])
        };

        // Subtrees starting at or after `first`, in order, until one is created after this range.
        let mut next_leaf = (*first).next_multiple_of(width);
        let mut next = || {
            let leaf = Location::new(next_leaf);
            if F::subtree_birth_size(leaf, height)? > leaves_end {
                return None;
            }
            next_leaf += width;
            Some((leaf, F::subtree_root_position(leaf, height)))
        };
        while let Some((left_leaf, left)) = next() {
            let Some((right_leaf, right)) = next() else {
                let (l, r) = children(nodes, left_leaf);
                nodes[index(left)] = hasher.node_digest(left, &l, &r);
                break;
            };
            let (ll, lr) = children(nodes, left_leaf);
            let (rl, rr) = children(nodes, right_leaf);
            let (left_digest, right_digest) =
                hasher.node_digest_pair([(left, &ll, &lr), (right, &rl, &rr)]);
            nodes[index(left)] = left_digest;
            nodes[index(right)] = right_digest;
        }
    }

    // Remaining nodes start before `first`. Birth sizes fall with `leaf`, so stop at `first`.
    let mut deferred = Vec::new();
    for height in 1..=(*leaves_end).ilog2() {
        let width = 1u64 << height;
        let height_start = deferred.len();
        let mut leaf = (*first).next_multiple_of(width);
        while let Some(prev) = leaf.checked_sub(width) {
            leaf = prev;
            let loc = Location::new(leaf);
            let Some(birth) = F::subtree_birth_size(loc, height) else {
                continue;
            };
            if birth <= first {
                break;
            }
            if birth <= leaves_end {
                deferred.push((height, F::subtree_root_position(loc, height)));
            }
        }
        // Keep each height ascending so dirty buckets stay sorted.
        deferred[height_start..].reverse();
    }
    deferred
}

/// Collect ancestor batch data by walking the parent + its Weak chain.
/// Returns the size before the oldest retained ancestor followed by its appended nodes and
/// overwrites in root-to-tip order. Skips empty batches (e.g. root batches from `from_mem`).
#[allow(clippy::type_complexity)]
fn collect_ancestor_batches<F: Family, D: Digest, S: Strategy>(
    parent: &Arc<MerkleizedBatch<F, D, S>>,
) -> (Position<F>, Vec<Arc<Vec<D>>>, Vec<Arc<Overwrites<F, D>>>) {
    let mut appended = Vec::new();
    let mut overwrites = Vec::new();
    let mut base_size = parent.parent_size;

    // Parent is alive (strong Arc held by UnmerkleizedBatch).
    if !parent.appended.is_empty() || !parent.overwrites.is_empty() {
        appended.push(Arc::clone(&parent.appended));
        overwrites.push(Arc::clone(&parent.overwrites));
    }

    // Walk Weak chain for grandparents+.
    let mut current = parent.parent.as_ref().and_then(Weak::upgrade);
    while let Some(batch) = current {
        base_size = batch.parent_size;
        if !batch.appended.is_empty() || !batch.overwrites.is_empty() {
            appended.push(Arc::clone(&batch.appended));
            overwrites.push(Arc::clone(&batch.overwrites));
        }
        current = batch.parent.as_ref().and_then(Weak::upgrade);
    }

    appended.reverse();
    overwrites.reverse();
    (base_size, appended, overwrites)
}

// ---------------------------------------------------------------------------
// MerkleizedBatch
// ---------------------------------------------------------------------------

/// A speculative batch whose dirty Merkle nodes have been computed, in contrast to
/// [`UnmerkleizedBatch`].
#[derive(Debug)]
pub struct MerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    /// The parent batch in the chain, if any.
    parent: Option<Weak<Self>>,

    /// This batch's appended nodes only (not accumulated from ancestors).
    pub(crate) appended: Arc<Vec<D>>,

    /// This batch's overwrites only (not accumulated from ancestors).
    pub(crate) overwrites: Arc<Overwrites<F, D>>,

    /// Number of nodes in the parent batch.
    pub(crate) parent_size: Position<F>,

    /// Number of committed nodes when the batch chain was forked. Inherited unchanged
    /// by all descendants. Used by `apply_batch` to detect already-committed ancestors.
    pub(crate) base_size: Position<F>,

    /// Number of nodes before the oldest retained ancestor batch.
    pub(crate) ancestor_base_size: Position<F>,

    /// Pruning boundary of the [`Mem`] when the batch chain was forked. Inherited
    /// unchanged by all descendants, like `base_size`.
    pruning_boundary: Location<F>,

    /// Arc refs to each ancestor's appended nodes, collected during merkleize while
    /// ancestors are alive. Root-to-tip order.
    pub(crate) ancestor_appended: Vec<Arc<Vec<D>>>,

    /// Arc refs to each ancestor's overwrites, collected during merkleize while
    /// ancestors are alive. Root-to-tip order.
    pub(crate) ancestor_overwrites: Vec<Arc<Overwrites<F, D>>>,

    pub(crate) strategy: S,
}

impl<F: Family, D: Digest> MerkleizedBatch<F, D, Sequential> {
    /// Create a root batch representing the committed state of `mem`, with the default
    /// [`Sequential`] strategy.
    pub fn from_mem(mem: &Mem<F, D>) -> Arc<Self> {
        Self::from_mem_with_strategy(mem, Sequential)
    }
}

impl<F: Family, D: Digest, S: Strategy> MerkleizedBatch<F, D, S> {
    /// Create a root batch representing the committed state of `mem`, using `strategy`
    /// for merkleization.
    pub fn from_mem_with_strategy(mem: &Mem<F, D>, strategy: S) -> Arc<Self> {
        Arc::new(Self {
            parent: None,
            appended: Arc::new(Vec::new()),
            overwrites: Arc::new(Overwrites::default()),
            parent_size: mem.size(),
            base_size: mem.size(),
            ancestor_base_size: mem.size(),
            pruning_boundary: mem.pruning_boundary(),
            ancestor_appended: Vec::new(),
            ancestor_overwrites: Vec::new(),
            strategy,
        })
    }

    /// The total number of nodes visible through this batch.
    pub fn size(&self) -> Position<F> {
        Position::new(*self.parent_size + self.appended.len() as u64)
    }

    /// Resolve a node: own data -> Weak parent chain.
    ///
    /// Returns `None` for positions that only exist in the committed [`Mem`].
    /// Callers that need committed data should fall back to [`Mem::get_node`]
    /// (or use a layered adapter such as the one in `qmdb::current::batch`).
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
        if pos >= self.size() {
            return None;
        }
        if let Some(d) = self.overwrites.get(&pos) {
            return Some(*d);
        }
        if pos >= self.parent_size {
            let i = (*pos - *self.parent_size) as usize;
            return self.appended.get(i).copied();
        }
        // Walk Weak parent chain.
        let mut current = self.parent.as_ref().and_then(Weak::upgrade);
        while let Some(batch) = current {
            if let Some(d) = batch.overwrites.get(&pos) {
                return Some(*d);
            }
            if pos >= batch.parent_size {
                let i = (*pos - *batch.parent_size) as usize;
                return batch.appended.get(i).copied();
            }
            current = batch.parent.as_ref().and_then(Weak::upgrade);
        }
        None
    }

    /// Compute the root digest after this batch's mutations using `inactive_peaks` and the bagging
    /// carried by `hasher`.
    pub fn root(
        &self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        let leaves = self.leaves();
        let peaks: Vec<D> = F::peaks(self.size())
            .map(|(peak_pos, _)| {
                self.get_node(peak_pos)
                    .or_else(|| base.get_node(peak_pos))
                    .expect("peak missing")
            })
            .collect();
        hasher.root(leaves, inactive_peaks, peaks.iter())
    }

    /// Inclusion proof for the element at `loc` using `inactive_peaks` and the bagging carried by
    /// `hasher`.
    pub fn proof(
        &self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(base, hasher, loc..loc + 1, inactive_peaks)
            .map_err(|e| match e {
                Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
                _ => e,
            })
    }

    /// Inclusion proof for all elements in `range` using `inactive_peaks` and the bagging carried
    /// by `hasher`.
    pub fn range_proof(
        &self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        range: Range<Location<F>>,
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        crate::merkle::proof::build_range_proof(
            hasher,
            self.leaves(),
            inactive_peaks,
            range,
            |pos| Self::get_node(self, pos).or_else(|| base.get_node(pos)),
            Error::ElementPruned,
        )
    }

    /// Items before this location have been pruned.
    pub const fn pruning_boundary(&self) -> Location<F> {
        self.pruning_boundary
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location<F> {
        Location::try_from(self.size()).expect("invalid size")
    }

    /// Create a child batch on top of this merkleized batch.
    ///
    /// The batch becomes invalid if any ancestor is dropped before being applied, or a sibling
    /// fork has been applied.
    pub fn new_batch(self: &Arc<Self>) -> UnmerkleizedBatch<F, D, S> {
        UnmerkleizedBatch::new(Arc::clone(self))
    }

    /// Number of nodes in the committed Mem when the batch chain was forked.
    pub const fn base_size(&self) -> Position<F> {
        self.base_size
    }

    /// Return a reference to the batch's strategy.
    pub const fn strategy(&self) -> &S {
        &self.strategy
    }
}

impl<F: Family, D: Digest, S: Strategy> Readable for MerkleizedBatch<F, D, S> {
    type Family = F;
    type Digest = D;

    fn size(&self) -> Position<F> {
        Self::size(self)
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        Self::get_node(self, pos)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{Bagging::ForwardFold, hasher::Standard, mem::Mem};
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::{Manual, Rayon};
    use commonware_runtime::{Runner as _, deterministic};

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn mem_root<F: Family>(mem: &Mem<F, D>, hasher: &H) -> D {
        mem.root(hasher, 0).unwrap()
    }

    fn batch_root<F: Family>(
        base: &Mem<F, D>,
        batch: &MerkleizedBatch<F, D, commonware_parallel::Sequential>,
        hasher: &H,
    ) -> D {
        batch.root(base, hasher, 0).unwrap()
    }

    fn build_reference<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new();
        let batch = {
            let mut batch = mem.new_batch();
            for i in 0u64..n {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(hasher, &element);
            }
            batch.merkleize(&mem, hasher)
        };
        mem.apply_batch(&batch).unwrap();
        mem
    }

    fn consistency_with_reference<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            for &n in &[1u64, 2, 10, 100, 199] {
                let reference = build_reference::<F>(&hasher, n);
                let base = Mem::<F, D>::new();
                let mut batch = base.new_batch();
                for i in 0..n {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                let merkleized = batch.merkleize(&base, &hasher);
                let mut result = Mem::<F, D>::new();
                result.apply_batch(&merkleized).unwrap();
                assert_eq!(
                    mem_root(&result, &hasher),
                    mem_root(&reference, &hasher),
                    "root mismatch for n={n}"
                );
            }
        });
    }

    fn lifecycle<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let base_root = mem_root(&base, &hasher);
            let mut batch = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&base, &hasher);
            assert_ne!(batch_root(&base, &merkleized, &hasher), base_root);
            assert_eq!(mem_root(&base, &hasher), base_root);
            // Apply and verify proof from the resulting Mem.
            let mut applied = base;
            applied.apply_batch(&merkleized).unwrap();
            let loc = Location::<F>::new(55);
            let element = hasher.digest(&55u64.to_be_bytes());
            let proof = applied.proof(&hasher, loc, 0).unwrap();
            assert!(proof.verify_element_inclusion(
                &hasher,
                &element,
                loc,
                &batch_root(&applied, &merkleized, &hasher)
            ));
        });
    }

    fn apply_batch<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let mut base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..75 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&base, &hasher);
            let new_root = batch_root(&base, &merkleized, &hasher);
            base.apply_batch(&merkleized).unwrap();
            assert_eq!(mem_root(&base, &hasher), new_root);
            let reference = build_reference::<F>(&hasher, 75);
            assert_eq!(mem_root(&base, &hasher), mem_root(&reference, &hasher));
        });
    }

    fn multiple_forks<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let base_root = mem_root(&base, &hasher);
            let mut ba = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                ba = ba.add(&hasher, &element);
            }
            let ma = ba.merkleize(&base, &hasher);
            let mut bb = base.new_batch();
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                bb = bb.add(&hasher, &element);
            }
            let mb = bb.merkleize(&base, &hasher);
            assert_ne!(
                batch_root(&base, &ma, &hasher),
                batch_root(&base, &mb, &hasher)
            );
            assert_ne!(batch_root(&base, &ma, &hasher), base_root);
            assert_eq!(mem_root(&base, &hasher), base_root);
        });
    }

    fn fork_of_fork_reads<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let mut ba = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                ba = ba.add(&hasher, &element);
            }
            let ma = ba.merkleize(&base, &hasher);
            let mut bb = ma.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                bb = bb.add(&hasher, &element);
            }
            let mb = bb.merkleize(&base, &hasher);
            let reference = build_reference::<F>(&hasher, 70);
            assert_eq!(
                batch_root(&base, &mb, &hasher),
                mem_root(&reference, &hasher)
            );
            // Apply both batches and verify proofs from the resulting Mem.
            let mut applied = base;
            applied.apply_batch(&ma).unwrap();
            applied.apply_batch(&mb).unwrap();
            for i in [0u64, 25, 55, 65, 69] {
                let loc = Location::<F>::new(i);
                let element = hasher.digest(&i.to_be_bytes());
                let proof = applied.proof(&hasher, loc, 0).unwrap();
                assert!(proof.verify_element_inclusion(
                    &hasher,
                    &element,
                    loc,
                    &batch_root(&applied, &mb, &hasher)
                ));
            }
        });
    }

    fn update_leaf_digest_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 100);
            let base_root = mem_root(&base, &hasher);
            let updated = Sha256::fill(0xFF);
            let m = base
                .new_batch()
                .update_leaf_digest(Location::new(5), updated)
                .unwrap()
                .merkleize(&base, &hasher);
            assert_ne!(batch_root(&base, &m, &hasher), base_root);
            let pos5 = Position::<F>::try_from(Location::new(5)).unwrap();
            let original = base.get_node(pos5).unwrap();
            let m2 = base
                .new_batch()
                .update_leaf_digest(Location::new(5), original)
                .unwrap()
                .merkleize(&base, &hasher);
            assert_eq!(batch_root(&base, &m2, &hasher), base_root);
        });
    }

    fn update_and_add<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let base_root = mem_root(&base, &hasher);
            let updated = Sha256::fill(0xAA);
            let mut batch = base
                .new_batch()
                .update_leaf_digest(Location::new(10), updated)
                .unwrap();
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let m = batch.merkleize(&base, &hasher);
            assert_ne!(batch_root(&base, &m, &hasher), base_root);
            let pos10 = Position::<F>::try_from(Location::new(10)).unwrap();
            assert_eq!(m.get_node(pos10), Some(updated));
        });
    }

    fn update_leaf_batched_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 100);
            let base_root = mem_root(&base, &hasher);
            let updated = Sha256::fill(0xBB);
            let locs = [0u64, 10, 50, 99];
            let updates: Vec<(Location<F>, D)> =
                locs.iter().map(|&i| (Location::new(i), updated)).collect();
            let m = base
                .new_batch()
                .update_leaf_batched(&updates)
                .unwrap()
                .merkleize(&base, &hasher);
            assert_ne!(batch_root(&base, &m, &hasher), base_root);
            let restore: Vec<(Location<F>, D)> = locs
                .iter()
                .map(|&l| {
                    let pos = Position::<F>::try_from(Location::new(l)).unwrap();
                    (Location::new(l), base.get_node(pos).unwrap())
                })
                .collect();
            let m2 = base
                .new_batch()
                .update_leaf_batched(&restore)
                .unwrap()
                .merkleize(&base, &hasher);
            assert_eq!(batch_root(&base, &m2, &hasher), base_root);
        });
    }

    fn proof_verification<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let m = batch.merkleize(&base, &hasher);
            // Apply and verify proofs from the resulting Mem.
            let mut applied = base;
            applied.apply_batch(&m).unwrap();
            let loc = Location::<F>::new(55);
            let element = hasher.digest(&55u64.to_be_bytes());
            let proof = applied.proof(&hasher, loc, 0).unwrap();
            assert!(proof.verify_element_inclusion(
                &hasher,
                &element,
                loc,
                &batch_root(&applied, &m, &hasher)
            ));
            let range = Location::<F>::new(50)..Location::new(55);
            let rp = applied.range_proof(&hasher, range.clone(), 0).unwrap();
            let elements: Vec<D> = (50u64..55)
                .map(|i| hasher.digest(&i.to_be_bytes()))
                .collect();
            assert!(rp.verify_range_inclusion(
                &hasher,
                &elements,
                range.start,
                &batch_root(&applied, &m, &hasher)
            ));
        });
    }

    /// A proof requested directly from a speculative [`MerkleizedBatch`], before it is applied to
    /// `base`, must succeed even when the Merkle path needs nodes that only exist in `base`. The
    /// batch chain alone does not contain nodes committed before the fork.
    fn speculative_proof_uses_base_fallback<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let m = batch.merkleize(&base, &hasher);
            let expected_root = batch_root(&base, &m, &hasher);

            // A newly appended leaf: the path needs the committed peaks.
            let loc = Location::<F>::new(52);
            let element = hasher.digest(&52u64.to_be_bytes());
            let proof = m.proof(&base, &hasher, loc, 0).unwrap();
            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &expected_root));

            // A committed leaf: the path needs committed siblings as well as committed peaks.
            let loc = Location::<F>::new(49);
            let element = hasher.digest(&49u64.to_be_bytes());
            let proof = m.proof(&base, &hasher, loc, 0).unwrap();
            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &expected_root));

            // A range of new leaves and a range spanning the fork boundary.
            for range in [
                Location::<F>::new(50)..Location::<F>::new(55),
                Location::<F>::new(45)..Location::<F>::new(55),
            ] {
                let elements: Vec<D> = (*range.start..*range.end)
                    .map(|i| hasher.digest(&i.to_be_bytes()))
                    .collect();
                let rp = m.range_proof(&base, &hasher, range.clone(), 0).unwrap();
                assert!(rp.verify_range_inclusion(&hasher, &elements, range.start, &expected_root));
            }
        });
    }

    fn empty_batch<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let base_root = mem_root(&base, &hasher);
            let m = base.new_batch().merkleize(&base, &hasher);
            assert_eq!(batch_root(&base, &m, &hasher), base_root);
        });
    }

    fn batch_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&base, &hasher);
            let mut batch_again = merkleized.new_batch();
            for i in 55u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_again = batch_again.add(&hasher, &element);
            }
            let reference = build_reference::<F>(&hasher, 60);
            assert_eq!(
                batch_root(&base, &batch_again.merkleize(&base, &hasher), &hasher),
                mem_root(&reference, &hasher)
            );
        });
    }

    fn sequential_apply_batch<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let mut base = build_reference::<F>(&hasher, 50);
            let mut b1 = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                b1 = b1.add(&hasher, &element);
            }
            let m1 = b1.merkleize(&base, &hasher);
            base.apply_batch(&m1).unwrap();
            let mut b2 = base.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                b2 = b2.add(&hasher, &element);
            }
            let m2 = b2.merkleize(&base, &hasher);
            base.apply_batch(&m2).unwrap();
            let reference = build_reference::<F>(&hasher, 70);
            assert_eq!(mem_root(&base, &hasher), mem_root(&reference, &hasher));
        });
    }

    fn batch_on_pruned_base<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let mut base = build_reference::<F>(&hasher, 100);
            base.prune(Location::new(27)).unwrap();
            let mut batch = base.new_batch();
            for i in 100u64..110 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let m = batch.merkleize(&base, &hasher);
            let expected_root = batch_root(&base, &m, &hasher);
            // Apply and verify proofs from the resulting Mem.
            let mut applied = base;
            applied.apply_batch(&m).unwrap();
            let loc = Location::<F>::new(80);
            let element = hasher.digest(&80u64.to_be_bytes());
            let proof = applied.proof(&hasher, loc, 0).unwrap();
            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &expected_root));
            assert!(matches!(
                applied.proof(&hasher, Location::new(0), 0),
                Err(Error::ElementPruned(_))
            ));
        });
    }

    fn three_deep_stacking<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let mut base = build_reference::<F>(&hasher, 100);
            let da = Sha256::fill(0xDD);
            let db = Sha256::fill(0xEE);
            let ma = base
                .new_batch()
                .update_leaf_digest(Location::new(5), da)
                .unwrap()
                .merkleize(&base, &hasher);
            let mb = ma
                .new_batch()
                .update_leaf_digest(Location::new(10), db)
                .unwrap()
                .merkleize(&base, &hasher);
            let mut bc = mb.new_batch();
            for i in 300u64..310 {
                let element = hasher.digest(&i.to_be_bytes());
                bc = bc.add(&hasher, &element);
            }
            let mc = bc.merkleize(&base, &hasher);
            let c_root = batch_root(&base, &mc, &hasher);
            base.apply_batch(&mc).unwrap();
            assert_eq!(mem_root(&base, &hasher), c_root);
        });
    }

    fn overwrite_collision<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let mut base = build_reference::<F>(&hasher, 100);
            let dx = Sha256::fill(0xAA);
            let dy = Sha256::fill(0xBB);
            let ma = base
                .new_batch()
                .update_leaf_digest(Location::new(5), dx)
                .unwrap()
                .merkleize(&base, &hasher);
            let mb = ma
                .new_batch()
                .update_leaf_digest(Location::new(5), dy)
                .unwrap()
                .merkleize(&base, &hasher);
            let b_root = batch_root(&base, &mb, &hasher);
            base.apply_batch(&mb).unwrap();
            assert_eq!(mem_root(&base, &hasher), b_root);
            let pos5 = Position::<F>::try_from(Location::new(5)).unwrap();
            assert_eq!(base.get_node(pos5), Some(dy));
        });
    }

    fn update_appended_leaf<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let updated = Sha256::fill(0xEE);
            let m = batch
                .update_leaf_digest(Location::new(52), updated)
                .unwrap()
                .merkleize(&base, &hasher);
            let pos52 = Position::<F>::try_from(Location::new(52)).unwrap();
            assert_eq!(m.get_node(pos52), Some(updated));
            let mut reference = build_reference::<F>(&hasher, 60);
            let batch = reference
                .new_batch()
                .update_leaf_digest(Location::new(52), updated)
                .unwrap()
                .merkleize(&reference, &hasher);
            reference.apply_batch(&batch).unwrap();
            assert_eq!(
                batch_root(&base, &m, &hasher),
                mem_root(&reference, &hasher)
            );
        });
    }

    fn update_leaf_element<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let base_root = mem_root(&base, &hasher);
            let element = b"updated-element";
            let m = base
                .new_batch()
                .update_leaf(&hasher, Location::new(5), element)
                .unwrap()
                .merkleize(&base, &hasher);
            assert_ne!(batch_root(&base, &m, &hasher), base_root);
            let mut base = base;
            let batch = base
                .new_batch()
                .update_leaf(&hasher, Location::new(5), element)
                .unwrap()
                .merkleize(&base, &hasher);
            base.apply_batch(&batch).unwrap();
            assert_eq!(batch_root(&base, &m, &hasher), mem_root(&base, &hasher));
        });
    }

    fn update_out_of_bounds<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 50);
            let r1 = base
                .new_batch()
                .update_leaf_digest(Location::new(50), Sha256::fill(0xFF));
            assert!(matches!(r1, Err(Error::LeafOutOfBounds(_))));
            let updates = [(Location::<F>::new(50), Sha256::fill(0xFF))];
            let r2 = base.new_batch().update_leaf_batched(&updates);
            assert!(matches!(r2, Err(Error::LeafOutOfBounds(_))));
        });
    }

    /// A strategy that always splits work into `parallelism` batches, run on one thread.
    fn split_strategy(parallelism: usize) -> Manual<Rayon> {
        Rayon::new(NZUsize!(1))
            .unwrap()
            .with_parallelism(NZUsize!(parallelism))
            .manual()
    }

    /// `add_many` near the maximum leaf count, where some subtree roots can never exist.
    fn add_many_at_limit<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            for (first, count) in [((1u64 << 62) - 1, 1u64), (*F::MAX_LEAVES - 7, 7)] {
                let first = Location::new(first);
                let pinned = F::nodes_to_pin(first).map(|_| D::EMPTY).collect();
                let base = Mem::<F, D>::from_components(Vec::new(), first, pinned).unwrap();
                let items: Vec<u64> = (0..count).collect();

                let batch = base
                    .new_batch()
                    .add_many(&hasher, &items)
                    .merkleize(&base, &hasher);
                let mut expected = base.new_batch();
                for item in &items {
                    expected = expected.add(&hasher, &item.to_be_bytes());
                }
                let expected = expected.merkleize(&base, &hasher);

                assert_eq!(batch.appended, expected.appended, "first={first}");
                assert_eq!(
                    batch.root(&base, &hasher, 0).unwrap(),
                    expected.root(&base, &hasher, 0).unwrap(),
                    "first={first}"
                );
            }
        });
    }

    /// Repeated `add_many` calls on real worker threads, interleaved with `add` and `update_leaf`
    /// on a pruned base, match the same operations one leaf at a time on a parent batch.
    fn add_many_mixed_operations<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            for parallelism in [1, 2, 3, 8] {
                let strategy = Rayon::new(NZUsize!(parallelism)).unwrap().manual();
                let mut base = build_reference::<F>(&hasher, 63);
                base.prune_all();
                let parent = base
                    .new_batch()
                    .add(&hasher, b"parent")
                    .merkleize(&base, &hasher);

                let mut actual = MerkleizedBatch::from_mem_with_strategy(&base, strategy)
                    .new_batch()
                    .add(&hasher, b"parent");
                let mut expected = parent.new_batch();
                for count in [0, 1, 2, 63, 64, 127, 128, 129, 256, 511, 1000] {
                    actual = actual.add(&hasher, b"prefix");
                    expected = expected.add(&hasher, b"prefix");
                    let items: Vec<u64> = (0..count).collect();
                    actual = actual.add_many(&hasher, &items);
                    for item in &items {
                        expected = expected.add(&hasher, &item.to_be_bytes());
                    }
                    for loc in [63, *actual.leaves() / 2 + 32, *actual.leaves() - 1] {
                        let loc = Location::new(loc);
                        actual = actual.update_leaf(&hasher, loc, b"update").unwrap();
                        expected = expected.update_leaf(&hasher, loc, b"update").unwrap();
                    }
                }
                let actual = actual.merkleize(&base, &hasher);
                let expected = expected.merkleize(&base, &hasher);

                assert_eq!(
                    actual.root(&base, &hasher, 0).unwrap(),
                    expected.root(&base, &hasher, 0).unwrap(),
                    "workers={parallelism}"
                );
                for pos in *parent.size()..*actual.size() {
                    let pos = Position::new(pos);
                    assert_eq!(
                        actual.get_node(pos),
                        expected.get_node(pos),
                        "workers={parallelism} pos={pos}"
                    );
                }
            }
        });
    }

    /// `add_many` split across workers matches adding the same items one at a time, on top of
    /// committed leaves and an unapplied parent batch.
    fn add_many_matches_add<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            for parallelism in [2, 3, 8] {
                let strategy = split_strategy(parallelism);
                for committed in [0u64, 1, 2, 3, 6, 7, 14, 30, 62, 63, 100] {
                    let base = build_reference::<F>(&hasher, committed);
                    for (parent_count, count) in [
                        (0, 1),
                        (0, 127),
                        (0, 128),
                        (0, 129),
                        (0, 300),
                        (0, 1000),
                        (5, 200),
                        (130, 777),
                    ] {
                        let items: Vec<u64> = (0..(parent_count + count) as u64).collect();
                        let (parent_items, child_items) = items.split_at(parent_count);

                        let parent =
                            MerkleizedBatch::from_mem_with_strategy(&base, strategy.clone())
                                .new_batch()
                                .add_many(&hasher, parent_items)
                                .merkleize(&base, &hasher);
                        let child = parent
                            .new_batch()
                            .add_many(&hasher, child_items)
                            .merkleize(&base, &hasher);

                        let mut expected_parent = base.new_batch();
                        for item in parent_items {
                            expected_parent = expected_parent.add(&hasher, &item.to_be_bytes());
                        }
                        let expected_parent = expected_parent.merkleize(&base, &hasher);
                        let mut expected_child = expected_parent.new_batch();
                        for item in child_items {
                            expected_child = expected_child.add(&hasher, &item.to_be_bytes());
                        }
                        let expected_child = expected_child.merkleize(&base, &hasher);

                        let case = format!(
                            "{parallelism} workers, {committed}+{parent_count}+{count} leaves"
                        );
                        assert_eq!(parent.appended, expected_parent.appended, "{case}");
                        assert_eq!(child.appended, expected_child.appended, "{case}");
                        assert_eq!(
                            child.root(&base, &hasher, 0).unwrap(),
                            expected_child.root(&base, &hasher, 0).unwrap(),
                            "{case}"
                        );
                    }
                }
            }
        });
    }

    /// Updates and appends after `add_many` replace the nodes it built.
    fn add_many_then_mutate<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            let base = build_reference::<F>(&hasher, 30);
            let items: Vec<u64> = (0..600).collect();

            let mut batch = MerkleizedBatch::from_mem_with_strategy(&base, split_strategy(4))
                .new_batch()
                .add_many(&hasher, &items);
            let mut expected = base.new_batch();
            for item in &items {
                expected = expected.add(&hasher, &item.to_be_bytes());
            }
            for loc in [3, 47, 629] {
                batch = batch
                    .update_leaf(&hasher, Location::new(loc), b"updated")
                    .unwrap();
                expected = expected
                    .update_leaf(&hasher, Location::new(loc), b"updated")
                    .unwrap();
            }
            let batch = batch.add(&hasher, b"extra").merkleize(&base, &hasher);
            let expected = expected.add(&hasher, b"extra").merkleize(&base, &hasher);

            assert_eq!(batch.appended, expected.appended);
            assert_eq!(batch.overwrites, expected.overwrites);
            assert_eq!(
                batch.root(&base, &hasher, 0).unwrap(),
                expected.root(&base, &hasher, 0).unwrap()
            );
        });
    }

    // --- MMR tests ---

    #[test]
    fn mmr_add_many_matches_add() {
        add_many_matches_add::<crate::mmr::Family>();
    }

    #[test]
    fn mmr_add_many_then_mutate() {
        add_many_then_mutate::<crate::mmr::Family>();
    }

    #[test]
    fn mmr_add_many_at_limit() {
        add_many_at_limit::<crate::mmr::Family>();
    }

    #[test]
    fn mmr_add_many_mixed_operations() {
        add_many_mixed_operations::<crate::mmr::Family>();
    }

    #[test]
    fn mmr_consistency() {
        consistency_with_reference::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_lifecycle() {
        lifecycle::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_apply_batch() {
        apply_batch::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_multiple_forks() {
        multiple_forks::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_fork_of_fork_reads() {
        fork_of_fork_reads::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_digest() {
        update_leaf_digest_roundtrip::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_and_add() {
        update_and_add::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_batched() {
        update_leaf_batched_roundtrip::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_proof_verification() {
        proof_verification::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_speculative_proof_uses_base_fallback() {
        speculative_proof_uses_base_fallback::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_empty_batch() {
        empty_batch::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_batch_roundtrip() {
        batch_roundtrip::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_sequential_apply_batch() {
        sequential_apply_batch::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_batch_on_pruned_base() {
        batch_on_pruned_base::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_three_deep_stacking() {
        three_deep_stacking::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_overwrite_collision() {
        overwrite_collision::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_appended_leaf() {
        update_appended_leaf::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_element() {
        update_leaf_element::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_out_of_bounds() {
        update_out_of_bounds::<crate::mmr::Family>();
    }

    // --- MMB tests ---

    #[test]
    fn mmb_add_many_matches_add() {
        add_many_matches_add::<crate::mmb::Family>();
    }

    #[test]
    fn mmb_add_many_then_mutate() {
        add_many_then_mutate::<crate::mmb::Family>();
    }

    #[test]
    fn mmb_add_many_at_limit() {
        add_many_at_limit::<crate::mmb::Family>();
    }

    #[test]
    fn mmb_add_many_mixed_operations() {
        add_many_mixed_operations::<crate::mmb::Family>();
    }

    #[test]
    fn mmb_consistency() {
        consistency_with_reference::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_lifecycle() {
        lifecycle::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_apply_batch() {
        apply_batch::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_multiple_forks() {
        multiple_forks::<crate::mmb::Family>();
    }

    /// A structure rebuilt from the pinned nodes at `n - 1` plus the final element generates a
    /// verifiable proof for that element against the root at `n`.
    fn tip_proof_from_pins<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new(ForwardFold);
            for &n in &[1u64, 2, 3, 8, 100, 199] {
                let reference = build_reference::<F>(&hasher, n);
                let boundary = Location::new(n - 1);
                let pin_map = reference.nodes_to_pin(boundary);
                let pinned_nodes: Vec<D> =
                    F::nodes_to_pin(boundary).map(|pos| pin_map[&pos]).collect();
                let element = hasher.digest(&(n - 1).to_be_bytes());

                let peaks = F::peaks(F::location_to_position(Location::new(n))).count();
                for inactive_peaks in 0..=peaks.min(2) {
                    let root = reference.root(&hasher, inactive_peaks).unwrap();

                    let mut rebuilt = Mem::<F, D>::init(crate::merkle::mem::Config {
                        nodes: Vec::new(),
                        pruning_boundary: boundary,
                        pinned_nodes: pinned_nodes.clone(),
                    })
                    .unwrap();
                    let batch = rebuilt
                        .new_batch()
                        .add(&hasher, &element)
                        .merkleize(&rebuilt, &hasher);
                    rebuilt.apply_batch(&batch).unwrap();
                    assert_eq!(rebuilt.root(&hasher, inactive_peaks).unwrap(), root);

                    let proof = rebuilt.proof(&hasher, boundary, inactive_peaks).unwrap();
                    assert!(proof.verify_range_inclusion(&hasher, &[element], boundary, &root));
                }
            }
        });
    }

    #[test]
    fn mmr_tip_proof_from_pins() {
        tip_proof_from_pins::<crate::mmr::Family>();
    }

    #[test]
    fn mmb_tip_proof_from_pins() {
        tip_proof_from_pins::<crate::mmb::Family>();
    }

    #[test]
    fn mmb_fork_of_fork_reads() {
        fork_of_fork_reads::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_digest() {
        update_leaf_digest_roundtrip::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_and_add() {
        update_and_add::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_batched() {
        update_leaf_batched_roundtrip::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_proof_verification() {
        proof_verification::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_speculative_proof_uses_base_fallback() {
        speculative_proof_uses_base_fallback::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_empty_batch() {
        empty_batch::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_batch_roundtrip() {
        batch_roundtrip::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_sequential_apply_batch() {
        sequential_apply_batch::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_batch_on_pruned_base() {
        batch_on_pruned_base::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_three_deep_stacking() {
        three_deep_stacking::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_overwrite_collision() {
        overwrite_collision::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_appended_leaf() {
        update_appended_leaf::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_element() {
        update_leaf_element::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_out_of_bounds() {
        update_out_of_bounds::<crate::mmb::Family>();
    }
}
