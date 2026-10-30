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
//! data in the committed [`Mem`]. Each retained record carries the size and peaks before
//! and after its changes, so [`Mem::apply_batch`] can find the structure's state in the
//! chain and replay only the records that follow it.
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
//! applied. Invalid batches must not be used, because their methods may return incorrect data or
//! panic. [`Mem::apply_batch`] is the exception. It returns an error unless the structure is at
//! a state the chain reached before the batch: the base of its oldest retained ancestor or the
//! tip of one of them.
//!
//! Pruning the base after a batch has been merkleized does not invalidate it: prune and apply
//! commute (see [`Mem::apply_batch`]). An unmerkleized batch still reads sibling digests from the
//! base while merkleizing, so it must be merkleized before the base is pruned past any leaf it
//! updates.
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
    Error, Family, Location, Position, Readable, hasher::Hasher, mem::Mem, proof::Proof,
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
use core::cell::Cell;
use core::{iter::Peekable, num::NonZeroUsize, ops::Range};

#[cfg(feature = "std")]
std::thread_local! {
    /// Per-thread encoding scratch, reused across Rayon splits and batches to
    /// avoid repeatedly allocating and growing a fresh buffer.
    static ENCODE_BUF: Cell<Vec<u8>> = const { Cell::new(Vec::new()) };
}

/// The most [`ENCODE_BUF`] capacity a thread keeps between items. A buffer grown past it by an
/// unusually large item is freed after that item instead of being held for the thread's lifetime.
#[cfg(feature = "std")]
const MAX_RETAINED_ENCODE_CAPACITY: usize = 64 * 1024;

/// Overwritten node digests keyed by position.
pub(crate) type Overwrites<F, D> = hashbrown::HashMap<Position<F>, D, RandomState>;

/// Push a node position into the list for its height, growing the outer Vec as needed.
fn push_node<F: Family>(levels: &mut Vec<Vec<Position<F>>>, height: u32, pos: Position<F>) {
    let h = height as usize;
    if levels.len() <= h {
        levels.resize_with(h + 1, Vec::new);
    }
    levels[h].push(pos);
}

/// Return every internal node that needs hashing, once each, grouped by height.
///
/// `overwritten_leaves` lists overwritten leaves from the parent batch; `new_internal_nodes`
/// lists new internal nodes by height. Neither input may contain duplicates.
/// Ancestors above the parent's peaks are new nodes already recorded in `new_internal_nodes`.
fn plan_hashes<F: Family>(
    parent_size: Position<F>,
    mut overwritten_leaves: Vec<Location<F>>,
    new_internal_nodes: Vec<Vec<Position<F>>>,
) -> Vec<Vec<Position<F>>> {
    let mut levels = new_internal_nodes;
    if overwritten_leaves.is_empty() {
        return levels;
    }
    overwritten_leaves.sort_unstable();
    let mut leaves = overwritten_leaves.into_iter().peekable();
    let mut first_leaf = Location::new(0);
    for (pos, height) in F::peaks(parent_size) {
        let Some(&next) = leaves.peek() else {
            break;
        };
        let end = first_leaf + (1u64 << height);
        if next < end {
            mark_dirty_subtree(&mut levels, pos, height, first_leaf, &mut leaves);
        }
        first_leaf = end;
    }
    assert!(
        leaves.peek().is_none(),
        "updated leaf outside parent forest"
    );
    levels
}

/// Record the overwritten leaves' ancestors within this subtree, once each.
/// Advance `leaves` past those leaves.
///
/// `leaves` must be sorted, with its next leaf inside the subtree.
fn mark_dirty_subtree<F: Family>(
    levels: &mut Vec<Vec<Position<F>>>,
    pos: Position<F>,
    height: u32,
    first_leaf: Location<F>,
    leaves: &mut Peekable<impl Iterator<Item = Location<F>>>,
) {
    if height == 0 {
        leaves.next();
        return;
    }
    push_node(levels, height, pos);
    let (left, right) = F::children(pos, height);
    let mid = first_leaf + (1u64 << (height - 1));
    if leaves.peek().is_some_and(|loc| *loc < mid) {
        mark_dirty_subtree(levels, left, height - 1, first_leaf, leaves);
    }
    let end = first_leaf + (1u64 << height);
    if leaves.peek().is_some_and(|loc| *loc < end) {
        mark_dirty_subtree(levels, right, height - 1, mid, leaves);
    }
}

/// A speculative batch whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    parent: Arc<MerkleizedBatch<F, D, S>>,
    appended: Vec<D>,
    /// Nodes this batch overwrites, by position. Every key is below the parent's size, and nodes at
    /// or above it are in `appended`. Until [`Self::merkleize`] hashes internal nodes, the map
    /// holds only overwritten parent leaves.
    overwrites: Overwrites<F, D>,
    /// Internal nodes created by this batch, recorded once each and grouped by height.
    new_internal_nodes: Vec<Vec<Position<F>>>,
}

impl<F: Family, D: Digest, S: Strategy> UnmerkleizedBatch<F, D, S> {
    /// Create a new batch from `parent`.
    pub fn new(parent: Arc<MerkleizedBatch<F, D, S>>) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: Overwrites::default(),
            new_internal_nodes: Vec::new(),
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

        // Overwrites only hold positions below the parent's size (see `store_node`).
        let parent_size = self.parent.size();
        if pos >= parent_size {
            let index = (*pos - *parent_size) as usize;
            return self.appended.get(index).copied();
        }
        if let Some(d) = self.overwrites.get(&pos) {
            return Some(*d);
        }
        if let Some(d) = self.parent.get_node(pos) {
            return Some(d);
        }
        base.get_node(pos)
    }

    /// Store a digest at the given position.
    ///
    /// Positions at or above the parent's size belong to nodes this batch appended and go to
    /// `appended`, indexed from the parent's size. Positions below it go to `overwrites`.
    fn store_node(&mut self, pos: Position<F>, digest: D) {
        let parent_size = self.parent.size();
        if pos >= parent_size {
            let index = (*pos - *parent_size) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }

    /// Return every internal node this batch must hash, once each, grouped by height.
    fn hash_plan(&mut self) -> Vec<Vec<Position<F>>> {
        let overwritten_leaves = self
            .overwrites
            .keys()
            .map(|&pos| {
                Location::try_from(pos).expect("only leaves are overwritten before merkleize")
            })
            .collect();
        plan_hashes(
            self.parent.size(),
            overwritten_leaves,
            core::mem::take(&mut self.new_internal_nodes),
        )
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
            push_node(&mut self.new_internal_nodes, height, size);
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
    #[cfg(feature = "std")]
    pub(crate) fn add_many<Item: Write + Send + Sync>(
        self,
        hasher: &impl Hasher<F, Digest = D>,
        items: &[Item],
    ) -> Self {
        let first = self.leaves();
        let digests = self
            .strategy()
            .map_collect_vec(items.iter().enumerate(), |(i, item)| {
                let pos = Position::try_from(first + i as u64).expect("valid leaf location");

                // Leave the thread-local slot empty while encoding and hashing, so callbacks
                // can re-enter add_many without accessing this call's buffer.
                let mut buf = ENCODE_BUF.take();
                buf.clear();
                item.write(&mut buf);
                let digest = hasher.leaf_digest(pos, buf.as_slice());
                if buf.capacity() <= MAX_RETAINED_ENCODE_CAPACITY {
                    ENCODE_BUF.set(buf);
                }
                digest
            });
        self.add_leaf_digests(digests)
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
        Ok(self)
    }

    /// Overwrite the digest of an existing leaf.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(mut self, loc: Location<F>, digest: D) -> Result<Self, Error<F>> {
        let pos = self.validate_loc(loc)?;
        self.store_node(pos, digest);
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
        }
        Ok(self)
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed dirty nodes.
    /// `base` provides committed node data as fallback during hash computation.
    ///
    /// # Panics
    ///
    /// Panics if a node it reads is in neither the batch chain nor `base`. This happens when an
    /// unapplied ancestor that appended the node has been dropped, or when `base` has been pruned
    /// past a leaf this batch updates. The [module docs](crate::merkle::batch) describe both cases
    /// under "Batch invalidation".
    pub fn merkleize(
        mut self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<MerkleizedBatch<F, D, S>> {
        let levels = self.hash_plan();

        // Dirty nodes below the parent's size land in `overwrites`, so size it once instead of
        // rehashing as it grows.
        let parent_size = self.parent.size();
        let overwritten: usize = levels
            .iter()
            .map(|level| level.iter().filter(|pos| **pos < parent_size).count())
            .sum();
        self.overwrites.reserve(overwritten);
        for (height, positions) in levels.iter().enumerate() {
            if positions.is_empty() {
                continue;
            }
            self.merkleize_level(base, hasher, positions, height as u32);
        }

        // Record the peaks of the state this batch represents. A batch without changes shares
        // its parent's.
        let tip_peaks: Arc<[D]> = if self.appended.is_empty() && self.overwrites.is_empty() {
            Arc::clone(&self.parent.data.tip_peaks)
        } else {
            F::peaks(self.size())
                .map(|(pos, _)| {
                    self.get_node(base, pos)
                        .expect("peak must be in the batch chain or base")
                })
                .collect()
        };

        // Collect ancestor data by walking the parent chain (strong Arc + Weak walk).
        let ancestors = collect_ancestor_batches(&self.parent);

        Arc::new(MerkleizedBatch {
            parent: Some(Arc::downgrade(&self.parent)),
            data: Arc::new(BatchData {
                parent_size: self.parent.size(),
                appended: self.appended,
                overwrites: self.overwrites,
                parent_peaks: Arc::clone(&self.parent.data.tip_peaks),
                tip_peaks,
            }),
            base_size: self.parent.base_size,
            pruning_boundary: self.parent.pruning_boundary(),
            ancestors,
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
    /// The strategy splits the positions into batches of adjacent pairs, so every pair reaches
    /// [`Hasher::node_digest_pair`] together and only the last batch can end in a lone node.
    fn merkleize_level(
        &mut self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        positions: &[Position<F>],
        height: u32,
    ) {
        let pairs = positions.len().div_ceil(2);
        let computed: Vec<Vec<(Position<F>, D)>> =
            self.parent
                .strategy
                .run_batches(pairs, NonZeroUsize::MIN, 2, |batches| {
                    batches.map_collect_vec(
                        |ranges| ranges,
                        |range| {
                            let positions =
                                &positions[2 * range.start..positions.len().min(2 * range.end)];
                            let mut computed = Vec::with_capacity(positions.len());
                            self.zip_nodes(base, hasher, positions, height, &mut computed);
                            computed
                        },
                    )
                });
        for nodes in computed {
            for (pos, digest) in nodes {
                self.store_node(pos, digest);
            }
        }
    }
}

/// A batch's changes and the states before and after them, shared with descendants.
#[derive(Debug)]
pub(super) struct BatchData<F: Family, D: Digest> {
    /// Number of nodes before this batch's changes.
    pub(super) parent_size: Position<F>,
    /// Nodes this batch appends after `parent_size`.
    pub(super) appended: Vec<D>,
    /// Nodes this batch overwrites, by position. Every key is below `parent_size`, and nodes at or
    /// above it are in `appended`.
    pub(super) overwrites: Overwrites<F, D>,
    /// Peak digests of the state before this batch's changes.
    pub(super) parent_peaks: Arc<[D]>,
    /// Peak digests of the state after this batch's changes.
    pub(super) tip_peaks: Arc<[D]>,
}

impl<F: Family, D: Digest> BatchData<F, D> {
    /// Number of nodes after this batch's changes.
    pub(super) fn size(&self) -> Position<F> {
        Position::new(*self.parent_size + self.appended.len() as u64)
    }

    fn is_empty(&self) -> bool {
        self.appended.is_empty() && self.overwrites.is_empty()
    }
}

/// Collect the records of `parent` and the ancestors still reachable through its `Weak` chain,
/// in root-to-tip order. Skips empty records (e.g. root batches from `from_mem`).
fn collect_ancestor_batches<F: Family, D: Digest, S: Strategy>(
    parent: &Arc<MerkleizedBatch<F, D, S>>,
) -> Vec<Arc<BatchData<F, D>>> {
    let mut ancestors = Vec::new();

    // Parent is alive (strong Arc held by UnmerkleizedBatch).
    if !parent.data.is_empty() {
        ancestors.push(Arc::clone(&parent.data));
    }

    // Walk Weak chain for grandparents+.
    let mut current = parent.parent.as_ref().and_then(Weak::upgrade);
    while let Some(batch) = current {
        if !batch.data.is_empty() {
            ancestors.push(Arc::clone(&batch.data));
        }
        current = batch.parent.as_ref().and_then(Weak::upgrade);
    }

    ancestors.reverse();
    ancestors
}

/// A speculative batch whose dirty Merkle nodes have been computed, in contrast to
/// [`UnmerkleizedBatch`].
#[derive(Debug)]
pub struct MerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    /// The parent batch in the chain, if any.
    parent: Option<Weak<Self>>,

    /// This batch's own changes and the states before and after them.
    pub(super) data: Arc<BatchData<F, D>>,

    /// Number of committed nodes when the batch chain was forked. Inherited unchanged
    /// by all descendants.
    pub(crate) base_size: Position<F>,

    /// Pruning boundary of the [`Mem`] when the batch chain was forked. Inherited
    /// unchanged by all descendants, like `base_size`.
    pruning_boundary: Location<F>,

    /// Records of the non-empty ancestors still alive at merkleize, in root-to-tip order. Each
    /// record holds only that ancestor's own changes.
    pub(super) ancestors: Vec<Arc<BatchData<F, D>>>,

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
        let peaks: Arc<[D]> = mem.peaks().collect();
        Arc::new(Self {
            parent: None,
            data: Arc::new(BatchData {
                parent_size: mem.size(),
                appended: Vec::new(),
                overwrites: Overwrites::default(),
                parent_peaks: Arc::clone(&peaks),
                tip_peaks: peaks,
            }),
            base_size: mem.size(),
            pruning_boundary: mem.pruning_boundary(),
            ancestors: Vec::new(),
            strategy,
        })
    }

    /// The total number of nodes visible through this batch.
    pub fn size(&self) -> Position<F> {
        self.data.size()
    }

    /// Number of ancestor records this batch retains.
    #[cfg(feature = "std")]
    pub(crate) const fn ancestor_count(&self) -> usize {
        self.ancestors.len()
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

        // A batch's overwrites only hold positions below its parent's size.
        if pos >= self.data.parent_size {
            let i = (*pos - *self.data.parent_size) as usize;
            return self.data.appended.get(i).copied();
        }
        if let Some(d) = self.data.overwrites.get(&pos) {
            return Some(*d);
        }
        // Walk Weak parent chain.
        let mut current = self.parent.as_ref().and_then(Weak::upgrade);
        while let Some(batch) = current {
            if pos >= batch.data.parent_size {
                let i = (*pos - *batch.data.parent_size) as usize;
                return batch.data.appended.get(i).copied();
            }
            if let Some(d) = batch.data.overwrites.get(&pos) {
                return Some(*d);
            }
            current = batch.parent.as_ref().and_then(Weak::upgrade);
        }
        None
    }

    /// Compute the root digest after this batch's mutations using `inactive_peaks` and the bagging
    /// carried by `hasher`.
    pub fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        hasher.root(self.leaves(), inactive_peaks, self.data.tip_peaks.iter())
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
        crate::merkle::RangePlan::new(self.leaves(), range)?.build(hasher, inactive_peaks, |pos| {
            Self::get_node(self, pos).or_else(|| base.get_node(pos))
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{Bagging::ForwardFold, hasher::Standard, mem::Mem, path};
    use alloc::collections::BTreeSet;
    use commonware_cryptography::{Sha256, sha256};
    use commonware_parallel::mocks::explore;
    use commonware_runtime::{Runner as _, deterministic};
    use core::sync::atomic::{AtomicUsize, Ordering};

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn mem_root<F: Family>(mem: &Mem<F, D>, hasher: &H) -> D {
        mem.root(hasher, 0).unwrap()
    }

    fn batch_root<F: Family>(
        batch: &MerkleizedBatch<F, D, commonware_parallel::Sequential>,
        hasher: &H,
    ) -> D {
        batch.root(hasher, 0).unwrap()
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
            assert_ne!(batch_root(&merkleized, &hasher), base_root);
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
                &batch_root(&merkleized, &hasher)
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
            let new_root = batch_root(&merkleized, &hasher);
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
            assert_ne!(batch_root(&ma, &hasher), batch_root(&mb, &hasher));
            assert_ne!(batch_root(&ma, &hasher), base_root);
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
            assert_eq!(batch_root(&mb, &hasher), mem_root(&reference, &hasher));
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
                    &batch_root(&mb, &hasher)
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
            assert_ne!(batch_root(&m, &hasher), base_root);
            let pos5 = Position::<F>::try_from(Location::new(5)).unwrap();
            let original = base.get_node(pos5).unwrap();
            let m2 = base
                .new_batch()
                .update_leaf_digest(Location::new(5), original)
                .unwrap()
                .merkleize(&base, &hasher);
            assert_eq!(batch_root(&m2, &hasher), base_root);
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
            assert_ne!(batch_root(&m, &hasher), base_root);
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
            assert_ne!(batch_root(&m, &hasher), base_root);
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
            assert_eq!(batch_root(&m2, &hasher), base_root);
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
                &batch_root(&m, &hasher)
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
                &batch_root(&m, &hasher)
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
            let expected_root = batch_root(&m, &hasher);

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
            let mut base = build_reference::<F>(&hasher, 50);
            let base_root = mem_root(&base, &hasher);
            let m = base.new_batch().merkleize(&base, &hasher);
            assert_eq!(batch_root(&m, &hasher), base_root);
            let child = m.new_batch().merkleize(&base, &hasher);
            base.apply_batch(&child).unwrap();
            assert_eq!(mem_root(&base, &hasher), base_root);
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
                batch_root(&batch_again.merkleize(&base, &hasher), &hasher),
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
            let expected_root = batch_root(&m, &hasher);
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
            let c_root = batch_root(&mc, &hasher);
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
            let b_root = batch_root(&mb, &hasher);
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
            assert_eq!(batch_root(&m, &hasher), mem_root(&reference, &hasher));
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
            assert_ne!(batch_root(&m, &hasher), base_root);
            let mut base = base;
            let batch = base
                .new_batch()
                .update_leaf(&hasher, Location::new(5), element)
                .unwrap()
                .merkleize(&base, &hasher);
            base.apply_batch(&batch).unwrap();
            assert_eq!(batch_root(&m, &hasher), mem_root(&base, &hasher));
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

    /// Compare roots with a tree built only by appending.
    /// The reference does not walk the ancestors of overwritten leaves.
    fn updates_match_append_only_rebuild<F: Family>() {
        let hasher: H = Standard::new(ForwardFold);
        for initial_len in 1..=9 {
            let initial: Vec<_> = (0..initial_len).map(|i| Sha256::fill(i as u8)).collect();
            let mut base = Mem::<F, D>::new();
            let mut batch = base.new_batch();
            for &digest in &initial {
                batch = batch.add_leaf_digest(digest);
            }
            let batch = batch.merkleize(&base, &hasher);
            base.apply_batch(&batch).unwrap();

            for mask in 0..1usize << initial_len {
                let mut expected = initial.clone();
                let mut batch = base.new_batch();
                for i in (0..initial_len).rev() {
                    if mask & (1 << i) == 0 {
                        continue;
                    }
                    let loc = Location::new(i as u64);
                    let digest = Sha256::fill(32 + i as u8);
                    batch = batch
                        .update_leaf(&hasher, loc, b"temporary")
                        .unwrap()
                        .update_leaf_digest(loc, Sha256::fill(254))
                        .unwrap()
                        .update_leaf_batched(&[(loc, Sha256::fill(255)), (loc, digest)])
                        .unwrap();
                    expected[i] = digest;
                    if i % 2 == 0 {
                        let appended = Sha256::fill(expected.len() as u8);
                        batch = batch.add_leaf_digest(appended);
                        expected.push(appended);
                    }
                }
                // Update an appended leaf, then append again so the peak forest can change.
                batch = batch.add_leaf_digest(Sha256::fill(254));
                batch = batch
                    .update_leaf_digest(Location::new(expected.len() as u64), Sha256::fill(253))
                    .unwrap();
                expected.push(Sha256::fill(253));
                batch = batch.add_leaf_digest(Sha256::fill(252));
                expected.push(Sha256::fill(252));
                // Only overwritten leaves from the parent batch are recorded, once each.
                assert_eq!(batch.overwrites.len(), mask.count_ones() as usize);
                let batch = batch.merkleize(&base, &hasher);

                let empty = Mem::<F, D>::new();
                let mut reference = empty.new_batch();
                for digest in expected {
                    reference = reference.add_leaf_digest(digest);
                }
                let reference = reference.merkleize(&empty, &hasher);
                assert_eq!(
                    batch_root(&batch, &hasher),
                    batch_root(&reference, &hasher),
                    "initial_len={initial_len} mask={mask}"
                );
            }
        }
    }

    /// Check that the plan contains exactly the required internal nodes, with no duplicates.
    fn hash_plan_is_exact<F: Family>() {
        let hasher: H = Standard::new(ForwardFold);
        let mut base = Mem::<F, D>::new();
        let mut batch = base.new_batch();
        for i in 0..37u8 {
            batch = batch.add_leaf_digest(Sha256::fill(i));
        }
        base.apply_batch(&batch.merkleize(&base, &hasher)).unwrap();

        let all: Vec<u64> = (0..37).collect();
        let cases: [(&[u64], u8); 5] = [
            (&[0, 1, 2], 0),
            (&[36, 5, 5, 20, 0], 0),
            (&[3, 36], 1),
            (&[7, 36], 5),
            // In MMB, the second append merges two peaks from the parent batch.
            (&all, 3),
        ];
        for (updates, appends) in cases {
            let mut batch = base.new_batch();
            for &loc in updates {
                batch = batch
                    .update_leaf_digest(Location::new(loc), Sha256::fill(0xAA))
                    .unwrap();
            }
            for i in 0..appends {
                batch = batch.add_leaf_digest(Sha256::fill(0xBB + i));
            }

            // Build the expected set from new internal nodes, then walk each overwritten
            // leaf's ancestors separately.
            let mut expected = BTreeSet::new();
            for pos in *base.size()..*batch.size() {
                let pos = Position::<F>::new(pos);
                if Location::try_from(pos).is_err() {
                    expected.insert((F::pos_to_height(pos), pos));
                }
            }
            for &loc in updates {
                let loc = Location::new(loc);
                let mut first_leaf = Location::new(0);
                for (peak, height) in F::peaks(batch.size()) {
                    let end = first_leaf + (1u64 << height);
                    if loc < end {
                        for (parent, _, h) in path::Iterator::new(peak, height, first_leaf, loc) {
                            expected.insert((h, parent));
                        }
                        break;
                    }
                    first_leaf = end;
                }
            }

            let levels = batch.hash_plan();
            let actual: Vec<_> = levels
                .iter()
                .enumerate()
                .flat_map(|(h, positions)| positions.iter().map(move |&pos| (h as u32, pos)))
                .collect();
            assert_eq!(actual.len(), expected.len(), "updates={updates:?}");
            assert_eq!(actual.into_iter().collect::<BTreeSet<_>>(), expected);
        }
    }

    /// Counts the paired and lone node hashes a merkleization performs.
    #[derive(Clone)]
    struct CountingHasher<'a> {
        inner: H,
        pairs: &'a AtomicUsize,
        singles: &'a AtomicUsize,
    }

    impl<F: Family> Hasher<F> for CountingHasher<'_> {
        type Digest = D;

        fn hash(&self, parts: &[&[u8]]) -> D {
            <H as Hasher<F>>::hash(&self.inner, parts)
        }

        fn root_bagging(&self) -> crate::merkle::Bagging {
            <H as Hasher<F>>::root_bagging(&self.inner)
        }

        fn node_digest(&self, pos: Position<F>, left: &D, right: &D) -> D {
            self.singles.fetch_add(1, Ordering::Relaxed);
            <H as Hasher<F>>::node_digest(&self.inner, pos, left, right)
        }

        fn node_digest_pair(&self, nodes: [(Position<F>, &D, &D); 2]) -> (D, D) {
            self.pairs.fetch_add(1, Ordering::Relaxed);
            <H as Hasher<F>>::node_digest_pair(&self.inner, nodes)
        }
    }

    /// Merkleizes `n` appends on `strategy` and returns the root with the number of paired and
    /// lone node hashes it took.
    fn merkleize_counting<F: Family>(n: u64, strategy: impl Strategy) -> (D, usize, usize) {
        let (pairs, singles) = (AtomicUsize::new(0), AtomicUsize::new(0));
        let hasher = CountingHasher {
            inner: Standard::new(ForwardFold),
            pairs: &pairs,
            singles: &singles,
        };
        let base = Mem::<F, D>::new();
        let mut batch = base.new_batch_with_strategy(strategy);
        for i in 0..n {
            let element = Hasher::<F>::digest(&hasher, &i.to_be_bytes());
            batch = batch.add(&hasher, &element);
        }
        let root = batch.merkleize(&base, &hasher).root(&hasher, 0).unwrap();
        (
            root,
            pairs.load(Ordering::Relaxed),
            singles.load(Ordering::Relaxed),
        )
    }

    /// A split level hashes the same node pairs as a serial one. Batches hold whole adjacent
    /// pairs, so splitting changes neither the root nor the counts of paired and lone node hashes.
    fn level_batches_keep_pairs<F: Family>() {
        for n in [1u64, 2, 3, 10, 100, 199] {
            let serial = merkleize_counting::<F>(n, commonware_parallel::Sequential);
            explore(|strategy| {
                let result = merkleize_counting::<F>(n, strategy.clone());
                assert_eq!(
                    result, serial,
                    "merkleizing {n} leaves must match the serial root and hash counts"
                );
            });
        }
    }

    /// `get_node` returns each node from the nearest batch in the chain that wrote it. Each batch
    /// locates its appended nodes from its own parent size. Nodes that exist only in the committed
    /// base read as `None`.
    fn get_node_resolves_from_writing_batch<F: Family>() {
        let hasher: H = Standard::new(ForwardFold);
        let base = build_reference::<F>(&hasher, 10);
        let (x, y, z, w) = (
            Sha256::fill(0xA1),
            Sha256::fill(0xB2),
            Sha256::fill(0xC3),
            Sha256::fill(0xD4),
        );

        let leaf_0 = Position::<F>::try_from(Location::new(0)).unwrap();
        let leaf_5 = Position::<F>::try_from(Location::new(5)).unwrap();
        let leaf_9 = Position::<F>::try_from(Location::new(9)).unwrap();
        let leaf_10 = Position::<F>::try_from(Location::new(10)).unwrap();
        let leaf_11 = Position::<F>::try_from(Location::new(11)).unwrap();

        // A appends leaf 10 at its parent's size.
        let a = base
            .new_batch()
            .add_leaf_digest(x)
            .merkleize(&base, &hasher);
        assert_eq!(leaf_10, a.data.parent_size);
        assert_eq!(a.get_node(leaf_10), Some(x));

        // B overwrites leaf 0 and its ancestors up to the first peak.
        let b = a
            .new_batch()
            .update_leaf_digest(Location::new(0), y)
            .unwrap()
            .merkleize(&base, &hasher);
        let (peak, _) = F::peaks(b.size()).next().unwrap();
        let peak_digest = b.data.tip_peaks[0];

        // Each descendant of B reads leaf 0 and the peak as B wrote them and leaf 10 as A wrote it.
        // Base-only leaf 5 and the position at the batch's size read as `None`.
        let check_ancestor_nodes =
            |batch: &MerkleizedBatch<F, D, commonware_parallel::Sequential>| {
                assert_eq!(batch.get_node(leaf_0), Some(y));
                assert_eq!(batch.get_node(peak), Some(peak_digest));
                assert_eq!(batch.get_node(leaf_10), Some(x));
                assert_eq!(batch.get_node(leaf_5), None);
                assert_eq!(batch.get_node(batch.size()), None);
            };

        // An empty batch holds no nodes of its own, so every read walks its ancestors.
        let empty = b.new_batch().merkleize(&base, &hasher);
        check_ancestor_nodes(&empty);

        // C returns its own leaf 9 and leaf 11 and reads other nodes through `empty`.
        let c = empty
            .new_batch()
            .update_leaf_digest(Location::new(9), z)
            .unwrap()
            .add_leaf_digest(w)
            .merkleize(&base, &hasher);
        assert_eq!(leaf_11, c.data.parent_size);
        assert_eq!(c.get_node(leaf_9), Some(z));
        assert_eq!(c.get_node(leaf_11), Some(w));
        check_ancestor_nodes(&c);
    }

    #[test]
    fn mmr_consistency() {
        consistency_with_reference::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_level_batches_keep_pairs() {
        level_batches_keep_pairs::<crate::mmr::Family>();
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
    #[test]
    fn mmr_updates_match_append_only_rebuild() {
        updates_match_append_only_rebuild::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_hash_plan_is_exact() {
        hash_plan_is_exact::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_get_node_resolves_from_writing_batch() {
        get_node_resolves_from_writing_batch::<crate::mmr::Family>();
    }

    #[test]
    fn mmb_consistency() {
        consistency_with_reference::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_level_batches_keep_pairs() {
        level_batches_keep_pairs::<crate::mmb::Family>();
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
    #[test]
    fn mmb_updates_match_append_only_rebuild() {
        updates_match_append_only_rebuild::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_hash_plan_is_exact() {
        hash_plan_is_exact::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_get_node_resolves_from_writing_batch() {
        get_node_resolves_from_writing_batch::<crate::mmb::Family>();
    }

    /// Reentrant encoding must preserve bytes written before and after the nested call.
    #[cfg(feature = "std")]
    #[test]
    fn add_many_tolerates_nested_add_many() {
        struct Nested(u8);

        impl Write for Nested {
            fn write(&self, buf: &mut impl bytes::BufMut) {
                buf.put_u8(0xFF);
                let hasher: H = Standard::new(ForwardFold);
                let inner = Mem::<crate::mmr::Family, D>::new();
                let _ = inner.new_batch().add_many(&hasher, &[u64::from(self.0)]);
                buf.put_u8(self.0);
            }
        }

        let hasher: H = Standard::new(ForwardFold);
        let base = Mem::<crate::mmr::Family, D>::new();
        let items: Vec<Nested> = (0..4).map(Nested).collect();
        let nested = base
            .new_batch()
            .add_many(&hasher, &items)
            .merkleize(&base, &hasher);
        let mut expected = base.new_batch();
        for i in 0..4u8 {
            expected = expected.add(&hasher, &[0xFF, i]);
        }
        let expected = expected.merkleize(&base, &hasher);
        assert_eq!(batch_root(&nested, &hasher), batch_root(&expected, &hasher));
    }
}
