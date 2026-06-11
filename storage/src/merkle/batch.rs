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
//! # Merkleization
//!
//! [`UnmerkleizedBatch::merkleize`] recomputes every node whose digest a batch's mutations
//! changed. Two terms describe a node's digest, and a third its origin:
//!
//! - Dirty: this batch wrote the node's digest. Updated and appended leaves start dirty;
//!   internal nodes become dirty as merkleization computes them.
//! - Clean: untouched by this batch; resolved by lookup.
//! - New: created by this batch's appends (the appended leaf plus the internal nodes
//!   [`Family::parent_heights`] reports born with it). Every new node ends up dirty, but a
//!   new internal node needs a digest even when all its children are clean: it has no
//!   previous digest to keep.
//!
//! The batch records only the leaves it wrote and the nodes its appends created. Which
//! internal nodes to recompute is derived, not tracked: a node needs recomputation exactly
//! when a child was recomputed or the node is new. Merkleization applies this rule one
//! height at a time, alternating between two states:
//!
//! - A `Frontier`: all dirty nodes at height h, with their computed digests, sorted by the
//!   leftmost leaf of their subtrees.
//! - A `Level`: all nodes at height h + 1 that need a digest. Each is a `Parent` holding
//!   the digests of its dirty children; clean children are resolved by lookup.
//!
//! `Frontier::ascend` builds the level by linearly merging the frontier with the new nodes
//! one height up: sibling frontier nodes are adjacent and fold into one `Parent`, a parent
//! that is itself new appears once, and nodes with no parent (peaks, parents not yet born)
//! drop out. `Level::hash` hashes every parent (independently, so possibly in parallel) and
//! the results are the next frontier.
//!
//! The loop starts from the dirty leaves and stops when a frontier is empty and no new
//! nodes remain above it. This is correct because each frontier is complete: it contains
//! every dirty node at its height, so the rule above finds every node at the next height
//! that needs recomputation. (An empty frontier with new nodes above it happens in MMB,
//! where one append can merge subtrees made entirely of clean nodes.)
//!
//! Example: an MMR holds leaves 0..=2; a batch updates leaf 1 and appends leaf 3, creating
//! positions 4, 5, and 6 (the subtrees under 5 and 6 complete when leaf 3 arrives):
//!
//! ```text
//! height 2:           6*+
//!                   /     \                 nodes labeled by position
//! height 1:      2*         5*+             * dirty: digest written by this batch
//!               /  \       /  \             + new: created by appending leaf 3
//! height 0:    0    1*    3    4*+
//!
//! location:    0    1     2    3
//! ```
//!
//! - The frontier at height 0 holds positions 1 (updated) and 4 (appended).
//! - Ascend: node 1's parent is node 2 (right child dirty, left child 0 clean); node 4's
//!   parent is the new node 5 (right child dirty, left child 3 clean). Hash both.
//! - The frontier at height 1 holds positions 2 and 5: siblings, folding into the new
//!   node 6 with both children dirty. Hash it.
//! - The frontier at height 2 holds position 6, a peak: no parent, nothing new above, done.
//!
//! # Parent chain and memory
//!
//! Each [`MerkleizedBatch`] stores its own local data (appended nodes and overwrites)
//! plus `Arc` refs to each ancestor's data, collected during
//! [`UnmerkleizedBatch::merkleize`]. These ancestor batches' data are used by
//! [`Mem::apply_batch`] to replay uncommitted ancestors without requiring the
//! ancestor batches to still be alive.
//!
//! A `Weak` pointer to the parent is kept for [`MerkleizedBatch::get_node`] lookups
//! (used during a child's merkleize) and for walking the chain to collect ancestor
//! batch data. Committed-and-dropped ancestors truncate the `Weak` walk, but their
//! data is already captured in `ancestor_appended` / `ancestor_overwrites`.
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
    hasher::Hasher, mem::Mem, proof::Proof, Error, Family, Location, Position, Readable,
};
use ahash::RandomState;
use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use commonware_cryptography::Digest;
use commonware_parallel::{Sequential, Strategy};
use core::ops::Range;

/// Overwritten node digests keyed by position.
pub(crate) type Overwrites<F, D> = hashbrown::HashMap<Position<F>, D, RandomState>;

/// Nodes newly created by this batch's appends, grouped by height.
/// Each inner list is sorted by leftmost leaf because appends proceed left to right.
#[derive(Default)]
struct NewNodes<F: Family>(Vec<Vec<(Location<F>, Position<F>)>>);

impl<F: Family> NewNodes<F> {
    /// Add a node created at `height`: its position and its subtree's leftmost leaf.
    #[inline]
    fn add(&mut self, height: u32, leftmost: Location<F>, pos: Position<F>) {
        let height = height as usize;
        if self.0.len() <= height {
            self.0.resize_with(height + 1, Vec::new);
        }
        self.0[height].push((leftmost, pos));
    }

    /// The new nodes at `height`.
    fn at_height(&self, height: u32) -> &[(Location<F>, Position<F>)] {
        self.0.get(height as usize).map_or(&[], Vec::as_slice)
    }

    /// Whether any new nodes exist above `height`.
    fn any_above(&self, height: u32) -> bool {
        // Lists below the top may be empty, but the topmost is not: the outer vec only
        // grows to a new height when add pushes a node at that height. So any list
        // existing above `height` implies a node exists above `height`.
        self.0.len() > height as usize + 1
    }
}

/// A dirty node: one whose digest this batch wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Node<F: Family, D: Digest> {
    /// Leftmost leaf of the node's subtree.
    leftmost: Location<F>,
    /// The node's position.
    pos: Position<F>,
    /// The node's computed digest.
    digest: D,
}

/// A [`Node`] awaiting its digest: identified as a parent of frontier nodes by
/// [`Frontier::ascend`], it becomes a [`Node`] through [`Self::into_node`]. `Some` children
/// are dirty (taken from the frontier by sibling adjacency); `None` children are clean and
/// resolved by lookup.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parent<F: Family, D: Digest> {
    /// Leftmost leaf of the parent's subtree.
    leftmost: Location<F>,
    /// The parent's position.
    pos: Position<F>,
    /// The left child's digest, if dirty.
    left: Option<D>,
    /// The right child's digest, if dirty.
    right: Option<D>,
}

impl<F: Family, D: Digest> Parent<F, D> {
    /// Resolve clean children and hash: the parent -> dirty node transition.
    fn into_node(
        self,
        hasher: &impl Hasher<F, Digest = D>,
        height: u32,
        resolve: impl Fn(Position<F>) -> D,
    ) -> Node<F, D> {
        let (left_pos, right_pos) = F::children(self.pos, height);
        let left = self.left.unwrap_or_else(|| resolve(left_pos));
        let right = self.right.unwrap_or_else(|| resolve(right_pos));
        Node {
            leftmost: self.leftmost,
            pos: self.pos,
            digest: hasher.node_digest(self.pos, &left, &right),
        }
    }
}

/// The dirty nodes at a single height during merkleization, sorted by strictly increasing
/// leftmost leaf. Unrelated to the append frontier of a compact structure.
struct Frontier<F: Family, D: Digest> {
    /// The height all nodes share.
    height: u32,
    /// The dirty nodes, sorted by leftmost leaf.
    nodes: Vec<Node<F, D>>,
}

impl<F: Family, D: Digest> Frontier<F, D> {
    /// Create a frontier from sorted `nodes` at `height`.
    fn new(height: u32, nodes: Vec<Node<F, D>>) -> Self {
        debug_assert!(nodes.windows(2).all(|w| w[0].leftmost < w[1].leftmost));
        Self { height, nodes }
    }

    const fn height(&self) -> u32 {
        self.height
    }

    const fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    fn iter(&self) -> impl Iterator<Item = &Node<F, D>> {
        self.nodes.iter()
    }

    /// The frontier -> level transition: pair sibling children by adjacency, merge the new
    /// nodes one height up, and gate on parent existence. Peaks and not-yet-created parents
    /// fall out; a parent that is itself a new node appears once.
    fn ascend(&self, new: &NewNodes<F>, leaves: Location<F>) -> Level<F, D> {
        let parent_height = self.height + 1;
        let width = 1u64 << self.height;
        let parent_mask = !((1u64 << parent_height) - 1);

        let mut parents = Vec::with_capacity(self.nodes.len() / 2 + 1);
        let mut new_iter = new.at_height(parent_height).iter().copied().peekable();
        let mut i = 0;
        while i < self.nodes.len() {
            let Node {
                leftmost, digest, ..
            } = self.nodes[i];
            let parent_loc = Location::new(*leftmost & parent_mask);
            // New nodes left of this parent have no dirty children.
            while let Some(&(new_loc, new_pos)) = new_iter.peek() {
                if new_loc >= parent_loc {
                    break;
                }
                parents.push(Parent {
                    leftmost: new_loc,
                    pos: new_pos,
                    left: None,
                    right: None,
                });
                new_iter.next();
            }
            // A new node at this parent IS this parent; drop the duplicate. (This precedes
            // the existence gate below, which a new node always passes.)
            if new_iter
                .peek()
                .is_some_and(|&(new_loc, _)| new_loc == parent_loc)
            {
                new_iter.next();
            }
            // Gather the parent's dirty children: the left child (if dirty) is at parent_loc
            // and the right child (if dirty) at parent_loc + width, adjacent in the frontier.
            let (mut left, mut right) = (None, None);
            if leftmost == parent_loc {
                left = Some(digest);
                i += 1;
                if let Some(next) = self.nodes.get(i) {
                    if *next.leftmost == *parent_loc + width {
                        right = Some(next.digest);
                        i += 1;
                    }
                }
            } else {
                right = Some(digest);
                i += 1;
            }
            // The parent may not exist (this node is a peak, or its parent's merge has not
            // happened yet).
            let Some(pos) = F::subtree_root(parent_loc, parent_height, leaves) else {
                continue;
            };
            parents.push(Parent {
                leftmost: parent_loc,
                pos,
                left,
                right,
            });
        }
        for (new_loc, new_pos) in new_iter {
            parents.push(Parent {
                leftmost: new_loc,
                pos: new_pos,
                left: None,
                right: None,
            });
        }

        Level {
            height: parent_height,
            parents,
        }
    }
}

/// The parents identified at one height, awaiting their digests: the state between two
/// frontiers.
struct Level<F: Family, D: Digest> {
    /// The height all parents share.
    height: u32,
    /// The parents to compute, sorted by leftmost leaf.
    parents: Vec<Parent<F, D>>,
}

impl<F: Family, D: Digest> Level<F, D> {
    /// The level -> frontier transition: resolve clean children and hash every parent (the
    /// messages are independent, so `strategy` may parallelize).
    fn hash<S: Strategy>(
        self,
        strategy: &S,
        hasher: &impl Hasher<F, Digest = D>,
        resolve: impl Fn(Position<F>) -> D + Send + Sync,
    ) -> Frontier<F, D> {
        let height = self.height;
        let nodes = strategy.map_init_collect_vec(
            &self.parents,
            || hasher.clone(),
            |hasher, &parent| parent.into_node(hasher, height, &resolve),
        );
        // Strategies preserve input order, so the nodes remain sorted by leftmost.
        Frontier::new(height, nodes)
    }
}

/// A speculative batch whose root digest has not yet been computed,
/// in contrast to [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, D: Digest, S: Strategy> {
    /// The merkleized batch this batch extends.
    parent: Arc<MerkleizedBatch<F, D, S>>,
    /// Nodes appended past the parent's size, in position order (non-leaf slots start as
    /// placeholders and are filled by `merkleize`).
    appended: Vec<D>,
    /// Overwrites of positions below the parent's size.
    overwrites: Overwrites<F, D>,
    /// Pre-existing leaves overwritten by this batch, in call order (possibly duplicated;
    /// `merkleize` sorts and dedups).
    updated: Vec<Location<F>>,
    /// Nodes newly created by this batch's appends.
    new: NewNodes<F>,
}

impl<F: Family, D: Digest, S: Strategy> UnmerkleizedBatch<F, D, S> {
    /// Create a new batch from `parent`.
    pub fn new(parent: Arc<MerkleizedBatch<F, D, S>>) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: Overwrites::default(),
            updated: Vec::new(),
            new: NewNodes::default(),
        }
    }

    /// Return a reference to the batch's strategy.
    pub fn strategy(&self) -> &S {
        &self.parent.strategy
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
        self.new.add(0, leaves, size);
        self.appended.push(digest);
        size += 1;

        for (height, leftmost) in F::parent_heights(leaves) {
            self.appended.push(D::EMPTY);
            self.new.add(height, leftmost, size);
            size += 1;
        }

        size
    }

    /// Add a run of pre-computed leaf digests, in order.
    #[cfg(feature = "std")]
    pub(crate) fn add_leaf_digests(mut self, digests: impl IntoIterator<Item = D>) -> Self {
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
        self.updated.push(loc);
        Ok(self)
    }

    /// Overwrite the digest of an existing leaf.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(mut self, loc: Location<F>, digest: D) -> Result<Self, Error<F>> {
        let pos = self.validate_loc(loc)?;
        self.store_node(pos, digest);
        self.updated.push(loc);
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
            self.updated.push(*loc);
        }
        Ok(self)
    }

    /// Return the height-0 `Frontier` that seeds merkleization: every leaf this batch
    /// updated or appended, in location order.
    fn leaf_frontier(&mut self, base: &Mem<F, D>, new: &NewNodes<F>) -> Frontier<F, D> {
        let parent_leaves = self.parent.leaves();
        let parent_size = self.parent.size();

        let mut updated = core::mem::take(&mut self.updated);
        updated.sort_unstable();
        updated.dedup();
        // Updates to leaves this batch itself appended enter the frontier through `new`
        // below; their slots in `appended` already hold the final digests.
        updated.retain(|loc| *loc < parent_leaves);

        let appended = new.at_height(0);
        let mut nodes = Vec::with_capacity(updated.len() + appended.len());
        nodes.extend(updated.into_iter().map(|leftmost| {
            let pos = Position::try_from(leftmost).expect("validated leaf location");
            let digest = self.get_node(base, pos).expect("updated leaf missing");
            Node {
                leftmost,
                pos,
                digest,
            }
        }));
        nodes.extend(appended.iter().map(|&(leftmost, pos)| Node {
            leftmost,
            pos,
            digest: self.appended[(*pos - *parent_size) as usize],
        }));
        Frontier::new(0, nodes)
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed dirty
    /// nodes. `base` provides committed node data as fallback during hash computation.
    pub fn merkleize(
        mut self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Arc<MerkleizedBatch<F, D, S>> {
        let leaves = self.leaves();
        let new = core::mem::take(&mut self.new);
        // Bottom-up frontier propagation; see the Merkleization section of the module docs.
        let mut frontier = self.leaf_frontier(base, &new);
        while !frontier.is_empty() || new.any_above(frontier.height()) {
            let level = frontier.ascend(&new, leaves);
            let computed = level.hash(&self.parent.strategy, hasher, |pos| {
                self.get_node(base, pos)
                    .unwrap_or_else(|| panic!("missing child at {pos}"))
            });
            for node in computed.iter() {
                self.store_node(node.pos, node.digest);
            }
            frontier = computed;
        }

        // Collect ancestor data by walking the parent chain (strong Arc + Weak walk).
        let (ancestor_appended, ancestor_overwrites) = collect_ancestor_batches(&self.parent);

        Arc::new(MerkleizedBatch {
            parent: Some(Arc::downgrade(&self.parent)),
            parent_size: self.parent.size(),
            appended: Arc::new(self.appended),
            overwrites: Arc::new(self.overwrites),
            base_size: self.parent.base_size,
            pruning_boundary: self.parent.pruning_boundary(),
            ancestor_appended,
            ancestor_overwrites,
            strategy: self.parent.strategy.clone(),
        })
    }
}

/// Collect ancestor batch data by walking the parent + its Weak chain.
/// Returns (appended, overwrites) in root-to-tip order. Skips empty batches
/// (e.g. root batches from `from_mem`).
#[allow(clippy::type_complexity)]
fn collect_ancestor_batches<F: Family, D: Digest, S: Strategy>(
    parent: &Arc<MerkleizedBatch<F, D, S>>,
) -> (Vec<Arc<Vec<D>>>, Vec<Arc<Overwrites<F, D>>>) {
    let mut appended = Vec::new();
    let mut overwrites = Vec::new();

    // Parent is alive (strong Arc held by UnmerkleizedBatch).
    if !parent.appended.is_empty() || !parent.overwrites.is_empty() {
        appended.push(Arc::clone(&parent.appended));
        overwrites.push(Arc::clone(&parent.overwrites));
    }

    // Walk Weak chain for grandparents+.
    let mut current = parent.parent.as_ref().and_then(Weak::upgrade);
    while let Some(batch) = current {
        if !batch.appended.is_empty() || !batch.overwrites.is_empty() {
            appended.push(Arc::clone(&batch.appended));
            overwrites.push(Arc::clone(&batch.overwrites));
        }
        current = batch.parent.as_ref().and_then(Weak::upgrade);
    }

    appended.reverse();
    overwrites.reverse();
    (appended, overwrites)
}

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
            pruning_boundary: Readable::pruning_boundary(mem),
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
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1, inactive_peaks)
            .map_err(|e| match e {
                Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
                _ => e,
            })
    }

    /// Inclusion proof for all elements in `range` using `inactive_peaks` and the bagging carried
    /// by `hasher`.
    pub fn range_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        range: Range<Location<F>>,
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        crate::merkle::proof::build_range_proof(
            hasher,
            self.leaves(),
            inactive_peaks,
            range,
            |pos| Self::get_node(self, pos),
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
    type Error = Error<F>;

    fn size(&self) -> Position<F> {
        Self::size(self)
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        Self::get_node(self, pos)
    }

    fn pruning_boundary(&self) -> Location<F> {
        Self::pruning_boundary(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, mem::Mem, Bagging::ForwardFold};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn mem_root<F: Family>(mem: &Mem<F, D>, hasher: &H) -> D {
        mem.root(hasher, 0).unwrap()
    }

    /// Specification tests for the merkleization state machine, using MMR positions
    /// (leaves at 0, 1, 3, 4; height 1 at 2, 5; height 2 at 6).
    mod frontier {
        use super::*;
        use commonware_parallel::Sequential;

        type F = crate::mmr::Family;

        fn node(leftmost: u64, pos: u64, byte: u8) -> Node<F, D> {
            Node {
                leftmost: Location::new(leftmost),
                pos: Position::new(pos),
                digest: Sha256::fill(byte),
            }
        }

        fn parent(leftmost: u64, pos: u64, left: Option<u8>, right: Option<u8>) -> Parent<F, D> {
            Parent {
                leftmost: Location::new(leftmost),
                pos: Position::new(pos),
                left: left.map(Sha256::fill),
                right: right.map(Sha256::fill),
            }
        }

        fn new_nodes(entries: &[(u32, u64, u64)]) -> NewNodes<F> {
            let mut new = NewNodes::default();
            for &(height, leftmost, pos) in entries {
                new.add(height, Location::new(leftmost), Position::new(pos));
            }
            new
        }

        fn ascend(
            height: u32,
            nodes: Vec<Node<F, D>>,
            new: &NewNodes<F>,
            leaves: u64,
        ) -> Vec<Parent<F, D>> {
            Frontier::new(height, nodes)
                .ascend(new, Location::new(leaves))
                .parents
        }

        #[test]
        fn ascend_pairs_adjacent_siblings() {
            let parents = ascend(0, vec![node(0, 0, 1), node(1, 1, 2)], &new_nodes(&[]), 2);
            assert_eq!(parents, vec![parent(0, 2, Some(1), Some(2))]);
        }

        #[test]
        fn ascend_left_child_only() {
            let parents = ascend(0, vec![node(0, 0, 1)], &new_nodes(&[]), 2);
            assert_eq!(parents, vec![parent(0, 2, Some(1), None)]);
        }

        #[test]
        fn ascend_right_child_only() {
            let parents = ascend(0, vec![node(1, 1, 2)], &new_nodes(&[]), 2);
            assert_eq!(parents, vec![parent(0, 2, None, Some(2))]);
        }

        #[test]
        fn ascend_gates_on_parent_existence() {
            // Leaf 2 is a lone peak in a 3-leaf structure; its parent does not exist yet.
            let parents = ascend(0, vec![node(2, 3, 1)], &new_nodes(&[]), 3);
            assert!(parents.is_empty());
        }

        #[test]
        fn ascend_drops_new_node_duplicating_parent() {
            // The dirty child's parent was itself created by an append; it appears once,
            // with the dirty child attached.
            let parents = ascend(0, vec![node(1, 1, 2)], &new_nodes(&[(1, 0, 2)]), 2);
            assert_eq!(parents, vec![parent(0, 2, None, Some(2))]);
        }

        #[test]
        fn ascend_emits_new_node_left_of_frontier() {
            // A new node over clean leaves [0, 2) precedes the parent of the dirty leaf 2.
            let parents = ascend(0, vec![node(2, 3, 1)], &new_nodes(&[(1, 0, 2)]), 4);
            assert_eq!(
                parents,
                vec![parent(0, 2, None, None), parent(2, 5, Some(1), None)]
            );
        }

        #[test]
        fn ascend_emits_trailing_new_nodes() {
            let parents = ascend(0, vec![], &new_nodes(&[(1, 0, 2), (1, 2, 5)]), 4);
            assert_eq!(
                parents,
                vec![parent(0, 2, None, None), parent(2, 5, None, None)]
            );
        }

        #[test]
        fn ascend_pairs_higher_heights() {
            let parents = ascend(1, vec![node(0, 2, 1), node(2, 5, 2)], &new_nodes(&[]), 4);
            assert_eq!(parents, vec![parent(0, 6, Some(1), Some(2))]);
        }

        #[test]
        fn into_node_uses_dirty_children() {
            let hasher: H = Standard::new(ForwardFold);
            let node = parent(0, 2, Some(1), Some(2))
                .into_node(&hasher, 1, |_| panic!("resolve must not be called"));
            assert_eq!(node.leftmost, Location::new(0));
            assert_eq!(node.pos, Position::new(2));
            assert_eq!(
                node.digest,
                hasher.node_digest(Position::<F>::new(2), &Sha256::fill(1), &Sha256::fill(2))
            );
        }

        #[test]
        fn into_node_resolves_clean_children() {
            let hasher: H = Standard::new(ForwardFold);
            let clean = Sha256::fill(9);

            let left_clean = parent(0, 2, None, Some(2)).into_node(&hasher, 1, |pos| {
                assert_eq!(pos, Position::new(0));
                clean
            });
            assert_eq!(
                left_clean.digest,
                hasher.node_digest(Position::<F>::new(2), &clean, &Sha256::fill(2))
            );

            let right_clean = parent(0, 2, Some(1), None).into_node(&hasher, 1, |pos| {
                assert_eq!(pos, Position::new(1));
                clean
            });
            assert_eq!(
                right_clean.digest,
                hasher.node_digest(Position::<F>::new(2), &Sha256::fill(1), &clean)
            );
        }

        #[test]
        fn hash_level_preserves_order_and_height() {
            let hasher: H = Standard::new(ForwardFold);
            let level = Level {
                height: 1,
                parents: vec![
                    parent(0, 2, Some(1), Some(2)),
                    parent(2, 5, Some(3), Some(4)),
                ],
            };
            let frontier = level.hash(&Sequential, &hasher, |_| unreachable!());
            assert_eq!(frontier.height(), 1);
            let nodes: Vec<_> = frontier.iter().copied().collect();
            assert_eq!(
                nodes,
                vec![
                    parent(0, 2, Some(1), Some(2)).into_node(&hasher, 1, |_| unreachable!()),
                    parent(2, 5, Some(3), Some(4)).into_node(&hasher, 1, |_| unreachable!()),
                ]
            );
        }

        #[test]
        #[should_panic]
        fn frontier_rejects_unsorted_nodes() {
            Frontier::new(0, vec![node(1, 1, 1), node(0, 0, 2)]);
        }

        #[test]
        fn new_nodes_add_and_query() {
            let new = new_nodes(&[(2, 0, 6), (0, 4, 7), (1, 4, 9)]);
            assert_eq!(new.at_height(0), &[(Location::new(4), Position::new(7))]);
            assert_eq!(new.at_height(1), &[(Location::new(4), Position::new(9))]);
            assert_eq!(new.at_height(2), &[(Location::new(0), Position::new(6))]);
            assert_eq!(new.at_height(3), &[]);
            assert!(new.any_above(0));
            assert!(new.any_above(1));
            assert!(!new.any_above(2));
        }
    }

    /// Apply randomly interleaved appends, updates (including of leaves appended in the same
    /// batch), and prunes, comparing the root and spot proofs against a structure rebuilt from
    /// scratch after every batch.
    fn randomized_differential<F: Family>() {
        use commonware_utils::test_rng;
        use rand::Rng as _;

        let hasher: H = Standard::new(ForwardFold);
        let mut rng = test_rng();
        let mut mem = Mem::<F, D>::new();
        let mut elements: Vec<[u8; 8]> = Vec::new();
        let mut pruned_to = 0u64;
        for round in 0..100 {
            let mut batch = mem.new_batch();
            for _ in 0..rng.gen_range(1..12) {
                let leaves = elements.len() as u64;
                let element = rng.gen::<u64>().to_be_bytes();
                if leaves == pruned_to || rng.gen_bool(0.5) {
                    elements.push(element);
                    batch = batch.add(&hasher, &element);
                } else {
                    let loc = rng.gen_range(pruned_to..leaves);
                    elements[loc as usize] = element;
                    batch = batch
                        .update_leaf(&hasher, Location::new(loc), &element)
                        .unwrap();
                }
            }
            let merkleized = batch.merkleize(&mem, &hasher);
            mem.apply_batch(&merkleized).unwrap();

            let mut reference = Mem::<F, D>::new();
            let rebuilt = elements
                .iter()
                .fold(reference.new_batch(), |b, e| b.add(&hasher, e))
                .merkleize(&reference, &hasher);
            reference.apply_batch(&rebuilt).unwrap();
            let root = mem_root(&mem, &hasher);
            assert_eq!(
                root,
                mem_root(&reference, &hasher),
                "root mismatch (round={round}, leaves={}, pruned_to={pruned_to})",
                elements.len()
            );

            let leaves = elements.len() as u64;
            for _ in 0..3 {
                let loc = rng.gen_range(pruned_to..leaves);
                let proof = mem.proof(&hasher, Location::new(loc), 0).unwrap();
                assert!(
                    proof.verify_element_inclusion(
                        &hasher,
                        &elements[loc as usize],
                        Location::new(loc),
                        &root
                    ),
                    "proof failed (round={round}, loc={loc})"
                );
            }

            if rng.gen_bool(0.3) {
                pruned_to = rng.gen_range(pruned_to..=leaves);
                mem.prune(Location::new(pruned_to)).unwrap();
            }
        }
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

    // --- MMR tests ---

    #[test]
    fn mmr_randomized_differential() {
        randomized_differential::<crate::mmr::Family>();
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
    fn mmb_randomized_differential() {
        randomized_differential::<crate::mmb::Family>();
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
