//! A lightweight batch layer over a merkleized structure.
//!
//! # Overview
//!
//! [`UnmerkleizedBatch`] accumulates mutations (appends and overwrites) against a parent
//! [`MerkleizedBatch`]. Calling [`UnmerkleizedBatch::merkleize`] computes the root and
//! produces a new [`MerkleizedBatch`]. Batches can be stacked to arbitrary depth
//! (Base <- Layer <- Layer <- ...) to represent speculative chains.
//!
//! All batches are `Arc`-backed, so multiple forks can coexist on the same parent.
//!
//! # Lifecycle
//!
//! ```text
//! MerkleizedBatch::Checkpoint                      (seal committed state as fork point)
//!                           |
//!                      new_batch()
//!                           |
//!                           v
//!                    UnmerkleizedBatch              (accumulate mutations)
//!                           |
//!                      merkleize()
//!                           |
//!                           v
//!                    MerkleizedBatch::Layer         (immutable, has root, supports proofs)
//!                           |
//!                      finalize()
//!                           |
//!                           v
//!                       Changeset                   (owned delta relative to checkpoint)
//!                           |
//!                    mem.apply(cs)
//!                           |
//!                           v
//!                          Mem                      (committed)
//! ```
//!
//! # Checkpoints
//!
//! A [`MerkleizedBatch::Checkpoint`] records the committed size so that
//! [`MerkleizedBatch::finalize`] produces changesets relative to that point. Without it,
//! `base_size()` would recurse through any post-commit layers all the way to the original
//! empty `Base`, producing a changeset the base would reject as stale.
//!
//! # Example (MMR)
//!
//! ```ignore
//! let hasher = StandardHasher::<Sha256>::new();
//! let mut mmr = Mmr::new(&hasher);
//!
//! // Fork two independent speculative chains from the same base.
//! // Clone is cheap -- just an Arc refcount bump.
//! let a1 = mmr.new_batch()
//!     .add(&hasher, b"a1")
//!     .merkleize(&hasher);
//! let b1 = mmr.new_batch()
//!     .add(&hasher, b"b1")
//!     .merkleize(&hasher);
//!
//! // Commit A1. b1 still works because it shares the old state through its own Arc.
//! mmr.apply(a1.finalize()).unwrap();
//! ```

use crate::merkle::{
    hasher::Hasher, mem::Mem, path, proof::Proof, Error, Family, Location, Position, Readable,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use commonware_parallel::ThreadPool;
        use rayon::prelude::*;
    }
}

/// Minimum number of digest computations required to trigger parallelization.
#[cfg(feature = "std")]
pub(crate) const MIN_TO_PARALLELIZE: usize = 20;

// ---------------------------------------------------------------------------
// UnmerkleizedBatch
// ---------------------------------------------------------------------------

/// A batch whose root digest has not been computed.
///
/// Call [`UnmerkleizedBatch::merkleize`] to produce an immutable [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<F: Family, D: Digest> {
    parent: MerkleizedBatch<F, D>,
    appended: Vec<D>,
    overwrites: BTreeMap<Position<F>, D>,
    dirty_nodes: BTreeSet<(u32, Position<F>)>,
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

impl<F: Family, D: Digest> UnmerkleizedBatch<F, D> {
    /// Create a new batch from `parent`.
    pub const fn new(parent: MerkleizedBatch<F, D>) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: BTreeMap::new(),
            dirty_nodes: BTreeSet::new(),
            #[cfg(feature = "std")]
            pool: None,
        }
    }

    /// Set a thread pool for parallel merkleization.
    #[cfg(feature = "std")]
    pub fn with_pool(mut self, pool: Option<ThreadPool>) -> Self {
        self.pool = pool;
        self
    }

    /// The total number of nodes visible through this batch.
    pub(crate) fn size(&self) -> Position<F> {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location<F> {
        Location::try_from(self.size()).expect("invalid size")
    }

    /// Resolve a node: overwrites -> appended -> parent.
    fn get_node(&self, pos: Position<F>) -> Option<D> {
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
        self.parent.get_node(pos)
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
    /// bottom-up so that an early exit is possible when hitting a node that was already
    /// dirtied by a prior `update_leaf`.
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
                if !self.dirty_nodes.insert((h, parent_pos)) {
                    break;
                }
            }
            return;
        }

        panic!("leaf {loc} not found (size: {})", self.size());
    }

    /// Add a pre-computed leaf digest.
    pub fn add_leaf_digest(mut self, digest: D) -> Self {
        let heights = F::parent_heights(self.leaves());
        self.appended.push(digest);

        for height in heights {
            let pos = self.size();
            self.appended.push(D::EMPTY);
            self.dirty_nodes.insert((height, pos));
        }

        self
    }

    /// Hash `element` and add it as a leaf.
    pub fn add(self, hasher: &impl Hasher<F, Digest = D>, element: &[u8]) -> Self {
        let digest = hasher.leaf_digest(self.size(), element);
        self.add_leaf_digest(digest)
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
        let leaves = self.leaves();
        if loc >= leaves {
            return Err(Error::LeafOutOfBounds(loc));
        }
        if loc < self.parent.pruning_boundary() {
            return Err(Error::ElementPruned(Position::try_from(loc)?));
        }
        let pos = Position::try_from(loc)?;
        let digest = hasher.leaf_digest(pos, element);
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(self)
    }

    /// Overwrite the digest of an existing leaf and mark ancestors dirty.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(mut self, loc: Location<F>, digest: D) -> Result<Self, Error<F>> {
        let leaves = self.leaves();
        if loc >= leaves {
            return Err(Error::LeafOutOfBounds(loc));
        }
        if loc < self.parent.pruning_boundary() {
            return Err(Error::ElementPruned(Position::try_from(loc)?));
        }
        let pos = Position::try_from(loc)?;
        if F::position_to_location(pos).is_none() {
            return Err(Error::NonLeaf(pos));
        }
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(self)
    }

    /// Batch update multiple leaf digests.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_batched(mut self, updates: &[(Location<F>, D)]) -> Result<Self, Error<F>> {
        let leaves = self.leaves();
        let prune_boundary = self.parent.pruning_boundary();
        for (loc, _) in updates {
            if *loc >= leaves {
                return Err(Error::LeafOutOfBounds(*loc));
            }
            if *loc < prune_boundary {
                return Err(Error::ElementPruned(Position::try_from(*loc)?));
            }
        }
        for (loc, digest) in updates {
            let pos = Position::try_from(*loc).unwrap();
            self.store_node(pos, *digest);
            self.mark_dirty(*loc);
        }
        Ok(self)
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed root.
    pub fn merkleize(mut self, hasher: &impl Hasher<F, Digest = D>) -> MerkleizedBatch<F, D> {
        let dirty: Vec<_> = core::mem::take(&mut self.dirty_nodes).into_iter().collect();

        #[cfg(feature = "std")]
        if let Some(pool) = self.pool.take() {
            if dirty.len() >= MIN_TO_PARALLELIZE {
                self.merkleize_parallel(hasher, &pool, &dirty);
            } else {
                self.merkleize_serial(hasher, &dirty);
            }
            self.pool = Some(pool);
        } else {
            self.merkleize_serial(hasher, &dirty);
        }

        #[cfg(not(feature = "std"))]
        self.merkleize_serial(hasher, &dirty);

        // Compute root from peaks.
        let leaves = self.leaves();
        let peaks: Vec<D> = F::peaks(self.size())
            .map(|(peak_pos, _)| self.get_node(peak_pos).expect("peak missing"))
            .collect();
        let root = hasher.root(leaves, peaks.iter());

        MerkleizedBatch::Layer(Arc::new(MerkleizedBatchLayer {
            parent_size: self.parent.size(),
            parent: self.parent,
            appended: self.appended,
            overwrites: self.overwrites,
            root,
            #[cfg(feature = "std")]
            pool: self.pool,
        }))
    }

    /// Compute digests for dirty internal nodes, bottom-up by height.
    fn merkleize_serial(
        &mut self,
        hasher: &impl Hasher<F, Digest = D>,
        dirty: &[(u32, Position<F>)],
    ) {
        for &(height, pos) in dirty {
            let (left, right) = F::children(pos, height);
            let left_d = self.get_node(left).expect("left child missing");
            let right_d = self.get_node(right).expect("right child missing");
            let digest = hasher.node_digest(pos, &left_d, &right_d);
            self.store_node(pos, digest);
        }
    }

    /// Process dirty nodes in parallel, grouping by height. Falls back to serial
    /// when the remaining count drops below the threshold.
    #[cfg(feature = "std")]
    fn merkleize_parallel(
        &mut self,
        hasher: &impl Hasher<F, Digest = D>,
        pool: &ThreadPool,
        dirty: &[(u32, Position<F>)],
    ) {
        let mut same_height = Vec::new();
        let mut current_height = dirty.first().map_or(1, |&(h, _)| h);
        for (i, &(height, pos)) in dirty.iter().enumerate() {
            if height == current_height {
                same_height.push(pos);
                continue;
            }
            if same_height.len() < MIN_TO_PARALLELIZE {
                self.merkleize_serial(hasher, &dirty[i - same_height.len()..]);
                return;
            }
            self.compute_height_parallel(hasher, pool, &same_height, current_height);
            same_height.clear();
            current_height = height;
            same_height.push(pos);
        }

        if same_height.len() < MIN_TO_PARALLELIZE {
            self.merkleize_serial(hasher, &dirty[dirty.len() - same_height.len()..]);
            return;
        }

        self.compute_height_parallel(hasher, pool, &same_height, current_height);
    }

    /// Compute digests for nodes at the same height in parallel, then store sequentially.
    #[cfg(feature = "std")]
    fn compute_height_parallel(
        &mut self,
        hasher: &impl Hasher<F, Digest = D>,
        pool: &ThreadPool,
        same_height: &[Position<F>],
        height: u32,
    ) {
        let computed: Vec<(Position<F>, D)> = pool.install(|| {
            same_height
                .par_iter()
                .map_init(
                    || hasher.clone(),
                    |hasher, &pos| {
                        let (left, right) = F::children(pos, height);
                        let left_d = self.get_node(left).expect("left child missing");
                        let right_d = self.get_node(right).expect("right child missing");
                        let digest = hasher.node_digest(pos, &left_d, &right_d);
                        (pos, digest)
                    },
                )
                .collect()
        });
        for (pos, digest) in computed {
            self.store_node(pos, digest);
        }
    }
}

// ---------------------------------------------------------------------------
// MerkleizedBatch
// ---------------------------------------------------------------------------

/// Inner data for a [`MerkleizedBatch::Layer`].
#[derive(Debug)]
pub struct MerkleizedBatchLayer<F: Family, D: Digest> {
    /// The previous chain link (either another layer, a base, or a checkpoint).
    parent: MerkleizedBatch<F, D>,
    /// Digests appended beyond the parent's tip.
    appended: Vec<D>,
    /// Node positions in the parent that this layer overwrites.
    overwrites: BTreeMap<Position<F>, D>,
    /// Root digest including this layer's mutations.
    root: D,
    /// Cached `parent.size()` to avoid re-traversal.
    parent_size: Position<F>,
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

/// A batch whose root digest has been computed.
///
/// These form a singly-linked chain (e.g. `Checkpoint <- Layer <- Layer`) representing
/// speculative state on top of committed data.
#[derive(Clone, Debug)]
pub enum MerkleizedBatch<F: Family, D: Digest> {
    /// The committed on-disk structure. Terminal node of the chain.
    Base(Mem<F, D>),

    /// An uncommitted mutation on top of a parent batch.
    Layer(Arc<MerkleizedBatchLayer<F, D>>),

    /// A wrapper around an existing batch that marks it as the base point for changeset
    /// computation. Adds no data -- all reads delegate to the inner batch. The only
    /// behavioral difference is that [`base_size()`](Self::base_size) returns the wrapped
    /// batch's size instead of recursing further. See [module-level docs](self#checkpoints).
    Checkpoint {
        /// The wrapped batch. All reads delegate here.
        inner: Arc<Self>,
        /// `inner.size()` at creation time. Returned by both `size()` and `base_size()`.
        size: Position<F>,
    },
}

impl<F: Family, D: Digest> MerkleizedBatch<F, D> {
    /// The total number of nodes visible through this batch.
    pub fn size(&self) -> Position<F> {
        match self {
            Self::Base(mem) => mem.size(),
            Self::Layer(layer) => Position::new(*layer.parent_size + layer.appended.len() as u64),
            Self::Checkpoint { size, .. } => *size,
        }
    }

    /// Resolve a node: overwrites -> appended -> parent (recursive).
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
        match self {
            Self::Base(mem) => mem.get_node(pos),
            Self::Layer(layer) => {
                let size = Position::new(*layer.parent_size + layer.appended.len() as u64);
                if pos >= size {
                    return None;
                }
                if let Some(d) = layer.overwrites.get(&pos) {
                    return Some(*d);
                }
                if pos >= layer.parent_size {
                    let i = (*pos - *layer.parent_size) as usize;
                    return layer.appended.get(i).copied();
                }
                layer.parent.get_node(pos)
            }
            Self::Checkpoint { inner, .. } => inner.get_node(pos),
        }
    }

    /// Return the root digest after this batch is applied.
    pub fn root(&self) -> D {
        match self {
            Self::Base(mem) => *mem.root(),
            Self::Layer(layer) => layer.root,
            Self::Checkpoint { inner, .. } => inner.root(),
        }
    }

    /// Items before this location have been pruned.
    pub fn pruning_boundary(&self) -> Location<F> {
        match self {
            Self::Base(mem) => Readable::pruning_boundary(mem),
            Self::Layer(layer) => layer.parent.pruning_boundary(),
            Self::Checkpoint { inner, .. } => inner.pruning_boundary(),
        }
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location<F> {
        Location::try_from(self.size()).expect("invalid size")
    }

    /// Create a child batch on top of this merkleized batch.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, D> {
        let batch = UnmerkleizedBatch::new(self.clone());
        #[cfg(feature = "std")]
        let batch = batch.with_pool(self.pool());
        batch
    }

    /// Get the thread pool from this batch (if any).
    #[cfg(feature = "std")]
    pub(crate) fn pool(&self) -> Option<ThreadPool> {
        match self {
            Self::Base(_) => None,
            Self::Layer(layer) => layer.pool.clone(),
            Self::Checkpoint { inner, .. } => inner.pool(),
        }
    }

    /// Flatten this batch chain into a single [`Changeset`] relative to the
    /// ultimate base.
    pub fn finalize(self) -> Changeset<F, D> {
        let base_size = self.base_size();
        self.finalize_from(base_size)
    }

    /// Like [`Self::finalize`], but produces a [`Changeset`] relative to `current_base`
    /// instead of the chain's original base.
    ///
    /// Use this when an ancestor batch in the chain has already been committed, advancing
    /// the base's size past the original fork point.
    ///
    /// # Panics
    ///
    /// Panics if `current_base` exceeds this batch's size.
    pub fn finalize_from(self, current_base: Position<F>) -> Changeset<F, D> {
        let effective = self.size();
        assert!(
            current_base <= effective,
            "current_base ({current_base:?}) exceeds batch size ({effective:?})"
        );

        // Resolve nodes at [current_base, effective).
        let mut appended = Vec::with_capacity((*effective - *current_base) as usize);
        for i in *current_base..*effective {
            appended.push(self.get_node(Position::new(i)).expect("node in range"));
        }

        // Collect overwrites from the chain, filtered to positions < current_base.
        let mut overwrites = BTreeMap::new();
        self.collect_overwrites(&mut overwrites);
        overwrites.retain(|&pos, _| pos < current_base);

        Changeset {
            appended,
            overwrites,
            root: self.root(),
            base_size: current_base,
        }
    }

    /// Number of nodes in the committed structure this chain was forked from.
    ///
    /// Recurses to the chain root for `Base` and `Layer`. Stops at `Checkpoint`,
    /// which defines the boundary.
    pub fn base_size(&self) -> Position<F> {
        match self {
            Self::Base(mem) => mem.size(),
            Self::Layer(layer) => layer.parent.base_size(),
            Self::Checkpoint { size, .. } => *size,
        }
    }

    /// Collect all overwrites that target nodes in the original structure (i.e. positions <
    /// `base_size()`), walking from the deepest ancestor to the current batch. Later batches
    /// overwrite earlier ones.
    fn collect_overwrites(&self, into: &mut BTreeMap<Position<F>, D>) {
        match self {
            Self::Base(_) | Self::Checkpoint { .. } => {}
            Self::Layer(layer) => {
                layer.parent.collect_overwrites(into);
                for (&pos, &d) in &layer.overwrites {
                    into.insert(pos, d);
                }
            }
        }
    }
}

#[cfg(feature = "std")]
impl<F: Family, D: Digest> MerkleizedBatch<F, D> {
    /// Flatten all layers into a single Base, resolving every node through the chain.
    /// No-op if already a Base. After flattening, node lookups no longer walk the chain.
    ///
    /// Note: the thread pool (if any) is not preserved through flattening.
    pub(crate) fn flatten(&mut self) {
        if matches!(self, Self::Base(_)) {
            return;
        }
        let root = self.root();
        let size = self.size();
        let leaves = self.leaves();
        let pruning_boundary = self.pruning_boundary();
        let pruning_pos = Position::try_from(pruning_boundary).expect("valid pruning_boundary");

        // Collect pinned nodes (peaks at the prune boundary).
        let mut pinned_nodes = BTreeMap::new();
        for pos in F::nodes_to_pin(leaves, pruning_boundary) {
            let d = self
                .get_node(pos)
                .expect("pinned node must exist in batch chain");
            pinned_nodes.insert(pos, d);
        }

        // Collect retained nodes above the prune boundary.
        let mut retained = Vec::with_capacity((*size - *pruning_pos) as usize);
        for p in *pruning_pos..*size {
            retained.push(self.get_node(Position::new(p)).expect("node in range"));
        }

        *self = Self::Base(Mem::from_pruned_with_retained(
            root,
            pruning_pos,
            pinned_nodes,
            retained,
        ));
    }

    /// Push a changeset as a new layer on top of this batch, mutating `self` in place.
    /// The old value becomes the parent of the new layer.
    /// Panics if the changeset base size does not match the current size.
    pub(crate) fn push_changeset(&mut self, changeset: Changeset<F, D>) {
        let parent_size = self.size();
        assert_eq!(
            changeset.base_size, parent_size,
            "changeset base_size mismatch"
        );
        let parent = self.clone();
        *self = Self::Layer(Arc::new(MerkleizedBatchLayer {
            parent_size,
            parent,
            appended: changeset.appended,
            overwrites: changeset.overwrites,
            root: changeset.root,
            #[cfg(feature = "std")]
            pool: None,
        }));
    }
}

impl<F: Family, D: Digest> Readable for MerkleizedBatch<F, D> {
    type Family = F;
    type Digest = D;
    type Error = Error<F>;

    fn size(&self) -> Position<F> {
        Self::size(self)
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        Self::get_node(self, pos)
    }

    fn root(&self) -> D {
        Self::root(self)
    }

    fn pruning_boundary(&self) -> Location<F> {
        Self::pruning_boundary(self)
    }

    fn proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid_index() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::RangeOutOfBounds(_) => Error::LeafOutOfBounds(loc),
            _ => e,
        })
    }

    fn range_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        range: Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        crate::merkle::proof::build_range_proof(
            hasher,
            self.leaves(),
            range,
            |pos| Self::get_node(self, pos),
            Error::ElementPruned,
        )
    }
}

// ---------------------------------------------------------------------------
// Changeset
// ---------------------------------------------------------------------------

/// Owned set of changes against a base Merkle structure.
pub struct Changeset<F: Family, D: Digest> {
    /// Nodes appended after the base structure's existing nodes.
    pub(crate) appended: Vec<D>,
    /// Overwritten nodes within the base structure's range.
    pub(crate) overwrites: BTreeMap<Position<F>, D>,
    /// Root digest after applying the changeset.
    pub(crate) root: D,
    /// Size of the base structure when this changeset was created.
    pub(crate) base_size: Position<F>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, mem::Mem};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn build_reference<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new(hasher);
        let changeset = {
            let mut batch = mem.new_batch();
            for i in 0u64..n {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(hasher, &element);
            }
            batch.merkleize(hasher).finalize()
        };
        mem.apply(changeset).unwrap();
        mem
    }

    fn consistency_with_reference<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            for &n in &[1u64, 2, 10, 100, 199] {
                let reference = build_reference::<F>(&hasher, n);
                let base = Mem::<F, D>::new(&hasher);
                let mut batch = base.new_batch();
                for i in 0..n {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                let merkleized = batch.merkleize(&hasher);
                let changeset = merkleized.finalize();
                let mut result = Mem::<F, D>::new(&hasher);
                result.apply(changeset).unwrap();
                assert_eq!(result.root(), reference.root(), "root mismatch for n={n}");
            }
        });
    }

    fn lifecycle<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let base_root = *base.root();
            let mut batch = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);
            assert_ne!(merkleized.root(), base_root);
            let loc = Location::<F>::new(55);
            let element = hasher.digest(&55u64.to_be_bytes());
            let proof = merkleized.proof(&hasher, loc).unwrap();
            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &merkleized.root()));
            assert_eq!(*base.root(), base_root);
        });
    }

    fn changeset_apply<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..75 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);
            let batch_root = merkleized.root();
            base.apply(merkleized.finalize()).unwrap();
            assert_eq!(*base.root(), batch_root);
            let reference = build_reference::<F>(&hasher, 75);
            assert_eq!(base.root(), reference.root());
        });
    }

    fn multiple_forks<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let base_root = *base.root();
            let mut ba = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                ba = ba.add(&hasher, &element);
            }
            let ma = ba.merkleize(&hasher);
            let mut bb = base.new_batch();
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                bb = bb.add(&hasher, &element);
            }
            let mb = bb.merkleize(&hasher);
            assert_ne!(ma.root(), mb.root());
            assert_ne!(ma.root(), base_root);
            assert_eq!(*base.root(), base_root);
        });
    }

    fn fork_of_fork_reads<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut ba = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                ba = ba.add(&hasher, &element);
            }
            let ma = ba.merkleize(&hasher);
            let mut bb = ma.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                bb = bb.add(&hasher, &element);
            }
            let mb = bb.merkleize(&hasher);
            let reference = build_reference::<F>(&hasher, 70);
            assert_eq!(mb.root(), *reference.root());
            for i in [0u64, 25, 55, 65, 69] {
                let loc = Location::<F>::new(i);
                let element = hasher.digest(&i.to_be_bytes());
                let proof = mb.proof(&hasher, loc).unwrap();
                assert!(proof.verify_element_inclusion(&hasher, &element, loc, &mb.root()));
            }
        });
    }

    fn fork_of_fork_flattened<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 50);
            let mut ba = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                ba = ba.add(&hasher, &element);
            }
            let ma = ba.merkleize(&hasher);
            let mut bb = ma.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                bb = bb.add(&hasher, &element);
            }
            let mb = bb.merkleize(&hasher);
            let b_root = mb.root();
            let changeset = mb.finalize();
            drop(ma);
            base.apply(changeset).unwrap();
            assert_eq!(*base.root(), b_root);
        });
    }

    fn update_leaf_digest_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 100);
            let base_root = *base.root();
            let updated = Sha256::fill(0xFF);
            let m = base
                .new_batch()
                .update_leaf_digest(Location::new(5), updated)
                .unwrap()
                .merkleize(&hasher);
            assert_ne!(m.root(), base_root);
            let pos5 = Position::<F>::try_from(Location::new(5)).unwrap();
            let original = base.get_node(pos5).unwrap();
            let m2 = base
                .new_batch()
                .update_leaf_digest(Location::new(5), original)
                .unwrap()
                .merkleize(&hasher);
            assert_eq!(m2.root(), base_root);
        });
    }

    fn update_and_add<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let base_root = *base.root();
            let updated = Sha256::fill(0xAA);
            let mut batch = base
                .new_batch()
                .update_leaf_digest(Location::new(10), updated)
                .unwrap();
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let m = batch.merkleize(&hasher);
            assert_ne!(m.root(), base_root);
            let pos10 = Position::<F>::try_from(Location::new(10)).unwrap();
            assert_eq!(m.get_node(pos10), Some(updated));
        });
    }

    fn update_leaf_batched_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 100);
            let base_root = *base.root();
            let updated = Sha256::fill(0xBB);
            let locs = [0u64, 10, 50, 99];
            let updates: Vec<(Location<F>, D)> =
                locs.iter().map(|&i| (Location::new(i), updated)).collect();
            let m = base
                .new_batch()
                .update_leaf_batched(&updates)
                .unwrap()
                .merkleize(&hasher);
            assert_ne!(m.root(), base_root);
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
                .merkleize(&hasher);
            assert_eq!(m2.root(), base_root);
        });
    }

    fn proof_verification<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let m = batch.merkleize(&hasher);
            let loc = Location::<F>::new(55);
            let element = hasher.digest(&55u64.to_be_bytes());
            let proof = m.proof(&hasher, loc).unwrap();
            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &m.root()));
            let range = Location::<F>::new(50)..Location::new(55);
            let rp = m.range_proof(&hasher, range.clone()).unwrap();
            let elements: Vec<D> = (50u64..55)
                .map(|i| hasher.digest(&i.to_be_bytes()))
                .collect();
            assert!(rp.verify_range_inclusion(&hasher, &elements, range.start, &m.root()));
        });
    }

    fn empty_batch<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let base_root = *base.root();
            let m = base.new_batch().merkleize(&hasher);
            assert_eq!(m.root(), base_root);
        });
    }

    fn batch_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);
            let mut batch_again = merkleized.new_batch();
            for i in 55u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_again = batch_again.add(&hasher, &element);
            }
            let reference = build_reference::<F>(&hasher, 60);
            assert_eq!(batch_again.merkleize(&hasher).root(), *reference.root());
        });
    }

    fn sequential_changesets<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 50);
            let mut b1 = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                b1 = b1.add(&hasher, &element);
            }
            base.apply(b1.merkleize(&hasher).finalize()).unwrap();
            let mut b2 = base.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                b2 = b2.add(&hasher, &element);
            }
            base.apply(b2.merkleize(&hasher).finalize()).unwrap();
            let reference = build_reference::<F>(&hasher, 70);
            assert_eq!(base.root(), reference.root());
        });
    }

    fn batch_on_pruned_base<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 100);
            base.prune(Location::new(27)).unwrap();
            let mut batch = base.new_batch();
            for i in 100u64..110 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let m = batch.merkleize(&hasher);
            let loc = Location::<F>::new(80);
            let element = hasher.digest(&80u64.to_be_bytes());
            let proof = m.proof(&hasher, loc).unwrap();
            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &m.root()));
            assert!(matches!(
                m.proof(&hasher, Location::new(0)),
                Err(Error::ElementPruned(_))
            ));
        });
    }

    fn three_deep_stacking<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 100);
            let da = Sha256::fill(0xDD);
            let db = Sha256::fill(0xEE);
            let ma = base
                .new_batch()
                .update_leaf_digest(Location::new(5), da)
                .unwrap()
                .merkleize(&hasher);
            let mb = ma
                .new_batch()
                .update_leaf_digest(Location::new(10), db)
                .unwrap()
                .merkleize(&hasher);
            let mut bc = mb.new_batch();
            for i in 300u64..310 {
                let element = hasher.digest(&i.to_be_bytes());
                bc = bc.add(&hasher, &element);
            }
            let mc = bc.merkleize(&hasher);
            let c_root = mc.root();
            let changeset = mc.finalize();
            drop(mb);
            drop(ma);
            base.apply(changeset).unwrap();
            assert_eq!(*base.root(), c_root);
        });
    }

    fn overwrite_collision<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 100);
            let dx = Sha256::fill(0xAA);
            let dy = Sha256::fill(0xBB);
            let ma = base
                .new_batch()
                .update_leaf_digest(Location::new(5), dx)
                .unwrap()
                .merkleize(&hasher);
            let mb = ma
                .new_batch()
                .update_leaf_digest(Location::new(5), dy)
                .unwrap()
                .merkleize(&hasher);
            let b_root = mb.root();
            let changeset = mb.finalize();
            drop(ma);
            base.apply(changeset).unwrap();
            assert_eq!(*base.root(), b_root);
            let pos5 = Position::<F>::try_from(Location::new(5)).unwrap();
            assert_eq!(base.get_node(pos5), Some(dy));
        });
    }

    fn update_appended_leaf<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
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
                .merkleize(&hasher);
            let pos52 = Position::<F>::try_from(Location::new(52)).unwrap();
            assert_eq!(m.get_node(pos52), Some(updated));
            let mut reference = build_reference::<F>(&hasher, 60);
            let cs = reference
                .new_batch()
                .update_leaf_digest(Location::new(52), updated)
                .unwrap()
                .merkleize(&hasher)
                .finalize();
            reference.apply(cs).unwrap();
            assert_eq!(m.root(), *reference.root());
        });
    }

    fn update_leaf_element<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let base_root = *base.root();
            let element = b"updated-element";
            let m = base
                .new_batch()
                .update_leaf(&hasher, Location::new(5), element)
                .unwrap()
                .merkleize(&hasher);
            assert_ne!(m.root(), base_root);
            let mut base = base;
            let cs = base
                .new_batch()
                .update_leaf(&hasher, Location::new(5), element)
                .unwrap()
                .merkleize(&hasher)
                .finalize();
            base.apply(cs).unwrap();
            assert_eq!(m.root(), *base.root());
        });
    }

    fn update_out_of_bounds<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
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

    fn finalize_from<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 50);

            // Layer A: add 10 elements.
            let mut batch_a = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B on A: add 10 more.
            let mut batch_b = merkleized_a.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);

            // Commit A first.
            let cs_a = merkleized_a.finalize();
            base.apply(cs_a).unwrap();

            // Commit B relative to the new base.
            let cs_b = merkleized_b.finalize_from(base.size());
            base.apply(cs_b).unwrap();

            let reference = build_reference::<F>(&hasher, 70);
            assert_eq!(base.root(), reference.root());
        });
    }

    fn finalize_from_with_overwrites<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut base = build_reference::<F>(&hasher, 50);

            let digest_x = Sha256::fill(0xAA);
            let digest_y = Sha256::fill(0xBB);

            // Layer A: overwrite leaf 5 with X.
            let batch_a = base
                .new_batch()
                .update_leaf_digest(Location::new(5), digest_x)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B on A: overwrite leaf 5 with Y, add leaves.
            let mut batch_b = merkleized_a
                .new_batch()
                .update_leaf_digest(Location::new(5), digest_y)
                .unwrap();
            for i in 60u64..65 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);
            let expected_root = merkleized_b.root();

            // Commit A first.
            let cs_a = merkleized_a.finalize();
            base.apply(cs_a).unwrap();

            // Commit B relative to new base.
            let cs_b = merkleized_b.finalize_from(base.size());
            base.apply(cs_b).unwrap();

            assert_eq!(*base.root(), expected_root);
            let pos5 = Position::<F>::try_from(Location::new(5)).unwrap();
            assert_eq!(
                base.get_node(pos5),
                Some(digest_y),
                "overwrite in intermediate range was lost"
            );
        });
    }

    fn flatten_base_noop<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = MerkleizedBatch::<F, D>::Base(base);
            let root_before = batch.root();
            let size_before = batch.size();
            batch.flatten();
            assert!(matches!(batch, MerkleizedBatch::Base(_)));
            assert_eq!(batch.root(), root_before);
            assert_eq!(batch.size(), size_before);
        });
    }

    fn flatten_single_layer<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let updated = Sha256::fill(0xEE);
            let batch = batch
                .update_leaf_digest(Location::new(52), updated)
                .unwrap();
            let mut merkleized = batch.merkleize(&hasher);
            assert!(matches!(merkleized, MerkleizedBatch::Layer(_)));
            let root_before = merkleized.root();
            let size_before = merkleized.size();
            merkleized.flatten();
            assert!(matches!(merkleized, MerkleizedBatch::Base(_)));
            assert_eq!(merkleized.root(), root_before);
            assert_eq!(merkleized.size(), size_before);
        });
    }

    fn flatten_deep_chain<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut ba = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                ba = ba.add(&hasher, &element);
            }
            let ma = ba.merkleize(&hasher);
            let mut bb = ma.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                bb = bb.add(&hasher, &element);
            }
            let mb = bb.merkleize(&hasher);
            let mut bc = mb.new_batch();
            for i in 70u64..80 {
                let element = hasher.digest(&i.to_be_bytes());
                bc = bc.add(&hasher, &element);
            }
            let mut mc = bc.merkleize(&hasher);
            let root_before = mc.root();
            let size_before = mc.size();
            mc.flatten();
            assert!(matches!(mc, MerkleizedBatch::Base(_)));
            assert_eq!(mc.root(), root_before);
            assert_eq!(mc.size(), size_before);
            let reference = build_reference::<F>(&hasher, 80);
            assert_eq!(mc.root(), *reference.root());
        });
    }

    fn flatten_idempotent<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let mut merkleized = batch.merkleize(&hasher);
            merkleized.flatten();
            let root_after = merkleized.root();
            let size_after = merkleized.size();
            merkleized.flatten();
            assert_eq!(merkleized.root(), root_after);
            assert_eq!(merkleized.size(), size_after);
        });
    }

    fn flatten_with_overwrites<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 100);
            let da = Sha256::fill(0xDD);
            let db = Sha256::fill(0xEE);
            let batch_a = base
                .new_batch()
                .update_leaf_digest(Location::new(5), da)
                .unwrap();
            let ma = batch_a.merkleize(&hasher);
            let batch_b = ma
                .new_batch()
                .update_leaf_digest(Location::new(5), db)
                .unwrap();
            let mut mb = batch_b.merkleize(&hasher);
            let root_before = mb.root();
            let pos5 = Position::<F>::try_from(Location::new(5)).unwrap();
            assert_eq!(mb.get_node(pos5), Some(db));
            mb.flatten();
            assert!(matches!(mb, MerkleizedBatch::Base(_)));
            assert_eq!(mb.root(), root_before);
            assert_eq!(mb.get_node(pos5), Some(db));
        });
    }

    // --- MMR tests ---

    #[test]
    fn mmr_consistency() {
        consistency_with_reference::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_lifecycle() {
        lifecycle::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_changeset_apply() {
        changeset_apply::<crate::mmr::Family>();
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
    fn mmr_fork_of_fork_flattened() {
        fork_of_fork_flattened::<crate::mmr::Family>();
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
    fn mmr_sequential_changesets() {
        sequential_changesets::<crate::mmr::Family>();
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
    fn mmr_finalize_from() {
        finalize_from::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_finalize_from_with_overwrites() {
        finalize_from_with_overwrites::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_flatten_base_noop() {
        flatten_base_noop::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_flatten_single_layer() {
        flatten_single_layer::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_flatten_deep_chain() {
        flatten_deep_chain::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_flatten_idempotent() {
        flatten_idempotent::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_flatten_with_overwrites() {
        flatten_with_overwrites::<crate::mmr::Family>();
    }

    // --- MMB tests ---

    #[test]
    fn mmb_consistency() {
        consistency_with_reference::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_lifecycle() {
        lifecycle::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_changeset_apply() {
        changeset_apply::<crate::mmb::Family>();
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
    fn mmb_fork_of_fork_flattened() {
        fork_of_fork_flattened::<crate::mmb::Family>();
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
    fn mmb_sequential_changesets() {
        sequential_changesets::<crate::mmb::Family>();
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
    fn mmb_finalize_from() {
        finalize_from::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_finalize_from_with_overwrites() {
        finalize_from_with_overwrites::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_flatten_base_noop() {
        flatten_base_noop::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_flatten_single_layer() {
        flatten_single_layer::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_flatten_deep_chain() {
        flatten_deep_chain::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_flatten_idempotent() {
        flatten_idempotent::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_flatten_with_overwrites() {
        flatten_with_overwrites::<crate::mmb::Family>();
    }
}
