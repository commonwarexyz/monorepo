//! A lightweight batch layer over a merkleized MMR.
//!
//! # Overview
//!
//! [`MerkleizedBatch`] is an immutable, reference-counted MMR state (persistent data structure).
//! [`UnmerkleizedBatch`] accumulates mutations against a parent batch. After merkleization the
//! batch produces a new [`MerkleizedBatch`]. Because batches are behind [`Arc`], they can be
//! freely cloned and stored in homogeneous collections regardless of chain depth.
//!
//! - [`Changeset`] -- owned delta that can be applied to the base MMR.
//! - [`MerkleizedBatch::Snapshot`] -- a sealed view where `base_size() == size()`, created by
//!   `to_batch()` to seal committed state as a fork point.
//!
//! # Example
//!
//! ```ignore
//! let hasher = StandardHasher::<Sha256>::new();
//! let mut mmr = Mmr::new(&hasher);
//!
//! // Fork two independent speculative chains from the same base.
//! // Clone is O(1) -- just an Arc refcount bump.
//! let a1 = mmr.new_batch()
//!     .add(&hasher, b"a1")
//!     .merkleize(&hasher);
//! let b1 = mmr.new_batch()
//!     .add(&hasher, b"b1")
//!     .merkleize(&hasher);
//!
//! // Extend each chain with a second batch.
//! let a2 = {
//!     let mut batch = a1.new_batch();
//!     batch.add(&hasher, b"a2");
//!     batch.merkleize(&hasher)
//! };
//! let b2 = {
//!     let mut batch = b1.new_batch();
//!     batch.add(&hasher, b"b2");
//!     batch.merkleize(&hasher)
//! };
//!
//! // Commit A1. a2, b1, b2 all still work because they share the
//! // old state through their own Arcs.
//! mmr.apply(a1.finalize()).unwrap();
//!
//! // Commit A2 on top of A1. A2's full chain targets the original
//! // base, but A1 is already committed. finalize_from skips A1's
//! // nodes and produces only A2's delta.
//! mmr.apply(a2.finalize_from(mmr.size())).unwrap();
//! ```

use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_needing_parents, PathIterator, PeakIterator},
    mem::Mmr,
    read::Readable,
    Error, Location, Position,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec::Vec,
};
use commonware_cryptography::Digest;
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use commonware_parallel::ThreadPool;
        use rayon::prelude::*;
    }
}

/// A batch whose root digest has not been computed.
///
/// Call [`UnmerkleizedBatch::merkleize`] to produce an immutable [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<D: Digest> {
    parent: MerkleizedBatch<D>,
    appended: Vec<D>,
    overwrites: BTreeMap<Position, D>,
    dirty_nodes: BTreeSet<(Position, u32)>,
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

impl<D: Digest> UnmerkleizedBatch<D> {
    /// Create a new batch from `parent`.
    /// O(1) time and space (the parent is an `Arc`-backed persistent structure).
    pub const fn new(parent: MerkleizedBatch<D>) -> Self {
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
    pub(crate) fn size(&self) -> Position {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmr size")
    }

    /// Resolve a node: overwrites -> appended -> parent.
    fn get_node(&self, pos: Position) -> Option<D> {
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

    /// Store a digest to `pos`.
    fn store_node(&mut self, pos: Position, digest: D) {
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
        let nodes_needing_parents = nodes_needing_parents(PeakIterator::new(self.size()))
            .into_iter()
            .rev();
        self.appended.push(digest);

        let mut height = 1;
        for _ in nodes_needing_parents {
            let new_node_pos = self.size();
            self.appended.push(D::EMPTY);
            self.dirty_nodes.insert((new_node_pos, height));
            height += 1;
        }

        self
    }

    /// Hash `element` and add it as a leaf.
    pub fn add(self, hasher: &impl Hasher<Digest = D>, element: &[u8]) -> Self {
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
        hasher: &impl Hasher<Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<Self, Error> {
        let leaves = Location::try_from(self.size()).expect("invalid mmr size");
        if loc >= leaves {
            return Err(Error::LeafOutOfBounds(loc));
        }
        let pos = Position::try_from(loc)?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
        let digest = hasher.leaf_digest(pos, element);
        self.store_node(pos, digest);
        self.mark_dirty(pos);
        Ok(self)
    }

    /// Overwrite the digest of an existing leaf and mark ancestors dirty.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(mut self, loc: Location, digest: D) -> Result<Self, Error> {
        let pos = Position::try_from(loc).map_err(|_| Error::LocationOverflow(loc))?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
        if pos >= self.size() {
            return Err(Error::InvalidPosition(pos));
        }
        self.store_node(pos, digest);
        self.mark_dirty(pos);
        Ok(self)
    }

    /// Batch update multiple leaf digests.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_batched(mut self, updates: &[(Location, D)]) -> Result<Self, Error> {
        let leaves = Location::try_from(self.size()).expect("invalid mmr size");
        let prune_boundary = self.parent.pruned_to_pos();
        let mut positions = Vec::with_capacity(updates.len());
        for (loc, _) in updates {
            if *loc >= leaves {
                return Err(Error::LeafOutOfBounds(*loc));
            }
            let pos = Position::try_from(*loc)?;
            if pos < prune_boundary {
                return Err(Error::ElementPruned(pos));
            }
            positions.push(pos);
        }
        for ((_, digest), pos) in updates.iter().zip(positions.iter()) {
            self.store_node(*pos, *digest);
            self.mark_dirty(*pos);
        }
        Ok(self)
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed root.
    pub fn merkleize(mut self, hasher: &impl Hasher<Digest = D>) -> MerkleizedBatch<D> {
        let mut dirty: Vec<_> = core::mem::take(&mut self.dirty_nodes).into_iter().collect();
        dirty.sort_by_key(|a| a.1);

        #[cfg(feature = "std")]
        if let Some(pool) = self.pool.take() {
            use crate::mmr::mem::MIN_TO_PARALLELIZE;

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
        let leaves = Location::try_from(self.size()).expect("invalid mmr size");
        let peaks: Vec<D> = PeakIterator::new(self.size())
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
    fn merkleize_serial(&mut self, hasher: &impl Hasher<Digest = D>, dirty: &[(Position, u32)]) {
        for &(pos, height) in dirty {
            let left = pos - (1 << height);
            let right = pos - 1;
            let left_d = self.get_node(left).expect("left child missing");
            let right_d = self.get_node(right).expect("right child missing");
            let digest = hasher.node_digest(pos, &left_d, &right_d);
            self.store_node(pos, digest);
        }
    }

    /// Process dirty nodes in parallel, grouping by height. Falls back to `merkleize_serial`
    /// when the remaining count drops below `MIN_TO_PARALLELIZE`.
    #[cfg(feature = "std")]
    fn merkleize_parallel(
        &mut self,
        hasher: &impl Hasher<Digest = D>,
        pool: &ThreadPool,
        dirty: &[(Position, u32)],
    ) {
        use crate::mmr::mem::MIN_TO_PARALLELIZE;

        let mut same_height = Vec::new();
        let mut current_height = 1;
        for (i, &(pos, height)) in dirty.iter().enumerate() {
            if height == current_height {
                same_height.push(pos);
                continue;
            }
            if same_height.len() < MIN_TO_PARALLELIZE {
                self.merkleize_serial(hasher, &dirty[i - same_height.len()..]);
                return;
            }
            self.update_node_digests(hasher, pool, &same_height, current_height);
            same_height.clear();
            current_height += 1;
            same_height.push(pos);
        }

        if same_height.len() < MIN_TO_PARALLELIZE {
            self.merkleize_serial(hasher, &dirty[dirty.len() - same_height.len()..]);
            return;
        }

        self.update_node_digests(hasher, pool, &same_height, current_height);
    }

    /// Compute digests for nodes at the same height in parallel, then apply sequentially.
    #[cfg(feature = "std")]
    fn update_node_digests(
        &mut self,
        hasher: &impl Hasher<Digest = D>,
        pool: &ThreadPool,
        same_height: &[Position],
        height: u32,
    ) {
        let two_h = 1 << height;
        let computed: Vec<(Position, D)> = pool.install(|| {
            same_height
                .par_iter()
                .map_init(
                    || hasher.clone(),
                    |hasher, &pos| {
                        let left = pos - two_h;
                        let right = pos - 1;
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

    /// Mark ancestors of `pos` as dirty up to the peak.
    fn mark_dirty(&mut self, pos: Position) {
        for (peak_pos, mut height) in PeakIterator::new(self.size()) {
            if peak_pos < pos {
                continue;
            }

            let path = PathIterator::new(pos, peak_pos, height)
                .collect::<Vec<_>>()
                .into_iter()
                .rev();
            height = 1;
            for (parent_pos, _) in path {
                if !self.dirty_nodes.insert((parent_pos, height)) {
                    break;
                }
                height += 1;
            }
            return;
        }

        panic!("invalid pos {pos}:{}", self.size());
    }
}

/// A batch whose root digest has been computed.
///
/// `Clone` is O(1) (`Arc::clone`). Batches can be freely shared and stored in homogeneous
/// collections regardless of chain depth.
#[derive(Clone, Debug)]
pub enum MerkleizedBatch<D: Digest> {
    /// Committed MMR (chain terminal). `Mmr` is already `Arc`-wrapped internally,
    /// so cloning is O(1).
    Base(Mmr<D>),
    /// Speculative layer on top of a parent batch.
    Layer(Arc<MerkleizedBatchLayer<D>>),
    /// Sealed snapshot of a (possibly layered) chain.
    ///
    /// Acts as a chain terminator for [`MerkleizedBatch::base_size`]: the chain's tip size is
    /// reported as the base, so [`Self::finalize`] produces changesets relative to the snapshot
    /// point rather than recursing to the original `Base`.
    ///
    /// This is necessary because `push_changeset` builds a `Layer` on top of the DB's existing
    /// state. Without `Snapshot`, a batch forked from the post-push state would recurse through
    /// the new `Layer` all the way to the original `Base`, yielding `base_size() == 0` instead
    /// of the current tip. The resulting changeset would then fail the stale-changeset check in
    /// [`super::journaled::Mmr::apply`].
    Snapshot {
        /// The sealed chain. Reads (`get_node`, `root`, etc.) delegate here.
        inner: Arc<Self>,
        /// `inner.size()` cached at creation time. Returned by both `size()` and `base_size()`,
        /// which is what prevents the `base_size` recursion from walking past this point.
        size: Position,
    },
}

/// The data behind a [`MerkleizedBatch::Layer`].
#[derive(Debug)]
pub struct MerkleizedBatchLayer<D: Digest> {
    /// The previous chain link (either another layer, a base, or a snapshot).
    parent: MerkleizedBatch<D>,
    /// Digests appended beyond the parent's tip.
    appended: Vec<D>,
    /// Node positions in the parent that this layer overwrites.
    overwrites: BTreeMap<Position, D>,
    /// Root digest of the MMR including this layer's mutations.
    root: D,
    /// Cached `parent.size()` to avoid re-traversal.
    parent_size: Position,
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

impl<D: Digest> MerkleizedBatch<D> {
    /// The total number of nodes visible through this batch.
    pub fn size(&self) -> Position {
        match self {
            Self::Base(mmr) => mmr.size(),
            Self::Layer(layer) => Position::new(*layer.parent_size + layer.appended.len() as u64),
            Self::Snapshot { size, .. } => *size,
        }
    }

    /// Resolve a node: overwrites -> appended -> parent (recursive).
    pub fn get_node(&self, pos: Position) -> Option<D> {
        match self {
            Self::Base(mmr) => mmr.get_node(pos),
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
            Self::Snapshot { inner, .. } => inner.get_node(pos),
        }
    }

    /// Return the root digest of the authenticated journal after this batch is applied.
    pub fn root(&self) -> D {
        match self {
            Self::Base(mmr) => *mmr.root(),
            Self::Layer(layer) => layer.root,
            Self::Snapshot { inner, .. } => inner.root(),
        }
    }

    /// Items before this position have been pruned.
    pub fn pruned_to_pos(&self) -> Position {
        match self {
            Self::Base(mmr) => Readable::pruned_to_pos(mmr),
            Self::Layer(layer) => layer.parent.pruned_to_pos(),
            Self::Snapshot { inner, .. } => inner.pruned_to_pos(),
        }
    }

    /// Create a child batch on top of this merkleized batch.
    pub fn new_batch(&self) -> UnmerkleizedBatch<D> {
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
            Self::Snapshot { inner, .. } => inner.pool(),
        }
    }

    /// Flatten this batch chain into a single [`Changeset`] relative to the
    /// ultimate base MMR.
    pub fn finalize(self) -> Changeset<D> {
        let base_size = self.base_size();
        self.finalize_from(base_size)
    }

    /// Like [`Self::finalize`], but produces a [`Changeset`] relative to `current_base`
    /// instead of the chain's original base.
    ///
    /// Use this when an ancestor batch in the chain has already been committed, advancing
    /// the base MMR's size past the original fork point. For example, given a chain
    /// `base -> A -> B`, after committing A the base size advances. Calling
    /// `B.finalize_from(mmr.size())` produces a changeset containing only B's delta.
    ///
    /// Calling `finalize()` in this situation would produce a changeset targeting the
    /// original base size, which `apply()` rejects as stale.
    ///
    /// # Panics
    ///
    /// Panics if `current_base` exceeds this batch's size.
    pub fn finalize_from(self, current_base: Position) -> Changeset<D> {
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
}

impl<D: Digest> Readable for MerkleizedBatch<D> {
    type Digest = D;

    fn size(&self) -> Position {
        Self::size(self)
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        Self::get_node(self, pos)
    }

    fn root(&self) -> D {
        Self::root(self)
    }

    fn pruned_to_pos(&self) -> Position {
        Self::pruned_to_pos(self)
    }
}

impl<D: Digest> MerkleizedBatch<D> {
    /// Number of nodes in the MMR that this batch chain was forked from.
    ///
    /// For `Base` and `Layer` this recurses to the root of the chain.
    /// For `Snapshot` it returns the size at the snapshot point, allowing
    /// child chains to treat the snapshot as their base.
    pub fn base_size(&self) -> Position {
        match self {
            Self::Base(mmr) => mmr.size(),
            Self::Layer(layer) => layer.parent.base_size(),
            Self::Snapshot { size, .. } => *size,
        }
    }

    /// Collect all overwrites that target nodes in the original MMR (i.e. positions <
    /// `base_size()`), walking from the deepest ancestor to the current batch. Later batches
    /// overwrite earlier ones.
    fn collect_overwrites(&self, into: &mut BTreeMap<Position, D>) {
        match self {
            Self::Base(_) | Self::Snapshot { .. } => {}
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
impl<D: Digest> MerkleizedBatch<D> {
    /// Flatten all layers into a single Base, resolving every node through the chain.
    /// No-op if already a Base. After flattening, node lookups no longer walk the chain.
    ///
    /// Note: the thread pool (if any) is not preserved through flattening. Callers that need
    /// parallel merkleization should re-apply the pool via `with_pool()`.
    pub(crate) fn flatten(&mut self) {
        if matches!(self, Self::Base(_)) {
            return;
        }
        let root = self.root();
        let size = self.size();
        let pruned_to_pos = self.pruned_to_pos();

        // Collect pinned nodes (peaks at the prune boundary).
        let mut pinned_nodes = BTreeMap::new();
        for pos in crate::mmr::iterator::nodes_to_pin(pruned_to_pos) {
            let d = self
                .get_node(pos)
                .expect("pinned node must exist in batch chain");
            pinned_nodes.insert(pos, d);
        }

        // Collect retained nodes above the prune boundary.
        let mut retained = Vec::with_capacity((*size - *pruned_to_pos) as usize);
        for p in *pruned_to_pos..*size {
            retained.push(self.get_node(Position::new(p)).expect("node in range"));
        }

        *self = Self::Base(Mmr::from_pruned_with_retained(
            root,
            pruned_to_pos,
            pinned_nodes,
            retained,
        ));
    }

    /// Push a changeset as a new layer on top of this batch, mutating `self` in place.
    /// `self.clone()` is O(1) (Arc clone). The old value becomes the parent of the new layer.
    /// Panics if the changeset base size does not match the current size.
    pub(crate) fn push_changeset(&mut self, changeset: Changeset<D>) {
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

/// Owned set of changes against a base MMR.
/// Apply via [`super::mem::Mmr::apply`] or [`super::journaled::Mmr::apply`].
pub struct Changeset<D: Digest> {
    /// Nodes appended after the base MMR's existing nodes.
    pub(crate) appended: Vec<D>,
    /// Overwritten nodes within the base MMR's range.
    pub(crate) overwrites: BTreeMap<Position, D>,
    /// Root digest after applying the changeset.
    pub(crate) root: D,
    /// Size of the base MMR when this changeset was created.
    pub(crate) base_size: Position,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{conformance::build_test_mmr, hasher::Standard, mem::Mmr, read::Readable};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    /// Build a reference MMR with `n` elements for comparison.
    fn build_reference(hasher: &Standard<Sha256>, n: u64) -> Mmr<sha256::Digest> {
        let mmr = Mmr::new(hasher);
        build_test_mmr(hasher, mmr, n)
    }

    /// Helper: wrap an Mmr in a MerkleizedBatch::Base.
    fn base_batch(
        mmr: Mmr<sha256::Digest>,
    ) -> (Mmr<sha256::Digest>, MerkleizedBatch<sha256::Digest>) {
        let base = MerkleizedBatch::Base(mmr.clone());
        (mmr, base)
    }

    /// Build via MerkleizedBatch/UnmerkleizedBatch and verify consistency with reference Mmr.
    #[test]
    fn test_consistency_with_reference() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();

            for &n in &[1u64, 2, 10, 100, 199] {
                let reference = build_reference(&hasher, n);

                let base = Mmr::new(&hasher);
                let (_, parent) = base_batch(base);

                let mut batch = UnmerkleizedBatch::new(parent);
                for i in 0..n {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                let merkleized = batch.merkleize(&hasher);
                let changeset = merkleized.finalize();
                let mut result = Mmr::new(&hasher);
                result.apply(changeset).unwrap();

                assert_eq!(result.root(), reference.root(), "root mismatch for n={n}");

                for pos in 0..*reference.size() {
                    assert_eq!(
                        result.get_node(Position::new(pos)),
                        reference.get_node(Position::new(pos)),
                        "node mismatch at pos {pos} for n={n}"
                    );
                }
            }
        });
    }

    /// MerkleizedBatch lifecycle: build, read root + proofs, base unchanged.
    #[test]
    fn test_lifecycle() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let base_root = *base.root();

            let (_, parent) = base_batch(base);
            let mut batch = UnmerkleizedBatch::new(parent.clone());
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);

            assert_ne!(merkleized.root(), base_root);

            // Proof from merkleized batch should work.
            let proof = merkleized.proof(&hasher, Location::new(55)).unwrap();
            let element = hasher.digest(&55u64.to_be_bytes());
            assert!(proof.verify_element_inclusion(
                &hasher,
                &element,
                Location::new(55),
                &merkleized.root(),
            ));

            // Base should be unchanged.
            assert_eq!(parent.root(), base_root);
        });
    }

    /// MerkleizedBatch changeset apply.
    #[test]
    fn test_changeset_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base.clone());

            let mut batch = UnmerkleizedBatch::new(parent);
            for i in 50u64..75 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);
            let batch_root = merkleized.root();
            let changeset = merkleized.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), batch_root);

            let reference = build_reference(&hasher, 75);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Two batches on same base with different mutations. Verify independent roots and base unchanged.
    #[test]
    fn test_multiple_forks() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let base_root = *base.root();
            let (_, parent) = base_batch(base);

            // Fork A.
            let mut batch_a = UnmerkleizedBatch::new(parent.clone());
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&hasher);

            // Fork B.
            let mut batch_b = UnmerkleizedBatch::new(parent.clone());
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);

            assert_ne!(merkleized_a.root(), merkleized_b.root());
            assert_ne!(merkleized_a.root(), base_root);
            assert_ne!(merkleized_b.root(), base_root);
            assert_eq!(parent.root(), base_root);
        });
    }

    /// Base <- A <- B. B resolves through all layers.
    #[test]
    fn test_fork_of_fork_reads() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base);

            // Layer A.
            let mut batch_a = UnmerkleizedBatch::new(parent);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B on top of A.
            let mut batch_b = UnmerkleizedBatch::new(merkleized_a);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);

            let reference = build_reference(&hasher, 70);
            assert_eq!(merkleized_b.root(), *reference.root());

            // Proofs from B should verify.
            for i in [0u64, 25, 55, 65, 69] {
                let element = hasher.digest(&i.to_be_bytes());
                let proof = merkleized_b.proof(&hasher, Location::new(i)).unwrap();
                assert!(
                    proof.verify_element_inclusion(
                        &hasher,
                        &element,
                        Location::new(i),
                        &merkleized_b.root(),
                    ),
                    "proof failed for element {i}"
                );
            }
        });
    }

    /// Base <- A <- B. Flatten B's changeset and apply to base.
    #[test]
    fn test_fork_of_fork_flattened_changeset() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base.clone());

            let mut batch_a = UnmerkleizedBatch::new(parent);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&hasher);

            let mut batch_b = UnmerkleizedBatch::new(merkleized_a);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);
            let b_root = merkleized_b.root();

            let changeset = merkleized_b.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), b_root);

            let reference = build_reference(&hasher, 70);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Overwrite leaf digest in batch, merkleize, verify root changes and reverts.
    #[test]
    fn test_update_leaf() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 100);
            let base_root = *base.root();
            let (_, parent) = base_batch(base);

            let updated_digest = Sha256::fill(0xFF);

            // Update leaf and verify root changes.
            let batch = UnmerkleizedBatch::new(parent.clone())
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized = batch.merkleize(&hasher);
            assert_ne!(merkleized.root(), base_root);

            // Restore original and verify root reverts.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            let original_digest = parent.get_node(leaf_5_pos).unwrap();
            let batch2 = UnmerkleizedBatch::new(parent)
                .update_leaf_digest(Location::new(5), original_digest)
                .unwrap();
            let merkleized2 = batch2.merkleize(&hasher);
            assert_eq!(merkleized2.root(), base_root);
        });
    }

    /// Overwrite a leaf, add leaves, merkleize. Verify digest stored and proof works.
    #[test]
    fn test_update_and_add() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let base_root = *base.root();
            let (_, parent) = base_batch(base);

            let updated_digest = Sha256::fill(0xAA);
            let mut batch = UnmerkleizedBatch::new(parent)
                .update_leaf_digest(Location::new(10), updated_digest)
                .unwrap();

            // Add more leaves.
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);
            assert_ne!(merkleized.root(), base_root);

            // Verify the updated leaf's digest is in the batch.
            let leaf_10_pos = Position::try_from(Location::new(10)).unwrap();
            assert_eq!(merkleized.get_node(leaf_10_pos), Some(updated_digest));

            // Verify new leaf's proof (add uses leaf_digest, so verify_element_inclusion works).
            let element = hasher.digest(&52u64.to_be_bytes());
            let proof = merkleized.proof(&hasher, Location::new(52)).unwrap();
            assert!(proof.verify_element_inclusion(
                &hasher,
                &element,
                Location::new(52),
                &merkleized.root(),
            ));
        });
    }

    /// Batch update multiple leaf digests, merkleize, verify root changes and digests stored.
    #[test]
    fn test_update_leaf_batched() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 100);
            let base_root = *base.root();

            let updated_digest = Sha256::fill(0xBB);
            let updates: Vec<(Location, sha256::Digest)> = [0u64, 10, 50, 99]
                .iter()
                .map(|&i| (Location::new(i), updated_digest))
                .collect();

            let (_, parent) = base_batch(base.clone());
            let batch = UnmerkleizedBatch::new(parent)
                .update_leaf_batched(&updates)
                .unwrap();
            let merkleized = batch.merkleize(&hasher);

            assert_ne!(merkleized.root(), base_root);

            // Verify digests were stored correctly.
            for &loc_val in &[0u64, 10, 50, 99] {
                let pos = Position::try_from(Location::new(loc_val)).unwrap();
                assert_eq!(
                    merkleized.get_node(pos),
                    Some(updated_digest),
                    "digest mismatch at loc {loc_val}"
                );
            }

            // Verify restoring originals gives back original root.
            let mut restore_updates = Vec::new();
            for &loc_val in &[0u64, 10, 50, 99] {
                let pos = Position::try_from(Location::new(loc_val)).unwrap();
                let original = base.get_node(pos).unwrap();
                restore_updates.push((Location::new(loc_val), original));
            }
            let (_, parent2) = base_batch(base);
            let batch2 = UnmerkleizedBatch::new(parent2)
                .update_leaf_batched(&restore_updates)
                .unwrap();
            let merkleized2 = batch2.merkleize(&hasher);
            assert_eq!(merkleized2.root(), base_root);
        });
    }

    /// Single-element and range proofs from MerkleizedBatch verify against root.
    #[test]
    fn test_proof_verification() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base);

            let mut batch = UnmerkleizedBatch::new(parent);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);

            // Single element proof.
            let element = hasher.digest(&55u64.to_be_bytes());
            let proof = merkleized.proof(&hasher, Location::new(55)).unwrap();
            assert!(proof.verify_element_inclusion(
                &hasher,
                &element,
                Location::new(55),
                &merkleized.root(),
            ));

            // Range proof.
            let range = Location::new(50)..Location::new(55);
            let range_proof = merkleized.range_proof(&hasher, range.clone()).unwrap();
            let mut elements = Vec::new();
            for i in 50u64..55 {
                elements.push(hasher.digest(&i.to_be_bytes()));
            }
            assert!(range_proof.verify_range_inclusion(
                &hasher,
                &elements,
                range.start,
                &merkleized.root(),
            ));
        });
    }

    /// Merkleize a no-op batch. Same root as parent.
    #[test]
    fn test_empty_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let base_root = *base.root();

            let (_, parent) = base_batch(base.clone());
            let batch = UnmerkleizedBatch::new(parent);
            let merkleized = batch.merkleize(&hasher);

            assert_eq!(merkleized.root(), base_root);

            // Proofs should match.
            for loc in [0u64, 10, 49] {
                let base_proof = base.proof(&hasher, Location::new(loc)).unwrap();
                let batch_proof = merkleized.proof(&hasher, Location::new(loc)).unwrap();
                assert_eq!(base_proof, batch_proof, "proof mismatch at loc {loc}");
            }
        });
    }

    /// MerkleizedBatch -> new_batch -> more mutations -> merkleize -> verify.
    #[test]
    fn test_batch_roundtrip() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base);

            // First batch: add 5 leaves.
            let mut batch = UnmerkleizedBatch::new(parent);
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);

            // Round-trip: back to batch, add more, merkleize again.
            let mut batch_again = merkleized.new_batch();
            for i in 55u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_again = batch_again.add(&hasher, &element);
            }
            let merkleized_again = batch_again.merkleize(&hasher);

            let reference = build_reference(&hasher, 60);
            assert_eq!(merkleized_again.root(), *reference.root());
        });
    }

    /// Apply changeset 1. Create new batch on updated base, apply changeset 2. Verify final state.
    #[test]
    fn test_sequential_changesets() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 50);

            // Changeset 1: add 10 leaves.
            let (_, parent1) = base_batch(base.clone());
            let mut batch1 = UnmerkleizedBatch::new(parent1);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch1 = batch1.add(&hasher, &element);
            }
            let cs1 = batch1.merkleize(&hasher).finalize();
            base.apply(cs1).unwrap();

            // Changeset 2: add 10 more leaves on updated base.
            let (_, parent2) = base_batch(base.clone());
            let mut batch2 = UnmerkleizedBatch::new(parent2);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch2 = batch2.add(&hasher, &element);
            }
            let cs2 = batch2.merkleize(&hasher).finalize();
            base.apply(cs2).unwrap();

            let reference = build_reference(&hasher, 70);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Create batch on a base that has been pruned. Proofs for retained elements work.
    #[test]
    fn test_batch_on_pruned_base() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 100);
            base.prune(Location::new(27)).unwrap();

            let (_, parent) = base_batch(base);
            let mut batch = UnmerkleizedBatch::new(parent);
            for i in 100u64..110 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let merkleized = batch.merkleize(&hasher);

            // Proof for retained element should work.
            let element = hasher.digest(&80u64.to_be_bytes());
            let proof = merkleized.proof(&hasher, Location::new(80)).unwrap();
            assert!(proof.verify_element_inclusion(
                &hasher,
                &element,
                Location::new(80),
                &merkleized.root(),
            ));

            // Proof for pruned element should fail.
            let result = merkleized.proof(&hasher, Location::new(0));
            assert!(
                matches!(result, Err(Error::ElementPruned(_))),
                "expected ElementPruned, got {result:?}"
            );
        });
    }

    /// Base <- A (overwrites leaf 5) <- B (adds). B's changeset includes A's overwrite.
    #[test]
    fn test_flattened_changeset_preserves_overwrites() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 100);

            let updated_digest = Sha256::fill(0xCC);
            let (_, parent) = base_batch(base.clone());

            // Layer A: overwrite leaf 5.
            let batch_a = UnmerkleizedBatch::new(parent)
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B on A: add leaves.
            let mut batch_b = merkleized_a.new_batch();
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);
            let b_root = merkleized_b.root();

            let changeset = merkleized_b.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), b_root);

            // Verify leaf 5 has the updated digest.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            assert_eq!(base.get_node(leaf_5_pos), Some(updated_digest));
        });
    }

    /// Three-deep stacking: A overwrites, B overwrites, C adds. Flatten and verify.
    #[test]
    fn test_three_deep_stacking() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 100);
            let (_, parent) = base_batch(base.clone());

            let digest_a = Sha256::fill(0xDD);
            let digest_b = Sha256::fill(0xEE);

            // Layer A: overwrite leaf 5.
            let batch_a = UnmerkleizedBatch::new(parent)
                .update_leaf_digest(Location::new(5), digest_a)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B on A: overwrite leaf 10.
            let batch_b = merkleized_a
                .new_batch()
                .update_leaf_digest(Location::new(10), digest_b)
                .unwrap();
            let merkleized_b = batch_b.merkleize(&hasher);

            // Layer C on B: add 10 leaves.
            let mut batch_c = merkleized_b.new_batch();
            for i in 300u64..310 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_c = batch_c.add(&hasher, &element);
            }
            let merkleized_c = batch_c.merkleize(&hasher);
            let c_root = merkleized_c.root();

            let changeset = merkleized_c.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), c_root);

            // Build equivalent directly via a single batch.
            let mut reference = build_reference(&hasher, 100);
            let (_, ref_parent) = base_batch(reference.clone());
            let changeset = {
                let mut batch = UnmerkleizedBatch::new(ref_parent)
                    .update_leaf_digest(Location::new(5), digest_a)
                    .unwrap()
                    .update_leaf_digest(Location::new(10), digest_b)
                    .unwrap();
                for i in 300u64..310 {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&hasher, &element);
                }
                batch.merkleize(&hasher).finalize()
            };
            reference.apply(changeset).unwrap();
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Overwrite collision: A writes X, B writes Y. Flattened should have Y.
    #[test]
    fn test_overwrite_collision_in_stack() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 100);
            let (_, parent) = base_batch(base.clone());

            let digest_x = Sha256::fill(0xAA);
            let digest_y = Sha256::fill(0xBB);

            let batch_a = UnmerkleizedBatch::new(parent)
                .update_leaf_digest(Location::new(5), digest_x)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&hasher);

            let batch_b = merkleized_a
                .new_batch()
                .update_leaf_digest(Location::new(5), digest_y)
                .unwrap();
            let merkleized_b = batch_b.merkleize(&hasher);
            let b_root = merkleized_b.root();

            let changeset = merkleized_b.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), b_root);

            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            assert_eq!(base.get_node(leaf_5_pos), Some(digest_y));
        });
    }

    /// finalize_from: commit parent, then finalize child relative to new base.
    #[test]
    fn test_finalize_from() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base.clone());

            // Layer A: add 10 elements.
            let mut batch_a = UnmerkleizedBatch::new(parent);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B on A: add 10 more elements.
            let mut batch_b = merkleized_a.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);

            // Commit A first.
            let cs_a = merkleized_a.finalize();
            base.apply(cs_a).unwrap();

            // Now commit B relative to the new base size.
            let cs_b = merkleized_b.finalize_from(base.size());
            base.apply(cs_b).unwrap();

            let reference = build_reference(&hasher, 70);
            assert_eq!(base.root(), reference.root());

            for pos in 0..*reference.size() {
                assert_eq!(
                    base.get_node(Position::new(pos)),
                    reference.get_node(Position::new(pos)),
                    "node mismatch at pos {pos}"
                );
            }
        });
    }

    /// finalize_from with overwrites in the intermediate range [base_size, current_base).
    ///
    /// Layer A appends leaves. Layer B overwrites a leaf added by A. After committing A,
    /// finalize_from on B must include the overwrite -- it targets a position that is now
    /// part of the committed base.
    #[test]
    fn test_finalize_from_with_overwrites() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base.clone());

            let digest_x = Sha256::fill(0xAA);
            let digest_y = Sha256::fill(0xBB);

            // Layer A: overwrite leaf 5 with X.
            let batch_a = UnmerkleizedBatch::new(parent)
                .update_leaf_digest(Location::new(5), digest_x)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B on A: overwrite leaf 5 with Y.
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

            // Now commit B relative to the new base size.
            let cs_b = merkleized_b.finalize_from(base.size());
            base.apply(cs_b).unwrap();

            // The root must match B's speculative root.
            assert_eq!(*base.root(), expected_root);

            // The overwritten leaf must have the new digest.
            let overwrite_pos = Position::try_from(Location::new(5)).unwrap();
            assert_eq!(
                base.get_node(overwrite_pos),
                Some(digest_y),
                "overwrite in intermediate range was lost"
            );
        });
    }

    /// flatten() on a Base is a no-op.
    #[test]
    fn test_flatten_base_noop() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, mut batch) = base_batch(base);
            let root_before = batch.root();
            let size_before = batch.size();

            batch.flatten();

            assert!(matches!(batch, MerkleizedBatch::Base(_)));
            assert_eq!(batch.root(), root_before);
            assert_eq!(batch.size(), size_before);
        });
    }

    /// flatten() flattens a single Layer into a Base with identical semantics.
    #[test]
    fn test_flatten_single_layer() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base);

            let mut batch = UnmerkleizedBatch::new(parent);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let updated_digest = Sha256::fill(0xEE);
            let batch = batch
                .update_leaf_digest(Location::new(52), updated_digest)
                .unwrap();
            let mut merkleized = batch.merkleize(&hasher);
            assert!(matches!(merkleized, MerkleizedBatch::Layer(_)));

            let root_before = merkleized.root();
            let size_before = merkleized.size();

            merkleized.flatten();

            assert!(matches!(merkleized, MerkleizedBatch::Base(_)));
            assert_eq!(merkleized.root(), root_before);
            assert_eq!(merkleized.size(), size_before);

            // Build reference the same way: 60 elements, then update leaf 52.
            let mut reference = build_reference(&hasher, 60);
            let (_, ref_parent) = base_batch(reference.clone());
            let changeset = {
                UnmerkleizedBatch::new(ref_parent)
                    .update_leaf_digest(Location::new(52), updated_digest)
                    .unwrap()
                    .merkleize(&hasher)
                    .finalize()
            };
            reference.apply(changeset).unwrap();
            assert_eq!(merkleized.root(), *reference.root());
        });
    }

    /// flatten() flattens a deep chain (Base <- A <- B <- C) into a single Base.
    #[test]
    fn test_flatten_deep_chain() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base);

            // Layer A: add 10 elements.
            let mut batch_a = UnmerkleizedBatch::new(parent);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B: add 10 more.
            let mut batch_b = merkleized_a.new_batch();
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&hasher);

            // Layer C: add 10 more.
            let mut batch_c = merkleized_b.new_batch();
            for i in 70u64..80 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_c = batch_c.add(&hasher, &element);
            }
            let mut merkleized_c = batch_c.merkleize(&hasher);

            let root_before = merkleized_c.root();
            let size_before = merkleized_c.size();

            merkleized_c.flatten();

            assert!(matches!(merkleized_c, MerkleizedBatch::Base(_)));
            assert_eq!(merkleized_c.root(), root_before);
            assert_eq!(merkleized_c.size(), size_before);

            let reference = build_reference(&hasher, 80);
            assert_eq!(merkleized_c.root(), *reference.root());
        });
    }

    /// flatten() is idempotent: second call is a no-op.
    #[test]
    fn test_flatten_idempotent() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base);

            let mut batch = UnmerkleizedBatch::new(parent);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let mut merkleized = batch.merkleize(&hasher);

            merkleized.flatten();
            let root_after_first = merkleized.root();
            let size_after_first = merkleized.size();

            merkleized.flatten();
            assert_eq!(merkleized.root(), root_after_first);
            assert_eq!(merkleized.size(), size_after_first);
        });
    }

    /// flatten() preserves overwrites from stacked layers.
    #[test]
    fn test_flatten_with_overwrites() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 100);
            let (_, parent) = base_batch(base);

            let digest_a = Sha256::fill(0xDD);
            let digest_b = Sha256::fill(0xEE);

            // Layer A: overwrite leaf 5.
            let batch_a = UnmerkleizedBatch::new(parent)
                .update_leaf_digest(Location::new(5), digest_a)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&hasher);

            // Layer B: overwrite leaf 5 again (last writer wins).
            let batch_b = merkleized_a
                .new_batch()
                .update_leaf_digest(Location::new(5), digest_b)
                .unwrap();
            let mut merkleized_b = batch_b.merkleize(&hasher);

            let root_before = merkleized_b.root();
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            assert_eq!(merkleized_b.get_node(leaf_5_pos), Some(digest_b));

            merkleized_b.flatten();

            assert!(matches!(merkleized_b, MerkleizedBatch::Base(_)));
            assert_eq!(merkleized_b.root(), root_before);
            assert_eq!(merkleized_b.get_node(leaf_5_pos), Some(digest_b));
        });
    }

    /// update_leaf_digest and update_leaf_batched reject out-of-bounds locations.
    #[test]
    fn test_update_leaf_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&hasher, 50);
            let (_, parent) = base_batch(base);

            let batch = UnmerkleizedBatch::new(parent.clone());

            // update_leaf_digest at location == leaf count.
            let Err(err) = batch.update_leaf_digest(Location::new(50), Sha256::fill(0xFF)) else {
                panic!("expected error");
            };
            assert!(matches!(err, Error::InvalidPosition(_)));

            // update_leaf_batched with one out-of-bounds location.
            let batch = UnmerkleizedBatch::new(parent);
            let updates = [(Location::new(50), Sha256::fill(0xFF))];
            let Err(err) = batch.update_leaf_batched(&updates) else {
                panic!("expected error");
            };
            assert!(matches!(err, Error::LeafOutOfBounds(_)));
        });
    }
}
