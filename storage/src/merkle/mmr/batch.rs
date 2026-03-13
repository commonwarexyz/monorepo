//! A lightweight batch layer over a merkleized MMR.
//!
//! # Overview
//!
//! [`MerkleizedBatch`] is an immutable, reference-counted MMR state (persistent data structure).
//! [`UnmerkleizedBatch`] accumulates mutations against a parent batch. After merkleization the
//! batch produces a new [`MerkleizedBatch`]. Because batches are behind [`Arc`], they can be
//! freely cloned and stored in homogeneous collections regardless of chain depth.
//!
//! ```text
//! Arc<Mmr> ──MerkleizedBatch::Base──> MerkleizedBatch
//!                                        │
//!                               UnmerkleizedBatch::new(snap)
//!                                        │
//!                                        v
//!                                UnmerkleizedBatch    (accumulate mutations)
//!                                        │
//!                                   merkleize()
//!                                        │
//!                                        v
//!                                MerkleizedBatch      (MerkleizedBatch::Layer)
//!                                 │
//!                            finalize()
//!                                 │
//!                                 v
//!                             Changeset
//! ```
//!
//! - [`Changeset`] -- owned delta that can be applied to the base MMR.
//!
//! # Example
//!
//! ```ignore
//! let mut hasher = StandardHasher::<Sha256>::new();
//! let mmr = Arc::new(Mmr::new(&mut hasher));
//! let base = MerkleizedBatch::Base(Arc::clone(&mmr));
//!
//! let snap_a = {
//!     let mut batch = UnmerkleizedBatch::new(base.clone());
//!     batch.add(&mut hasher, b"leaf-0");
//!     batch.merkleize(&mut hasher)
//! };
//!
//! // snap_a can be stored, cloned, used as parent for further batches.
//! let snap_b = {
//!     let mut batch = UnmerkleizedBatch::new(snap_a.clone());
//!     batch.add(&mut hasher, b"leaf-1");
//!     batch.merkleize(&mut hasher)
//! };
//! ```

#[cfg(any(feature = "std", test))]
use crate::mmr::iterator::pos_to_height;
use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_needing_parents, PathIterator, PeakIterator},
    mem::{Dirty, Mmr},
    read::{BatchChainInfo, Readable},
    Error, Location, Position,
};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use commonware_cryptography::Digest;
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use commonware_parallel::ThreadPool;
        use rayon::prelude::*;
    }
}

/// Owned set of changes against a base MMR.
/// Apply via [`super::mem::Mmr::apply`].
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

/// A batch whose root digest has not been computed.
///
/// Call [`UnmerkleizedBatch::merkleize`] to produce an immutable [`MerkleizedBatch`].
pub struct UnmerkleizedBatch<D: Digest> {
    parent: MerkleizedBatch<D>,
    appended: Vec<D>,
    overwrites: BTreeMap<Position, D>,
    dirty: Dirty,
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

/// Immutable MMR state at any point in a batch chain.
///
/// `Clone` is O(1) (`Arc::clone`). Batches can be freely shared and stored
/// in homogeneous collections regardless of chain depth.
#[derive(Clone, Debug)]
pub enum MerkleizedBatch<D: Digest> {
    /// Committed MMR (chain terminal).
    Base(Arc<Mmr<D>>),
    /// Speculative layer on top of a parent batch.
    Layer(Arc<MerkleizedBatchLayer<D>>),
}

/// The data behind a [`MerkleizedBatch::Layer`].
#[derive(Debug)]
pub struct MerkleizedBatchLayer<D: Digest> {
    parent: MerkleizedBatch<D>,
    appended: Vec<D>,
    overwrites: BTreeMap<Position, D>,
    root: D,
    /// Cached `parent.size()` to avoid re-traversal.
    parent_size: Position,
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

impl<D: Digest> UnmerkleizedBatch<D> {
    /// Create a new batch borrowing `parent` immutably.
    /// O(1) time and space.
    pub fn new(parent: MerkleizedBatch<D>) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: BTreeMap::new(),
            dirty: Dirty::default(),
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

    /// Store a digest at `pos`.
    fn store_node(&mut self, pos: Position, digest: D) {
        let parent_size = self.parent.size();
        if pos >= parent_size {
            let index = (*pos - *parent_size) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }

    /// Add a pre-computed leaf digest. Returns the leaf's position.
    pub fn add_leaf_digest(&mut self, digest: D) -> Position {
        let nodes_needing_parents = nodes_needing_parents(PeakIterator::new(self.size()))
            .into_iter()
            .rev();
        let leaf_pos = self.size();
        self.appended.push(digest);

        let mut height = 1;
        for _ in nodes_needing_parents {
            let new_node_pos = self.size();
            self.appended.push(D::EMPTY);
            self.dirty.insert(new_node_pos, height);
            height += 1;
        }

        leaf_pos
    }

    /// Hash `element` and add it as a leaf. Returns the leaf's position.
    pub fn add(&mut self, hasher: &mut impl Hasher<Digest = D>, element: &[u8]) -> Position {
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
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<(), Error> {
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
        Ok(())
    }

    /// Overwrite the digest of an existing leaf and mark ancestors dirty.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_digest(&mut self, loc: Location, digest: D) -> Result<(), Error> {
        let pos = Position::try_from(loc).map_err(|_| Error::LocationOverflow(loc))?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
        if pos >= self.size() {
            return Err(Error::InvalidPosition(pos));
        }
        if pos_to_height(pos) != 0 {
            return Err(Error::PositionNotLeaf(pos));
        }
        self.store_node(pos, digest);
        self.mark_dirty(pos);
        Ok(())
    }

    /// Batch update multiple leaf digests.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_batched(&mut self, updates: &[(Location, D)]) -> Result<(), Error> {
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
        Ok(())
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed root.
    pub fn merkleize(mut self, hasher: &mut impl Hasher<Digest = D>) -> MerkleizedBatch<D> {
        let dirty = self.dirty.take_sorted_by_height();

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
    fn merkleize_serial(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        dirty: &[(Position, u32)],
    ) {
        for &(pos, height) in dirty {
            let left = pos - (1 << height);
            let right = pos - 1;
            let left_d = self.get_node(left).expect("left child missing");
            let right_d = self.get_node(right).expect("right child missing");
            let digest = hasher.node_digest(pos, &left_d, &right_d);
            self.store_node(pos, digest);
        }
    }

    /// Process dirty nodes in parallel, grouping by height.
    #[cfg(feature = "std")]
    fn merkleize_parallel(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
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
            current_height = height;
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
        hasher: &mut impl Hasher<Digest = D>,
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
                if !self.dirty.insert(parent_pos, height) {
                    break;
                }
                height += 1;
            }
            return;
        }

        panic!("invalid pos {pos}:{}", self.size());
    }
}

impl<D: Digest> MerkleizedBatch<D> {
    /// The total number of nodes visible through this batch.
    pub fn size(&self) -> Position {
        match self {
            Self::Base(mmr) => mmr.size(),
            Self::Layer(layer) => Position::new(*layer.parent_size + layer.appended.len() as u64),
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
        }
    }

    /// Root digest.
    pub fn root(&self) -> D {
        match self {
            Self::Base(mmr) => *mmr.root(),
            Self::Layer(layer) => layer.root,
        }
    }

    /// Items before this position have been pruned.
    pub fn pruned_to_pos(&self) -> Position {
        match self {
            Self::Base(mmr) => Readable::pruned_to_pos(mmr.as_ref()),
            Self::Layer(layer) => layer.parent.pruned_to_pos(),
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
        }
    }

    /// Flatten this batch chain into a single [`Changeset`] relative to the
    /// ultimate base MMR.
    pub fn finalize(&self) -> Changeset<D> {
        let base_size = self.base_size();
        self.finalize_from(base_size)
    }

    /// Flatten this batch chain into a [`Changeset`] relative to a given base size.
    ///
    /// This is useful when an ancestor batch has already been committed and the
    /// base MMR size has advanced past the original `base_size()`.
    pub fn finalize_from(&self, current_base: Position) -> Changeset<D> {
        let effective = self.size();

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

impl<D: Digest> BatchChainInfo for MerkleizedBatch<D> {
    type Digest = D;

    fn base_size(&self) -> Position {
        match self {
            Self::Base(mmr) => mmr.size(),
            Self::Layer(layer) => layer.parent.base_size(),
        }
    }

    fn collect_overwrites(&self, into: &mut BTreeMap<Position, D>) {
        match self {
            Self::Base(_) => {}
            Self::Layer(layer) => {
                layer.parent.collect_overwrites(into);
                for (&pos, &d) in &layer.overwrites {
                    into.insert(pos, d);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{conformance::build_test_mmr, hasher::Standard, mem::Mmr, read::Readable};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    /// Build a reference MMR with `n` elements for comparison.
    fn build_reference(hasher: &mut Standard<Sha256>, n: u64) -> Mmr<sha256::Digest> {
        let mmr = Mmr::new(hasher);
        build_test_mmr(hasher, mmr, n)
    }

    /// Helper: wrap an Mmr in a MerkleizedBatch::Base.
    fn base_batch(
        mmr: Mmr<sha256::Digest>,
    ) -> (Arc<Mmr<sha256::Digest>>, MerkleizedBatch<sha256::Digest>) {
        let arc = Arc::new(mmr);
        let snap = MerkleizedBatch::Base(Arc::clone(&arc));
        (arc, snap)
    }

    /// Build via MerkleizedBatch/UnmerkleizedBatch and verify consistency with reference Mmr.
    #[test]
    fn test_consistency_with_reference() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();

            for &n in &[1u64, 2, 10, 100, 199] {
                let reference = build_reference(&mut hasher, n);

                let base = Mmr::new(&mut hasher);
                let (_, snap) = base_batch(base);

                let mut batch = UnmerkleizedBatch::new(snap);
                for i in 0..n {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch.add(&mut hasher, &element);
                }
                let merkleized = batch.merkleize(&mut hasher);
                let changeset = merkleized.finalize();
                let mut result = Mmr::new(&mut hasher);
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let (_, snap) = base_batch(base);
            let mut batch = UnmerkleizedBatch::new(snap.clone());
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            assert_ne!(merkleized.root(), base_root);

            // Proof from merkleized batch should work.
            let proof = merkleized.proof(&mut hasher, Location::new(55)).unwrap();
            let element = hasher.digest(&55u64.to_be_bytes());
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new(55),
                &merkleized.root(),
            ));

            // Base should be unchanged.
            assert_eq!(snap.root(), base_root);
        });
    }

    /// MerkleizedBatch changeset apply.
    #[test]
    fn test_changeset_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base.clone());

            let mut batch = UnmerkleizedBatch::new(snap);
            for i in 50u64..75 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);
            let batch_root = merkleized.root();
            let changeset = merkleized.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), batch_root);

            let reference = build_reference(&mut hasher, 75);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Two batches on same base with different mutations. Verify independent roots and base unchanged.
    #[test]
    fn test_multiple_forks() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();
            let (_, snap) = base_batch(base);

            // Fork A.
            let mut batch_a = UnmerkleizedBatch::new(snap.clone());
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Fork B.
            let mut batch_b = UnmerkleizedBatch::new(snap.clone());
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);

            assert_ne!(merkleized_a.root(), merkleized_b.root());
            assert_ne!(merkleized_a.root(), base_root);
            assert_ne!(merkleized_b.root(), base_root);
            assert_eq!(snap.root(), base_root);
        });
    }

    /// Base <- A <- B. B resolves through all layers.
    #[test]
    fn test_fork_of_fork_reads() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base);

            // Layer A.
            let mut batch_a = UnmerkleizedBatch::new(snap);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on top of A.
            let mut batch_b = UnmerkleizedBatch::new(merkleized_a);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);

            let reference = build_reference(&mut hasher, 70);
            assert_eq!(merkleized_b.root(), *reference.root());

            // Proofs from B should verify.
            for i in [0u64, 25, 55, 65, 69] {
                let element = hasher.digest(&i.to_be_bytes());
                let proof = merkleized_b.proof(&mut hasher, Location::new(i)).unwrap();
                assert!(
                    proof.verify_element_inclusion(
                        &mut hasher,
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base.clone());

            let mut batch_a = UnmerkleizedBatch::new(snap);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            let mut batch_b = UnmerkleizedBatch::new(merkleized_a);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);
            let b_root = merkleized_b.root();

            let changeset = merkleized_b.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), b_root);

            let reference = build_reference(&mut hasher, 70);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Overwrite leaf digest in batch, merkleize, verify root changes and reverts.
    #[test]
    fn test_update_leaf() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 100);
            let base_root = *base.root();
            let (_, snap) = base_batch(base);

            let updated_digest = Sha256::fill(0xFF);

            let mut batch = UnmerkleizedBatch::new(snap.clone());
            batch
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized = batch.merkleize(&mut hasher);
            assert_ne!(merkleized.root(), base_root);

            // Restore original and verify root reverts.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            let original_digest = snap.get_node(leaf_5_pos).unwrap();
            let mut batch2 = UnmerkleizedBatch::new(snap);
            batch2
                .update_leaf_digest(Location::new(5), original_digest)
                .unwrap();
            let merkleized2 = batch2.merkleize(&mut hasher);
            assert_eq!(merkleized2.root(), base_root);
        });
    }

    /// Overwrite a leaf, add leaves, merkleize. Verify digest stored and proof works.
    #[test]
    fn test_update_and_add() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();
            let (_, snap) = base_batch(base);

            let updated_digest = Sha256::fill(0xAA);
            let mut batch = UnmerkleizedBatch::new(snap);
            batch
                .update_leaf_digest(Location::new(10), updated_digest)
                .unwrap();

            // Add more leaves.
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);
            assert_ne!(merkleized.root(), base_root);

            // Verify the updated leaf's digest is in the batch.
            let leaf_10_pos = Position::try_from(Location::new(10)).unwrap();
            assert_eq!(merkleized.get_node(leaf_10_pos), Some(updated_digest));

            // Verify new leaf's proof (add uses leaf_digest, so verify_element_inclusion works).
            let element = hasher.digest(&52u64.to_be_bytes());
            let proof = merkleized.proof(&mut hasher, Location::new(52)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 100);
            let base_root = *base.root();

            let updated_digest = Sha256::fill(0xBB);
            let updates: Vec<(Location, sha256::Digest)> = [0u64, 10, 50, 99]
                .iter()
                .map(|&i| (Location::new(i), updated_digest))
                .collect();

            let (_, snap) = base_batch(base.clone());
            let mut batch = UnmerkleizedBatch::new(snap);
            batch.update_leaf_batched(&updates).unwrap();
            let merkleized = batch.merkleize(&mut hasher);

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
            let (_, snap2) = base_batch(base);
            let mut batch2 = UnmerkleizedBatch::new(snap2);
            batch2.update_leaf_batched(&restore_updates).unwrap();
            let merkleized2 = batch2.merkleize(&mut hasher);
            assert_eq!(merkleized2.root(), base_root);
        });
    }

    /// Single-element and range proofs from MerkleizedBatch verify against root.
    #[test]
    fn test_proof_verification() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base);

            let mut batch = UnmerkleizedBatch::new(snap);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Single element proof.
            let element = hasher.digest(&55u64.to_be_bytes());
            let proof = merkleized.proof(&mut hasher, Location::new(55)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new(55),
                &merkleized.root(),
            ));

            // Range proof.
            let range = Location::new(50)..Location::new(55);
            let range_proof = merkleized.range_proof(&mut hasher, range.clone()).unwrap();
            let mut elements = Vec::new();
            for i in 50u64..55 {
                elements.push(hasher.digest(&i.to_be_bytes()));
            }
            assert!(range_proof.verify_range_inclusion(
                &mut hasher,
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let (_, snap) = base_batch(base.clone());
            let batch = UnmerkleizedBatch::new(snap);
            let merkleized = batch.merkleize(&mut hasher);

            assert_eq!(merkleized.root(), base_root);

            // Proofs should match.
            for loc in [0u64, 10, 49] {
                let base_proof = base.proof(&mut hasher, Location::new(loc)).unwrap();
                let batch_proof = merkleized.proof(&mut hasher, Location::new(loc)).unwrap();
                assert_eq!(base_proof, batch_proof, "proof mismatch at loc {loc}");
            }
        });
    }

    /// MerkleizedBatch -> new_batch -> more mutations -> merkleize -> verify.
    #[test]
    fn test_builder_roundtrip() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base);

            // First batch: add 5 leaves.
            let mut batch = UnmerkleizedBatch::new(snap);
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Round-trip: back to batch, add more, merkleize again.
            let mut batch_again = merkleized.new_batch();
            for i in 55u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_again.add(&mut hasher, &element);
            }
            let merkleized_again = batch_again.merkleize(&mut hasher);

            let reference = build_reference(&mut hasher, 60);
            assert_eq!(merkleized_again.root(), *reference.root());
        });
    }

    /// Apply changeset 1. Create new batch on updated base, apply changeset 2. Verify final state.
    #[test]
    fn test_sequential_changesets() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            // Changeset 1: add 10 leaves.
            let (_, snap1) = base_batch(base.clone());
            let mut batch1 = UnmerkleizedBatch::new(snap1);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch1.add(&mut hasher, &element);
            }
            let cs1 = batch1.merkleize(&mut hasher).finalize();
            base.apply(cs1).unwrap();

            // Changeset 2: add 10 more leaves on updated base.
            let (_, snap2) = base_batch(base.clone());
            let mut batch2 = UnmerkleizedBatch::new(snap2);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch2.add(&mut hasher, &element);
            }
            let cs2 = batch2.merkleize(&mut hasher).finalize();
            base.apply(cs2).unwrap();

            let reference = build_reference(&mut hasher, 70);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Create batch on a base that has been pruned. Proofs for retained elements work.
    #[test]
    fn test_batch_on_pruned_base() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);
            base.prune(Location::new(27)).unwrap();

            let (_, snap) = base_batch(base);
            let mut batch = UnmerkleizedBatch::new(snap);
            for i in 100u64..110 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Proof for retained element should work.
            let element = hasher.digest(&80u64.to_be_bytes());
            let proof = merkleized.proof(&mut hasher, Location::new(80)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new(80),
                &merkleized.root(),
            ));

            // Proof for pruned element should fail.
            let result = merkleized.proof(&mut hasher, Location::new(0));
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            let updated_digest = Sha256::fill(0xCC);
            let (_, snap) = base_batch(base.clone());

            // Layer A: overwrite leaf 5.
            let mut batch_a = UnmerkleizedBatch::new(snap);
            batch_a
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: add leaves.
            let mut batch_b = merkleized_a.new_batch();
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);
            let (_, snap) = base_batch(base.clone());

            let digest_a = Sha256::fill(0xDD);
            let digest_b = Sha256::fill(0xEE);

            // Layer A: overwrite leaf 5.
            let mut batch_a = UnmerkleizedBatch::new(snap);
            batch_a
                .update_leaf_digest(Location::new(5), digest_a)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: overwrite leaf 10.
            let mut batch_b = merkleized_a.new_batch();
            batch_b
                .update_leaf_digest(Location::new(10), digest_b)
                .unwrap();
            let merkleized_b = batch_b.merkleize(&mut hasher);

            // Layer C on B: add 10 leaves.
            let mut batch_c = merkleized_b.new_batch();
            for i in 300u64..310 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_c.add(&mut hasher, &element);
            }
            let merkleized_c = batch_c.merkleize(&mut hasher);
            let c_root = merkleized_c.root();

            let changeset = merkleized_c.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), c_root);

            // Build equivalent directly via a single batch.
            let mut reference = build_reference(&mut hasher, 100);
            let (_, ref_snap) = base_batch(reference.clone());
            let changeset = {
                let mut batch = UnmerkleizedBatch::new(ref_snap);
                batch
                    .update_leaf_digest(Location::new(5), digest_a)
                    .unwrap();
                batch
                    .update_leaf_digest(Location::new(10), digest_b)
                    .unwrap();
                for i in 300u64..310 {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher).finalize()
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);
            let (_, snap) = base_batch(base.clone());

            let digest_x = Sha256::fill(0xAA);
            let digest_y = Sha256::fill(0xBB);

            let mut batch_a = UnmerkleizedBatch::new(snap);
            batch_a
                .update_leaf_digest(Location::new(5), digest_x)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            let mut batch_b = UnmerkleizedBatch::new(merkleized_a);
            batch_b
                .update_leaf_digest(Location::new(5), digest_y)
                .unwrap();
            let merkleized_b = batch_b.merkleize(&mut hasher);
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base.clone());

            // Layer A: add 10 elements.
            let mut batch_a = UnmerkleizedBatch::new(snap);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: add 10 more elements.
            let mut batch_b = UnmerkleizedBatch::new(merkleized_a.clone());
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);

            // Commit A first.
            let cs_a = merkleized_a.finalize();
            base.apply(cs_a).unwrap();

            // Now commit B relative to the new base size.
            let cs_b = merkleized_b.finalize_from(base.size());
            base.apply(cs_b).unwrap();

            let reference = build_reference(&mut hasher, 70);
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
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base.clone());

            // Layer A: add 10 elements.
            let mut batch_a = UnmerkleizedBatch::new(snap);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: overwrite a leaf that A added, then add more.
            let mut batch_b = UnmerkleizedBatch::new(merkleized_a.clone());
            let overwrite_loc = Location::new(55);
            let new_digest = Sha256::fill(0xCC);
            batch_b
                .update_leaf_digest(overwrite_loc, new_digest)
                .unwrap();
            for i in 60u64..65 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);
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
            let overwrite_pos = Position::try_from(overwrite_loc).unwrap();
            assert_eq!(
                base.get_node(overwrite_pos),
                Some(new_digest),
                "overwrite in intermediate range was lost"
            );
        });
    }

    /// Batches can be stored in a Vec (homogeneous collection).
    #[test]
    fn test_homogeneous_collection() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let (_, snap) = base_batch(base);

            let mut batches: Vec<MerkleizedBatch<sha256::Digest>> = Vec::new();

            // Depth 1.
            let mut batch = UnmerkleizedBatch::new(snap);
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized1 = batch.merkleize(&mut hasher);
            batches.push(merkleized1.clone());

            // Depth 2 (child of merkleized1).
            let mut batch = UnmerkleizedBatch::new(merkleized1);
            for i in 55u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch.add(&mut hasher, &element);
            }
            let merkleized2 = batch.merkleize(&mut hasher);
            batches.push(merkleized2);

            // All batches have the same concrete type.
            assert_eq!(batches.len(), 2);
            assert_ne!(batches[0].root(), batches[1].root());
            assert_ne!(batches[0].size(), batches[1].size());
        });
    }

    /// Merkleize a no-op batch. Same root as parent.
    #[test]
    fn test_empty_batch_roundtrip() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();
            let (_, snap) = base_batch(base);

            let batch = UnmerkleizedBatch::new(snap);
            let merkleized = batch.merkleize(&mut hasher);

            assert_eq!(merkleized.root(), base_root);
        });
    }
}
