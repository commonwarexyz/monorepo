//! A lightweight, borrow-based batch layer over a merkleized MMR.
//!
//! # Overview
//!
//! A [`Batch`] borrows a parent MMR ([`Readable`]) immutably and records mutations -- append
//! and leaf updates -- without mutating the parent. Multiple batches can coexist on the same
//! parent, and batches can be stacked (Base <- A <- B <- ...) to arbitrary depth.
//!
//! # Lifecycle
//!
//! ```text
//! Mmr ─────borrow────> UnmerkleizedBatch  (accumulate mutations)
//!                            │
//!                       merkleize()
//!                            │
//!                            v
//!                      MerkleizedBatch     (has root, supports proofs)
//!                            │
//!                       finalize()
//!                            │
//!                            v
//!                        Changeset         (owned delta, no borrow)
//!                            │
//!                      mmr.apply(cs).unwrap()
//!                            │
//!                            v
//!                           Mmr             (updated in place)
//! ```
//!
//! # Type aliases
//!
//! - [`UnmerkleizedBatch`] -- mutable phase: add, update leaves.
//! - [`MerkleizedBatch`]   -- immutable phase: root is computed, proofs available.
//! - [`Changeset`]         -- owned delta that can be applied to the base MMR.
//!
//! # Example
//!
//! ```ignore
//! let mut hasher = StandardHasher::<Sha256>::new();
//! let mut mmr = Mmr::new(&mut hasher);
//!
//! // Build a batch of mutations.
//! let changeset = {
//!     let mut batch = UnmerkleizedBatch::new(&mmr);
//!     batch.add(&mut hasher, b"leaf-0");
//!     batch.add(&mut hasher, b"leaf-1");
//!     batch.merkleize(&mut hasher).finalize()
//! };
//!
//! // Apply the changeset back to the base MMR.
//! mmr.apply(changeset).unwrap();
//! ```
//!
//! If you need to keep branching while a merkleized batch is being finalized
//! and applied, retain the merkleized batch as the branch parent:
//!
//! ```ignore
//! let merkleized = batch.merkleize(&mut hasher);
//! let pending_changeset = merkleized.finalize_incremental();
//!
//! let mut child = merkleized.new_batch();
//! child.add(&mut hasher, b"leaf-2");
//! let child_changeset = child.merkleize(&mut hasher).finalize_incremental();
//! ```
//!
//! Branching from a retained merkleized batch is speculative. This branches
//! from the prepared parent state, not from the last applied state of the
//! underlying MMR.
//!
//! Once the oldest prepared parent has been applied, descendants can be
//! compacted back onto the live MMR with [`MerkleizedBatch::rebase`]. This
//! drops one speculative ancestor level without copying the batch-local delta.
//!
//! Manual rebasing is only needed to bound retained chain depth. If you never
//! rebase, speculative reads continue to work, but they keep traversing the
//! retained parent chain.
//!
//! A typical flow is:
//!
//! ```ignore
//! let parent = batch.merkleize(&mut hasher);
//! let parent_changeset = parent.finalize_incremental();
//!
//! let child = {
//!     let mut batch = parent.new_batch();
//!     batch.add(&mut hasher, b"leaf-2");
//!     batch.merkleize(&mut hasher)
//! };
//!
//! // Parent is now reflected in the live MMR.
//! mmr.apply(parent_changeset).unwrap();
//!
//! // Rebase the child onto the live MMR to drop one speculative ancestor.
//! let child_changeset = {
//!     let child = child.rebase(&mmr).unwrap();
//!     child.finalize_incremental()
//! };
//! mmr.apply(child_changeset).unwrap();
//! ```
//!
//! Rebasing is valid only once the live parent matches the frozen parent state
//! captured by the batch. Calling [`MerkleizedBatch::rebase`] too early, or on
//! the wrong live MMR, returns [`Error::RebaseParentMismatch`] or
//! [`Error::RebaseParentRootMismatch`].

#[cfg(any(feature = "std", test))]
use crate::mmr::iterator::pos_to_height;
use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_needing_parents, PathIterator, PeakIterator},
    mem::Dirty,
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

/// A mutable batch of mutations against a parent MMR, which may itself be a
/// merkleized batch.
pub struct Batch<'a, D: Digest, P: Readable<D>> {
    /// The parent MMR.
    parent: &'a P,
    /// Nodes appended by this batch, at positions [parent.size(), parent.size() + appended.len()).
    appended: Vec<D>,
    /// Overwritten nodes at positions < parent.size(). Shadows parent data; later writes win.
    overwrites: BTreeMap<Position, D>,
    /// Non-leaf nodes whose digests must be recomputed before merkleization.
    state: Dirty,
    /// Thread pool for parallel merkleization.
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, D, P> = Batch<'a, D, P>;

/// An immutable merkleized batch that can be retained as a speculative parent
/// while its finalized changeset is being applied.
pub struct MerkleizedBatch<'a, D: Digest, P: Readable<D>> {
    /// The parent MMR.
    parent: &'a P,
    /// The parent MMR root when this batch was merkleized.
    parent_root: D,
    /// The parent MMR size when this batch was merkleized.
    parent_size: Position,
    /// The parent pruning boundary when this batch was merkleized.
    parent_pruned_to_pos: Position,
    /// The original base size for the entire batch chain.
    parent_base_size: Position,
    /// Nodes appended by this batch, at positions [parent.size(), parent.size() + appended.len()).
    appended: Arc<Vec<D>>,
    /// Overwritten nodes at positions < parent.size(). Shadows parent data; later writes win.
    overwrites: Arc<BTreeMap<Position, D>>,
    /// The root digest of the MMR after this batch is applied.
    root: D,
    /// Thread pool for parallel merkleization.
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

/// Owned set of changes against a base MMR.
/// Apply via [`super::mem::Mmr::apply`].
pub struct Changeset<D: Digest> {
    /// Nodes appended after the base MMR's existing nodes.
    pub(crate) appended: Arc<Vec<D>>,
    /// Overwritten nodes within the base MMR's range.
    pub(crate) overwrites: Arc<BTreeMap<Position, D>>,
    /// Root digest after applying the changeset.
    pub(crate) root: D,
    /// Size of the base MMR when this changeset was created.
    pub(crate) base_size: Position,
}

impl<'a, D: Digest, P: Readable<D>> Batch<'a, D, P> {
    /// The total number of nodes visible through this batch.
    pub(crate) fn size(&self) -> Position {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// Resolve a node: overwrites -> appended -> parent.
    fn get_node(&self, pos: Position) -> Option<D> {
        if pos >= self.size() {
            return None;
        }
        if let Some(d) = self.overwrites.get(&pos) {
            return Some(*d);
        }
        if pos >= self.parent.size() {
            let index = (*pos - *self.parent.size()) as usize;
            return self.appended.get(index).copied();
        }
        self.parent.get_node(pos)
    }

    /// Store a digest to the given storage location.
    fn store_node(&mut self, pos: Position, digest: D) {
        if pos >= self.parent.size() {
            let index = (*pos - *self.parent.size()) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }
}

impl<'a, D: Digest, P: Readable<D>> UnmerkleizedBatch<'a, D, P> {
    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmr size")
    }

    /// Create a new batch borrowing `parent` immutably.
    /// O(1) time and space.
    pub fn new(parent: &'a P) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: BTreeMap::new(),
            state: Dirty::default(),
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
            self.state.insert(new_node_pos, height);
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

    /// Consume this batch and produce an immutable [MerkleizedBatch] with computed root.
    pub fn merkleize(mut self, hasher: &mut impl Hasher<Digest = D>) -> MerkleizedBatch<'a, D, P>
    where
        P: BatchChainInfo<D>,
    {
        let dirty = self.state.take_sorted_by_height();

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

        MerkleizedBatch {
            parent: self.parent,
            parent_root: self.parent.root(),
            parent_size: self.parent.size(),
            parent_pruned_to_pos: self.parent.pruned_to_pos(),
            parent_base_size: self.parent.base_size(),
            appended: Arc::new(self.appended),
            overwrites: Arc::new(self.overwrites),
            root,
            #[cfg(feature = "std")]
            pool: self.pool,
        }
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

    /// Process dirty nodes in parallel, grouping by height. Falls back to `merkleize_serial`
    /// when the remaining count drops below MIN_TO_PARALLELIZE.
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
                    || hasher.fork(),
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
                if !self.state.insert(parent_pos, height) {
                    break;
                }
                height += 1;
            }
            return;
        }

        panic!("invalid pos {pos}:{}", self.size());
    }
}

impl<'a, D: Digest, P: Readable<D>> MerkleizedBatch<'a, D, P> {
    /// The total number of nodes visible through this batch.
    pub(crate) fn size(&self) -> Position {
        Position::new(*self.parent_size + self.appended.len() as u64)
    }

    /// Resolve a node: overwrites -> appended -> parent.
    fn get_node(&self, pos: Position) -> Option<D> {
        if pos >= self.size() {
            return None;
        }
        if let Some(d) = self.overwrites.get(&pos) {
            return Some(*d);
        }
        if pos >= self.parent_size {
            let index = (*pos - *self.parent_size) as usize;
            return self.appended.get(index).copied();
        }
        self.parent.get_node(pos)
    }
}

impl<'a, D: Digest, P: Readable<D>> Readable<D> for MerkleizedBatch<'a, D, P> {
    fn size(&self) -> Position {
        self.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.get_node(pos)
    }

    fn root(&self) -> D {
        self.root
    }

    fn pruned_to_pos(&self) -> Position {
        self.parent_pruned_to_pos
    }
}

impl<'a, D: Digest, P: Readable<D> + BatchChainInfo<D>> BatchChainInfo<D>
    for MerkleizedBatch<'a, D, P>
{
    fn base_size(&self) -> Position {
        self.parent_base_size
    }

    fn collect_overwrites(&self, into: &mut BTreeMap<Position, D>) {
        self.parent.collect_overwrites(into);
        let base_size = self.parent_base_size;
        for (&pos, &digest) in self.overwrites.iter() {
            if pos < base_size {
                into.insert(pos, digest);
            }
        }
    }
}

impl<'a, D: Digest, P: Readable<D>> MerkleizedBatch<'a, D, P> {
    /// Access the parent MMR.
    #[cfg(feature = "std")]
    pub(crate) const fn parent(&self) -> &P {
        self.parent
    }

    /// Access the thread pool.
    #[cfg(feature = "std")]
    pub(crate) fn pool(&self) -> Option<ThreadPool> {
        self.pool.clone()
    }

    /// Create a child batch on top of this merkleized batch.
    pub fn new_batch(&self) -> UnmerkleizedBatch<'_, D, Self> {
        let batch = UnmerkleizedBatch::new(self);
        #[cfg(feature = "std")]
        let batch = batch.with_pool(self.pool.clone());
        batch
    }

    /// Rebase this batch onto an equivalent live parent after that parent has
    /// been applied, dropping one speculative ancestor from the read-through
    /// chain.
    pub fn rebase<'b, Q>(&self, parent: &'b Q) -> Result<MerkleizedBatch<'b, D, Q>, Error>
    where
        Q: Readable<D> + BatchChainInfo<D>,
    {
        let actual_size = parent.size();
        let actual_pruned_to_pos = parent.pruned_to_pos();
        if actual_size != self.parent_size || actual_pruned_to_pos != self.parent_pruned_to_pos {
            return Err(Error::RebaseParentMismatch {
                expected_size: self.parent_size,
                expected_pruned_to_pos: self.parent_pruned_to_pos,
                actual_size,
                actual_pruned_to_pos,
            });
        }
        let actual_root = parent.root();
        if actual_root != self.parent_root {
            return Err(Error::RebaseParentRootMismatch);
        }

        Ok(MerkleizedBatch {
            parent,
            parent_root: actual_root,
            parent_size: actual_size,
            parent_pruned_to_pos: actual_pruned_to_pos,
            parent_base_size: parent.base_size(),
            appended: self.appended.clone(),
            overwrites: self.overwrites.clone(),
            root: self.root,
            #[cfg(feature = "std")]
            pool: self.pool.clone(),
        })
    }

    /// Convert back to a dirty batch for further mutations.
    pub fn into_dirty(self) -> UnmerkleizedBatch<'a, D, P> {
        Batch {
            parent: self.parent,
            appended: match Arc::try_unwrap(self.appended) {
                Ok(appended) => appended,
                Err(appended) => (*appended).clone(),
            },
            overwrites: match Arc::try_unwrap(self.overwrites) {
                Ok(overwrites) => overwrites,
                Err(overwrites) => (*overwrites).clone(),
            },
            state: Dirty::default(),
            #[cfg(feature = "std")]
            pool: self.pool,
        }
    }
}

impl<'a, D: Digest, P: Readable<D> + BatchChainInfo<D>> MerkleizedBatch<'a, D, P> {
    /// Finalize this batch into a [`Changeset`] relative to the base of the
    /// entire retained batch chain.
    pub fn finalize(&self) -> Changeset<D> {
        let base_size = self.base_size();
        let mut overwrites = BTreeMap::new();
        self.collect_overwrites(&mut overwrites);

        let mut appended = Vec::with_capacity((*self.size() - *base_size) as usize);
        for pos in *base_size..*self.size() {
            appended.push(
                self.get_node(Position::new(pos))
                    .expect("flattened appended node missing"),
            );
        }

        Changeset {
            appended: Arc::new(appended),
            overwrites: Arc::new(overwrites),
            root: self.root,
            base_size,
        }
    }
}

impl<'a, D: Digest, P: Readable<D>> MerkleizedBatch<'a, D, P> {
    /// Finalize this batch into a [`Changeset`] relative to its immediate
    /// parent. This is the form used with [`Self::rebase`] for pipelined
    /// speculative execution.
    pub fn finalize_incremental(&self) -> Changeset<D> {
        Changeset {
            appended: self.appended.clone(),
            overwrites: self.overwrites.clone(),
            root: self.root,
            base_size: self.parent_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        conformance::build_test_mmr,
        hasher::{Hasher as _, Standard},
        mem::Mmr,
        read::Readable,
    };
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    /// Build a reference MMR with `n` elements for comparison.
    fn build_reference(hasher: &mut Standard<Sha256>, n: u64) -> Mmr<sha256::Digest> {
        let mmr = Mmr::new(hasher);
        build_test_mmr(hasher, mmr, n)
    }

    use commonware_cryptography::sha256;

    /// For N in {1, 2, 10, 100, 199}, build via reference and via Batch, verify same root and nodes.
    #[test]
    fn test_consistency_with_reference() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();

            for &n in &[1u64, 2, 10, 100, 199] {
                // Reference via build_reference
                let reference = build_reference(&mut hasher, n);

                // Via Batch: start from empty base, add all via batch
                let base = Mmr::new(&mut hasher);
                let mut batch = UnmerkleizedBatch::new(&base);
                for i in 0..n {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    batch.add(&mut hasher, &element);
                }
                let merkleized = batch.merkleize(&mut hasher);
                let changeset = merkleized.finalize();
                let mut result = base.clone();
                result.apply(changeset).unwrap();

                assert_eq!(result.root(), reference.root(), "root mismatch for n={n}");

                // Verify all node digests match.
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

    /// Fork from base, add leaves, merkleize, read root + proofs from MerkleizedBatch, discard batch,
    /// verify base unchanged.
    #[test]
    fn test_lifecycle() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let mut batch = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Batch root should differ from base.
            assert_ne!(merkleized.root(), base_root);

            // Proof from merkleized batch should work.
            let proof = merkleized.proof(Location::new(55)).unwrap();
            hasher.inner().update(&55u64.to_be_bytes());
            let element = hasher.inner().finalize();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new(55),
                &merkleized.root(),
            ));

            // Base should be unchanged.
            assert_eq!(*base.root(), base_root);
        });
    }

    /// Fork, add, merkleize, finalize, apply. Verify base root matches batch root.
    #[test]
    fn test_changeset_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            let mut batch = UnmerkleizedBatch::new(&base);
            for i in 50u64..75 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);
            let batch_root = merkleized.root();
            let changeset = merkleized.finalize();
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), batch_root);

            // Verify matches building directly.
            let reference = build_reference(&mut hasher, 75);
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

    /// Two batches on same base with different mutations. Verify independent roots and base unchanged.
    #[test]
    fn test_multiple_forks() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            // Fork A: add 10 elements.
            let mut batch_a = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Fork B: add 5 different elements (using different seed).
            let mut batch_b = UnmerkleizedBatch::new(&base);
            for i in 100u64..105 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);

            assert_ne!(merkleized_a.root(), merkleized_b.root());
            assert_ne!(merkleized_a.root(), base_root);
            assert_ne!(merkleized_b.root(), base_root);

            assert_eq!(*base.root(), base_root);
        });
    }

    /// Base <- A <- B. Verify B's root and proofs resolve through all layers.
    #[test]
    fn test_fork_of_fork_reads() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            // Layer A: add elements 50..60.
            let mut batch_a = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on top of A: add elements 60..70.
            let mut batch_b = UnmerkleizedBatch::new(&merkleized_a);
            for i in 60u64..70 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);

            // B should have the same root as building 70 elements directly.
            let reference = build_reference(&mut hasher, 70);
            assert_eq!(merkleized_b.root(), *reference.root());

            // Proofs from B should verify.
            for i in [0u64, 25, 55, 65, 69] {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                let proof = merkleized_b.proof(Location::new(i)).unwrap();
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

    /// Base <- A <- B. Apply A, then B, and verify the final root and nodes.
    #[test]
    fn test_fork_of_fork_incremental_changesets() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            // Layer A.
            let mut batch_a = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on top of A.
            let mut batch_b = UnmerkleizedBatch::new(&merkleized_a);
            for i in 60u64..70 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);
            let a_changeset = merkleized_a.finalize_incremental();
            let b_root = merkleized_b.root();
            let b_changeset = merkleized_b.finalize_incremental();

            base.apply(a_changeset).unwrap();
            base.apply(b_changeset).unwrap();

            assert_eq!(*base.root(), b_root);

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

    /// Finalizing a merkleized batch leaves it available as a speculative
    /// parent for further branching.
    #[test]
    fn test_finalize_leaves_merkleized_batch_available_for_children() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let parent = {
                let mut batch = UnmerkleizedBatch::new(&base);
                for i in 50u64..60 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher)
            };
            let parent_finalized = parent.finalize_incremental();
            assert_eq!(parent_finalized.base_size, base.size());

            let child = {
                let mut batch = parent.new_batch();
                for i in 60u64..70 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher)
            };
            let child_root = child.root();
            let child_finalized = child.finalize_incremental();
            assert_eq!(child_finalized.base_size, parent.size());
            assert_eq!(
                Position::new(*child_finalized.base_size + child_finalized.appended.len() as u64),
                build_reference(&mut hasher, 70).size(),
            );
            assert_eq!(child_root, *build_reference(&mut hasher, 70).root());
        });
    }

    /// After the parent is applied, a child batch can be rebased onto the live
    /// MMR so future descendants no longer depend on the old speculative parent.
    #[test]
    fn test_rebase_compacts_one_parent_level() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let mut live_after_parent = base.clone();

            let parent = {
                let mut batch = UnmerkleizedBatch::new(&base);
                for i in 50u64..60 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher)
            };
            let parent_finalized = parent.finalize_incremental();
            live_after_parent.apply(parent_finalized).unwrap();

            let rebased_child = {
                let mut batch = parent.new_batch();
                for i in 60u64..70 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    batch.add(&mut hasher, &element);
                }
                let child = batch.merkleize(&mut hasher);
                child.rebase(&live_after_parent).unwrap()
            };
            drop(parent);

            let grandchild = {
                let mut batch = rebased_child.new_batch();
                for i in 70u64..75 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher)
            };
            let expected_root = grandchild.root();

            let mut live_after_grandchild = live_after_parent.clone();
            live_after_grandchild
                .apply(rebased_child.finalize_incremental())
                .unwrap();
            live_after_grandchild
                .apply(grandchild.finalize_incremental())
                .unwrap();

            let reference = build_reference(&mut hasher, 75);
            assert_eq!(*live_after_grandchild.root(), expected_root);
            assert_eq!(live_after_grandchild.root(), reference.root());
        });
    }

    /// Rebasing must fail if the candidate live parent no longer matches the
    /// frozen parent state captured by the batch.
    #[test]
    fn test_rebase_rejects_mismatched_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 10);

            let parent = {
                let mut batch = UnmerkleizedBatch::new(&base);
                batch.add(&mut hasher, b"a");
                batch.merkleize(&mut hasher)
            };
            let child = {
                let mut batch = parent.new_batch();
                batch.add(&mut hasher, b"b");
                batch.merkleize(&mut hasher)
            };

            let other = build_reference(&mut hasher, 12);
            let result = child.rebase(&other);
            assert!(matches!(
                result,
                Err(Error::RebaseParentMismatch {
                    expected_size,
                    actual_size,
                    ..
                }) if expected_size == parent.size() && actual_size == other.size()
            ));
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

            let updated_digest = Sha256::fill(0xFF);

            // Update leaf and verify root changes.
            let mut batch = UnmerkleizedBatch::new(&base);
            batch
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized = batch.merkleize(&mut hasher);
            assert_ne!(merkleized.root(), base_root);

            // Restore original digest and verify root reverts.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            let original_digest = base.get_node(leaf_5_pos).unwrap();
            let mut batch2 = UnmerkleizedBatch::new(&base);
            batch2
                .update_leaf_digest(Location::new(5), original_digest)
                .unwrap();
            let merkleized_batch2 = batch2.merkleize(&mut hasher);
            assert_eq!(merkleized_batch2.root(), base_root);
        });
    }

    /// Update existing leaf, then add new leaves. Verify root changes and new leaf proof works.
    #[test]
    fn test_update_and_add() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let updated_digest = Sha256::fill(0xAA);
            let mut batch = UnmerkleizedBatch::new(&base);
            batch
                .update_leaf_digest(Location::new(10), updated_digest)
                .unwrap();

            // Add more leaves.
            for i in 50u64..55 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);
            assert_ne!(merkleized.root(), base_root);

            // Verify the updated leaf's digest is in the batch.
            let leaf_10_pos = Position::try_from(Location::new(10)).unwrap();
            assert_eq!(merkleized.get_node(leaf_10_pos), Some(updated_digest));

            // Verify new leaf's proof (add uses leaf_digest, so verify_element_inclusion works).
            hasher.inner().update(&52u64.to_be_bytes());
            let element = hasher.inner().finalize();
            let proof = merkleized.proof(Location::new(52)).unwrap();
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

            let mut batch = UnmerkleizedBatch::new(&base);
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
            let mut batch2 = UnmerkleizedBatch::new(&base);
            batch2.update_leaf_batched(&restore_updates).unwrap();
            let merkleized_batch2 = batch2.merkleize(&mut hasher);
            assert_eq!(merkleized_batch2.root(), base_root);
        });
    }

    /// Single-element and range proofs from MerkleizedBatch verify against root.
    #[test]
    fn test_proof_verification() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let mut batch = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Single element proof.
            hasher.inner().update(&55u64.to_be_bytes());
            let element = hasher.inner().finalize();
            let proof = merkleized.proof(Location::new(55)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new(55),
                &merkleized.root(),
            ));

            // Range proof.
            let range = Location::new(50)..Location::new(55);
            let range_proof = merkleized.range_proof(range.clone()).unwrap();
            let mut elements = Vec::new();
            for i in 50u64..55 {
                hasher.inner().update(&i.to_be_bytes());
                elements.push(hasher.inner().finalize());
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

            let batch = UnmerkleizedBatch::new(&base);
            let merkleized = batch.merkleize(&mut hasher);

            assert_eq!(merkleized.root(), base_root);

            // Proofs should match.
            for loc in [0u64, 10, 49] {
                let base_proof = base.proof(Location::new(loc)).unwrap();
                let batch_proof = merkleized.proof(Location::new(loc)).unwrap();
                assert_eq!(base_proof, batch_proof, "proof mismatch at loc {loc}");
            }
        });
    }

    /// MerkleizedBatch -> into_dirty -> more mutations -> merkleize -> verify.
    #[test]
    fn test_into_dirty_roundtrip() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            // First batch: add 5 leaves.
            let mut batch = UnmerkleizedBatch::new(&base);
            for i in 50u64..55 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Round-trip: back to dirty, add more, merkleize again.
            let mut dirty_again = merkleized.into_dirty();
            for i in 55u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                dirty_again.add(&mut hasher, &element);
            }
            let merkleized_again = dirty_again.merkleize(&mut hasher);

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
            let mut batch1 = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch1.add(&mut hasher, &element);
            }
            let cs1 = batch1.merkleize(&mut hasher).finalize();
            base.apply(cs1).unwrap();

            // Changeset 2: add 10 more leaves on updated base.
            let mut batch2 = UnmerkleizedBatch::new(&base);
            for i in 60u64..70 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
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
            base.prune_to_pos(Position::new(50));

            let mut batch = UnmerkleizedBatch::new(&base);
            for i in 100u64..110 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Proof for retained element should work.
            hasher.inner().update(&80u64.to_be_bytes());
            let element = hasher.inner().finalize();
            let proof = merkleized.proof(Location::new(80)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new(80),
                &merkleized.root(),
            ));

            // Proof for pruned element should fail.
            let result = merkleized.proof(Location::new(0));
            assert!(
                matches!(result, Err(Error::ElementPruned(_))),
                "expected ElementPruned, got {result:?}"
            );
        });
    }

    /// Base <- A (overwrites leaf 5) <- B (adds). Apply A, then B, preserving the overwrite.
    #[test]
    fn test_incremental_changeset_preserves_overwrites() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            let updated_digest = Sha256::fill(0xCC);

            // Layer A: overwrite leaf 5.
            let mut batch_a = UnmerkleizedBatch::new(&base);
            batch_a
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: add leaves.
            let mut batch_b = UnmerkleizedBatch::new(&merkleized_a);
            for i in 100u64..105 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);
            let b_root = merkleized_b.root();

            let a_changeset = merkleized_a.finalize();
            let b_changeset = merkleized_b.finalize();
            base.apply(a_changeset).unwrap();
            base.apply(b_changeset).unwrap();

            assert_eq!(*base.root(), b_root);

            // Verify leaf 5 has the updated digest.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            assert_eq!(base.get_node(leaf_5_pos), Some(updated_digest));
        });
    }

    /// Base <- A (overwrite leaf 5) <- B (overwrite leaf 10) <- C (add 10).
    /// Apply A, then B, then C, and verify the result matches building the equivalent directly.
    #[test]
    fn test_three_deep_stacking() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            let digest_a = Sha256::fill(0xDD);
            let digest_b = Sha256::fill(0xEE);

            // Layer A: overwrite leaf 5.
            let mut batch_a = UnmerkleizedBatch::new(&base);
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
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch_c.add(&mut hasher, &element);
            }
            let merkleized_c = batch_c.merkleize(&mut hasher);
            let c_root = merkleized_c.root();

            let a_changeset = merkleized_a.finalize();
            let b_changeset = merkleized_b.finalize();
            let c_changeset = merkleized_c.finalize();
            base.apply(a_changeset).unwrap();
            base.apply(b_changeset).unwrap();
            base.apply(c_changeset).unwrap();

            assert_eq!(*base.root(), c_root);

            // Build the equivalent directly: 100 base elements with leaves 5 and 10
            // overwritten, then 10 new elements.
            let mut reference = build_reference(&mut hasher, 100);
            let changeset = {
                let mut batch = UnmerkleizedBatch::new(&reference);
                batch
                    .update_leaf_digest(Location::new(5), digest_a)
                    .unwrap();
                batch
                    .update_leaf_digest(Location::new(10), digest_b)
                    .unwrap();
                for i in 300u64..310 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    batch.add(&mut hasher, &element);
                }
                batch.merkleize(&mut hasher).finalize()
            };
            reference.apply(changeset).unwrap();
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

    /// A overwrites leaf 5 with X, B overwrites leaf 5 with Y.
    /// Applying A then B should leave Y as the last writer.
    #[test]
    fn test_overwrite_collision_in_stack() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            let digest_x = Sha256::fill(0xAA);
            let digest_y = Sha256::fill(0xBB);

            // Layer A: overwrite leaf 5 with X.
            let mut batch_a = UnmerkleizedBatch::new(&base);
            batch_a
                .update_leaf_digest(Location::new(5), digest_x)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: overwrite leaf 5 with Y.
            let mut batch_b = merkleized_a.new_batch();
            batch_b
                .update_leaf_digest(Location::new(5), digest_y)
                .unwrap();
            let merkleized_b = batch_b.merkleize(&mut hasher);
            let b_root = merkleized_b.root();

            let a_changeset = merkleized_a.finalize();
            let b_changeset = merkleized_b.finalize();
            base.apply(a_changeset).unwrap();
            base.apply(b_changeset).unwrap();

            assert_eq!(*base.root(), b_root);

            // Verify leaf 5 has Y, not X.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            assert_eq!(base.get_node(leaf_5_pos), Some(digest_y));
        });
    }

    /// Add leaves in a batch, then update one of those new leaves. Verify root.
    #[test]
    fn test_update_appended_leaf() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            // Add 10 leaves in batch, then update the 3rd new leaf (location 52).
            let mut batch = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                batch.add(&mut hasher, &element);
            }
            let updated_digest = Sha256::fill(0xEE);
            batch
                .update_leaf_digest(Location::new(52), updated_digest)
                .unwrap();
            let merkleized = batch.merkleize(&mut hasher);

            // Verify the updated leaf has the new digest.
            let leaf_52_pos = Position::try_from(Location::new(52)).unwrap();
            assert_eq!(merkleized.get_node(leaf_52_pos), Some(updated_digest));

            // Build reference the same way: 60 elements, then update leaf 52.
            let mut reference = build_reference(&mut hasher, 60);
            let changeset = {
                let mut batch = UnmerkleizedBatch::new(&reference);
                batch
                    .update_leaf_digest(Location::new(52), updated_digest)
                    .unwrap();
                batch.merkleize(&mut hasher).finalize()
            };
            reference.apply(changeset).unwrap();
            assert_eq!(merkleized.root(), *reference.root());
        });
    }

    /// update_leaf (element-based) hashes the element before storing. Verify root matches
    /// building the same update via Mmr::update_leaf.
    #[test]
    fn test_update_leaf_element() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let element = b"updated-element";
            let mut batch = UnmerkleizedBatch::new(&base);
            batch
                .update_leaf(&mut hasher, Location::new(5), element)
                .unwrap();
            let merkleized = batch.merkleize(&mut hasher);
            assert_ne!(merkleized.root(), base_root);

            // Reference: same update on Mmr.
            let mut reference = base.clone();
            reference
                .update_leaf(&mut hasher, Location::new(5), element)
                .unwrap();
            assert_eq!(merkleized.root(), *reference.root());
        });
    }

    /// update_leaf_digest and update_leaf_batched reject out-of-bounds locations.
    #[test]
    fn test_update_out_of_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let mut batch = UnmerkleizedBatch::new(&base);

            // update_leaf_digest at location == leaf count.
            let result = batch.update_leaf_digest(Location::new(50), Sha256::fill(0xFF));
            assert!(
                matches!(result, Err(Error::InvalidPosition(_))),
                "expected InvalidPosition, got {result:?}"
            );

            // update_leaf_batched with one out-of-bounds location.
            let updates = [(Location::new(50), Sha256::fill(0xFF))];
            let result = batch.update_leaf_batched(&updates);
            assert!(
                matches!(result, Err(Error::LeafOutOfBounds(_))),
                "expected LeafOutOfBounds, got {result:?}"
            );
        });
    }
}
