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

#[cfg(any(feature = "std", test))]
use crate::mmr::iterator::pos_to_height;
use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_needing_parents, PathIterator, PeakIterator},
    mem::{Clean, Dirty, State},
    read::{BatchChainInfo, Readable},
    Error, Location, Position,
};
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_cryptography::Digest;
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use commonware_parallel::ThreadPool;
        use rayon::prelude::*;
    }
}

/// A batch of mutations against a parent MMR, which may itself be a merkleized batch.
pub struct Batch<'a, D: Digest, P: Readable<Digest = D>, S: State<D> = Dirty> {
    /// The parent MMR.
    parent: &'a P,
    /// Nodes appended by this batch, at positions [parent.size(), parent.size() + appended.len()).
    appended: Vec<D>,
    /// Overwritten nodes at positions < parent.size(). Shadows parent data; later writes win.
    overwrites: BTreeMap<Position, D>,
    /// Type-state: Dirty (mutable, no root) or `Clean<D>` (immutable, has root).
    state: S,
    /// Thread pool for parallel merkleization.
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, D, P> = Batch<'a, D, P, Dirty>;

/// A batch whose root digest has been computed.
pub type MerkleizedBatch<'a, D, P> = Batch<'a, D, P, Clean<D>>;

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

impl<'a, D: Digest, P: Readable<Digest = D>, S: State<D>> Batch<'a, D, P, S> {
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

impl<'a, D: Digest, P: Readable<Digest = D>> UnmerkleizedBatch<'a, D, P> {
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
            self.state.insert(new_node_pos, height);
            height += 1;
        }

        self
    }

    /// Hash `element` and add it as a leaf.
    pub fn add(self, hasher: &mut impl Hasher<Digest = D>, element: &[u8]) -> Self {
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
        hasher: &mut impl Hasher<Digest = D>,
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
        if pos_to_height(pos) != 0 {
            return Err(Error::PositionNotLeaf(pos));
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

    /// Consume this batch and produce an immutable [MerkleizedBatch] with computed root.
    pub fn merkleize(mut self, hasher: &mut impl Hasher<Digest = D>) -> MerkleizedBatch<'a, D, P> {
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

        Batch {
            parent: self.parent,
            appended: self.appended,
            overwrites: self.overwrites,
            state: Clean { root },
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

impl<'a, D: Digest, P: Readable<Digest = D>> Readable for MerkleizedBatch<'a, D, P> {
    type Digest = D;

    fn size(&self) -> Position {
        self.size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.get_node(pos)
    }

    fn root(&self) -> D {
        self.state.root
    }

    fn pruned_to_pos(&self) -> Position {
        self.parent.pruned_to_pos()
    }
}

impl<'a, D: Digest, P: Readable<Digest = D> + BatchChainInfo<Digest = D>> BatchChainInfo
    for MerkleizedBatch<'a, D, P>
{
    type Digest = D;

    fn base_size(&self) -> Position {
        self.parent.base_size()
    }

    fn collect_overwrites(&self, into: &mut BTreeMap<Position, D>) {
        self.parent.collect_overwrites(into);
        let base_size = self.parent.base_size();
        for (&pos, &digest) in &self.overwrites {
            if pos < base_size {
                into.insert(pos, digest);
            }
        }
    }
}

impl<'a, D: Digest, P: Readable<Digest = D>> MerkleizedBatch<'a, D, P> {
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

    /// Convert back to a dirty batch for further mutations.
    pub fn into_dirty(self) -> UnmerkleizedBatch<'a, D, P> {
        Batch {
            parent: self.parent,
            appended: self.appended,
            overwrites: self.overwrites,
            state: Dirty::default(),
            #[cfg(feature = "std")]
            pool: self.pool,
        }
    }
}

impl<'a, D: Digest, P: Readable<Digest = D> + BatchChainInfo<Digest = D>>
    MerkleizedBatch<'a, D, P>
{
    /// Flatten this batch chain into a single [`Changeset`] relative to the
    /// ultimate base MMR.
    pub fn finalize(self) -> Changeset<D> {
        let base_size = self.parent.base_size();
        let effective = self.size();

        // Resolve nodes at [base_size, effective).
        let mut appended = Vec::with_capacity((*effective - *base_size) as usize);
        for i in *base_size..*effective {
            appended.push(self.get_node(Position::new(i)).expect("node in range"));
        }

        // Collect overwrites from entire chain, filtered to positions < base_size.
        let mut overwrites = BTreeMap::new();
        self.collect_overwrites(&mut overwrites);
        overwrites.retain(|&pos, _| pos < base_size);

        Changeset {
            appended,
            overwrites,
            root: self.state.root,
            base_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{conformance::build_test_mmr, hasher::Standard, mem::Mmr, read::Readable};
    use commonware_cryptography::Sha256;
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
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&mut hasher, &element);
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
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Batch root should differ from base.
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
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&mut hasher, &element);
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
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Fork B: add 5 different elements (using different seed).
            let mut batch_b = UnmerkleizedBatch::new(&base);
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&mut hasher, &element);
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
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on top of A: add elements 60..70.
            let mut batch_b = UnmerkleizedBatch::new(&merkleized_a);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);

            // B should have the same root as building 70 elements directly.
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

    /// Base <- A <- B. B.finalize() captures both A and B changes. Apply to base, verify.
    #[test]
    fn test_fork_of_fork_flattened_changeset() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            // Layer A.
            let mut batch_a = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&mut hasher, &element);
            }
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on top of A.
            let mut batch_b = UnmerkleizedBatch::new(&merkleized_a);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);
            let b_root = merkleized_b.root();

            let changeset = merkleized_b.finalize();
            drop(merkleized_a);
            base.apply(changeset).unwrap();

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
            let batch = UnmerkleizedBatch::new(&base)
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized = batch.merkleize(&mut hasher);
            assert_ne!(merkleized.root(), base_root);

            // Restore original digest and verify root reverts.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            let original_digest = base.get_node(leaf_5_pos).unwrap();
            let batch2 = UnmerkleizedBatch::new(&base)
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
            let mut batch = UnmerkleizedBatch::new(&base)
                .update_leaf_digest(Location::new(10), updated_digest)
                .unwrap();

            // Add more leaves.
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&mut hasher, &element);
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

            let batch = UnmerkleizedBatch::new(&base)
                .update_leaf_batched(&updates)
                .unwrap();
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
            let batch2 = UnmerkleizedBatch::new(&base)
                .update_leaf_batched(&restore_updates)
                .unwrap();
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
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&mut hasher, &element);
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

            let batch = UnmerkleizedBatch::new(&base);
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
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&mut hasher, &element);
            }
            let merkleized = batch.merkleize(&mut hasher);

            // Round-trip: back to dirty, add more, merkleize again.
            let mut dirty_again = merkleized.into_dirty();
            for i in 55u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                dirty_again = dirty_again.add(&mut hasher, &element);
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
                let element = hasher.digest(&i.to_be_bytes());
                batch1 = batch1.add(&mut hasher, &element);
            }
            let cs1 = batch1.merkleize(&mut hasher).finalize();
            base.apply(cs1).unwrap();

            // Changeset 2: add 10 more leaves on updated base.
            let mut batch2 = UnmerkleizedBatch::new(&base);
            for i in 60u64..70 {
                let element = hasher.digest(&i.to_be_bytes());
                batch2 = batch2.add(&mut hasher, &element);
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

            let mut batch = UnmerkleizedBatch::new(&base);
            for i in 100u64..110 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&mut hasher, &element);
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

            // Layer A: overwrite leaf 5.
            let batch_a = UnmerkleizedBatch::new(&base)
                .update_leaf_digest(Location::new(5), updated_digest)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: add leaves.
            let mut batch_b = UnmerkleizedBatch::new(&merkleized_a);
            for i in 100u64..105 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&mut hasher, &element);
            }
            let merkleized_b = batch_b.merkleize(&mut hasher);
            let b_root = merkleized_b.root();

            let changeset = merkleized_b.finalize();
            drop(merkleized_a);
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), b_root);

            // Verify leaf 5 has the updated digest.
            let leaf_5_pos = Position::try_from(Location::new(5)).unwrap();
            assert_eq!(base.get_node(leaf_5_pos), Some(updated_digest));
        });
    }

    /// Base <- A (overwrite leaf 5) <- B (overwrite leaf 10) <- C (add 10).
    /// Flatten C's changeset, apply to base, verify root matches building the equivalent directly.
    #[test]
    fn test_three_deep_stacking() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            let digest_a = Sha256::fill(0xDD);
            let digest_b = Sha256::fill(0xEE);

            // Layer A: overwrite leaf 5.
            let batch_a = UnmerkleizedBatch::new(&base)
                .update_leaf_digest(Location::new(5), digest_a)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: overwrite leaf 10.
            let batch_b = merkleized_a
                .new_batch()
                .update_leaf_digest(Location::new(10), digest_b)
                .unwrap();
            let merkleized_b = batch_b.merkleize(&mut hasher);

            // Layer C on B: add 10 leaves.
            let mut batch_c = merkleized_b.new_batch();
            for i in 300u64..310 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_c = batch_c.add(&mut hasher, &element);
            }
            let merkleized_c = batch_c.merkleize(&mut hasher);
            let c_root = merkleized_c.root();

            // Flatten C's changeset all the way to base.
            let changeset = merkleized_c.finalize();
            drop(merkleized_b);
            drop(merkleized_a);
            base.apply(changeset).unwrap();

            assert_eq!(*base.root(), c_root);

            // Build the equivalent directly: 100 base elements with leaves 5 and 10
            // overwritten, then 10 new elements.
            let mut reference = build_reference(&mut hasher, 100);
            let changeset = {
                let mut batch = UnmerkleizedBatch::new(&reference)
                    .update_leaf_digest(Location::new(5), digest_a)
                    .unwrap()
                    .update_leaf_digest(Location::new(10), digest_b)
                    .unwrap();
                for i in 300u64..310 {
                    let element = hasher.digest(&i.to_be_bytes());
                    batch = batch.add(&mut hasher, &element);
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
    /// Flattened changeset should have Y (last writer wins).
    #[test]
    fn test_overwrite_collision_in_stack() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            let digest_x = Sha256::fill(0xAA);
            let digest_y = Sha256::fill(0xBB);

            // Layer A: overwrite leaf 5 with X.
            let batch_a = UnmerkleizedBatch::new(&base)
                .update_leaf_digest(Location::new(5), digest_x)
                .unwrap();
            let merkleized_a = batch_a.merkleize(&mut hasher);

            // Layer B on A: overwrite leaf 5 with Y.
            let batch_b = merkleized_a
                .new_batch()
                .update_leaf_digest(Location::new(5), digest_y)
                .unwrap();
            let merkleized_b = batch_b.merkleize(&mut hasher);
            let b_root = merkleized_b.root();

            let changeset = merkleized_b.finalize();
            drop(merkleized_a);
            base.apply(changeset).unwrap();

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
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&mut hasher, &element);
            }
            let updated_digest = Sha256::fill(0xEE);
            let batch = batch
                .update_leaf_digest(Location::new(52), updated_digest)
                .unwrap();
            let merkleized = batch.merkleize(&mut hasher);

            // Verify the updated leaf has the new digest.
            let leaf_52_pos = Position::try_from(Location::new(52)).unwrap();
            assert_eq!(merkleized.get_node(leaf_52_pos), Some(updated_digest));

            // Build reference the same way: 60 elements, then update leaf 52.
            let mut reference = build_reference(&mut hasher, 60);
            let changeset = {
                UnmerkleizedBatch::new(&reference)
                    .update_leaf_digest(Location::new(52), updated_digest)
                    .unwrap()
                    .merkleize(&mut hasher)
                    .finalize()
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
            let batch = UnmerkleizedBatch::new(&base)
                .update_leaf(&mut hasher, Location::new(5), element)
                .unwrap();
            let merkleized = batch.merkleize(&mut hasher);
            assert_ne!(merkleized.root(), base_root);

            // Reference: same update on Mmr.
            let mut reference = base.clone();
            let batch = reference
                .new_batch()
                .update_leaf(&mut hasher, Location::new(5), element)
                .unwrap();
            reference
                .apply(batch.merkleize(&mut hasher).finalize())
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

            let batch = UnmerkleizedBatch::new(&base);

            // update_leaf_digest at location == leaf count.
            let Err(err) = batch.update_leaf_digest(Location::new(50), Sha256::fill(0xFF)) else {
                panic!("expected error");
            };
            assert!(matches!(err, Error::InvalidPosition(_)));

            // update_leaf_batched with one out-of-bounds location.
            let batch = UnmerkleizedBatch::new(&base);
            let updates = [(Location::new(50), Sha256::fill(0xFF))];
            let Err(err) = batch.update_leaf_batched(&updates) else {
                panic!("expected error");
            };
            assert!(matches!(err, Error::LeafOutOfBounds(_)));
        });
    }
}
