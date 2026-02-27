//! A lightweight, borrow-based diff layer over a merkleized MMR.
//!
//! # Overview
//!
//! A [`Diff`] borrows a parent MMR (anything implementing [`MmrRead`])
//! immutably and records mutations -- appends, leaf updates, pops, and
//! pruning advances -- without touching the parent. Multiple diffs can
//! coexist on the same parent, and diffs can be stacked (Base <- A <- B)
//! to arbitrary depth.
//!
//! # Lifecycle
//!
//! ```text
//! CleanMmr ──borrow──> UnmerkleizedBatch  (accumulate mutations)
//!                            │
//!                       merkleize()
//!                            │
//!                            v
//!                      MerkleizedBatch     (has root, supports proofs)
//!                            │
//!                     into_changeset()
//!                            │
//!                            v
//!                        Changeset         (owned delta, no borrow)
//!                            │
//!                      mmr.apply(cs)
//!                            │
//!                            v
//!                        CleanMmr          (updated in place)
//! ```
//!
//! # Type aliases
//!
//! - [`UnmerkleizedBatch`] -- mutable phase: add, update, pop, advance pruning.
//! - [`MerkleizedBatch`]   -- immutable phase: root is computed, proofs available.
//! - [`Changeset`]         -- owned delta that can be applied to the base MMR.
//!
//! # Example
//!
//! ```ignore
//! let mut hasher = StandardHasher::<Sha256>::new();
//! let mut mmr = CleanMmr::new(&mut hasher.inner());
//!
//! // Build a batch of mutations.
//! let changeset = {
//!     let mut batch = UnmerkleizedBatch::new(&mmr);
//!     batch.add(&mut hasher, b"leaf-0");
//!     batch.add(&mut hasher, b"leaf-1");
//!     batch.merkleize(&mut hasher).into_changeset()
//! };
//!
//! // Apply the changeset back to the base MMR.
//! mmr.apply(changeset);
//! ```

#[cfg(any(feature = "std", test))]
use crate::mmr::iterator::pos_to_height;
use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_needing_parents, PathIterator, PeakIterator},
    mem::{Clean, Dirty, State},
    read::{ChainInfo, MmrRead},
    Error, Location, Position,
};
use alloc::{collections::BTreeMap, vec::Vec};
use commonware_cryptography::Digest;
use core::cmp;
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use commonware_parallel::ThreadPool;
        use rayon::prelude::*;
    }
}

/// Minimum number of dirty nodes to trigger parallel merkleization.
#[cfg(feature = "std")]
const MIN_TO_PARALLELIZE: usize = 20;

/// A diff layer over a parent MMR.
///
/// Stores only mutations (appends, overwrites, pops, pruning) and reads
/// through the parent for unchanged nodes. The type-state parameter `S`
/// tracks whether the diff has been merkleized ([`Clean`]) or not ([`Dirty`]).
pub struct Diff<'a, D: Digest, P: MmrRead<D>, S: State<D> = Dirty> {
    parent: &'a P,
    /// How many of the parent's nodes remain visible (decreases on pop).
    parent_visible: Position,
    /// New nodes at positions [parent_visible, effective_size).
    appended: Vec<D>,
    /// Modified nodes at positions < parent_visible. Shadows parent data.
    overwrites: BTreeMap<Position, D>,
    /// Logical pruning boundary (materialized on apply).
    pruned_to_pos: Position,
    /// Type-state: Dirty (mutable phase) or `Clean<D>` (immutable, has root).
    state: S,
    /// Thread pool for parallel merkleization.
    #[cfg(feature = "std")]
    pool: Option<ThreadPool>,
}

/// A diff whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, D, P> = Diff<'a, D, P, Dirty>;

/// A diff whose root digest has been computed.
pub type MerkleizedBatch<'a, D, P> = Diff<'a, D, P, Clean<D>>;

/// Owned delta extracted from a diff chain, relative to the ultimate base.
///
/// Apply via [`super::mem::CleanMmr::apply`].
pub struct Changeset<D: Digest> {
    /// Base nodes to keep: [0, parent_end). If < base.size(), truncate tail.
    pub(crate) parent_end: Position,
    /// Nodes at positions [parent_end, parent_end + appended.len()).
    pub(crate) appended: Vec<D>,
    /// Modified base nodes in [pruned_to_pos, parent_end).
    pub(crate) overwrites: BTreeMap<Position, D>,
    /// Root digest reflecting all changes.
    pub(crate) root: D,
    /// Pruning boundary to apply.
    pub(crate) pruned_to_pos: Position,
}

impl<'a, D: Digest, P: MmrRead<D>, S: State<D>> Diff<'a, D, P, S> {
    /// The total number of nodes visible through this diff.
    fn effective_size(&self) -> Position {
        Position::new(*self.parent_visible + self.appended.len() as u64)
    }

    /// Resolve a node: overwrites -> appended -> parent.
    fn resolve_node(&self, pos: Position) -> Option<D> {
        if pos >= self.effective_size() {
            return None;
        }
        if let Some(d) = self.overwrites.get(&pos) {
            return Some(*d);
        }
        if pos >= self.parent_visible {
            let index = (*pos - *self.parent_visible) as usize;
            return self.appended.get(index).copied();
        }
        self.parent.get_node(pos)
    }

    /// Write a digest to the correct storage location.
    fn store_node(&mut self, pos: Position, digest: D) {
        if pos >= self.parent_visible {
            let index = (*pos - *self.parent_visible) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }
}

impl<'a, D: Digest, P: MmrRead<D>> UnmerkleizedBatch<'a, D, P> {
    /// The total number of nodes visible through this diff.
    pub fn size(&self) -> Position {
        self.effective_size()
    }

    /// The number of leaves visible through this diff.
    pub fn leaves(&self) -> Location {
        Location::try_from(self.effective_size()).expect("invalid mmr size")
    }

    /// Create a new diff borrowing `parent` immutably.
    /// O(1) time and space.
    pub fn new(parent: &'a P) -> Self {
        Self {
            parent_visible: parent.size(),
            pruned_to_pos: parent.pruned_to_pos(),
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
        let nodes_needing_parents = nodes_needing_parents(PeakIterator::new(self.effective_size()))
            .into_iter()
            .rev();
        let leaf_pos = self.effective_size();
        self.appended.push(digest);

        let mut height = 1;
        for _ in nodes_needing_parents {
            let new_node_pos = self.effective_size();
            self.appended.push(D::EMPTY);
            self.state.insert(new_node_pos, height);
            height += 1;
        }

        leaf_pos
    }

    /// Hash `element` and add it as a leaf. Returns the leaf's position.
    pub fn add(&mut self, hasher: &mut impl Hasher<Digest = D>, element: &[u8]) -> Position {
        let digest = hasher.leaf_digest(self.effective_size(), element);
        self.add_leaf_digest(digest)
    }

    /// Update the leaf at `loc` to `element`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LeafOutOfBounds`] if `loc` is not an existing leaf.
    /// Returns [`Error::LocationOverflow`] if `loc` > [`crate::mmr::MAX_LOCATION`].
    /// Returns [`Error::ElementPruned`] if the leaf has been pruned.
    pub fn update_leaf(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<(), Error> {
        let leaves = Location::try_from(self.effective_size()).expect("invalid mmr size");
        if loc >= leaves {
            return Err(Error::LeafOutOfBounds(loc));
        }
        let pos = Position::try_from(loc)?;
        let prune_boundary = cmp::max(self.parent.pruned_to_pos(), self.pruned_to_pos);
        if pos < prune_boundary {
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
        let prune_boundary = cmp::max(self.parent.pruned_to_pos(), self.pruned_to_pos);
        if pos < prune_boundary {
            return Err(Error::ElementPruned(pos));
        }
        if pos >= self.effective_size() {
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
        let leaves = Location::try_from(self.effective_size()).expect("invalid mmr size");
        let prune_boundary = cmp::max(self.parent.pruned_to_pos(), self.pruned_to_pos);
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

    /// Pop the most recent leaf. Can pop into parent range.
    pub fn pop(&mut self) -> Result<Position, Error> {
        if self.effective_size() == 0 {
            return Err(Error::Empty);
        }

        let mut new_size = self.effective_size() - 1;
        loop {
            if new_size < self.pruned_to_pos {
                return Err(Error::ElementPruned(new_size));
            }
            if new_size.is_mmr_size() {
                break;
            }
            new_size -= 1;
        }

        // Truncate: remove nodes from appended and/or shrink parent_visible.
        if new_size >= self.parent_visible {
            let keep_appended = (*new_size - *self.parent_visible) as usize;
            self.appended.truncate(keep_appended);
        } else {
            self.appended.clear();
            self.parent_visible = new_size;
            // Remove overwrites at positions >= new parent_visible.
            self.overwrites.split_off(&new_size);
        }

        // Remove dirty nodes that are now out of bounds.
        self.state.remove_above(self.effective_size());

        Ok(self.effective_size())
    }

    /// Record intent to prune to `pos`. Logical only -- parent is immutable.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPosition`] if `pos` exceeds the diff's size.
    pub fn advance_pruning(&mut self, pos: Position) -> Result<(), Error> {
        if pos > self.effective_size() {
            return Err(Error::InvalidPosition(pos));
        }
        self.pruned_to_pos = cmp::max(self.pruned_to_pos, pos);
        Ok(())
    }

    /// Consume this batch and produce an immutable MerkleizedBatch with computed root.
    ///
    /// If a thread pool was set via [`with_pool`](Self::with_pool) and there are
    /// enough dirty nodes, node digests at the same height are computed in parallel.
    pub fn merkleize(mut self, hasher: &mut impl Hasher<Digest = D>) -> MerkleizedBatch<'a, D, P> {
        let dirty = self.state.take_sorted_by_height();

        #[cfg(feature = "std")]
        let saved_pool = self.pool.clone();
        #[cfg(feature = "std")]
        match (self.pool.take(), dirty.len() >= MIN_TO_PARALLELIZE) {
            (Some(pool), true) => self.merkleize_parallel(hasher, pool, &dirty),
            _ => self.merkleize_serial(hasher, &dirty),
        }

        #[cfg(not(feature = "std"))]
        self.merkleize_serial(hasher, &dirty);

        // Compute root from peaks.
        let leaves = Location::try_from(self.effective_size()).expect("invalid mmr size");
        let peaks: Vec<D> = PeakIterator::new(self.effective_size())
            .map(|(peak_pos, _)| self.resolve_node(peak_pos).expect("peak missing"))
            .collect();
        let root = hasher.root(leaves, peaks.iter());

        Diff {
            parent: self.parent,
            parent_visible: self.parent_visible,
            appended: self.appended,
            overwrites: self.overwrites,
            pruned_to_pos: self.pruned_to_pos,
            state: Clean { root },
            // Preserve the pool so child batches can inherit it.
            #[cfg(feature = "std")]
            pool: saved_pool,
        }
    }

    // NOTE: The serial/parallel merkleize logic is intentionally duplicated in
    // `mem::DirtyMmr` which uses direct indexing instead of resolve_node/store_node.
    fn merkleize_serial(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        dirty: &[(Position, u32)],
    ) {
        for &(pos, height) in dirty {
            let left = pos - (1 << height);
            let right = pos - 1;
            let left_d = self.resolve_node(left).expect("left child missing");
            let right_d = self.resolve_node(right).expect("right child missing");
            let digest = hasher.node_digest(pos, &left_d, &right_d);
            self.store_node(pos, digest);
        }
    }

    /// Process dirty nodes in parallel, grouping by height. Falls back to serial
    /// when the remaining count drops below [`MIN_TO_PARALLELIZE`].
    #[cfg(feature = "std")]
    fn merkleize_parallel(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        pool: ThreadPool,
        dirty: &[(Position, u32)],
    ) {
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
            self.update_node_digests(hasher, pool.clone(), &same_height, current_height);
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
        pool: ThreadPool,
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
                        let left_d = self.resolve_node(left).expect("left child missing");
                        let right_d = self.resolve_node(right).expect("right child missing");
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

    /// Shorthand for `self.merkleize(hasher).into_changeset()`.
    pub fn finalize(self, hasher: &mut impl Hasher<Digest = D>) -> Changeset<D>
    where
        P: ChainInfo<D>,
    {
        self.merkleize(hasher).into_changeset()
    }

    /// Mark ancestors of `pos` as dirty up to the peak.
    fn mark_dirty(&mut self, pos: Position) {
        for (peak_pos, mut height) in PeakIterator::new(self.effective_size()) {
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

        panic!("invalid pos {pos}:{}", self.effective_size());
    }
}

impl<'a, D: Digest, P: MmrRead<D>> MmrRead<D> for MerkleizedBatch<'a, D, P> {
    fn size(&self) -> Position {
        self.effective_size()
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        self.resolve_node(pos)
    }

    fn root(&self) -> D {
        self.state.root
    }

    fn pruned_to_pos(&self) -> Position {
        self.pruned_to_pos
    }
}

impl<'a, D: Digest, P: MmrRead<D> + ChainInfo<D>> ChainInfo<D> for MerkleizedBatch<'a, D, P> {
    fn base_size(&self) -> Position {
        self.parent.base_size()
    }

    fn base_visible(&self) -> Position {
        cmp::min(self.parent_visible, self.parent.base_visible())
    }

    fn collect_chain_overwrites(&self, into: &mut BTreeMap<Position, D>) {
        self.parent.collect_chain_overwrites(into);
        let bs = self.parent.base_size();
        for (&pos, &digest) in &self.overwrites {
            if pos < bs {
                into.insert(pos, digest);
            }
        }
    }
}

impl<'a, D: Digest, P: MmrRead<D>> MerkleizedBatch<'a, D, P> {
    /// Access the parent MMR.
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

    /// Convert back to a dirty diff for further mutations.
    pub fn into_dirty(self) -> UnmerkleizedBatch<'a, D, P> {
        Diff {
            parent: self.parent,
            parent_visible: self.parent_visible,
            appended: self.appended,
            overwrites: self.overwrites,
            pruned_to_pos: self.pruned_to_pos,
            state: Dirty::default(),
            #[cfg(feature = "std")]
            pool: self.pool,
        }
    }
}

impl<'a, D: Digest, P: MmrRead<D> + ChainInfo<D>> MerkleizedBatch<'a, D, P> {
    /// Flatten this diff chain into a single [`Changeset`] relative to the
    /// ultimate base MMR.
    pub fn into_changeset(self) -> Changeset<D> {
        let base_vis = cmp::min(self.parent_visible, self.parent.base_visible());
        let effective = self.effective_size();
        let pruned = self.pruned_to_pos;

        // Resolve nodes at [base_vis, effective).
        let mut appended = Vec::with_capacity((*effective - *base_vis) as usize);
        for i in *base_vis..*effective {
            appended.push(self.resolve_node(Position::new(i)).expect("node in range"));
        }

        // Collect overwrites from entire chain, filtered to [pruned, base_vis).
        let mut overwrites = BTreeMap::new();
        self.parent.collect_chain_overwrites(&mut overwrites);
        let bs = self.parent.base_size();
        for (&pos, &digest) in &self.overwrites {
            if pos < bs {
                overwrites.insert(pos, digest);
            }
        }
        overwrites.retain(|&pos, _| pos >= pruned && pos < base_vis);

        Changeset {
            parent_end: base_vis,
            appended,
            overwrites,
            root: self.state.root,
            pruned_to_pos: pruned,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        conformance::build_test_mmr,
        hasher::{Hasher as _, Standard},
        mem::CleanMmr,
        read::MmrRead,
    };
    use commonware_cryptography::{Hasher, Sha256};
    use commonware_runtime::{deterministic, Runner as _};

    /// Build a reference MMR with `n` elements for comparison.
    fn build_reference(hasher: &mut Standard<Sha256>, n: u64) -> CleanMmr<sha256::Digest> {
        let mmr = CleanMmr::new(hasher);
        build_test_mmr(hasher, mmr, n)
    }

    use commonware_cryptography::sha256;

    /// For N in {1, 2, 10, 100, 199}, build via reference and via Diff, verify same root and nodes.
    #[test]
    fn test_consistency_with_reference() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();

            for &n in &[1u64, 2, 10, 100, 199] {
                // Reference via build_reference
                let reference = build_reference(&mut hasher, n);

                // Via Diff: start from empty base, add all via diff
                let base = CleanMmr::new(&mut hasher);
                let mut diff = UnmerkleizedBatch::new(&base);
                for i in 0..n {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    diff.add(&mut hasher, &element);
                }
                let clean_diff = diff.merkleize(&mut hasher);
                let changeset = clean_diff.into_changeset();
                let mut result = base.clone();
                result.apply(changeset);

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

    /// Fork from base, add leaves, merkleize, read root + proofs from MerkleizedBatch, discard diff,
    /// verify base unchanged.
    #[test]
    fn test_lifecycle() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let clean_diff = diff.merkleize(&mut hasher);

            // Diff root should differ from base.
            assert_ne!(clean_diff.root(), base_root);

            // Proof from clean diff should work.
            let proof = clean_diff.proof(Location::new_unchecked(55)).unwrap();
            hasher.inner().update(&55u64.to_be_bytes());
            let element = hasher.inner().finalize();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new_unchecked(55),
                &clean_diff.root(),
            ));

            // Drop diff, verify base unchanged.
            drop(clean_diff);
            assert_eq!(*base.root(), base_root);
        });
    }

    /// Fork, add, merkleize, into_changeset, apply. Verify base root matches diff root.
    #[test]
    fn test_changeset_apply() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 50u64..75 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let clean_diff = diff.merkleize(&mut hasher);
            let diff_root = clean_diff.root();
            let changeset = clean_diff.into_changeset();
            base.apply(changeset);

            assert_eq!(*base.root(), diff_root);

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

    /// Two diffs on same base with different mutations. Verify independent roots and base unchanged.
    #[test]
    fn test_multiple_forks() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            // Fork A: add 10 elements.
            let mut diff_a = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_a.add(&mut hasher, &element);
            }
            let clean_a = diff_a.merkleize(&mut hasher);

            // Fork B: add 5 different elements (using different seed).
            let mut diff_b = UnmerkleizedBatch::new(&base);
            for i in 100u64..105 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_b.add(&mut hasher, &element);
            }
            let clean_b = diff_b.merkleize(&mut hasher);

            assert_ne!(clean_a.root(), clean_b.root());
            assert_ne!(clean_a.root(), base_root);
            assert_ne!(clean_b.root(), base_root);

            drop(clean_a);
            drop(clean_b);
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
            let mut diff_a = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_a.add(&mut hasher, &element);
            }
            let clean_a = diff_a.merkleize(&mut hasher);

            // Layer B on top of A: add elements 60..70.
            let mut diff_b = UnmerkleizedBatch::new(&clean_a);
            for i in 60u64..70 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_b.add(&mut hasher, &element);
            }
            let clean_b = diff_b.merkleize(&mut hasher);

            // B should have the same root as building 70 elements directly.
            let reference = build_reference(&mut hasher, 70);
            assert_eq!(clean_b.root(), *reference.root());

            // Proofs from B should verify.
            for i in [0u64, 25, 55, 65, 69] {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                let proof = clean_b.proof(Location::new_unchecked(i)).unwrap();
                assert!(
                    proof.verify_element_inclusion(
                        &mut hasher,
                        &element,
                        Location::new_unchecked(i),
                        &clean_b.root(),
                    ),
                    "proof failed for element {i}"
                );
            }
        });
    }

    /// Base <- A <- B. B.into_changeset() captures both A and B changes. Apply to base, verify.
    #[test]
    fn test_fork_of_fork_flattened_changeset() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            // Layer A.
            let mut diff_a = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_a.add(&mut hasher, &element);
            }
            let clean_a = diff_a.merkleize(&mut hasher);

            // Layer B on top of A.
            let mut diff_b = UnmerkleizedBatch::new(&clean_a);
            for i in 60u64..70 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_b.add(&mut hasher, &element);
            }
            let clean_b = diff_b.merkleize(&mut hasher);
            let b_root = clean_b.root();

            let changeset = clean_b.into_changeset();
            drop(clean_a);
            base.apply(changeset);

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

    /// Overwrite leaf digest in diff, merkleize, verify root changes and reverts.
    #[test]
    fn test_update_leaf() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 100);
            let base_root = *base.root();

            let updated_digest = Sha256::fill(0xFF);

            // Update leaf and verify root changes.
            let mut diff = UnmerkleizedBatch::new(&base);
            diff.update_leaf_digest(Location::new_unchecked(5), updated_digest)
                .unwrap();
            let clean_diff = diff.merkleize(&mut hasher);
            assert_ne!(clean_diff.root(), base_root);

            // Restore original digest and verify root reverts.
            let leaf_5_pos = Position::try_from(Location::new_unchecked(5)).unwrap();
            let original_digest = base.get_node(leaf_5_pos).unwrap();
            let mut diff2 = UnmerkleizedBatch::new(&base);
            diff2
                .update_leaf_digest(Location::new_unchecked(5), original_digest)
                .unwrap();
            let clean_diff2 = diff2.merkleize(&mut hasher);
            assert_eq!(clean_diff2.root(), base_root);
        });
    }

    /// Update existing leaf, then add new leaves. Verify root differs and new leaf proof works.
    #[test]
    fn test_update_and_add() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let updated_digest = Sha256::fill(0xAA);
            let mut diff = UnmerkleizedBatch::new(&base);
            diff.update_leaf_digest(Location::new_unchecked(10), updated_digest)
                .unwrap();

            // Add more leaves.
            for i in 50u64..55 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let clean_diff = diff.merkleize(&mut hasher);
            assert_ne!(clean_diff.root(), base_root);

            // Verify the updated leaf's digest is in the diff.
            let leaf_10_pos = Position::try_from(Location::new_unchecked(10)).unwrap();
            assert_eq!(clean_diff.get_node(leaf_10_pos), Some(updated_digest));

            // Verify new leaf's proof (add uses leaf_digest, so verify_element_inclusion works).
            hasher.inner().update(&52u64.to_be_bytes());
            let element = hasher.inner().finalize();
            let proof = clean_diff.proof(Location::new_unchecked(52)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new_unchecked(52),
                &clean_diff.root(),
            ));
        });
    }

    /// Batch update multiple leaf digests, merkleize, verify root differs and digests stored.
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
                .map(|&i| (Location::new_unchecked(i), updated_digest))
                .collect();

            let mut diff = UnmerkleizedBatch::new(&base);
            diff.update_leaf_batched(&updates).unwrap();
            let clean_diff = diff.merkleize(&mut hasher);

            assert_ne!(clean_diff.root(), base_root);

            // Verify digests were stored correctly.
            for &loc_val in &[0u64, 10, 50, 99] {
                let pos = Position::try_from(Location::new_unchecked(loc_val)).unwrap();
                assert_eq!(
                    clean_diff.get_node(pos),
                    Some(updated_digest),
                    "digest mismatch at loc {loc_val}"
                );
            }

            // Verify restoring originals gives back original root.
            let mut restore_updates = Vec::new();
            for &loc_val in &[0u64, 10, 50, 99] {
                let pos = Position::try_from(Location::new_unchecked(loc_val)).unwrap();
                let original = base.get_node(pos).unwrap();
                restore_updates.push((Location::new_unchecked(loc_val), original));
            }
            let mut diff2 = UnmerkleizedBatch::new(&base);
            diff2.update_leaf_batched(&restore_updates).unwrap();
            let clean_diff2 = diff2.merkleize(&mut hasher);
            assert_eq!(clean_diff2.root(), base_root);
        });
    }

    /// Single-element and range proofs from MerkleizedBatch verify against root.
    #[test]
    fn test_proof_verification() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let clean_diff = diff.merkleize(&mut hasher);

            // Single element proof.
            hasher.inner().update(&55u64.to_be_bytes());
            let element = hasher.inner().finalize();
            let proof = clean_diff.proof(Location::new_unchecked(55)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new_unchecked(55),
                &clean_diff.root(),
            ));

            // Range proof.
            let range = Location::new_unchecked(50)..Location::new_unchecked(55);
            let range_proof = clean_diff.range_proof(range.clone()).unwrap();
            let mut elements = Vec::new();
            for i in 50u64..55 {
                hasher.inner().update(&i.to_be_bytes());
                elements.push(hasher.inner().finalize());
            }
            assert!(range_proof.verify_range_inclusion(
                &mut hasher,
                &elements,
                range.start,
                &clean_diff.root(),
            ));
        });
    }

    /// Merkleize a no-op diff. Same root as parent.
    #[test]
    fn test_empty_diff() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);
            let base_root = *base.root();

            let diff = UnmerkleizedBatch::new(&base);
            let clean_diff = diff.merkleize(&mut hasher);

            assert_eq!(clean_diff.root(), base_root);

            // Proofs should match.
            for loc in [0u64, 10, 49] {
                let base_proof = base.proof(Location::new_unchecked(loc)).unwrap();
                let diff_proof = clean_diff.proof(Location::new_unchecked(loc)).unwrap();
                assert_eq!(base_proof, diff_proof, "proof mismatch at loc {loc}");
            }
        });
    }

    /// Add then pop in diff. Verify root matches smaller reference MMR.
    #[test]
    fn test_pop_appended() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 50u64..55 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            // Pop last leaf.
            diff.pop().unwrap();

            let clean_diff = diff.merkleize(&mut hasher);

            let reference = build_reference(&mut hasher, 54);
            assert_eq!(clean_diff.root(), *reference.root());
        });
    }

    /// Pop leaves from base range via diff. Verify root matches building a fresh MMR with fewer
    /// leaves.
    #[test]
    fn test_pop_into_parent() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let mut diff = UnmerkleizedBatch::new(&base);
            // Pop 5 leaves from the base.
            for _ in 0..5 {
                diff.pop().unwrap();
            }
            let clean_diff = diff.merkleize(&mut hasher);

            let reference = build_reference(&mut hasher, 45);
            assert_eq!(clean_diff.root(), *reference.root());

            // Apply and verify.
            let mut base_copy = base.clone();
            let changeset = clean_diff.into_changeset();
            base_copy.apply(changeset);
            assert_eq!(base_copy.root(), reference.root());
        });
    }

    /// Pop into parent range, then add new leaves. Verify root and proofs.
    #[test]
    fn test_pop_then_add() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let mut diff = UnmerkleizedBatch::new(&base);
            // Pop 5.
            for _ in 0..5 {
                diff.pop().unwrap();
            }
            // Add 10 new.
            for i in 100u64..110 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let clean_diff = diff.merkleize(&mut hasher);

            // Build reference: 45 original elements then 10 with different seed.
            let mut reference = build_reference(&mut hasher, 45);
            let changeset = {
                let mut diff = UnmerkleizedBatch::new(&reference);
                for i in 100u64..110 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    diff.add(&mut hasher, &element);
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            reference.apply(changeset);

            assert_eq!(clean_diff.root(), *reference.root());
        });
    }

    /// Pop past pruned boundary returns Error::ElementPruned.
    #[test]
    fn test_pop_error_on_prune_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 20);
            base.prune_to_pos(Position::new(15));

            let mut diff = UnmerkleizedBatch::new(&base);
            // Pop until we hit the prune boundary.
            loop {
                match diff.pop() {
                    Ok(_) => continue,
                    Err(Error::ElementPruned(_)) => break,
                    Err(e) => panic!("unexpected error: {e}"),
                }
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

            // First diff: add 5 leaves.
            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 50u64..55 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let clean_diff = diff.merkleize(&mut hasher);

            // Round-trip: back to dirty, add more, merkleize again.
            let mut dirty_again = clean_diff.into_dirty();
            for i in 55u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                dirty_again.add(&mut hasher, &element);
            }
            let clean_again = dirty_again.merkleize(&mut hasher);

            let reference = build_reference(&mut hasher, 60);
            assert_eq!(clean_again.root(), *reference.root());
        });
    }

    /// Apply changeset 1. Create new diff on updated base, apply changeset 2. Verify final state.
    #[test]
    fn test_sequential_changesets() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            // Changeset 1: add 10 leaves.
            let mut diff1 = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff1.add(&mut hasher, &element);
            }
            let cs1 = diff1.merkleize(&mut hasher).into_changeset();
            base.apply(cs1);

            // Changeset 2: add 10 more leaves on updated base.
            let mut diff2 = UnmerkleizedBatch::new(&base);
            for i in 60u64..70 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff2.add(&mut hasher, &element);
            }
            let cs2 = diff2.merkleize(&mut hasher).into_changeset();
            base.apply(cs2);

            let reference = build_reference(&mut hasher, 70);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Diff advances pruning, changeset carries it, apply prunes base.
    #[test]
    fn test_advance_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 100u64..110 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            diff.advance_pruning(Position::new(50)).unwrap();
            let clean_diff = diff.merkleize(&mut hasher);
            let changeset = clean_diff.into_changeset();
            base.apply(changeset);

            assert_eq!(base.bounds().start, Position::new(50));

            // Root should match reference built from scratch with same content.
            let reference = build_reference(&mut hasher, 110);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Create diff on a base that has been pruned. Proofs for retained elements work.
    #[test]
    fn test_diff_on_pruned_base() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);
            base.prune_to_pos(Position::new(50));

            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 100u64..110 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let clean_diff = diff.merkleize(&mut hasher);

            // Proof for retained element should work.
            hasher.inner().update(&80u64.to_be_bytes());
            let element = hasher.inner().finalize();
            let proof = clean_diff.proof(Location::new_unchecked(80)).unwrap();
            assert!(proof.verify_element_inclusion(
                &mut hasher,
                &element,
                Location::new_unchecked(80),
                &clean_diff.root(),
            ));

            // Proof for pruned element should fail.
            let result = clean_diff.proof(Location::new_unchecked(0));
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
            let mut diff_a = UnmerkleizedBatch::new(&base);
            diff_a
                .update_leaf_digest(Location::new_unchecked(5), updated_digest)
                .unwrap();
            let clean_a = diff_a.merkleize(&mut hasher);

            // Layer B on A: add leaves.
            let mut diff_b = UnmerkleizedBatch::new(&clean_a);
            for i in 100u64..105 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_b.add(&mut hasher, &element);
            }
            let clean_b = diff_b.merkleize(&mut hasher);
            let b_root = clean_b.root();

            let changeset = clean_b.into_changeset();
            drop(clean_a);
            base.apply(changeset);

            assert_eq!(*base.root(), b_root);

            // Verify leaf 5 has the updated digest.
            let leaf_5_pos = Position::try_from(Location::new_unchecked(5)).unwrap();
            assert_eq!(base.get_node(leaf_5_pos), Some(updated_digest));
        });
    }

    /// Base <- A (pops into base) <- B (adds). B's changeset has parent_end < base.size().
    #[test]
    fn test_flattened_changeset_with_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 50);

            // Layer A: pop 5 leaves.
            let mut diff_a = UnmerkleizedBatch::new(&base);
            for _ in 0..5 {
                diff_a.pop().unwrap();
            }
            let clean_a = diff_a.merkleize(&mut hasher);

            // Layer B on A: add 10 new leaves.
            let mut diff_b = UnmerkleizedBatch::new(&clean_a);
            for i in 200u64..210 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_b.add(&mut hasher, &element);
            }
            let clean_b = diff_b.merkleize(&mut hasher);
            let b_root = clean_b.root();

            let changeset = clean_b.into_changeset();
            drop(clean_a);
            base.apply(changeset);

            assert_eq!(*base.root(), b_root);

            // Build reference: 45 base elements + 10 new.
            let mut reference = build_reference(&mut hasher, 45);
            let changeset = {
                let mut diff = UnmerkleizedBatch::new(&reference);
                for i in 200u64..210 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    diff.add(&mut hasher, &element);
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            reference.apply(changeset);
            assert_eq!(base.root(), reference.root());
        });
    }

    /// Base <- A (overwrite leaf 5) <- B (pop 3) <- C (add 10).
    /// Flatten C's changeset, apply to base, verify root matches building the equivalent directly.
    #[test]
    fn test_three_deep_stacking() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut base = build_reference(&mut hasher, 100);

            // Layer A: overwrite leaf 5.
            let updated_digest = Sha256::fill(0xDD);
            let mut diff_a = UnmerkleizedBatch::new(&base);
            diff_a
                .update_leaf_digest(Location::new_unchecked(5), updated_digest)
                .unwrap();
            let clean_a = diff_a.merkleize(&mut hasher);

            // Layer B on A: pop 3 leaves.
            let mut diff_b = clean_a.new_batch();
            for _ in 0..3 {
                diff_b.pop().unwrap();
            }
            let clean_b = diff_b.merkleize(&mut hasher);

            // Layer C on B: add 10 leaves.
            let mut diff_c = clean_b.new_batch();
            for i in 300u64..310 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff_c.add(&mut hasher, &element);
            }
            let clean_c = diff_c.merkleize(&mut hasher);
            let c_root = clean_c.root();

            // Flatten C's changeset all the way to base.
            let changeset = clean_c.into_changeset();
            drop(clean_b);
            drop(clean_a);
            base.apply(changeset);

            assert_eq!(*base.root(), c_root);

            // Build the equivalent directly: 97 base elements with leaf 5 overwritten,
            // then 10 new elements.
            let mut reference = build_reference(&mut hasher, 97);
            let changeset = {
                let mut diff = UnmerkleizedBatch::new(&reference);
                diff.update_leaf_digest(Location::new_unchecked(5), updated_digest)
                    .unwrap();
                for i in 300u64..310 {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    diff.add(&mut hasher, &element);
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            reference.apply(changeset);
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
            let mut diff_a = UnmerkleizedBatch::new(&base);
            diff_a
                .update_leaf_digest(Location::new_unchecked(5), digest_x)
                .unwrap();
            let clean_a = diff_a.merkleize(&mut hasher);

            // Layer B on A: overwrite leaf 5 with Y.
            let mut diff_b = clean_a.new_batch();
            diff_b
                .update_leaf_digest(Location::new_unchecked(5), digest_y)
                .unwrap();
            let clean_b = diff_b.merkleize(&mut hasher);
            let b_root = clean_b.root();

            let changeset = clean_b.into_changeset();
            drop(clean_a);
            base.apply(changeset);

            assert_eq!(*base.root(), b_root);

            // Verify leaf 5 has Y, not X.
            let leaf_5_pos = Position::try_from(Location::new_unchecked(5)).unwrap();
            assert_eq!(base.get_node(leaf_5_pos), Some(digest_y));
        });
    }

    /// Add leaves in a diff, then update one of those new leaves. Verify root.
    #[test]
    fn test_update_appended_leaf() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            // Add 10 leaves in diff, then update the 3rd new leaf (location 52).
            let mut diff = UnmerkleizedBatch::new(&base);
            for i in 50u64..60 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                diff.add(&mut hasher, &element);
            }
            let updated_digest = Sha256::fill(0xEE);
            diff.update_leaf_digest(Location::new_unchecked(52), updated_digest)
                .unwrap();
            let clean_diff = diff.merkleize(&mut hasher);

            // Verify the updated leaf has the new digest.
            let leaf_52_pos = Position::try_from(Location::new_unchecked(52)).unwrap();
            assert_eq!(clean_diff.get_node(leaf_52_pos), Some(updated_digest));

            // Build reference the same way: 60 elements, then update leaf 52.
            let mut reference = build_reference(&mut hasher, 60);
            let changeset = {
                let mut diff = UnmerkleizedBatch::new(&reference);
                diff.update_leaf_digest(Location::new_unchecked(52), updated_digest)
                    .unwrap();
                diff.merkleize(&mut hasher).into_changeset()
            };
            reference.apply(changeset);
            assert_eq!(clean_diff.root(), *reference.root());
        });
    }

    /// advance_pruning beyond size returns an error.
    #[test]
    fn test_advance_pruning_error() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 50);

            let mut diff = UnmerkleizedBatch::new(&base);
            let result = diff.advance_pruning(Position::new(999));
            assert!(
                matches!(result, Err(Error::InvalidPosition(_))),
                "expected InvalidPosition, got {result:?}"
            );
        });
    }

    /// After advance_pruning(50), update_leaf_digest at position 40 should fail.
    #[test]
    fn test_update_leaf_respects_logical_prune_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let base = build_reference(&mut hasher, 100);

            let mut diff = UnmerkleizedBatch::new(&base);
            diff.advance_pruning(Position::new(50)).unwrap();

            // Update at location 10 (position < 50) should fail.
            let result = diff.update_leaf_digest(Location::new_unchecked(10), Sha256::fill(0xFF));
            assert!(
                matches!(result, Err(Error::ElementPruned(_))),
                "expected ElementPruned, got {result:?}"
            );
        });
    }
}
