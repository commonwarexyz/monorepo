//! Shared batch infrastructure for Merkle-family data structures.
//!
//! A [`Batch`] borrows a parent structure immutably and records mutations (appends and leaf
//! updates) without modifying the parent. Multiple batches can coexist on the same parent,
//! and batches can be stacked (Base <- A <- B <- ...) to arbitrary depth.
//!
//! # Lifecycle
//!
//! ```text
//! Base ────borrow────> UnmerkleizedBatch  (accumulate mutations)
//!                            |
//!                       merkleize()       (family-specific)
//!                            |
//!                            v
//!                      MerkleizedBatch    (has root, supports proofs)
//!                            |
//!                       finalize()
//!                            |
//!                            v
//!                        Changeset        (owned delta, no borrow)
//!                            |
//!                      base.apply(cs)
//!                            |
//!                            v
//!                          Base           (updated in place)
//! ```
//!
//! # Type aliases
//!
//! - [`UnmerkleizedBatch`] -- builder phase: add, update leaves (each consumes and returns self).
//! - [`MerkleizedBatch`]   -- immutable phase: root is computed, proofs available.
//! - [`Changeset`]         -- owned delta that can be applied to the base.
//!
//! Each Merkle family (MMR, MMB) re-exports these with the family type parameter fixed and
//! supplies family-specific `add`, `update_leaf`, and `merkleize`.
//!
//! # Example (MMR)
//!
//! ```ignore
//! let mut hasher = StandardHasher::<Sha256>::new();
//! let mut mmr = Mmr::new(&mut hasher);
//!
//! // Build a batch of mutations.
//! let changeset = mmr.new_batch()
//!     .add(&mut hasher, b"leaf-0")
//!     .add(&mut hasher, b"leaf-1")
//!     .merkleize(&mut hasher)
//!     .finalize();
//!
//! // Apply the changeset back to the base.
//! mmr.apply(changeset).unwrap();
//! ```

use crate::merkle::{
    hasher::Hasher, path, proof::Proof, Error, Family, Location, Position, Readable,
};
use alloc::{
    collections::{BTreeMap, BTreeSet},
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
// State type-state
// ---------------------------------------------------------------------------

mod private {
    pub trait Sealed {}
}

/// Trait for valid batch state types.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {}

/// Marker type for a batch whose root digest has been computed.
#[derive(Clone, Copy, Debug)]
pub struct Clean<D: Digest> {
    /// The root digest after this batch has been applied.
    pub root: D,
}

impl<D: Digest> private::Sealed for Clean<D> {}
impl<D: Digest> State<D> for Clean<D> {}

/// Marker type for an unmerkleized batch (root digest not yet computed).
#[derive(Clone, Debug)]
pub struct Dirty<F: Family> {
    /// Internal nodes that need to have their digests recomputed.
    /// Each entry is (node_pos, height).
    dirty_nodes: BTreeSet<(Position<F>, u32)>,
}

impl<F: Family> Default for Dirty<F> {
    fn default() -> Self {
        Self {
            dirty_nodes: BTreeSet::new(),
        }
    }
}

impl<F: Family> Dirty<F> {
    /// Insert a dirty node. Returns true if newly inserted.
    pub fn insert(&mut self, pos: Position<F>, height: u32) -> bool {
        self.dirty_nodes.insert((pos, height))
    }

    /// Take all dirty nodes sorted by ascending height (bottom-up for merkleize).
    pub fn take_sorted_by_height(&mut self) -> Vec<(Position<F>, u32)> {
        let mut v: Vec<_> = core::mem::take(&mut self.dirty_nodes).into_iter().collect();
        v.sort_by_key(|a| a.1);
        v
    }
}

impl<F: Family> private::Sealed for Dirty<F> {}
impl<F: Family, D: Digest> State<D> for Dirty<F> {}

// ---------------------------------------------------------------------------
// Batch
// ---------------------------------------------------------------------------

/// A batch of mutations against a parent Merkle structure.
///
/// The batch borrows the parent immutably and records appends and overwrites.
/// Multiple batches can coexist on the same parent, and batches can be stacked
/// (Base <- A <- B) to arbitrary depth.
pub struct Batch<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>, S: State<D>> {
    /// The parent structure.
    pub(crate) parent: &'a P,
    /// Nodes appended by this batch.
    pub(crate) appended: Vec<D>,
    /// Overwritten nodes at positions < parent.size().
    pub(crate) overwrites: BTreeMap<Position<F>, D>,
    /// Type-state: Dirty (mutable, no root) or Clean (immutable, has root).
    pub(crate) state: S,
    /// Thread pool for parallel merkleization.
    #[cfg(feature = "std")]
    pub(crate) pool: Option<ThreadPool>,
}

/// A batch whose root digest has not been computed.
pub type UnmerkleizedBatch<'a, F, D, P> = Batch<'a, F, D, P, Dirty<F>>;

/// A batch whose root digest has been computed.
pub type MerkleizedBatch<'a, F, D, P> = Batch<'a, F, D, P, Clean<D>>;

impl<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>, S: State<D>>
    Batch<'a, F, D, P, S>
{
    /// The total number of nodes visible through this batch.
    pub fn size(&self) -> Position<F> {
        Position::new(*self.parent.size() + self.appended.len() as u64)
    }

    /// The number of leaves visible through this batch.
    pub fn leaves(&self) -> crate::merkle::Location<F> {
        crate::merkle::Location::try_from(self.size()).expect("invalid size")
    }

    /// Resolve a node: overwrites -> appended -> parent.
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
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

    /// Store a digest at the given position.
    pub(crate) fn store_node(&mut self, pos: Position<F>, digest: D) {
        if pos >= self.parent.size() {
            let index = (*pos - *self.parent.size()) as usize;
            self.appended[index] = digest;
        } else {
            self.overwrites.insert(pos, digest);
        }
    }
}

impl<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>> UnmerkleizedBatch<'a, F, D, P> {
    /// Create a new batch borrowing `parent` immutably.
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

    /// Mark ancestors of the leaf at `loc` as dirty up to its peak.
    ///
    /// Walks from peak to leaf (top-down) using [`path::Iterator`], then inserts dirty markers
    /// bottom-up so that an early exit is possible when hitting a node that was already
    /// dirtied by a prior `update_leaf`.
    pub(crate) fn mark_dirty(&mut self, loc: Location<F>) {
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
                if !self.state.insert(parent_pos, h) {
                    break;
                }
            }
            return;
        }

        panic!("leaf {loc} not found (size: {})", self.size());
    }

    /// Batch update multiple leaf digests.
    #[cfg(any(feature = "std", test))]
    pub fn update_leaf_batched(mut self, updates: &[(Location<F>, D)]) -> Result<Self, Error<F>> {
        let leaves = self.leaves();
        let prune_boundary = self.parent.pruned_to_pos();
        for (loc, _) in updates {
            if *loc >= leaves {
                return Err(Error::LeafOutOfBounds(*loc));
            }
            let pos = Position::try_from(*loc)?;
            if pos < prune_boundary {
                return Err(Error::ElementPruned(pos));
            }
        }
        for (loc, digest) in updates {
            let pos = Position::try_from(*loc).unwrap();
            self.store_node(pos, *digest);
            self.mark_dirty(*loc);
        }
        Ok(self)
    }

    /// Compute digests for all dirty internal nodes, using the pool for parallelism when
    /// available and beneficial. Uses [`Family::children`] to locate each node's children.
    pub fn merkleize_dirty(&mut self, hasher: &impl Hasher<F, Digest = D>) {
        let dirty = self.state.take_sorted_by_height();

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
    }

    /// Compute digests for dirty internal nodes, bottom-up by height.
    fn merkleize_serial(
        &mut self,
        hasher: &impl Hasher<F, Digest = D>,
        dirty: &[(Position<F>, u32)],
    ) {
        for &(pos, height) in dirty {
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
        dirty: &[(Position<F>, u32)],
    ) {
        let mut same_height = Vec::new();
        let mut current_height = dirty.first().map_or(1, |&(_, h)| h);
        for (i, &(pos, height)) in dirty.iter().enumerate() {
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
    /// Add a pre-computed leaf digest.
    pub fn add_leaf_digest(mut self, digest: D) -> Self {
        let parents: Vec<u32> = F::parent_heights(self.size()).collect();
        self.appended.push(digest);

        for height in parents {
            let pos = self.size();
            self.appended.push(D::EMPTY);
            self.state.insert(pos, height);
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
        let pos = Position::try_from(loc)?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
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
        let pos = Position::try_from(loc)?;
        if pos < self.parent.pruned_to_pos() {
            return Err(Error::ElementPruned(pos));
        }
        if F::position_to_location(pos).is_none() {
            return Err(Error::NonLeaf(pos));
        }
        self.store_node(pos, digest);
        self.mark_dirty(loc);
        Ok(self)
    }

    /// Consume this batch and produce an immutable [`MerkleizedBatch`] with computed root.
    pub fn merkleize(
        mut self,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> MerkleizedBatch<'a, F, D, P> {
        self.merkleize_dirty(hasher);

        let leaves = self.leaves();
        let peaks: Vec<D> = F::peaks(self.size())
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
}

impl<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>> Readable
    for MerkleizedBatch<'a, F, D, P>
{
    type Family = F;
    type Digest = D;
    type Error = Error<F>;

    fn size(&self) -> Position<F> {
        self.size()
    }

    fn get_node(&self, pos: Position<F>) -> Option<D> {
        self.get_node(pos)
    }

    fn root(&self) -> D {
        self.state.root
    }

    fn pruned_to_pos(&self) -> Position<F> {
        self.parent.pruned_to_pos()
    }

    fn proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid() {
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
            |pos| self.get_node(pos),
            Error::ElementPruned,
        )
    }
}

impl<'a, F: Family, D: Digest, P: Readable<Family = F, Digest = D>> MerkleizedBatch<'a, F, D, P> {
    /// Access the parent structure.
    #[cfg(feature = "std")]
    pub(crate) const fn parent(&self) -> &P {
        self.parent
    }

    /// Access the thread pool.
    #[cfg(feature = "std")]
    pub fn pool(&self) -> Option<ThreadPool> {
        self.pool.clone()
    }

    /// Create a child batch on top of this merkleized batch.
    pub fn new_batch(&self) -> UnmerkleizedBatch<'_, F, D, Self> {
        let batch = UnmerkleizedBatch::new(self);
        #[cfg(feature = "std")]
        let batch = batch.with_pool(self.pool.clone());
        batch
    }

    /// Convert back to a dirty batch for further mutations.
    pub fn into_dirty(self) -> UnmerkleizedBatch<'a, F, D, P> {
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

// ---------------------------------------------------------------------------
// Batch Chain and Finalize
// ---------------------------------------------------------------------------

/// Information needed to flatten a chain of batches into a single [`Changeset`].
pub trait BatchChainInfo<F: Family>: Send + Sync {
    /// The digest type used by this structure.
    type Digest: Digest;

    /// Number of nodes in the original structure that the batch chain was forked
    /// from. This is constant through the entire chain.
    fn base_size(&self) -> Position<F>;

    /// Collect all overwrites that target nodes in the original structure
    /// (i.e. positions < `base_size()`), walking from the deepest
    /// ancestor to the current batch. Later batches overwrite earlier ones.
    fn collect_overwrites(&self, into: &mut BTreeMap<Position<F>, Self::Digest>);
}

impl<
        'a,
        F: Family,
        D: Digest,
        P: Readable<Family = F, Digest = D> + BatchChainInfo<F, Digest = D>,
        S: State<D>,
    > BatchChainInfo<F> for Batch<'a, F, D, P, S>
{
    type Digest = D;

    fn base_size(&self) -> Position<F> {
        self.parent.base_size()
    }

    fn collect_overwrites(&self, into: &mut BTreeMap<Position<F>, D>) {
        self.parent.collect_overwrites(into);
        let base_size = self.base_size();
        for (pos, d) in &self.overwrites {
            if *pos < base_size {
                into.insert(*pos, *d);
            }
        }
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

impl<
        'a,
        F: Family,
        D: Digest,
        P: Readable<Family = F, Digest = D> + BatchChainInfo<F, Digest = D>,
    > MerkleizedBatch<'a, F, D, P>
{
    /// Flatten this batch chain into a single [`Changeset`] relative to the
    /// ultimate base structure.
    pub fn finalize(self) -> Changeset<F, D> {
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
                let changeset = batch.merkleize(&hasher).finalize();
                let mut result = base.clone();
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

    fn into_dirty_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let mut batch = base.new_batch();
            for i in 50u64..55 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let mut dirty = batch.merkleize(&hasher).into_dirty();
            for i in 55u64..60 {
                let element = hasher.digest(&i.to_be_bytes());
                dirty = dirty.add(&hasher, &element);
            }
            let reference = build_reference::<F>(&hasher, 60);
            assert_eq!(dirty.merkleize(&hasher).root(), *reference.root());
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
            let mut reference = base.clone();
            let cs = reference
                .new_batch()
                .update_leaf(&hasher, Location::new(5), element)
                .unwrap()
                .merkleize(&hasher)
                .finalize();
            reference.apply(cs).unwrap();
            assert_eq!(m.root(), *reference.root());
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
    fn mmr_into_dirty_roundtrip() {
        into_dirty_roundtrip::<crate::mmr::Family>();
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
    fn mmb_into_dirty_roundtrip() {
        into_dirty_roundtrip::<crate::mmb::Family>();
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
}
