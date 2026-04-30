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
//! let hasher = StandardHasher::<Sha256>::new();
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
    hasher::Hasher, mem::Mem, path, proof::Proof, Error, Family, Location, Position, Readable,
};
use alloc::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use commonware_cryptography::Digest;
use commonware_parallel::{Sequential, Strategy};
use core::ops::Range;

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
pub struct UnmerkleizedBatch<F: Family, D: Digest, S: Strategy = Sequential> {
    parent: Arc<MerkleizedBatch<F, D, S>>,
    appended: Vec<D>,
    overwrites: BTreeMap<Position<F>, D>,
    /// Dirty internal node positions bucketed by height. Outer index is height; inner Vec
    /// holds positions at that height in push order (monotonically increasing for
    /// `add_leaf_digest`; may contain duplicates from interleaved `mark_dirty` walks, deduped
    /// in `merkleize`). Avoids the BTreeSet insert cost and a final global sort.
    dirty_nodes: Vec<Vec<Position<F>>>,
}

impl<F: Family, D: Digest, S: Strategy> UnmerkleizedBatch<F, D, S> {
    /// Create a new batch from `parent`.
    pub const fn new(parent: Arc<MerkleizedBatch<F, D, S>>) -> Self {
        Self {
            parent,
            appended: Vec::new(),
            overwrites: BTreeMap::new(),
            dirty_nodes: Vec::new(),
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
        let heights = F::parent_heights(self.leaves());
        self.appended.push(digest);

        for height in heights {
            let pos = self.size();
            self.appended.push(D::EMPTY);
            push_dirty(&mut self.dirty_nodes, height, pos);
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
        // Each bucket accumulates positions in push order, which for `add_leaf_digest` is
        // already ascending; the stable `sort` is cheap on such near-sorted input. The dedup
        // then collapses any duplicates that slipped past `mark_dirty`'s last-entry check.
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
        let (ancestor_appended, ancestor_overwrites) = collect_ancestor_batches(&self.parent);

        let parent_size = self.parent.size();
        Arc::new(MerkleizedBatch {
            parent: Some(Arc::downgrade(&self.parent)),
            appended: Arc::new(self.appended),
            overwrites: Arc::new(self.overwrites),
            parent_size,
            base_size: self.parent.base_size,
            pruning_boundary: self.parent.pruning_boundary(),
            ancestor_appended,
            ancestor_overwrites,
            strategy: self.parent.strategy.clone(),
        })
    }

    /// Compute digests for one height's dirty nodes via the configured strategy.
    fn merkleize_bucket(
        &mut self,
        base: &Mem<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
        positions: &[Position<F>],
        height: u32,
    ) {
        let computed: Vec<(Position<F>, D)> = self.parent.strategy.map_init_collect_vec(
            positions,
            || hasher.clone(),
            |hasher, &pos| {
                let (left, right) = F::children(pos, height);
                let left_d = self.get_node(base, left).expect("left child missing");
                let right_d = self.get_node(base, right).expect("right child missing");
                let digest = hasher.node_digest(pos, &left_d, &right_d);
                (pos, digest)
            },
        );
        for (pos, digest) in computed {
            self.store_node(pos, digest);
        }
    }
}

/// Collect ancestor batch data by walking the parent + its Weak chain.
/// Returns (appended, overwrites) in root-to-tip order. Skips empty batches
/// (e.g. root batches from `from_mem`).
#[allow(clippy::type_complexity)]
fn collect_ancestor_batches<F: Family, D: Digest, S: Strategy>(
    parent: &Arc<MerkleizedBatch<F, D, S>>,
) -> (Vec<Arc<Vec<D>>>, Vec<Arc<BTreeMap<Position<F>, D>>>) {
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

// ---------------------------------------------------------------------------
// MerkleizedBatch
// ---------------------------------------------------------------------------

/// A speculative batch whose dirty Merkle nodes have been computed, in contrast to
/// [`UnmerkleizedBatch`].
#[derive(Debug)]
pub struct MerkleizedBatch<F: Family, D: Digest, S: Strategy = Sequential> {
    /// The parent batch in the chain, if any.
    parent: Option<Weak<Self>>,

    /// This batch's appended nodes only (not accumulated from ancestors).
    pub(crate) appended: Arc<Vec<D>>,

    /// This batch's overwrites only (not accumulated from ancestors).
    pub(crate) overwrites: Arc<BTreeMap<Position<F>, D>>,

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
    pub(crate) ancestor_overwrites: Vec<Arc<BTreeMap<Position<F>, D>>>,

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
            overwrites: Arc::new(BTreeMap::new()),
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

    fn mem_root<F: Family>(mem: &Mem<F, D>, hasher: &H) -> D {
        mem.root(hasher, 0).unwrap()
    }

    fn batch_root<F: Family>(base: &Mem<F, D>, batch: &MerkleizedBatch<F, D>, hasher: &H) -> D {
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
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
                &batch_root(&applied, &merkleized, &hasher),
                0,
            ));
        });
    }

    fn apply_batch<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
                    &batch_root(&applied, &mb, &hasher),
                    0,
                ));
            }
        });
    }

    fn update_leaf_digest_roundtrip<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
                &batch_root(&applied, &m, &hasher),
                0,
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
                &batch_root(&applied, &m, &hasher),
                0,
            ));
        });
    }

    fn empty_batch<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let base = build_reference::<F>(&hasher, 50);
            let base_root = mem_root(&base, &hasher);
            let m = base.new_batch().merkleize(&base, &hasher);
            assert_eq!(batch_root(&base, &m, &hasher), base_root);
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
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
            assert!(proof.verify_element_inclusion(&hasher, &element, loc, &expected_root, 0));
            assert!(matches!(
                applied.proof(&hasher, Location::new(0), 0),
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
            let hasher: H = Standard::new();
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
            let hasher: H = Standard::new();
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
