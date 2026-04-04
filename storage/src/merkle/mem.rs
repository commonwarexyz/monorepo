//! Generic in-memory Merkle structure, parameterized by [`Family`].
//!
//! Both MMR and MMB share the same node storage, pruning, root computation, and proof logic.
//! This module provides the unified [`Mem`] struct; per-family modules re-export it as
//! `mmr::mem::Mmr` and `mmb::mem::Mmb` via type aliases.
//!
//! Internally, the structure's data is behind an [`Arc`] so that
//! [`new_batch`](Mem::new_batch) shares it with the batch layer without copying. Mutating
//! methods ([`apply_batch`](Mem::apply_batch), [`prune`](Mem::prune), etc.) use `Arc::make_mut`: this is
//! in-place when no outstanding batch references the data, but triggers an O(N) copy-on-write
//! if any batch is still alive.

use crate::merkle::{
    batch, hasher::Hasher, proof as merkle_proof, Error, Family, Location, Position, Proof,
    Readable,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Configuration for initializing a [`Mem`].
pub struct Config<F: Family, D: Digest> {
    /// The retained nodes.
    pub nodes: Vec<D>,

    /// The leaf location up to which pruning has been performed, or 0 if never pruned.
    pub pruning_boundary: Location<F>,

    /// The pinned nodes, in the order expected by [`Family::nodes_to_pin`].
    pub pinned_nodes: Vec<D>,
}

/// The shared, reference-counted data behind a [`Mem`].
///
/// Separated so that `Mem::clone()` is a refcount bump. Mutation goes through
/// `Arc::make_mut`, which is in-place when the refcount is 1 and COW-copies otherwise.
#[derive(Clone, Debug)]
struct MemInner<F: Family, D: Digest> {
    /// The retained nodes, starting at `pruning_boundary`.
    nodes: VecDeque<D>,

    /// The highest position for which pruning has been performed, or 0 if never pruned.
    ///
    /// # Invariant
    ///
    /// This is always leaf-aligned (the position corresponding to some `Location`).
    pruning_boundary: Position<F>,

    /// Auxiliary map from node position to the digest of any pinned node.
    pinned_nodes: BTreeMap<Position<F>, D>,

    /// The root digest.
    root: D,
}

impl<F: Family, D: Digest> MemInner<F, D> {
    fn pos_to_index(&self, pos: Position<F>) -> usize {
        *pos.checked_sub(*self.pruning_boundary).unwrap() as usize
    }
}

/// A basic, `no_std`-compatible Merkle structure where all nodes are stored in-memory.
///
/// Nodes are either _retained_, _pruned_, or _pinned_. Retained nodes are stored in the main
/// deque. Pruned nodes precede `pruning_boundary` and are no longer stored unless they are still
/// required for root computation or proof generation, in which case they are kept in
/// `pinned_nodes`.
///
/// The structure is always merkleized (its root is always computed). Mutations go through the
/// batch API: create an [`UnmerkleizedBatch`](batch::UnmerkleizedBatch) via [`Self::new_batch`],
/// accumulate changes, merkleize, then apply the result via [`Self::apply_batch`].
#[derive(Clone, Debug)]
pub struct Mem<F: Family, D: Digest> {
    inner: Arc<MemInner<F, D>>,
}

impl<F: Family, D: Digest> Mem<F, D> {
    /// Create a new, empty structure.
    pub fn new(hasher: &impl Hasher<F, Digest = D>) -> Self {
        let root = hasher.root(Location::new(0), core::iter::empty::<&D>());
        Self {
            inner: Arc::new(MemInner {
                nodes: VecDeque::new(),
                pruning_boundary: Position::new(0),
                pinned_nodes: BTreeMap::new(),
                root,
            }),
        }
    }

    /// Return a [`Mem`] initialized with the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPinnedNodes`] if the number of pinned nodes doesn't match the
    /// expected count for `config.pruning_boundary`.
    ///
    /// Returns [`Error::InvalidSize`] if the resulting size is invalid.
    pub fn init(
        config: Config<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Result<Self, Error<F>> {
        let pruning_boundary = Position::try_from(config.pruning_boundary)?;

        let Some(size) = pruning_boundary.checked_add(config.nodes.len() as u64) else {
            return Err(Error::InvalidSize(u64::MAX));
        };
        if !size.is_valid_size() {
            return Err(Error::InvalidSize(*size));
        }

        let expected_pinned_positions: Vec<_> = F::nodes_to_pin(config.pruning_boundary).collect();
        if config.pinned_nodes.len() != expected_pinned_positions.len() {
            return Err(Error::InvalidPinnedNodes);
        }

        let pinned_nodes = expected_pinned_positions
            .into_iter()
            .zip(config.pinned_nodes)
            .collect();
        let nodes = VecDeque::from(config.nodes);
        let root = Self::compute_root(hasher, &nodes, &pinned_nodes, pruning_boundary);

        Ok(Self {
            inner: Arc::new(MemInner {
                nodes,
                pruning_boundary,
                pinned_nodes,
                root,
            }),
        })
    }

    /// Re-initialize with the given nodes, pruning boundary, and pinned nodes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPinnedNodes`] if the provided pinned node count is invalid for the
    /// given state.
    ///
    /// Returns [`Error::LocationOverflow`] if `pruning_boundary` exceeds [`Family::MAX_LEAVES`].
    pub fn from_components(
        hasher: &impl Hasher<F, Digest = D>,
        nodes: Vec<D>,
        pruning_boundary: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error<F>> {
        Self::init(
            Config {
                nodes,
                pruning_boundary,
                pinned_nodes,
            },
            hasher,
        )
    }

    /// Build a pruned structure that retains nodes above the prune boundary.
    ///
    /// Like `from_components` but also accepts retained nodes (stored in the
    /// `nodes` deque). Used by the grafted MMR which has no disk fallback.
    #[cfg(feature = "std")]
    pub(crate) fn from_pruned_with_retained(
        root: D,
        pruning_boundary: Position<F>,
        pinned_nodes: BTreeMap<Position<F>, D>,
        retained_nodes: Vec<D>,
    ) -> Self {
        Self {
            inner: Arc::new(MemInner {
                nodes: VecDeque::from(retained_nodes),
                pruning_boundary,
                pinned_nodes,
                root,
            }),
        }
    }

    /// Compute the root digest from the current peaks.
    pub(crate) fn compute_root(
        hasher: &impl Hasher<F, Digest = D>,
        nodes: &VecDeque<D>,
        pinned_nodes: &BTreeMap<Position<F>, D>,
        pruning_boundary: Position<F>,
    ) -> D {
        let size = Position::new(nodes.len() as u64 + *pruning_boundary);
        let leaves = Location::try_from(size).expect("invalid merkle size");
        let get_node = |pos: Position<F>| -> &D {
            if pos < pruning_boundary {
                return pinned_nodes
                    .get(&pos)
                    .expect("requested node is pruned and not pinned");
            }
            let index = (*pos - *pruning_boundary) as usize;
            &nodes[index]
        };
        let peaks = F::peaks(size).map(|(p, _)| get_node(p));
        hasher.root(leaves, peaks)
    }

    /// Return the total number of nodes, irrespective of any pruning.
    pub fn size(&self) -> Position<F> {
        Position::new(self.inner.nodes.len() as u64 + *self.inner.pruning_boundary)
    }

    /// Return the total number of leaves.
    pub fn leaves(&self) -> Location<F> {
        Location::try_from(self.size()).expect("invalid merkle size")
    }

    /// Returns `[start, end)` where `start` is the oldest retained leaf and `end` is the total
    /// leaf count.
    pub fn bounds(&self) -> Range<Location<F>> {
        Location::try_from(self.inner.pruning_boundary).expect("valid pruning_boundary")
            ..self.leaves()
    }

    /// Return a new iterator over the peaks.
    pub fn peak_iterator(&self) -> impl Iterator<Item = (Position<F>, u32)> {
        F::peaks(self.size())
    }

    /// Get the root digest.
    pub fn root(&self) -> &D {
        &self.inner.root
    }

    /// Return the requested node if it is either retained or present in the pinned_nodes map, and
    /// panic otherwise.
    ///
    /// # Panics
    ///
    /// Panics if the requested node does not exist.
    pub(crate) fn get_node_unchecked(&self, pos: Position<F>) -> &D {
        if pos < self.inner.pruning_boundary {
            return self
                .inner
                .pinned_nodes
                .get(&pos)
                .expect("requested node is pruned and not pinned");
        }

        &self.inner.nodes[self.pos_to_index(pos)]
    }

    /// Return the index of the element in the current nodes vector given its position.
    ///
    /// # Panics
    ///
    /// Panics if `pos` precedes the oldest retained position.
    fn pos_to_index(&self, pos: Position<F>) -> usize {
        assert!(
            pos >= self.inner.pruning_boundary,
            "pos precedes oldest retained position"
        );
        self.inner.pos_to_index(pos)
    }

    /// Return the requested node or `None` if it is not stored.
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
        if pos < self.inner.pruning_boundary {
            return self.inner.pinned_nodes.get(&pos).copied();
        }

        self.inner.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Get the nodes (position + digest) that need to be pinned when pruned to `prune_loc`.
    pub(crate) fn nodes_to_pin(&self, prune_loc: Location<F>) -> BTreeMap<Position<F>, D> {
        F::nodes_to_pin(prune_loc)
            .map(|pos| (pos, *self.get_node_unchecked(pos)))
            .collect()
    }

    /// Prune all nodes up to but not including the given leaf location, and pin the nodes still
    /// required for root computation and proof generation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocationOverflow`] if `loc` exceeds [`Family::MAX_LEAVES`].
    /// Returns [`Error::LeafOutOfBounds`] if `loc` exceeds the current leaf count.
    pub fn prune(&mut self, loc: Location<F>) -> Result<(), Error<F>> {
        if loc > self.leaves() {
            return Err(Error::LeafOutOfBounds(loc));
        }

        let pos = Position::try_from(loc)?;
        if pos <= self.inner.pruning_boundary {
            return Ok(());
        }

        self.prune_to_loc(loc);
        Ok(())
    }

    /// Prune all retained nodes.
    pub fn prune_all(&mut self) {
        if !self.inner.nodes.is_empty() {
            self.prune_to_loc(self.leaves());
        }
    }

    /// Location-based pruning.
    fn prune_to_loc(&mut self, loc: Location<F>) {
        let pinned = self.nodes_to_pin(loc);
        let pos = Position::try_from(loc).expect("valid location");
        let retained_nodes = self.pos_to_index(pos);
        let inner = Arc::make_mut(&mut self.inner);
        inner.pinned_nodes = pinned;
        inner.nodes.drain(0..retained_nodes);
        inner.pruning_boundary = pos;
    }

    /// Return an inclusion proof for the element at location `loc`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LocationOverflow`] if `loc` exceeds the valid range.
    /// Returns [`Error::LeafOutOfBounds`] if `loc` >= [`Self::leaves()`].
    /// Returns [`Error::ElementPruned`] if a required node is missing.
    pub fn proof(
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

    /// Return an inclusion proof for all elements within the provided `range` of locations.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Empty`] if the range is empty.
    /// Returns [`Error::LocationOverflow`] if any location exceeds the valid range.
    /// Returns [`Error::RangeOutOfBounds`] if `range.end` > [`Self::leaves()`].
    /// Returns [`Error::ElementPruned`] if a required node is missing.
    pub fn range_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        range: Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        merkle_proof::build_range_proof(
            hasher,
            self.leaves(),
            range,
            |pos| self.get_node(pos),
            Error::ElementPruned,
        )
    }

    /// Get the digests of nodes that need to be pinned at the provided pruning boundary.
    #[cfg(test)]
    pub(crate) fn node_digests_to_pin(&self, prune_loc: Location<F>) -> Vec<D> {
        F::nodes_to_pin(prune_loc)
            .map(|pos| *self.get_node_unchecked(pos))
            .collect()
    }

    /// Pin extra nodes. It's up to the caller to ensure this set is valid.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: BTreeMap<Position<F>, D>) {
        let inner = Arc::make_mut(&mut self.inner);
        for (pos, node) in pinned_nodes {
            inner.pinned_nodes.insert(pos, node);
        }
    }

    /// Truncate the structure to a smaller valid size, discarding all nodes beyond that size.
    /// Recomputes the root after truncation.
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    pub(crate) fn truncate(&mut self, new_size: Position<F>, hasher: &impl Hasher<F, Digest = D>) {
        debug_assert!(new_size.is_valid_size());
        debug_assert!(new_size >= self.inner.pruning_boundary);
        let keep = (*new_size - *self.inner.pruning_boundary) as usize;
        let inner = Arc::make_mut(&mut self.inner);
        inner.nodes.truncate(keep);
        inner.root = Self::compute_root(
            hasher,
            &inner.nodes,
            &inner.pinned_nodes,
            inner.pruning_boundary,
        );
    }

    /// Return the nodes this structure currently has pinned.
    #[cfg(test)]
    pub(crate) fn pinned_nodes(&self) -> BTreeMap<Position<F>, D> {
        self.inner.pinned_nodes.clone()
    }

    /// Create a new speculative batch with this structure as its parent.
    ///
    /// The batch holds a shared reference via `Arc`. If the batch (or any
    /// [`MerkleizedBatch`](batch::MerkleizedBatch) derived from it) is still alive when
    /// [`apply_batch`](Self::apply_batch) or another mutating method is called, the mutation
    /// triggers a copy-on-write.
    pub fn new_batch(&self) -> batch::UnmerkleizedBatch<F, D> {
        let root = batch::MerkleizedBatch::from_mem(self);
        root.new_batch()
    }

    /// Apply a merkleized batch. Already-committed ancestors are skipped automatically.
    pub fn apply_batch(&mut self, batch: &batch::MerkleizedBatch<F, D>) -> Result<(), Error<F>> {
        let skip_ancestors = if self.size() == batch.base_size {
            false
        } else if self.size() > batch.base_size && self.size() < batch.size() {
            true
        } else {
            return Err(Error::StaleBatch {
                expected: batch.base_size,
                actual: self.size(),
            });
        };

        let inner = Arc::make_mut(&mut self.inner);

        // Apply ancestor segments (root-to-tip order) if not already committed.
        if !skip_ancestors {
            for (appended, overwrites) in batch
                .ancestor_appended
                .iter()
                .zip(&batch.ancestor_overwrites)
            {
                for (&pos, &digest) in overwrites.iter() {
                    let index = inner.pos_to_index(pos);
                    inner.nodes[index] = digest;
                }
                for &digest in appended.iter() {
                    inner.nodes.push_back(digest);
                }
            }
        }

        // Apply this batch's own data.
        for (&pos, &digest) in batch.overwrites.iter() {
            let index = inner.pos_to_index(pos);
            inner.nodes[index] = digest;
        }
        for &digest in batch.appended.iter() {
            inner.nodes.push_back(digest);
        }

        inner.root = batch.root();
        Ok(())
    }
}

impl<F: Family, D: Digest> Readable for Mem<F, D> {
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
        *self.root()
    }

    fn pruning_boundary(&self) -> Location<F> {
        Location::try_from(self.inner.pruning_boundary).expect("valid pruning_boundary")
    }

    fn proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        self.proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        range: Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        self.range_proof(hasher, range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, Error, Location, Position};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_runtime::{deterministic, Runner as _, ThreadPooler};

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn build<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new(hasher);
        let batch = {
            let mut batch = mem.new_batch();
            for i in 0u64..n {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(hasher, &element);
            }
            batch.merkleize(hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();
        mem
    }

    fn build_raw<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new(hasher);
        let batch = {
            let mut batch = mem.new_batch();
            for i in 0u64..n {
                batch = batch.add(hasher, &i.to_be_bytes());
            }
            batch.merkleize(hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();
        mem
    }

    fn empty<F: Family>() {
        let hasher: H = Standard::new();
        let mem = Mem::<F, D>::new(&hasher);
        assert_eq!(*mem.leaves(), 0);
        assert_eq!(*mem.size(), 0);
        assert!(mem.bounds().is_empty());
    }

    fn validity<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut mem = Mem::<F, D>::new(&hasher);
            for i in 0u64..256 {
                assert!(
                    mem.size().is_valid_size(),
                    "size should be valid at step {i}"
                );
                let old_size = mem.size();
                let batch = mem
                    .new_batch()
                    .add(&hasher, &i.to_be_bytes())
                    .merkleize(&hasher, &mem);
                mem.apply_batch(&batch).unwrap();
                for size in *old_size + 1..*mem.size() {
                    assert!(
                        !Position::<F>::new(size).is_valid_size(),
                        "size {size} should not be valid"
                    );
                }
            }
        });
    }

    fn prune_all_then_append<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut mem = Mem::<F, D>::new(&hasher);
            for i in 0u64..256 {
                mem.prune_all();
                let batch = mem
                    .new_batch()
                    .add(&hasher, &i.to_be_bytes())
                    .merkleize(&hasher, &mem);
                mem.apply_batch(&batch).unwrap();
                assert_eq!(*mem.leaves(), i + 1);
            }
        });
    }

    fn range_proof_out_of_bounds<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mem = Mem::<F, D>::new(&hasher);
            assert!(matches!(
                mem.range_proof(&hasher, Location::new(0)..Location::new(1)),
                Err(Error::RangeOutOfBounds(_))
            ));
            let mem = build::<F>(&hasher, 10);
            assert!(matches!(
                mem.range_proof(&hasher, Location::new(5)..Location::new(11)),
                Err(Error::RangeOutOfBounds(_))
            ));
            assert!(mem
                .range_proof(&hasher, Location::new(5)..Location::new(10))
                .is_ok());
        });
    }

    fn proof_out_of_bounds<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mem = Mem::<F, D>::new(&hasher);
            assert!(matches!(
                mem.proof(&hasher, Location::new(0)),
                Err(Error::LeafOutOfBounds(_))
            ));
            let mem = build::<F>(&hasher, 10);
            assert!(matches!(
                mem.proof(&hasher, Location::new(10)),
                Err(Error::LeafOutOfBounds(_))
            ));
            assert!(mem.proof(&hasher, Location::new(9)).is_ok());
        });
    }

    fn init_pinned_nodes_validation<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();

            assert!(Mem::<F, D>::init(
                Config {
                    nodes: vec![],
                    pruning_boundary: Location::new(0),
                    pinned_nodes: vec![],
                },
                &hasher,
            )
            .is_ok());

            assert!(matches!(
                Mem::<F, D>::init(
                    Config {
                        nodes: vec![],
                        pruning_boundary: Location::new(8),
                        pinned_nodes: vec![],
                    },
                    &hasher,
                ),
                Err(Error::InvalidPinnedNodes)
            ));

            assert!(matches!(
                Mem::<F, D>::init(
                    Config {
                        nodes: vec![],
                        pruning_boundary: Location::new(0),
                        pinned_nodes: vec![hasher.digest(b"dummy")],
                    },
                    &hasher,
                ),
                Err(Error::InvalidPinnedNodes)
            ));

            let mem = build::<F>(&hasher, 50);
            let prune_loc = Location::<F>::new(25);
            let pinned_nodes = mem.node_digests_to_pin(prune_loc);
            assert!(Mem::<F, D>::init(
                Config {
                    nodes: vec![],
                    pruning_boundary: prune_loc,
                    pinned_nodes,
                },
                &hasher,
            )
            .is_ok());
        });
    }

    fn root_stable_under_pruning<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut reference = Mem::<F, D>::new(&hasher);
            let mut pruned = Mem::<F, D>::new(&hasher);
            for i in 0u64..200 {
                let element = hasher.digest(&i.to_be_bytes());
                let cs = reference
                    .new_batch()
                    .add(&hasher, &element)
                    .merkleize(&hasher, &reference);
                reference.apply_batch(&cs).unwrap();
                let cs = pruned
                    .new_batch()
                    .add(&hasher, &element)
                    .merkleize(&hasher, &pruned);
                pruned.apply_batch(&cs).unwrap();
                pruned.prune_all();
                assert_eq!(pruned.root(), reference.root());
            }
        });
    }

    fn do_batch_update<F: Family>(
        hasher: &H,
        mut mem: Mem<F, D>,
        pool: Option<commonware_parallel::ThreadPool>,
    ) {
        let element = D::from(*b"01234567012345670123456701234567");
        let root = *mem.root();

        let batch = {
            let mut batch = mem.new_batch();
            if let Some(ref pool) = pool {
                batch = batch.with_pool(Some(pool.clone()));
            }
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                batch = batch
                    .update_leaf(hasher, Location::new(leaf), &element)
                    .unwrap();
            }
            batch.merkleize(hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();
        assert_ne!(*mem.root(), root);

        let batch = {
            let mut batch = mem.new_batch();
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                let element = hasher.digest(&leaf.to_be_bytes());
                batch = batch
                    .update_leaf(hasher, Location::new(leaf), &element)
                    .unwrap();
            }
            batch.merkleize(hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();
        assert_eq!(*mem.root(), root);
    }

    fn batch_update_leaf<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mem = build::<F>(&hasher, 200);
            do_batch_update(&hasher, mem, None);
        });
    }

    fn batch_parallel_update_leaf<F: Family>() {
        let executor = commonware_runtime::tokio::Runner::default();
        executor.start(|ctx| async move {
            let hasher: H = Standard::new();
            let mem = build::<F>(&hasher, 200);
            let pool = ctx
                .create_thread_pool(commonware_utils::NZUsize!(4))
                .unwrap();
            do_batch_update(&hasher, mem, Some(pool));
        });
    }

    fn root_changes_with_each_append<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = Mem::<F, D>::new(&hasher);
        let mut prev_root = *mem.root();
        for i in 0u64..16 {
            let batch = {
                let batch = mem.new_batch();
                let batch = batch.add(&hasher, &i.to_be_bytes());
                batch.merkleize(&hasher, &mem)
            };
            mem.apply_batch(&batch).unwrap();
            assert_ne!(
                *mem.root(),
                prev_root,
                "root should change after append {i}"
            );
            prev_root = *mem.root();
        }
    }

    fn single_element_proof_roundtrip<F: Family>() {
        let hasher: H = Standard::new();
        let mem = build_raw::<F>(&hasher, 16);
        let root = *mem.root();
        for i in 0u64..16 {
            let proof = mem
                .proof(&hasher, Location::new(i))
                .unwrap_or_else(|e| panic!("loc={i}: {e:?}"));
            assert!(
                proof.verify_element_inclusion(&hasher, &i.to_be_bytes(), Location::new(i), &root),
                "loc={i}: proof should verify"
            );
        }
    }

    fn range_proof_roundtrip_exhaustive<F: Family>() {
        for n in 1u64..=24 {
            let hasher: H = Standard::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = *mem.root();

            for start in 0..n {
                for end in start + 1..=n {
                    let range = Location::new(start)..Location::new(end);
                    let proof = mem
                        .range_proof(&hasher, range.clone())
                        .unwrap_or_else(|e| panic!("n={n}, range={start}..{end}: {e:?}"));
                    let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();

                    assert!(
                        proof.verify_range_inclusion(&hasher, &elements, range.start, &root),
                        "n={n}, range={start}..{end}: range proof should verify"
                    );
                }
            }
        }
    }

    fn root_with_repeated_pruning<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, 32);
        let root = *mem.root();

        for prune_leaf in 1..*mem.leaves() {
            let prune_loc = Location::new(prune_leaf);
            mem.prune(prune_loc).unwrap();
            assert_eq!(
                *mem.root(),
                root,
                "root changed after pruning to {prune_loc}"
            );
            assert_eq!(mem.bounds().start, prune_loc);
            assert!(
                mem.proof(&hasher, prune_loc).is_ok(),
                "boundary leaf {prune_loc} should remain provable"
            );
            assert!(
                mem.proof(&hasher, mem.leaves() - 1).is_ok(),
                "latest leaf should remain provable after pruning to {prune_loc}"
            );
        }

        mem.prune_all();
        assert_eq!(*mem.root(), root, "root changed after prune_all");
        assert!(mem.bounds().is_empty(), "prune_all should retain no leaves");
    }

    fn append_after_partial_prune<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build_raw::<F>(&hasher, 20);
        mem.prune(Location::new(7)).unwrap();

        let batch = {
            let mut batch = mem.new_batch();
            for i in 20u64..48 {
                batch = batch.add(&hasher, &i.to_be_bytes());
            }
            batch.merkleize(&hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();

        let root = *mem.root();
        for loc in *mem.bounds().start..*mem.leaves() {
            let proof = mem
                .proof(&hasher, Location::new(loc))
                .unwrap_or_else(|e| panic!("loc={loc}: {e:?}"));
            assert!(
                proof.verify_element_inclusion(
                    &hasher,
                    &loc.to_be_bytes(),
                    Location::new(loc),
                    &root
                ),
                "loc={loc}: proof should verify after append on pruned structure"
            );
        }
    }

    fn update_leaf<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build_raw::<F>(&hasher, 11);
        let root_before = *mem.root();

        let batch = {
            let batch = mem.new_batch();
            let batch = batch
                .update_leaf(&hasher, Location::new(5), b"updated-5")
                .unwrap();
            batch.merkleize(&hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();

        assert_ne!(*mem.root(), root_before, "root should change after update");
        assert_eq!(*mem.leaves(), 11);

        let proof = mem.proof(&hasher, Location::new(5)).unwrap();
        assert!(
            proof.verify_element_inclusion(&hasher, b"updated-5", Location::new(5), mem.root()),
            "updated leaf should verify with new data"
        );

        assert!(
            !proof.verify_element_inclusion(
                &hasher,
                &5u64.to_be_bytes(),
                Location::new(5),
                mem.root()
            ),
            "old data should not verify"
        );

        for i in [0u64, 3, 7, 10] {
            let p = mem.proof(&hasher, Location::new(i)).unwrap();
            assert!(
                p.verify_element_inclusion(&hasher, &i.to_be_bytes(), Location::new(i), mem.root()),
                "leaf {i} should still verify with original data"
            );
        }
    }

    fn update_leaf_every_position<F: Family>() {
        let n = 20u64;
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, n);

        for update_loc in 0..n {
            let batch = {
                let batch = mem.new_batch();
                let batch = batch
                    .update_leaf(&hasher, Location::new(update_loc), b"new-value")
                    .unwrap();
                batch.merkleize(&hasher, &mem)
            };
            mem.apply_batch(&batch).unwrap();

            let proof = mem.proof(&hasher, Location::new(update_loc)).unwrap();
            assert!(
                proof.verify_element_inclusion(
                    &hasher,
                    b"new-value",
                    Location::new(update_loc),
                    mem.root()
                ),
                "update at {update_loc} should verify"
            );
        }
    }

    fn update_leaf_errors<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, 10);

        {
            let batch = mem.new_batch();
            assert!(matches!(
                batch.update_leaf(&hasher, Location::new(10), b"x"),
                Err(Error::LeafOutOfBounds(_))
            ));
        }

        mem.prune(Location::new(5)).unwrap();
        {
            let batch = mem.new_batch();
            assert!(matches!(
                batch.update_leaf(&hasher, Location::new(3), b"x"),
                Err(Error::ElementPruned(_))
            ));
            let batch = mem.new_batch();
            assert!(batch.update_leaf(&hasher, Location::new(5), b"x").is_ok());
        }
    }

    fn update_leaf_with_append<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, 8);

        let batch = {
            let batch = mem.new_batch();
            let batch = batch
                .update_leaf(&hasher, Location::new(3), b"updated-3")
                .unwrap();
            let batch = batch.add(&hasher, &100u64.to_be_bytes());
            let batch = batch.add(&hasher, &101u64.to_be_bytes());
            batch.merkleize(&hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();

        assert_eq!(*mem.leaves(), 10);

        let proof = mem.proof(&hasher, Location::new(3)).unwrap();
        assert!(proof.verify_element_inclusion(
            &hasher,
            b"updated-3",
            Location::new(3),
            mem.root()
        ));

        let proof = mem.proof(&hasher, Location::new(8)).unwrap();
        assert!(proof.verify_element_inclusion(
            &hasher,
            &100u64.to_be_bytes(),
            Location::new(8),
            mem.root()
        ));
    }

    fn update_leaf_under_merge_parent<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, 2);
        let batch = {
            let batch = mem.new_batch();
            let batch = batch.add(&hasher, &2u64.to_be_bytes());
            let batch = batch
                .update_leaf(&hasher, Location::new(0), b"updated-0")
                .unwrap();
            batch.merkleize(&hasher, &mem)
        };
        mem.apply_batch(&batch).unwrap();

        let ref_hasher: H = Standard::new();
        let mut ref_mem = build::<F>(&ref_hasher, 2);
        let cs = {
            let batch = ref_mem.new_batch();
            let batch = batch.add(&ref_hasher, &2u64.to_be_bytes());
            batch.merkleize(&ref_hasher, &ref_mem)
        };
        ref_mem.apply_batch(&cs).unwrap();
        let cs = {
            let batch = ref_mem.new_batch();
            let batch = batch
                .update_leaf(&ref_hasher, Location::new(0), b"updated-0")
                .unwrap();
            batch.merkleize(&ref_hasher, &ref_mem)
        };
        ref_mem.apply_batch(&cs).unwrap();

        assert_eq!(*mem.root(), *ref_mem.root(), "roots must match");

        let proof = mem.proof(&hasher, Location::new(0)).unwrap();
        assert!(
            proof.verify_element_inclusion(&hasher, b"updated-0", Location::new(0), mem.root()),
            "updated leaf should verify"
        );
    }

    /// Prune to every valid boundary in structures of size 1..=max_n, then update_leaf +
    /// merkleize each retained leaf and verify its inclusion proof. This exercises the pinned
    /// nodes produced by `nodes_to_pin` under re-merkleization.
    fn update_leaf_after_prune<F: Family>() {
        let max_n = 20u64;
        let hasher: H = Standard::new();
        for n in 1..=max_n {
            for prune_to in 1..n {
                let mut mem = build_raw::<F>(&hasher, n);
                mem.prune(Location::new(prune_to)).unwrap();

                for update_loc in prune_to..n {
                    // Clone so each update starts from the same pruned state.
                    let mut m = mem.clone();
                    let batch = {
                        let batch = m.new_batch();
                        let batch = batch
                            .update_leaf(&hasher, Location::new(update_loc), b"new")
                            .unwrap();
                        batch.merkleize(&hasher, &m)
                    };
                    m.apply_batch(&batch).unwrap();

                    let proof = m.proof(&hasher, Location::new(update_loc)).unwrap();
                    assert!(
                        proof.verify_element_inclusion(
                            &hasher,
                            b"new",
                            Location::new(update_loc),
                            m.root()
                        ),
                        "n={n} prune={prune_to} update={update_loc}: proof should verify"
                    );
                }
            }
        }
    }

    // --- MMR tests ---

    #[test]
    fn mmr_empty() {
        empty::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_validity() {
        validity::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_prune_all_then_append() {
        prune_all_then_append::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_range_proof_oob() {
        range_proof_out_of_bounds::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_proof_oob() {
        proof_out_of_bounds::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_init_pinned_nodes() {
        init_pinned_nodes_validation::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_root_stable_under_pruning() {
        root_stable_under_pruning::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_batch_update_leaf() {
        batch_update_leaf::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_batch_parallel_update_leaf() {
        batch_parallel_update_leaf::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_root_changes_with_each_append() {
        root_changes_with_each_append::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_single_element_proof_roundtrip() {
        single_element_proof_roundtrip::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_range_proof_roundtrip_exhaustive() {
        range_proof_roundtrip_exhaustive::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_root_with_repeated_pruning() {
        root_with_repeated_pruning::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_append_after_partial_prune() {
        append_after_partial_prune::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf() {
        update_leaf::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_every_position() {
        update_leaf_every_position::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_errors() {
        update_leaf_errors::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_with_append() {
        update_leaf_with_append::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_under_merge_parent() {
        update_leaf_under_merge_parent::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_update_leaf_after_prune() {
        update_leaf_after_prune::<crate::mmr::Family>();
    }

    // --- MMB tests ---

    #[test]
    fn mmb_empty() {
        empty::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_validity() {
        validity::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_prune_all_then_append() {
        prune_all_then_append::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_range_proof_oob() {
        range_proof_out_of_bounds::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_proof_oob() {
        proof_out_of_bounds::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_init_pinned_nodes() {
        init_pinned_nodes_validation::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_root_stable_under_pruning() {
        root_stable_under_pruning::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_batch_update_leaf() {
        batch_update_leaf::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_batch_parallel_update_leaf() {
        batch_parallel_update_leaf::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_root_changes_with_each_append() {
        root_changes_with_each_append::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_single_element_proof_roundtrip() {
        single_element_proof_roundtrip::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_range_proof_roundtrip_exhaustive() {
        range_proof_roundtrip_exhaustive::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_root_with_repeated_pruning() {
        root_with_repeated_pruning::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_append_after_partial_prune() {
        append_after_partial_prune::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf() {
        update_leaf::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_every_position() {
        update_leaf_every_position::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_errors() {
        update_leaf_errors::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_with_append() {
        update_leaf_with_append::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_under_merge_parent() {
        update_leaf_under_merge_parent::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_update_leaf_after_prune() {
        update_leaf_after_prune::<crate::mmb::Family>();
    }
}
