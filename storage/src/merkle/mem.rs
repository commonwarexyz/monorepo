//! Generic in-memory Merkle structure, parameterized by [`Family`].
//!
//! Both MMR and MMB share the same node storage, pruning, root computation, and proof logic.
//! This module provides the unified [`Mem`] struct; per-family modules re-export it as
//! `mmr::mem::Mmr` and `mmb::mem::Mmb` via type aliases.

use crate::merkle::{
    batch, hasher::Hasher, proof as merkle_proof, Error, Family, Location, Position, Proof,
    Readable,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
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

/// A basic, `no_std`-compatible Merkle structure where all nodes are stored in-memory.
///
/// Nodes are either _retained_, _pruned_, or _pinned_. Retained nodes are stored in the main deque.
/// Pruned nodes precede `pruning_boundary` and are no longer stored unless they are part of the
/// pruning-boundary pinned-node set, in which case they are kept in `pinned_nodes`.
///
/// Mutations go through the batch API: create an
/// [`UnmerkleizedBatch`](batch::UnmerkleizedBatch) via [`Self::new_batch`], accumulate changes,
/// merkleize, then apply the result via [`Self::apply_batch`]. Roots are computed explicitly with
/// [`Self::root`] from a caller-supplied `inactive_peaks` count, with the bagging policy carried
/// by the supplied [`Hasher`].
#[derive(Clone, Debug)]
pub struct Mem<F: Family, D: Digest> {
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
}

impl<F: Family, D: Digest> Default for Mem<F, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Family, D: Digest> Mem<F, D> {
    /// Create a new, empty structure.
    pub const fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            pruning_boundary: Position::new(0),
            pinned_nodes: BTreeMap::new(),
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
    pub fn init(config: Config<F, D>) -> Result<Self, Error<F>> {
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

        Ok(Self {
            nodes,
            pruning_boundary,
            pinned_nodes,
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
        nodes: Vec<D>,
        pruning_boundary: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error<F>> {
        Self::init(Config {
            nodes,
            pruning_boundary,
            pinned_nodes,
        })
    }

    /// Build a pruned structure that retains nodes above the prune boundary.
    ///
    /// Like `from_components` but also accepts retained nodes (stored in the
    /// `nodes` deque). Used by the grafted MMR which has no disk fallback.
    #[cfg(feature = "std")]
    pub(crate) fn from_pruned_with_retained(
        pruning_boundary: Position<F>,
        pinned_nodes: BTreeMap<Position<F>, D>,
        retained_nodes: Vec<D>,
    ) -> Self {
        Self {
            nodes: VecDeque::from(retained_nodes),
            pruning_boundary,
            pinned_nodes,
        }
    }

    /// Compute the root digest for this structure using `inactive_peaks` and the bagging carried by
    /// `hasher`.
    pub fn root(
        &self,
        hasher: &impl Hasher<F, Digest = D>,
        inactive_peaks: usize,
    ) -> Result<D, Error<F>> {
        let size = self.size();
        let leaves = Location::try_from(size).expect("invalid merkle size");
        let peaks: Vec<&D> = F::peaks(size)
            .map(|(p, _)| self.get_node_unchecked(p))
            .collect();
        hasher.root(leaves, inactive_peaks, peaks)
    }

    /// Return the total number of nodes, irrespective of any pruning.
    pub fn size(&self) -> Position<F> {
        Position::new(self.nodes.len() as u64 + *self.pruning_boundary)
    }

    /// Return the total number of leaves.
    pub fn leaves(&self) -> Location<F> {
        Location::try_from(self.size()).expect("invalid merkle size")
    }

    /// Returns `[start, end)` where `start` is the oldest retained leaf and `end` is the total
    /// leaf count.
    pub fn bounds(&self) -> Range<Location<F>> {
        Location::try_from(self.pruning_boundary).expect("valid pruning_boundary")..self.leaves()
    }

    /// Return a new iterator over the peaks.
    pub fn peak_iterator(&self) -> impl Iterator<Item = (Position<F>, u32)> {
        F::peaks(self.size())
    }

    /// Return the requested node if it is either retained or present in the pinned_nodes map, and
    /// panic otherwise.
    ///
    /// # Panics
    ///
    /// Panics if the requested node does not exist.
    pub(crate) fn get_node_unchecked(&self, pos: Position<F>) -> &D {
        if pos < self.pruning_boundary {
            return self
                .pinned_nodes
                .get(&pos)
                .expect("requested node is pruned and not pinned");
        }

        &self.nodes[self.pos_to_index(pos)]
    }

    /// Return the index of the element in the current nodes vector given its position.
    ///
    /// # Panics
    ///
    /// Panics if `pos` precedes the oldest retained position.
    fn pos_to_index(&self, pos: Position<F>) -> usize {
        assert!(
            pos >= self.pruning_boundary,
            "pos precedes oldest retained position"
        );
        (*pos - *self.pruning_boundary) as usize
    }

    /// Return the requested node or `None` if it is not stored.
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
        if pos < self.pruning_boundary {
            return self.pinned_nodes.get(&pos).copied();
        }

        self.nodes.get(self.pos_to_index(pos)).copied()
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
        if pos <= self.pruning_boundary {
            return Ok(());
        }

        self.prune_to_loc(loc);
        Ok(())
    }

    /// Prune all retained nodes.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            self.prune_to_loc(self.leaves());
        }
    }

    /// Location-based pruning.
    fn prune_to_loc(&mut self, loc: Location<F>) {
        let pinned = self.nodes_to_pin(loc);
        let pos = Position::try_from(loc).expect("valid location");
        let retained_nodes = self.pos_to_index(pos);
        self.pinned_nodes = pinned;
        self.nodes.drain(0..retained_nodes);
        self.pruning_boundary = pos;
    }

    /// Return an inclusion proof for the element at location `loc` using an explicit root spec.
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

    /// Return an inclusion proof for all elements within the provided `range` of locations
    /// using an explicit root spec.
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
        inactive_peaks: usize,
    ) -> Result<Proof<F, D>, Error<F>> {
        merkle_proof::build_range_proof(
            hasher,
            self.leaves(),
            inactive_peaks,
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
        for (pos, node) in pinned_nodes {
            self.pinned_nodes.insert(pos, node);
        }
    }

    /// Truncate the structure to a smaller valid size, discarding all nodes beyond that size.
    #[cfg(feature = "std")]
    #[allow(dead_code)]
    pub(crate) fn truncate(&mut self, new_size: Position<F>) {
        debug_assert!(new_size.is_valid_size());
        debug_assert!(new_size >= self.pruning_boundary);
        let keep = (*new_size - *self.pruning_boundary) as usize;
        self.nodes.truncate(keep);
    }

    /// Return the nodes this structure currently has pinned.
    #[cfg(test)]
    pub(crate) fn pinned_nodes(&self) -> BTreeMap<Position<F>, D> {
        self.pinned_nodes.clone()
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> batch::UnmerkleizedBatch<F, D> {
        let root = batch::MerkleizedBatch::from_mem(self);
        root.new_batch()
    }

    /// Create a new speculative batch backed by `strategy` for merkleization.
    pub fn new_batch_with_strategy<S: Strategy>(
        &self,
        strategy: S,
    ) -> batch::UnmerkleizedBatch<F, D, S> {
        let root = batch::MerkleizedBatch::from_mem_with_strategy(self, strategy);
        root.new_batch()
    }

    /// Apply a merkleized batch. Already-committed ancestors are skipped automatically.
    pub fn apply_batch<S: Strategy>(
        &mut self,
        batch: &batch::MerkleizedBatch<F, D, S>,
    ) -> Result<(), Error<F>> {
        let skip_ancestors = if self.size() == batch.base_size {
            false
        } else if self.size() > batch.base_size && self.size() < batch.size() {
            true
        } else if self.size() == batch.size() && batch.appended.is_empty() {
            // All ancestors committed and this batch has overwrites only (no appends).
            true
        } else {
            return Err(Error::StaleBatch {
                expected: batch.base_size,
                actual: self.size(),
            });
        };

        // Apply ancestor batches in root-to-tip order. Already-committed
        // batches (whose appended nodes are already in the Mem) are skipped
        // by tracking a running position through the ancestor chain.
        let mut batch_pos = *batch.base_size;
        for (appended, overwrites) in batch
            .ancestor_appended
            .iter()
            .zip(&batch.ancestor_overwrites)
        {
            batch_pos += appended.len() as u64;
            // Overwrite-only ancestors don't advance batch_pos, so they can't be
            // distinguished from their predecessor by size. Use strict < to
            // avoid skipping them at the boundary. Re-applying committed
            // overwrites is harmless (idempotent).
            let committed = if appended.is_empty() {
                skip_ancestors && batch_pos < *self.size()
            } else {
                skip_ancestors && batch_pos <= *self.size()
            };
            if committed {
                continue;
            }
            for (&pos, &digest) in overwrites.iter() {
                if pos < self.pruning_boundary {
                    continue;
                }
                let index = self.pos_to_index(pos);
                self.nodes[index] = digest;
            }
            for &digest in appended.iter() {
                self.nodes.push_back(digest);
            }
        }

        // Apply this batch's own data.
        for (&pos, &digest) in batch.overwrites.iter() {
            if skip_ancestors && pos < self.pruning_boundary {
                continue;
            }
            let index = self.pos_to_index(pos);
            self.nodes[index] = digest;
        }
        for &digest in batch.appended.iter() {
            self.nodes.push_back(digest);
        }

        // Detect missing ancestor data. If an uncommitted ancestor was dropped
        // before this batch was merkleized, its appended nodes are absent and the
        // Mem ends up smaller than expected. This does not catch dropped
        // overwrite-only ancestors (they don't change the size).
        if self.size() != batch.size() {
            return Err(Error::AncestorDropped {
                expected: batch.size(),
                actual: self.size(),
            });
        }

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

    fn pruning_boundary(&self) -> Location<F> {
        Location::try_from(self.pruning_boundary).expect("valid pruning_boundary")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::{hasher::Standard, Bagging, Error, Location, Position};
    use commonware_cryptography::{sha256, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner as _, ThreadPooler};
    use commonware_utils::NZUsize;

    type D = sha256::Digest;
    type H = Standard<Sha256>;

    fn plain_root<F: Family>(mem: &Mem<F, D>, hasher: &H) -> D {
        mem.root(hasher, 0).unwrap()
    }

    fn build<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
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

    fn build_raw<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new();
        let batch = {
            let mut batch = mem.new_batch();
            for i in 0u64..n {
                batch = batch.add(hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mem, hasher)
        };
        mem.apply_batch(&batch).unwrap();
        mem
    }

    fn empty<F: Family>() {
        let mem = Mem::<F, D>::new();
        assert_eq!(*mem.leaves(), 0);
        assert_eq!(*mem.size(), 0);
        assert!(mem.bounds().is_empty());
    }

    fn validity<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut mem = Mem::<F, D>::new();
            for i in 0u64..256 {
                assert!(
                    mem.size().is_valid_size(),
                    "size should be valid at step {i}"
                );
                let old_size = mem.size();
                let batch = mem
                    .new_batch()
                    .add(&hasher, &i.to_be_bytes())
                    .merkleize(&mem, &hasher);
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
            let mut mem = Mem::<F, D>::new();
            for i in 0u64..256 {
                mem.prune_all();
                let batch = mem
                    .new_batch()
                    .add(&hasher, &i.to_be_bytes())
                    .merkleize(&mem, &hasher);
                mem.apply_batch(&batch).unwrap();
                assert_eq!(*mem.leaves(), i + 1);
            }
        });
    }

    fn range_proof_out_of_bounds<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mem = Mem::<F, D>::new();
            assert!(matches!(
                mem.range_proof(&hasher, Location::new(0)..Location::new(1), 0),
                Err(Error::RangeOutOfBounds(_))
            ));
            let mem = build::<F>(&hasher, 10);
            assert!(matches!(
                mem.range_proof(&hasher, Location::new(5)..Location::new(11), 0),
                Err(Error::RangeOutOfBounds(_))
            ));
            assert!(mem
                .range_proof(&hasher, Location::new(5)..Location::new(10), 0)
                .is_ok());
        });
    }

    fn proof_out_of_bounds<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mem = Mem::<F, D>::new();
            assert!(matches!(
                mem.proof(&hasher, Location::new(0), 0),
                Err(Error::LeafOutOfBounds(_))
            ));
            let mem = build::<F>(&hasher, 10);
            assert!(matches!(
                mem.proof(&hasher, Location::new(10), 0),
                Err(Error::LeafOutOfBounds(_))
            ));
            assert!(mem.proof(&hasher, Location::new(9), 0).is_ok());
        });
    }

    fn init_pinned_nodes_validation<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();

            assert!(Mem::<F, D>::init(Config {
                nodes: vec![],
                pruning_boundary: Location::new(0),
                pinned_nodes: vec![],
            })
            .is_ok());

            assert!(matches!(
                Mem::<F, D>::init(Config {
                    nodes: vec![],
                    pruning_boundary: Location::new(8),
                    pinned_nodes: vec![],
                }),
                Err(Error::InvalidPinnedNodes)
            ));

            assert!(matches!(
                Mem::<F, D>::init(Config {
                    nodes: vec![],
                    pruning_boundary: Location::new(0),
                    pinned_nodes: vec![hasher.digest(b"dummy")],
                }),
                Err(Error::InvalidPinnedNodes)
            ));

            let mem = build::<F>(&hasher, 50);
            let prune_loc = Location::<F>::new(25);
            let pinned_nodes = mem.node_digests_to_pin(prune_loc);
            assert!(Mem::<F, D>::init(Config {
                nodes: vec![],
                pruning_boundary: prune_loc,
                pinned_nodes,
            })
            .is_ok());
        });
    }

    fn root_stable_under_pruning<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mut reference = Mem::<F, D>::new();
            let mut pruned = Mem::<F, D>::new();
            for i in 0u64..200 {
                let element = hasher.digest(&i.to_be_bytes());
                let cs = reference
                    .new_batch()
                    .add(&hasher, &element)
                    .merkleize(&reference, &hasher);
                reference.apply_batch(&cs).unwrap();
                let cs = pruned
                    .new_batch()
                    .add(&hasher, &element)
                    .merkleize(&pruned, &hasher);
                pruned.apply_batch(&cs).unwrap();
                pruned.prune_all();
                assert_eq!(
                    plain_root(&pruned, &hasher),
                    plain_root(&reference, &hasher)
                );
            }
        });
    }

    fn do_batch_update<F: Family, S: Strategy>(hasher: &H, mut mem: Mem<F, D>, strategy: S) {
        let element = D::from(*b"01234567012345670123456701234567");
        let root = plain_root(&mem, hasher);

        let batch = {
            let mut batch = mem.new_batch_with_strategy(strategy);
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                batch = batch
                    .update_leaf(hasher, Location::new(leaf), &element)
                    .unwrap();
            }
            batch.merkleize(&mem, hasher)
        };
        mem.apply_batch(&batch).unwrap();
        assert_ne!(plain_root(&mem, hasher), root);

        let batch = {
            let mut batch = mem.new_batch();
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                let element = hasher.digest(&leaf.to_be_bytes());
                batch = batch
                    .update_leaf(hasher, Location::new(leaf), &element)
                    .unwrap();
            }
            batch.merkleize(&mem, hasher)
        };
        mem.apply_batch(&batch).unwrap();
        assert_eq!(plain_root(&mem, hasher), root);
    }

    fn batch_update_leaf<F: Family>() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let hasher: H = Standard::new();
            let mem = build::<F>(&hasher, 200);
            do_batch_update(&hasher, mem, Sequential);
        });
    }

    fn batch_parallel_update_leaf<F: Family>() {
        let executor = commonware_runtime::tokio::Runner::default();
        executor.start(|ctx| async move {
            let hasher: H = Standard::new();
            let mem = build::<F>(&hasher, 200);
            let strategy = ctx.create_strategy(NZUsize!(4)).unwrap();
            do_batch_update(&hasher, mem, strategy);
        });
    }

    fn root_changes_with_each_append<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = Mem::<F, D>::new();
        let mut prev_root = plain_root(&mem, &hasher);
        for i in 0u64..16 {
            let batch = {
                let batch = mem.new_batch();
                let batch = batch.add(&hasher, &i.to_be_bytes());
                batch.merkleize(&mem, &hasher)
            };
            mem.apply_batch(&batch).unwrap();
            assert_ne!(
                plain_root(&mem, &hasher),
                prev_root,
                "root should change after append {i}"
            );
            prev_root = plain_root(&mem, &hasher);
        }
    }

    fn single_element_proof_roundtrip<F: Family>() {
        let hasher: H = Standard::new();
        let mem = build_raw::<F>(&hasher, 16);
        let root = plain_root(&mem, &hasher);
        for i in 0u64..16 {
            let proof = mem
                .proof(&hasher, Location::new(i), 0)
                .unwrap_or_else(|e| panic!("loc={i}: {e:?}"));
            assert!(
                proof.verify_element_inclusion(
                    &hasher,
                    &i.to_be_bytes(),
                    Location::new(i),
                    &root,
                    0
                ),
                "loc={i}: proof should verify"
            );
        }
    }

    fn range_proof_roundtrip_exhaustive<F: Family>() {
        for n in 1u64..=24 {
            let hasher: H = Standard::new();
            let mem = build_raw::<F>(&hasher, n);
            let root = plain_root(&mem, &hasher);

            for start in 0..n {
                for end in start + 1..=n {
                    let range = Location::new(start)..Location::new(end);
                    let proof = mem
                        .range_proof(&hasher, range.clone(), 0)
                        .unwrap_or_else(|e| panic!("n={n}, range={start}..{end}: {e:?}"));
                    let elements: Vec<_> = (start..end).map(|i| i.to_be_bytes()).collect();

                    assert!(
                        proof.verify_range_inclusion(&hasher, &elements, range.start, &root, 0),
                        "n={n}, range={start}..{end}: range proof should verify"
                    );
                }
            }
        }
    }

    fn root_with_repeated_pruning<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, 32);
        let root = plain_root(&mem, &hasher);

        for prune_leaf in 1..*mem.leaves() {
            let prune_loc = Location::new(prune_leaf);
            mem.prune(prune_loc).unwrap();
            assert_eq!(
                plain_root(&mem, &hasher),
                root,
                "root changed after pruning to {prune_loc}"
            );
            assert_eq!(mem.bounds().start, prune_loc);
            assert!(
                mem.proof(&hasher, prune_loc, 0).is_ok(),
                "boundary leaf {prune_loc} should remain provable"
            );
            assert!(
                mem.proof(&hasher, mem.leaves() - 1, 0).is_ok(),
                "latest leaf should remain provable after pruning to {prune_loc}"
            );
        }

        mem.prune_all();
        assert_eq!(
            plain_root(&mem, &hasher),
            root,
            "root changed after prune_all"
        );
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
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        let root = plain_root(&mem, &hasher);
        for loc in *mem.bounds().start..*mem.leaves() {
            let proof = mem
                .proof(&hasher, Location::new(loc), 0)
                .unwrap_or_else(|e| panic!("loc={loc}: {e:?}"));
            assert!(
                proof.verify_element_inclusion(
                    &hasher,
                    &loc.to_be_bytes(),
                    Location::new(loc),
                    &root,
                    0,
                ),
                "loc={loc}: proof should verify after append on pruned structure"
            );
        }
    }

    fn update_leaf<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build_raw::<F>(&hasher, 11);
        let root_before = plain_root(&mem, &hasher);

        let batch = {
            let batch = mem.new_batch();
            let batch = batch
                .update_leaf(&hasher, Location::new(5), b"updated-5")
                .unwrap();
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        assert_ne!(
            plain_root(&mem, &hasher),
            root_before,
            "root should change after update"
        );
        assert_eq!(*mem.leaves(), 11);

        let proof = mem.proof(&hasher, Location::new(5), 0).unwrap();
        assert!(
            proof.verify_element_inclusion(
                &hasher,
                b"updated-5",
                Location::new(5),
                &plain_root(&mem, &hasher),
                0,
            ),
            "updated leaf should verify with new data"
        );

        assert!(
            !proof.verify_element_inclusion(
                &hasher,
                &5u64.to_be_bytes(),
                Location::new(5),
                &plain_root(&mem, &hasher),
                0,
            ),
            "old data should not verify"
        );

        for i in [0u64, 3, 7, 10] {
            let p = mem.proof(&hasher, Location::new(i), 0).unwrap();
            assert!(
                p.verify_element_inclusion(
                    &hasher,
                    &i.to_be_bytes(),
                    Location::new(i),
                    &plain_root(&mem, &hasher),
                    0,
                ),
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
                batch.merkleize(&mem, &hasher)
            };
            mem.apply_batch(&batch).unwrap();

            let proof = mem.proof(&hasher, Location::new(update_loc), 0).unwrap();
            assert!(
                proof.verify_element_inclusion(
                    &hasher,
                    b"new-value",
                    Location::new(update_loc),
                    &plain_root(&mem, &hasher),
                    0,
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
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        assert_eq!(*mem.leaves(), 10);

        let proof = mem.proof(&hasher, Location::new(3), 0).unwrap();
        assert!(proof.verify_element_inclusion(
            &hasher,
            b"updated-3",
            Location::new(3),
            &plain_root(&mem, &hasher),
            0,
        ));

        let proof = mem.proof(&hasher, Location::new(8), 0).unwrap();
        assert!(proof.verify_element_inclusion(
            &hasher,
            &100u64.to_be_bytes(),
            Location::new(8),
            &plain_root(&mem, &hasher),
            0,
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
            batch.merkleize(&mem, &hasher)
        };
        mem.apply_batch(&batch).unwrap();

        let ref_hasher: H = Standard::new();
        let mut ref_mem = build::<F>(&ref_hasher, 2);
        let cs = {
            let batch = ref_mem.new_batch();
            let batch = batch.add(&ref_hasher, &2u64.to_be_bytes());
            batch.merkleize(&ref_mem, &ref_hasher)
        };
        ref_mem.apply_batch(&cs).unwrap();
        let cs = {
            let batch = ref_mem.new_batch();
            let batch = batch
                .update_leaf(&ref_hasher, Location::new(0), b"updated-0")
                .unwrap();
            batch.merkleize(&ref_mem, &ref_hasher)
        };
        ref_mem.apply_batch(&cs).unwrap();

        assert_eq!(
            plain_root(&mem, &hasher),
            plain_root(&ref_mem, &hasher),
            "roots must match"
        );

        let proof = mem.proof(&hasher, Location::new(0), 0).unwrap();
        assert!(
            proof.verify_element_inclusion(
                &hasher,
                b"updated-0",
                Location::new(0),
                &plain_root(&mem, &hasher),
                0,
            ),
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
                        batch.merkleize(&m, &hasher)
                    };
                    m.apply_batch(&batch).unwrap();

                    let proof = m.proof(&hasher, Location::new(update_loc), 0).unwrap();
                    assert!(
                        proof.verify_element_inclusion(
                            &hasher,
                            b"new",
                            Location::new(update_loc),
                            &plain_root(&m, &hasher),
                            0,
                        ),
                        "n={n} prune={prune_to} update={update_loc}: proof should verify"
                    );
                }
            }
        }
    }

    /// Applying C (child of B, grandchild of A) after only A is applied
    /// must apply B's uncommitted data + C's data, skipping only A.
    fn apply_batch_skips_only_committed_ancestors<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = Mem::<F, D>::new();

        // Chain: Mem -> A -> B -> C
        let a = mem.new_batch().add(&hasher, b"a").merkleize(&mem, &hasher);
        let b = a.new_batch().add(&hasher, b"b").merkleize(&mem, &hasher);
        let c = b.new_batch().add(&hasher, b"c").merkleize(&mem, &hasher);

        // Apply A, then apply C directly (skipping B's apply_batch).
        // C's ancestor batches carry [A.data, B.data]. A is already committed
        // so only B + C should be applied.
        mem.apply_batch(&a).unwrap();
        mem.apply_batch(&c).unwrap();

        // Verify against a reference that applied all three in order.
        let mut reference = Mem::<F, D>::new();
        let full = {
            let mut batch = reference.new_batch();
            for leaf in [b"a".as_slice(), b"b", b"c"] {
                batch = batch.add(&hasher, leaf);
            }
            batch.merkleize(&reference, &hasher)
        };
        reference.apply_batch(&full).unwrap();
        assert_eq!(plain_root(&mem, &hasher), plain_root(&reference, &hasher));
    }

    /// Dropping an uncommitted ancestor before merkleizing a descendant must
    /// be detected at apply time, not silently corrupt data.
    fn apply_batch_detects_dropped_ancestor<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = Mem::<F, D>::new();

        let a = mem.new_batch().add(&hasher, b"a").merkleize(&mem, &hasher);
        let b = a.new_batch().add(&hasher, b"b").merkleize(&mem, &hasher);
        drop(a); // A dropped before C is merkleized, so its data is lost
        let c = b.new_batch().add(&hasher, b"c").merkleize(&mem, &hasher);

        let result = mem.apply_batch(&c);
        assert!(
            matches!(result, Err(Error::AncestorDropped { .. })),
            "expected AncestorDropped, got {result:?}"
        );
    }

    /// Overwrite-only ancestor B must not be skipped when applying C after A.
    fn apply_batch_overwrite_only_ancestor<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build_raw::<F>(&hasher, 10);

        let pos0 = Position::<F>::try_from(Location::new(0)).unwrap();

        // A: add 5 leaves.
        let a = {
            let mut b = mem.new_batch();
            for i in 100u64..105 {
                b = b.add(&hasher, &i.to_be_bytes());
            }
            b.merkleize(&mem, &hasher)
        };

        // B: overwrite leaf 0, no appends.
        let b = a
            .new_batch()
            .update_leaf(&hasher, Location::new(0), b"updated-0")
            .unwrap()
            .merkleize(&mem, &hasher);

        // C: add 5 more leaves.
        let c = {
            let mut batch = b.new_batch();
            for i in 200u64..205 {
                batch = batch.add(&hasher, &i.to_be_bytes());
            }
            batch.merkleize(&mem, &hasher)
        };

        // Apply A, then C (skipping B's apply_batch).
        mem.apply_batch(&a).unwrap();
        mem.apply_batch(&c).unwrap();

        // B's overwrite must have been applied.
        let updated = hasher.leaf_digest(pos0, b"updated-0");
        assert_eq!(
            mem.get_node(pos0),
            Some(updated),
            "overwrite-only ancestor B's overwrites were skipped"
        );
    }

    fn split_root_spec_matches_recompute<F: Family>() {
        let hasher: H = Standard::new();
        let plain = build::<F>(&hasher, 49);
        let inactive_peaks = 1;
        let peaks: Vec<_> = F::peaks(plain.size())
            .map(|(pos, _)| plain.get_node(pos).expect("peak should be present"))
            .collect();
        let expected = <crate::merkle::hasher::Standard<commonware_cryptography::Sha256> as crate::merkle::hasher::Hasher<F>>::root(
            &hasher,
            plain.leaves(),
            inactive_peaks,
            peaks.iter(),
        )
        .unwrap();

        assert_eq!(plain.root(&hasher, inactive_peaks).unwrap(), expected);
        let _ = Bagging::ForwardFold;
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
    #[test]
    fn mmr_apply_batch_skips_only_committed_ancestors() {
        apply_batch_skips_only_committed_ancestors::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_apply_batch_detects_dropped_ancestor() {
        apply_batch_detects_dropped_ancestor::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_apply_batch_overwrite_only_ancestor() {
        apply_batch_overwrite_only_ancestor::<crate::mmr::Family>();
    }
    #[test]
    fn mmr_split_root_spec_matches_recompute() {
        split_root_spec_matches_recompute::<crate::mmr::Family>();
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
    #[test]
    fn mmb_apply_batch_skips_only_committed_ancestors() {
        apply_batch_skips_only_committed_ancestors::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_apply_batch_detects_dropped_ancestor() {
        apply_batch_detects_dropped_ancestor::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_apply_batch_overwrite_only_ancestor() {
        apply_batch_overwrite_only_ancestor::<crate::mmb::Family>();
    }
    #[test]
    fn mmb_split_root_spec_matches_recompute() {
        split_root_spec_matches_recompute::<crate::mmb::Family>();
    }
}
