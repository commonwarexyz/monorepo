//! Generic in-memory Merkle structure, parameterized by [`Family`].
//!
//! Both MMR and MMB share the same node storage, pruning, root computation, and proof logic.
//! This module provides the unified [`Mem`] struct; per-family modules re-export it as
//! `mmr::mem::Mmr` and `mmb::mem::Mmb` via type aliases.

use crate::merkle::{
    batch::ChainInfo, hasher::Hasher, proof as merkle_proof, Error, Family, Location, Position,
    Proof, Readable,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Configuration for initializing a [`Mem`].
pub struct Config<F: Family, D: Digest> {
    /// The retained nodes.
    pub nodes: Vec<D>,

    /// The leaf location up to which pruning has been performed, or 0 if never pruned.
    pub pruned_to: Location<F>,

    /// The pinned nodes, in the order expected by [`Family::nodes_to_pin`].
    pub pinned_nodes: Vec<D>,
}

/// A basic, `no_std`-compatible Merkle structure where all nodes are stored in-memory.
///
/// Nodes are either _retained_, _pruned_, or _pinned_. Retained nodes are stored in the main
/// deque. Pruned nodes precede `pruned_to_pos` and are no longer stored unless they are still
/// required for root computation or proof generation, in which case they are kept in
/// `pinned_nodes`.
///
/// The structure is always merkleized (its root is always computed). Mutations go through the
/// batch API: create an [`UnmerkleizedBatch`](crate::merkle::batch::UnmerkleizedBatch) via
/// [`Self::new_batch`], accumulate changes, then apply the resulting
/// [`Changeset`](crate::merkle::batch::Changeset) via [`Self::apply`].
#[derive(Clone, Debug)]
pub struct Mem<F: Family, D: Digest> {
    /// The retained nodes, starting at `pruned_to_pos`.
    pub(crate) nodes: VecDeque<D>,

    /// The highest position for which pruning has been performed, or 0 if never pruned.
    ///
    /// # Invariant
    ///
    /// This is always leaf-aligned (the position corresponding to some `Location`).
    pub(crate) pruned_to_pos: Position<F>,

    /// Auxiliary map from node position to the digest of any pinned node. Only recomputed when
    /// `pruned_to_pos` changes; appending nodes can only shrink the required set, so the current
    /// map is always a valid superset of what is needed.
    pub(crate) pinned_nodes: BTreeMap<Position<F>, D>,

    /// The root digest.
    pub(crate) root: D,
}

impl<F: Family, D: Digest> Mem<F, D> {
    /// Create a new, empty structure.
    pub fn new(hasher: &impl Hasher<F, Digest = D>) -> Self {
        let root = hasher.root(Location::new(0), core::iter::empty::<&D>());
        Self {
            nodes: VecDeque::new(),
            pruned_to_pos: Position::new(0),
            pinned_nodes: BTreeMap::new(),
            root,
        }
    }

    /// Return a [`Mem`] initialized with the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPinnedNodes`] if the number of pinned nodes doesn't match the
    /// expected count for `config.pruned_to`.
    ///
    /// Returns [`Error::InvalidSize`] if the resulting size is invalid.
    pub fn init(
        config: Config<F, D>,
        hasher: &impl Hasher<F, Digest = D>,
    ) -> Result<Self, Error<F>> {
        let pruned_to_pos = Position::try_from(config.pruned_to)?;

        let Some(size) = pruned_to_pos.checked_add(config.nodes.len() as u64) else {
            return Err(Error::InvalidSize(u64::MAX));
        };
        if !size.is_valid_size() {
            return Err(Error::InvalidSize(*size));
        }

        let expected_pinned_positions = F::nodes_to_pin(size, pruned_to_pos);
        if config.pinned_nodes.len() != expected_pinned_positions.len() {
            return Err(Error::InvalidPinnedNodes);
        }

        let pinned_nodes = expected_pinned_positions
            .into_iter()
            .zip(config.pinned_nodes)
            .collect();
        let nodes = VecDeque::from(config.nodes);
        let root = Self::compute_root(hasher, &nodes, &pinned_nodes, pruned_to_pos);

        Ok(Self {
            nodes,
            pruned_to_pos,
            pinned_nodes,
            root,
        })
    }

    /// Re-initialize with the given nodes, pruning boundary, and pinned nodes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidPinnedNodes`] if the provided pinned node count is invalid for the
    /// given state.
    ///
    /// Returns [`Error::LocationOverflow`] if `pruned_to` exceeds [`Family::MAX_LEAVES`].
    pub fn from_components(
        hasher: &impl Hasher<F, Digest = D>,
        nodes: Vec<D>,
        pruned_to: Location<F>,
        pinned_nodes: Vec<D>,
    ) -> Result<Self, Error<F>> {
        Self::init(
            Config {
                nodes,
                pruned_to,
                pinned_nodes,
            },
            hasher,
        )
    }

    /// Compute the root digest from the current peaks.
    pub(crate) fn compute_root(
        hasher: &impl Hasher<F, Digest = D>,
        nodes: &VecDeque<D>,
        pinned_nodes: &BTreeMap<Position<F>, D>,
        pruned_to_pos: Position<F>,
    ) -> D {
        let size = Position::new(nodes.len() as u64 + *pruned_to_pos);
        let leaves = Location::try_from(size).expect("invalid merkle size");
        let get_node = |pos: Position<F>| -> &D {
            if pos < pruned_to_pos {
                return pinned_nodes
                    .get(&pos)
                    .expect("requested node is pruned and not pinned");
            }
            let index = (*pos - *pruned_to_pos) as usize;
            &nodes[index]
        };
        let peaks = F::peaks(size).map(|(p, _)| get_node(p));
        hasher.root(leaves, peaks)
    }

    /// Return the total number of nodes, irrespective of any pruning. The next added element's
    /// position will have this value.
    pub fn size(&self) -> Position<F> {
        Position::new(self.nodes.len() as u64 + *self.pruned_to_pos)
    }

    /// Return the total number of leaves.
    pub fn leaves(&self) -> Location<F> {
        Location::try_from(self.size()).expect("invalid merkle size")
    }

    /// Returns `[start, end)` where `start` is the oldest retained leaf and `end` is the total
    /// leaf count.
    pub fn bounds(&self) -> Range<Location<F>> {
        Location::try_from(self.pruned_to_pos).expect("valid pruned_to_pos")..self.leaves()
    }

    /// Return a new iterator over the peaks.
    pub fn peak_iterator(&self) -> impl Iterator<Item = (Position<F>, u32)> {
        F::peaks(self.size())
    }

    /// Get the root digest.
    pub const fn root(&self) -> &D {
        &self.root
    }

    /// Return the requested node if it is either retained or present in the pinned_nodes map, and
    /// panic otherwise. Use [`get_node`](Self::get_node) instead if you require a non-panicking
    /// getter.
    ///
    /// # Panics
    ///
    /// Panics if the requested node does not exist for any reason such as the node is pruned or
    /// `pos` is out of bounds.
    pub(crate) fn get_node_unchecked(&self, pos: Position<F>) -> &D {
        if pos < self.pruned_to_pos {
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
            pos >= self.pruned_to_pos,
            "pos precedes oldest retained position"
        );

        *pos.checked_sub(*self.pruned_to_pos).unwrap() as usize
    }

    /// Return the requested node or `None` if it is not stored.
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }

        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Get the nodes (position + digest) that need to be pinned (those required for proof
    /// generation) when pruned to position `prune_pos`.
    pub(crate) fn nodes_to_pin(&self, prune_pos: Position<F>) -> BTreeMap<Position<F>, D> {
        F::nodes_to_pin(self.size(), prune_pos)
            .into_iter()
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
        if pos <= self.pruned_to_pos {
            return Ok(());
        }

        self.prune_to_pos(pos);
        Ok(())
    }

    /// Prune all retained nodes.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            self.prune_to_pos(self.size());
        }
    }

    /// Position-based pruning. Assumes `pos` is leaf-aligned.
    fn prune_to_pos(&mut self, pos: Position<F>) {
        self.pinned_nodes = self.nodes_to_pin(pos);
        let retained_nodes = self.pos_to_index(pos);
        self.nodes.drain(0..retained_nodes);
        self.pruned_to_pos = pos;
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
        // loc is valid so it won't overflow from + 1
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
    pub(crate) fn node_digests_to_pin(&self, prune_pos: Position<F>) -> Vec<D> {
        F::nodes_to_pin(self.size(), prune_pos)
            .into_iter()
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
    /// Recomputes the root after truncation.
    ///
    /// `new_size` must be a valid size (i.e., `new_size.is_valid_size()`) and must be
    /// `>= pruned_to_pos`.
    #[cfg(feature = "std")]
    pub(crate) fn truncate(&mut self, new_size: Position<F>, hasher: &impl Hasher<F, Digest = D>) {
        debug_assert!(new_size.is_valid_size());
        debug_assert!(new_size >= self.pruned_to_pos);
        let keep = (*new_size - *self.pruned_to_pos) as usize;
        self.nodes.truncate(keep);
        self.root = Self::compute_root(hasher, &self.nodes, &self.pinned_nodes, self.pruned_to_pos);
    }

    /// Return the nodes this structure currently has pinned.
    #[cfg(test)]
    pub(crate) fn pinned_nodes(&self) -> BTreeMap<Position<F>, D> {
        self.pinned_nodes.clone()
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> crate::merkle::batch::UnmerkleizedBatch<'_, F, D, Self> {
        crate::merkle::batch::UnmerkleizedBatch::new(self)
    }

    /// Apply a changeset produced by
    /// [`MerkleizedBatch::finalize`](crate::merkle::batch::MerkleizedBatch::finalize).
    ///
    /// A changeset is only valid if the structure has not been modified since the batch that
    /// produced it was created. Applying a stale changeset returns [`Error::StaleChangeset`].
    pub fn apply(
        &mut self,
        changeset: crate::merkle::batch::Changeset<F, D>,
    ) -> Result<(), Error<F>> {
        if changeset.base_size != self.size() {
            return Err(Error::StaleChangeset {
                expected: changeset.base_size,
                actual: self.size(),
            });
        }

        // 1. Overwrite: write modified digests into surviving base nodes.
        for (pos, digest) in changeset.overwrites {
            let index = self.pos_to_index(pos);
            self.nodes[index] = digest;
        }

        // 2. Append: push new nodes onto the end.
        for digest in changeset.appended {
            self.nodes.push_back(digest);
        }

        // 3. Update derived state.
        self.root = changeset.root;
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

    fn pruned_to_pos(&self) -> Position<F> {
        self.pruned_to_pos
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

impl<F: Family, D: Digest> ChainInfo<F> for Mem<F, D> {
    type Digest = D;

    fn base_size(&self) -> Position<F> {
        self.size()
    }

    fn collect_overwrites(&self, _into: &mut BTreeMap<Position<F>, D>) {}
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

    /// Like [`build`] but uses raw `i.to_be_bytes()` as elements instead of hashing them first.
    /// Tests that verify proof inclusion against `&i.to_be_bytes()` need this variant.
    fn build_raw<F: Family>(hasher: &H, n: u64) -> Mem<F, D> {
        let mut mem = Mem::new(hasher);
        let changeset = {
            let mut batch = mem.new_batch();
            for i in 0u64..n {
                batch = batch.add(hasher, &i.to_be_bytes());
            }
            batch.merkleize(hasher).finalize()
        };
        mem.apply(changeset).unwrap();
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
                let changeset = mem
                    .new_batch()
                    .add(&hasher, &i.to_be_bytes())
                    .merkleize(&hasher)
                    .finalize();
                mem.apply(changeset).unwrap();
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
                let changeset = mem
                    .new_batch()
                    .add(&hasher, &i.to_be_bytes())
                    .merkleize(&hasher)
                    .finalize();
                mem.apply(changeset).unwrap();
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

            // Empty config succeeds.
            assert!(Mem::<F, D>::init(
                Config {
                    nodes: vec![],
                    pruned_to: Location::new(0),
                    pinned_nodes: vec![],
                },
                &hasher,
            )
            .is_ok());

            // Pruned but no pinned nodes fails.
            assert!(matches!(
                Mem::<F, D>::init(
                    Config {
                        nodes: vec![],
                        pruned_to: Location::new(8),
                        pinned_nodes: vec![],
                    },
                    &hasher,
                ),
                Err(Error::InvalidPinnedNodes)
            ));

            // Extra pinned nodes with no pruning fails.
            assert!(matches!(
                Mem::<F, D>::init(
                    Config {
                        nodes: vec![],
                        pruned_to: Location::new(0),
                        pinned_nodes: vec![hasher.digest(b"dummy")],
                    },
                    &hasher,
                ),
                Err(Error::InvalidPinnedNodes)
            ));

            // Correct pinned nodes from a built structure succeed.
            let mem = build::<F>(&hasher, 50);
            let prune_loc = Location::<F>::new(25);
            let prune_pos = Position::try_from(prune_loc).unwrap();
            let pinned_nodes = mem.node_digests_to_pin(prune_pos);
            assert!(Mem::<F, D>::init(
                Config {
                    nodes: vec![],
                    pruned_to: prune_loc,
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
                    .merkleize(&hasher)
                    .finalize();
                reference.apply(cs).unwrap();
                let cs = pruned
                    .new_batch()
                    .add(&hasher, &element)
                    .merkleize(&hasher)
                    .finalize();
                pruned.apply(cs).unwrap();
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

        let changeset = {
            let mut batch = mem.new_batch();
            if let Some(ref pool) = pool {
                batch = batch.with_pool(Some(pool.clone()));
            }
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                batch = batch
                    .update_leaf(hasher, Location::new(leaf), &element)
                    .unwrap();
            }
            batch.merkleize(hasher).finalize()
        };
        mem.apply(changeset).unwrap();
        assert_ne!(*mem.root(), root);

        let changeset = {
            let mut batch = mem.new_batch();
            for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
                let element = hasher.digest(&leaf.to_be_bytes());
                batch = batch
                    .update_leaf(hasher, Location::new(leaf), &element)
                    .unwrap();
            }
            batch.merkleize(hasher).finalize()
        };
        mem.apply(changeset).unwrap();
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
            let changeset = {
                let batch = mem.new_batch();
                let batch = batch.add(&hasher, &i.to_be_bytes());
                batch.merkleize(&hasher).finalize()
            };
            mem.apply(changeset).unwrap();
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

        let changeset = {
            let mut batch = mem.new_batch();
            for i in 20u64..48 {
                batch = batch.add(&hasher, &i.to_be_bytes());
            }
            batch.merkleize(&hasher).finalize()
        };
        mem.apply(changeset).unwrap();

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

        // Update leaf 5 with new data.
        let changeset = {
            let batch = mem.new_batch();
            let batch = batch
                .update_leaf(&hasher, Location::new(5), b"updated-5")
                .unwrap();
            batch.merkleize(&hasher).finalize()
        };
        mem.apply(changeset).unwrap();

        // Root should change.
        assert_ne!(*mem.root(), root_before, "root should change after update");

        // Size and leaves should not change.
        assert_eq!(*mem.leaves(), 11);

        // The updated leaf should be provable with the new data.
        let proof = mem.proof(&hasher, Location::new(5)).unwrap();
        assert!(
            proof.verify_element_inclusion(&hasher, b"updated-5", Location::new(5), mem.root()),
            "updated leaf should verify with new data"
        );

        // The old data should no longer verify.
        assert!(
            !proof.verify_element_inclusion(
                &hasher,
                &5u64.to_be_bytes(),
                Location::new(5),
                mem.root()
            ),
            "old data should not verify"
        );

        // Other leaves should still verify with their original data.
        for i in [0u64, 3, 7, 10] {
            let p = mem.proof(&hasher, Location::new(i)).unwrap();
            assert!(
                p.verify_element_inclusion(&hasher, &i.to_be_bytes(), Location::new(i), mem.root()),
                "leaf {i} should still verify with original data"
            );
        }
    }

    fn update_leaf_every_position<F: Family>() {
        // Update each leaf one at a time and verify the entire tree after each update.
        let n = 20u64;
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, n);

        for update_loc in 0..n {
            let changeset = {
                let batch = mem.new_batch();
                let batch = batch
                    .update_leaf(&hasher, Location::new(update_loc), b"new-value")
                    .unwrap();
                batch.merkleize(&hasher).finalize()
            };
            mem.apply(changeset).unwrap();

            // The updated leaf should verify.
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

        // Out of bounds.
        {
            let batch = mem.new_batch();
            assert!(matches!(
                batch.update_leaf(&hasher, Location::new(10), b"x"),
                Err(Error::LeafOutOfBounds(_))
            ));
        }

        // Pruned leaf.
        mem.prune(Location::new(5)).unwrap();
        {
            let batch = mem.new_batch();
            assert!(matches!(
                batch.update_leaf(&hasher, Location::new(3), b"x"),
                Err(Error::ElementPruned(_))
            ));
            // Boundary leaf should succeed.
            let batch = mem.new_batch();
            assert!(batch.update_leaf(&hasher, Location::new(5), b"x").is_ok());
        }
    }

    fn update_leaf_with_append<F: Family>() {
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, 8);

        // Update an existing leaf and append new ones in the same batch.
        let changeset = {
            let batch = mem.new_batch();
            let batch = batch
                .update_leaf(&hasher, Location::new(3), b"updated-3")
                .unwrap();
            let batch = batch.add(&hasher, &100u64.to_be_bytes());
            let batch = batch.add(&hasher, &101u64.to_be_bytes());
            batch.merkleize(&hasher).finalize()
        };
        mem.apply(changeset).unwrap();

        assert_eq!(*mem.leaves(), 10);

        // Updated leaf verifies.
        let proof = mem.proof(&hasher, Location::new(3)).unwrap();
        assert!(proof.verify_element_inclusion(
            &hasher,
            b"updated-3",
            Location::new(3),
            mem.root()
        ));

        // New leaves verify.
        let proof = mem.proof(&hasher, Location::new(8)).unwrap();
        assert!(proof.verify_element_inclusion(
            &hasher,
            &100u64.to_be_bytes(),
            Location::new(8),
            mem.root()
        ));
    }

    /// Regression: add then update_leaf in the same batch where the updated leaf falls within the
    /// merge parent's subtree.
    fn update_leaf_under_merge_parent<F: Family>() {
        // Start with 2 leaves so the next add triggers a merge of the two height-0 peaks.
        // After adding leaf 2, the merge creates a height-1 parent. Then we update leaf 0,
        // which is a child of that merge parent.
        let hasher: H = Standard::new();
        let mut mem = build::<F>(&hasher, 2);
        let changeset = {
            let batch = mem.new_batch();
            let batch = batch.add(&hasher, &2u64.to_be_bytes());
            let batch = batch
                .update_leaf(&hasher, Location::new(0), b"updated-0")
                .unwrap();
            batch.merkleize(&hasher).finalize()
        };
        mem.apply(changeset).unwrap();

        // Build a reference structure with the same operations applied separately.
        let ref_hasher: H = Standard::new();
        let mut ref_mem = build::<F>(&ref_hasher, 2);
        let cs = {
            let batch = ref_mem.new_batch();
            let batch = batch.add(&ref_hasher, &2u64.to_be_bytes());
            batch.merkleize(&ref_hasher).finalize()
        };
        ref_mem.apply(cs).unwrap();
        let cs = {
            let batch = ref_mem.new_batch();
            let batch = batch
                .update_leaf(&ref_hasher, Location::new(0), b"updated-0")
                .unwrap();
            batch.merkleize(&ref_hasher).finalize()
        };
        ref_mem.apply(cs).unwrap();

        assert_eq!(*mem.root(), *ref_mem.root(), "roots must match");

        // Updated leaf should verify.
        let proof = mem.proof(&hasher, Location::new(0)).unwrap();
        assert!(
            proof.verify_element_inclusion(&hasher, b"updated-0", Location::new(0), mem.root()),
            "updated leaf should verify"
        );
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
}
