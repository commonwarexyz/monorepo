//! Generic in-memory Merkle structure, parameterized by [`Family`].
//!
//! Both MMR and MMB share the same node storage, pruning, root computation, and proof logic.
//! This module provides the unified [`Mem`] struct; per-family modules re-export it as
//! `mmr::mem::Mmr` and `mmb::mem::Mmb` via type aliases.

use crate::merkle::{
    batch::BatchChainInfo, hasher::Hasher, proof as merkle_proof, Error, Family, Location,
    Position, Proof, Readable,
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
    pub fn new(hasher: &mut impl Hasher<F, Digest = D>) -> Self {
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
        hasher: &mut impl Hasher<F, Digest = D>,
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
    /// Returns [`Error::LocationOverflow`] if `pruned_to` exceeds [`Family::MAX_LOCATION`].
    pub fn from_components(
        hasher: &mut impl Hasher<F, Digest = D>,
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
        hasher: &mut impl Hasher<F, Digest = D>,
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
    /// Returns [`Error::LocationOverflow`] if `loc` exceeds [`Family::MAX_LOCATION`].
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
        hasher: &mut impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid() {
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
        hasher: &mut impl Hasher<F, Digest = D>,
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
        hasher: &mut impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        self.proof(hasher, loc)
    }

    fn range_proof(
        &self,
        hasher: &mut impl Hasher<F, Digest = D>,
        range: Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        self.range_proof(hasher, range)
    }
}

impl<F: Family, D: Digest> BatchChainInfo<F> for Mem<F, D> {
    type Digest = D;

    fn base_size(&self) -> Position<F> {
        self.size()
    }

    fn collect_overwrites(&self, _into: &mut BTreeMap<Position<F>, D>) {}
}
