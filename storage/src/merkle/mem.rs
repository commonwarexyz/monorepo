//! A basic, `no_std` compatible in-memory implementation for any Merkle-family structure.
//!
//! `Mem<F, D>` stores all nodes in a [`VecDeque`], supports pruning with pinned nodes for proof
//! generation, and is parameterized by a [`Family`] marker that determines the node layout.

use crate::merkle::{
    batch::{self, BatchChainInfo},
    hasher::Hasher,
    Family, Location, Position, Proof, Readable,
};
use alloc::{
    collections::{BTreeMap, VecDeque},
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;

/// Configuration for initializing a [Mem].
pub struct Config<F: Family, D: Digest> {
    /// The retained nodes.
    pub nodes: Vec<D>,

    /// The leaf location up to which this structure has been pruned, or 0 if never pruned.
    pub pruned_to: Location<F>,

    /// The pinned nodes, in the order expected by [`Family::nodes_to_pin`].
    pub pinned_nodes: Vec<D>,
}

/// Errors from `Mem` operations. Each Merkle family wraps these in its own error type.
#[derive(Debug)]
pub enum Error<F: Family> {
    /// The provided size is not valid for this family.
    InvalidSize(u64),
    /// The provided pinned node list does not match the expected pruning boundary.
    InvalidPinnedNodes,
    /// A required node was not available (e.g. pruned).
    ElementPruned(Position<F>),
    /// A requested leaf location exceeds the current leaf count.
    LeafOutOfBounds(Location<F>),
    /// Location exceeds the valid range.
    LocationOverflow(Location<F>),
    /// A non-leaf position was used where a leaf position was required.
    NonLeaf(Position<F>),
    /// Position exceeds the valid range.
    PositionOverflow(Position<F>),
    /// Changeset was created against a different state.
    StaleChangeset {
        expected: Position<F>,
        actual: Position<F>,
    },
}

impl<F: Family> From<crate::merkle::Error<F>> for Error<F> {
    fn from(e: crate::merkle::Error<F>) -> Self {
        match e {
            crate::merkle::Error::LocationOverflow(loc) => Self::LocationOverflow(loc),
            crate::merkle::Error::NonLeaf(pos) => Self::NonLeaf(pos),
            crate::merkle::Error::PositionOverflow(pos) => Self::PositionOverflow(pos),
        }
    }
}

/// A basic in-memory Merkle-family structure.
///
/// Nodes are either _retained_, _pruned_, or _pinned_. Retained nodes are stored in the main
/// deque. Pruned nodes precede `pruned_to_pos` and are no longer stored unless they are still
/// required for root computation or proof generation, in which case they are kept as pinned nodes.
///
/// The structure is always merkleized (its root is always computed). Mutations go through the
/// batch API: create an [`batch::UnmerkleizedBatch`] via [`Self::new_batch`], accumulate changes,
/// then apply the resulting [`batch::Changeset`] via [`Self::apply`].
#[derive(Clone, Debug)]
pub struct Mem<F: Family, D: Digest> {
    /// The retained nodes, starting at `pruned_to_pos`.
    nodes: VecDeque<D>,

    /// The highest position for which this structure has been pruned, or 0 if never pruned.
    ///
    /// This is always leaf-aligned (the position corresponding to some `Location`).
    pruned_to_pos: Position<F>,

    /// Auxiliary map from node position to the digest of any pinned node.
    pinned_nodes: BTreeMap<Position<F>, D>,

    /// The root digest.
    root: D,

    /// The number of leaves.
    leaves: Location<F>,
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
            leaves: Location::new(0),
        }
    }

    /// Initialize from a [Config].
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPinnedNodes] if the number of pinned nodes doesn't match the
    /// expected count.
    /// Returns [Error::InvalidSize] if the total size is invalid.
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
        let leaves = Location::try_from(size).map_err(|_| Error::InvalidSize(*size))?;
        let root = Self::compute_root(hasher, leaves, &nodes, &pinned_nodes, pruned_to_pos);

        Ok(Self {
            nodes,
            pruned_to_pos,
            pinned_nodes,
            root,
            leaves,
        })
    }

    /// Initialize from individual components.
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
    fn compute_root(
        hasher: &mut impl Hasher<F, Digest = D>,
        leaves: Location<F>,
        nodes: &VecDeque<D>,
        pinned_nodes: &BTreeMap<Position<F>, D>,
        pruned_to_pos: Position<F>,
    ) -> D {
        let size = Position::try_from(leaves).expect("invalid leaves");
        let get_node = |pos: Position<F>| -> &D {
            if pos < pruned_to_pos {
                return pinned_nodes
                    .get(&pos)
                    .expect("requested node is pruned and not pinned");
            }
            let index = (*pos - *pruned_to_pos) as usize;
            &nodes[index]
        };

        let peaks: Vec<&D> = F::peaks_fold_order(size)
            .iter()
            .map(|(peak_pos, _)| get_node(*peak_pos))
            .collect();
        hasher.root(leaves, peaks)
    }

    /// Return the total number of nodes, irrespective of any pruning.
    pub fn size(&self) -> Position<F> {
        Position::new(self.nodes.len() as u64 + *self.pruned_to_pos)
    }

    /// Return the total number of leaves.
    pub const fn leaves(&self) -> Location<F> {
        self.leaves
    }

    /// Returns `[start, end)` where `start` is the oldest retained leaf and `end` is the total
    /// leaf count.
    pub fn bounds(&self) -> Range<Location<F>> {
        Location::try_from(self.pruned_to_pos).expect("valid pruned_to_pos")..self.leaves()
    }

    /// Return a new iterator over the peaks.
    pub fn peak_iterator(&self) -> F::PeakIterator {
        F::peak_iterator(self.size())
    }

    /// Get the root digest.
    pub const fn root(&self) -> &D {
        &self.root
    }

    /// Return the requested node if it is either retained or pinned, panicking otherwise.
    ///
    /// # Panics
    ///
    /// Panics if the requested node does not exist (pruned and not pinned, or out of bounds).
    pub(crate) fn get_node_unchecked(&self, pos: Position<F>) -> &D {
        if pos < self.pruned_to_pos {
            return self
                .pinned_nodes
                .get(&pos)
                .expect("requested node is pruned and not pinned");
        }

        &self.nodes[self.pos_to_index(pos)]
    }

    /// Return the index in the nodes deque for a given position.
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

    /// Return the position of the node at the given index in the nodes deque.
    fn index_to_pos(&self, index: usize) -> Position<F> {
        self.pruned_to_pos + (index as u64)
    }

    /// Return the requested node, or None if pruned/out of bounds.
    pub fn get_node(&self, pos: Position<F>) -> Option<D> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }
        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Return the positions and digests that must remain pinned for the given pruning boundary.
    fn collect_pinned_nodes(
        &self,
        size: Position<F>,
        prune_pos: Position<F>,
    ) -> BTreeMap<Position<F>, D> {
        F::nodes_to_pin(size, prune_pos)
            .into_iter()
            .map(|pos| (pos, *self.get_node_unchecked(pos)))
            .collect()
    }

    /// Recompute the pinned node set for the current size.
    pub(crate) fn refresh_pinned_nodes(&mut self) {
        if self.pruned_to_pos == 0 {
            self.pinned_nodes.clear();
            return;
        }
        self.pinned_nodes = self.collect_pinned_nodes(self.size(), self.pruned_to_pos);
    }

    /// Create a new speculative batch with this structure as its parent.
    pub fn new_batch(&self) -> batch::UnmerkleizedBatch<'_, F, D, Self> {
        batch::UnmerkleizedBatch::new(self)
    }

    /// Apply a changeset produced by [`batch::MerkleizedBatch::finalize`].
    ///
    /// A changeset is only valid if the structure has not been modified since the batch that
    /// produced it was created. Applying a stale changeset returns [Error::StaleChangeset].
    pub fn apply(&mut self, changeset: batch::Changeset<F, D>) -> Result<(), Error<F>> {
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
        self.leaves = Location::try_from(self.size()).expect("invalid size");
        self.root = changeset.root;
        Ok(())
    }

    /// Prune all nodes up to but not including the given leaf location, and pin the nodes still
    /// required for root computation and proof generation.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOverflow] if `loc` exceeds the valid range.
    /// Returns [Error::LeafOutOfBounds] if `loc` exceeds the current leaf count.
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

    /// Prune all nodes and pin those required for proof generation going forward.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            let pos = self.index_to_pos(self.nodes.len());
            self.prune_to_pos(pos);
        }
    }

    /// Position-based pruning.
    fn prune_to_pos(&mut self, pos: Position<F>) {
        self.pinned_nodes = self.collect_pinned_nodes(self.size(), pos);
        let retained_nodes = self.pos_to_index(pos);
        self.nodes.drain(0..retained_nodes);
        self.pruned_to_pos = pos;
    }

    /// Return an inclusion proof for the element at location `loc`.
    pub fn proof(
        &self,
        hasher: &mut impl Hasher<F, Digest = D>,
        loc: Location<F>,
    ) -> Result<Proof<F, D>, Error<F>> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        self.range_proof(hasher, loc..loc + 1).map_err(|e| match e {
            Error::LeafOutOfBounds(l) => Error::LeafOutOfBounds(l),
            other => other,
        })
    }

    /// Return an inclusion proof for all elements in `range`.
    pub fn range_proof(
        &self,
        hasher: &mut impl Hasher<F, Digest = D>,
        range: Range<Location<F>>,
    ) -> Result<Proof<F, D>, Error<F>> {
        crate::merkle::proof::build_range_proof(hasher, self.leaves(), range, |pos| {
            self.get_node(pos)
        })
    }

    /// Get the digests of nodes that need to be pinned when pruned to `start_pos`.
    #[cfg(test)]
    pub(crate) fn node_digests_to_pin(&self, start_pos: Position<F>) -> Vec<D> {
        F::nodes_to_pin(self.size(), start_pos)
            .into_iter()
            .map(|pos| *self.get_node_unchecked(pos))
            .collect()
    }

    /// Return the nodes currently pinned.
    #[cfg(test)]
    pub(crate) fn pinned_nodes(&self) -> BTreeMap<Position<F>, D> {
        self.pinned_nodes.clone()
    }

    /// Utility to pin extra nodes. Used by stores that build on the mem structure.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: BTreeMap<Position<F>, D>) {
        for (pos, node) in pinned_nodes.into_iter() {
            self.pinned_nodes.insert(pos, node);
        }
    }

    /// Truncate to a smaller valid size, discarding all nodes beyond it.
    #[cfg(feature = "std")]
    pub(crate) fn truncate(
        &mut self,
        new_size: Position<F>,
        hasher: &mut impl Hasher<F, Digest = D>,
    ) {
        debug_assert!(new_size.is_valid_size());
        debug_assert!(new_size >= self.pruned_to_pos);
        let keep = (*new_size - *self.pruned_to_pos) as usize;
        self.nodes.truncate(keep);
        self.leaves = Location::try_from(new_size).expect("invalid size");
        self.root = Self::compute_root(
            hasher,
            self.leaves,
            &self.nodes,
            &self.pinned_nodes,
            self.pruned_to_pos,
        );
    }

    /// Get the map from node position to digest for nodes that need to be pinned at `prune_pos`.
    #[cfg(test)]
    pub(crate) fn nodes_to_pin(&self, prune_pos: Position<F>) -> BTreeMap<Position<F>, D> {
        self.collect_pinned_nodes(self.size(), prune_pos)
    }

    /// The pruned-to position.
    pub(crate) const fn pruned_to_pos(&self) -> Position<F> {
        self.pruned_to_pos
    }
}

// --- Readable impl ---

impl<F: Family, D: Digest> Readable for Mem<F, D> {
    type Family = F;
    type Digest = D;
    type Error = Error<F>;
    type PeakIterator = F::PeakIterator;

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

    fn peak_iterator(&self) -> Self::PeakIterator {
        F::peak_iterator(self.size())
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

// --- BatchChainInfo impl ---

impl<F: Family, D: Digest> BatchChainInfo<F> for Mem<F, D> {
    type Digest = D;

    fn base_size(&self) -> Position<F> {
        self.size()
    }

    fn collect_overwrites(&self, _into: &mut BTreeMap<Position<F>, D>) {}
}

/// Blueprint for a range proof, separating fold-prefix peaks from nodes that must be fetched.
pub struct Blueprint<F: Family> {
    /// Peak positions that precede the proven range (to be folded into a single accumulator).
    pub fold_prefix: Vec<Position<F>>,
    /// Node positions to include in the proof: after-peaks followed by DFS siblings.
    pub fetch_nodes: Vec<Position<F>>,
}
