//! A basic, no_std compatible MMR where all nodes are stored in-memory.

use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_needing_parents, nodes_to_pin, PathIterator, PeakIterator},
    proof,
    Error::{self, *},
    Location, Position, Proof,
};
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::{mem, ops::Range};
cfg_if::cfg_if! {
    if #[cfg(feature = "std")] {
        use commonware_parallel::ThreadPool;
        use rayon::prelude::*;
    } else {
        struct ThreadPool;
    }
}

/// Minimum number of digest computations required during batch updates to trigger parallelization.
#[cfg(feature = "std")]
const MIN_TO_PARALLELIZE: usize = 20;

/// An MMR whose root digest has not been computed.
pub type DirtyMmr<D> = Mmr<D, Dirty>;

/// An MMR whose root digest has been computed.
pub type CleanMmr<D> = Mmr<D, Clean<D>>;

/// Sealed trait for MMR state types.
mod private {
    pub trait Sealed {}
}

/// Trait for valid MMR state types.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {
    /// Add the given leaf digest to the MMR, returning its position.
    fn add_leaf_digest<H: Hasher<Digest = D>>(
        mmr: &mut Mmr<D, Self>,
        hasher: &mut H,
        digest: D,
    ) -> Position;
}

/// Marker type for a MMR whose root digest has been computed.
#[derive(Clone, Copy, Debug)]
pub struct Clean<D: Digest> {
    /// The root digest of the MMR.
    pub root: D,
}

impl<D: Digest> private::Sealed for Clean<D> {}
impl<D: Digest> State<D> for Clean<D> {
    fn add_leaf_digest<H: Hasher<Digest = D>>(
        mmr: &mut CleanMmr<D>,
        hasher: &mut H,
        digest: D,
    ) -> Position {
        mmr.add_leaf_digest(hasher, digest)
    }
}

/// Marker type for a dirty MMR (root digest not computed).
#[derive(Clone, Debug, Default)]
pub struct Dirty {
    /// Non-leaf nodes that need to have their digests recomputed due to a batched update operation.
    ///
    /// This is a set of tuples of the form (node_pos, height).
    dirty_nodes: BTreeSet<(Position, u32)>,
}

impl private::Sealed for Dirty {}
impl<D: Digest> State<D> for Dirty {
    fn add_leaf_digest<H: Hasher<Digest = D>>(
        mmr: &mut DirtyMmr<D>,
        _hasher: &mut H,
        digest: D,
    ) -> Position {
        mmr.add_leaf_digest(digest)
    }
}

/// Configuration for initializing an [Mmr].
pub struct Config<D: Digest> {
    /// The retained nodes of the MMR.
    pub nodes: Vec<D>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pub pruned_to_pos: Position,

    /// The pinned nodes of the MMR, in the order expected by `nodes_to_pin`.
    pub pinned_nodes: Vec<D>,
}

/// A basic MMR where all nodes are stored in-memory.
///
/// # Terminology
///
/// Nodes in this structure are either _retained_, _pruned_, or _pinned_. Retained nodes are nodes
/// that have not yet been pruned, and have digests stored explicitly within the tree structure.
/// Pruned nodes are those whose positions precede that of the _oldest retained_ node, for which no
/// digests are maintained. Pinned nodes are nodes that would otherwise be pruned based on their
/// position, but whose digests remain required for proof generation. The digests for pinned nodes
/// are stored in an auxiliary map, and are at most O(log2(n)) in number.
///
/// # Max Capacity
///
/// The maximum number of elements that can be stored is usize::MAX (u32::MAX on 32-bit
/// architectures).
///
/// # Type States
///
/// The MMR uses the type-state pattern to enforce at compile-time whether the MMR has pending
/// updates that must be merkleized before computing proofs. [CleanMmr] represents a clean
/// MMR whose root digest has been computed. [DirtyMmr] represents a dirty MMR whose root
/// digest needs to be computed. A dirty MMR can be converted into a clean MMR by calling
/// [DirtyMmr::merkleize].
#[derive(Clone, Debug)]
pub struct Mmr<D: Digest, S: State<D> = Dirty> {
    /// The nodes of the MMR, laid out according to a post-order traversal of the MMR trees,
    /// starting from the from tallest tree to shortest.
    nodes: VecDeque<D>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pruned_to_pos: Position,

    /// The auxiliary map from node position to the digest of any pinned node.
    pinned_nodes: BTreeMap<Position, D>,

    /// Type-state for the MMR.
    state: S,
}

impl<D: Digest> Default for DirtyMmr<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest> From<CleanMmr<D>> for DirtyMmr<D> {
    fn from(clean: CleanMmr<D>) -> Self {
        DirtyMmr {
            nodes: clean.nodes,
            pruned_to_pos: clean.pruned_to_pos,
            pinned_nodes: clean.pinned_nodes,
            state: Dirty {
                dirty_nodes: BTreeSet::new(),
            },
        }
    }
}

impl<D: Digest, S: State<D>> Mmr<D, S> {
    /// Return the total number of nodes in the MMR, irrespective of any pruning. The next added
    /// element's position will have this value.
    pub fn size(&self) -> Position {
        Position::new(self.nodes.len() as u64 + *self.pruned_to_pos)
    }

    /// Return the total number of leaves in the MMR.
    pub fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmr size")
    }

    /// Return the position of the last leaf in this MMR, or None if the MMR is empty.
    pub fn last_leaf_pos(&self) -> Option<Position> {
        if self.size() == 0 {
            return None;
        }

        Some(PeakIterator::last_leaf_pos(self.size()))
    }

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pub const fn pruned_to_pos(&self) -> Position {
        self.pruned_to_pos
    }

    /// Return the position of the oldest retained node in the MMR, not including those cached in
    /// pinned_nodes.
    pub fn oldest_retained_pos(&self) -> Option<Position> {
        if self.pruned_to_pos == self.size() {
            return None;
        }

        Some(self.pruned_to_pos)
    }

    /// Return a new iterator over the peaks of the MMR.
    pub fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Return the position of the element given its index in the current nodes vector.
    fn index_to_pos(&self, index: usize) -> Position {
        self.pruned_to_pos + (index as u64)
    }

    /// Return the requested node if it is either retained or present in the pinned_nodes map, and
    /// panic otherwise. Use `get_node` instead if you require a non-panicking getter.
    ///
    /// # Warning
    ///
    /// If the requested digest is for an unmerkleized node (only possible in the Dirty state) a
    /// dummy digest will be returned.
    ///
    /// # Panics
    ///
    /// Panics if the requested node does not exist for any reason such as the node is pruned or
    /// `pos` is out of bounds.
    pub(crate) fn get_node_unchecked(&self, pos: Position) -> &D {
        if pos < self.pruned_to_pos {
            return self
                .pinned_nodes
                .get(&pos)
                .expect("requested node is pruned and not pinned");
        }

        &self.nodes[self.pos_to_index(pos)]
    }

    /// Return the index of the element in the current nodes vector given its position in the MMR.
    ///
    /// # Panics
    ///
    /// Panics if `pos` precedes the oldest retained position.
    fn pos_to_index(&self, pos: Position) -> usize {
        assert!(
            pos >= self.pruned_to_pos,
            "pos precedes oldest retained position"
        );

        *pos.checked_sub(*self.pruned_to_pos).unwrap() as usize
    }

    /// Utility used by stores that build on the mem MMR to pin extra nodes if needed. It's up to
    /// the caller to ensure that this set of pinned nodes is valid for their use case.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: BTreeMap<Position, D>) {
        for (pos, node) in pinned_nodes.into_iter() {
            self.pinned_nodes.insert(pos, node);
        }
    }

    /// Add `element` to the MMR and return its position.
    /// The element can be an arbitrary byte slice, and need not be converted to a digest first.
    pub fn add<H: Hasher<Digest = D>>(&mut self, hasher: &mut H, element: &[u8]) -> Position {
        let digest = hasher.leaf_digest(self.size(), element);
        S::add_leaf_digest(self, hasher, digest)
    }
}

/// Implementation for Clean MMR state.
impl<D: Digest> CleanMmr<D> {
    /// Return an [Mmr] initialized with the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPinnedNodes] if the number of pinned nodes doesn't match the expected
    /// count for `config.pruned_to_pos`.
    ///
    /// Returns [Error::InvalidSize] if the MMR size is invalid.
    pub fn init(config: Config<D>, hasher: &mut impl Hasher<Digest = D>) -> Result<Self, Error> {
        // Validate that the total size is valid
        let Some(size) = config.pruned_to_pos.checked_add(config.nodes.len() as u64) else {
            return Err(Error::InvalidSize(u64::MAX));
        };
        if !size.is_mmr_size() {
            return Err(Error::InvalidSize(*size));
        }

        // Validate and populate pinned nodes
        let mut pinned_nodes = BTreeMap::new();
        let mut expected_pinned_nodes = 0;
        for (i, pos) in nodes_to_pin(config.pruned_to_pos).enumerate() {
            expected_pinned_nodes += 1;
            if i >= config.pinned_nodes.len() {
                return Err(Error::InvalidPinnedNodes);
            }
            pinned_nodes.insert(pos, config.pinned_nodes[i]);
        }

        // Check for too many pinned nodes
        if config.pinned_nodes.len() != expected_pinned_nodes {
            return Err(Error::InvalidPinnedNodes);
        }

        let mmr = Mmr {
            nodes: VecDeque::from(config.nodes),
            pruned_to_pos: config.pruned_to_pos,
            pinned_nodes,
            state: Dirty::default(),
        };
        Ok(mmr.merkleize(hasher, None))
    }

    /// Create a new, empty MMR in the Clean state.
    pub fn new(hasher: &mut impl Hasher<Digest = D>) -> Self {
        let mmr: DirtyMmr<D> = Default::default();
        mmr.merkleize(hasher, None)
    }

    /// Re-initialize the MMR with the given nodes, pruned_to_pos, and pinned_nodes.
    pub fn from_components(
        hasher: &mut impl Hasher<Digest = D>,
        nodes: Vec<D>,
        pruned_to_pos: Position,
        pinned_nodes: Vec<D>,
    ) -> Self {
        DirtyMmr::from_components(nodes, pruned_to_pos, pinned_nodes).merkleize(hasher, None)
    }

    /// Return the requested node or None if it is not stored in the MMR.
    pub fn get_node(&self, pos: Position) -> Option<D> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }

        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Add a leaf's `digest` to the MMR, generating the necessary parent nodes to maintain the
    /// MMR's structure.
    pub(super) fn add_leaf_digest(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        digest: D,
    ) -> Position {
        let mut dirty_mmr = mem::replace(self, Self::new(hasher)).into_dirty();
        let leaf_pos = dirty_mmr.add_leaf_digest(digest);
        *self = dirty_mmr.merkleize(hasher, None);
        leaf_pos
    }

    /// Pop the most recent leaf element out of the MMR if it exists, returning Empty or
    /// ElementPruned errors otherwise.
    pub fn pop(&mut self, hasher: &mut impl Hasher<Digest = D>) -> Result<Position, Error> {
        let mut dirty_mmr = mem::replace(self, Self::new(hasher)).into_dirty();
        let result = dirty_mmr.pop();
        *self = dirty_mmr.merkleize(hasher, None);
        result
    }

    /// Get the nodes (position + digest) that need to be pinned (those required for proof
    /// generation) in this MMR when pruned to position `prune_pos`.
    pub(crate) fn nodes_to_pin(&self, prune_pos: Position) -> BTreeMap<Position, D> {
        nodes_to_pin(prune_pos)
            .map(|pos| (pos, *self.get_node_unchecked(pos)))
            .collect()
    }

    /// Prune all nodes up to but not including the given position, and pin the O(log2(n)) number of
    /// them required for proof generation.
    pub fn prune_to_pos(&mut self, pos: Position) {
        // Recompute the set of older nodes to retain.
        self.pinned_nodes = self.nodes_to_pin(pos);
        let retained_nodes = self.pos_to_index(pos);
        self.nodes.drain(0..retained_nodes);
        self.pruned_to_pos = pos;
    }

    /// Prune all nodes and pin the O(log2(n)) number of them required for proof generation going
    /// forward.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            let pos = self.index_to_pos(self.nodes.len());
            self.prune_to_pos(pos);
        }
    }

    /// Change the digest of any retained leaf. This is useful if you want to use the MMR
    /// implementation as an updatable binary Merkle tree, and otherwise should be avoided.
    ///
    /// # Errors
    ///
    /// Returns [Error::ElementPruned] if the leaf has been pruned.
    /// Returns [Error::LeafOutOfBounds] if `loc` is not an existing leaf.
    /// Returns [Error::LocationOverflow] if `loc` > [crate::mmr::MAX_LOCATION].
    ///
    /// # Warning
    ///
    /// This method will change the root and invalidate any previous inclusion proofs.
    /// Use of this method will prevent using this structure as a base mmr for grafting.
    pub fn update_leaf(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<(), Error> {
        let mut dirty_mmr = mem::replace(self, Self::new(hasher)).into_dirty();
        let result = dirty_mmr.update_leaf(hasher, loc, element);
        *self = dirty_mmr.merkleize(hasher, None);
        result
    }

    /// Convert this Clean MMR into a Dirty MMR without making any changes to it.
    pub fn into_dirty(self) -> DirtyMmr<D> {
        self.into()
    }

    /// Get the root digest of the MMR.
    pub const fn root(&self) -> &D {
        &self.state.root
    }

    /// Returns the root that would be produced by calling `root` on an empty MMR.
    pub fn empty_mmr_root(hasher: &mut impl commonware_cryptography::Hasher<Digest = D>) -> D {
        hasher.update(&0u64.to_be_bytes());
        hasher.finalize()
    }

    /// Return an inclusion proof for the element at location `loc`.
    ///
    /// # Errors
    ///
    /// Returns [Error::LocationOverflow] if `loc` > [crate::mmr::MAX_LOCATION].
    /// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned.
    ///
    /// # Panics
    ///
    /// Panics if `loc` is out of bounds.
    pub fn proof(&self, loc: Location) -> Result<Proof<D>, Error> {
        if !loc.is_valid() {
            return Err(Error::LocationOverflow(loc));
        }
        // loc is valid so it won't overflow from + 1
        self.range_proof(loc..loc + 1)
    }

    /// Return an inclusion proof for all elements within the provided `range` of locations.
    ///
    /// # Errors
    ///
    /// Returns [Error::Empty] if the range is empty.
    /// Returns [Error::LocationOverflow] if any location in `range` exceeds [crate::mmr::MAX_LOCATION].
    /// Returns [Error::ElementPruned] if some element needed to generate the proof has been pruned.
    ///
    /// # Panics
    ///
    /// Panics if the element range is out of bounds.
    pub fn range_proof(&self, range: Range<Location>) -> Result<Proof<D>, Error> {
        let leaves = self.leaves();
        assert!(
            range.start < leaves,
            "range start {} >= leaf count {}",
            range.start,
            leaves
        );
        assert!(
            range.end <= leaves,
            "range end {} > leaf count {}",
            range.end,
            leaves
        );

        let size = self.size();
        let positions = proof::nodes_required_for_range_proof(size, range)?;
        let digests = positions
            .into_iter()
            .map(|pos| self.get_node(pos).ok_or(Error::ElementPruned(pos)))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Proof { size, digests })
    }

    /// Get the digests of nodes that need to be pinned (those required for proof generation) in
    /// this MMR when pruned to position `prune_pos`.
    #[cfg(test)]
    pub(crate) fn node_digests_to_pin(&self, start_pos: Position) -> Vec<D> {
        nodes_to_pin(start_pos)
            .map(|pos| *self.get_node_unchecked(pos))
            .collect()
    }

    /// Return the nodes this MMR currently has pinned. Pinned nodes are nodes that would otherwise
    /// be pruned, but whose digests remain required for proof generation.
    #[cfg(test)]
    pub(super) fn pinned_nodes(&self) -> BTreeMap<Position, D> {
        self.pinned_nodes.clone()
    }
}

/// Implementation for Dirty MMR state.
impl<D: Digest> DirtyMmr<D> {
    /// Return a new (empty) `Mmr`.
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            pruned_to_pos: Position::new(0),
            pinned_nodes: BTreeMap::new(),
            state: Dirty::default(),
        }
    }

    /// Re-initialize the MMR with the given nodes, pruned_to_pos, and pinned_nodes.
    pub fn from_components(nodes: Vec<D>, pruned_to_pos: Position, pinned_nodes: Vec<D>) -> Self {
        Self {
            nodes: VecDeque::from(nodes),
            pruned_to_pos,
            pinned_nodes: nodes_to_pin(pruned_to_pos)
                .enumerate()
                .map(|(i, pos)| (pos, pinned_nodes[i]))
                .collect(),
            state: Dirty::default(),
        }
    }

    /// Add `digest` as a new leaf in the MMR, returning its position.
    pub(super) fn add_leaf_digest(&mut self, digest: D) -> Position {
        // Compute the new parent nodes, if any.
        let nodes_needing_parents = nodes_needing_parents(self.peak_iterator())
            .into_iter()
            .rev();
        let leaf_pos = self.size();
        self.nodes.push_back(digest);

        let mut height = 1;
        for _ in nodes_needing_parents {
            let new_node_pos = self.size();
            self.nodes.push_back(D::EMPTY);
            self.state.dirty_nodes.insert((new_node_pos, height));
            height += 1;
        }

        leaf_pos
    }

    /// Pop the most recent leaf element out of the MMR if it exists, returning Empty or
    /// ElementPruned errors otherwise.
    pub fn pop(&mut self) -> Result<Position, Error> {
        if self.size() == 0 {
            return Err(Empty);
        }

        let mut new_size = self.size() - 1;
        loop {
            if new_size < self.pruned_to_pos {
                return Err(ElementPruned(new_size));
            }
            if new_size.is_mmr_size() {
                break;
            }
            new_size -= 1;
        }
        let num_to_drain = *(self.size() - new_size) as usize;
        self.nodes.drain(self.nodes.len() - num_to_drain..);

        // Remove dirty nodes that are now out of bounds.
        let cutoff = (self.size(), 0);
        self.state.dirty_nodes.split_off(&cutoff);

        Ok(self.size())
    }

    /// Compute updated digests for dirty nodes and compute the root, converting this MMR into a
    /// [CleanMmr].
    pub fn merkleize(
        mut self,
        hasher: &mut impl Hasher<Digest = D>,
        pool: Option<ThreadPool>,
    ) -> CleanMmr<D> {
        #[cfg(feature = "std")]
        match (pool, self.state.dirty_nodes.len() >= MIN_TO_PARALLELIZE) {
            (Some(pool), true) => self.merkleize_parallel(hasher, pool, MIN_TO_PARALLELIZE),
            _ => self.merkleize_serial(hasher),
        }

        #[cfg(not(feature = "std"))]
        self.merkleize_serial(hasher);

        // Compute root
        let peaks = self
            .peak_iterator()
            .map(|(peak_pos, _)| self.get_node_unchecked(peak_pos));
        let size = self.size();
        let digest = hasher.root(size, peaks);

        CleanMmr {
            nodes: self.nodes,
            pruned_to_pos: self.pruned_to_pos,
            pinned_nodes: self.pinned_nodes,
            state: Clean { root: digest },
        }
    }

    fn merkleize_serial(&mut self, hasher: &mut impl Hasher<Digest = D>) {
        let mut nodes: Vec<(Position, u32)> = self.state.dirty_nodes.iter().copied().collect();
        self.state.dirty_nodes.clear();
        nodes.sort_by(|a, b| a.1.cmp(&b.1));

        for (pos, height) in nodes {
            let left = pos - (1 << height);
            let right = pos - 1;
            let digest = hasher.node_digest(
                pos,
                self.get_node_unchecked(left),
                self.get_node_unchecked(right),
            );
            let index = self.pos_to_index(pos);
            self.nodes[index] = digest;
        }
    }

    /// Process any pending batched updates, using parallel hash workers as long as the number of
    /// computations that can be parallelized exceeds `min_to_parallelize`.
    ///
    /// This implementation parallelizes the computation of digests across all nodes at the same
    /// height, starting from the bottom and working up to the peaks. If ever the number of
    /// remaining digest computations is less than the `min_to_parallelize`, it switches to the
    /// serial implementation.
    #[cfg(feature = "std")]
    fn merkleize_parallel(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        pool: ThreadPool,
        min_to_parallelize: usize,
    ) {
        let mut nodes: Vec<(Position, u32)> = self.state.dirty_nodes.iter().copied().collect();
        self.state.dirty_nodes.clear();
        // Sort by increasing height.
        nodes.sort_by(|a, b| a.1.cmp(&b.1));

        let mut same_height = Vec::new();
        let mut current_height = 1;
        for (i, (pos, height)) in nodes.iter().enumerate() {
            if *height == current_height {
                same_height.push(*pos);
                continue;
            }
            if same_height.len() < min_to_parallelize {
                self.state.dirty_nodes = nodes[i - same_height.len()..].iter().copied().collect();
                self.merkleize_serial(hasher);
                return;
            }
            self.update_node_digests(hasher, pool.clone(), &same_height, current_height);
            same_height.clear();
            current_height += 1;
            same_height.push(*pos);
        }

        if same_height.len() < min_to_parallelize {
            self.state.dirty_nodes = nodes[nodes.len() - same_height.len()..]
                .iter()
                .copied()
                .collect();
            self.merkleize_serial(hasher);
            return;
        }

        self.update_node_digests(hasher, pool, &same_height, current_height);
    }

    /// Update digests of the given set of nodes of equal height in the MMR. Since they are all at
    /// the same height, this can be done in parallel without synchronization.
    #[cfg(feature = "std")]
    fn update_node_digests(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        pool: ThreadPool,
        same_height: &[Position],
        height: u32,
    ) {
        let two_h = 1 << height;
        pool.install(|| {
            let computed_digests: Vec<(usize, D)> = same_height
                .par_iter()
                .map_init(
                    || hasher.fork(),
                    |hasher, &pos| {
                        let left = pos - two_h;
                        let right = pos - 1;
                        let digest = hasher.node_digest(
                            pos,
                            self.get_node_unchecked(left),
                            self.get_node_unchecked(right),
                        );
                        let index = self.pos_to_index(pos);
                        (index, digest)
                    },
                )
                .collect();

            for (index, digest) in computed_digests {
                self.nodes[index] = digest;
            }
        });
    }

    /// Mark the non-leaf nodes in the path from the given position to the root as dirty, so that
    /// their digests are appropriately recomputed during the next `merkleize`.
    fn mark_dirty(&mut self, pos: Position) {
        for (peak_pos, mut height) in self.peak_iterator() {
            if peak_pos < pos {
                continue;
            }

            // We have found the mountain containing the path we are looking for. Traverse it from
            // leaf to root, that way we can exit early if we hit a node that is already dirty.
            let path = PathIterator::new(pos, peak_pos, height)
                .collect::<Vec<_>>()
                .into_iter()
                .rev();
            height = 1;
            for (parent_pos, _) in path {
                if !self.state.dirty_nodes.insert((parent_pos, height)) {
                    break;
                }
                height += 1;
            }
            return;
        }

        panic!("invalid pos {pos}:{}", self.size());
    }

    /// Update the leaf at `loc` to `element`.
    pub fn update_leaf(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<(), Error> {
        self.update_leaf_batched(hasher, None, &[(loc, element)])
    }

    /// Batch update the digests of multiple retained leaves.
    ///
    /// # Errors
    ///
    /// Returns [Error::LeafOutOfBounds] if any location is not an existing leaf.
    /// Returns [Error::LocationOverflow] if any location exceeds [crate::mmr::MAX_LOCATION].
    /// Returns [Error::ElementPruned] if any of the leaves has been pruned.
    pub fn update_leaf_batched<T: AsRef<[u8]> + Sync>(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        pool: Option<ThreadPool>,
        updates: &[(Location, T)],
    ) -> Result<(), Error> {
        if updates.is_empty() {
            return Ok(());
        }

        let leaves = self.leaves();
        let mut positions = Vec::with_capacity(updates.len());
        for (loc, _) in updates {
            if *loc >= leaves {
                return Err(Error::LeafOutOfBounds(*loc));
            }
            let pos = Position::try_from(*loc)?;
            if pos < self.pruned_to_pos {
                return Err(Error::ElementPruned(pos));
            }
            positions.push(pos);
        }

        #[cfg(feature = "std")]
        if let Some(pool) = pool {
            if updates.len() >= MIN_TO_PARALLELIZE {
                self.update_leaf_parallel(hasher, pool, updates, &positions);
                return Ok(());
            }
        }

        for ((_, element), pos) in updates.iter().zip(positions.iter()) {
            // Update the digest of the leaf node and mark its ancestors as dirty.
            let digest = hasher.leaf_digest(*pos, element.as_ref());
            let index = self.pos_to_index(*pos);
            self.nodes[index] = digest;
            self.mark_dirty(*pos);
        }

        Ok(())
    }

    /// Batch update the digests of multiple retained leaves using multiple threads.
    #[cfg(feature = "std")]
    fn update_leaf_parallel<T: AsRef<[u8]> + Sync>(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        pool: ThreadPool,
        updates: &[(Location, T)],
        positions: &[Position],
    ) {
        pool.install(|| {
            let digests: Vec<(Position, D)> = updates
                .par_iter()
                .zip(positions.par_iter())
                .map_init(
                    || hasher.fork(),
                    |hasher, ((_, elem), pos)| {
                        let digest = hasher.leaf_digest(*pos, elem.as_ref());
                        (*pos, digest)
                    },
                )
                .collect();

            for (pos, digest) in digests {
                let index = self.pos_to_index(pos);
                self.nodes[index] = digest;
                self.mark_dirty(pos);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        hasher::{Hasher as _, Standard},
        stability::ROOTS,
    };
    use commonware_cryptography::{sha256, Hasher, Sha256};
    use commonware_runtime::{deterministic, tokio, RayonPoolSpawner, Runner};
    use commonware_utils::{hex, NZUsize};

    /// Build the MMR corresponding to the stability test `ROOTS` and confirm the roots match.
    fn build_and_check_test_roots_mmr(mmr: &mut CleanMmr<sha256::Digest>) {
        let mut hasher: Standard<Sha256> = Standard::new();
        for i in 0u64..199 {
            hasher.inner().update(&i.to_be_bytes());
            let element = hasher.inner().finalize();
            let root = *mmr.root();
            let expected_root = ROOTS[i as usize];
            assert_eq!(hex(&root), expected_root, "at: {i}");
            mmr.add(&mut hasher, &element);
        }
        assert_eq!(hex(mmr.root()), ROOTS[199], "Root after 200 elements");
    }

    /// Same as `build_and_check_test_roots` but uses `add` + `merkleize` instead of `add`.
    pub fn build_batched_and_check_test_roots(
        mut mmr: DirtyMmr<sha256::Digest>,
        pool: Option<ThreadPool>,
    ) {
        let mut hasher: Standard<Sha256> = Standard::new();
        for i in 0u64..199 {
            hasher.inner().update(&i.to_be_bytes());
            let element = hasher.inner().finalize();
            mmr.add(&mut hasher, &element);
        }
        let mmr = mmr.merkleize(&mut hasher, pool);
        assert_eq!(hex(mmr.root()), ROOTS[199], "Root after 200 elements");
    }

    /// Test empty MMR behavior.
    #[test]
    fn test_mem_mmr_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            assert_eq!(
                mmr.peak_iterator().next(),
                None,
                "empty iterator should have no peaks"
            );
            assert_eq!(mmr.size(), 0);
            assert_eq!(mmr.leaves(), Location::new_unchecked(0));
            assert_eq!(mmr.last_leaf_pos(), None);
            assert_eq!(mmr.oldest_retained_pos(), None);
            assert_eq!(mmr.get_node(Position::new(0)), None);
            assert_eq!(*mmr.root(), Mmr::empty_mmr_root(hasher.inner()));
            assert!(matches!(mmr.pop(&mut hasher), Err(Empty)));
            mmr.prune_all();
            assert_eq!(mmr.size(), 0, "prune_all on empty MMR should do nothing");

            assert_eq!(*mmr.root(), hasher.root(Position::new(0), [].iter()));
        });
    }

    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    #[test]
    fn test_mem_mmr_add_eleven_values() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<Position> = Vec::new();
            for _ in 0..11 {
                leaves.push(mmr.add(&mut hasher, &element));
                let peaks: Vec<(Position, u32)> = mmr.peak_iterator().collect();
                assert_ne!(peaks.len(), 0);
                assert!(peaks.len() as u64 <= mmr.size());
                let nodes_needing_parents = nodes_needing_parents(mmr.peak_iterator());
                assert!(nodes_needing_parents.len() <= peaks.len());
            }
            assert_eq!(mmr.oldest_retained_pos().unwrap(), Position::new(0));
            assert_eq!(mmr.size(), 19, "mmr not of expected size");
            assert_eq!(
                leaves,
                vec![0, 1, 3, 4, 7, 8, 10, 11, 15, 16, 18]
                    .into_iter()
                    .map(Position::new)
                    .collect::<Vec<_>>(),
                "mmr leaf positions not as expected"
            );
            let peaks: Vec<(Position, u32)> = mmr.peak_iterator().collect();
            assert_eq!(
                peaks,
                vec![
                    (Position::new(14), 3),
                    (Position::new(17), 1),
                    (Position::new(18), 0)
                ],
                "mmr peaks not as expected"
            );

            // Test nodes_needing_parents on the final MMR. Since there's a height gap between the
            // highest peak (14) and the next, only the lower two peaks (17, 18) should be returned.
            let peaks_needing_parents = nodes_needing_parents(mmr.peak_iterator());
            assert_eq!(
                peaks_needing_parents,
                vec![Position::new(17), Position::new(18)],
                "mmr nodes needing parents not as expected"
            );

            // verify leaf digests
            for leaf in leaves.iter().by_ref() {
                let digest = hasher.leaf_digest(*leaf, &element);
                assert_eq!(mmr.get_node(*leaf).unwrap(), digest);
            }

            // verify height=1 node digests
            let digest2 = hasher.node_digest(Position::new(2), &mmr.nodes[0], &mmr.nodes[1]);
            assert_eq!(mmr.nodes[2], digest2);
            let digest5 = hasher.node_digest(Position::new(5), &mmr.nodes[3], &mmr.nodes[4]);
            assert_eq!(mmr.nodes[5], digest5);
            let digest9 = hasher.node_digest(Position::new(9), &mmr.nodes[7], &mmr.nodes[8]);
            assert_eq!(mmr.nodes[9], digest9);
            let digest12 = hasher.node_digest(Position::new(12), &mmr.nodes[10], &mmr.nodes[11]);
            assert_eq!(mmr.nodes[12], digest12);
            let digest17 = hasher.node_digest(Position::new(17), &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], digest17);

            // verify height=2 node digests
            let digest6 = hasher.node_digest(Position::new(6), &mmr.nodes[2], &mmr.nodes[5]);
            assert_eq!(mmr.nodes[6], digest6);
            let digest13 = hasher.node_digest(Position::new(13), &mmr.nodes[9], &mmr.nodes[12]);
            assert_eq!(mmr.nodes[13], digest13);
            let digest17 = hasher.node_digest(Position::new(17), &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], digest17);

            // verify topmost digest
            let digest14 = hasher.node_digest(Position::new(14), &mmr.nodes[6], &mmr.nodes[13]);
            assert_eq!(mmr.nodes[14], digest14);

            // verify root
            let root = *mmr.root();
            let peak_digests = [digest14, digest17, mmr.nodes[18]];
            let expected_root = hasher.root(Position::new(19), peak_digests.iter());
            assert_eq!(root, expected_root, "incorrect root");

            // pruning tests
            mmr.prune_to_pos(Position::new(14)); // prune up to the tallest peak
            assert_eq!(mmr.oldest_retained_pos().unwrap(), Position::new(14));

            // After pruning, we shouldn't be able to generate a proof for any elements before the
            // pruning boundary. (To be precise, due to the maintenance of pinned nodes, we may in
            // fact still be able to generate them for some, but it's not guaranteed. For example,
            // in this case, we actually can still generate a proof for the node with location 7
            // even though it's pruned.)
            assert!(matches!(
                mmr.proof(Location::new_unchecked(0)),
                Err(ElementPruned(_))
            ));
            assert!(matches!(
                mmr.proof(Location::new_unchecked(6)),
                Err(ElementPruned(_))
            ));

            // We should still be able to generate a proof for any leaf following the pruning
            // boundary, the first of which is at location 8 and the last location 10.
            assert!(mmr.proof(Location::new_unchecked(8)).is_ok());
            assert!(mmr.proof(Location::new_unchecked(10)).is_ok());

            let root_after_prune = *mmr.root();
            assert_eq!(root, root_after_prune, "root changed after pruning");

            assert!(
                mmr.range_proof(Location::new_unchecked(5)..Location::new_unchecked(9))
                    .is_err(),
                "attempts to range_prove elements at or before the oldest retained should fail"
            );
            assert!(
                mmr.range_proof(Location::new_unchecked(8)..mmr.leaves()).is_ok(),
                "attempts to range_prove over all elements following oldest retained should succeed"
            );

            // Test that we can initialize a new MMR from another's elements.
            let oldest_pos = mmr.oldest_retained_pos().unwrap();
            let digests = mmr.node_digests_to_pin(oldest_pos);
            let mmr_copy = Mmr::init(
                Config {
                    nodes: mmr.nodes.iter().copied().collect(),
                    pruned_to_pos: oldest_pos,
                    pinned_nodes: digests,
                },
                &mut hasher,
            )
            .unwrap();
            assert_eq!(mmr_copy.size(), 19);
            assert_eq!(mmr_copy.leaves(), mmr.leaves());
            assert_eq!(mmr_copy.last_leaf_pos(), mmr.last_leaf_pos());
            assert_eq!(mmr_copy.oldest_retained_pos(), mmr.oldest_retained_pos());
            assert_eq!(*mmr_copy.root(), root);
        });
    }

    /// Test that pruning all nodes never breaks adding new nodes.
    #[test]
    fn test_mem_mmr_prune_all() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            for _ in 0..1000 {
                mmr.prune_all();
                mmr.add(&mut hasher, &element);
            }
        });
    }

    /// Test that the MMR validity check works as expected.
    #[test]
    fn test_mem_mmr_validity() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            for _ in 0..1001 {
                assert!(
                    mmr.size().is_mmr_size(),
                    "mmr of size {} should be valid",
                    mmr.size()
                );
                let old_size = mmr.size();
                mmr.add(&mut hasher, &element);
                for size in *old_size + 1..*mmr.size() {
                    assert!(
                        !Position::new(size).is_mmr_size(),
                        "mmr of size {size} should be invalid",
                    );
                }
            }
        });
    }

    /// Test that the MMR root computation remains stable by comparing against previously computed
    /// roots.
    #[test]
    fn test_mem_mmr_root_stability() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Test root stability under different MMR building methods.
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            build_and_check_test_roots_mmr(&mut mmr);

            let mut hasher: Standard<Sha256> = Standard::new();
            let mmr = CleanMmr::new(&mut hasher);
            build_batched_and_check_test_roots(mmr.into_dirty(), None);
        });
    }

    /// Test root stability using the parallel builder implementation. This requires we use the
    /// tokio runtime since the deterministic runtime would block due to being single-threaded.
    #[test]
    fn test_mem_mmr_root_stability_parallel() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let pool = context.create_pool(NZUsize!(4)).unwrap();
            let mut hasher: Standard<Sha256> = Standard::new();

            let mmr = Mmr::init(
                Config {
                    nodes: vec![],
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            )
            .unwrap();
            build_batched_and_check_test_roots(mmr.into_dirty(), Some(pool));
        });
    }

    /// Build the MMR corresponding to the stability test while pruning after each add, and confirm
    /// the static roots match that from the root computation.
    #[test]
    fn test_mem_mmr_root_stability_while_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = CleanMmr::new(&mut hasher);
            for i in 0u64..199 {
                let root = *mmr.root();
                let expected_root = ROOTS[i as usize];
                assert_eq!(hex(&root), expected_root, "at: {i}");
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                mmr.add(&mut hasher, &element);
                mmr.prune_all();
            }
        });
    }

    fn compute_big_mmr(
        hasher: &mut Standard<Sha256>,
        mut mmr: DirtyMmr<sha256::Digest>,
        pool: Option<ThreadPool>,
    ) -> (CleanMmr<sha256::Digest>, Vec<Position>) {
        let mut leaves = Vec::new();
        let mut c_hasher = Sha256::default();
        for i in 0u64..199 {
            c_hasher.update(&i.to_be_bytes());
            let element = c_hasher.finalize();
            let leaf_pos = mmr.size();
            mmr.add(hasher, &element);
            leaves.push(leaf_pos);
        }

        (mmr.merkleize(hasher, pool), leaves)
    }

    #[test]
    fn test_mem_mmr_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let (mut mmr, _) = compute_big_mmr(&mut hasher, Mmr::default(), None);
            let root = *mmr.root();
            let expected_root = ROOTS[199];
            assert_eq!(hex(&root), expected_root);

            // Pop off one node at a time until empty, confirming the root is still is as expected.
            for i in (0..199u64).rev() {
                assert!(mmr.pop(&mut hasher).is_ok());
                let root = *mmr.root();
                let expected_root = ROOTS[i as usize];
                assert_eq!(hex(&root), expected_root);
            }

            assert!(
                matches!(mmr.pop(&mut hasher).unwrap_err(), Empty),
                "pop on empty MMR should fail"
            );

            // Test that we can pop all elements up to and including the oldest retained leaf.
            for i in 0u64..199 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                mmr.add(&mut hasher, &element);
            }

            let leaf_pos = Position::try_from(Location::new_unchecked(100)).unwrap();
            mmr.prune_to_pos(leaf_pos);
            while mmr.size() > leaf_pos {
                mmr.pop(&mut hasher).unwrap();
            }
            assert_eq!(hex(mmr.root()), ROOTS[100]);
            let result = mmr.pop(&mut hasher);
            assert!(matches!(result, Err(ElementPruned(_))));
            assert_eq!(mmr.oldest_retained_pos(), None);
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (mut mmr, leaves) = compute_big_mmr(&mut hasher, Mmr::default(), None);
            let root = *mmr.root();

            // For a few leaves, update the leaf and ensure the root changes, and the root reverts
            // to its previous state then we update the leaf to its original value.
            for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
                // Change the leaf.
                let leaf_loc =
                    Location::try_from(leaves[leaf]).expect("leaf position should map to location");
                mmr.update_leaf(&mut hasher, leaf_loc, &element).unwrap();
                let updated_root = *mmr.root();
                assert!(root != updated_root);

                // Restore the leaf to its original value, ensure the root is as before.
                hasher.inner().update(&leaf.to_be_bytes());
                let element = hasher.inner().finalize();
                mmr.update_leaf(&mut hasher, leaf_loc, &element).unwrap();
                let restored_root = *mmr.root();
                assert_eq!(root, restored_root);
            }

            // Confirm the tree has all the hashes necessary to update any element after pruning.
            mmr.prune_to_pos(leaves[150]);
            for &leaf_pos in &leaves[150..=190] {
                mmr.prune_to_pos(leaf_pos);
                let leaf_loc =
                    Location::try_from(leaf_pos).expect("leaf position should map to location");
                mmr.update_leaf(&mut hasher, leaf_loc, &element).unwrap();
            }
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf_error_out_of_bounds() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (mut mmr, _) = compute_big_mmr(&mut hasher, Mmr::default(), None);
            let invalid_loc = mmr.leaves();
            let result = mmr.update_leaf(&mut hasher, invalid_loc, &element);
            assert!(matches!(result, Err(Error::LeafOutOfBounds(_))));
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf_error_pruned() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (mut mmr, _) = compute_big_mmr(&mut hasher, Mmr::default(), None);
            mmr.prune_all();
            let result = mmr.update_leaf(&mut hasher, Location::new_unchecked(0), &element);
            assert!(matches!(result, Err(Error::ElementPruned(_))));
        });
    }

    #[test]
    fn test_mem_mmr_batch_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let (mmr, leaves) = compute_big_mmr(&mut hasher, Mmr::default(), None);
            do_batch_update(&mut hasher, mmr, &leaves);
        });
    }

    /// Same test as above only using a thread pool to trigger parallelization. This requires we use
    /// tokio runtime instead of the deterministic one.
    #[test]
    fn test_mem_mmr_batch_parallel_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = tokio::Runner::default();
        executor.start(|ctx| async move {
            let pool = ctx.create_pool(NZUsize!(4)).unwrap();
            let mmr = Mmr::init(
                Config {
                    nodes: Vec::new(),
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: Vec::new(),
                },
                &mut hasher,
            )
            .unwrap();
            let (mmr, leaves) = compute_big_mmr(&mut hasher, mmr.into_dirty(), Some(pool));
            do_batch_update(&mut hasher, mmr, &leaves);
        });
    }

    fn do_batch_update(
        hasher: &mut Standard<Sha256>,
        mmr: CleanMmr<sha256::Digest>,
        leaves: &[Position],
    ) {
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let root = *mmr.root();

        // Change a handful of leaves using a batch update.
        let mut updates = Vec::new();
        for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
            let leaf_loc =
                Location::try_from(leaves[leaf]).expect("leaf position should map to location");
            updates.push((leaf_loc, &element));
        }
        let mut dirty_mmr = mmr.into_dirty();
        dirty_mmr
            .update_leaf_batched(hasher, None, &updates)
            .unwrap();

        let mmr = dirty_mmr.merkleize(hasher, None);
        let updated_root = *mmr.root();
        assert_eq!(
            "af3acad6aad59c1a880de643b1200a0962a95d06c087ebf677f29eb93fc359a4",
            hex(&updated_root)
        );

        // Batch-restore the changed leaves to their original values.
        let mut updates = Vec::new();
        for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
            hasher.inner().update(&leaf.to_be_bytes());
            let element = hasher.inner().finalize();
            let leaf_loc =
                Location::try_from(leaves[leaf]).expect("leaf position should map to location");
            updates.push((leaf_loc, element));
        }
        let mut dirty_mmr = mmr.into_dirty();
        dirty_mmr
            .update_leaf_batched(hasher, None, &updates)
            .unwrap();

        let mmr = dirty_mmr.merkleize(hasher, None);
        let restored_root = *mmr.root();
        assert_eq!(root, restored_root);
    }

    #[test]
    fn test_init_pinned_nodes_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            // Test with empty config - should succeed
            let config = Config::<sha256::Digest> {
                nodes: vec![],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with too few pinned nodes - should fail
            // Use a valid MMR size (127 is valid: 2^7 - 1 makes a complete tree)
            let config = Config::<sha256::Digest> {
                nodes: vec![],
                pruned_to_pos: Position::new(127),
                pinned_nodes: vec![], // Should have nodes for position 127
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidPinnedNodes)
            ));

            // Test with too many pinned nodes - should fail
            let config = Config {
                nodes: vec![],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![Sha256::hash(b"dummy")],
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidPinnedNodes)
            ));

            // Test with correct number of pinned nodes - should succeed
            // Build a small MMR to get valid pinned nodes
            let mut mmr = CleanMmr::new(&mut hasher);
            for i in 0u64..50 {
                mmr.add(&mut hasher, &i.to_be_bytes());
            }
            let pinned_nodes = mmr.node_digests_to_pin(Position::new(50));
            let config = Config {
                nodes: vec![],
                pruned_to_pos: Position::new(50),
                pinned_nodes,
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());
        });
    }

    #[test]
    fn test_init_size_validation() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            // Test with valid size 0 - should succeed
            let config = Config::<sha256::Digest> {
                nodes: vec![],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with invalid size 2 - should fail
            // Size 2 is invalid (can't have just one parent node + one leaf)
            let config = Config {
                nodes: vec![Sha256::hash(b"node1"), Sha256::hash(b"node2")],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));

            // Test with valid size 3 (one full tree with 2 leaves) - should succeed
            let config = Config {
                nodes: vec![
                    Sha256::hash(b"leaf1"),
                    Sha256::hash(b"leaf2"),
                    Sha256::hash(b"parent"),
                ],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with large valid size (127 = 2^7 - 1, a complete tree) - should succeed
            // Build a real MMR to get the correct structure
            let mut mmr = CleanMmr::new(&mut hasher);
            for i in 0u64..64 {
                mmr.add(&mut hasher, &i.to_be_bytes());
            }
            assert_eq!(mmr.size(), 127); // Verify we have the expected size
            let nodes: Vec<_> = (0..127)
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();

            let config = Config {
                nodes,
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Test with non-zero pruned_to_pos - should succeed
            // Build a small MMR (11 leaves -> 19 nodes), prune it, then init from that state
            let mut mmr = CleanMmr::new(&mut hasher);
            for i in 0u64..11 {
                mmr.add(&mut hasher, &i.to_be_bytes());
            }
            assert_eq!(mmr.size(), 19); // 11 leaves = 19 total nodes

            // Prune to position 7
            mmr.prune_to_pos(Position::new(7));
            let nodes: Vec<_> = (7..*mmr.size())
                .map(|i| *mmr.get_node_unchecked(Position::new(i)))
                .collect();
            let pinned_nodes = mmr.node_digests_to_pin(Position::new(7));

            let config = Config {
                nodes: nodes.clone(),
                pruned_to_pos: Position::new(7),
                pinned_nodes: pinned_nodes.clone(),
            };
            assert!(Mmr::init(config, &mut hasher).is_ok());

            // Same nodes but wrong pruned_to_pos - should fail
            // pruned_to_pos=8 + 12 nodes = size 20 (invalid)
            let config = Config {
                nodes: nodes.clone(),
                pruned_to_pos: Position::new(8),
                pinned_nodes: pinned_nodes.clone(),
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));

            // Same nodes but different wrong pruned_to_pos - should fail
            // pruned_to_pos=9 + 12 nodes = size 21 (invalid)
            let config = Config {
                nodes,
                pruned_to_pos: Position::new(9),
                pinned_nodes,
            };
            assert!(matches!(
                Mmr::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));
        });
    }
}
