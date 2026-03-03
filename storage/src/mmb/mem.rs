//! A basic, no_std compatible MMB where all nodes are stored in-memory.

use crate::mmb::{
    hasher::Hasher,
    iterator::{
        child_steps, children, leaves_for_size, nodes_to_pin, peak_birth_step, step_to_pos,
        PeakIterator,
    },
    Error::{self, *},
    Location, Position,
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
        /// Placeholder for no_std builds where parallelism is unavailable.
        // TODO(#3001): Migrate to commonware-parallel
        pub struct ThreadPool;
    }
}

/// Minimum number of digest computations required during batch updates to trigger parallelization.
#[cfg(feature = "std")]
const MIN_TO_PARALLELIZE: usize = 20;

/// An MMB whose root digest has not been computed.
pub type DirtyMmb<D> = Mmb<D, Dirty>;

/// An MMB whose root digest has been computed.
pub type CleanMmb<D> = Mmb<D, Clean<D>>;

/// Sealed trait for MMB state types.
mod private {
    pub trait Sealed {}
}

/// Trait for valid MMB state types.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {}

/// Marker type for an MMB whose root digest has been computed.
#[derive(Clone, Copy, Debug)]
pub struct Clean<D: Digest> {
    /// The root digest of the MMB.
    pub root: D,
}

impl<D: Digest> private::Sealed for Clean<D> {}
impl<D: Digest> State<D> for Clean<D> {}

/// Marker type for a dirty MMB (root digest not computed).
#[derive(Clone, Debug, Default)]
pub struct Dirty {
    /// Non-leaf nodes that need to have their digests recomputed due to a batched update operation.
    ///
    /// This is a set of tuples of the form (node_pos, height).
    dirty_nodes: BTreeSet<(Position, u32)>,
}

impl private::Sealed for Dirty {}
impl<D: Digest> State<D> for Dirty {}

/// Configuration for initializing an [Mmb].
pub struct Config<D: Digest> {
    /// The retained nodes of the MMB.
    pub nodes: Vec<D>,

    /// The highest position for which this MMB has been pruned, or 0 if this MMB has never been
    /// pruned.
    pub pruned_to_pos: Position,

    /// The pinned nodes of the MMB, in the order expected by `nodes_to_pin`.
    pub pinned_nodes: Vec<D>,
}

/// A basic MMB where all nodes are stored in-memory.
///
/// # Terminology
///
/// Nodes in this structure are either _retained_, _pruned_, or _pinned_. Retained nodes are nodes
/// that have not yet been pruned, and have digests stored explicitly within the tree structure.
/// Pruned nodes are those whose positions precede that of the _oldest retained_ node, for which no
/// digests are maintained. Pinned nodes are nodes that would otherwise be pruned based on their
/// position, but whose digests remain required for proof generation. The digests for pinned nodes
/// are stored in an auxiliary map, and are at most O(log^2(n)) in number.
///
/// # Max Capacity
///
/// The maximum number of elements that can be stored is usize::MAX (u32::MAX on 32-bit
/// architectures).
///
/// # Type States
///
/// The MMB uses the type-state pattern to enforce at compile-time whether the MMB has pending
/// updates that must be merkleized before computing proofs. [CleanMmb] represents a clean
/// MMB whose root digest has been computed. [DirtyMmb] represents a dirty MMB whose root
/// digest needs to be computed. A dirty MMB can be converted into a clean MMB by calling
/// [DirtyMmb::merkleize].
#[derive(Clone, Debug)]
pub struct Mmb<D: Digest, S: State<D> = Dirty> {
    /// The nodes of the MMB, appended in insertion order. Each step appends a leaf and
    /// optionally a merge parent, so nodes from different logical trees may be interleaved.
    nodes: VecDeque<D>,

    /// The highest position for which this MMB has been pruned, or 0 if this MMB has never been
    /// pruned.
    pruned_to_pos: Position,

    /// The auxiliary map from node position to the digest of any pinned node.
    pinned_nodes: BTreeMap<Position, D>,

    /// Type-state for the MMB.
    state: S,
}

impl<D: Digest> Default for DirtyMmb<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<D: Digest> From<CleanMmb<D>> for DirtyMmb<D> {
    fn from(clean: CleanMmb<D>) -> Self {
        DirtyMmb {
            nodes: clean.nodes,
            pruned_to_pos: clean.pruned_to_pos,
            pinned_nodes: clean.pinned_nodes,
            state: Dirty {
                dirty_nodes: BTreeSet::new(),
            },
        }
    }
}

impl<D: Digest, S: State<D>> Mmb<D, S> {
    /// Return the total number of nodes in the MMB, irrespective of any pruning. The next added
    /// element's position will have this value.
    pub fn size(&self) -> Position {
        Position::new(self.nodes.len() as u64 + *self.pruned_to_pos)
    }

    /// Return the total number of leaves in the MMB.
    pub fn leaves(&self) -> Location {
        leaves_for_size(*self.size())
            .map(Location::new)
            .expect("invalid mmb size")
    }

    /// Return the position of the last leaf in this MMB, or None if the MMB is empty.
    pub fn last_leaf_pos(&self) -> Option<Position> {
        if self.size() == 0 {
            return None;
        }

        Some(PeakIterator::last_leaf_pos(self.size()))
    }

    /// Returns [start, end) where `start` and `end - 1` are the positions of the oldest and newest
    /// retained nodes respectively.
    pub fn bounds(&self) -> Range<Position> {
        self.pruned_to_pos..self.size()
    }

    /// Return a new iterator over the peaks of the MMB.
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

    /// Return the index of the element in the current nodes vector given its position in the MMB.
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

    /// Utility used by stores that build on the mem MMB to pin extra nodes if needed. It's up to
    /// the caller to ensure that this set of pinned nodes is valid for their use case.
    #[cfg(any(feature = "std", test))]
    #[allow(dead_code)]
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: BTreeMap<Position, D>) {
        for (pos, node) in pinned_nodes.into_iter() {
            self.pinned_nodes.insert(pos, node);
        }
    }
}

/// Implementation for Clean MMB state.
impl<D: Digest> CleanMmb<D> {
    /// Return an [Mmb] initialized with the given `config`.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPinnedNodes] if the number of pinned nodes doesn't match the expected
    /// count for `config.pruned_to_pos`.
    ///
    /// Returns [Error::InvalidSize] if the MMB size is invalid.
    pub fn init(config: Config<D>, hasher: &mut impl Hasher<Digest = D>) -> Result<Self, Error> {
        // Validate that the total size is valid
        let Some(size) = config.pruned_to_pos.checked_add(config.nodes.len() as u64) else {
            return Err(Error::InvalidSize(u64::MAX));
        };
        if !size.is_valid_size() {
            return Err(Error::InvalidSize(*size));
        }

        // Validate and populate pinned nodes
        let expected_pins = nodes_to_pin(size, config.pruned_to_pos);
        if config.pinned_nodes.len() != expected_pins.len() {
            return Err(Error::InvalidPinnedNodes);
        }
        let mut pinned_nodes = BTreeMap::new();
        for (i, pos) in expected_pins.into_iter().enumerate() {
            pinned_nodes.insert(pos, config.pinned_nodes[i]);
        }

        let mmb = Mmb {
            nodes: VecDeque::from(config.nodes),
            pruned_to_pos: config.pruned_to_pos,
            pinned_nodes,
            state: Dirty::default(),
        };
        Ok(mmb.merkleize(hasher, None))
    }

    /// Create a new, empty MMB in the Clean state.
    pub fn new(hasher: &mut impl Hasher<Digest = D>) -> Self {
        let mmb: DirtyMmb<D> = Default::default();
        mmb.merkleize(hasher, None)
    }

    /// Re-initialize the MMB with the given nodes, pruned_to_pos, and pinned_nodes.
    pub fn from_components(
        hasher: &mut impl Hasher<Digest = D>,
        nodes: Vec<D>,
        pruned_to_pos: Position,
        pinned_nodes: Vec<D>,
    ) -> Self {
        DirtyMmb::from_components(nodes, pruned_to_pos, pinned_nodes).merkleize(hasher, None)
    }

    /// Return the requested node or None if it is not stored in the MMB.
    pub fn get_node(&self, pos: Position) -> Option<D> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }

        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Get the nodes (position + digest) that need to be pinned (those required for proof
    /// generation) in this MMB when pruned to position `prune_pos`.
    pub(crate) fn nodes_to_pin(&self, prune_pos: Position) -> BTreeMap<Position, D> {
        nodes_to_pin(self.size(), prune_pos)
            .into_iter()
            .map(|pos| (pos, *self.get_node_unchecked(pos)))
            .collect()
    }

    /// Prune all nodes up to but not including the given position, and pin the nodes
    /// required for re-merkleization of any retained leaf.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPosition] if `pos` is before the current pruning boundary or
    /// beyond the MMB size.
    pub fn prune_to_pos(&mut self, pos: Position) -> Result<(), Error> {
        if pos < self.pruned_to_pos || pos > self.size() {
            return Err(Error::InvalidPosition(pos));
        }

        if pos == self.pruned_to_pos {
            return Ok(());
        }

        self.pinned_nodes = self.nodes_to_pin(pos);
        let retained_nodes = self.pos_to_index(pos);
        self.nodes.drain(0..retained_nodes);
        self.pruned_to_pos = pos;
        Ok(())
    }

    /// Prune all nodes and pin the nodes required for re-merkleization of any retained leaf.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            let pos = self.index_to_pos(self.nodes.len());
            self.prune_to_pos(pos).expect("pos is always valid");
        }
    }

    /// Change the digest of any retained leaf. This is useful if you want to use the MMB
    /// implementation as an updatable binary Merkle tree, and otherwise should be avoided.
    ///
    /// # Errors
    ///
    /// Returns [Error::LeafOutOfBounds] if `loc` is not an existing leaf.
    /// Returns [Error::ElementPruned] if the leaf has been pruned.
    ///
    /// # Warning
    ///
    /// This method will change the root and invalidate any previous inclusion proofs.
    pub fn update_leaf(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        loc: Location,
        element: &[u8],
    ) -> Result<(), Error> {
        let mut dirty_mmb = mem::replace(self, Self::new(hasher)).into_dirty();
        let result = dirty_mmb.update_leaf(hasher, loc, element);
        *self = dirty_mmb.merkleize(hasher, None);
        result
    }

    /// Convert this Clean MMB into a Dirty MMB without making any changes to it.
    pub fn into_dirty(self) -> DirtyMmb<D> {
        self.into()
    }

    /// Get the root digest of the MMB.
    pub const fn root(&self) -> &D {
        &self.state.root
    }

    /// Returns the root that would be produced by calling `root` on an empty MMB.
    pub fn empty_mmb_root(hasher: &mut impl commonware_cryptography::Hasher<Digest = D>) -> D {
        hasher.update(&0u64.to_be_bytes());
        hasher.finalize()
    }
}

/// Implementation for Dirty MMB state.
impl<D: Digest> DirtyMmb<D> {
    /// Return a new (empty) `Mmb`.
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            pruned_to_pos: Position::new(0),
            pinned_nodes: BTreeMap::new(),
            state: Dirty::default(),
        }
    }

    /// Re-initialize the MMB with the given nodes, pruned_to_pos, and pinned_nodes.
    pub fn from_components(nodes: Vec<D>, pruned_to_pos: Position, pinned_nodes: Vec<D>) -> Self {
        let size = Position::new(nodes.len() as u64 + *pruned_to_pos);
        let pins = nodes_to_pin(size, pruned_to_pos);
        Self {
            nodes: VecDeque::from(nodes),
            pruned_to_pos,
            pinned_nodes: pins
                .into_iter()
                .enumerate()
                .map(|(i, pos)| (pos, pinned_nodes[i]))
                .collect(),
            state: Dirty::default(),
        }
    }

    /// Add `digest` as a new leaf in the MMB, returning its position.
    ///
    /// The leaf is always appended at `size()`. After appending, if any adjacent same-height peak
    /// pair exists, the rightmost such pair is merged by appending one parent node.
    pub(crate) fn add_leaf_digest(&mut self, digest: D) -> Position {
        let n = self.leaves().as_u64();

        // Compute the merge height in O(1) from the leaf count. The peak heights are determined
        // by the bits of N+1, and adjacent equal-height peaks occur at a single predictable
        // position in the bit pattern.
        let merge_height = if n == 0 {
            None
        } else if n & 1 == 1 {
            // Odd N: newest peak is h=0, new leaf pairs with it.
            Some(1)
        } else {
            // Even N: check for an existing same-height pair. The pair occurs where the
            // trailing 1-bits of N+1 end, provided that position is within the peak range.
            let np1 = n + 1;
            let k = np1.trailing_ones();
            if k < np1.ilog2() {
                Some(k + 1)
            } else {
                None
            }
        };

        // 1. Append the new leaf.
        let leaf_pos = self.size();
        self.nodes.push_back(digest);

        // 2. Append the parent (if a merge was triggered).
        if let Some(height) = merge_height {
            let parent_pos = self.size();
            self.nodes.push_back(D::EMPTY);
            self.state.dirty_nodes.insert((parent_pos, height));
        }

        leaf_pos
    }

    /// Overwrite the digest of an existing leaf and mark its ancestors as dirty.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidPosition] if `loc` is not an existing leaf.
    /// Returns [Error::ElementPruned] if the leaf has been pruned.
    #[cfg(any(feature = "std", test))]
    #[allow(dead_code)]
    pub(crate) fn update_leaf_digest(&mut self, loc: Location, digest: D) -> Result<(), Error> {
        let pos = Position::try_from(loc).map_err(|_| Error::InvalidPosition(Position::new(0)))?;
        if pos >= self.size() {
            return Err(Error::InvalidPosition(pos));
        }
        if pos < self.pruned_to_pos {
            return Err(Error::ElementPruned(pos));
        }
        let index = self.pos_to_index(pos);
        self.nodes[index] = digest;
        self.mark_dirty(loc);
        Ok(())
    }

    /// Add `element` to the MMB and return its position.
    /// The element can be an arbitrary byte slice, and need not be converted to a digest first.
    pub fn add<H: Hasher<Digest = D>>(&mut self, hasher: &mut H, element: &[u8]) -> Position {
        let digest = hasher.leaf_digest(self.size(), element);
        self.add_leaf_digest(digest)
    }

    /// Pop the most recent leaf element out of the MMB if it exists, returning Empty or
    /// ElementPruned errors otherwise.
    pub fn pop(&mut self) -> Result<Position, Error> {
        if self.size() == 0 {
            return Err(Empty);
        }

        // Calculate the exact size of an MMB with N - 1 leaves.
        let new_leaves = self.leaves().as_u64() - 1;
        let new_size = Position::new(2 * new_leaves - (new_leaves + 1).ilog2() as u64);

        if new_size < self.pruned_to_pos {
            return Err(ElementPruned(new_size));
        }

        let num_to_drain = *(self.size() - new_size) as usize;
        self.nodes.drain(self.nodes.len() - num_to_drain..);

        // Remove dirty nodes that are now out of bounds.
        let cutoff = (self.size(), 0);
        self.state.dirty_nodes.split_off(&cutoff);

        Ok(self.size())
    }

    /// Compute updated digests for dirty nodes and compute the root, converting this MMB into a
    /// [CleanMmb].
    pub fn merkleize(
        mut self,
        hasher: &mut impl Hasher<Digest = D>,
        #[cfg_attr(not(feature = "std"), allow(unused_variables))] pool: Option<ThreadPool>,
    ) -> CleanMmb<D> {
        #[cfg(feature = "std")]
        match (pool, self.state.dirty_nodes.len() >= MIN_TO_PARALLELIZE) {
            (Some(pool), true) => self.merkleize_parallel(hasher, pool, MIN_TO_PARALLELIZE),
            _ => self.merkleize_serial(hasher),
        }

        #[cfg(not(feature = "std"))]
        self.merkleize_serial(hasher);

        // Compute root by folding peaks oldest-first (iterator yields newest-first).
        let peak_digests: Vec<_> = self
            .peak_iterator()
            .map(|(peak_pos, _)| *self.get_node_unchecked(peak_pos))
            .collect();
        let digest = hasher.root(self.leaves(), peak_digests.iter().rev());

        CleanMmb {
            nodes: self.nodes,
            pruned_to_pos: self.pruned_to_pos,
            pinned_nodes: self.pinned_nodes,
            state: Clean { root: digest },
        }
    }

    fn merkleize_serial(&mut self, hasher: &mut impl Hasher<Digest = D>) {
        let mut nodes: Vec<(Position, u32)> = self.state.dirty_nodes.iter().copied().collect();
        self.state.dirty_nodes.clear();
        nodes.sort_by_key(|a| a.1);

        for (pos, height) in nodes {
            let (left, right) = children(pos, height);
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
        nodes.sort_by_key(|a| a.1);

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
            current_height = *height;
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

    /// Update digests of the given set of nodes of equal height in the MMB. Since they are all at
    /// the same height, this can be done in parallel without synchronization.
    #[cfg(feature = "std")]
    fn update_node_digests(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        pool: ThreadPool,
        same_height: &[Position],
        height: u32,
    ) {
        pool.install(|| {
            let computed_digests: Vec<(usize, D)> = same_height
                .par_iter()
                .map_init(
                    || hasher.fork(),
                    |hasher, &pos| {
                        let (left, right) = children(pos, height);
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

    /// Mark the non-leaf nodes in the path from the given leaf location to the root as dirty.
    fn mark_dirty(&mut self, loc: Location) {
        let target_loc = loc.as_u64();

        // 1. Find the peak that covers this leaf and compute its birth step.
        let mut end_leaf_cursor = self.leaves().as_u64();
        let mut covering = None;

        for (_, height) in self.peak_iterator() {
            let leaves_in_peak = 1u64 << height;
            let start_leaf_cursor = end_leaf_cursor - leaves_in_peak;

            if target_loc >= start_leaf_cursor {
                // Compute the peak's birth step from the leaf range.
                let last_leaf = end_leaf_cursor - 1;
                let step = peak_birth_step(last_leaf, height);
                covering = Some((step, height, start_leaf_cursor));
                break;
            }
            end_leaf_cursor = start_leaf_cursor;
        }

        let (mut step, mut height, mut leaf_start) = covering.expect("leaf must be under a peak");

        // 2. Walk top-down using child_steps (direct arithmetic, no parent_birth_step
        //    inversion), collecting the path. Then insert bottom-up with early exit: once we
        //    hit an already-dirty ancestor, all nodes above it are guaranteed dirty.
        let mut path = [(Position::new(0), 0u32); 64];
        let mut path_len = 0;

        while height > 0 {
            let pos = step_to_pos(step, false);
            path[path_len] = (pos, height);
            path_len += 1;

            let (left_step, right_step) = child_steps(step, height);
            height -= 1;

            let leaves_in_half = 1u64 << height;
            let mid_point = leaf_start + leaves_in_half;

            if target_loc < mid_point {
                step = left_step;
            } else {
                step = right_step;
                leaf_start = mid_point;
            }
        }

        // Insert bottom-up (reverse of collection order) with early exit.
        for &(pos, h) in path[..path_len].iter().rev() {
            if !self.state.dirty_nodes.insert((pos, h)) {
                break;
            }
        }
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
    /// Returns [Error::ElementPruned] if any of the leaves has been pruned.
    pub fn update_leaf_batched<T: AsRef<[u8]> + Sync>(
        &mut self,
        hasher: &mut impl Hasher<Digest = D>,
        #[cfg_attr(not(feature = "std"), allow(unused_variables))] pool: Option<ThreadPool>,
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
            // Safe: loc < leaves guarantees loc is a valid location.
            let pos = Position::try_from(*loc).expect("valid location");
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

        for ((loc, element), pos) in updates.iter().zip(positions.iter()) {
            // Update the digest of the leaf node and mark its ancestors as dirty.
            let digest = hasher.leaf_digest(*pos, element.as_ref());
            let index = self.pos_to_index(*pos);
            self.nodes[index] = digest;
            self.mark_dirty(*loc);
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
            let digests: Vec<(Location, Position, D)> = updates
                .par_iter()
                .zip(positions.par_iter())
                .map_init(
                    || hasher.fork(),
                    |hasher, ((loc, elem), pos)| {
                        let digest = hasher.leaf_digest(*pos, elem.as_ref());
                        (*loc, *pos, digest)
                    },
                )
                .collect();

            for (loc, pos, digest) in digests {
                let index = self.pos_to_index(pos);
                self.nodes[index] = digest;
                self.mark_dirty(loc);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmb::hasher::{Hasher as _, Standard};
    use commonware_cryptography::{sha256, Hasher, Sha256};
    use commonware_runtime::{deterministic, tokio, Runner, ThreadPooler};
    use commonware_utils::NZUsize;

    /// Build a test MMB by adding `elements` leaves, where leaf i has value hash(i).
    fn build_test_mmb<H: super::Hasher<Digest = sha256::Digest>>(
        hasher: &mut H,
        mmb: CleanMmb<sha256::Digest>,
        elements: u64,
    ) -> CleanMmb<sha256::Digest> {
        let mut mmb = mmb.into_dirty();
        for i in 0u64..elements {
            hasher.inner().update(&i.to_be_bytes());
            let element = hasher.inner().finalize();
            mmb.add(hasher, &element);
        }
        mmb.merkleize(hasher, None)
    }

    /// Test empty MMB behavior.
    #[test]
    fn test_mem_mmb_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mmb = CleanMmb::new(&mut hasher);
            assert_eq!(
                mmb.peak_iterator().next(),
                None,
                "empty iterator should have no peaks"
            );
            assert_eq!(mmb.size(), 0);
            assert_eq!(mmb.leaves(), 0u64);
            assert_eq!(mmb.last_leaf_pos(), None);
            assert!(mmb.bounds().is_empty());
            assert_eq!(mmb.get_node(Position::new(0)), None);
            assert_eq!(*mmb.root(), Mmb::empty_mmb_root(hasher.inner()));
            let mut mmb = mmb.into_dirty();
            assert!(matches!(mmb.pop(), Err(Empty)));
            let mmb = mmb.merkleize(&mut hasher, None);

            assert_eq!(
                *mmb.root(),
                hasher.root(Location::new(0), [].iter())
            );
        });
    }

    /// Test MMB building by consecutively adding 8 equal elements, producing the exact structure
    /// documented in `mmb/mod.rs`:
    ///
    /// ```text
    ///    Height
    ///      2        6
    ///             /   \
    ///      1     2     5      9      12
    ///           / \   / \    / \    /  \
    ///      0   0   1 3   4  7   8 10  11
    ///
    /// Location 0   1 2   3  4   5  6   7
    /// ```
    #[test]
    fn test_mem_mmb_add_eight_values() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmb = DirtyMmb::new();
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<Position> = Vec::new();
            for _ in 0..8 {
                leaves.push(mmb.add(&mut hasher, &element));
                let peaks: Vec<(Position, u32)> = mmb.peak_iterator().collect();
                assert_ne!(peaks.len(), 0);
                assert!(peaks.len() as u64 <= mmb.size());
            }
            let mmb = mmb.merkleize(&mut hasher, None);
            assert_eq!(mmb.bounds().start, Position::new(0));
            assert_eq!(mmb.size(), 13, "mmb not of expected size");
            assert_eq!(mmb.leaves(), 8u64);

            // Verify leaf positions match the documented structure.
            // Leaf N has physical index 2*N - ilog2(N+1).
            assert_eq!(
                leaves,
                vec![0, 1, 3, 4, 6, 8, 10, 11]
                    .into_iter()
                    .map(Position::new)
                    .collect::<Vec<_>>(),
                "mmb leaf positions not as expected"
            );

            // Verify all leaf positions round-trip through Location.
            for (i, leaf) in leaves.iter().enumerate() {
                let loc = Location::try_from(*leaf).unwrap();
                assert_eq!(*loc, i as u64);
            }

            // Verify peaks match the documented structure (newest-first order).
            let peaks: Vec<(Position, u32)> = mmb.peak_iterator().collect();
            assert_eq!(
                peaks,
                vec![
                    (Position::new(12), 1),
                    (Position::new(9), 1),
                    (Position::new(7), 2)
                ],
                "mmb peaks not as expected"
            );

            // Verify leaf digests.
            for leaf in leaves.iter() {
                let digest = hasher.leaf_digest(*leaf, &element);
                assert_eq!(mmb.get_node(*leaf).unwrap(), digest);
            }

            // Verify height-1 node digests (children found via delay matrix).
            // Parent at pos 2 (step 1): children are leaves at pos 0 and 1.
            let digest2 = hasher.node_digest(Position::new(2), &mmb.nodes[0], &mmb.nodes[1]);
            assert_eq!(mmb.nodes[2], digest2);
            // Parent at pos 5 (step 3): children are leaves at pos 3 and 4.
            let digest5 = hasher.node_digest(Position::new(5), &mmb.nodes[3], &mmb.nodes[4]);
            assert_eq!(mmb.nodes[5], digest5);
            // Parent at pos 9 (step 5): children are leaves at pos 6 and 8.
            let digest9 = hasher.node_digest(Position::new(9), &mmb.nodes[6], &mmb.nodes[8]);
            assert_eq!(mmb.nodes[9], digest9);
            // Parent at pos 12 (step 7): children are leaves at pos 10 and 11.
            let digest12 = hasher.node_digest(Position::new(12), &mmb.nodes[10], &mmb.nodes[11]);
            assert_eq!(mmb.nodes[12], digest12);

            // Verify height-2 node digest.
            // Parent at pos 7 (step 4): children are parents at pos 2 and 5.
            let digest7 = hasher.node_digest(Position::new(7), &mmb.nodes[2], &mmb.nodes[5]);
            assert_eq!(mmb.nodes[7], digest7);

            // Verify root matches hash structure (peaks folded oldest-first).
            let root = *mmb.root();
            let peak_digests = [digest7, digest9, digest12];
            let expected_root = hasher.root(Location::new(8), peak_digests.iter());
            assert_eq!(root, expected_root, "incorrect root");

            // Verify that the two newest peaks are same-height, so adding a 9th leaf triggers a merge.
            assert_eq!(peaks[0].1, peaks[1].1);
        });
    }

    /// Test that pruning all nodes never breaks adding new nodes.
    #[test]
    fn test_mem_mmb_prune_all() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmb = CleanMmb::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            for _ in 0..1000 {
                mmb.prune_all();
                let mut dirty = mmb.into_dirty();
                dirty.add(&mut hasher, &element);
                mmb = dirty.merkleize(&mut hasher, None);
            }
        });
    }

    /// Test that pruning after each add does not affect root computation.
    #[test]
    fn test_mem_mmb_root_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut reference_mmb = DirtyMmb::new();
            let mut mmb = DirtyMmb::new();
            for i in 0u64..200 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                reference_mmb.add(&mut hasher, &element);
                mmb.add(&mut hasher, &element);

                // Merkleize both to compare roots
                let reference_mmb_clean = reference_mmb.merkleize(&mut hasher, None);
                let mut mmb_clean = mmb.merkleize(&mut hasher, None);
                mmb_clean.prune_all();
                assert_eq!(mmb_clean.root(), reference_mmb_clean.root());

                reference_mmb = reference_mmb_clean.into_dirty();
                mmb = mmb_clean.into_dirty();
            }
        });
    }

    /// Test that incrementally advancing the prune boundary preserves the root.
    #[test]
    fn test_mem_mmb_incremental_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mmb = CleanMmb::new(&mut hasher);
            let mut mmb = build_test_mmb(&mut hasher, mmb, 200);
            let root = *mmb.root();

            // Advance the prune boundary in steps, confirming the root never changes.
            for prune_pos in [10, 25, 50, 100, 150, 199, 200] {
                let pos = Position::try_from(Location::new(prune_pos)).unwrap();
                mmb.prune_to_pos(pos).unwrap();
                assert_eq!(
                    *mmb.root(),
                    root,
                    "root changed after pruning to leaf {prune_pos}"
                );
            }

            // After pruning everything, the root should still match.
            mmb.prune_all();
            assert_eq!(*mmb.root(), root);
        });
    }

    /// Test that the MMB validity check works as expected.
    #[test]
    fn test_mem_mmb_validity() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmb = DirtyMmb::new();
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            for _ in 0..1001 {
                assert!(
                    mmb.size().is_valid_size(),
                    "mmb of size {} should be valid",
                    mmb.size()
                );
                let old_size = mmb.size();
                mmb.add(&mut hasher, &element);
                for size in *old_size + 1..*mmb.size() {
                    assert!(
                        !Position::new(size).is_valid_size(),
                        "mmb of size {size} should be invalid",
                    );
                }
            }
        });
    }

    /// Test that batched MMB building produces the same root as the incremental implementation.
    #[test]
    fn test_mem_mmb_batched_root() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let mut test_mmb = CleanMmb::new(&mut hasher);
            test_mmb = build_test_mmb(&mut hasher, test_mmb, NUM_ELEMENTS);
            let expected_root = test_mmb.root();

            let batched_mmb = CleanMmb::new(&mut hasher);

            // First element transitions Clean -> Dirty explicitly
            let mut dirty_mmb = batched_mmb.into_dirty();
            hasher.inner().update(&0u64.to_be_bytes());
            let element = hasher.inner().finalize();
            dirty_mmb.add(&mut hasher, &element);

            // Subsequent elements keep it Dirty
            for i in 1..NUM_ELEMENTS {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                dirty_mmb.add(&mut hasher, &element);
            }

            let batched_mmb = dirty_mmb.merkleize(&mut hasher, None);

            assert_eq!(
                batched_mmb.root(),
                expected_root,
                "Batched MMB root should match reference"
            );
        });
    }

    /// Test that parallel batched MMB building produces the same root as the reference.
    #[test]
    fn test_mem_mmb_batched_root_parallel() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let test_mmb = CleanMmb::new(&mut hasher);
            let test_mmb = build_test_mmb(&mut hasher, test_mmb, NUM_ELEMENTS);
            let expected_root = test_mmb.root();

            let pool = context.create_thread_pool(NZUsize!(4)).unwrap();
            let mut hasher: Standard<Sha256> = Standard::new();

            let mut mmb = Mmb::init(
                Config {
                    nodes: vec![],
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            )
            .unwrap()
            .into_dirty();

            let mut hasher: Standard<Sha256> = Standard::new();
            for i in 0u64..NUM_ELEMENTS {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                mmb.add(&mut hasher, &element);
            }
            let mmb = mmb.merkleize(&mut hasher, Some(pool));
            assert_eq!(
                mmb.root(),
                expected_root,
                "Batched MMB root should match reference"
            );
        });
    }

    #[test]
    fn test_mem_mmb_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 100;

            let mut hasher: Standard<Sha256> = Standard::new();
            let mmb = CleanMmb::new(&mut hasher);
            let mut mmb = build_test_mmb(&mut hasher, mmb, NUM_ELEMENTS);

            // Pop off one node at a time until empty, confirming the root matches reference.
            for i in (0..NUM_ELEMENTS).rev() {
                let mut dirty_mmb = mmb.into_dirty();
                assert!(dirty_mmb.pop().is_ok());
                mmb = dirty_mmb.merkleize(&mut hasher, None);
                let root = *mmb.root();
                let reference_mmb = CleanMmb::new(&mut hasher);
                let reference_mmb = build_test_mmb(&mut hasher, reference_mmb, i);
                assert_eq!(
                    root,
                    *reference_mmb.root(),
                    "root mismatch after pop at {i}"
                );
            }
            let mut mmb = mmb.into_dirty();
            assert!(
                matches!(mmb.pop().unwrap_err(), Empty),
                "pop on empty MMB should fail"
            );
        });
    }

    #[test]
    fn test_mem_mmb_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 200;
            let mmb = CleanMmb::new(&mut hasher);
            let mut mmb = build_test_mmb(&mut hasher, mmb, NUM_ELEMENTS);
            let root = *mmb.root();

            // For a few leaves, update the leaf and ensure the root changes, and the root reverts
            // to its previous state when we update the leaf to its original value.
            for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
                // Change the leaf.
                let leaf_loc = Location::new(leaf as u64);
                mmb.update_leaf(&mut hasher, leaf_loc, &element).unwrap();
                let updated_root = *mmb.root();
                assert!(root != updated_root);

                // Restore the leaf to its original value, ensure the root is as before.
                hasher.inner().update(&leaf.to_be_bytes());
                let element = hasher.inner().finalize();
                mmb.update_leaf(&mut hasher, leaf_loc, &element).unwrap();
                let restored_root = *mmb.root();
                assert_eq!(root, restored_root);
            }

            // Confirm the tree has all the hashes necessary to update any element after pruning.
            mmb.prune_to_pos(Position::new(150)).unwrap();
            for leaf_pos in 150u64..=190 {
                mmb.prune_to_pos(Position::new(leaf_pos)).unwrap();
                let leaf_loc = Location::new(leaf_pos);
                mmb.update_leaf(&mut hasher, leaf_loc, &element).unwrap();
            }
        });
    }

    #[test]
    fn test_mem_mmb_update_leaf_error_out_of_bounds() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mmb = CleanMmb::new(&mut hasher);
            let mut mmb = build_test_mmb(&mut hasher, mmb, 200);
            let invalid_loc = mmb.leaves();
            let result = mmb.update_leaf(&mut hasher, invalid_loc, &element);
            assert!(matches!(result, Err(Error::LeafOutOfBounds(_))));
        });
    }

    #[test]
    fn test_mem_mmb_update_leaf_error_pruned() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mmb = CleanMmb::new(&mut hasher);
            let mut mmb = build_test_mmb(&mut hasher, mmb, 100);
            mmb.prune_all();
            let result = mmb.update_leaf(&mut hasher, Location::new(0), &element);
            assert!(matches!(result, Err(Error::ElementPruned(_))));
        });
    }

    #[test]
    fn test_mem_mmb_batch_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mmb = CleanMmb::new(&mut hasher);
            let mmb = build_test_mmb(&mut hasher, mmb, 200);
            do_batch_update(&mut hasher, mmb, None);
        });
    }

    /// Same test as above only using a thread pool to trigger parallelization. This requires we use
    /// tokio runtime instead of the deterministic one.
    #[test]
    fn test_mem_mmb_batch_parallel_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = tokio::Runner::default();
        executor.start(|ctx| async move {
            let mmb = Mmb::init(
                Config {
                    nodes: Vec::new(),
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: Vec::new(),
                },
                &mut hasher,
            )
            .unwrap();
            let mmb = build_test_mmb(&mut hasher, mmb, 200);
            let pool = ctx.create_thread_pool(NZUsize!(4)).unwrap();
            do_batch_update(&mut hasher, mmb, Some(pool));
        });
    }

    #[test]
    fn test_update_leaf_digest() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 200;
            let mmb = CleanMmb::new(&mut hasher);
            let mmb = build_test_mmb(&mut hasher, mmb, NUM_ELEMENTS);
            let root = *mmb.root();

            let updated_digest = Sha256::fill(0xFF);

            // Save the original leaf digest so we can restore it.
            let loc = Location::new(5);
            let leaf_pos = Position::try_from(loc).unwrap();
            let original_digest = mmb.get_node(leaf_pos).unwrap();

            // Update a leaf via update_leaf_digest, merkleize, and confirm the root changes.
            let mut dirty = mmb.into_dirty();
            dirty.update_leaf_digest(loc, updated_digest).unwrap();
            let mmb = dirty.merkleize(&mut hasher, None);
            assert_ne!(*mmb.root(), root);

            // Restore the original digest and confirm the root reverts.
            let mut dirty = mmb.into_dirty();
            dirty.update_leaf_digest(loc, original_digest).unwrap();
            let mmb = dirty.merkleize(&mut hasher, None);
            assert_eq!(*mmb.root(), root);

            // Update multiple leaves before a single merkleize.
            let mut dirty = mmb.into_dirty();
            for i in [0u64, 1, 50, 100, 199] {
                dirty
                    .update_leaf_digest(Location::new(i), updated_digest)
                    .unwrap();
            }
            let mmb = dirty.merkleize(&mut hasher, None);
            assert_ne!(*mmb.root(), root);
        });
    }

    #[test]
    fn test_update_leaf_digest_errors() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            {
                // Out of bounds: location >= leaf count.
                let mmb = CleanMmb::new(&mut hasher);
                let mut mmb = build_test_mmb(&mut hasher, mmb, 100).into_dirty();
                let result = mmb.update_leaf_digest(Location::new(100), Sha256::fill(0));
                assert!(matches!(result, Err(Error::InvalidPosition(_))));
            }

            {
                // Pruned leaf.
                let mmb = CleanMmb::new(&mut hasher);
                let mut mmb = build_test_mmb(&mut hasher, mmb, 100);
                mmb.prune_to_pos(Position::new(50)).unwrap();
                let mut dirty = mmb.into_dirty();
                let result = dirty.update_leaf_digest(Location::new(0), Sha256::fill(0));
                assert!(matches!(result, Err(Error::ElementPruned(_))));
            }
        });
    }

    fn do_batch_update(
        hasher: &mut Standard<Sha256>,
        mmb: CleanMmb<sha256::Digest>,
        pool: Option<ThreadPool>,
    ) {
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let root = *mmb.root();

        // Change a handful of leaves using a batch update.
        let mut updates = Vec::new();
        for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
            let leaf_loc = Location::new(leaf);
            updates.push((leaf_loc, &element));
        }
        let mut mmb = mmb.into_dirty();
        mmb.update_leaf_batched(hasher, pool, &updates).unwrap();

        let mmb = mmb.merkleize(hasher, None);
        let updated_root = *mmb.root();
        assert_ne!(updated_root, root);

        // Batch-restore the changed leaves to their original values.
        let mut updates = Vec::new();
        for leaf in [0u64, 1, 10, 50, 100, 150, 197, 198] {
            hasher.inner().update(&leaf.to_be_bytes());
            let element = hasher.inner().finalize();
            let leaf_loc = Location::new(leaf);
            updates.push((leaf_loc, element));
        }
        let mut mmb = mmb.into_dirty();
        mmb.update_leaf_batched(hasher, None, &updates).unwrap();

        let mmb = mmb.merkleize(hasher, None);
        let restored_root = *mmb.root();
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
            assert!(Mmb::init(config, &mut hasher).is_ok());

            // Test with too few pinned nodes - should fail
            // Use a valid MMB size. For N=64 leaves, size = 2*64 - ilog2(65) = 128 - 6 = 122.
            let config = Config::<sha256::Digest> {
                nodes: vec![],
                pruned_to_pos: Position::new(122),
                pinned_nodes: vec![], // Should have nodes for this size
            };
            assert!(matches!(
                Mmb::init(config, &mut hasher),
                Err(Error::InvalidPinnedNodes)
            ));

            // Test with too many pinned nodes - should fail
            let config = Config {
                nodes: vec![],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![Sha256::hash(b"dummy")],
            };
            assert!(matches!(
                Mmb::init(config, &mut hasher),
                Err(Error::InvalidPinnedNodes)
            ));

            // Test with correct number of pinned nodes - should succeed.
            let mut mmb = DirtyMmb::new();
            for i in 0u64..50 {
                mmb.add(&mut hasher, &i.to_be_bytes());
            }
            let mmb = mmb.merkleize(&mut hasher, None);
            let prune_pos = mmb.size();
            let pinned = mmb.nodes_to_pin(prune_pos);
            let pinned_vec: Vec<_> = nodes_to_pin(mmb.size(), prune_pos)
                .into_iter()
                .map(|pos| pinned[&pos])
                .collect();
            let config = Config {
                nodes: vec![],
                pruned_to_pos: prune_pos,
                pinned_nodes: pinned_vec,
            };
            assert!(Mmb::init(config, &mut hasher).is_ok());
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
            assert!(Mmb::init(config, &mut hasher).is_ok());

            // Test with invalid size 2 - should fail
            // MMB size 2 is not valid (leaves_for_size(2) == None)
            let config = Config {
                nodes: vec![Sha256::hash(b"node1"), Sha256::hash(b"node2")],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(matches!(
                Mmb::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));

            // Test with valid size 3 (N=2 leaves) - should succeed
            let config = Config {
                nodes: vec![
                    Sha256::hash(b"leaf1"),
                    Sha256::hash(b"leaf2"),
                    Sha256::hash(b"parent"),
                ],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmb::init(config, &mut hasher).is_ok());

            // Test with valid size 1 (N=1 leaf) - should succeed
            let config = Config {
                nodes: vec![Sha256::hash(b"single_leaf")],
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmb::init(config, &mut hasher).is_ok());

            // Build a real MMB and re-init from it
            let mut mmb = DirtyMmb::new();
            for i in 0u64..64 {
                mmb.add(&mut hasher, &i.to_be_bytes());
            }
            let mmb = mmb.merkleize(&mut hasher, None);
            let expected_size = mmb.size();
            let nodes: Vec<_> = (0..*expected_size)
                .map(|i| *mmb.get_node_unchecked(Position::new(i)))
                .collect();

            let config = Config {
                nodes,
                pruned_to_pos: Position::new(0),
                pinned_nodes: vec![],
            };
            assert!(Mmb::init(config, &mut hasher).is_ok());

            // Test with non-zero pruned_to_pos - should succeed.
            let mut mmb = DirtyMmb::new();
            for i in 0u64..8 {
                mmb.add(&mut hasher, &i.to_be_bytes());
            }
            let mut mmb = mmb.merkleize(&mut hasher, None);
            assert_eq!(mmb.size(), 13); // 8 leaves = 13 total nodes

            // Prune to position 7.
            mmb.prune_to_pos(Position::new(7)).unwrap();
            let nodes: Vec<_> = (7..*mmb.size())
                .map(|i| *mmb.get_node_unchecked(Position::new(i)))
                .collect();
            let pinned = mmb.nodes_to_pin(Position::new(7));
            let pinned_vec: Vec<_> = nodes_to_pin(mmb.size(), Position::new(7))
                .into_iter()
                .map(|pos| pinned[&pos])
                .collect();

            let config = Config {
                nodes: nodes.clone(),
                pruned_to_pos: Position::new(7),
                pinned_nodes: pinned_vec.clone(),
            };
            assert!(Mmb::init(config, &mut hasher).is_ok());

            // Same nodes but wrong pruned_to_pos - should fail.
            let config = Config {
                nodes: nodes.clone(),
                pruned_to_pos: Position::new(8),
                pinned_nodes: pinned_vec.clone(),
            };
            assert!(matches!(
                Mmb::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));

            // Wrong pruned_to_pos with wrong pinned count - should fail.
            // pruned_to_pos=10 + 6 nodes = size 16 which is not a valid MMB size.
            let config = Config {
                nodes,
                pruned_to_pos: Position::new(10),
                pinned_nodes: pinned_vec,
            };
            assert!(matches!(
                Mmb::init(config, &mut hasher),
                Err(Error::InvalidSize(_))
            ));
        });
    }

    /// Verify that the MMB and MMR produce different roots for the same input, confirming
    /// they are distinct data structures.
    #[test]
    fn test_mmb_differs_from_mmr() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmb_hasher: Standard<Sha256> = Standard::new();
            let mut mmr_hasher: crate::mmr::hasher::Standard<Sha256> =
                crate::mmr::hasher::Standard::new();

            let mut mmb = DirtyMmb::new();
            let mut mmr = crate::mmr::mem::DirtyMmr::new();
            for i in 0u64..20 {
                hasher_update_and_add(&mut mmb_hasher, &mut mmb, i);
                {
                    use crate::mmr::hasher::Hasher as _;
                    mmr_hasher.inner().update(&i.to_be_bytes());
                    let element = mmr_hasher.inner().finalize();
                    mmr.add(&mut mmr_hasher, &element);
                }
            }
            let mmb = mmb.merkleize(&mut mmb_hasher, None);
            let mmr = mmr.merkleize(&mut mmr_hasher, None);

            // The sizes differ (MMR and MMB have different node counts for same leaf count).
            assert_ne!(*mmb.size(), *mmr.size());
            // The roots should also differ.
            assert_ne!(mmb.root(), mmr.root());
        });
    }

    /// Test that from_components produces the same result as building from scratch.
    #[test]
    fn test_from_components() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmb = DirtyMmb::new();
            for i in 0u64..50 {
                hasher_update_and_add(&mut hasher, &mut mmb, i);
            }
            let mmb = mmb.merkleize(&mut hasher, None);
            let root = *mmb.root();

            // Reconstruct via from_components
            let nodes: Vec<_> = mmb.nodes.iter().copied().collect();
            let clean = CleanMmb::from_components(&mut hasher, nodes, Position::new(0), vec![]);
            assert_eq!(*clean.root(), root);

            // Reconstruct dirty via from_components
            let nodes: Vec<_> = mmb.nodes.iter().copied().collect();
            let dirty = DirtyMmb::from_components(nodes, Position::new(0), vec![]);
            let clean = dirty.merkleize(&mut hasher, None);
            assert_eq!(*clean.root(), root);
        });
    }

    /// Test the leaf count and last leaf position calculations.
    #[test]
    fn test_leaves_and_last_leaf_pos() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmb = DirtyMmb::new();
            for i in 0u64..100 {
                assert_eq!(*mmb.leaves(), i);
                if i > 0 {
                    let last = mmb.last_leaf_pos().unwrap();
                    // The last leaf should be convertible to a location
                    let loc = Location::try_from(last).unwrap();
                    assert_eq!(*loc, i - 1);
                }
                hasher_update_and_add(&mut hasher, &mut mmb, i);
            }
        });
    }

    fn hasher_update_and_add(
        hasher: &mut Standard<Sha256>,
        mmb: &mut DirtyMmb<sha256::Digest>,
        i: u64,
    ) {
        hasher.inner().update(&i.to_be_bytes());
        let element = hasher.inner().finalize();
        mmb.add(hasher, &element);
    }
}
