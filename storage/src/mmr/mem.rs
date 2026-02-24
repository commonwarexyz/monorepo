//! A basic, no_std compatible MMR where all nodes are stored in-memory.
//!
//! The base [`Mmr`] is always merkleized (has a computed root). Mutations go
//! through a [`super::diff::DirtyDiff`] which borrows the base, accumulates
//! changes, and produces a [`super::diff::Changeset`] that is applied back.

use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_to_pin, PeakIterator},
    read::MmrRead,
    Error, Location, Position,
};
use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};
use commonware_cryptography::Digest;
use core::ops::Range;
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

// --- State types used by the diff layer ---

/// Sealed trait for diff state types.
mod private {
    pub trait Sealed {}
}

/// Trait for valid diff state types.
pub trait State<D: Digest>: private::Sealed + Sized + Send + Sync {}

/// Marker type for a merkleized diff (root digest computed).
#[derive(Clone, Copy, Debug)]
pub struct Clean<D: Digest> {
    /// The root digest.
    pub root: D,
}

impl<D: Digest> private::Sealed for Clean<D> {}
impl<D: Digest> State<D> for Clean<D> {}

/// Marker type and dirty-node tracker for an unmerkleized diff.
#[derive(Clone, Debug, Default)]
pub struct Dirty {
    /// Non-leaf nodes that need to have their digests recomputed.
    ///
    /// This is a set of tuples of the form (node_pos, height).
    dirty_nodes: BTreeSet<(Position, u32)>,
}

impl private::Sealed for Dirty {}
impl<D: Digest> State<D> for Dirty {}

impl Dirty {
    /// Insert a dirty node. Returns true if newly inserted.
    pub(crate) fn insert(&mut self, pos: Position, height: u32) -> bool {
        self.dirty_nodes.insert((pos, height))
    }

    /// Take all dirty nodes sorted by ascending height (bottom-up for merkleize).
    pub(crate) fn take_sorted_by_height(&mut self) -> Vec<(Position, u32)> {
        let mut v: Vec<_> = self.dirty_nodes.iter().copied().collect();
        self.dirty_nodes.clear();
        v.sort_by_key(|a| a.1);
        v
    }

    /// Remove all dirty nodes at positions >= cutoff.
    pub(crate) fn remove_above(&mut self, cutoff: Position) {
        let _ = self.dirty_nodes.split_off(&(cutoff, 0));
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

/// A basic, always-merkleized MMR where all nodes are stored in-memory.
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
/// # Mutations
///
/// The base MMR is always merkleized. To mutate it, create a
/// [`super::diff::DirtyDiff`], apply mutations, call `merkleize()` to get a
/// [`super::diff::CleanDiff`], extract a [`super::diff::Changeset`], and
/// [`apply`](Mmr::apply) it back.
#[derive(Clone, Debug)]
pub struct Mmr<D: Digest> {
    /// The nodes of the MMR, laid out according to a post-order traversal of the MMR trees,
    /// starting from the from tallest tree to shortest.
    nodes: VecDeque<D>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pruned_to_pos: Position,

    /// The auxiliary map from node position to the digest of any pinned node.
    pinned_nodes: BTreeMap<Position, D>,

    /// The root digest of the MMR.
    root: D,
}

impl<D: Digest> Mmr<D> {
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

        let dirty = DirtyMmr {
            nodes: VecDeque::from(config.nodes),
            pruned_to_pos: config.pruned_to_pos,
            pinned_nodes,
            state: Dirty::default(),
        };
        Ok(dirty.merkleize(hasher, None))
    }

    /// Create a new, empty MMR.
    pub fn new(hasher: &mut impl Hasher<Digest = D>) -> Self {
        let dirty: DirtyMmr<D> = Default::default();
        dirty.merkleize(hasher, None)
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

    /// Return the total number of nodes in the MMR, irrespective of any pruning.
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

    /// Returns [start, end) where `start` and `end - 1` are the positions of the oldest and newest
    /// retained nodes respectively.
    pub fn bounds(&self) -> Range<Position> {
        self.pruned_to_pos..self.size()
    }

    /// Return a new iterator over the peaks of the MMR.
    pub fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Return the requested node or None if it is not stored in the MMR.
    pub fn get_node(&self, pos: Position) -> Option<D> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }
        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Return the requested node if it is either retained or present in the pinned_nodes map, and
    /// panic otherwise. Use `get_node` instead if you require a non-panicking getter.
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

    /// Get the root digest of the MMR.
    pub const fn root(&self) -> &D {
        &self.root
    }

    /// Inclusion proof for the element at `loc`.
    pub fn proof(&self, loc: Location) -> Result<crate::mmr::proof::Proof<D>, Error> {
        <Self as MmrRead<D>>::proof(self, loc)
    }

    /// Inclusion proof for all elements in `range`.
    pub fn range_proof(
        &self,
        range: Range<Location>,
    ) -> Result<crate::mmr::proof::Proof<D>, Error> {
        <Self as MmrRead<D>>::range_proof(self, range)
    }

    /// Returns the root that would be produced by calling `root` on an empty MMR.
    pub fn empty_mmr_root(hasher: &mut impl commonware_cryptography::Hasher<Digest = D>) -> D {
        hasher.update(&0u64.to_be_bytes());
        hasher.finalize()
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
        let changeset = {
            let mut diff = super::diff::DirtyDiff::new(self as &Self);
            diff.update_leaf(hasher, loc, element)?;
            diff.merkleize(hasher).into_changeset()
        };
        self.apply(changeset);
        Ok(())
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
    pub(crate) fn pinned_nodes(&self) -> BTreeMap<Position, D> {
        self.pinned_nodes.clone()
    }

    /// Apply a changeset produced by [`super::diff::CleanDiff::into_changeset`].
    ///
    /// This is the only way to transfer diff changes into the base MMR.
    /// After apply, the base's root matches the diff's root.
    pub fn apply(&mut self, changeset: super::diff::Changeset<D>) {
        // 1. Truncate: if diff popped into base range, remove tail nodes.
        if changeset.parent_end < self.size() {
            let keep = (*changeset.parent_end - *self.pruned_to_pos) as usize;
            self.nodes.truncate(keep);
        }

        // 2. Overwrite: write modified digests into surviving base nodes.
        for (pos, digest) in changeset.overwrites {
            let index = self.pos_to_index(pos);
            self.nodes[index] = digest;
        }

        // 3. Append: push new nodes onto the end.
        for digest in changeset.appended {
            self.nodes.push_back(digest);
        }

        // 4. Root: set the pre-computed root from the diff.
        self.root = changeset.root;

        // 5. Prune: if pruning advanced, physically prune and pin.
        //    Must be last because prune_to_pos needs all nodes present.
        if changeset.pruned_to_pos > self.pruned_to_pos {
            self.prune_to_pos(changeset.pruned_to_pos);
        }
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

    /// Return the position of the element given its index in the current nodes vector.
    fn index_to_pos(&self, index: usize) -> Position {
        self.pruned_to_pos + (index as u64)
    }

    /// Utility used by stores that build on the mem MMR to pin extra nodes if needed. It's up to
    /// the caller to ensure that this set of pinned nodes is valid for their use case.
    #[cfg(any(feature = "std", test))]
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: BTreeMap<Position, D>) {
        for (pos, node) in pinned_nodes.into_iter() {
            self.pinned_nodes.insert(pos, node);
        }
    }
}

impl<D: Digest> MmrRead<D> for Mmr<D> {
    fn size(&self) -> Position {
        Position::new(self.nodes.len() as u64 + *self.pruned_to_pos)
    }

    fn get_node(&self, pos: Position) -> Option<D> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }
        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    fn root(&self) -> &D {
        &self.root
    }

    fn pruned_to_pos(&self) -> Position {
        self.pruned_to_pos
    }
}

impl<D: Digest> super::read::ChainInfo<D> for Mmr<D> {
    fn base_size(&self) -> Position {
        self.size()
    }

    fn base_visible(&self) -> Position {
        self.size()
    }

    fn collect_chain_overwrites(&self, _into: &mut BTreeMap<Position, D>) {}
}

// ---------------------------------------------------------------------------
// DirtyMmr -- internal MMR used for reconstruction from components
// ---------------------------------------------------------------------------

/// A not-yet-merkleized MMR reconstructed from components.
///
/// Call [`merkleize`](DirtyMmr::merkleize) to compute digests and produce an [`Mmr`].
#[derive(Clone, Debug)]
pub(crate) struct DirtyMmr<D: Digest> {
    /// The nodes of the MMR, laid out according to a post-order traversal of the MMR trees,
    /// starting from the from tallest tree to shortest.
    nodes: VecDeque<D>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pruned_to_pos: Position,

    /// The auxiliary map from node position to the digest of any pinned node.
    pinned_nodes: BTreeMap<Position, D>,

    /// Dirty-node tracker.
    state: Dirty,
}

impl<D: Digest> Default for DirtyMmr<D> {
    fn default() -> Self {
        Self {
            nodes: VecDeque::new(),
            pruned_to_pos: Position::new(0),
            pinned_nodes: BTreeMap::new(),
            state: Dirty::default(),
        }
    }
}

impl<D: Digest> DirtyMmr<D> {
    /// Re-initialize with the given nodes, pruned_to_pos, and pinned_nodes.
    pub(crate) fn from_components(
        nodes: Vec<D>,
        pruned_to_pos: Position,
        pinned_nodes: Vec<D>,
    ) -> Self {
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

    // --- Accessors (duplicated from Mmr for DirtyMmr) ---

    /// Return the total number of nodes in the MMR, irrespective of any pruning.
    pub(crate) fn size(&self) -> Position {
        Position::new(self.nodes.len() as u64 + *self.pruned_to_pos)
    }

    /// Return the total number of leaves in the MMR.
    pub(crate) fn leaves(&self) -> Location {
        Location::try_from(self.size()).expect("invalid mmr size")
    }

    /// Return a new iterator over the peaks of the MMR.
    pub(crate) fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Return the requested node, panicking if it does not exist.
    pub(crate) fn get_node_unchecked(&self, pos: Position) -> &D {
        if pos < self.pruned_to_pos {
            return self
                .pinned_nodes
                .get(&pos)
                .expect("requested node is pruned and not pinned");
        }
        &self.nodes[self.pos_to_index(pos)]
    }

    /// Return the index of the element in the current nodes vector given its position.
    fn pos_to_index(&self, pos: Position) -> usize {
        assert!(
            pos >= self.pruned_to_pos,
            "pos precedes oldest retained position"
        );
        *pos.checked_sub(*self.pruned_to_pos).unwrap() as usize
    }

    // --- Merkleization ---
    // NOTE: The serial/parallel merkleize logic is intentionally duplicated in
    // `diff::Diff` which uses resolve_node/store_node indirection instead of
    // direct indexing.

    /// Compute updated digests for dirty nodes and compute the root, converting this MMR into an
    /// [Mmr].
    pub(crate) fn merkleize(
        mut self,
        hasher: &mut impl Hasher<Digest = D>,
        #[cfg_attr(not(feature = "std"), allow(unused_variables))] pool: Option<ThreadPool>,
    ) -> Mmr<D> {
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
        let root = hasher.root(self.leaves(), peaks);

        Mmr {
            nodes: self.nodes,
            pruned_to_pos: self.pruned_to_pos,
            pinned_nodes: self.pinned_nodes,
            root,
        }
    }

    fn merkleize_serial(&mut self, hasher: &mut impl Hasher<Digest = D>) {
        let mut nodes: Vec<(Position, u32)> = self.state.dirty_nodes.iter().copied().collect();
        self.state.dirty_nodes.clear();
        nodes.sort_by_key(|a| a.1);

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        conformance::build_test_mmr,
        diff::DirtyDiff,
        hasher::{Hasher as _, Standard},
        iterator::nodes_needing_parents,
        Error::{ElementPruned, Empty},
    };
    use commonware_cryptography::{sha256, Hasher, Sha256};
    use commonware_runtime::{deterministic, tokio, Runner, ThreadPooler};
    use commonware_utils::NZUsize;

    /// Test empty MMR behavior.
    #[test]
    fn test_mem_mmr_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mmr = Mmr::new(&mut hasher);
            assert_eq!(
                mmr.peak_iterator().next(),
                None,
                "empty iterator should have no peaks"
            );
            assert_eq!(mmr.size(), 0);
            assert_eq!(mmr.leaves(), Location::new_unchecked(0));
            assert_eq!(mmr.last_leaf_pos(), None);
            assert!(mmr.bounds().is_empty());
            assert_eq!(mmr.get_node(Position::new(0)), None);
            assert_eq!(*mmr.root(), Mmr::empty_mmr_root(hasher.inner()));

            // Pop on empty via diff should fail.
            {
                let mut diff = DirtyDiff::new(&mmr);
                assert!(matches!(diff.pop(), Err(Empty)));
            }

            let mut mmr = mmr;
            mmr.prune_all();
            assert_eq!(mmr.size(), 0, "prune_all on empty MMR should do nothing");

            assert_eq!(
                *mmr.root(),
                hasher.root(Location::new_unchecked(0), [].iter())
            );
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
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

            // Build the MMR one element at a time, checking peaks at each step.
            let mut base = Mmr::new(&mut hasher);
            let mut leaves: Vec<Position> = Vec::new();
            for _ in 0..11 {
                let changeset = {
                    let mut diff = DirtyDiff::new(&base);
                    let pos = diff.add(&mut hasher, &element);
                    leaves.push(pos);
                    let peaks: Vec<(Position, u32)> = PeakIterator::new(diff.size()).collect();
                    assert_ne!(peaks.len(), 0);
                    assert!(peaks.len() as u64 <= *diff.size());
                    let nodes_needing_parents =
                        nodes_needing_parents(PeakIterator::new(diff.size()));
                    assert!(nodes_needing_parents.len() <= peaks.len());
                    diff.merkleize(&mut hasher).into_changeset()
                };
                base.apply(changeset);
            }
            let mmr = &base;
            assert_eq!(mmr.bounds().start, Position::new(0));
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
            let n = |pos: u64| *mmr.get_node_unchecked(Position::new(pos));
            let digest2 = hasher.node_digest(Position::new(2), &n(0), &n(1));
            assert_eq!(n(2), digest2);
            let digest5 = hasher.node_digest(Position::new(5), &n(3), &n(4));
            assert_eq!(n(5), digest5);
            let digest9 = hasher.node_digest(Position::new(9), &n(7), &n(8));
            assert_eq!(n(9), digest9);
            let digest12 = hasher.node_digest(Position::new(12), &n(10), &n(11));
            assert_eq!(n(12), digest12);
            let digest17 = hasher.node_digest(Position::new(17), &n(15), &n(16));
            assert_eq!(n(17), digest17);

            // verify height=2 node digests
            let digest6 = hasher.node_digest(Position::new(6), &n(2), &n(5));
            assert_eq!(n(6), digest6);
            let digest13 = hasher.node_digest(Position::new(13), &n(9), &n(12));
            assert_eq!(n(13), digest13);
            let digest17 = hasher.node_digest(Position::new(17), &n(15), &n(16));
            assert_eq!(n(17), digest17);

            // verify topmost digest
            let digest14 = hasher.node_digest(Position::new(14), &n(6), &n(13));
            assert_eq!(n(14), digest14);

            // verify root
            let root = *mmr.root();
            let peak_digests = [digest14, digest17, n(18)];
            let expected_root = hasher.root(Location::new_unchecked(11), peak_digests.iter());
            assert_eq!(root, expected_root, "incorrect root");

            // pruning tests
            let mut mmr = base;
            mmr.prune_to_pos(Position::new(14)); // prune up to the tallest peak
            assert_eq!(mmr.bounds().start, Position::new(14));

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
            let oldest_pos = mmr.bounds().start;
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
            assert_eq!(mmr_copy.bounds().start, mmr.bounds().start);
            assert_eq!(*mmr_copy.root(), root);
        });
    }

    /// Test that pruning all nodes never breaks adding new nodes.
    #[test]
    fn test_mem_mmr_prune_all() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new(&mut hasher);
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
            for _ in 0..1000 {
                mmr.prune_all();
                let changeset = {
                    let mut diff = DirtyDiff::new(&mmr);
                    diff.add(&mut hasher, &element);
                    diff.merkleize(&mut hasher).into_changeset()
                };
                mmr.apply(changeset);
            }
        });
    }

    /// Test that the MMR validity check works as expected.
    #[test]
    fn test_mem_mmr_validity() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");

            let mut base = Mmr::new(&mut hasher);
            for _ in 0..1001 {
                assert!(
                    base.size().is_mmr_size(),
                    "mmr of size {} should be valid",
                    base.size()
                );
                let old_size = base.size();
                let changeset = {
                    let mut diff = DirtyDiff::new(&base);
                    diff.add(&mut hasher, &element);
                    let new_size = diff.size();
                    for size in *old_size + 1..*new_size {
                        assert!(
                            !Position::new(size).is_mmr_size(),
                            "mmr of size {size} should be invalid",
                        );
                    }
                    diff.merkleize(&mut hasher).into_changeset()
                };
                base.apply(changeset);
            }
        });
    }

    /// Test that batched MMR building produces the same root as the reference implementation.
    /// Root stability for the reference implementation is verified by the conformance test.
    #[test]
    fn test_mem_mmr_batched_root() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let mut test_mmr = Mmr::new(&mut hasher);
            test_mmr = build_test_mmr(&mut hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let batched_mmr = Mmr::new(&mut hasher);

            // Build the entire MMR in one diff.
            let changeset = {
                let mut diff = DirtyDiff::new(&batched_mmr);
                for i in 0..NUM_ELEMENTS {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    diff.add(&mut hasher, &element);
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            let mut batched_mmr = batched_mmr;
            batched_mmr.apply(changeset);

            assert_eq!(
                batched_mmr.root(),
                expected_root,
                "Batched MMR root should match reference"
            );
        });
    }

    /// Test that parallel batched MMR building produces the same root as the reference.
    /// This requires the tokio runtime since the deterministic runtime is single-threaded.
    #[test]
    fn test_mem_mmr_batched_root_parallel() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            const NUM_ELEMENTS: u64 = 199;
            let test_mmr = Mmr::new(&mut hasher);
            let test_mmr = build_test_mmr(&mut hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root();

            let pool = context.create_thread_pool(NZUsize!(4)).unwrap();
            let mut hasher: Standard<Sha256> = Standard::new();

            let base = Mmr::init(
                Config {
                    nodes: vec![],
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: vec![],
                },
                &mut hasher,
            )
            .unwrap();

            let changeset = {
                let mut diff = DirtyDiff::new(&base).with_pool(Some(pool));
                let mut hasher: Standard<Sha256> = Standard::new();
                for i in 0u64..NUM_ELEMENTS {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    diff.add(&mut hasher, &element);
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            let mut mmr = base;
            mmr.apply(changeset);
            assert_eq!(
                mmr.root(),
                expected_root,
                "Batched MMR root should match reference"
            );
        });
    }

    /// Test that pruning after each add does not affect root computation.
    #[test]
    fn test_mem_mmr_root_with_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut reference_mmr = Mmr::new(&mut hasher);
            let mut mmr = Mmr::new(&mut hasher);
            for i in 0u64..200 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();

                // Add to both via diff.
                let ref_changeset = {
                    let mut diff = DirtyDiff::new(&reference_mmr);
                    diff.add(&mut hasher, &element);
                    diff.merkleize(&mut hasher).into_changeset()
                };
                reference_mmr.apply(ref_changeset);

                let changeset = {
                    let mut diff = DirtyDiff::new(&mmr);
                    diff.add(&mut hasher, &element);
                    diff.merkleize(&mut hasher).into_changeset()
                };
                mmr.apply(changeset);

                // Prune the second MMR.
                mmr.prune_all();
                assert_eq!(mmr.root(), reference_mmr.root());
            }
        });
    }

    #[test]
    fn test_mem_mmr_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 100;

            let mut hasher: Standard<Sha256> = Standard::new();
            let mmr = Mmr::new(&mut hasher);
            let mut mmr = build_test_mmr(&mut hasher, mmr, NUM_ELEMENTS);

            // Pop off one node at a time until empty, confirming the root matches reference.
            for i in (0..NUM_ELEMENTS).rev() {
                let changeset = {
                    let mut diff = DirtyDiff::new(&mmr);
                    assert!(diff.pop().is_ok());
                    diff.merkleize(&mut hasher).into_changeset()
                };
                mmr.apply(changeset);
                let root = *mmr.root();
                let reference_mmr = Mmr::new(&mut hasher);
                let reference_mmr = build_test_mmr(&mut hasher, reference_mmr, i);
                assert_eq!(
                    root,
                    *reference_mmr.root(),
                    "root mismatch after pop at {i}"
                );
            }

            // Pop on empty should fail.
            {
                let mut diff = DirtyDiff::new(&mmr);
                assert!(
                    matches!(diff.pop().unwrap_err(), Empty),
                    "pop on empty MMR should fail"
                );
            }

            // Test that we can pop all elements up to and including the oldest retained leaf.
            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                for i in 0u64..NUM_ELEMENTS {
                    hasher.inner().update(&i.to_be_bytes());
                    let element = hasher.inner().finalize();
                    diff.add(&mut hasher, &element);
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            mmr.apply(changeset);

            let leaf_pos = Position::try_from(Location::new_unchecked(100)).unwrap();
            mmr.prune_to_pos(leaf_pos);

            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                while diff.size() > leaf_pos {
                    diff.pop().unwrap();
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            mmr.apply(changeset);

            let reference_mmr = Mmr::new(&mut hasher);
            let reference_mmr = build_test_mmr(&mut hasher, reference_mmr, 100);
            assert_eq!(*mmr.root(), *reference_mmr.root());

            // Pop past pruned boundary should fail.
            {
                let mut diff = DirtyDiff::new(&mmr);
                let result = diff.pop();
                assert!(matches!(result, Err(ElementPruned(_))));
                assert!(mmr.bounds().is_empty());
            }
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 200;
            let mmr = Mmr::new(&mut hasher);
            let mut mmr = build_test_mmr(&mut hasher, mmr, NUM_ELEMENTS);
            let root = *mmr.root();

            // For a few leaves, update the leaf and ensure the root changes, and the root reverts
            // to its previous state then we update the leaf to its original value.
            for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
                // Change the leaf.
                let leaf_loc = Location::new_unchecked(leaf as u64);
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
            mmr.prune_to_pos(Position::new(150));
            for leaf_pos in 150u64..=190 {
                mmr.prune_to_pos(Position::new(leaf_pos));
                let leaf_loc = Location::new_unchecked(leaf_pos);
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
            let mmr = Mmr::new(&mut hasher);
            let mut mmr = build_test_mmr(&mut hasher, mmr, 200);
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
            let mmr = Mmr::new(&mut hasher);
            let mut mmr = build_test_mmr(&mut hasher, mmr, 100);
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
            let mmr = Mmr::new(&mut hasher);
            let mmr = build_test_mmr(&mut hasher, mmr, 200);
            do_batch_update(&mut hasher, mmr, None);
        });
    }

    /// Same test as above only using a thread pool to trigger parallelization. This requires we use
    /// tokio runtime instead of the deterministic one.
    #[test]
    fn test_mem_mmr_batch_parallel_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = tokio::Runner::default();
        executor.start(|ctx| async move {
            let mmr = Mmr::init(
                Config {
                    nodes: Vec::new(),
                    pruned_to_pos: Position::new(0),
                    pinned_nodes: Vec::new(),
                },
                &mut hasher,
            )
            .unwrap();
            let mmr = build_test_mmr(&mut hasher, mmr, 200);
            let pool = ctx.create_thread_pool(NZUsize!(4)).unwrap();
            do_batch_update(&mut hasher, mmr, Some(pool));
        });
    }

    #[test]
    fn test_update_leaf_digest() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            const NUM_ELEMENTS: u64 = 200;
            let mmr = Mmr::new(&mut hasher);
            let mmr = build_test_mmr(&mut hasher, mmr, NUM_ELEMENTS);
            let root = *mmr.root();

            let updated_digest = Sha256::fill(0xFF);

            // Save the original leaf digest so we can restore it.
            let loc = Location::new_unchecked(5);
            let leaf_pos = Position::try_from(loc).unwrap();
            let original_digest = mmr.get_node(leaf_pos).unwrap();

            // Update a leaf via DirtyDiff::update_leaf_digest, merkleize, and confirm root changes.
            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                diff.update_leaf_digest(loc, updated_digest).unwrap();
                diff.merkleize(&mut hasher).into_changeset()
            };
            let mut mmr = mmr;
            mmr.apply(changeset);
            assert_ne!(*mmr.root(), root);

            // Restore the original digest and confirm the root reverts.
            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                diff.update_leaf_digest(loc, original_digest).unwrap();
                diff.merkleize(&mut hasher).into_changeset()
            };
            mmr.apply(changeset);
            assert_eq!(*mmr.root(), root);

            // Update multiple leaves before a single merkleize.
            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                for i in [0u64, 1, 50, 100, 199] {
                    diff.update_leaf_digest(Location::new_unchecked(i), updated_digest)
                        .unwrap();
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            mmr.apply(changeset);
            assert_ne!(*mmr.root(), root);
        });
    }

    #[test]
    fn test_update_leaf_digest_errors() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            {
                // Out of bounds: location >= leaf count.
                let mmr = Mmr::new(&mut hasher);
                let mmr = build_test_mmr(&mut hasher, mmr, 100);
                let mut diff = DirtyDiff::new(&mmr);
                let result = diff.update_leaf_digest(Location::new_unchecked(100), Sha256::fill(0));
                assert!(matches!(result, Err(Error::InvalidPosition(_))));
            }

            {
                // Pruned leaf.
                let mmr = Mmr::new(&mut hasher);
                let mut mmr = build_test_mmr(&mut hasher, mmr, 100);
                mmr.prune_to_pos(Position::new(50));
                let mut diff = DirtyDiff::new(&mmr);
                let result = diff.update_leaf_digest(Location::new_unchecked(0), Sha256::fill(0));
                assert!(matches!(result, Err(Error::ElementPruned(_))));
            }
        });
    }

    fn do_batch_update(
        hasher: &mut Standard<Sha256>,
        mmr: Mmr<sha256::Digest>,
        pool: Option<ThreadPool>,
    ) {
        let element = <Sha256 as Hasher>::Digest::from(*b"01234567012345670123456701234567");
        let root = *mmr.root();

        // Change a handful of leaves using a batch update via DirtyDiff.
        // update_leaf_batched takes pre-computed leaf digests, so hash through leaf_digest.
        let leaf_locs: Vec<Location> = [0u64, 1, 10, 50, 100, 150, 197, 198]
            .iter()
            .map(|&l| Location::new_unchecked(l))
            .collect();
        let updates: Vec<(Location, sha256::Digest)> = leaf_locs
            .iter()
            .map(|&loc| {
                let pos = Position::try_from(loc).unwrap();
                let digest = hasher.leaf_digest(pos, &element);
                (loc, digest)
            })
            .collect();
        let changeset = {
            let mut diff = DirtyDiff::new(&mmr);
            if let Some(pool) = pool {
                diff = diff.with_pool(Some(pool));
            }
            diff.update_leaf_batched(&updates).unwrap();
            diff.merkleize(hasher).into_changeset()
        };
        let mut mmr = mmr;
        mmr.apply(changeset);
        let updated_root = *mmr.root();
        assert_ne!(updated_root, root);

        // Batch-restore the changed leaves to their original values.
        let restore_updates: Vec<(Location, sha256::Digest)> = leaf_locs
            .iter()
            .map(|&loc| {
                let leaf_num = *loc;
                hasher.inner().update(&leaf_num.to_be_bytes());
                let element = hasher.inner().finalize();
                let pos = Position::try_from(loc).unwrap();
                let digest = hasher.leaf_digest(pos, &element);
                (loc, digest)
            })
            .collect();
        let changeset = {
            let mut diff = DirtyDiff::new(&mmr);
            diff.update_leaf_batched(&restore_updates).unwrap();
            diff.merkleize(hasher).into_changeset()
        };
        mmr.apply(changeset);
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
            let mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                for i in 0u64..50 {
                    diff.add(&mut hasher, &i.to_be_bytes());
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            let mut mmr = mmr;
            mmr.apply(changeset);
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
            let mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                for i in 0u64..64 {
                    diff.add(&mut hasher, &i.to_be_bytes());
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            let mut mmr = mmr;
            mmr.apply(changeset);
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
            let mmr = Mmr::new(&mut hasher);
            let changeset = {
                let mut diff = DirtyDiff::new(&mmr);
                for i in 0u64..11 {
                    diff.add(&mut hasher, &i.to_be_bytes());
                }
                diff.merkleize(&mut hasher).into_changeset()
            };
            let mut mmr = mmr;
            mmr.apply(changeset);
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

    #[test]
    fn test_mem_mmr_range_proof_out_of_bounds() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Range end > leaves errors on empty MMR
            let mmr = Mmr::new(&mut hasher);
            assert_eq!(mmr.leaves(), Location::new_unchecked(0));
            let result = mmr.range_proof(Location::new_unchecked(0)..Location::new_unchecked(1));
            assert!(matches!(result, Err(Error::RangeOutOfBounds(_))));

            // Range end > leaves errors on non-empty MMR
            let mmr = build_test_mmr(&mut hasher, mmr, 10);
            assert_eq!(mmr.leaves(), Location::new_unchecked(10));
            let result = mmr.range_proof(Location::new_unchecked(5)..Location::new_unchecked(11));
            assert!(matches!(result, Err(Error::RangeOutOfBounds(_))));

            // Range end == leaves succeeds
            let result = mmr.range_proof(Location::new_unchecked(5)..Location::new_unchecked(10));
            assert!(result.is_ok());
        });
    }

    #[test]
    fn test_mem_mmr_proof_out_of_bounds() {
        let mut hasher: Standard<Sha256> = Standard::new();

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Test on empty MMR - should return error, not panic
            let mmr = Mmr::new(&mut hasher);
            let result = mmr.proof(Location::new_unchecked(0));
            assert!(
                matches!(result, Err(Error::LeafOutOfBounds(_))),
                "expected LeafOutOfBounds, got {:?}",
                result
            );

            // Test on non-empty MMR with location >= leaves
            let mmr = build_test_mmr(&mut hasher, mmr, 10);
            let result = mmr.proof(Location::new_unchecked(10));
            assert!(
                matches!(result, Err(Error::LeafOutOfBounds(_))),
                "expected LeafOutOfBounds, got {:?}",
                result
            );

            // location < leaves should succeed
            let result = mmr.proof(Location::new_unchecked(9));
            assert!(result.is_ok(), "expected Ok, got {:?}", result);
        });
    }
}
