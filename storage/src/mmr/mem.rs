//! A basic MMR where all nodes are stored in-memory.
//!
//! # Terminology
//!
//! Nodes in this structure are either _retained_, _pruned_, or _pinned_. Retained nodes are nodes
//! that have not yet been pruned, and have digests stored explicitly within the tree structure.
//! Pruned nodes are those whose positions precede that of the _oldest retained_ node, for which no
//! digests are maintained. Pinned nodes are nodes that would otherwise be pruned based on their
//! position, but whose digests remain required for proof generation. The digests for pinned nodes
//! are stored in an auxiliary map, and are at most O(log2(n)) in number.
use crate::mmr::{
    iterator::{nodes_needing_parents, PathIterator, PeakIterator},
    verification::Proof,
    Builder,
    Error::{self, ElementPruned, Empty},
    Hasher,
};
use commonware_cryptography::Hasher as CHasher;
use commonware_runtime::ThreadPool;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};

pub struct Config<H: CHasher> {
    /// The retained nodes of the MMR.
    pub nodes: Vec<H::Digest>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pub pruned_to_pos: u64,

    /// The pinned nodes of the MMR, in the order expected by [Proof::nodes_to_pin].
    pub pinned_nodes: Vec<H::Digest>,

    /// Optional thread pool to use for parallelizing batch updates.
    pub pool: Option<ThreadPool>,
}

/// Implementation of `Mmr`.
///
/// # Max Capacity
///
/// The maximum number of elements that can be stored is usize::MAX
/// (u32::MAX on 32-bit architectures).
pub struct Mmr<H: CHasher> {
    /// The nodes of the MMR, laid out according to a post-order traversal of the MMR trees,
    /// starting from the from tallest tree to shortest.
    nodes: VecDeque<H::Digest>,

    /// The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    /// pruned.
    pruned_to_pos: u64,

    /// The auxiliary map from node position to the digest of any pinned node.
    pub(super) pinned_nodes: HashMap<u64, H::Digest>,

    /// Non-leaf nodes that need to have their digests recomputed due to a batched update operation.
    ///
    /// This is a set of tuples of the form (node_pos, height).
    dirty_nodes: HashSet<(u64, u32)>,

    /// Dummy digest used as a placeholder for nodes whose digests will be updated with the next
    /// `sync`.
    dirty_digest: H::Digest,

    /// Thread pool to use for parallelizing updates.
    pub(super) thread_pool: Option<ThreadPool>,
}

impl<H: CHasher> Default for Mmr<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Builder<H> for Mmr<H> {
    async fn add(&mut self, hasher: &mut impl Hasher<H>, element: &[u8]) -> Result<u64, Error> {
        Ok(self.add(hasher, element))
    }

    fn root(&self, hasher: &mut impl Hasher<H>) -> H::Digest {
        self.root(hasher)
    }
}

/// Minimum number of digest computations required during batch updates to trigger parallelization.
const MIN_TO_PARALLELIZE: usize = 20;

impl<H: CHasher> Mmr<H> {
    /// Return a new (empty) `Mmr`.
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            pruned_to_pos: 0,
            pinned_nodes: HashMap::new(),
            dirty_nodes: HashSet::new(),
            dirty_digest: Self::dirty_digest(),
            thread_pool: None,
        }
    }

    // Computes the digest to use as the `self.dirty_digest` placeholder. The specific value is
    // unimportant so we simply use the empty hash.
    fn dirty_digest() -> H::Digest {
        H::empty()
    }

    /// Return an [Mmr] initialized with the given `config`.
    pub fn init(config: Config<H>) -> Self {
        let mut mmr = Self {
            nodes: VecDeque::from(config.nodes),
            pruned_to_pos: config.pruned_to_pos,
            pinned_nodes: HashMap::new(),
            dirty_nodes: HashSet::new(),
            dirty_digest: Self::dirty_digest(),
            thread_pool: config.pool,
        };
        if mmr.size() == 0 {
            return mmr;
        }

        for (i, pos) in Proof::<H::Digest>::nodes_to_pin(config.pruned_to_pos).enumerate() {
            mmr.pinned_nodes.insert(pos, config.pinned_nodes[i]);
        }

        mmr
    }

    /// Return the total number of nodes in the MMR, irrespective of any pruning. The next added
    /// element's position will have this value.
    pub fn size(&self) -> u64 {
        self.nodes.len() as u64 + self.pruned_to_pos
    }

    pub fn last_leaf_pos(&self) -> Option<u64> {
        if self.size() == 0 {
            return None;
        }

        Some(PeakIterator::last_leaf_pos(self.size()))
    }

    // The highest position for which this MMR has been pruned, or 0 if this MMR has never been
    // pruned.
    pub fn pruned_to_pos(&self) -> u64 {
        self.pruned_to_pos
    }

    /// Return the position of the oldest retained node in the MMR, not including those cached in
    /// pinned_nodes.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        if self.pruned_to_pos == self.size() {
            return None;
        }

        Some(self.pruned_to_pos)
    }

    /// Return a new iterator over the peaks of the MMR.
    pub(super) fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Return the position of the element given its index in the current nodes vector.
    fn index_to_pos(&self, index: usize) -> u64 {
        index as u64 + self.pruned_to_pos
    }

    /// Returns the requested node, assuming it is either retained or known to exist in the
    /// pinned_nodes map.
    pub fn get_node_unchecked(&self, pos: u64) -> &H::Digest {
        if pos < self.pruned_to_pos {
            return self
                .pinned_nodes
                .get(&pos)
                .expect("requested node is pruned and not pinned");
        }

        &self.nodes[self.pos_to_index(pos)]
    }

    /// Returns the requested node or None if it is not stored in the MMR.
    pub fn get_node(&self, pos: u64) -> Option<H::Digest> {
        if pos < self.pruned_to_pos {
            return self.pinned_nodes.get(&pos).copied();
        }

        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Return the index of the element in the current nodes vector given its position in the MMR.
    ///
    /// Will underflow if `pos` precedes the oldest retained position.
    fn pos_to_index(&self, pos: u64) -> usize {
        (pos - self.pruned_to_pos) as usize
    }

    /// Add `element` to the MMR and return its position in the MMR. The element can be an arbitrary
    /// byte slice, and need not be converted to a digest first.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub fn add(&mut self, hasher: &mut impl Hasher<H>, element: &[u8]) -> u64 {
        let leaf_pos = self.size();
        let digest = hasher.leaf_digest(leaf_pos, element);
        self.add_leaf_digest(hasher, digest);

        leaf_pos
    }

    /// Add `element` to the MMR and return its position in the MMR, but without updating ancestors
    /// until `sync` is called. The element can be an arbitrary byte slice, and need not be
    /// converted to a digest first.
    pub fn add_batched(&mut self, hasher: &mut impl Hasher<H>, element: &[u8]) -> u64 {
        let leaf_pos = self.size();
        let digest = hasher.leaf_digest(leaf_pos, element);

        // Compute the new parent nodes if any, and insert them into the MMR
        // with a dummy digest, and add each to the dirty nodes set.
        let nodes_needing_parents = nodes_needing_parents(self.peak_iterator())
            .into_iter()
            .rev();
        self.nodes.push_back(digest);

        let mut height = 1;
        for _ in nodes_needing_parents {
            let new_node_pos = self.size();
            // The digest we push here doesn't matter as it will be updated later.
            self.nodes.push_back(self.dirty_digest);
            self.dirty_nodes.insert((new_node_pos, height));
            height += 1;
        }

        leaf_pos
    }

    /// Add a leaf's `digest` to the MMR, generating the necessary parent nodes to maintain the
    /// MMR's structure.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub(super) fn add_leaf_digest(&mut self, hasher: &mut impl Hasher<H>, mut digest: H::Digest) {
        assert!(
            self.dirty_nodes.is_empty(),
            "dirty nodes must be processed before adding an element w/o batching"
        );
        let nodes_needing_parents = nodes_needing_parents(self.peak_iterator())
            .into_iter()
            .rev();
        self.nodes.push_back(digest);

        // Compute the new parent nodes if any, and insert them into the MMR.
        for sibling_pos in nodes_needing_parents {
            let new_node_pos = self.size();
            let sibling_digest = self.get_node_unchecked(sibling_pos);
            digest = hasher.node_digest(new_node_pos, sibling_digest, &digest);
            self.nodes.push_back(digest);
        }
    }

    /// Pop the most recent leaf element out of the MMR if it exists, returning Empty or
    /// ElementPruned errors otherwise.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub fn pop(&mut self) -> Result<u64, Error> {
        if self.size() == 0 {
            return Err(Empty);
        }
        assert!(
            self.dirty_nodes.is_empty(),
            "dirty nodes must be processed before popping elements"
        );

        let mut new_size = self.size() - 1;
        loop {
            if new_size < self.pruned_to_pos {
                return Err(ElementPruned(new_size));
            }
            if PeakIterator::check_validity(new_size) {
                break;
            }
            new_size -= 1;
        }
        let num_to_drain = (self.size() - new_size) as usize;
        self.nodes.drain(self.nodes.len() - num_to_drain..);

        Ok(self.size())
    }

    /// Change the digest of any retained leaf. This is useful if you want to use the MMR
    /// implementation as an updatable binary Merkle tree, and otherwise should be avoided.
    ///
    /// # Warning
    ///
    /// - Panics if `pos` does not correspond to a leaf, or if the leaf has been pruned.
    ///
    /// - This method will change the root and invalidate any previous inclusion proofs.
    ///
    /// - Use of this method will prevent using this structure as a base mmr for grafting.
    pub fn update_leaf(&mut self, hasher: &mut impl Hasher<H>, pos: u64, element: &[u8]) {
        if pos < self.pruned_to_pos {
            panic!("element pruned: pos={pos}");
        }

        // Update the digest of the leaf node.
        let mut digest = hasher.leaf_digest(pos, element);
        let mut index = self.pos_to_index(pos);
        self.nodes[index] = digest;

        // Update digests of all its ancestors.
        for (peak_pos, height) in self.peak_iterator() {
            if peak_pos < pos {
                continue;
            }
            // We have found the mountain containing the path we need to update.
            let path: Vec<_> = PathIterator::new(pos, peak_pos, height).collect();
            for (parent_pos, sibling_pos) in path.into_iter().rev() {
                if parent_pos == pos {
                    panic!("pos was not for a leaf");
                }
                let sibling_digest = self.get_node_unchecked(sibling_pos);
                digest = if sibling_pos == parent_pos - 1 {
                    // The sibling is the right child of the parent.
                    hasher.node_digest(parent_pos, &digest, sibling_digest)
                } else {
                    hasher.node_digest(parent_pos, sibling_digest, &digest)
                };
                index = self.pos_to_index(parent_pos);
                self.nodes[index] = digest;
            }
            return;
        }

        panic!("invalid pos {}:{}", pos, self.size())
    }

    /// Batch update the digests of multiple retained leaves.
    ///
    /// # Warning
    ///
    /// Panics if any of the updated leaves has been pruned.
    pub fn update_leaf_batched<T: AsRef<[u8]> + Sync>(
        &mut self,
        hasher: &mut impl Hasher<H>,
        updates: &[(u64, T)],
    ) {
        if updates.len() >= MIN_TO_PARALLELIZE && self.thread_pool.is_some() {
            self.update_leaf_parallel(hasher, updates);
            return;
        }

        for (pos, element) in updates {
            if *pos < self.pruned_to_pos {
                panic!("element pruned: pos={pos}");
            }

            // Update the digest of the leaf node and mark its ancestors as dirty.
            let digest = hasher.leaf_digest(*pos, element.as_ref());
            let index = self.pos_to_index(*pos);
            self.nodes[index] = digest;
            self.mark_dirty(*pos);
        }
    }

    /// Mark the non-leaf nodes in the path from the given position to the root as dirty, so that
    /// their digests are appropriately recomputed during the next `sync`.
    fn mark_dirty(&mut self, pos: u64) {
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
                if !self.dirty_nodes.insert((parent_pos, height)) {
                    break;
                }
                height += 1;
            }
            return;
        }

        panic!("invalid pos {}:{}", pos, self.size());
    }

    /// Batch update the digests of multiple retained leaves using multiple threads.
    ///
    /// # Warning
    ///
    /// Assumes `self.pool` is non-None and panics otherwise.
    fn update_leaf_parallel<T: AsRef<[u8]> + Sync>(
        &mut self,
        hasher: &mut impl Hasher<H>,
        updates: &[(u64, T)],
    ) {
        let pool = self.thread_pool.as_ref().unwrap().clone();
        pool.install(|| {
            let digests: Vec<(u64, H::Digest)> = updates
                .par_iter()
                .map_init(
                    || hasher.fork(),
                    |hasher, (pos, elem)| {
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

    /// Returns whether there are pending updates.
    pub fn is_dirty(&self) -> bool {
        !self.dirty_nodes.is_empty()
    }

    /// Process any pending batched updates.
    pub fn sync(&mut self, hasher: &mut impl Hasher<H>) {
        if self.dirty_nodes.is_empty() {
            return;
        }
        if self.dirty_nodes.len() >= MIN_TO_PARALLELIZE && self.thread_pool.is_some() {
            self.sync_parallel(hasher, MIN_TO_PARALLELIZE);
            return;
        }

        self.sync_serial(hasher);
    }

    fn sync_serial(&mut self, hasher: &mut impl Hasher<H>) {
        let mut nodes: Vec<(u64, u32)> = self.dirty_nodes.iter().copied().collect();
        self.dirty_nodes.clear();
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
    ///
    /// # Warning
    ///
    /// Assumes `self.pool` is non-None and panics otherwise.
    fn sync_parallel(&mut self, hasher: &mut impl Hasher<H>, min_to_parallelize: usize) {
        let mut nodes: Vec<(u64, u32)> = self.dirty_nodes.iter().copied().collect();
        self.dirty_nodes.clear();
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
                self.dirty_nodes = nodes[i - same_height.len()..].iter().copied().collect();
                self.sync_serial(hasher);
                return;
            }
            self.update_node_digests(hasher, &same_height, current_height);
            same_height.clear();
            current_height += 1;
            same_height.push(*pos);
        }

        if same_height.len() < min_to_parallelize {
            self.dirty_nodes = nodes[nodes.len() - same_height.len()..]
                .iter()
                .copied()
                .collect();
            self.sync_serial(hasher);
            return;
        }

        self.update_node_digests(hasher, &same_height, current_height);
    }

    /// Update digests of the given set of nodes of equal height in the MMR. Since they are all at
    /// the same height, this can be done in parallel without synchronization.
    ///
    /// # Warning
    ///
    /// Assumes `self.pool` is non-None and panics otherwise.
    fn update_node_digests(
        &mut self,
        hasher: &mut impl Hasher<H>,
        same_height: &[u64],
        height: u32,
    ) {
        let two_h = 1 << height;
        let pool = self.thread_pool.as_ref().unwrap().clone();
        pool.install(|| {
            let computed_digests: Vec<(usize, H::Digest)> = same_height
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

    /// Computes the root of the MMR.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub fn root(&self, hasher: &mut impl Hasher<H>) -> H::Digest {
        assert!(
            self.dirty_nodes.is_empty(),
            "dirty nodes must be processed before computing the root"
        );
        let peaks = self
            .peak_iterator()
            .map(|(peak_pos, _)| self.get_node_unchecked(peak_pos));
        let size = self.size();
        hasher.root(size, peaks)
    }

    /// Return an inclusion proof for the specified element. Returns ElementPruned error if some
    /// element needed to generate the proof has been pruned.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub async fn proof(&self, element_pos: u64) -> Result<Proof<H::Digest>, Error> {
        self.range_proof(element_pos, element_pos).await
    }

    /// Return an inclusion proof for the specified range of elements, inclusive of both endpoints.
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub async fn range_proof(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<H::Digest>, Error> {
        if start_element_pos < self.pruned_to_pos {
            return Err(ElementPruned(start_element_pos));
        }
        assert!(
            self.dirty_nodes.is_empty(),
            "dirty nodes must be processed before computing proofs"
        );
        Proof::<H::Digest>::range_proof(self, start_element_pos, end_element_pos).await
    }

    /// Prune all nodes and pin the O(log2(n)) number of them required for proof generation going
    /// forward.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            self.prune_to_pos(self.index_to_pos(self.nodes.len()));
        }
    }

    /// Prune all nodes up to but not including the given position, and pin the O(log2(n)) number of
    /// them required for proof generation.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub fn prune_to_pos(&mut self, pos: u64) {
        assert!(
            self.dirty_nodes.is_empty(),
            "dirty nodes must be processed before pruning"
        );
        // Recompute the set of older nodes to retain.
        self.pinned_nodes = self.nodes_to_pin(pos);
        let retained_nodes = self.pos_to_index(pos);
        self.nodes.drain(0..retained_nodes);
        self.pruned_to_pos = pos;
    }

    /// Get the nodes (position + digest) that need to be pinned (those required for proof
    /// generation) in this MMR when pruned to position `prune_pos`.
    pub(super) fn nodes_to_pin(&self, prune_pos: u64) -> HashMap<u64, H::Digest> {
        Proof::<H::Digest>::nodes_to_pin(prune_pos)
            .map(|pos| (pos, *self.get_node_unchecked(pos)))
            .collect()
    }

    /// Get the digests of nodes that need to be pinned (those required for proof generation) in
    /// this MMR when pruned to position `prune_pos`.
    pub(super) fn node_digests_to_pin(&self, start_pos: u64) -> Vec<H::Digest> {
        Proof::<H::Digest>::nodes_to_pin(start_pos)
            .map(|pos| *self.get_node_unchecked(pos))
            .collect()
    }

    /// Utility used by stores that build on the mem MMR to pin extra nodes if needed. It's up to
    /// the caller to ensure that this set of pinned nodes is valid for their use case.
    pub(super) fn add_pinned_nodes(&mut self, pinned_nodes: HashMap<u64, H::Digest>) {
        for (pos, node) in pinned_nodes.into_iter() {
            self.pinned_nodes.insert(pos, node);
        }
    }

    /// A lightweight cloning operation that "clones" only the fully pruned state of this MMR. The
    /// output is exactly the same as the result of mmr.prune_all(), only you get a copy without
    /// mutating the original, and the thread pool if any is not cloned.
    ///
    /// Runtime is Log_2(n) in the number of elements even if the original MMR is never pruned.
    ///
    /// # Warning
    ///
    /// Panics if there are unprocessed batch updates.
    pub fn clone_pruned(&self) -> Self {
        if self.size() == 0 {
            return Self::new();
        }
        assert!(
            self.dirty_nodes.is_empty(),
            "dirty nodes must be processed before cloning"
        );

        // Create the "old_nodes" of the MMR in the fully pruned state.
        let old_nodes = self.node_digests_to_pin(self.size());

        Self::init(Config {
            nodes: vec![],
            pruned_to_pos: self.size(),
            pinned_nodes: old_nodes,
            pool: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::{
        hasher::Standard,
        iterator::leaf_num_to_pos,
        tests::{build_and_check_test_roots_mmr, build_batched_and_check_test_roots, ROOTS},
    };
    use commonware_cryptography::Sha256;
    use commonware_runtime::{create_pool, deterministic, tokio, Runner};
    use commonware_utils::hex;

    /// Test empty MMR behavior.
    #[test]
    fn test_mem_mmr_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new();
            assert_eq!(
                mmr.peak_iterator().next(),
                None,
                "empty iterator should have no peaks"
            );
            assert_eq!(mmr.size(), 0);
            assert_eq!(mmr.last_leaf_pos(), None);
            assert_eq!(mmr.oldest_retained_pos(), None);
            assert_eq!(mmr.get_node(0), None);
            assert!(matches!(mmr.pop(), Err(Empty)));
            mmr.prune_all();
            assert_eq!(mmr.size(), 0, "prune_all on empty MMR should do nothing");

            assert_eq!(mmr.root(&mut hasher), hasher.root(0, [].iter()));

            let clone = mmr.clone_pruned();
            assert_eq!(clone.size(), 0);
        });
    }

    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    #[test]
    fn test_mem_mmr_add_eleven_values() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new();
            let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<u64> = Vec::new();
            let mut hasher: Standard<Sha256> = Standard::new();
            for _ in 0..11 {
                leaves.push(mmr.add(&mut hasher, &element));
                assert_eq!(mmr.last_leaf_pos().unwrap(), *leaves.last().unwrap());
                let peaks: Vec<(u64, u32)> = mmr.peak_iterator().collect();
                assert_ne!(peaks.len(), 0);
                assert!(peaks.len() <= mmr.size() as usize);
                let nodes_needing_parents = nodes_needing_parents(mmr.peak_iterator());
                assert!(nodes_needing_parents.len() <= peaks.len());
            }
            assert_eq!(mmr.oldest_retained_pos().unwrap(), 0);
            assert_eq!(mmr.size(), 19, "mmr not of expected size");
            assert_eq!(
                leaves,
                vec![0, 1, 3, 4, 7, 8, 10, 11, 15, 16, 18],
                "mmr leaf positions not as expected"
            );
            let peaks: Vec<(u64, u32)> = mmr.peak_iterator().collect();
            assert_eq!(
                peaks,
                vec![(14, 3), (17, 1), (18, 0)],
                "mmr peaks not as expected"
            );

            // Test nodes_needing_parents on the final MMR. Since there's a height gap between the
            // highest peak (14) and the next, only the lower two peaks (17, 18) should be returned.
            let peaks_needing_parents = nodes_needing_parents(mmr.peak_iterator());
            assert_eq!(
                peaks_needing_parents,
                vec![17, 18],
                "mmr nodes needing parents not as expected"
            );

            // verify leaf digests
            for leaf in leaves.iter().by_ref() {
                let digest = hasher.leaf_digest(*leaf, &element);
                assert_eq!(mmr.get_node(*leaf).unwrap(), digest);
            }

            // verify height=1 node digests
            let digest2 = hasher.node_digest(2, &mmr.nodes[0], &mmr.nodes[1]);
            assert_eq!(mmr.nodes[2], digest2);
            let digest5 = hasher.node_digest(5, &mmr.nodes[3], &mmr.nodes[4]);
            assert_eq!(mmr.nodes[5], digest5);
            let digest9 = hasher.node_digest(9, &mmr.nodes[7], &mmr.nodes[8]);
            assert_eq!(mmr.nodes[9], digest9);
            let digest12 = hasher.node_digest(12, &mmr.nodes[10], &mmr.nodes[11]);
            assert_eq!(mmr.nodes[12], digest12);
            let digest17 = hasher.node_digest(17, &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], digest17);

            // verify height=2 node digests
            let digest6 = hasher.node_digest(6, &mmr.nodes[2], &mmr.nodes[5]);
            assert_eq!(mmr.nodes[6], digest6);
            let digest13 = hasher.node_digest(13, &mmr.nodes[9], &mmr.nodes[12]);
            assert_eq!(mmr.nodes[13], digest13);
            let digest17 = hasher.node_digest(17, &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], digest17);

            // verify topmost digest
            let digest14 = hasher.node_digest(14, &mmr.nodes[6], &mmr.nodes[13]);
            assert_eq!(mmr.nodes[14], digest14);

            // verify root
            let root = mmr.root(&mut hasher);
            let peak_digests = [digest14, digest17, mmr.nodes[18]];
            let expected_root = hasher.root(19, peak_digests.iter());
            assert_eq!(root, expected_root, "incorrect root");

            // pruning tests
            mmr.prune_to_pos(14); // prune up to the tallest peak
            assert_eq!(mmr.oldest_retained_pos().unwrap(), 14);

            // After pruning up to a peak, we shouldn't be able to prove any elements before it.
            assert!(matches!(mmr.proof(0).await, Err(ElementPruned(_))));
            assert!(matches!(mmr.proof(11).await, Err(ElementPruned(_))));
            // We should still be able to prove any leaf following this peak, the first of which is
            // at position 15.
            assert!(mmr.proof(15).await.is_ok());

            let root_after_prune = mmr.root(&mut hasher);
            assert_eq!(root, root_after_prune, "root changed after pruning");
            assert!(
                mmr.proof(11).await.is_err(),
                "attempts to prove elements at or before the oldest retained should fail"
            );
            assert!(
                mmr.range_proof(10, 15).await.is_err(),
                "attempts to range_prove elements at or before the oldest retained should fail"
            );
            assert!(
                mmr.range_proof(15, mmr.last_leaf_pos().unwrap())
                    .await
                    .is_ok(),
                "attempts to range_prove over elements following oldest retained should succeed"
            );

            // Test that we can initialize a new MMR from another's elements.
            let oldest_pos = mmr.oldest_retained_pos().unwrap();
            let digests = mmr.node_digests_to_pin(oldest_pos);
            let mmr_copy = Mmr::init(Config {
                nodes: mmr.nodes.iter().copied().collect(),
                pruned_to_pos: oldest_pos,
                pinned_nodes: digests,
                pool: None,
            });
            assert_eq!(mmr_copy.size(), 19);
            assert_eq!(mmr_copy.oldest_retained_pos(), mmr.oldest_retained_pos());
            assert_eq!(mmr_copy.root(&mut hasher), root);

            // Test that clone_pruned produces a valid copy of the MMR as if it had been cloned
            // after being fully pruned.
            mmr.prune_to_pos(17); // prune up to the second peak
            let clone = mmr.clone_pruned();
            assert_eq!(clone.oldest_retained_pos(), None);
            assert_eq!(clone.pruned_to_pos(), clone.size());
            mmr.prune_all();
            assert_eq!(mmr.oldest_retained_pos(), None);
            assert_eq!(mmr.pruned_to_pos(), mmr.size());
            assert_eq!(mmr.size(), clone.size());
            assert_eq!(mmr.root(&mut hasher), clone.root(&mut hasher));
        });
    }

    /// Test that pruning all nodes never breaks adding new nodes.
    #[test]
    fn test_mem_mmr_prune_all() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new();
            let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut hasher: Standard<Sha256> = Standard::new();
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
            let mut mmr = Mmr::new();
            let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut hasher: Standard<Sha256> = Standard::new();
            for _ in 0..1001 {
                assert!(
                    PeakIterator::check_validity(mmr.size()),
                    "mmr of size {} should be valid",
                    mmr.size()
                );
                let old_size = mmr.size();
                mmr.add(&mut hasher, &element);
                for size in old_size + 1..mmr.size() {
                    assert!(
                        !PeakIterator::check_validity(size),
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
            let mut mmr = Mmr::new();
            build_and_check_test_roots_mmr(&mut mmr).await;

            let mut mmr = Mmr::new();
            build_batched_and_check_test_roots(&mut mmr).await;
        });
    }

    /// Test root stability using the parallel builder implementation. This requires we use the
    /// tokio runtime since the deterministic runtime would block due to being single-threaded.
    #[test]
    fn test_mem_mmr_root_stability_parallel() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            let pool = commonware_runtime::create_pool(context, 4).unwrap();

            let mut mmr = Mmr::init(Config {
                nodes: vec![],
                pruned_to_pos: 0,
                pinned_nodes: vec![],
                pool: Some(pool),
            });
            build_batched_and_check_test_roots(&mut mmr).await;
        });
    }

    /// Build the MMR corresponding to the stability test while pruning after each add, and confirm
    /// the static roots match that from the root computation.
    #[test]
    fn test_mem_mmr_root_stability_while_pruning() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new();
            for i in 0u64..199 {
                let root = mmr.root(&mut hasher);
                let expected_root = ROOTS[i as usize];
                assert_eq!(hex(&root), expected_root, "at: {i}");
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                mmr.add(&mut hasher, &element);
                mmr.prune_all();
            }
        });
    }

    fn compute_big_mmr(hasher: &mut impl Hasher<Sha256>, mmr: &mut Mmr<Sha256>) -> Vec<u64> {
        let mut leaves = Vec::new();
        let mut c_hasher = Sha256::default();
        for i in 0u64..199 {
            c_hasher.update(&i.to_be_bytes());
            let element = c_hasher.finalize();
            leaves.push(mmr.add(hasher, &element));
        }
        mmr.sync(hasher);

        leaves
    }

    #[test]
    fn test_mem_mmr_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hasher: Standard<Sha256> = Standard::new();
            let mut mmr = Mmr::new();
            compute_big_mmr(&mut hasher, &mut mmr);
            let root = mmr.root(&mut hasher);
            let expected_root = ROOTS[199];
            assert_eq!(hex(&root), expected_root);

            // Pop off one node at a time until empty, confirming the root is still is as expected.
            for i in (0..199u64).rev() {
                assert!(mmr.pop().is_ok());
                let root = mmr.root(&mut hasher);
                let expected_root = ROOTS[i as usize];
                assert_eq!(hex(&root), expected_root);
            }

            assert!(
                matches!(mmr.pop().unwrap_err(), Empty),
                "pop on empty MMR should fail"
            );

            // Test that we can pop all elements up to and including the oldest retained leaf.
            for i in 0u64..199 {
                hasher.inner().update(&i.to_be_bytes());
                let element = hasher.inner().finalize();
                mmr.add(&mut hasher, &element);
            }

            let leaf_pos = leaf_num_to_pos(100);
            mmr.prune_to_pos(leaf_pos);
            while mmr.size() > leaf_pos {
                assert!(mmr.pop().is_ok());
            }
            assert_eq!(hex(&mmr.root(&mut hasher)), ROOTS[100]);
            assert!(matches!(mmr.pop().unwrap_err(), ElementPruned(_)));
            assert_eq!(mmr.oldest_retained_pos(), None);
        });
    }

    #[test]
    fn test_mem_mmr_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new();
            compute_big_mmr(&mut hasher, &mut mmr);
            let leaves = compute_big_mmr(&mut hasher, &mut mmr);
            let root = mmr.root(&mut hasher);

            // For a few leaves, update the leaf and ensure the root changes, and the root reverts
            // to its previous state then we update the leaf to its original value.
            for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
                // Change the leaf.
                mmr.update_leaf(&mut hasher, leaves[leaf], &element);
                let updated_root = mmr.root(&mut hasher);
                assert!(root != updated_root);

                // Restore the leaf to its original value, ensure the root is as before.
                hasher.inner().update(&leaf.to_be_bytes());
                let element = hasher.inner().finalize();
                mmr.update_leaf(&mut hasher, leaves[leaf], &element);
                let restored_root = mmr.root(&mut hasher);
                assert_eq!(root, restored_root);
            }

            // Confirm the tree has all the hashes necessary to update any element after pruning.
            mmr.prune_to_pos(leaves[150]);
            for &leaf_pos in &leaves[150..=190] {
                mmr.prune_to_pos(leaf_pos);
                mmr.update_leaf(&mut hasher, leaf_pos, &element);
            }
        });
    }

    #[test]
    #[should_panic(expected = "pos was not for a leaf")]
    fn test_mem_mmr_update_leaf_panic_invalid() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new();
            compute_big_mmr(&mut hasher, &mut mmr);
            let not_a_leaf_pos = 2;
            mmr.update_leaf(&mut hasher, not_a_leaf_pos, &element);
        });
    }

    #[test]
    #[should_panic(expected = "element pruned")]
    fn test_mem_mmr_update_leaf_panic_pruned() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");

        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new();
            compute_big_mmr(&mut hasher, &mut mmr);
            mmr.prune_all();
            mmr.update_leaf(&mut hasher, 0, &element);
        });
    }

    #[test]
    fn test_mem_mmr_batch_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut mmr = Mmr::new();
            let leaves = compute_big_mmr(&mut hasher, &mut mmr);
            do_batch_update(&mut hasher, &mut mmr, &leaves);
        });
    }

    #[test]
    /// Same test as above only using a thread pool to trigger parallelization. This requires we use
    /// tokio runtime instead of the deterministic one.
    fn test_mem_mmr_batch_parallel_update_leaf() {
        let mut hasher: Standard<Sha256> = Standard::new();
        let executor = tokio::Runner::default();
        executor.start(|ctx| async move {
            let pool = create_pool(ctx, 4).unwrap();
            let mut mmr = Mmr::init(Config {
                nodes: Vec::new(),
                pruned_to_pos: 0,
                pinned_nodes: Vec::new(),
                pool: Some(pool),
            });
            let leaves = compute_big_mmr(&mut hasher, &mut mmr);
            do_batch_update(&mut hasher, &mut mmr, &leaves);
        });
    }

    fn do_batch_update(hasher: &mut Standard<Sha256>, mmr: &mut Mmr<Sha256>, leaves: &[u64]) {
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
        let root = mmr.root(hasher);

        // Change a handful of leaves using a batch update.
        let mut updates = Vec::new();
        for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
            updates.push((leaves[leaf], &element));
        }
        mmr.update_leaf_batched(hasher, &updates);

        mmr.sync(hasher);
        let updated_root = mmr.root(hasher);
        assert_eq!(
            "af3acad6aad59c1a880de643b1200a0962a95d06c087ebf677f29eb93fc359a4",
            hex(&updated_root)
        );

        // Batch-restore the changed leaves to their original values.
        let mut updates = Vec::new();
        for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
            hasher.inner().update(&leaf.to_be_bytes());
            let element = hasher.inner().finalize();
            updates.push((leaves[leaf], element));
        }
        mmr.update_leaf_batched(hasher, &updates);

        mmr.sync(hasher);
        let restored_root = mmr.root(hasher);
        assert_eq!(root, restored_root);
    }
}
