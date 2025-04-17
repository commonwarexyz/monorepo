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
    hasher::Hasher,
    iterator::{nodes_needing_parents, PathIterator, PeakIterator},
    verification::{Proof, Storage},
    Error,
    Error::{ElementPruned, Empty},
};
use commonware_cryptography::Hasher as CHasher;
use std::collections::{HashMap, VecDeque};

/// Implementation of `Mmr`.
///
/// # Max Capacity
///
/// The maximum number of elements that can be stored is usize::MAX
/// (u32::MAX on 32-bit architectures).
pub struct Mmr<H: CHasher> {
    // The nodes of the MMR, laid out according to a post-order traversal of the MMR trees, starting
    // from the from tallest tree to shortest.
    nodes: VecDeque<H::Digest>,

    // The position of the oldest element still retained by the MMR, or the size of the MMR if there
    // are no retained nodes because the MMR is empty or it has been fully pruned.
    pub(crate) oldest_retained_pos: u64,

    // The auxiliary map from node position to the digest of any pinned node.
    pub(crate) pinned_nodes: HashMap<u64, H::Digest>,
}

impl<H: CHasher> Default for Mmr<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Storage<H::Digest> for Mmr<H> {
    async fn size(&self) -> Result<u64, Error> {
        Ok(self.size())
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        Ok(self.get_node(position))
    }
}

impl<H: CHasher> Mmr<H> {
    /// Return a new (empty) `Mmr`.
    pub fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            oldest_retained_pos: 0,
            pinned_nodes: HashMap::new(),
        }
    }

    /// Return an `Mmr` initialized with the given nodes, oldest retained position, and hashes of
    /// pinned nodes.
    pub fn init(
        nodes: Vec<H::Digest>,
        oldest_retained_pos: u64,
        pinned_nodes: Vec<H::Digest>,
    ) -> Self {
        let mut mmr = Self {
            nodes: VecDeque::from(nodes),
            oldest_retained_pos,
            pinned_nodes: HashMap::new(),
        };
        if mmr.size() == 0 {
            return mmr;
        }

        let required_positions = Proof::<H>::nodes_to_pin(mmr.size(), oldest_retained_pos);
        assert_eq!(pinned_nodes.len(), required_positions.len());
        for (i, pos) in required_positions.into_iter().enumerate() {
            mmr.pinned_nodes.insert(pos, pinned_nodes[i]);
        }

        mmr
    }

    /// Return the total number of nodes in the MMR, irrespective of any pruning. The next added
    /// element's position will have this value.
    pub fn size(&self) -> u64 {
        self.nodes.len() as u64 + self.oldest_retained_pos
    }

    pub fn last_leaf_pos(&self) -> Option<u64> {
        if self.size() == 0 {
            return None;
        }

        Some(PeakIterator::last_leaf_pos(self.size()))
    }

    /// Return the position of the oldest retained node in the MMR, not including those cached in
    /// pinned_nodes.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        if self.oldest_retained_pos == self.size() {
            return None;
        }

        Some(self.oldest_retained_pos)
    }

    /// Return a new iterator over the peaks of the MMR.
    pub(crate) fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Return the position of the element given its index in the current nodes vector.
    fn index_to_pos(&self, index: usize) -> u64 {
        index as u64 + self.oldest_retained_pos
    }

    /// Returns the requested node, assuming it is either retained or known to exist in the
    /// pinned_nodes map.
    pub fn get_node_unchecked(&self, pos: u64) -> &H::Digest {
        if pos < self.oldest_retained_pos {
            return self.pinned_nodes.get(&pos).unwrap();
        }

        &self.nodes[self.pos_to_index(pos)]
    }

    /// Returns the requested node or None if it is not stored in the MMR.
    pub fn get_node(&self, pos: u64) -> Option<H::Digest> {
        if pos < self.oldest_retained_pos {
            return self.pinned_nodes.get(&pos).copied();
        }

        self.nodes.get(self.pos_to_index(pos)).copied()
    }

    /// Return the index of the element in the current nodes vector given its position in the MMR.
    ///
    /// Will underflow if `pos` precedes the oldest retained position.
    fn pos_to_index(&self, pos: u64) -> usize {
        (pos - self.oldest_retained_pos) as usize
    }

    /// Add an element to the MMR and return its position in the MMR.
    pub fn add(&mut self, hasher: &mut H, element: &[u8]) -> u64 {
        let element_pos = self.index_to_pos(self.nodes.len());
        let hash = Hasher::new(hasher).leaf_hash(element_pos, element);
        self.add_leaf_digest(hasher, hash);

        element_pos
    }

    /// Add a leaf's `digest` to the MMR, generating the necessary parent nodes to maintain the
    /// MMR's structure.
    pub(crate) fn add_leaf_digest(&mut self, hasher: &mut H, mut digest: H::Digest) {
        let peaks = nodes_needing_parents(self.peak_iterator());
        self.nodes.push_back(digest);

        // Compute the new parent nodes if any, and insert them into the MMR.
        let mut h = Hasher::new(hasher);
        for sibling_pos in peaks.into_iter().rev() {
            let parent_pos = self.index_to_pos(self.nodes.len());
            let sibling_hash = self.get_node_unchecked(sibling_pos);
            digest = h.node_hash(parent_pos, sibling_hash, &digest);
            self.nodes.push_back(digest);
        }
    }

    /// Pop the most recent leaf element out of the MMR if it exists, returning Empty or
    /// ElementPruned errors otherwise.
    pub fn pop(&mut self) -> Result<u64, Error> {
        if self.size() == 0 {
            return Err(Empty);
        }

        let mut new_size = self.size() - 1;
        loop {
            if new_size < self.oldest_retained_pos {
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

    /// Change the digest of an existing leaf.   Panics if `pos` does not correspond to a leaf.
    ///
    /// # Warning
    ///
    /// This method will change the root hash and invalidate any previous inclusion proofs! This is
    /// useful if you want to use the MMR implementation as an updatable binary Merkle tree, and
    /// otherwise should be avoided. Returns ElementPruned if some element required to update the
    /// tree has been pruned.
    pub fn update_leaf(
        &mut self,
        hasher: &mut H,
        pos: u64,
        element: &H::Digest,
    ) -> Result<(), Error> {
        if pos < self.oldest_retained_pos {
            return Err(ElementPruned(pos));
        }

        for (peak_pos, height) in self.peak_iterator() {
            if peak_pos < pos {
                continue;
            }
            // We have found the mountain containing the leaf we want to update. Now update the
            // hashes of all nodes along the path from leaf to its peak.
            let mut h = Hasher::new(hasher);

            // Recompute the leaf node hash.
            let mut hash = h.leaf_hash(pos, element);
            let mut index = self.pos_to_index(pos);
            self.nodes[index] = hash;

            // Traverse up to the peak, recomputing each parent node hash along the way.
            let path: Vec<_> = PathIterator::new(pos, peak_pos, height).collect();
            for (parent_pos, sibling_pos) in path.into_iter().rev() {
                if sibling_pos < self.oldest_retained_pos {
                    return Err(ElementPruned(sibling_pos));
                }
                if parent_pos == pos {
                    panic!("pos was not for a leaf");
                }
                let sibling_hash = self.get_node_unchecked(sibling_pos);
                hash = if sibling_pos == parent_pos - 1 {
                    // The sibling is the right child of the parent.
                    h.node_hash(parent_pos, &hash, sibling_hash)
                } else {
                    h.node_hash(parent_pos, sibling_hash, &hash)
                };
                index = self.pos_to_index(parent_pos);
                self.nodes[index] = hash;
            }
            return Ok(());
        }

        panic!("invalid MMR")
    }

    /// Computes the root hash of the MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        let peaks = self
            .peak_iterator()
            .map(|(peak_pos, _)| self.get_node_unchecked(peak_pos));
        let size = self.size();
        Hasher::new(hasher).root_hash(size, peaks)
    }

    /// Return an inclusion proof for the specified element.
    ///
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    pub async fn proof(&self, element_pos: u64) -> Result<Proof<H>, Error> {
        self.range_proof(element_pos, element_pos).await
    }

    /// Return an inclusion proof for the specified range of elements, inclusive of both endpoints.
    ///
    /// Returns ElementPruned error if some element needed to generate the proof has been pruned.
    pub async fn range_proof(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<H>, Error> {
        if start_element_pos < self.oldest_retained_pos {
            return Err(ElementPruned(start_element_pos));
        }
        Proof::<H>::range_proof(self, start_element_pos, end_element_pos).await
    }

    /// Prune all nodes and pin the O(log2(n)) number of them required for proof generation going
    /// forward.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            self.prune_to_pos(self.index_to_pos(self.nodes.len()));
        }
    }

    /// Prune all nodes up to but not including the given position, and pin the O(log2(n)) number of
    /// them required for proof generation.
    pub fn prune_to_pos(&mut self, pos: u64) {
        // Recompute the set of older nodes to retain.
        self.pinned_nodes = self.nodes_to_pin(pos);
        let retained_nodes = self.pos_to_index(pos);
        self.nodes.drain(0..retained_nodes);
        self.oldest_retained_pos = pos;
    }

    /// Get the nodes (position + digest) that need to be pinned (those required for proof
    /// generation) in this MMR when pruned to position `prune_pos`.
    pub(crate) fn nodes_to_pin(&self, prune_pos: u64) -> HashMap<u64, H::Digest> {
        let positions = Proof::<H>::nodes_to_pin(self.size(), prune_pos);
        positions
            .into_iter()
            .map(|pos| (pos, *self.get_node_unchecked(pos)))
            .collect()
    }

    /// Get the digests of nodes that need to be pinned (those required for proof generation) in
    /// this MMR when pruned to position `prune_pos`.
    pub(crate) fn node_digests_to_pin(&self, start_pos: u64) -> Vec<H::Digest> {
        let positions = Proof::<H>::nodes_to_pin(self.size(), start_pos);
        positions
            .into_iter()
            .map(|pos| *self.get_node_unchecked(pos))
            .collect()
    }

    /// Utility used by stores that build on the mem MMR to pin extra nodes if needed. It's up to
    /// the caller to ensure that this set of pinned nodes is valid for their use case.
    pub(crate) fn add_pinned_nodes(&mut self, pinned_nodes: HashMap<u64, H::Digest>) {
        for (pos, node) in pinned_nodes.into_iter() {
            self.pinned_nodes.insert(pos, node);
        }
    }

    // A lightweight cloning operation that "clones" only the fully pruned state of this MMR. The
    // output is exactly the same as the result of mmr.prune_all(), only you get a copy without
    // mutating the original.
    //
    // Overhead is Log_2(n) in the number of elements even if the original MMR is never pruned.
    pub fn clone_pruned(&self) -> Self {
        if self.size() == 0 {
            return Self::new();
        }

        // Create the "old_nodes" of the MMR in the fully pruned state.
        let old_nodes = self.node_digests_to_pin(self.size());

        Self::init(vec![], self.size(), old_nodes)
    }
}

// We make this tests module pub(crate) so other mmr types (such as the journaled MMR) can use the
// same precomputed ROOTS.
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::mmr::iterator::leaf_num_to_pos;
    use commonware_cryptography::{Hasher as CHasher, Sha256};
    use commonware_runtime::{deterministic::Executor, Runner};
    use commonware_utils::hex;

    /// Test empty MMR behavior.
    #[test]
    fn test_mem_mmr_empty() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
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

            let mut hasher = Sha256::default();
            assert_eq!(
                mmr.root(&mut hasher),
                Hasher::new(&mut hasher).root_hash(0, [].iter())
            );

            let clone = mmr.clone_pruned();
            assert_eq!(clone.size(), 0);
        });
    }

    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    #[test]
    fn test_mem_mmr_add_eleven_values() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
            let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<u64> = Vec::new();
            let mut hasher = Sha256::default();
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

            // verify leaf hashes
            let mut hasher = Sha256::default();
            let mut mmr_hasher = Hasher::new(&mut hasher);
            for leaf in leaves.iter().by_ref() {
                let hash = mmr_hasher.leaf_hash(*leaf, &element);
                assert_eq!(mmr.get_node(*leaf).unwrap(), hash);
            }

            // verify height=1 hashes
            let hash2 = mmr_hasher.node_hash(2, &mmr.nodes[0], &mmr.nodes[1]);
            assert_eq!(mmr.nodes[2], hash2);
            let hash5 = mmr_hasher.node_hash(5, &mmr.nodes[3], &mmr.nodes[4]);
            assert_eq!(mmr.nodes[5], hash5);
            let hash9 = mmr_hasher.node_hash(9, &mmr.nodes[7], &mmr.nodes[8]);
            assert_eq!(mmr.nodes[9], hash9);
            let hash12 = mmr_hasher.node_hash(12, &mmr.nodes[10], &mmr.nodes[11]);
            assert_eq!(mmr.nodes[12], hash12);
            let hash17 = mmr_hasher.node_hash(17, &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], hash17);

            // verify height=2 hashes
            let hash6 = mmr_hasher.node_hash(6, &mmr.nodes[2], &mmr.nodes[5]);
            assert_eq!(mmr.nodes[6], hash6);
            let hash13 = mmr_hasher.node_hash(13, &mmr.nodes[9], &mmr.nodes[12]);
            assert_eq!(mmr.nodes[13], hash13);
            let hash17 = mmr_hasher.node_hash(17, &mmr.nodes[15], &mmr.nodes[16]);
            assert_eq!(mmr.nodes[17], hash17);

            // verify topmost hash
            let hash14 = mmr_hasher.node_hash(14, &mmr.nodes[6], &mmr.nodes[13]);
            assert_eq!(mmr.nodes[14], hash14);

            // verify root hash
            let mut hasher = Sha256::default();
            let root_hash = mmr.root(&mut hasher);
            let peak_hashes = [hash14, hash17, mmr.nodes[18]];
            let expected_root_hash = mmr_hasher.root_hash(19, peak_hashes.iter());
            assert_eq!(root_hash, expected_root_hash, "incorrect root hash");

            // pruning tests
            mmr.prune_to_pos(14); // prune up to the tallest peak
            assert_eq!(mmr.oldest_retained_pos().unwrap(), 14);

            // After pruning up to a peak, we shouldn't be able to prove any elements before it.
            assert!(matches!(mmr.proof(0).await, Err(ElementPruned(_))));
            assert!(matches!(mmr.proof(11).await, Err(ElementPruned(_))));
            // We should still be able to prove any leaf following this peak, the first of which is
            // at position 15.
            assert!(mmr.proof(15).await.is_ok());

            let root_hash_after_prune = mmr.root(&mut hasher);
            assert_eq!(
                root_hash, root_hash_after_prune,
                "root hash changed after pruning"
            );
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
            let mmr_copy =
                Mmr::<Sha256>::init(mmr.nodes.iter().copied().collect(), oldest_pos, digests);
            assert_eq!(mmr_copy.size(), 19);
            assert_eq!(mmr_copy.oldest_retained_pos(), mmr.oldest_retained_pos());
            assert_eq!(mmr_copy.root(&mut hasher), root_hash);

            // Test that clone_pruned produces a valid copy of the MMR as if it had been cloned
            // after being fully pruned.
            mmr.prune_to_pos(17); // prune up to the second peak
            let clone = mmr.clone_pruned();
            assert_eq!(clone.oldest_retained_pos(), None);
            mmr.prune_all();
            assert_eq!(mmr.oldest_retained_pos(), clone.oldest_retained_pos());
            assert_eq!(mmr.size(), clone.size());
            assert_eq!(mmr.root(&mut hasher), clone.root(&mut hasher));
        });
    }

    /// Test that pruning all nodes never breaks adding new nodes.
    #[test]
    fn test_mem_mmr_prune_all() {
        let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
        let mut hasher = Sha256::default();
        for _ in 0..1000 {
            mmr.prune_all();
            mmr.add(&mut hasher, &element);
        }
    }

    /// Test that the MMR validity check works as expected.
    #[test]
    fn test_mem_mmr_validity() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
            let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut hasher = Sha256::default();
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
                        "mmr of size {} should be invalid",
                        size
                    );
                }
            }
        });
    }

    /// Roots for all MMRs with 0..200 elements.
    ///
    /// We use these pre-generated roots to ensure that we don't silently change the tree hashing
    /// algorithm.
    pub(crate) const ROOTS: [&str; 200] = [
        "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
        "7676407563b96f8f78658b5b6fd523b190634cf5435393a66d62986a35cdd838",
        "ea9fecf8f1137ea087d15b8877a06e64029a2d2e7d8b8c2220213c8c590ad52a",
        "e9e73c4746ec9ad329e0abada3155b3266fe35c26b09fb4cf8e76afbd8890680",
        "4ce8f78f8411a10364a77ed458f458a5cc413cd2f92181403cb7302465a560c7",
        "055c9c09a4f8ff9d41f875f57ff9e7afeb7e58d554b35959755c0d6cd5180010",
        "36771d4af0af342207e650d874aaa292807831f33f416609c50a4d5bf220b386",
        "3985eaacbbe87805e27d4e1b82b1ffb76a9c9c705e8d7b75f604a86afc218c8a",
        "041a41f4c70f5be225c8c018b87b07da51aee80c9eb138ae4175f7f0a0e4e670",
        "f4107afbcbb927b2f70b0c0fa352eacd6c2c26a71385cfbb572d484c5806c1aa",
        "a41d7fb992e7d06f7b57835ee06cf6bbed6eb2b61c51d1e178c5c9753e542787",
        "6548a284abdd5fff9940e1a81cb0b7ab1225a060ebc8d2b961dd7d8cb1454727",
        "dde12753fdfa81d59e56297b9c3b444d7dcde8fd9033d7589fab5e915e9e1d86",
        "74c4c0772536bcbe5effe82fc7cdd8e46449306393547b64d52ac35912cdc583",
        "0f3fd4ba6b949a2cafce04c3fb9533e02bfb28a777efed50e7e0075e82769923",
        "1de606df85255961e2a2122a1b61a646b9dffdb7a39ea4ecffcc733e3ef7d049",
        "f0d797beb68b7e486139421ffe176ec21ce330a4debc914705d46c09938459f5",
        "09c9ebd8d7e528b4f1f29be9efc07b9cfda86c268258cbec60da4c9090c74f56",
        "6368bf81a9984ee0ab7c1ccd8aec4c8baf22a14ec444ca97947cd1e7b0b50910",
        "7195003fd96b06d2345b5ea02811e082d5b2a8deba44e7b8bc7a678e75128064",
        "d93a67a13df9ae7568dc7b3a9015afbd4be0636447216406e2ef81d37aa2c5d1",
        "5968bdd338f60e08121a0424442b9b435159b53b4177a417acbb5e81d9afceed",
        "7b9cee8f420b6b58afe14f0be315d51e2da320154e2bd83b86b6ab65a5d6e7ba",
        "e800ab561317c4f514c8f4a9f8dee8608eb727009c8052d434ecb03e465335d0",
        "b75d0bcfb32273a6a150944631534c9181fca16e03ad083ad071d4d8aef30709",
        "f0339cc83740e3e48436c869d4434dd5e29957af1dc7ebd843e88b1ae543b868",
        "61bf5037f812646d25e260b2b79bf3bed9edf540c545a9119da5ca19a99f23ae",
        "6f08446b78fb39779ce769bc6907edf6d580047f151b8af98b3f1d68a6cab8db",
        "f54c366a4d2b19dfabcf9562e2a567b15c948498f172d223db09394648430956",
        "0d7f9d02077c8015a33a80b488e9510b4f219f34542cc985c1673fa73b3abf15",
        "ecbcdac946e4735fabbec373de0fe8fc74bdbb54751e3651b72b1a6dd2ee3254",
        "e3d831cb4f7e6bdf1f9236952559ce7e7ced856abb140660bae7e35559b607ed",
        "d62e272a2716613ab6a960eb2e16b211e387f03b5d129f6ff9093960e09cdc51",
        "eba0c1e246d0fab436cdcf8249ce55920014495d4490853463c1f0b9c51d45b8",
        "8824cdf87a4b60a31d1d30ad1b6fac753809afe1294b6b114522548c029905a6",
        "6c41cd344760a0f223ff77054da185aef8b1512223fe2f06c59b7371d9678619",
        "cf1b1aa2dbb0f78ad7f735a20d4689f2a7743cc6ce30e6fe8ab1c1578bc926fd",
        "39f59891c2273541174e621142638bc0ab354c953778f3a6ccaa3914489b6b8f",
        "3e5b56a3964418ba229bae1a766ac26f35d5f044c6a17f2fafecb677d85a3b64",
        "49d1d775d0ff5dd6fd247922f776469d3e236e0251a1533a86d06e0fc663a77d",
        "5b299678281ce68981e3e2f0c4deef0eec414222938bb5123a710ec9400571bf",
        "835017bdd0e05f61719c0e3b1e94dcc0cf0b60328420b8696dc0b7090dca8b48",
        "ef0603c1b30d49a9e38749947dd90d17e61b4483999e63489fe9efc920dd2745",
        "54f889f331d4e383cf05d04b2cab3f5512aefb4498b4ed13f97fc3a73a58605d",
        "1f355117e2d405c4a272da9a83f951e3a00998e30cc354ce9fa3d7acb3e06c78",
        "611102f648e71ee0aa8b0f1fb5dd6cb113f1630f640f8794bbedfd36d68b76f0",
        "8635c87f5664198965b59b6555c5c31c18d1dd0cfde8ad310f5945ed3af2c7d4",
        "91c45e51b06e91b1474947d79639e1dd806e93e4ad72fa190b817dcd2c619fab",
        "d57f5d6d868d3fdbb5d97d9b8d7684a73a7b4e4a9f854160a92a583acebe37af",
        "539c8263ade2a42e86307960defedadfbe0810840f0543ad5fe64e378044f146",
        "340361294fbc4357a84615a2c6c057d41015ac3688e45db2788f6027d158d7be",
        "3c19386acb0a97947765def9b0427eb6130618196b91977386749655baf90101",
        "9962dcc2db6cb1787b15824bbad54b03492ad7f23d86e3c6109e1649bc351a44",
        "c281f592cc55e5431228e8e075a801640e8f07907cb94d203e7a848236b74178",
        "125617fa7488d1ca193c62e1b62e360171ab00597ba06249ffa6b40e4636c8a1",
        "91cf03368afc21f8a16a5d29cd438eae36d605b17aa730495f1f52b2c405c76a",
        "5158ce6a963f0cbc29d9a278e19a173efecd4e4a76904d976759361251d05822",
        "e547785582ff991d26f7462361dea3bc3b3014d44798fbdade057ad71d0c348a",
        "0b8000d561d68767ec14f2a21be1df67dd97d5746f4112a08b208eabff5a3cc9",
        "1dd183efd7cd89a2f5f837ca4bc9ba1dd8b36146ae6ac4e20a3f6bb7a66cba2a",
        "a3eb0e974d929bb2fa8dc5e9abbe4fc51731bcd2b919095dfb0d1e3daec9cd63",
        "fece8b224f7a64d67f020736719fb2ac30bde795610ec251b5fd82de4f3777c4",
        "08366a2ad117c4af3c65c2c622f005903f308e5b36cf7d4abde6a85921e13bbf",
        "61385b246f058fa4a563b68c8463ea854419d253e716bc7854cbcfb2d5aaaa8c",
        "39b47c3734fa04c5e25ca3c1fdd05ba90b404c4312ff64ab677340bfd5c9f5d9",
        "856b58ba8121292eb139e8322a3a5dea720577a9ada1d3ec56309422a80cf574",
        "4790b9715efeae9224b30eb5b12a1dd931f5cd46bc429eb6fa3a26ac38c35913",
        "5e3513b039d2e4fb5aeab1b6d522d2592050ef6105b03c3b1a116cabc68eb20a",
        "3f181082097473f2f9acbdf6228007b8647a217835403d3128fafdb0c0d01beb",
        "38090af5752ce7d6f35e4dc3e75011622a1188f6a32407d01c2cb02933b05366",
        "3b8ef716575ba9ff2128fddaa235abcc6b67ea4fb4f4dc4422971459df2dd545",
        "434f5d9aa23c51d43646fa4a7a4f41086fe503c8e07a349ffe7358fb78ed036a",
        "b99507f44d111cfdf42bce385c513b1ee204208f0501f8a1935983f4aacb4663",
        "2824294b1b8959215c162a28e627e9433345e81ea6aef4bfada227ea03ea87bf",
        "8f1bf9667fbe4e42f6a567b554af125886cdb8b0a03a6b2afe123f1b21ef1e51",
        "d1d534ac950bf18cc225d02fa16a94a97fcbf66ec4a96c85003310123f51dd91",
        "2c70401526b22eb8d853b866b5f517a177b70e1bcb4abc2050022cab126eab8a",
        "294372879e02e89e54001843a835f8085fb16990ed788e1e17ab5baae3590d97",
        "ccd5e7d8102db4d2fe6016b605c1375fb3418f2239aabdb1efd8fe1436d618ee",
        "60f7e4c97258e2116cab06f72f7d2228377295ab55fc5b8cd68546fa2cff7180",
        "d59f34201e2aa8c3fd9e09b847ff0cd4d16074081ed763393b3438a61226bbb8",
        "dda8d247e04a419cf56d77e97b686ee5d7047d0e4a8b0eb0509ef497d162f019",
        "53ed258a5880a34bdd6dbdd56d78c4a8483d552016dc1f4be3f047b7037c4fdc",
        "1d017a52bba710fe44d442fc8ed6c0c0aa2bf897029500d6b2157d95251243af",
        "d9208fcb088daa3b18f475273dfabdf3e6ee119272ec70f9312c1c13440bd96b",
        "c196d0ff129a9cf99098faba4d9d3fff8bf1222f3accfdd066be316a400189d7",
        "1f7ef6763d1c515ab5c5cc26a16256de3b979bf55ec7e4bb77bf3a9f32a52ff7",
        "8644ce2d487e8343cb3fec379c28483dbc87516f84fa155febe2d17fdd8386a3",
        "c7313eef9f6531831391f0fb23471de96c01786ab568e699f44ca5780bd7bd02",
        "71ad2f97e4ba25c79b1006f44375525a9a691abf009bd2a85cfa97cabfcb736a",
        "02d45be470cb8fe79715438dc6f8fc5bbc3e85dd8d8e54eaab191b9fcd519259",
        "d370a5cadcdb0e41b4bee3e926fb424562b8035bcfa0d3371173ed9467698ea0",
        "2a69858f63545f8452a90524474b8859469ca06e52d7d4404d08d0278171546d",
        "9c02e6ed9f2d7b91a6be0796de5b2605085642545f56079a8759b946f81ed351",
        "ed4865a61aada2b14262deb60b5ccac5b8ef37f3df8b68cfa9d88c262225f89d",
        "1b116ac51f52d9d2fa5b02a62ae5efa2a0b7aa31a5abd2d20d02c6bb5289684f",
        "163f841a79813d06e3dd3fe3662734f49bc5cc020c41a81e11b2903005700e50",
        "d6c6958437610fd52ae44bafccc7940bf8fd26917ade7b55c0b15d5b70eb6609",
        "d4367a2ced0d467a3ae3195ee375888e545722b6d653479faebf19d886ffbc8f",
        "fbc4a385d5419a0f667abcc4fe09efc503accc057e7a4c84acfb9250c006b32e",
        "a584b1d4375a4e15706bab392601536378334d754cd491eef59611a949345d98",
        "8c5379636b9f91d91a0eb4d4101846a147e205c450e32ff854e25aba098a862d",
        "83338d52af9dd2dedc14e052d0bed495013dfde0ed87a88abb8cd8cec85e7109",
        "2925ec80c1a2511fbd92c23a3ac1210c588e574620c8644ff383fa61ae49cce7",
        "0f6fb936332ff8eda213ca907407f6f6e88bdedc39d36e72a4d271a921efba91",
        "c0b8ebd97919568c0eb3d91c5440d82c5113ba2364ee7130d94a54602c4e4f27",
        "dfa4e1e4aa007f82aae40be9c718137e1315e19da46a329a6caf4253a80ba3d3",
        "fe3cbba95b537ec75166eb548c3be6a85c88ca789d79557c176e8c1b90b3095f",
        "2963ba9fe2572c0c7827faaaa99bc2ba4863061f7ec0f61ac536b9c576679ffc",
        "6eb88bfa4d07d0fbdc5eb2d77c2504749b532efca883534a51781b62aa30ba65",
        "de5c2ae29dc7d7aa61a36f894665b8a59101616b3286bbc43c488f4e6d2d6be2",
        "352918398570aff052eb9044299ef7f97e8779e3b1572d2db44302746fa3e021",
        "f5c78b0f902f759fc3ca2763ec585ff200fbc9837431b6df02398e5eb13f6fe9",
        "be696289775fa55f47982dade7573a69398b084b21e4e02d5d13523bc315033e",
        "86e17e71a1b645e3efebb71eca1c4664a2b324bf99fd410966da373bb7357419",
        "2d0173464be0053ac627ef6024bc8c4056efe40520c148cc7b4fdcc8285390a8",
        "7f77a14d6175851afd844cdd4f289ab566e120190d42d57b167932c05964b2e5",
        "aab1912c61e2a8c99c2220cb5f8cc3ca0db82e9d8e655022e379f433aa701c49",
        "68076b2e51b9b32d84d0a69bb09a42c0f0c78a55171b25b881dd6f272ff9076b",
        "f8480344e34ad147ef9960af2d2a1631201642c93a7c0ec59ef432df874682fe",
        "63e870e86c4a95a4afbdfb75ca9f2f5928fbd866e3d8233d23f914603ed46178",
        "d04afced8358884ac74b60c73121d3f6d5fd54267501b891acc9577652f55358",
        "7f17d74afce5950c93c56c2acfecd1a3e98a445f8f06652d2fa1f0c4b042c2cf",
        "fdc8f413371d6de57d94b73fb2ba130ead6aaec491d2365418abf301cc31fbec",
        "201ae8590dcd4ef338f431c642d9a3e2381ca8d461fa3697977d98a3535aff86",
        "41b38461bb19e20d73392ad96ff453e19d9256d3e67232bdce68353600fbadb8",
        "008800687c883595708041976240864c6f16b947e73355850e2fec6278f271a6",
        "386abe200dd33e7d8b82497078af9bc8bdcd29d4f576d124f4cd7ab7d62de3ac",
        "ccfb11a1968121793585de0a46d3fa65d8622208de59f5807a64f09b5655cf6b",
        "792289bcfde5056b063d80b24d2cc547cd69b66d68d17cda260802b42ca6deb7",
        "9968f72a0025372c119a57aaa2cc6bc4097af32f4fbe74426400d40860fbeafe",
        "e494f16da9c92c9ff3a1084b57845cf35141f5235bd314137922762491b4ef29",
        "ce7cb8456d5e2d86e8df3de8fc9d405de713692c9a55f7c23b23f8c1350514ff",
        "51a69a4817e311923ecbff58b56e0579488023166325f5a7c7ca6b9f3d6bba7f",
        "a485b7b34fb0216a40b62dbbb2fd49dfeab651e44ea5adf069b7aa377f40b612",
        "3c527f8b5556a7e4d73f5c4a9fd929f16e620c04b71b12e42d3b450c00a83803",
        "33b1d7ab84b04b90145503f87471ba6ba742bd858da108245784f618954c9cb4",
        "984c179490367dc2d4a3f94037f7b78d9a42d87ea8eccf19bdd4b9e377c3dcb7",
        "8fa6b7139776fa3f4816f6b39562aa967f02a5a619ce76d24c9dfe1f4ac0e627",
        "d32ffff650711171cce566a61c7ffc55d1fe6a52ff3486aaf25525659a5db570",
        "9c05774a36aa9d0bfb071973e55d27d025c6fd21d0cd010ddc9432da04c552c9",
        "8a377da699bb85cf793c463649b1e53352c4d289c10a463e3da347cf0a7ce663",
        "b632a32ff6ccbe53c399095a47276937e0fa11f588e8166331c46282df6d7292",
        "86309e3a515432e814101aab1e718e1336dca9f91ef271ca4ead50f5bbc48d0b",
        "bffc5b71402d586aeea2ad682ede1c2b89adc37ff43816405816deccd3cae21b",
        "9727623aaf308cc8ce711e0b5f40fa76c906c9ca9f2892bb00f86f16dd297a32",
        "89f4c1bce56473e96bcd9fe06c07ae9e332a2b5f782fe6e3f2dcb88e57796025",
        "1272c8ba048225f0348819c6962f970622e05f2ad708a02932ad1a5b6ef0c6c5",
        "12133e775dea36c42631f3cca0b58d7af46cf3797ba690f302b5d28328bc4bce",
        "2b9d357c0bc0c4ef92645731fb49f3b82d19f0bca6191549c820e23b5f7ef488",
        "03f32ebf322815798d5c4596c83265274df86292ec74b65fce3b6e68f8bd6dc6",
        "b6b1e6eeeb449e2f34c52505f98ac857f46a8f98bfa9a9e4a86bc063ac2df669",
        "e458ce180dc8360f55219f23c6ff7df9a4fd0fffe2738e0385114d63b5665cfa",
        "84e476d0a1d5c9cb50805e32132502d4f403150f68e2405f6268276a0cd21358",
        "c09b56491c472926ca09562950096d213221592a9bae27b5b6c067587f2c1bf2",
        "a7163a4e8c61c064ac54a631159ec2c1726a1beadb41fe30ad71a276e32719b5",
        "3cd3a864fdf0f6d355d0628f364cbe4cb39fbed237a90a6fe5d512dc9c3780b0",
        "a5bfc49544ea5314339dd3c66e3147b7432325ceed7fdf5bba4c168417ee894d",
        "a7dce1d4ea213bfe0522c8a40d790b450725b2265fce7f487a8412f065408466",
        "53cf25cc550b0a6e6a4df67e412550efe85f466e19de0a3f75e5f4a279ebca3c",
        "e3b7cf4bc05489c7ab04fcd06f44429b10f3e397194ac335c7f04e3275305a58",
        "f1ea7417154ff412564381d0579245d5c5392f689cf156dab70392edb4575159",
        "ba3455b72800bcb2c4826532ee07747eb8cd5ad1357b57a0304bbad011298a5d",
        "86e9cee8ee0f181f5c32bc4624a4ad3aea76ee9e31c6ae2aa5a00be155875e54",
        "c8371b4a906542fbc26981fe54579031a6f23a3728accb5dfd2044e7dd2dbfe6",
        "db2902d25a95a72c081ef5685e8b4406963853fcf06e11f37b247b1486e697b2",
        "1beff6ec8bd1ebafa3923c96d6c1c1fc25d4ceeb12f6c7b04f56a960f42c8ebe",
        "1cf844c3c35d828aac85f93e1f5c611d2161df326163b123f6907f1b54a6bc1e",
        "22adf3131035ed1ef9808b658223a4278d5a06efb648577e88114a7b814e65cb",
        "56d44dbdaa62c1e1f826f1a99a55e4415d99f27043bcc3b999bb79115aa1cf89",
        "c805263481303944d9189469488d1dd36dbdc6d6d42fdc2971375051dfc511db",
        "5ebdcd3f7e2fe558be557d799f3ced886fc6a08cf38fa775d713f3f8b9485246",
        "7da5931e8cbcb6e151f2106e0b5f5198f44e62f2b29a4e47f3e3a4b05e622a36",
        "7dd08e28700d60231868088da9cbbb46056b732076edf1d6e07b816f9563594e",
        "b9be5856487edf3e7814e55bec8c118ddb5bef8150fb9ee74b40dae18b512a9e",
        "2f481eb9eb3ae2556ca6bd38478a7da87af01f0428242173adb086abb3258507",
        "3d5e3dda5b0c2cdab22ca513b4cebb024a6c260a90da24414e751d7cb0ee68b7",
        "d67a3388529c932f85daaa03c114dde54661716a33aada66b482337ff816c23e",
        "d16c6c6ad379b79cf417e1339afa81e63b5be20a6d19dbb9c6a5991cf7f78825",
        "fb6e7bde608b1bc0f5be4c34a63c51a4b2e934c91057bbd1e83860125d2e917c",
        "01902ecdab30d33d0df32fd32e663f46ec1aa09b10fbbaa5cca5b9038f635da4",
        "322428a14306d9cd75a54d7d4ce586c5a62a4beb84929f36703480c87a16baa0",
        "ae494e35f8632d1e89834750bf6b9f83a5abaf5ae108d387d75a99a41f262f53",
        "4d020bfff37176bafea76c529dbd743435c95efa64e4f79b613fa6ca11770ad7",
        "898922cbc36eaff9b38f17dd32fcfd22540d3df4bef31a0b6100660a34893f7b",
        "7fea96d799e7d286d99d1be11c28d02180d877d48d1d8258787c8e8df5b25467",
        "ef299195417e6aa3fe07ce847bbb1e4dfab8959700ccac0f0ca6f62d0d78bde5",
        "85e20d7eeea9600eb4313ba2f821fd25fa32a31f4d522b20bd71a4d4c7d3a9af",
        "6c748202320e8edc1fc1c5d0929d1824f728a0edfdb6732e59dcf7041e96edb4",
        "615079f8a57735afd423f355877a3421375dbad5ac485b3ccee503ec14788cec",
        "bbe47ac28fc3458d21c89b042e75539211e63f55e80f52edaee8365d2ca1d311",
        "a280b5d71c849e421292e484151e77dc1a0315e443100275a9b4fbded1ab6140",
        "a2a7815b07c156de0b9f5a2fd0c6ad73bd70d06fef7c328c0fefe95a43899c52",
        "c5252ffc458658cd274ea080b4c52a84ab0915d7e9fdc949b94bbc462fb46543",
        "bfa7188cd6e33ceb7db6c87b8afc3cea4098b90293d0d962315cc83d51f4710f",
        "a2f018444b66aef64c149c1bdf0bec28784772f09cc4abb3dcccb882bde089f8",
        "27f7d66ded874e6b5ac1843ea8147df16c79ac09fd1db2a5a0f5d6e76dea12e6",
        "a15e25ef9f2b99281a81a9926cd2b5bc9335ece7c35dd4ad99845bfb0ba8c0e9",
        "6ef54ff7810f3b28821950a29ec9a797c5f2b3fe79fb50bda7c392777752a4ff",
        "77a20dc05f10e9b4f494d3d22cdcddb7cbe5e99f951c2cee900c9024f34ab4e8",
    ];

    /// Test that the MMR root computation remains stable by comparing against previously computed
    /// roots.
    #[test]
    fn test_mem_mmr_root_stability() {
        let mut hasher = Sha256::new();
        for i in 0u64..200 {
            let mut mmr = Mmr::<Sha256>::new();
            for j in 0u64..i {
                hasher.update(&j.to_be_bytes());
                let element = hasher.finalize();
                mmr.add(&mut hasher, &element);
            }
            let root = mmr.root(&mut hasher);
            let expected_root = ROOTS[i as usize];
            assert_eq!(hex(&root), expected_root);

            // confirm pruning doesn't affect the root computation
            mmr.prune_all();
            let root2 = mmr.root(&mut hasher);
            assert_eq!(root, root2);
        }
    }

    fn compute_big_mmr(hasher: &mut Sha256) -> (Mmr<Sha256>, Vec<u64>) {
        let mut mmr = Mmr::<Sha256>::new();
        let mut leaves = Vec::new();
        for i in 0u64..199 {
            hasher.update(&i.to_be_bytes());
            let element = hasher.finalize();
            leaves.push(mmr.add(hasher, &element));
        }
        (mmr, leaves)
    }

    #[test]
    fn test_mem_mmr_pop() {
        let mut hasher = Sha256::new();
        let (mut mmr, _) = compute_big_mmr(&mut hasher);
        let root = mmr.root(&mut hasher);
        let expected_root = ROOTS[199];
        assert_eq!(hex(&root), expected_root);

        // Pop off one node at a time until empty, confirming the root hash is still is as expected.
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
            hasher.update(&i.to_be_bytes());
            let element = hasher.finalize();
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
    }

    #[test]
    fn test_mem_mmr_update_leaf() {
        let mut hasher = Sha256::new();
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");

        let (mut mmr, leaves) = compute_big_mmr(&mut hasher);
        let root = mmr.root(&mut hasher);

        // For a few leaves, update the leaf and ensure the root hash changes, and the root hash
        // reverts to its previous state then we update the leaf to its original value.
        for leaf in [0usize, 1, 10, 50, 100, 150, 197, 198] {
            // Change the leaf.
            mmr.update_leaf(&mut hasher, leaves[leaf], &element)
                .unwrap();
            let updated_root = mmr.root(&mut hasher);
            assert!(root != updated_root);

            // Restore the leaf to its original value, ensure the root hash is as before.
            hasher.update(&leaf.to_be_bytes());
            let element = hasher.finalize();
            mmr.update_leaf(&mut hasher, leaves[leaf], &element)
                .unwrap();
            let restored_root = mmr.root(&mut hasher);
            assert_eq!(root, restored_root);
        }

        // Confirm the function gracefully handles failures when the MMR is pruned.
        mmr.prune_to_pos(leaves[150]);
        assert!(matches!(
            mmr.update_leaf(&mut hasher, leaves[150], &element),
            Err(ElementPruned(_))
        ));
        assert!(matches!(
            mmr.update_leaf(&mut hasher, leaves[149], &element),
            Err(ElementPruned(_))
        ));
        assert!(mmr.update_leaf(&mut hasher, leaves[190], &element).is_ok());
    }

    #[test]
    #[should_panic(expected = "pos was not for a leaf")]
    fn test_mem_mmr_update_leaf_panic_invalid() {
        let mut hasher = Sha256::new();
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");

        let (mut mmr, _) = compute_big_mmr(&mut hasher);
        let not_a_leaf_pos = 2;

        let _ = mmr.update_leaf(&mut hasher, not_a_leaf_pos, &element);
    }
}
