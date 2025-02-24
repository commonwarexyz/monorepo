//! A basic MMR where all nodes are stored in-memory.

use crate::mmr::{
    hasher::Hasher,
    iterator::{
        nodes_needing_parents, oldest_provable_pos, oldest_required_proof_pos, PeakIterator,
    },
    verification::{Proof, Storage},
    Error,
    Error::ElementPruned,
};
use commonware_cryptography::Hasher as CHasher;
use std::collections::HashMap;

/// Implementation of `Mmr`.
///
/// # Max Capacity
///
/// The maximum number of elements that can be stored is usize::MAX
/// (u32::MAX on 32-bit architectures).
pub struct Mmr<H: CHasher> {
    // The nodes of the MMR, laid out according to a post-order traversal of the MMR trees, starting
    // from the from tallest tree to shortest.
    nodes: Vec<H::Digest>,

    // The position of the oldest element still retained by the MMR. Will be 0 unless pruning has
    // been invoked.
    oldest_retained_pos: u64,

    // The hashes of the MMR's peaks that are older than oldest_retained_pos, keyed by their
    // position.
    old_peaks: HashMap<u64, H::Digest>,
}

impl<H: CHasher> Default for Mmr<H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: CHasher> Storage<H> for Mmr<H> {
    async fn size(&self) -> Result<u64, Error> {
        Ok(self.size())
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, Error> {
        if position < self.oldest_retained_pos {
            match self.old_peaks.get(&position) {
                Some(node) => Ok(Some(node.clone())),
                None => Ok(None),
            }
        } else {
            match self.nodes.get(self.pos_to_index(position)) {
                Some(node) => Ok(Some(node.clone())),
                None => Ok(None),
            }
        }
    }
}

impl<H: CHasher> Mmr<H> {
    /// Return a new (empty) `Mmr`.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            oldest_retained_pos: 0,
            old_peaks: HashMap::new(),
        }
    }

    /// Return an `Mmr` initialized with the given nodes and oldest retained position, and hashes of
    /// any peaks that are older than the oldest retained position.
    pub fn init(
        nodes: Vec<H::Digest>,
        oldest_retained_pos: u64,
        old_peaks: Vec<H::Digest>,
    ) -> Self {
        let mut s = Self {
            nodes,
            oldest_retained_pos,
            old_peaks: HashMap::new(),
        };
        assert!(PeakIterator::check_validity(s.size()));
        let mut given_peak_iter = old_peaks.iter();
        for (peak, _) in s.peak_iterator() {
            if peak < s.oldest_retained_pos {
                let given_peak = given_peak_iter.next().unwrap();
                assert!(s.old_peaks.insert(peak, given_peak.clone()).is_none());
            }
        }
        assert!(given_peak_iter.next().is_none());
        s
    }

    /// Return the total number of nodes in the MMR, irrespective of any pruning.
    pub fn size(&self) -> u64 {
        self.nodes.len() as u64 + self.oldest_retained_pos
    }

    /// Return the position of the oldest retained node in the MMR, not including the peaks which
    /// are always retained.
    pub fn oldest_retained_pos(&self) -> Option<u64> {
        if self.size() == 0 {
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

    /// Returns the requested node, assuming it is either a peak or known to exist within the
    /// currently retained node set.
    fn get_node_unchecked(&self, pos: u64) -> &H::Digest {
        if pos >= self.oldest_retained_pos {
            &self.nodes[self.pos_to_index(pos)]
        } else {
            self.old_peaks.get(&pos).unwrap()
        }
    }

    /// Return the index of the element in the current nodes vector given its position in the MMR.
    ///
    /// Will underflow if `pos` precedes the oldest retained position.
    fn pos_to_index(&self, pos: u64) -> usize {
        (pos - self.oldest_retained_pos) as usize
    }

    /// Add an element to the MMR and return its position in the MMR.
    pub fn add(&mut self, hasher: &mut H, element: &H::Digest) -> u64 {
        let peaks = nodes_needing_parents(self.peak_iterator());
        let element_pos = self.index_to_pos(self.nodes.len());

        // Insert the element into the MMR as a leaf.
        let mut h = Hasher::new(hasher);
        let mut hash = h.leaf_hash(element_pos, element);
        self.nodes.push(hash.clone());

        // Compute the new parent nodes if any, and insert them into the MMR.
        for sibling_pos in peaks.into_iter().rev() {
            let parent_pos = self.index_to_pos(self.nodes.len());
            let sibling_hash = self.get_node_unchecked(sibling_pos);
            hash = h.node_hash(parent_pos, sibling_hash, &hash);
            self.nodes.push(hash.clone());
        }
        element_pos
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
            return Err(ElementPruned);
        }
        Proof::<H>::range_proof::<Mmr<H>>(self, start_element_pos, end_element_pos).await
    }

    /// Prune all but the very last node.
    ///
    /// This always leaves the MMR in a valid state since the last node is always a peak.
    pub fn prune_all(&mut self) {
        if !self.nodes.is_empty() {
            self.prune_to_pos(self.index_to_pos(self.nodes.len() - 1));
        }
    }

    /// Prune the maximum amount of nodes possible while still allowing nodes with position `pos`
    /// or newer to be provable, returning the position of the oldest retained node.
    pub fn prune(&mut self, pos: u64) -> Option<u64> {
        if self.size() == 0 {
            return None;
        }
        let oldest_pos = oldest_required_proof_pos(self.peak_iterator(), pos);
        self.prune_to_pos(oldest_pos);
        Some(oldest_pos)
    }

    /// Prune all nodes up to but not including the given position (except for any peaks in that
    /// range).
    ///
    /// Pruned nodes will no longer be provable, nor will some nodes that follow them in some cases.
    /// Use prune(pos) to guarantee a desired node (and all that follow it) will remain provable
    /// after pruning.
    pub(crate) fn prune_to_pos(&mut self, pos: u64) {
        for peak in self.peak_iterator() {
            if peak.0 < pos && peak.0 >= self.oldest_retained_pos {
                assert!(self
                    .old_peaks
                    .insert(peak.0, self.nodes[self.pos_to_index(peak.0)].clone())
                    .is_none());
            }
        }
        let nodes_to_keep = self.pos_to_index(pos);
        self.nodes = self.nodes[nodes_to_keep..self.nodes.len()].to_vec();
        self.oldest_retained_pos = pos;
    }

    /// Return the oldest node position provable by this MMR.
    pub fn oldest_provable_pos(&self) -> Option<u64> {
        if self.size() == 0 {
            return None;
        }
        Some(oldest_provable_pos(
            self.peak_iterator(),
            self.oldest_retained_pos,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{nodes_needing_parents, Error::*, Hasher, Mmr, PeakIterator, Storage};
    use commonware_cryptography::{Hasher as CHasher, Sha256};
    use commonware_runtime::{deterministic::Executor, Runner};
    use commonware_utils::hex;

    /// Test empty MMR behavior.
    #[test]
    fn test_empty() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
            assert_eq!(
                mmr.peak_iterator().next(),
                None,
                "empty iterator should have no peaks"
            );
            assert_eq!(mmr.size(), 0);
            assert_eq!(mmr.oldest_provable_pos(), None);
            assert_eq!(mmr.oldest_retained_pos(), None);
            assert_eq!(mmr.get_node(0).await.unwrap(), None);
            assert_eq!(mmr.prune(0), None);
            mmr.prune_all();
            assert_eq!(mmr.size(), 0, "prune_all on empty MMR should do nothing");

            let mut hasher = Sha256::default();
            assert_eq!(
                mmr.root(&mut hasher),
                Hasher::new(&mut hasher).root_hash(0, [].iter())
            );
        });
    }

    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    #[test]
    fn test_add_eleven_values() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
            let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
            let mut leaves: Vec<u64> = Vec::new();
            let mut hasher = Sha256::default();
            for _ in 0..11 {
                leaves.push(mmr.add(&mut hasher, &element));
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
                assert_eq!(mmr.get_node(*leaf).await.unwrap().unwrap(), hash);
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
            let peak_hashes = [hash14, hash17, mmr.nodes[18].clone()];
            let expected_root_hash = mmr_hasher.root_hash(19, peak_hashes.iter());
            assert_eq!(root_hash, expected_root_hash, "incorrect root hash");

            // pruning tests
            mmr.prune_to_pos(14); // prune up to the tallest peak
            assert_eq!(mmr.oldest_retained_pos().unwrap(), 14);

            // After pruning up to a peak, we shouldn't be able to prove any elements before it.
            assert!(matches!(mmr.proof(0).await, Err(ElementPruned)));
            assert!(matches!(mmr.proof(11).await, Err(ElementPruned)));
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
                mmr.range_proof(15, 18).await.is_ok(),
                "attempts to range_prove over elements following oldest retained should succeed"
            );

            // Test that we can initialize a new MMR from another's elements.
            let mut old_peaks = Vec::new();
            mmr.peak_iterator().for_each(|peak| {
                if peak.0 < mmr.oldest_retained_pos().unwrap() {
                    old_peaks.push(mmr.get_node_unchecked(peak.0).clone());
                }
            });
            let mmr_copy = Mmr::<Sha256>::init(
                mmr.nodes.clone(),
                mmr.oldest_retained_pos().unwrap(),
                old_peaks,
            );
            assert_eq!(mmr_copy.size(), 19);
            assert_eq!(mmr_copy.oldest_retained_pos(), mmr.oldest_retained_pos());
        });
    }

    /// Test that pruning all nodes never breaks adding new nodes.
    #[test]
    fn test_prune_all() {
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
    fn test_mmr_validity() {
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
    const ROOTS: [&str; 200] = [
        "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
        "6640b495f46158d2b2169660ba347b07eceba14ec540e480a4231e37dc53e967",
        "b894998e23d5623fee6e7c1e32670a8478f22d0a7bd4a575d01ef230b5a71085",
        "71c2307dbd1a02956eaf884d07d1ab44d3d627e5c61d1beaa634309b02ea740d",
        "8d041581b2e235f0bc1beb837628c47d88f55cb2ed58f4196c7b3a6c8198e2ea",
        "89a6e782a9bbc95592ac77f9bad179485bb6ffc2a6cca6f8dd5a06d014783ed4",
        "0900cd1c5650b22848decafd43231954f869f41b807e09ef798cee82cad4020d",
        "ec53a229c820f65bbab4e78c4b78a6f2ca2646369de8448271901214eab22d27",
        "8c89b88db860368e5af6ddce7449d72924e81088482f142c8dec2396414c760e",
        "870f4f27721467b2695773eacb3ff189986d44ccb1ae22eb5a2d07634b53e8aa",
        "368ab1fb2852e29f033dbe90e1f09311a453fc1abf0983fa75f1abef2a3fe70c",
        "4d212a438603ae6c2a8796ba3b5e305193a31bf9bc4723c0c968ef157d870ef1",
        "f2e8eb70dea7b1fc80ad1942c460931d64963e218a3cdfbcd578a7ddc9c3c2fb",
        "20b2c442188ac9e4431b06bd12e0e6dd05dbfb0db71327080d1e5e2590f7181a",
        "51f9a9edc70ca6a26cd0653e1459e160fc54e290594978f56e4b6b01b91e8a06",
        "d8130b8975e7918cd9583dc1c9c1ac2fa6eccf3237427d56a9a70816817cf0b6",
        "8db75ce3cbd0fafcf31682a346ab80ca9d4a10f7642bca02efa0171d8c010452",
        "4b21ab3ff42546ff3760d4071692027f36c0429b0f6e9ccec93ab422329f5caf",
        "814bb78dcff5114e75db31bffb9acd121cf5ff9877377cacb57de0f2eaf3d15a",
        "0eead8d4e0ffa5774b8f7a49d76d5ff1ef4e2e454c9b3d2409e00deb7999cc6b",
        "af8fb3230b8c84190d6240b08094f059dba7ec245629ead7a9bbb88c49c9d2a8",
        "f16f40e9f4422732adb93062f1d74249f1274a4fa1a8e4ee42c3eea66aac9b4a",
        "81bed9a4c150aa8bf0b4266ee7b00158b42758660bd625875a181c69f09c7bef",
        "ae4b9de0e8f447033ef6a19feab8f360ec5dbce2324cf3b10eb2edf1e2fa4dce",
        "8c0a4d6205b06bb204f782aa6a12322f5dc313d001784e6543e4376ba50589d1",
        "0a8fa69865165c9d5db4fea8db80f6ca11890dd680e032e81d4d4edd18f98551",
        "c343cadcf61075283ccb41dcd262760ec4d26daa1a49a946432239b0f0ae8d01",
        "1fe05a928478b8f8ed98d1c3105b63597c378e8a5ef7c6281edda78f7acf9fd4",
        "f13adad518fe458a01665e28fd6b095b56ded44d01431828f23aef2432487ede",
        "85a4ff6c585fe918711b399b310196a23ab0d5b7ddbe34c4aeaf88a0aad09f7c",
        "924e5e708103226e88380f8fec816d08f8421b7e45d61f35f1723babefc0ab0c",
        "a9d1e94e1729eeea1115e18e0eb83d9cbbb741400fe31acfc197ca807cb152a2",
        "7262bde1f6f743cb5e11341dc18409242739a91c2d51c2742a1f8c982a7d2771",
        "129351e2cee6254f33180b9682821949ebf12533a3c3b8615e9384f52ab4d859",
        "657e650a3b41e87b9f0323a2ecc6654c3e09492bfc90e6ee1af69c473b350814",
        "e8c0e4bdb916a441ab71967bf034951cad5690b0cb160d4eb2629ca07d5a3528",
        "3e551830b30a28ef0d826430d388a6fd7fda49458b44546f50457ee5d243136b",
        "5d0c4cc423dc0753d9373930669d372bdf0d2e290d846b165ba795cdc551608a",
        "9fc6ae9f8c2212232ad369d44f91ea1b0a9425f6c12d9e6e06af8279146146d7",
        "9b295df834c6b098ecd78c4e622f636d5fb1419d9cd77523747831e1f11bd2fc",
        "0fd1c5aefad4806f37dd7247dbfb516af6974d628186709281ec3919315cef00",
        "a5e095913a4928786889374423b595b4a23315ebda576eb00110f15fd72bd8f2",
        "6922666676754d585175636272b8785fdeb1eca913bc85b450d81e02ef8c0bf5",
        "b6dcd0e354c93747dac382f388e856b021518220c3918da0fa1e096df1055970",
        "4d33258bcb14f41a237d2a9bc375d6b293a14561f07cbe5da867ab637094acf2",
        "8eb96250c2f84eb27b873663a5aa08ef2882ec6cfa3ec1991cafadd2a57531ff",
        "026fc60d62550af2b7f299eb2f7aeb2adf6835ed50a0ad1f5db7abb94c84f9a9",
        "62ea5e657100d806541947227b46eeef934c5983d34edf9c50a5a13377123986",
        "567428bce3750e9528bb037c37065417ab006ac1f1e756ed0f2757c67eaf6662",
        "83d56eb5b8ca395ad4d4d276bafddd83809262e58993ed14de816988b4ef4954",
        "77d23cdd34169b8a6438d4871a234ab5923088a11980aa2e26cd04f8a07205ed",
        "9866101eb59469f1573421e657278d650adfd835e96c4013040ad094b1798a70",
        "bee7580a8992311a0c0e70580ade026da29f0c84851b5e8003f928ace71954e9",
        "61cdea296c22a6e3347e6976ba4e1ded064ab2cd7a0f21ca04177fef3987b277",
        "134f6f1d89e524d85bf92745e393792c74fd0c4134c3aae5db1a17b8e1de60d8",
        "c3ef3c1bb7e9d0e97e42fe7dbd271b8218a216094b799dbdeb7f3be2ef8be1d3",
        "75c63e65c846e8ba11a665b8b6128c30b5d22c10f8801dea0b4adf1e09b7ffa1",
        "e875dc52b03c92e8d157f11344c88ef17961095de51e17ea0ea1b71f07c2e437",
        "66823dc665490b98d984060a7ec75ff2ccc8d10bd8f48c1e5fc04b82eff36cd2",
        "4e121570b286ae12667dbd82c5a34a3eb1114b1e767e9244c400cd1ef88d6681",
        "986d2d8b580887230ee1e1351a4befb010019d662c5e71a893d9635bd1658e96",
        "2719c06d6a6b2d14612cac3cd3a4a6de8444e54fb1663f6f03295615fbf83cdf",
        "31dc9ab11007c7aaa3095a01374d007ec6b8833a60f299847761a6cb9df67a7f",
        "0f2638c818cadb8f20d81c8011f5ea0a5657450a492ed764ad788ca76ee1c48f",
        "6552083c0d3b3652e063ebbb5c06d6259c7509ad9b3b6abdc80f8c309be278c4",
        "17f0ef7e3e4f6f365ee200f790758215a6181635addf87b2a9c7f76d116c3a7c",
        "6fd239dd036c1e87bf786bf49c37af59b0f34f4eafde3b00d77f573363d7a49c",
        "0649570cd4fbd973b25675173969bc066e08c78d08fe8667438c11a5d0056699",
        "2317463d8bf422b114b0f1643dd1e184d259f84256132b527ebc30046f239b7b",
        "6a4f9d2bfd364bd8073a3b1d60d526daec639ba490585f5a9afa171bc8d5d196",
        "76db3b4fa4c29b8d35a16319f41609215b4ec44205fc81018b317aa2a1ecef7b",
        "7edf39d8e5ec554133334dd027242dffb4169960269e5572010dc486c6d2e383",
        "d062612ee1dd74ff912dde7b57d16a7feca33bceed09874b1e7de8a0562d1355",
        "55684a09627eb18baf572b0b76bf7719937946bf71cb43945509399f994a721d",
        "b42037964a29d68386e7a747b4f81471d9604a8c8d78aa251be63acc699d8432",
        "f34ed1d1a8b73413f17010c1c0dd24734df1c86cbf6db892d6d962fcfa92683b",
        "b135c0dd54e12a2720c29c7730e5ca0090bda29f16d3afe3dbae361a767a721b",
        "d70fad124751e1cb30e947de0bbdb5058564fbed7436647037a9ed0682a9a580",
        "1cfe9ec806894915aebbf8aa5b6480a62b233fa45f720ecc73d7b26812cc5854",
        "c96f01f8b833ecbda3dc19b8fa632acea0872f1fe572a1714aa31e47781cbbab",
        "8aaf5356e38cce3bdb354dba449ebc4389966e55c99d85db8516aec2b8f1846e",
        "b7b524874fa748bd56961f8f96459d0171d5d32069b9f411ff893a8e86b230d7",
        "324a4d129f9b668f7dceb95f27b92892a93dbc83de7615c7cb3c49302bdf4f88",
        "b4489cc02ed10d2682cfb35a62f0cb8882f31ba522dcf54d265733b53c3c34c7",
        "933603994567cce0e3b5a32c6f6eb4fab2a578f7d2aa0ef6745f4b03ccd397af",
        "37ffd61f4be3000f9c1e7c090eaae61136b53af7fabd9fcc6d05f90248f045bb",
        "423c6d9d1760765153c27eeea40b14f83463d6ebea57ae355270666dc6934967",
        "791a549cf6e50a10763245c0da4401689c58634500976913c92f220ccafa762e",
        "a1bffb0a401e5f878e312d7436cf2c5544dadb981959608475d008be530ad4ab",
        "9918c92404577c358548f1f51bbf89b3db5577906cbf29bbeaa60d0aa4d9eab0",
        "8dfe0211bc16e8b0792e23b2719f5df47553ca7bc23e7191c037e837d9597471",
        "b6d078e5baab87ecc1f80af9ea0ca8a0546f55cb3287f8a894e200d47026b92c",
        "4aba7067cfb4652c142887d0ed13a017b8ead5746f6dd12673eea2fd7c6f4ef8",
        "0db0b4d2e07de8e6d965956940e1d23a4b57d4cf087f8e9159c7fbb4b93caab4",
        "97afd304075ff95d51a8dae47af90f5a0c71bf2882ce6816044c2ee21bba2477",
        "fa0055a578733c2fa41f4730f8d265277104e0fdae3f1df008b7dba48d433da7",
        "b96a525fb1c688110b7f711da1ca82c03c74c2a34a4a8bb3295b4a278af5c987",
        "a0afa39af696881bba6d65581547d491f3c3548ffe28608e3e30f49c8a8ad27f",
        "ac1d772be9ba60f58e146dc8b976e1ac9be3365f88acb90abecdf1a21c558246",
        "4b3b41bfbafb5c210cc3aa74b27a92c00e414d9a5b120962585e0deaf1e2aae7",
        "98df8adcdb2e5270d90dd695846d7cc200b2209cb09d0d9be8769a06675c51db",
        "907d57c535c088b7ae15407d56ae37d6df5714ea8c88f3b95c1795664680708e",
        "520fe4130cfd29f79f26e495c6fae824652e0d2eb21b6ff9dc5e67b3a76464c2",
        "450d2632143d97119a174f882dbc5049abe332d1cbdf565b3e8b9bf49e4d60e8",
        "cc306d235201b498c290fbf679479a5db9589a9dd96152af6df750ae8e88ab47",
        "e1fc8fe234c249ab723df3290a488c522525c702752818aa572a1b5bbd0c5b65",
        "54249776173ad9ffd6be5c07110c3aaae7a6830da5fa7382f4ea3e5669bc3bad",
        "b2c02758d57b23d39d030fd2136e515fdaac412bf7da959473151ecaadcc3480",
        "0fbbbc867ab2fa664ab6a11c07d149c01620fa2ffde53f56160c5bf22cd6b470",
        "8d798ee8a54b0bb05b9ff43e8f5851bcafa03bc7022befede9f502db37a75f74",
        "ec332eec0f9626806357ba6a5d4f634b469e2a433d236ac1236715f5982325c5",
        "3d254ed56716607489f02a2e3acc84d522044bbc555c2b77472179207a2b6306",
        "0ecaf06d6b0d50e6086f1c7acb5b35ae56952f4c59bbaa4079a598dde15ec29f",
        "99e231c89747942af83e4cde6fa9ceef8f10f62335cfcdccd161a3d6db7bf3a8",
        "bd248aa5ba08739dc81b55972e9d491a33956c3c0b4ccc658218b35be9e34492",
        "21b0d7c958bc03ea6fdda7b5c9bf9b39773c0c0108ef763df49745ec7dc90763",
        "48ceac1460f0d65a1f1fab44799ae02e186828336953065f2ea71fb64250cb84",
        "4fd0aef4a3b351bfb16c8eb23f03d8e12bf9441c762b0092d0c2f890de4fb1ac",
        "561e41090d066aadcb3ec54adeb516b9dc4d9afd7a526a079490feb1ebfe619f",
        "e328986b8264da1c9e272a253c14e83e263a44a4d32c2dc51987e9b21d92acea",
        "8fa66b85d518464dc8fed6f9ec5870c3b7bd534c857b0071e73d2588289fcd8d",
        "3e0f703782a71f8df6a4304f7937ee4a9ddcb7af0f1cda3bbac414387c798f83",
        "edd48932a449343e40104659061ac9a7fe31cf3e4dc06f3b7b3a639c3bd32011",
        "958f25c1a63e2374f48b488c623ac69a55131c15779a1ed8161411bac705f865",
        "b5f5054f245ab4e52064c3c5ce91b0d5d2dd503cbfa905e6b6c00bebe544c962",
        "6f4c6b96a4c3b11ed85bbdee19cc3c97be4469f569ea34fe61447405fdc602ab",
        "dad4c5debd5f62416821c440746f54745d47c5ba2756218b2bddb525c4b8b10c",
        "5bf1461a3d1cb5206bf48ed6974ab13b14a37137c6a26b6f49d38801c50dc48a",
        "0d80c30330947cee4d602820e2eed02f5add74ffc39ce0eedc9e0adde54540c0",
        "1ecbd1eace4654772d32c44a933cd52656860bc07255576a5b40ba4d5501440c",
        "df2e78c12957947d24eaca615550b786b7a9239ff8517febead0dd465ac63564",
        "10759ca224586db73f9a1d0a7f6b4cd5fa324855fd68b1192f09252e4aedde9a",
        "0957528a9d9ac7a34f1116aa4d7eeddd8474814d605a7619d7dc520211448068",
        "52114e42cc03221d0c680972184b9cdc0795eee75e761aed8c4cc8027b946084",
        "b3e7eff0a40864f7c279c5ac557013e6bc4c323638e3b1576c02879650b40332",
        "fcbd45caad2ffab82b5ea5fd1ecdeaa0be6301d4b0b634a0f2df8c1ecb6cdab4",
        "150f82fc54c7ffe7147e91466d39bf444a5ea493cfef9a9b7c8f833673b39dac",
        "20af599cb3b052fa439b9871efb5e4d3a954a163bf0adbb9f17160549da344b8",
        "850846bb92e6df287d6fd3ec8aab9a3b4bdd385feb257db72811809ba33f819f",
        "531498ffb0ac4b92f6461b661e0d64db6464f2c94b01fd26dae7342178c4591c",
        "d8418da3101469b9f6e4df946e260f44f8847fd630736bfd7afd9ce4a54a9f98",
        "7f72aff8be482080744f36ee7d9e05e125e481e0bc2380ea36f4d33a47d80639",
        "607a43a6a22d7f969d5427a5f89ce3d3c008b1ac2b0a927ec7e411081ea50537",
        "b74a68a310d876ffa3c0d9650f0b890d372b034a25a181f5b1d3bc4b7a130612",
        "209bf2985b76414a19cbb05d5a39c19462896a16194e8be00690befb9fcdd327",
        "a62a1c6407257b72f6bc9933d93214832b86f86359ca9a3f176af21128aa0758",
        "0fa1db94d3b0077ff713738cff7a2ca08ed2f16d30735cd7863a4be39576062a",
        "2c4820a2c9100b55b42a7b8aa0196c99a139b2bf69d3db8906f70939fd1d97dd",
        "cacafdaf2a6058e7c3c04e44f6ad45b5914da5f32c3f85453a3fa0cd92ac99e6",
        "256cab9a0f71f78e861f961dcedcfd2ddaef558a1cccf51fa1d4d9414430a1a7",
        "ff8a0b7aefa7ef8f3899f6c51b464847059f8fa11ffb6af1311e06f83e83d239",
        "ea4b830826b426031648917a24ef608f9808cd1f974362f7025788014d889b32",
        "60c06db3b950387f193eebd4376a6f7ec36eecd707af2a18d7717094716b4705",
        "fdcba56ac113107144a9ea8f0cbdce6537c709e15b8fe49b983afb646cb663f7",
        "352f2aefeaed8bdc990fdb11202c0777c5a80c2afd23b01a9720c5da5caf9eea",
        "c7c172109e906d5c8e851a21026bac99ae8326d867df0f96d854caae2f056c2a",
        "95a14f36ae15f04a42085efb2803b09c7afccef70007628f2e4064ffc20e10c7",
        "a17125264bac61ae593bbb55e504d0f0d9a98d7923300f50cf6f0f8f992ea737",
        "3bfa32a4860cff7c8a79763822101a2fff2456f708da140ef018260f1a839219",
        "f985bc659908a04b61b931eebeaa2cb7211186f48d94e066ecf4496f873af4ad",
        "9c51fd09e6e96da7c1c541dd3922d6ce95dc0395393c4106154b4775c7553c7a",
        "a3853aedb9c0dc33991fae58f95497edcf2fd9534526f8f0df27e6849497fd8b",
        "a0b67776ff6b19bdf6876c86f5df9b23b483ef732df9fd95bec43aff833f6840",
        "bbf5536c1d488b3dbe018e8623f905d7c3d82ae25b7f397f0417ca66decbaada",
        "dc0b8b01763a5edf1c6391d35154678dda91915367ce6df236f3c41c23851dfc",
        "704eee76232c0cd6946512fac3efc63392a8fc71b00b2c511563942a683e25f9",
        "ed1a2b0b2d4c19ecd3f190c6d939ab068a999cee876a63e780d4208ff65dd5df",
        "66ae291c2c13aa7d5805473e0ef5c5e699671810ec29067e2b4f68fe17bf9459",
        "e00236775485cb37e90d95b78c41773c4a1f0ea144ea79f48fcc035371002a43",
        "68bcd7fb41112e1af3c83017c7365c512f7fbf0d5021a025f6f1b7017a0c21e7",
        "868fdb9fa253928ae6edea1ab37d5dc7543ac68fe063f2aa54ade5f27374018f",
        "d2603d86737d42200e8cc26911e88ff5dd7ae0b26d4f3db005e64a20c1c145ba",
        "284cd27321a9ea5ff9b0121254a2b5a97a94d0285b3f4feca0ff0daae2e608c3",
        "a0ef34637f25035c8d9b751df77afeacd4e96fc361cd022dfd430ba60541a830",
        "789364e8064c04588c308bc0b7f8245c052daaaa3c2465484ce2c861e83b323c",
        "dfd43f820de855c96b68275b17707f96132bbd0142e0752c947d134a96ca9e02",
        "599f47ed2b528f8e69a869a69321c26ff5d381a07450d1e52ea541b3420a3700",
        "6182cdd179e500fabc42b628e00a3f10e92f886a3f257f2851cd6ef88be5983c",
        "0c935ea6d867d6ad94afad712fe8ab774b1d0a237a0ee6761c9dbe9d064540ad",
        "55a59168bd4fc73d33f07aa753f96498d0b5e2d44fcd9ee9842618d34ebd313f",
        "e0d63511aa1d70455e3222aca71b071ba9e8a841528bdb1494724a0b660a6d21",
        "5bc1f5d00d9ea14e60b1e30ba7dc4a4df63d0b4161ab76b9245faf865069b601",
        "9e5effda000fc36b9f9d7ccfcb1c0fa80633ba0c4e1860921615a3373a233925",
        "d9843b92564ed5732eada545b1b6cee8ad33e0d5b8c076e84d3719d82d6b3631",
        "d963b95dd975b603e0795465e18d215718f93d9452996115f44d6e98bf637c17",
        "0168affb6e415c4e32a43a006c56b0f04178b9dc4c0776f01254dbd390cee20a",
        "867b018e2ea8896500c26c098e1264454d5ba7f3cf540e035efef7058cf22925",
        "197578c75dedcf8e2ad69cb2b54cc3199d624ff5879640be720fee6fe25127d1",
        "233a3563f0e4ad1f9167794d8432440343a4f7c0ee884e637786a9dbfadc2e28",
        "d43d51330ef1802d96f45eae4774b230609f0dd8c36766b525f4c63e3d240ec6",
        "142a320ae73fee77266d8102e2de8d8aadedeb77dd88452b152e82ec7d19b7b6",
        "0bc659753f0a0c45b8d235ee2b5684067537951df018fe66d0b0c7e2d725fa2f",
        "40caf9a8301eb5a39ae293c04130073bd9056c025678032055b4a1c4f71390ed",
        "8ed975b21802a84795917b54275aa2f66c58817151a210de441252acb7911dee",
        "d6583949a6187fe87caaf426c04bcd4eae291d9e0fb2e1d4873cb3b2ed7e3cb9",
        "2bcd0829fd8b0e89841a2110baf09008cafde1fede304100c57a897753724880",
        "71e9170d6c7d8d85b7d9331305ff27b6a6f8a10fa7d145f9f42adae04b776319",
        "b0aa21e3c0e24118316eebf64d318c448adb9e7772aa5bf92c57a261aaed15f3",
        "8e7ef9a87c2dbc1f5eaa6d0c37ff0d4334c94b8d35e055a643e978336cee2207",
        "9da033b7451c9ed5a24dae924170d752fad0920681646745c801a119269da5a2",
    ];

    /// Test that the MMR root computation remains stable by comparing against previously computed
    /// roots.
    #[test]
    fn test_root_stability() {
        let mut hasher = Sha256::new();
        for i in 0..200 {
            let mut mmr = Mmr::<Sha256>::new();
            for _ in 0u64..i {
                hasher.update(&i.to_be_bytes());
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
}
