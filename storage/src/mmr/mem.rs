//! A basic MMR where all nodes are stored in-memory.

use crate::mmr::{
    hasher::Hasher,
    iterator::{nodes_needing_parents, PeakIterator},
    verification::{Proof, Storage},
    Error,
    Error::ElementPruned,
};
use commonware_cryptography::Hasher as CHasher;

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
    // The position of the oldest element still maintained by the MMR. Will be 0 unless forgetting
    // has been invoked. If non-zero, then proofs can only be generated for elements with positions
    // strictly after this point.
    oldest_remembered_pos: u64,
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
        match self.nodes.get(self.pos_to_index(position)) {
            Some(node) => Ok(Some(node.clone())),
            None => Ok(None),
        }
    }
}

impl<H: CHasher> Mmr<H> {
    /// Return a new (empty) `Mmr`.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            oldest_remembered_pos: 0,
        }
    }

    // Return an `Mmr` initialized with the given nodes and oldest remembered position.
    pub fn init(nodes: Vec<H::Digest>, oldest_remembered_pos: u64) -> Self {
        Self {
            nodes,
            oldest_remembered_pos,
        }
    }

    /// Return the total number of nodes in the MMR, independent of any forgetting.
    pub fn size(&self) -> u64 {
        self.nodes.len() as u64 + self.oldest_remembered_pos
    }

    /// Return the position of the oldest remembered node in the MMR.
    pub fn oldest_remembered_node_pos(&self) -> u64 {
        self.oldest_remembered_pos
    }

    /// Return a new iterator over the peaks of the MMR.
    fn peak_iterator(&self) -> PeakIterator {
        PeakIterator::new(self.size())
    }

    /// Return the position of the element given its index in the current nodes vector.
    fn index_to_pos(&self, index: usize) -> u64 {
        index as u64 + self.oldest_remembered_pos
    }

    /// Return the index of the element in the current nodes vector given its position in the MMR.
    fn pos_to_index(&self, pos: u64) -> usize {
        (pos - self.oldest_remembered_pos) as usize
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
            let sibling_hash = &self.nodes[self.pos_to_index(sibling_pos)];
            hash = h.node_hash(parent_pos, sibling_hash, &hash);
            self.nodes.push(hash.clone());
        }
        element_pos
    }

    /// Computes the root hash of the MMR.
    pub fn root(&self, hasher: &mut H) -> H::Digest {
        let peaks = self
            .peak_iterator()
            .map(|(peak_pos, _)| &self.nodes[(peak_pos - self.oldest_remembered_pos) as usize]);
        let size = self.size();
        Hasher::new(hasher).root_hash(size, peaks)
    }

    pub async fn proof(&self, element_pos: u64) -> Result<Proof<H>, Error> {
        self.range_proof(element_pos, element_pos).await
    }

    pub async fn range_proof(
        &self,
        start_element_pos: u64,
        end_element_pos: u64,
    ) -> Result<Proof<H>, Error> {
        // Since we only forget nodes up to what was at one point the tallest peak, we can always
        // prove any element that inclusively follows it. If we allow more flexible forgetting
        // strategies we will have to update this logic. See:
        // https://github.com/commonwarexyz/monorepo/issues/459
        if start_element_pos < self.oldest_remembered_pos {
            return Err(ElementPruned);
        }
        Proof::<H>::range_proof::<Mmr<H>>(self, start_element_pos, end_element_pos).await
    }

    /// Returns the position of the oldest element that must be retained by this MMR in order to
    /// preserve its ability to generate proofs for new elements. This is the position of the
    /// tallest peak.
    fn oldest_required_element(&self) -> u64 {
        match self.peak_iterator().next() {
            None => {
                // Degenerate case, only happens when MMR is empty.
                0
            }
            Some((pos, _)) => pos,
        }
    }

    /// Forget as many nodes as possible without breaking proof generation going forward, returning
    /// the position of the oldest remembered node after forgetting, or 0 if nothing was forgotten.
    pub fn forget_max(&mut self) -> u64 {
        self.forget_to_pos(self.oldest_required_element());
        self.oldest_required_element()
    }

    fn forget_to_pos(&mut self, pos: u64) {
        let nodes_to_remove = self.pos_to_index(pos);
        self.oldest_remembered_pos = pos;
        self.nodes = self.nodes[nodes_to_remove..self.nodes.len()].to_vec();
    }
}

#[cfg(test)]
mod tests {
    use crate::mmr::{
        hasher::Hasher, iterator::nodes_needing_parents, mem::Mmr, verification::Storage, Error::*,
    };
    use commonware_cryptography::{hash, Hasher as CHasher, Sha256};
    use commonware_runtime::{deterministic::Executor, Runner};
    use commonware_utils::hex;

    /// Test MMR building by consecutively adding 11 equal elements to a new MMR, producing the
    /// structure in the example documented at the top of the mmr crate's mod.rs file with 19 nodes
    /// and 3 peaks.
    #[test]
    fn test_add_eleven_values() {
        let (executor, _, _) = Executor::default();
        executor.start(async move {
            let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
            assert_eq!(
                mmr.peak_iterator().next(),
                None,
                "empty iterator should have no peaks"
            );
            assert_eq!(
                mmr.forget_max(),
                0,
                "forget_max on empty MMR should do nothing"
            );
            assert_eq!(
                mmr.oldest_required_element(),
                0,
                "oldest_required_element should return 0 on empty MMR"
            );
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
            assert_eq!(mmr.oldest_remembered_node_pos(), 0);
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

            // forgetting tests
            assert_eq!(
                mmr.forget_max(),
                14,
                "forget_max should forget to tallest peak"
            );
            assert_eq!(mmr.oldest_remembered_node_pos(), 14);

            // After forgetting we shouldn't be able to prove elements at or before the oldest remaining.
            assert!(matches!(mmr.proof(0).await, Err(ElementPruned)));
            assert!(matches!(mmr.proof(11).await, Err(ElementPruned)));
            assert!(mmr.proof(15).await.is_ok());

            let root_hash_after_forget = mmr.root(&mut hasher);
            assert_eq!(
                root_hash, root_hash_after_forget,
                "root hash changed after forgetting"
            );
            assert!(
                mmr.proof(11).await.is_err(),
                "attempts to prove elements at or before the oldest remaining should fail"
            );
            assert!(
                mmr.range_proof(10, 15).await.is_err(),
                "attempts to range_prove elements at or before the oldest remaining should fail"
            );
            assert!(
                mmr.range_proof(15, 18).await.is_ok(),
                "attempts to range_prove over elements following oldest remaining should succeed"
            );

            // Test that we can initialize a new MMR from another's elements.
            let mmr_copy = Mmr::<Sha256>::init(mmr.nodes.clone(), mmr.oldest_remembered_node_pos());
            assert_eq!(mmr_copy.size(), 19);
            assert_eq!(
                mmr_copy.oldest_remembered_node_pos(),
                mmr.oldest_remembered_node_pos()
            );
        });
    }

    /// Test that max-forgetting never breaks adding new nodes.
    #[test]
    fn test_forget_max() {
        let mut mmr: Mmr<Sha256> = Mmr::<Sha256>::new();
        let element = <Sha256 as CHasher>::Digest::from(*b"01234567012345670123456701234567");
        let mut hasher = Sha256::default();
        for _ in 0..1000 {
            mmr.forget_max();
            mmr.add(&mut hasher, &element);
        }
    }

    /// Roots for all MMRs with 0..200 elements.
    ///
    /// We use these pre-generated roots to ensure that we don't silently change the tree hashing
    /// algorithm.
    const ROOTS: [&str; 200] = [
        "af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc",
        "6640b495f46158d2b2169660ba347b07eceba14ec540e480a4231e37dc53e967",
        "9df224ccaba058aa137e63cd2668c4f3689173a7ccef7c0ac1ec3f079e456f79",
        "7596f95fa4a3f9cbb24760cbbeea41cc727e0fcfa167ea87ac361580efffdf47",
        "86c811b2c7b05ed5887db8de666567888fcbd9ff1e86ef6cda38c9b2c4e13169",
        "de7880bb806f1ef592e7dc47d5d4f5af19396fe1089969fc57dc037d182288ba",
        "4856a9cca73f93cad97017c15a6a28de76db959dcc2b77585a56c8b8afa5eac3",
        "1e356f2446d67fbcc2a03611f996e669666c8c5e4fc78e045ceffa7b6728ad29",
        "5f15ed1551f1a5042c4f1c6bda815c4f0c187b02bd1d84f3bfaea7a2072793d2",
        "0a31daee1b822f3292f3877ed9064dfc6d9c187ab45fa296b36665f1f243d1dd",
        "5a91bc0c1cde64c191af518c55f8380b3d4ffd77315bd3a4e241eb520f3b9d80",
        "1124f1590b44bd186e796533fdc5ced167036070f202ba4841a5c4167806d12e",
        "0809d11fbb8c56ac393444ba34a900f7a6428fcc5d5836f0f75c598a0445cb74",
        "8764f42c573c21a37cb32c6346abe71b573ad631e6b2fa034656df2fbdc584e0",
        "5299cd504b24274991095721a42e4109184285d7510233d531180221eaa4dfa9",
        "87e115893ebfc75c52b1f3b0e30a76489404a05972906c2e80034e51a711a455",
        "67c6da08950611d31b58d2cea28c516d686301f29d8ef21ae847e99d1c383cb8",
        "9b0f6b2f591e7b8338d9f0b45ff5705c1f259588ed2d9c45a4cb898ad8b96c7c",
        "534151483a6146cccf49913b4bb5481bae280819fd74cc2d29b128fd104df00f",
        "d60dc66ce726b5518401eb83c9747238c6246bee2951df0c21d123e48976551e",
        "4001205c77c823e75fcbfab3580390b0272614d7b7e488a1cc199502746c7ff8",
        "cf3d8cc2775f1ba81fbf1664b90956c6b9189feb637f380af3c28b7e9c4421f8",
        "92041809edde60af32bc18ab9cd8443b9742ea08296cd93bb0b231b4932ff3c6",
        "f1114faac31bf5b79e269d0a823de9f1bb54cadf3bbd3899d3404503a1e86525",
        "e588ab5af8ba8fbbc7091525864b33bc4dc11d296dc46c85237e56819e05dbf8",
        "f3a01a562c17e1a3cf51527b77607397ad1d00552e66035b6680cd95d6a7eda1",
        "957db1952ce89ec427d0034eb7c0b7a886ae2ede4f9e0111a419594c03f71e6c",
        "6e6aa6d258746ddfb7a40cd7dd7560486e5f805e0c3a2f664f57207993d96e7a",
        "9171298227a6f39ac7f797b4a1348925254aadc742d754d56c1b71ea5f5a7771",
        "f6705879ca7439fb6e039a842842f6022b0427b9b1462a691bfaad4d1b40b59b",
        "0307b0c5e1b95a634e82202774ed3ca930e5df712856ad78066e04395e136b92",
        "f962f4736a2997ac9098d8ff6b70277622ca81a5057fef03bd51edd174eda429",
        "e1a71f92d6711d48b2a84c5af76978dcc069d0eb62b95693cb7720c9d3e2acf3",
        "c3aa40186955a591630fa4edd96a9efbb96f1908fc162fdad7b5ccfae11b9fb3",
        "d9bcf7e38f9720c7ef34aee4c5969ef38e45245f2a18901d6a41f99bb4633beb",
        "9c80b73fe6366f9103f236d517956bc5af305b31a9f94503d05302faafd5a876",
        "a4e993bc5777914844c2a44493b6f4b11fa80b6624b8943153d0dd8596ccc592",
        "e6a4608d05c0fad14e61d0b4e40cc777f58925c3c4be66a40c065e300390fbb8",
        "74f1d960fc4fa543fdc6deb989cd1b985b0f4021a6f28e51e0da149b39c70dc0",
        "4cfaba43dbf82a7e85f3965cd1ea18f3954b3ab50248edfc5375a32619d828e7",
        "a70a15a23123e800fa402ef9400ce15cab0b399393524828a5a826333b99c324",
        "c7b69b49ff695f52866c46e4f8a4195bca1f6b1544a7959f559b9981866f8734",
        "9a42c119a9bc0c9e63847d7d75fac75bd64ca564d3438e6e2b35a1f7a1907949",
        "7ea377590b4838177f3e1bd1297f2ff106c33594b68e3f3b4d86f5a733edc464",
        "ed80b749d755cc671de8bcbe9523fcb007a4461607a07cc7d29b42b51890800d",
        "bcd106f2517a7f2f04f8a3ef24e8c0ffaedcdb417daff755150d19df8763216b",
        "1fa11d2a199ff23ce9f3b2b68c3b0ae07c870d328fd64a2342d123e5291d1fe6",
        "6ee35aba7df4bf8c16061f84d4acd92924096105dd4ad17b1a72d4b5f4d2ee29",
        "1349ae02d324b630f7baa37bdea7089dc10db78c116b15994159455b543a34b1",
        "b55e221d1ca839d708efd30af6d4c8f9afa7c07d66c45ba0386c349afc51cfcb",
        "3122d9a14a02eaf30a43a1d8c91b4501981693329bd8a6b70f9489b26b4d542b",
        "6938e4af2b8f33e97908bf7666d90c8ae970ab022cc5bde84df484bb57531143",
        "b502e5495d557b098e5d1c6cc01f6aaba041541929ada8fa9af5a8b4005e5442",
        "5b4facb775952c2fda9f3f6a43a3f45714a4a4098938dbdd4008752e78c83108",
        "996111339bcc196ba0f69aa345068418604eab78c81cf647c92a45938ad71c62",
        "1173b18d1429ab2f1ee17bc01b6b3c0c8af24d8bc129d4de3d91c8a492f40645",
        "aca1939d77018da0b13861ae12ab60de671c7b8306f6586802459728ed372a93",
        "1a9a4c42ffc4e50121f4653a4f0eb588a0426cc3014efa40979e5702ba2288f2",
        "589887d62010118bc0f4fc6e40408af681a85cd92ad91f549206163849180cb1",
        "f5ab67b23f667d709bb08f73c840fb9dec841975750085232eb43e46435412f2",
        "08d09d565b994505e11874b70c425a4d3b794ec4ad2d8334fe7a9c11e6a57eb8",
        "7300db79b56dbdd7fec2ef7130fa6657d1e51aeb416da939794e143c436591bd",
        "24b2c1aae068bc5f514491cf633d64451e16f304c2cc5dd2363b092ea8dfe98a",
        "78b06ae6b3f5ae420bcbe3accf159d281537e10733b387dbc1f853d31314f970",
        "0aa50ab1ae87879d9af14c4cb50a13c389d7549fc320a609eb549b8c39bbcba9",
        "2aee102a01e5da108633faff7a35ac60f8f224c53cd751198b7506519c8fe2d7",
        "a30dee20dbd75b113843859f2dff0be41da46625413946fac2d2f5e459ffb59b",
        "9c7571374fef130bf8895e1ba8dd8ea64c269c2435bee4767842415d48d5b893",
        "0526947ba6a80518e9b76eda4871a11db56c87d8e630d8164fc733a70f675da5",
        "e383d57097e048627e79c196eb28a27e22b1147df4596c48a6d82a31d5555d61",
        "f50d356755ef554991a800fbf4ddb32d09690dbb1766fc3d2e2a0e7fd38f1a5c",
        "06cba3b369a46d2f9cacb19562c093ad2235e15e7158ab54f807701bf0ff0017",
        "01088421b8b65524048c5ed3092bdf4d31428efc6dfebc61240fcd107dae4534",
        "31db1fb2dc7c1c690a2a8bcf9782fd7a3a1929aa912070a703760bdefbd40019",
        "fe3e53a3b3fee028ba9f57410e342254a1f0077c523b03e6df47f0eda925c7fc",
        "b8ab10cd264f1e71f9e7224e92537c43bd0f190b2eb412551e25f9cb3dfa85cb",
        "69f711c694892eb49cebacf86c82584dd2bfbea356dccbc633f77031c0e4b741",
        "496e32579a40f9a7e737126479c5c8dd0225c7386ec61cad0a81eec969f7d10c",
        "e9b4cff8f4b9b2bd53c55653270b6dc803e39fcd9021e6cd7df4cc791f2016ec",
        "acc2afaf8d4547241dd22ef8ef6f454d379a8fe3a89f4134c4de68ad5c6d724d",
        "6f38bd7287001cf8d941d0808695cfc2decc0b922644fdf970445e119a6c9690",
        "55148cb62b52d2cd3c488217af888489f6b7ab2503483cc9cad247b9c41ac951",
        "e0bb29a5c1e6bd85f95675f888aff38d52ff0da34a49703194a7082823f839a8",
        "42fbe33ce85066b250e5acff15079b7a55decc6f451c7438a2dd2700be0cd5ee",
        "65e8464144447cdba58433e5618586be3ac399ec18fabcb7b05887dcb3d3f593",
        "a0e5e686b42220e49f66350dd080d51301767865bc03916b7ccac8cb3113c0fd",
        "efcbe4d7f4029bb355ed228400a75f8da7578228b4e2f265b6bc4694b15e2260",
        "b525b69ec8fed6948ec48bffa1ea553f04a35a8e3f9267805c79bf4c60b4cc5e",
        "b0dc01198f280c2606c67b1913b7f32410a87d53c0115e29951005b2730943e6",
        "1d503869ed404acf9277e682aeb3d7cfa0db0efaf43db7ced37bc3b9a06ff23f",
        "1c0b1c1491eb78c45bb14637c3dba6109b8959efe157f16a4ab384406c952ce7",
        "f4acb95089044b98f6ebca68c1c40dbd7f05c065f11d4dbfa7115710b601cf09",
        "06d646c8656a76434795ef1512cc763868e370d356a21bd8067ab60add138086",
        "83cac997aec96fe6a15449a8f66e36c5bd07a4cf6ed186502a36b0a2ace4fc8c",
        "da887e4d9d8cd9e79baaf50c22342357d62b3598fbff02220e3ad1aae9500165",
        "2b0c70b609bfe8d437eed1287762e7058b63e840dce1174816e79ce0a80b0204",
        "203f44020f57d2427a464e0136bfcd1fdfcba0e8165ad1f3088923447a243f45",
        "767949797550e9a324a47f8201ddd16e2bd324e176977e7719fa7e47625a20ea",
        "58c056915b6e96bb12e150a797d9adbd73c70a80e6bbb9ef722f705dbff14097",
        "788e7ca7f427e6aae4d224539408596645eb3c09c0c09bd4cf43c2697ea4ee7b",
        "c3aa4afb4b1d8990c0665655a65ff51ff3ae5ead9f7f2134a7ab18768228a39a",
        "c9ba42efb98c6539702f782e2a723355434abb01dc2d62538b2662651ef6384b",
        "e2440c9e929bd6d59e6f2abd11fb281f7d3d3a8fc3f5117e3fccf798124972fc",
        "b676b53033240a5aadfd76a57b9c391d2e82699953f93163927e5bf53dae9fa3",
        "53b5372089212d6e9de62c5ed1fbd428f426fd7b617272d762c00154e600b3c3",
        "aa43c45552608bb722cd2a01a24b9a7161023f970d926e7118c9b30622a23c5b",
        "fb699e3f4ee048cb87b92d4cc00ee79bf211fad45cf03d49034f9910864010b1",
        "23ddbeedcf5540d4e7f2db090607423fb479acf8b3c840ece90c76c5badfd991",
        "4527a5dd599898fbb3c1362c8807d0898b939124b7e5a2dc1df791313eee525c",
        "f17c62a590b71c35b1c67d20c933b4d05b1b03ee9a99d81359755ada0df30e2a",
        "b323a4c91c6f83dc522c33108aea3102d85443a0bc26a0235f4e83d86477e786",
        "a79a878ef53f3e5f97150b93d098f843bc32d3ed8b6f41185eb8900b4e5c1c06",
        "3e6215ae2dbdba8c7eaaafa3d350bd6f3e6c6649c7b3cfe77a7d81bb13537101",
        "cde99c0dd45cad07f6181398ff30676574ccd9c6cb83b79d940d5eaa30992c39",
        "a42d11fcbaa4f81a16a82e1e77677c670ca7d4bc053ec7702a99be1b621b3ec1",
        "9aa8eda2771b7c8955722566ce75f843538425fef37cb968c76f06ab6e6ddaf1",
        "9ea03c9d831922d9cd321d446fc904aa6b1e0afbd8cff29b8d9e9736976256d9",
        "2c50b98c32219c78300a6b5b0ab21ce15dfcbe64fe14774c972867b641d6972b",
        "e7c7c5511da1288364fc7dca2f9e6980f701f6513f017e4aad9cb59ef31f804c",
        "8a6a038c37d5b44a849c143cc4e21e1762013a58f386f2fe7d24393fe2123c5a",
        "5c230019fac955b3e6b6d04195990f06fbd24c0b558e4f5900643f0315560142",
        "02bbee82d8fc58d9d7270595b39a85c938dcee91cd26435221ab3301f4b76ba1",
        "b579e14a0887050519b25618f90f98ae0cae08915533b02ea84252c569f84a00",
        "24db0d1afc134721aa653e16a4551737a178407124faf44325a086d3e9cce01b",
        "5e3751022de12113f2f8a2ac4b173ca056e12baa3ad01aaf7d1e6a567b75d3b1",
        "984aba28c9d53ac891f9a3a47aea0e7a5f1c3dd7850b132fa4ff47993fc05aff",
        "04915a7aaaf33711976e735150de41243cc69f39c3d2193616fbaa71139820c7",
        "6a19db31612d444cea333cf48c9f442c2974505e92ce3b3c6b029ee2460c7d58",
        "fa6b0269f90c1a76abdfcb4a7798caa7585f6de87d12aea97f0750e7497863a0",
        "1795d159bb69748aeabcc797f0109cf2e53718fc1fddaee4f8d7a74427a5ec3a",
        "c7d1f9a562853378bebf6cc2bec9e221f6062eea3f6a779265731a8da40245f7",
        "d96eaec3568183dd310062d5617184abd12df2a727aba670683781a55fb32bfc",
        "08cc2b8a0e3df49c5927aedb69f9aab680deea59bac1cdab4b182ce9bbdf44a0",
        "95fa5149bb136f345b706b331fc0153aeaa3212815063fa975390371df4fea47",
        "4321637119f8ce35b6aad33e06fcc1ba91004e93188ebd0fff7a378ce5b8c621",
        "46d26400e235cc732a3e7a872dbb8a03e735102be052268ef5e1b9f81559381f",
        "a0798537fd527f875a1b8ffa7ac4ca1f9fcc8da400c7e90144cda059ec121509",
        "c19da50f45b44787ca688405a6f66e1d70000a78d951e0f2cb5ad2ee256491d1",
        "3383013d7245d18474107ec7ab56dbce06be495ee7117fc6b8e55bd196bbe52f",
        "a0035cdc2d52a06b1cbe5fe961f33fe6ed7835bee7ac7bf5e20b93d84814403b",
        "f9a1d6dcb2e7bb649781aac402981c26bef7c8251d79c58758a49b156e1283e9",
        "0db66d90f481cd2cd58067c48df58ea1f54dbe57458d81d8fcaf6f40f9d3eed0",
        "dd90b12f05d562cfb3c56d54c65a08e1b3f36b6aaa8d1175ac8ded91cc1948c8",
        "ea45adbdebda7fa696999efadbc4897120469ccb1d3ca5c000a7dda0076ae5d3",
        "822556e39b6d4b013bca40d8c6a6fd7262be4599bd4ace746fb42e863eb16243",
        "93477f035f9c7f56446ca64779ac7c550eb560013b5935412d6007f74b253140",
        "966029dbfed551ae34d549b6b2fc10897d4bd58ff2db45e1a7e8c1f3e522848c",
        "2722c71e2f0fd7a8911c926a68361e78584fb58547c6a5524c4d04499ea05a44",
        "18abb94aa8ec914499d6e9613fb796c07193f0753ea53ddcbf6dcf06164ccf4f",
        "ff9ddda86d369c9b1eb76f218f025350b769229292deb63eefce7801bc9e7020",
        "b32bceca593299a66a6180a892bccd42e2d393b7f178b6bd8da7da9ed493c081",
        "c643efff633694ff7de82ba28c83f290a0f75343f51fd0dcdc71cee3663a488c",
        "135e7f453fc8d8f62de2d193a93d8a7ca521fc5f5c968e9c6e0453e9fc8bf2af",
        "897e44146cad4bca248736f46c0bf8aeb5ab94cf155b47af2b130c066ec8134b",
        "79ae8e7df23f60a7d289c74b309073d205c1bf3cce7ba33553569d77f29c323d",
        "c0ccaf622569270c56a140985d998e29db5a1a63eaba377bc5deaef197fd8d21",
        "5a20a4a7f5a34923fb5d00c5161042ce367b40ed1e70f2856d5bc263f22134ad",
        "eea5a54303e23085f2fcfec79100143bb9719547c1f7b1ff5146e76f13a667f3",
        "c968c34e4ec45936bde0e457a714c4b33b0f6cc19b079789787504166d964ef0",
        "72e63851f547d70f8d12ecffec5a504437c6cf57c4841278f73f853d7888cb0c",
        "739a6daca71d06de679d92fbf1ea0e6f4d6b9f5742411997cb713eca9f13da21",
        "dd920518eecc31db0ec484c47025fdf835857eba2e147bbf0ac1863feec4af60",
        "a381fb6136a2e9f486985b9dd00fce9e71e621f16d4937e6610c8649a7415d21",
        "5cf063825b0beaab8001f2ee143c68977d58adf575b6ca9caca1d98e88acc05e",
        "1e5d12ea0034b10a3c6c8939f242f3cd479d62fd8e6e71c58d3bf2f2f07f150c",
        "dbb596b4bab11c5b08ca26a205b05f77a5ee34c6c98d9919a50a79d796c5e484",
        "98af7d76c4bd1568791fc069d38c3c12624dd18657b3dd5b902f3ddddb3fd27c",
        "6f529b4174e59844a71faea3df9791631201a97db46059c02456b6383daab908",
        "2f4d4aa119c91d3ea8dba7dd537d4a8c977b81accff75ef21829a0ac557c954c",
        "dc985e4d7fb60e0ac5dff2100be803b647ba0071c73cd6d65bd903b5b1e34e3a",
        "f8ba71a992fd5cd5b4cda903c6f38759bf62359c7edbed6f6336c39875264fe3",
        "8d11683052a837ab944c4cf46bf7714dd22f5bba9d3c7d112785de4dc60c359f",
        "7c8b2fcd3050de3a82391ef769b4aefe26344be7b399c0d71cfe4db378d392e6",
        "ad9f2a6e85a92f2a9212dc17b4602e527ecb015d65108eab5ee3e5c08e564028",
        "af4dad20a60c495f96f716bdfc3dcd43f8403eec96e89c1577d25a1368aa91b2",
        "4354f5db9cc56189b330a9839585289b008ca818c95fe404b99332a19e22026f",
        "d71db6ed14873ca0f409f2ef6d660d98511df4cc8cce9baf4242f9eb279c34cd",
        "3f44eafd7612f6f5bfec1be806b54a9da7bcb39e0a22ad2841c499eaecf32690",
        "23653e60570bf4ff2b113244856d5cfd002b6efa58947ef1b079de8ee9f31f26",
        "55b95e33deec16322f794a43f68ddc2ee6d9db233b13f19e2078855c474cbdbc",
        "b232a7a9dd39fa0e6da4ed1e9306a20f90ee0404c0010f91dee5e6b5c6344f77",
        "ea47293128de7c015d94fadf54fd4a6c67ac6500703fb0ccfb14128484da6914",
        "22afe18354e32cffa35b361b2f2f6b9a2a0a708c17a48e8acb4b0d5c1122ec04",
        "ea35772a98614777475bf5e8ad6e537d7c2b8dc08bce36afd796ca4d06c8e7bc",
        "fb561977ed473fc350f3e6af098fd0d8a1fc6f20f151ef40b938c2b35c483b72",
        "7fbfb4f967a764dd63432635359cc0c29cc16370dbf1e1ddbaf0d149f7a94bbc",
        "a15d4d1fc27fe748ccb83b9a57ab803d1b10dcdecf1077c0828bd40366c8bd9a",
        "6cd2627c10e5ca816c7accb72367af6d3481126ef8d873ed7a8559fd9fb7aaba",
        "36611c5964ce9db1d41143de4c85dcf5e6ba53261199196e36beb69abc91e5a5",
        "b1fb749ab397cb1495f6f13e4b7ee16e0c28c8677a83df0a1fb7d587a2322923",
        "e815b6c84ef99dad298b955a5d2a5ae29438f3a6a2f5ae3f64f17506fc9b3365",
        "4f1ae306cad26f9393b1175d1f68c21e64836749748de7b564557e76bb9e5a34",
        "b66f9d4572f8d547998a10127c4fdc78fb46680451ac168d990dcedf45bc2cfd",
        "7b962f156a2293a6d2c9e241d8abf23dd2554fd2665c1d12021174618865d737",
        "c6bd3abeb0a29b3ce74df0899aaac55e012f1f1250e6a8c657527a130e4f779a",
        "2f13959436ad4b3a80b7845ee7298870a04c60fe41a67e62233fd103becb0777",
        "05530a1fcf6e05f66e8ec5bb719083f83a32c57e509c5be5697cc44fe9bbd28f",
        "1b1b0ce428dd25d6509287b0f43dae671e3640ae066c4e7caf3029fceabe8d8c",
        "dd6df42d1ca8f3ca69697e431863b66e9bff97bd6ec3dd10ef6e540adc46ab38",
        "97b296e314eed8f5e0c26fe46bb8908b17432984b7dc4cf00f8fcecb6a151aa6",
    ];

    /// Test that the MMR root computation remains stable by comparing against previously computed
    /// roots.
    #[test]
    fn test_root_stability() {
        let mut hasher = Sha256::new();
        let mut mmr = Mmr::<Sha256>::new();
        for i in 0..200 {
            for _ in 0u64..i {
                let element = hash(&i.to_be_bytes());
                mmr.add(&mut hasher, &element);
            }
            let root = mmr.root(&mut hasher);
            let expected_root = ROOTS[i as usize];
            assert_eq!(hex(&root), expected_root);
        }
    }
}
