use commonware_cryptography::{Digest, Hasher as CHasher};

/// Hasher decorator the MMR uses for computing leaf, node and root hashes.
pub(crate) struct Hasher<'a, H: CHasher<N>, const N: usize> {
    hasher: &'a mut H,
}

impl<'a, H: CHasher<N>, const N: usize> Hasher<'a, H, N> {
    pub(crate) fn new(hasher: &'a mut H) -> Self {
        Self { hasher }
    }

    /// Computes the hash for a leaf given its position and the element it represents.
    pub(crate) fn leaf_hash(&mut self, pos: u64, element: &Digest<N>) -> Digest<N> {
        self.update_with_pos(pos);
        self.update_with_hash(element);
        self.finalize_reset()
    }

    /// Computes the hash for a node given its position and the hashes of its children.
    pub(crate) fn node_hash(
        &mut self,
        pos: u64,
        left_hash: &Digest<N>,
        right_hash: &Digest<N>,
    ) -> Digest<N> {
        self.update_with_pos(pos);
        self.update_with_hash(left_hash);
        self.update_with_hash(right_hash);
        self.finalize_reset()
    }

    /// Computes the root hash for an MMR given its size and an iterator over the hashes of its
    /// peaks. The iterator should yield the peak hashes in decreasing order of their height.
    pub(crate) fn root_hash<'b>(
        &mut self,
        pos: u64,
        peak_hashes: impl Iterator<Item = &'b Digest<N>>,
    ) -> Digest<N> {
        self.update_with_pos(pos);
        for hash in peak_hashes {
            self.update_with_hash(hash);
        }
        self.finalize_reset()
    }

    pub(crate) fn update_with_pos(&mut self, pos: u64) {
        self.hasher.update(&pos.to_be_bytes());
    }
    pub(crate) fn update_with_hash(&mut self, hash: &Digest<N>) {
        self.hasher.update(hash);
    }
    pub(crate) fn finalize_reset(&mut self) -> Digest<N> {
        self.hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use commonware_cryptography::{sha256, Digest, Hasher as CHasher, Sha256};

    #[test]
    fn test_leaf_hash_sha256() {
        test_leaf_hash::<Sha256, { sha256::DIGEST_LENGTH }>();
    }

    #[test]
    fn test_node_hash_sha256() {
        test_node_hash::<Sha256, { sha256::DIGEST_LENGTH }>();
    }

    #[test]
    fn test_root_hash_sha256() {
        test_root_hash::<Sha256, { sha256::DIGEST_LENGTH }>();
    }

    fn test_leaf_hash<H: CHasher<N>, const N: usize>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::Hasher::new(&mut hasher);
        // input hashes to use
        let hash1 = Digest::<N>::from([1u8; N]);
        let hash2 = Digest::<N>::from([2u8; N]);

        let out = mmr_hasher.leaf_hash(0, &hash1);
        assert_ne!(out, Digest::<N>::from([0u8; N]), "hash should be non-zero");

        let mut out2 = mmr_hasher.leaf_hash(0, &hash1);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.leaf_hash(1, &hash1);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.leaf_hash(0, &hash2);
        assert_ne!(out, out2, "hash should change with different input hash");
    }

    fn test_node_hash<H: CHasher<N>, const N: usize>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::Hasher::new(&mut hasher);
        // input hashes to use

        let hash1 = Digest::<N>::from([1u8; N]);
        let hash2 = Digest::<N>::from([2u8; N]);
        let hash3 = Digest::<N>::from([3u8; N]);

        let out = mmr_hasher.node_hash(0, &hash1, &hash2);
        assert_ne!(out, Digest::<N>::from([0u8; N]), "hash should be non-zero");

        let mut out2 = mmr_hasher.node_hash(0, &hash1, &hash2);
        assert_eq!(out, out2, "hash should be re-computed consistently");

        out2 = mmr_hasher.node_hash(1, &hash1, &hash2);
        assert_ne!(out, out2, "hash should change with different pos");

        out2 = mmr_hasher.node_hash(0, &hash3, &hash2);
        assert_ne!(
            out, out2,
            "hash should change with different first input hash"
        );

        out2 = mmr_hasher.node_hash(0, &hash1, &hash3);
        assert_ne!(
            out, out2,
            "hash should change with different second input hash"
        );

        out2 = mmr_hasher.node_hash(0, &hash2, &hash1);
        assert_ne!(
            out, out2,
            "hash should change when swapping order of inputs"
        );
    }

    fn test_root_hash<H: CHasher<N>, const N: usize>() {
        let mut hasher = H::new();
        let mut mmr_hasher = super::Hasher::new(&mut hasher);
        // input hashes to use
        let hash1 = Digest::<N>::from([1u8; N]);
        let hash2 = Digest::<N>::from([2u8; N]);
        let hash3 = Digest::<N>::from([3u8; N]);
        let hash4 = Digest::<N>::from([4u8; N]);

        let empty_vec: Vec<Digest<N>> = Vec::new();
        let empty_out = mmr_hasher.root_hash(0, empty_vec.iter());
        assert_ne!(
            empty_out,
            Digest::<N>::from([0u8; N]),
            "root hash of empty MMR should be non-zero"
        );

        let vec = [hash1.clone(), hash2.clone(), hash3.clone(), hash4.clone()];
        let out = mmr_hasher.root_hash(10, vec.iter());
        assert_ne!(
            out,
            Digest::<N>::from([0u8; N]),
            "root hash should be non-zero"
        );
        assert_ne!(out, empty_out, "root hash should differ from empty MMR");

        let mut out2 = mmr_hasher.root_hash(10, vec.iter());
        assert_eq!(out, out2, "root hash should be computed consistently");

        out2 = mmr_hasher.root_hash(11, vec.iter());
        assert_ne!(out, out2, "root hash should change with different position");

        let vec2 = [hash1.clone(), hash2.clone(), hash4.clone(), hash3.clone()];
        out2 = mmr_hasher.root_hash(10, vec2.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different hash order"
        );

        let vec3 = [hash1.clone(), hash2.clone(), hash3.clone()];
        out2 = mmr_hasher.root_hash(10, vec3.iter());
        assert_ne!(
            out, out2,
            "root hash should change with different number of hashes"
        );
    }
}
