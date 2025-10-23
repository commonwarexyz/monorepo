use commonware_cryptography::PublicKey;
use commonware_utils::set::Ordered;
use std::ops::Deref;

// Use chunk size of 1 to minimize encoded size.
type BitMap = commonware_utils::bitmap::BitMap<1>;

/// Represents a set of peers and their knowledge of each other.
pub struct Set<P: PublicKey> {
    /// The list of peers, sorted and deduplicated.
    ordered: Ordered<P>,

    /// For each peer, whether I know their peer info or not.
    knowledge: BitMap,
}

impl<P: PublicKey> Set<P> {
    /// Creates a new [Set] for the given index.
    pub fn new(ordered: Ordered<P>) -> Self {
        let knowledge = BitMap::zeroes(ordered.len() as u64);
        Self { ordered, knowledge }
    }

    /// Marks the given peer as known or unknown.
    pub fn update(&mut self, peer: &P, known: bool) -> bool {
        if let Some(idx) = self.ordered.position(peer) {
            self.knowledge.set(idx as u64, known);
            return true;
        }
        false
    }

    /// Returns the number of peers in the set.
    pub fn len(&self) -> usize {
        self.ordered.len()
    }

    /// Returns the bit vector indicating which peers are known.
    pub fn knowledge(&self) -> BitMap {
        self.knowledge.clone()
    }
}

impl<'a, P: PublicKey> IntoIterator for &'a Set<P> {
    type Item = &'a P;
    type IntoIter = std::slice::Iter<'a, P>;

    fn into_iter(self) -> Self::IntoIter {
        self.ordered.iter()
    }
}

impl<P: PublicKey> std::ops::Index<usize> for Set<P> {
    type Output = P;

    fn index(&self, index: usize) -> &Self::Output {
        &self.ordered[index]
    }
}

impl<P: PublicKey> Deref for Set<P> {
    type Target = Ordered<P>;

    fn deref(&self) -> &Self::Target {
        &self.ordered
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::{ed25519, PrivateKeyExt, Signer};
    use std::collections::HashSet;

    fn create_test_peers() -> Vec<ed25519::PublicKey> {
        vec![
            ed25519::PrivateKey::from_seed(3).public_key(),
            ed25519::PrivateKey::from_seed(1).public_key(),
            ed25519::PrivateKey::from_seed(2).public_key(),
        ]
    }

    fn expected_sorted_peers() -> Vec<ed25519::PublicKey> {
        vec![
            ed25519::PrivateKey::from_seed(1).public_key(), // 478b8e507e0bb2b18c0f9e0824769e8562d10df9abe2e774896f82b4b4405266
            ed25519::PrivateKey::from_seed(2).public_key(), // 5925ba86e2189444a6c3b437b25d2ef35daecd1abf82c5fb36060f9fc0af428c
            ed25519::PrivateKey::from_seed(3).public_key(), // ec8924090e507c2d8371d2fb0bf965d553e6e5756aeec6c274df3801cf2b49b9
        ]
    }

    #[test]
    fn test_set_initialization_and_sorting() {
        let peers = create_test_peers();
        let set = Set::new(peers.into());

        let expected_peers = expected_sorted_peers();
        assert_eq!(set.len(), 3, "Set length should be 3");
        assert_eq!(
            set.ordered.as_ref(),
            expected_peers,
            "Peers should be sorted"
        );

        for (i, peer) in expected_peers.iter().enumerate() {
            assert_eq!(
                set.ordered.position(peer),
                Some(i),
                "Peer {peer} should map to index {i}"
            );
        }
        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![false, false, false]),
            "Initial knowledge should be all false"
        );
    }

    #[test]
    fn test_update_knowledge_single_peer() {
        let peers = create_test_peers();
        let mut set = Set::new(peers.into());
        let peer_to_update = ed25519::PrivateKey::from_seed(3).public_key();
        let non_existent_peer = ed25519::PrivateKey::from_seed(4).public_key();

        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![false, false, false]),
            "Initial state"
        );

        let update_result = set.update(&peer_to_update, true);
        assert!(update_result, "Update for existing peer should return true");
        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![false, false, true]),
            "Peer 3 should be known"
        );

        let update_result_again = set.update(&peer_to_update, true); // Idempotent
        assert!(update_result_again, "Idempotent update should return true");
        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![false, false, true]),
            "Knowledge should be unchanged after idempotent update"
        );

        let update_result_false = set.update(&peer_to_update, false);
        assert!(
            update_result_false,
            "Update to false for existing peer should return true"
        );
        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![false, false, false]),
            "Peer 3 should be unknown again"
        );

        let update_result_non_existent = set.update(&non_existent_peer, true);
        assert!(
            !update_result_non_existent,
            "Update for non-existent peer should return false"
        );
        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![false, false, false]),
            "Knowledge should be unchanged after failed update"
        );
    }

    #[test]
    fn test_update_multiple_peers() {
        let peers = create_test_peers();
        let mut set = Set::new(peers.into());
        let peer1 = ed25519::PrivateKey::from_seed(2).public_key();
        let peer2 = ed25519::PrivateKey::from_seed(3).public_key();
        let peer3 = ed25519::PrivateKey::from_seed(1).public_key();

        assert!(set.update(&peer1, true));
        assert!(set.update(&peer3, true));
        assert!(set.update(&peer2, true));
        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![true, true, true]),
            "All peers should be known"
        );

        assert!(set.update(&peer1, false));
        assert!(set.update(&peer3, false));
        assert_eq!(
            set.knowledge(),
            BitMap::from(vec![false, false, true]),
            "Only peer 3 should be known"
        );
    }

    #[test]
    fn test_len() {
        let peers = create_test_peers();
        let set = Set::new(peers.into());
        assert_eq!(set.len(), 3);

        let single_peer = vec![ed25519::PrivateKey::from_seed(10).public_key()];
        let single_set = Set::new(single_peer.into());
        assert_eq!(single_set.len(), 1);

        let empty_peers: Vec<ed25519::PublicKey> = vec![];
        let empty_set = Set::new(empty_peers.into());
        assert_eq!(empty_set.len(), 0);
    }

    #[test]
    fn test_knowledge_reflects_updates_and_cloning() {
        let peers = create_test_peers();
        let mut set = Set::new(peers.into());
        let peer1 = ed25519::PrivateKey::from_seed(2).public_key();
        let peer2 = ed25519::PrivateKey::from_seed(3).public_key();

        let knowledge_before_updates = set.knowledge();
        assert_eq!(
            knowledge_before_updates,
            BitMap::from(vec![false, false, false])
        );

        set.update(&peer1, true);
        let knowledge_after_first_update = set.knowledge();
        assert_eq!(
            knowledge_after_first_update,
            BitMap::from(vec![false, true, false])
        );
        assert_ne!(
            knowledge_before_updates, knowledge_after_first_update,
            "Cloned knowledge should differ after update"
        );

        set.update(&peer2, true);
        let knowledge_after_second_update = set.knowledge();
        assert_eq!(
            knowledge_after_second_update,
            BitMap::from(vec![false, true, true])
        );
        assert_ne!(
            knowledge_after_first_update, knowledge_after_second_update,
            "Cloned knowledge should differ after second update"
        );

        assert_eq!(
            knowledge_before_updates,
            BitMap::from(vec![false, false, false]),
            "Original clone must remain unchanged"
        );
    }

    #[test]
    fn test_into_iterator() {
        let peers_data = create_test_peers();
        let set = Set::new(peers_data.into());

        let expected_peers = expected_sorted_peers();
        let iterated_peers: Vec<&ed25519::PublicKey> = set.into_iter().collect();
        let expected_refs: Vec<&ed25519::PublicKey> = expected_peers.iter().collect();

        assert_eq!(
            iterated_peers, expected_refs,
            "Iterator should yield peers in sorted order"
        );

        let iterated_set: HashSet<ed25519::PublicKey> = set.into_iter().cloned().collect();
        let expected_set: HashSet<ed25519::PublicKey> = expected_peers.into_iter().collect();
        assert_eq!(
            iterated_set, expected_set,
            "Iterated elements should match expected unique peers"
        );
    }

    #[test]
    fn test_index() {
        let peers = create_test_peers();
        let set = Set::new(peers.into());
        let expected_peers = expected_sorted_peers();

        assert_eq!(set[0], expected_peers[0]);
        assert_eq!(set[1], expected_peers[1]);
        assert_eq!(set[2], expected_peers[2]);
    }

    #[test]
    #[should_panic]
    fn test_index_out_of_bounds_positive() {
        let peers: Vec<ed25519::PublicKey> = vec![ed25519::PrivateKey::from_seed(1).public_key()];
        let set = Set::new(peers.into());
        let _ = set[1];
    }

    #[test]
    fn test_empty_set_behavior() {
        let peers: Vec<ed25519::PublicKey> = Vec::new();
        let mut set = Set::new(peers.into());

        assert_eq!(set.len(), 0);
        assert_eq!(set.knowledge(), BitMap::zeroes(0));

        let update_result = set.update(&ed25519::PrivateKey::from_seed(1).public_key(), true);
        assert!(!update_result, "Update on empty set should fail");

        let mut count = 0;
        for _ in &set {
            count += 1;
        }
        assert_eq!(count, 0, "Iteration count on empty set");
    }

    #[test]
    fn test_single_peer_set() {
        let peers = vec![ed25519::PrivateKey::from_seed(42).public_key()];
        let mut set = Set::new(peers.clone().into());

        assert_eq!(set.len(), 1);
        assert_eq!(
            set.ordered.as_ref(),
            vec![ed25519::PrivateKey::from_seed(42).public_key()]
        );
        assert_eq!(
            set.ordered
                .position(&ed25519::PrivateKey::from_seed(42).public_key()),
            Some(0)
        );
        assert_eq!(set.knowledge(), BitMap::from(vec![false]));

        assert!(set.update(&ed25519::PrivateKey::from_seed(42).public_key(), true));
        assert_eq!(set.knowledge(), BitMap::from(vec![true]));

        assert!(set.update(&ed25519::PrivateKey::from_seed(42).public_key(), false));
        assert_eq!(set.knowledge(), BitMap::from(vec![false]));

        assert_eq!(set[0], ed25519::PrivateKey::from_seed(42).public_key());

        let mut iterated = vec![];
        for peer in &set {
            iterated.push(peer.clone());
        }
        assert_eq!(
            iterated,
            vec![ed25519::PrivateKey::from_seed(42).public_key()]
        );
    }
}
