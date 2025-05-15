use commonware_utils::{Array, BitVec};
use std::collections::HashMap;

/// Represents a set of peers and their knowledge of each other.
pub struct Set<P: Array> {
    /// The list of peers, sorted.
    sorted: Vec<P>,

    /// The index of each peer in the sorted list, for quick lookup.
    order: HashMap<P, usize>,

    /// For each peer, whether I know their peer info or not.
    knowledge: BitVec,
}

impl<P: Array> Set<P> {
    /// Creates a new set for the given index.
    pub fn new(mut peers: Vec<P>) -> Self {
        peers.sort();
        let mut order = HashMap::new();
        for (i, peer) in peers.iter().enumerate() {
            order.insert(peer.clone(), i);
        }
        let knowledge = BitVec::zeroes(peers.len());
        Self {
            sorted: peers,
            order,
            knowledge,
        }
    }

    /// Marks the given peer as known or unknown.
    pub fn update(&mut self, peer: &P, known: bool) -> bool {
        if let Some(idx) = self.order.get(peer) {
            self.knowledge.set_to(*idx, known);
            return true;
        }
        false
    }

    /// Returns the number of peers in the set.
    pub fn len(&self) -> usize {
        self.sorted.len()
    }

    /// Returns the bit vector indicating which peers are known.
    pub fn knowledge(&self) -> BitVec {
        self.knowledge.clone()
    }
}

impl<'a, P: Array> IntoIterator for &'a Set<P> {
    type Item = &'a P;
    type IntoIter = std::slice::Iter<'a, P>;

    fn into_iter(self) -> Self::IntoIter {
        self.sorted.iter()
    }
}

impl<P: Array> std::ops::Index<usize> for Set<P> {
    type Output = P;

    fn index(&self, index: usize) -> &Self::Output {
        &self.sorted[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{array::U64, BitVec};
    use std::collections::HashSet;

    fn create_test_peers() -> Vec<U64> {
        vec![U64::new(3), U64::new(1), U64::new(2)]
    }

    fn expected_sorted_peers() -> Vec<U64> {
        vec![U64::new(1), U64::new(2), U64::new(3)]
    }

    #[test]
    fn test_set_initialization_and_sorting() {
        let peers = create_test_peers();
        let set = Set::new(peers);

        let expected_peers = expected_sorted_peers();
        assert_eq!(set.len(), 3, "Set length should be 3");
        assert_eq!(set.sorted, expected_peers, "Peers should be sorted");

        for (i, peer) in expected_peers.iter().enumerate() {
            assert_eq!(
                set.order.get(peer),
                Some(&i),
                "Peer {} should map to index {}",
                peer,
                i
            );
        }
        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![false, false, false]),
            "Initial knowledge should be all false"
        );
    }

    #[test]
    fn test_update_knowledge_single_peer() {
        let peers = create_test_peers();
        let mut set = Set::new(peers);
        let peer_to_update = U64::new(2);
        let non_existent_peer = U64::new(4);

        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![false, false, false]),
            "Initial state"
        );

        let update_result = set.update(&peer_to_update, true);
        assert!(update_result, "Update for existing peer should return true");
        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![false, true, false]),
            "Peer 2 should be known"
        );

        let update_result_again = set.update(&peer_to_update, true); // Idempotent
        assert!(update_result_again, "Idempotent update should return true");
        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![false, true, false]),
            "Knowledge should be unchanged after idempotent update"
        );

        let update_result_false = set.update(&peer_to_update, false);
        assert!(
            update_result_false,
            "Update to false for existing peer should return true"
        );
        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![false, false, false]),
            "Peer 2 should be unknown again"
        );

        let update_result_non_existent = set.update(&non_existent_peer, true);
        assert!(
            !update_result_non_existent,
            "Update for non-existent peer should return false"
        );
        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![false, false, false]),
            "Knowledge should be unchanged after failed update"
        );
    }

    #[test]
    fn test_update_multiple_peers() {
        let peers = create_test_peers();
        let mut set = Set::new(peers);
        let peer1 = U64::new(1);
        let peer2 = U64::new(2);
        let peer3 = U64::new(3);

        assert!(set.update(&peer1, true));
        assert!(set.update(&peer3, true));
        assert!(set.update(&peer2, true));
        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![true, true, true]),
            "All peers should be known"
        );

        assert!(set.update(&peer1, false));
        assert!(set.update(&peer3, false));
        assert_eq!(
            set.knowledge(),
            BitVec::from(vec![false, true, false]),
            "Only peer 2 should be known"
        );
    }

    #[test]
    fn test_len() {
        let peers = create_test_peers();
        let set = Set::new(peers);
        assert_eq!(set.len(), 3);

        let single_peer = vec![U64::new(10)];
        let single_set = Set::new(single_peer);
        assert_eq!(single_set.len(), 1);

        let empty_peers: Vec<U64> = vec![];
        let empty_set = Set::new(empty_peers);
        assert_eq!(empty_set.len(), 0);
    }

    #[test]
    fn test_knowledge_reflects_updates_and_cloning() {
        let peers = create_test_peers();
        let mut set = Set::new(peers);
        let peer1 = U64::new(1);
        let peer2 = U64::new(2);

        let knowledge_before_updates = set.knowledge();
        assert_eq!(
            knowledge_before_updates,
            BitVec::from(vec![false, false, false])
        );

        set.update(&peer1, true);
        let knowledge_after_first_update = set.knowledge();
        assert_eq!(
            knowledge_after_first_update,
            BitVec::from(vec![true, false, false])
        );
        assert_ne!(
            knowledge_before_updates, knowledge_after_first_update,
            "Cloned knowledge should differ after update"
        );

        set.update(&peer2, true);
        let knowledge_after_second_update = set.knowledge();
        assert_eq!(
            knowledge_after_second_update,
            BitVec::from(vec![true, true, false])
        );
        assert_ne!(
            knowledge_after_first_update, knowledge_after_second_update,
            "Cloned knowledge should differ after second update"
        );

        assert_eq!(
            knowledge_before_updates,
            BitVec::from(vec![false, false, false]),
            "Original clone must remain unchanged"
        );
    }

    #[test]
    fn test_into_iterator() {
        let peers_data = create_test_peers();
        let set = Set::new(peers_data);

        let expected_peers = expected_sorted_peers();
        let iterated_peers: Vec<&U64> = set.into_iter().collect();
        let expected_refs: Vec<&U64> = expected_peers.iter().collect();

        assert_eq!(
            iterated_peers, expected_refs,
            "Iterator should yield peers in sorted order"
        );

        let iterated_set: HashSet<U64> = set.into_iter().cloned().collect();
        let expected_set: HashSet<U64> = expected_peers.into_iter().collect();
        assert_eq!(
            iterated_set, expected_set,
            "Iterated elements should match expected unique peers"
        );
    }

    #[test]
    fn test_index() {
        let peers = create_test_peers();
        let set = Set::new(peers);
        let expected_peers = expected_sorted_peers();

        assert_eq!(set[0], expected_peers[0]);
        assert_eq!(set[1], expected_peers[1]);
        assert_eq!(set[2], expected_peers[2]);
    }

    #[test]
    #[should_panic]
    fn test_index_out_of_bounds_positive() {
        let peers: Vec<U64> = vec![U64::new(1)];
        let set = Set::new(peers);
        let _ = set[1];
    }

    #[test]
    fn test_empty_set_behavior() {
        let peers: Vec<U64> = Vec::new();
        let mut set = Set::new(peers);

        assert_eq!(set.len(), 0);
        assert_eq!(set.knowledge(), BitVec::zeroes(0));

        let update_result = set.update(&U64::new(1), true);
        assert!(!update_result, "Update on empty set should fail");

        let mut count = 0;
        for _ in &set {
            count += 1;
        }
        assert_eq!(count, 0, "Iteration count on empty set");
    }

    #[test]
    fn test_single_peer_set() {
        let peers = vec![U64::new(42)];
        let mut set = Set::new(peers.clone());

        assert_eq!(set.len(), 1);
        assert_eq!(set.sorted, vec![U64::new(42)]);
        assert_eq!(set.order.get(&U64::new(42)), Some(&0));
        assert_eq!(set.knowledge(), BitVec::from(vec![false]));

        assert!(set.update(&U64::new(42), true));
        assert_eq!(set.knowledge(), BitVec::from(vec![true]));

        assert!(set.update(&U64::new(42), false));
        assert_eq!(set.knowledge(), BitVec::from(vec![false]));

        assert_eq!(set[0], U64::new(42));

        let mut iterated = vec![];
        for peer in &set {
            iterated.push(peer.clone());
        }
        assert_eq!(iterated, vec![U64::new(42)]);
    }
}
