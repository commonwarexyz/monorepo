use commonware_utils::{Array, BitVec};
use std::collections::HashMap;

/// Represents a set of peers and their knowledge of each other.
pub struct Set<P: Array> {
    /// The list of peers, sorted.
    pub sorted: Vec<P>,

    /// The index of each peer in the sorted list, for quick lookup.
    pub order: HashMap<P, usize>,

    /// My knowledge of each peer in the set.
    pub knowledge: BitVec,
}

impl<P: Array> Set<P> {
    /// Creates a new set for the given index.
    pub fn new(mut peers: Vec<P>) -> Self {
        // Insert peers in sorted order
        peers.sort();
        let mut order = HashMap::new();
        for (idx, peer) in peers.iter().enumerate() {
            order.insert(peer.clone(), idx);
        }

        // Create bit vector
        let knowledge = BitVec::zeroes(peers.len());

        Self {
            sorted: peers,
            order,
            knowledge,
        }
    }

    /// Marks a peer as found in the set.
    ///
    /// Returns `true` if the peer is in the set, `false` otherwise.
    pub fn found(&mut self, peer: &P) -> bool {
        if let Some(idx) = self.order.get(peer) {
            self.knowledge.set(*idx);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{array::U64, BitVec};

    #[test]
    fn test_set_initialization() {
        let peers = vec![U64::new(3), U64::new(1), U64::new(2)];
        let set = Set::new(peers);
        assert_eq!(set.sorted, vec![U64::new(1), U64::new(2), U64::new(3)]);
        assert_eq!(set.order.get(&U64::new(1)), Some(&0));
        assert_eq!(set.order.get(&U64::new(2)), Some(&1));
        assert_eq!(set.order.get(&U64::new(3)), Some(&2));
        assert_eq!(set.knowledge, BitVec::from(vec![false, false, false]));
    }

    #[test]
    fn test_found() {
        let peers = vec![U64::new(1), U64::new(2), U64::new(3)];
        let mut set = Set::new(peers);
        assert!(set.found(&U64::new(2)));
        assert_eq!(set.knowledge, BitVec::from(vec![false, true, false]));
        assert!(!set.found(&U64::new(4))); // Peer not in set
        assert_eq!(set.knowledge, BitVec::from(vec![false, true, false]));
    }
}
