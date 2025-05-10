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
    pub fn set_to(&mut self, peer: &P, known: bool) -> bool {
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

    #[test]
    fn test_set_initialization() {
        let peers = vec![U64::new(3), U64::new(1), U64::new(2)];
        let set = Set::new(peers);
        assert_eq!(set.len(), 3);
        assert_eq!(set.sorted, vec![U64::new(1), U64::new(2), U64::new(3)]);
        assert_eq!(set.order.get(&U64::new(1)), Some(&0));
        assert_eq!(set.order.get(&U64::new(2)), Some(&1));
        assert_eq!(set.order.get(&U64::new(3)), Some(&2));
        assert_eq!(set.knowledge(), BitVec::from(vec![false, false, false]));
    }

    #[test]
    fn test_set_to_known_and_unknown() {
        let peers = vec![U64::new(1), U64::new(2), U64::new(3)];
        let mut set = Set::new(peers);

        // Mark peer 2 as known
        assert!(set.set_to(&U64::new(2), true));
        assert_eq!(set.knowledge(), BitVec::from(vec![false, true, false]));

        // Mark peer 2 as unknown again
        assert!(set.set_to(&U64::new(2), false));
        assert_eq!(set.knowledge(), BitVec::from(vec![false, false, false]));

        // Mark peer 1 as known
        assert!(set.set_to(&U64::new(1), true));
        assert_eq!(set.knowledge(), BitVec::from(vec![true, false, false]));

        // Try to set a peer not in the set
        assert!(!set.set_to(&U64::new(4), true));
        assert_eq!(set.knowledge(), BitVec::from(vec![true, false, false])); // Knowledge should remain unchanged
    }

    #[test]
    fn test_len() {
        let peers = vec![U64::new(1), U64::new(2), U64::new(3)];
        let set = Set::new(peers);
        assert_eq!(set.len(), 3);

        let empty_peers: Vec<U64> = vec![];
        let empty_set = Set::new(empty_peers);
        assert_eq!(empty_set.len(), 0);
    }

    #[test]
    fn test_knowledge_cloning() {
        let peers = vec![U64::new(1), U64::new(2)];
        let mut set = Set::new(peers);
        set.set_to(&U64::new(1), true);

        let knowledge1 = set.knowledge();
        // Modify the original set's knowledge
        set.set_to(&U64::new(2), true);
        let knowledge2 = set.knowledge();

        assert_eq!(knowledge1, BitVec::from(vec![true, false]));
        assert_eq!(knowledge2, BitVec::from(vec![true, true]));
        assert_ne!(
            knowledge1, knowledge2,
            "Cloned BitVec should not reflect later changes to the original set's knowledge"
        );
    }

    #[test]
    fn test_into_iterator() {
        let peers_data = vec![U64::new(3), U64::new(1), U64::new(2)];
        let set = Set::new(peers_data.clone()); // clone because new sorts it

        let mut iterated_peers = Vec::new();
        for peer in &set {
            iterated_peers.push(peer.clone());
        }
        // new() sorts the peers
        assert_eq!(iterated_peers, vec![U64::new(1), U64::new(2), U64::new(3)]);
    }

    #[test]
    fn test_index() {
        let peers = vec![U64::new(3), U64::new(1), U64::new(2)];
        let set = Set::new(peers); // sorted: [1, 2, 3]

        assert_eq!(set[0], U64::new(1));
        assert_eq!(set[1], U64::new(2));
        assert_eq!(set[2], U64::new(3));
    }

    #[test]
    #[should_panic]
    fn test_index_out_of_bounds() {
        let peers: Vec<U64> = vec![U64::new(1)];
        let set = Set::new(peers);
        let _ = set[1]; // Accessing out of bounds
    }

    #[test]
    fn test_empty_set() {
        let peers: Vec<U64> = Vec::new();
        let mut set = Set::new(peers);

        assert_eq!(set.len(), 0);
        assert_eq!(set.knowledge(), BitVec::zeroes(0));
        assert!(!set.set_to(&U64::new(1), true)); // Cannot set anything

        let mut count = 0;
        for _ in &set {
            count += 1;
        }
        assert_eq!(count, 0);
    }
}
