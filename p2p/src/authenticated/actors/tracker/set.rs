use crate::authenticated::types;
use bitvec::{order::Lsb0, vec::BitVec};
use commonware_utils::Array;
use std::collections::HashMap;

/// Represents a set of peers and their knowledge of each other.
pub struct Set<P: Array> {
    /// The index at which this peer set applies.
    pub index: u64,

    /// The list of peers, sorted.
    pub sorted: Vec<P>,

    /// The index of each peer in the sorted list, for quick lookup.
    pub order: HashMap<P, usize>,

    /// My knowledge of each peer in the set.
    pub knowledge: BitVec<u8, Lsb0>,

    /// The message to send to other peers.
    pub msg: types::BitVec,
}

impl<P: Array> Set<P> {
    pub fn new(index: u64, mut peers: Vec<P>) -> Self {
        // Insert peers in sorted order
        peers.sort();
        let mut order = HashMap::new();
        for (idx, peer) in peers.iter().enumerate() {
            order.insert(peer.clone(), idx);
        }

        // Create bit vector
        let mut knowledge = BitVec::repeat(false, peers.len());
        knowledge.set_uninitialized(false);

        // Create message
        let msg = types::BitVec {
            index,
            bits: knowledge.clone().into(),
        };

        Self {
            index,
            sorted: peers,
            order,
            knowledge,
            msg,
        }
    }

    pub fn found(&mut self, peer: P) -> bool {
        if let Some(idx) = self.order.get(&peer) {
            self.knowledge.set(*idx, true);
            return true;
        }
        false
    }

    pub fn update_msg(&mut self) {
        let mut k = self.knowledge.clone();
        k.set_uninitialized(false);
        self.msg = types::BitVec {
            index: self.index,
            bits: k.into_vec(),
        };
    }

    pub fn msg(&self) -> types::BitVec {
        self.msg.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitvec::bitvec;
    use commonware_utils::array::U64;

    #[test]
    fn test_set_initialization() {
        let peers = vec![U64::new(3), U64::new(1), U64::new(2)];
        let set = Set::new(0, peers);
        assert_eq!(set.sorted, vec![U64::new(1), U64::new(2), U64::new(3)]);
        assert_eq!(set.order.get(&U64::new(1)), Some(&0));
        assert_eq!(set.order.get(&U64::new(2)), Some(&1));
        assert_eq!(set.order.get(&U64::new(3)), Some(&2));
        assert_eq!(set.knowledge, bitvec![u8, Lsb0; 0; 3]);
        assert_eq!(set.msg.bits, vec![0]); // Initial message is all zeros
    }

    #[test]
    fn test_found() {
        let peers = vec![U64::new(1), U64::new(2), U64::new(3)];
        let mut set = Set::new(0, peers);
        assert!(set.found(U64::new(2)));
        assert_eq!(set.knowledge, bitvec![u8, Lsb0; 0, 1, 0]);
        assert!(!set.found(U64::new(4))); // Peer not in set
        assert_eq!(set.knowledge, bitvec![u8, Lsb0; 0, 1, 0]);
    }

    #[test]
    fn test_update_msg() {
        let peers = vec![U64::new(1), U64::new(2), U64::new(3)];
        let mut set = Set::new(0, peers);
        set.found(U64::new(1));
        set.found(U64::new(3));
        set.update_msg();
        assert_eq!(set.msg.index, 0);
        assert_eq!(set.msg.bits, vec![0b101]); // Bits 0 and 2 set (LSB first)
    }

    #[test]
    fn test_msg() {
        let peers = vec![U64::new(1), U64::new(2)];
        let mut set = Set::new(1, peers);
        set.found(U64::new(2));
        set.update_msg();
        let msg = set.msg();
        assert_eq!(msg.index, 1);
        assert_eq!(msg.bits, vec![0b10]); // Bit 1 set (LSB first)
    }
}
