use crate::authenticated::types;
use bitvec::{order::Lsb0, vec::BitVec};
use commonware_utils::Array;
use std::collections::HashMap;

/// Represents a set of peers and their knowledge of each other.
pub struct PeerSet<P: Array> {
    pub index: u64,
    pub sorted: Vec<P>,
    pub order: HashMap<P, usize>,
    pub knowledge: BitVec<u8, Lsb0>,
    pub msg: types::BitVec,
}

impl<P: Array> PeerSet<P> {
    pub fn new(index: u64, mut peers: Vec<P>) -> Self {
        // Insert peers in sorted order
        peers.sort();
        let mut order = HashMap::new();
        for (idx, peer) in peers.iter().enumerate() {
            order.insert(peer.clone(), idx);
        }

        // Create bit vector
        let knowledge = BitVec::repeat(false, peers.len());

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
        self.msg = types::BitVec {
            index: self.index,
            bits: self.knowledge.clone().into(),
        };
    }

    pub fn msg(&self) -> types::BitVec {
        self.msg.clone()
    }
}
