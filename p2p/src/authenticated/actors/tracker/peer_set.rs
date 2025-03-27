use crate::authenticated::types;
use bitvec::{order::Lsb0, vec::BitVec};
use commonware_utils::Array;
use std::collections::HashMap;

/// Represents a set of peers and their knowledge of each other.
pub struct PeerSet<P: Array> {
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
