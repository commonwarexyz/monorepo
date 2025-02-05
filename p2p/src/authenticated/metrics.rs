use crate::Channel;
use commonware_cryptography::Octets;
use commonware_utils::hex;
use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Peer {
    pub peer: String,
}

impl Peer {
    pub fn new<P: Octets>(peer: &P) -> Self {
        Self { peer: hex(peer) }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub peer: String,
    pub message: i32,
}

impl Message {
    const BIT_VEC_TYPE: i32 = -1;
    const PEERS_TYPE: i32 = -2;
    const UNKNOWN_TYPE: i32 = i32::MIN;

    pub fn new_bit_vec<P: Octets>(peer: &P) -> Self {
        Self {
            peer: hex(peer),
            message: Self::BIT_VEC_TYPE,
        }
    }
    pub fn new_peers<P: Octets>(peer: &P) -> Self {
        Self {
            peer: hex(peer),
            message: Self::PEERS_TYPE,
        }
    }
    pub fn new_data<P: Octets>(peer: &P, channel: Channel) -> Self {
        Self {
            peer: hex(peer),
            message: channel as i32,
        }
    }
    pub fn new_unknown<P: Octets>(peer: &P) -> Self {
        Self {
            peer: hex(peer),
            message: Self::UNKNOWN_TYPE,
        }
    }
}
