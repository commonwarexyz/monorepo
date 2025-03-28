use crate::Channel;
use commonware_utils::Array;
use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Peer {
    pub peer: String,
}

impl Peer {
    pub fn new(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
        }
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
    const INVALID_TYPE: i32 = i32::MIN;

    pub fn new_bit_vec(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: Self::BIT_VEC_TYPE,
        }
    }
    pub fn new_peers(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: Self::PEERS_TYPE,
        }
    }
    pub fn new_data(peer: &impl Array, channel: Channel) -> Self {
        Self {
            peer: peer.to_string(),
            message: channel as i32,
        }
    }
    pub fn new_invalid(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: Self::INVALID_TYPE,
        }
    }
}
