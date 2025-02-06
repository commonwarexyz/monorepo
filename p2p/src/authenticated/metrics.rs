use crate::Channel;
use commonware_cryptography::FormattedBytes;
use commonware_utils::hex;
use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Peer {
    pub peer: String,
}

impl Peer {
    pub fn new(peer: &impl FormattedBytes) -> Self {
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

    pub fn new_bit_vec(peer: &impl FormattedBytes) -> Self {
        Self {
            peer: hex(peer),
            message: Self::BIT_VEC_TYPE,
        }
    }
    pub fn new_peers(peer: &impl FormattedBytes) -> Self {
        Self {
            peer: hex(peer),
            message: Self::PEERS_TYPE,
        }
    }
    pub fn new_data(peer: &impl FormattedBytes, channel: Channel) -> Self {
        Self {
            peer: hex(peer),
            message: channel as i32,
        }
    }
    pub fn new_unknown(peer: &impl FormattedBytes) -> Self {
        Self {
            peer: hex(peer),
            message: Self::UNKNOWN_TYPE,
        }
    }
}
