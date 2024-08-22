use commonware_cryptography::PublicKey;
use prometheus_client::encoding::EncodeLabelSet;

const HANDSHAKE_TYPE: i32 = -1;
const BIT_VEC_TYPE: i32 = -2;
const PEERS_TYPE: i32 = -3;
const UNKNOWN_TYPE: i32 = i32::MIN;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Peer {
    pub peer: String,
}

impl Peer {
    pub fn new(peer: &PublicKey) -> Self {
        Self {
            peer: hex::encode(peer),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub peer: String,
    pub message: i32,
}

impl Message {
    pub fn new_handshake(peer: &PublicKey) -> Self {
        Self {
            peer: hex::encode(peer),
            message: HANDSHAKE_TYPE,
        }
    }
    pub fn new_bit_vec(peer: &PublicKey) -> Self {
        Self {
            peer: hex::encode(peer),
            message: BIT_VEC_TYPE,
        }
    }
    pub fn new_peers(peer: &PublicKey) -> Self {
        Self {
            peer: hex::encode(peer),
            message: PEERS_TYPE,
        }
    }
    pub fn new_chunk(peer: &PublicKey, channel: u32) -> Self {
        Self {
            peer: hex::encode(peer),
            message: channel as i32,
        }
    }
    pub fn new_unknown(peer: &PublicKey) -> Self {
        Self {
            peer: hex::encode(peer),
            message: UNKNOWN_TYPE,
        }
    }
}
