use crate::Channel;
use commonware_cryptography::PublicKey;
use commonware_runtime::metrics::EncodeStruct;
use std::fmt;

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Peer<P: PublicKey> {
    pub peer: P,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum MessageType {
    Data(u64),
    Greeting,
    BitVec,
    Peers,
    Invalid,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(channel) => write!(f, "data_{channel}"),
            Self::Greeting => f.write_str("greeting"),
            Self::BitVec => f.write_str("bit_vec"),
            Self::Peers => f.write_str("peers"),
            Self::Invalid => f.write_str("invalid"),
        }
    }
}

/// Per-peer, per-message-type label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Message<P: PublicKey> {
    pub peer: P,
    pub message: MessageType,
}

impl<P: PublicKey> Message<P> {
    fn new(peer: &P, message: MessageType) -> Self {
        Self {
            peer: peer.clone(),
            message,
        }
    }
    pub fn new_data(peer: &P, channel: Channel) -> Self {
        Self::new(peer, MessageType::Data(channel))
    }
    pub fn new_greeting(peer: &P) -> Self {
        Self::new(peer, MessageType::Greeting)
    }
    pub fn new_bit_vec(peer: &P) -> Self {
        Self::new(peer, MessageType::BitVec)
    }
    pub fn new_peers(peer: &P) -> Self {
        Self::new(peer, MessageType::Peers)
    }
    pub fn new_invalid(peer: &P) -> Self {
        Self::new(peer, MessageType::Invalid)
    }
}
