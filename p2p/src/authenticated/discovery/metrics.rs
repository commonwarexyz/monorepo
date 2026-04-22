use crate::Channel;
use commonware_cryptography::PublicKey;
use commonware_runtime::metrics::{EncodeLabelSet, EncodeLabelValue, EncodeStruct, LabelValueEncoder};
use commonware_utils::Array;
use std::fmt::Write;

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

impl EncodeLabelValue for MessageType {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Data(channel) => encoder.write_str(&format!("data_{channel}")),
            Self::Greeting => encoder.write_str("greeting"),
            Self::BitVec => encoder.write_str("bit_vec"),
            Self::Peers => encoder.write_str("peers"),
            Self::Invalid => encoder.write_str("invalid"),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub peer: String,
    pub message: MessageType,
}

impl Message {
    pub fn new_data(peer: &impl Array, channel: Channel) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Data(channel),
        }
    }
    pub fn new_greeting(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Greeting,
        }
    }
    pub fn new_bit_vec(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::BitVec,
        }
    }
    pub fn new_peers(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Peers,
        }
    }
    pub fn new_invalid(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Invalid,
        }
    }
}
