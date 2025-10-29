use crate::Channel;
use commonware_utils::Array;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use std::fmt::Write;

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

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum MessageType {
    BitVec,
    Peers,
    Data(u64),
    Invalid,
}

impl EncodeLabelValue for MessageType {
    fn encode(&self, encoder: &mut LabelValueEncoder) -> Result<(), std::fmt::Error> {
        match self {
            MessageType::BitVec => encoder.write_str("bit_vec"),
            MessageType::Peers => encoder.write_str("peers"),
            MessageType::Data(channel) => encoder.write_str(&format!("data_{channel}")),
            MessageType::Invalid => encoder.write_str("invalid"),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub peer: String,
    pub message: MessageType,
}

impl Message {
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
    pub fn new_data(peer: &impl Array, channel: Channel) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Data(channel),
        }
    }
    pub fn new_invalid(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Invalid,
        }
    }
}
