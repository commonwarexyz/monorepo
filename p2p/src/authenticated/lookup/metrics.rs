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
    Data(u64),
    Invalid,
    Ping,
}

impl EncodeLabelValue for MessageType {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Data(channel) => encoder.write_str(&format!("data_{channel}")),
            Self::Invalid => encoder.write_str("invalid"),
            Self::Ping => encoder.write_str("ping"),
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
    pub fn new_invalid(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Invalid,
        }
    }
    pub fn new_ping(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Ping,
        }
    }
}
