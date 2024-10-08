use commonware_cryptography::{utils::hex, PublicKey};
use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReceivedMessage {
    pub peer: String,
    pub message: i32,
}

impl ReceivedMessage {
    pub fn new(peer: &PublicKey, channel: u32) -> Self {
        Self {
            peer: hex(peer),
            message: channel as i32,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SentMessage {
    pub peer: String,
}

impl SentMessage {
    pub fn new(peer: &PublicKey) -> Self {
        Self { peer: hex(peer) }
    }
}
