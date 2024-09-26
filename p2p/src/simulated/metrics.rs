use commonware_cryptography::{utils::hex, PublicKey};
use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ReceivedMessage {
    pub peer: String,
    pub message: i32,
}

impl ReceivedMessage {
    const UNKNOWN_TYPE: i32 = -1;
    const TOO_LARGE_TYPE: i32 = -2;

    pub fn new_unknown(peer: &PublicKey) -> Self {
        Self {
        peer: hex(peer),
        message: Self::UNKNOWN_TYPE,
        }
    }

    pub fn new_too_large(peer: &PublicKey) -> Self {
        Self {
        peer: hex(peer),
        message: Self::TOO_LARGE_TYPE,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SentMessage {
    pub peer: String,
    pub message: i32,
}

impl SentMessage {
    const SUCCESS_TYPE: i32 = -1;
    const FAILED_TYPE: i32 = -2;
    const DROPPED_TYPE: i32 = -3;

    pub fn new_success(peer: &PublicKey) -> Self {
        Self {
        peer: hex(peer),
        message: Self::SUCCESS_TYPE,
        }
    }

    pub fn new_failed(peer: &PublicKey) -> Self {
        Self {
        peer: hex(peer),
        message: Self::FAILED_TYPE,
        }
    }

    pub fn new_dropped(peer: &PublicKey) -> Self {
        Self {
        peer: hex(peer),
        message: Self::DROPPED_TYPE,
        }
    }
}