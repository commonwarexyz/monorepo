use commonware_cryptography::PublicKey;
use commonware_utils::hex;
use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub origin: String,
    pub recipient: String,
    pub channel: i32,
}

impl Message {
    pub fn new(origin: &PublicKey, recipient: &PublicKey, channel: u32) -> Self {
        Self {
            origin: hex(origin),
            recipient: hex(recipient),
            channel: channel as i32,
        }
    }
}
