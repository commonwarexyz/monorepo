use crate::Channel;
use commonware_cryptography::PublicKey;
use commonware_utils::hex;
use prometheus_client::encoding::EncodeLabelSet;

use crate::Channel;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub origin: String,
    pub recipient: String,
    pub channel: Channel,
}

impl Message {
    pub fn new(origin: &PublicKey, recipient: &PublicKey, channel: Channel) -> Self {
        Self {
            origin: hex(origin),
            recipient: hex(recipient),
            channel,
        }
    }
}
