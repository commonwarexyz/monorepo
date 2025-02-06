use crate::Channel;
use commonware_cryptography::Array;
use commonware_utils::hex;
use prometheus_client::encoding::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub origin: String,
    pub recipient: String,
    pub channel: Channel,
}

impl Message {
    pub fn new<P: Array>(origin: &P, recipient: &P, channel: Channel) -> Self {
        Self {
            origin: hex(origin),
            recipient: hex(recipient),
            channel,
        }
    }
}
