use crate::Channel;
use commonware_cryptography::PublicKey;
use commonware_runtime::telemetry::metrics::EncodeLabelSet;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Message {
    pub origin: String,
    pub recipient: String,
    pub channel: Channel,
}

impl Message {
    pub fn new<P: PublicKey>(origin: &P, recipient: &P, channel: Channel) -> Self {
        Self {
            origin: origin.to_string(),
            recipient: recipient.to_string(),
            channel,
        }
    }
}
