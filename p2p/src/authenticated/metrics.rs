use commonware_cryptography::PublicKey;
use commonware_runtime::telemetry::metrics::EncodeStruct;

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Peer<P: PublicKey> {
    pub peer: P,
}
