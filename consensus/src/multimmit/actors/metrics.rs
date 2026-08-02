use commonware_cryptography::PublicKey;
use commonware_runtime::telemetry::metrics::{EncodeLabelSet, EncodeLabelValue, EncodeStruct};

/// A bounded Multimmit network plane.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(super) enum TrafficPlane {
    Data,
    Consensus,
    Certificate,
}

/// Per-plane traffic label.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(super) struct Traffic {
    pub plane: TrafficPlane,
}

impl Traffic {
    pub const DATA: Self = Self {
        plane: TrafficPlane::Data,
    };
    pub const CONSENSUS: Self = Self {
        plane: TrafficPlane::Consensus,
    };
    pub const CERTIFICATE: Self = Self {
        plane: TrafficPlane::Certificate,
    };
    pub const VOTER: [Self; 3] = [Self::DATA, Self::CONSENSUS, Self::CERTIFICATE];
}

/// Per-peer traffic label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub(super) struct Peer<P: PublicKey> {
    pub peer: P,
}
