use commonware_cryptography::PublicKey;
use commonware_runtime::telemetry::metrics::{EncodeLabelSet, EncodeLabelValue, EncodeStruct};
use commonware_utils::Array;

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Peer<P: PublicKey> {
    pub peer: P,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum TimeoutReason {
    Inactivity,
    LeaderNullify,
    LeaderTimeout,
    CertificationTimeout,
    MissingProposal,
    IgnoredProposal,
    InvalidProposal,
    FailedCertification,
}

impl TimeoutReason {
    /// Returns the stable trace field value for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inactivity => "inactivity",
            Self::LeaderNullify => "leader_nullify",
            Self::LeaderTimeout => "leader_timeout",
            Self::CertificationTimeout => "certification_timeout",
            Self::MissingProposal => "missing_proposal",
            Self::IgnoredProposal => "ignored_proposal",
            Self::InvalidProposal => "invalid_proposal",
            Self::FailedCertification => "failed_certification",
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Timeout {
    pub leader: String,
    pub reason: TimeoutReason,
}

impl Timeout {
    pub fn new(leader: &impl Array, reason: TimeoutReason) -> Self {
        Self {
            leader: leader.to_string(),
            reason,
        }
    }
}

/// Per-leader label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Leader<P: PublicKey> {
    pub leader: P,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum MessageType {
    Notarize,
    Notarization,
    Nullify,
    Nullification,
    Finalize,
    Finalization,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Outbound {
    pub message: MessageType,
}

impl Outbound {
    pub const fn notarize() -> &'static Self {
        &Self {
            message: MessageType::Notarize,
        }
    }

    pub const fn notarization() -> &'static Self {
        &Self {
            message: MessageType::Notarization,
        }
    }

    pub const fn nullify() -> &'static Self {
        &Self {
            message: MessageType::Nullify,
        }
    }

    pub const fn nullification() -> &'static Self {
        &Self {
            message: MessageType::Nullification,
        }
    }

    pub const fn finalize() -> &'static Self {
        &Self {
            message: MessageType::Finalize,
        }
    }

    pub const fn finalization() -> &'static Self {
        &Self {
            message: MessageType::Finalization,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Inbound {
    pub peer: String,
    pub message: MessageType,
}

impl Inbound {
    pub fn notarize(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Notarize,
        }
    }

    pub fn nullify(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Nullify,
        }
    }

    pub fn finalize(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Finalize,
        }
    }

    pub fn notarization(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Notarization,
        }
    }

    pub fn nullification(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Nullification,
        }
    }

    pub fn finalization(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Finalization,
        }
    }
}
