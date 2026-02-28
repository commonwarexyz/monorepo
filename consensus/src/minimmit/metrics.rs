//! Metric labels for Minimmit consensus.

use commonware_utils::Array;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};

/// Peer label for metrics.
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

/// Message types for metrics labels.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum MessageType {
    Notarize,
    MNotarization,
    Nullify,
    Nullification,
    Finalization,
}

/// Outbound message labels.
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

    pub const fn m_notarization() -> &'static Self {
        &Self {
            message: MessageType::MNotarization,
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

    pub const fn finalization() -> &'static Self {
        &Self {
            message: MessageType::Finalization,
        }
    }
}

/// Inbound message labels.
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

    pub fn m_notarization(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::MNotarization,
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
