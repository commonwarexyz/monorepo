//! Prometheus metrics labels for minimmit consensus.

#![allow(dead_code)] // Skeleton implementation - metrics will be used when actors are complete

use commonware_utils::Array;
use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue};

/// Message types for metrics labeling.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum MessageType {
    /// Notarize vote.
    Notarize,
    /// Notarization certificate.
    Notarization,
    /// Nullify vote.
    Nullify,
    /// Nullification certificate.
    Nullification,
}

/// Labels for outbound messages.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Outbound {
    /// Message type.
    pub message: MessageType,
}

impl Outbound {
    /// Returns a static reference to notarize outbound label.
    pub const fn notarize() -> &'static Self {
        &Self {
            message: MessageType::Notarize,
        }
    }

    /// Returns a static reference to notarization outbound label.
    pub const fn notarization() -> &'static Self {
        &Self {
            message: MessageType::Notarization,
        }
    }

    /// Returns a static reference to nullify outbound label.
    pub const fn nullify() -> &'static Self {
        &Self {
            message: MessageType::Nullify,
        }
    }

    /// Returns a static reference to nullification outbound label.
    pub const fn nullification() -> &'static Self {
        &Self {
            message: MessageType::Nullification,
        }
    }
}

/// Labels for inbound messages.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Inbound {
    /// Peer identifier.
    pub peer: String,
    /// Message type.
    pub message: MessageType,
}

impl Inbound {
    /// Creates inbound labels for a notarize message.
    pub fn notarize(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Notarize,
        }
    }

    /// Creates inbound labels for a nullify message.
    pub fn nullify(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Nullify,
        }
    }

    /// Creates inbound labels for a notarization message.
    pub fn notarization(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Notarization,
        }
    }

    /// Creates inbound labels for a nullification message.
    pub fn nullification(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
            message: MessageType::Nullification,
        }
    }
}
