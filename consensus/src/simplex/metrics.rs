use crate::simplex::types::{Certificate, Tag, Vote};
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};
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
    ///
    /// Matches the `EncodeLabelValue` rendering so a timeout trace span and its
    /// metric series share the same string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Inactivity => "Inactivity",
            Self::LeaderNullify => "LeaderNullify",
            Self::LeaderTimeout => "LeaderTimeout",
            Self::CertificationTimeout => "CertificationTimeout",
            Self::MissingProposal => "MissingProposal",
            Self::IgnoredProposal => "IgnoredProposal",
            Self::InvalidProposal => "InvalidProposal",
            Self::FailedCertification => "FailedCertification",
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

impl<S: Scheme, D: Digest> From<&Vote<S, D>> for MessageType {
    fn from(vote: &Vote<S, D>) -> Self {
        match vote.phase() {
            Tag::Notarize => Self::Notarize,
            Tag::Nullify => Self::Nullify,
            Tag::Finalize => Self::Finalize,
        }
    }
}

impl<S: Scheme, D: Digest> From<&Certificate<S, D>> for MessageType {
    fn from(certificate: &Certificate<S, D>) -> Self {
        match certificate.phase() {
            Tag::Notarize => Self::Notarization,
            Tag::Nullify => Self::Nullification,
            Tag::Finalize => Self::Finalization,
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Outbound {
    pub message: MessageType,
}

impl Outbound {
    /// Returns the outbound label for a message.
    pub fn new(message: impl Into<MessageType>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Inbound {
    pub peer: String,
    pub message: MessageType,
}

impl Inbound {
    /// Returns the inbound label for a message from `peer`.
    pub fn new(peer: &impl Array, message: impl Into<MessageType>) -> Self {
        Self {
            peer: peer.to_string(),
            message: message.into(),
        }
    }
}
