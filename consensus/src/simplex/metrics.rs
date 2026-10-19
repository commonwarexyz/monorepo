use commonware_cryptography::PublicKey;
use commonware_runtime::telemetry::metrics::{EncodeLabelSet, EncodeLabelValue, EncodeStruct};
use commonware_utils::Array;

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Peer<P: PublicKey> {
    pub peer: P,
}

/// Handoff lifecycle event.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum HandoffEventKind {
    Requested,
    WaitReturned,
    CandidateReturned,
    RelayedBeforeCertification,
    RelayedAfterCertification,
    VotedBeforeCertification,
    VotedAfterCertification,
}

/// Handoff event label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HandoffEvent {
    pub event: HandoffEventKind,
}

/// Reason a pending handoff was abandoned.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum HandoffAbandonedReason {
    /// The leader exited the handoff's view before its build was recorded.
    ViewExit,
    /// A replacement parent became selectable, so the build was dropped for one on it.
    AncestrySuperseded,
    /// The captured ancestry of a build on an uncertified parent became invalid.
    AncestryInvalidated,
    /// The leader voted to nullify the view it is waiting in, at or below the parent, while the
    /// parent was still uncertified.
    ParentNullify,
    /// The parent certified after the leader had voted to nullify the handoff's view.
    ViewNullify,
    /// The automaton closed the build without returning a candidate.
    ResponseClosed,
    /// The built candidate could not be recorded because its captured parent was no longer
    /// valid, the leader had voted to nullify the view, or the view already held a different
    /// proposal.
    IneligibleAtRecording,
}

/// Handoff abandonment label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct HandoffAbandoned {
    pub reason: HandoffAbandonedReason,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub enum TimeoutReason {
    Retry,
    Inactivity,
    LeaderNullify,
    LeaderTimeout,
    CertificationTimeout,
    StallTimeout,
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
            Self::Retry => "Retry",
            Self::Inactivity => "Inactivity",
            Self::LeaderNullify => "LeaderNullify",
            Self::LeaderTimeout => "LeaderTimeout",
            Self::CertificationTimeout => "CertificationTimeout",
            Self::StallTimeout => "StallTimeout",
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
