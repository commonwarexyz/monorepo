use crate::types::Epoch;
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{EncodeLabelSet, EncodeLabelValue, EncodeStruct, Registered, raw},
};
use commonware_utils::{Array, ordered::Profile};
use std::sync::atomic::AtomicU64;

/// A gauge that holds a committee weight.
type WeightGauge = Registered<raw::Gauge<u64, AtomicU64>>;

/// Committee profile metrics retained by the engine.
pub(crate) struct CommitteeProfile {
    _total_weight: WeightGauge,
    _max_fault_weight: WeightGauge,
    _quorum_weight: WeightGauge,
    _max_participant_weight: WeightGauge,
    _minimum_quorum_cardinality: WeightGauge,
}

impl CommitteeProfile {
    /// Registers metrics for an epoch's committee profile.
    pub(crate) fn init(context: &impl RuntimeMetrics, epoch: Epoch, profile: Profile) -> Self {
        let context = context.child("committee").with_attribute("epoch", epoch);
        let register = |name, help, value: u64| {
            let gauge = raw::Gauge::<u64, AtomicU64>::default();
            gauge.set(value);
            context.register(name, help, gauge)
        };
        Self {
            _total_weight: register(
                "total_weight",
                "Total weight of the committee",
                profile.total_weight,
            ),
            _max_fault_weight: register(
                "max_fault_weight",
                "Maximum faulty weight tolerated by the committee",
                profile.max_fault_weight,
            ),
            _quorum_weight: register(
                "quorum_weight",
                "Weight required for a committee quorum",
                profile.quorum_weight,
            ),
            _max_participant_weight: register(
                "max_participant_weight",
                "Maximum weight of one committee participant",
                profile.max_weight,
            ),
            _minimum_quorum_cardinality: register(
                "minimum_quorum_cardinality",
                "Minimum number of participants required to reach committee quorum",
                profile.minimum_quorum_cardinality.into(),
            ),
        }
    }
}

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Peer<P: PublicKey> {
    pub peer: P,
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

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{Runner as _, deterministic};

    #[test]
    fn committee_profile_preserves_u64_values() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let total_weight = i64::MAX as u64 + 5;
            let profile = Profile {
                total_weight,
                max_fault_weight: 3,
                quorum_weight: total_weight - 3,
                max_weight: total_weight - 4,
                minimum_quorum_cardinality: 2,
            };
            let _metrics = CommitteeProfile::init(&context, Epoch::new(7), profile);
            let encoded = context.encode();

            for (name, value) in [
                ("committee_total_weight", total_weight),
                ("committee_max_fault_weight", 3),
                ("committee_quorum_weight", total_weight - 3),
                ("committee_max_participant_weight", total_weight - 4),
                ("committee_minimum_quorum_cardinality", 2),
            ] {
                let expected = format!("{name}{{epoch=\"7\"}} {value}");
                assert!(
                    encoded.lines().any(|line| line == expected),
                    "missing {name}={value} in:\n{encoded}"
                );
            }
        });
    }

    #[test]
    fn committee_profiles_are_scoped_by_epoch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let profile = |total_weight| Profile {
                total_weight,
                max_fault_weight: 1,
                quorum_weight: total_weight - 1,
                max_weight: total_weight - 2,
                minimum_quorum_cardinality: 2,
            };
            let _first = CommitteeProfile::init(&context, Epoch::new(1), profile(10));
            let _second = CommitteeProfile::init(&context, Epoch::new(2), profile(20));
            let encoded = context.encode();

            assert!(encoded.contains("committee_total_weight{epoch=\"1\"} 10"));
            assert!(encoded.contains("committee_total_weight{epoch=\"2\"} 20"));
        });
    }
}
