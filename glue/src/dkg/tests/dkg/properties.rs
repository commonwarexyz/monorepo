use super::harness::NodeState;
use crate::{
    dkg::types::EpochOutcome,
    simulate::{property::Property, tracker::ProgressTracker},
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    bls12381::{dkg::feldman_desmedt::Output, primitives::variant::MinPk},
    ed25519,
};
use commonware_utils::ordered::Set;
use std::{future::Future, pin::Pin};

#[derive(Clone, Copy)]
pub(super) enum ExpectedOutcome {
    Success,
    Failure,
}

#[derive(Clone)]
pub(super) struct DkgOutcome {
    participants: Set<ed25519::PublicKey>,
    expected: ExpectedOutcome,
}

impl DkgOutcome {
    pub(super) fn new(participants: Vec<ed25519::PublicKey>, expected: ExpectedOutcome) -> Self {
        Self {
            participants: Set::from_iter_dedup(participants),
            expected,
        }
    }
}

impl Property<ed25519::PublicKey, NodeState> for DkgOutcome {
    fn name(&self) -> &str {
        match self.expected {
            ExpectedOutcome::Success => "dkg_success",
            ExpectedOutcome::Failure => "dkg_failure",
        }
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a NodeState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if states.len() != self.participants.len() {
                return Err(format!(
                    "expected {} active states, got {}",
                    self.participants.len(),
                    states.len()
                ));
            }

            let mut expected: Option<Output<MinPk, ed25519::PublicKey>> = None;
            for state in states {
                if !state.completed() {
                    return Err("state did not complete".into());
                }

                let Some(info) = state.info() else {
                    if matches!(self.expected, ExpectedOutcome::Failure) {
                        if state.has_share(Epoch::zero()) {
                            return Err("failed DKG persisted epoch zero share".into());
                        }
                        continue;
                    }
                    return Err("missing DKG info".into());
                };

                if matches!(self.expected, ExpectedOutcome::Failure) {
                    return Err("failed DKG produced epoch info".into());
                }
                if info.outcome != EpochOutcome::Success {
                    return Err(format!("unexpected outcome: {:?}", info.outcome));
                }
                if info.epoch != Epoch::zero() {
                    return Err(format!("unexpected epoch: {:?}", info.epoch));
                }
                if info.round != 0 {
                    return Err(format!("unexpected round: {}", info.round));
                }
                if info.output.players() != &self.participants {
                    return Err("output players did not match participants".into());
                }
                if info.players != self.participants {
                    return Err("epoch info players did not match participants".into());
                }
                if !info.next_players.is_empty() {
                    return Err("DKG next_players should be empty".into());
                }
                if !info.output.revealed().is_empty() {
                    return Err("DKG revealed shares".into());
                }
                if let Some(expected) = &expected {
                    if &info.output != expected {
                        return Err("participants produced different outputs".into());
                    }
                } else {
                    expected = Some(info.output);
                }

                if !state.has_share(Epoch::zero()) {
                    return Err("secret store missing epoch zero share".into());
                }
            }
            Ok(())
        })
    }
}
