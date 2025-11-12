use crate::{simplex::types::Proposal, types::View};
use commonware_cryptography::Digest;
use tracing::debug;

/// Proposal verification status within a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProposalStatus {
    #[default]
    None,
    Unverified,
    Verified,
    Replaced,
}

/// Describes how a proposal slot changed after an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalChange<D>
where
    D: Digest,
{
    New,
    Unchanged,
    Replaced {
        previous: Proposal<D>,
        new: Proposal<D>,
    },
    Skipped,
}

/// Tracks proposal state, build/verify flags, and conflicts.
///
/// The voter actor drives this slot along two distinct paths:
/// - [`State::try_propose`] ➜ [`State::proposed`] for locally generated payloads inside
///   [`Actor::try_propose`](crate::simplex::actors::voter::Actor::try_propose) and
///   [`Actor::proposed`](crate::simplex::actors::voter::Actor::proposed).
/// - [`State::try_verify`] ➜ [`State::verified`] for peer payloads inside
///   [`Actor::try_verify`](crate::simplex::actors::voter::Actor::try_verify) and
///   [`Actor::verified`](crate::simplex::actors::voter::Actor::verified).
///
/// Keeping these flows centralized in the round state lets tests and recovery logic manipulate
/// proposals without needing to instantiate the async actor.
#[derive(Default)]
pub struct ProposalSlot<D>
where
    D: Digest,
{
    proposal: Option<Proposal<D>>,
    status: ProposalStatus,
    requested_build: bool,
    requested_verify: bool,
    awaiting_parent: Option<View>,
}

impl<D> ProposalSlot<D>
where
    D: Digest + Clone + PartialEq,
{
    pub fn new() -> Self {
        Self {
            proposal: None,
            status: ProposalStatus::None,
            requested_build: false,
            requested_verify: false,
            awaiting_parent: None,
        }
    }

    pub fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.as_ref()
    }

    pub fn status(&self) -> ProposalStatus {
        self.status
    }

    pub fn should_build(&self) -> bool {
        !self.requested_build && self.proposal.is_none()
    }

    pub fn set_building(&mut self) {
        self.requested_build = true;
        self.awaiting_parent = None;
    }

    pub fn request_verify(&mut self) -> bool {
        if self.requested_verify {
            return false;
        }
        self.requested_verify = true;
        true
    }

    /// Marks the slot as waiting on parent certificates.
    ///
    /// Returns `true` the first time it is invoked so callers can distinguish
    /// between a freshly-discovered gap (which should trigger a resolver fetch)
    /// and repeated checks we expect to run while we wait for the data.
    pub fn mark_parent_missing(&mut self, parent: View) -> bool {
        match self.awaiting_parent {
            Some(missing) if missing == parent => false,
            None | Some(_) => {
                self.awaiting_parent = Some(parent);
                true
            }
        }
    }

    pub fn clear_parent_missing(&mut self) {
        self.awaiting_parent = None;
    }

    pub fn record_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
        if let Some(existing) = &self.proposal {
            if !replay {
                debug!(
                    ?existing,
                    ?proposal,
                    "ignoring local proposal because slot already populated"
                );
                return;
            }
        }
        self.proposal = Some(proposal);
        self.status = ProposalStatus::Verified;
        self.requested_build = true;
        self.requested_verify = true;
    }

    pub fn mark_verified(&mut self) -> bool {
        if self.status != ProposalStatus::Unverified {
            return false;
        }
        self.status = ProposalStatus::Verified;
        true
    }

    pub fn update(&mut self, proposal: &Proposal<D>, recovered: bool) -> ProposalChange<D> {
        // Once we mark the slot as replaced we refuse to record any additional
        // votes, even if they target the original payload. Unless there is
        // a safety failure, we won't be able to use them for anything so we might
        // as well ignore them.
        if self.status == ProposalStatus::Replaced {
            return ProposalChange::Skipped;
        }
        match &self.proposal {
            None => {
                self.proposal = Some(proposal.clone());
                self.status = if recovered {
                    ProposalStatus::Verified
                } else {
                    ProposalStatus::Unverified
                };
                ProposalChange::New
            }
            Some(existing) if existing == proposal => {
                if recovered {
                    self.status = ProposalStatus::Verified;
                }
                ProposalChange::Unchanged
            }
            Some(existing) => {
                self.status = ProposalStatus::Replaced;
                ProposalChange::Replaced {
                    previous: existing.clone(),
                    new: proposal.clone(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{simplex::types::Proposal, types::Round as Rnd};
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    #[test]
    fn proposal_slot_request_build_behavior() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        assert!(slot.should_build());
        assert!(slot.should_build());
        slot.set_building();
        assert!(!slot.should_build());

        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(7, 3);
        let proposal = Proposal::new(round, 2, Sha256Digest::from([1u8; 32]));
        slot.record_proposal(false, proposal);
        assert!(!slot.should_build());
    }

    #[test]
    fn proposal_slot_records_proposal_with_flags() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        assert!(slot.proposal().is_none());

        let round = Rnd::new(9, 1);
        let proposal = Proposal::new(round, 0, Sha256Digest::from([2u8; 32]));
        slot.record_proposal(false, proposal.clone());

        match slot.proposal() {
            Some(stored) => assert_eq!(stored, &proposal),
            None => panic!("proposal missing after recording"),
        }
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert!(!slot.should_build());
        assert!(!slot.request_verify());
    }

    #[test]
    fn proposal_slot_records_and_prevents_duplicate_build() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(1, 2);
        let proposal = Proposal::new(round, 1, Sha256Digest::from([10u8; 32]));

        slot.record_proposal(false, proposal.clone());

        assert_eq!(slot.proposal(), Some(&proposal));
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert!(!slot.should_build());
        assert!(!slot.request_verify());
    }

    #[test]
    fn proposal_slot_replay_allows_existing_proposal() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(17, 6);
        let proposal = Proposal::new(round, 5, Sha256Digest::from([11u8; 32]));

        slot.record_proposal(false, proposal.clone());
        slot.record_proposal(true, proposal.clone());

        assert!(!slot.should_build());
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert_eq!(slot.proposal(), Some(&proposal));
    }

    #[test]
    fn proposal_slot_update_preserves_status_when_equal() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(13, 2);
        let proposal = Proposal::new(round, 1, Sha256Digest::from([12u8; 32]));

        assert!(matches!(slot.update(&proposal, false), ProposalChange::New));
        assert!(matches!(
            slot.update(&proposal, true),
            ProposalChange::Unchanged
        ));
        assert_eq!(slot.status(), ProposalStatus::Verified);
    }

    #[test]
    fn proposal_slot_certificate_then_vote_detects_replacement() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(21, 4);
        let proposal_a = Proposal::new(round, 2, Sha256Digest::from([13u8; 32]));
        let proposal_b = Proposal::new(round, 2, Sha256Digest::from([14u8; 32]));

        assert!(matches!(
            slot.update(&proposal_a, true),
            ProposalChange::New
        ));
        let result = slot.update(&proposal_b, false);
        match result {
            ProposalChange::Replaced { previous, new } => {
                assert_eq!(previous, proposal_a);
                assert_eq!(new, proposal_b);
            }
            other => panic!("unexpected change: {other:?}"),
        }
        assert_eq!(slot.status(), ProposalStatus::Replaced);
        assert_eq!(slot.proposal(), Some(&proposal_a));
    }

    #[test]
    fn proposal_slot_certificate_during_pending_propose_detects_equivocation() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(25, 8);
        let compromised = Proposal::new(round, 2, Sha256Digest::from([42u8; 32]));
        let honest = Proposal::new(round, 2, Sha256Digest::from([15u8; 32]));

        assert!(slot.should_build());
        slot.set_building();
        assert!(!slot.should_build());

        // Compromised node produces a certificate before our local propose returns.
        assert!(matches!(
            slot.update(&compromised, true),
            ProposalChange::New
        ));
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert_eq!(slot.proposal(), Some(&compromised));

        // Once we finally finish proposing our honest payload, the slot should just
        // ignore it (the equivocation was already detected when the certificate
        // arrived).
        slot.record_proposal(false, honest.clone());
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert_eq!(slot.proposal(), Some(&compromised));
    }

    #[test]
    fn proposal_slot_certificate_during_pending_verify_detects_equivocation() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(26, 9);
        let leader_proposal = Proposal::new(round, 4, Sha256Digest::from([16u8; 32]));
        let conflicting = Proposal::new(round, 4, Sha256Digest::from([99u8; 32]));

        assert!(matches!(
            slot.update(&leader_proposal, false),
            ProposalChange::New
        ));
        assert_eq!(slot.status(), ProposalStatus::Unverified);
        assert!(slot.request_verify());
        assert!(!slot.request_verify());

        let change = slot.update(&conflicting, true);
        match change {
            ProposalChange::Replaced { previous, new } => {
                assert_eq!(previous, leader_proposal);
                assert_eq!(new, conflicting);
            }
            other => panic!("expected replacement, got {other:?}"),
        }
        assert_eq!(slot.status(), ProposalStatus::Replaced);
        // Verifier completion arriving afterwards must be ignored.
        assert!(!slot.mark_verified());
        assert!(matches!(
            slot.update(&conflicting, true),
            ProposalChange::Skipped
        ));
    }

    #[test]
    fn proposal_slot_certificates_override_votes() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(21, 4);
        let proposal_a = Proposal::new(round, 2, Sha256Digest::from([15u8; 32]));
        let proposal_b = Proposal::new(round, 2, Sha256Digest::from([16u8; 32]));

        assert!(matches!(
            slot.update(&proposal_a, false),
            ProposalChange::New
        ));
        match slot.update(&proposal_b, true) {
            ProposalChange::Replaced { previous, new } => {
                assert_eq!(previous, proposal_a);
                assert_eq!(new, proposal_b);
            }
            other => panic!("certificate should override votes, got {other:?}"),
        }
        assert_eq!(slot.status(), ProposalStatus::Replaced);
        assert_eq!(slot.proposal(), Some(&proposal_a));
    }

    #[test]
    fn proposal_slot_certificate_does_not_clear_replaced() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(25, 7);
        let proposal_a = Proposal::new(round, 3, Sha256Digest::from([17u8; 32]));
        let proposal_b = Proposal::new(round, 3, Sha256Digest::from([18u8; 32]));

        assert!(matches!(
            slot.update(&proposal_a, false),
            ProposalChange::New
        ));
        assert!(matches!(
            slot.update(&proposal_b, true),
            ProposalChange::Replaced { .. }
        ));
        assert!(matches!(
            slot.update(&proposal_b, true),
            ProposalChange::Skipped
        ));
        assert_eq!(slot.status(), ProposalStatus::Replaced);
    }
}
