//! Per-view consensus logic for Minimmit.

use crate::minimmit::{
    scheme::Scheme,
    types::{Certificate, Notarize, Proposal},
};
use commonware_cryptography::Digest;
use std::collections::BTreeSet;

/// Phase within a view to prevent invalid transitions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Phase<D: Digest> {
    /// Haven't voted or nullified yet.
    #[default]
    Idle,
    /// Voted for this proposal digest (cannot vote again).
    Voted { digest: D },
    /// Sent a nullify vote (cannot vote in this view).
    Nullified,
}

/// Per-view state machine.
#[derive(Debug)]
pub struct ViewState<D: Digest> {
    phase: Phase<D>,
    proposals: BTreeSet<Proposal<D>>,
    verified: BTreeSet<Proposal<D>>,
    broadcast_m_notarizations: BTreeSet<Proposal<D>>,
    propose_sent: bool,
    broadcast_notarize: bool,
    broadcast_nullify: bool,
    broadcast_nullification: bool,
}

impl<D: Digest> Default for ViewState<D> {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            proposals: BTreeSet::new(),
            verified: BTreeSet::new(),
            broadcast_m_notarizations: BTreeSet::new(),
            propose_sent: false,
            broadcast_notarize: false,
            broadcast_nullify: false,
            broadcast_nullification: false,
        }
    }
}

impl<D: Digest> ViewState<D> {
    /// Returns the current phase.
    pub const fn phase(&self) -> &Phase<D> {
        &self.phase
    }

    /// Returns true if the proposal is verified.
    pub fn is_verified(&self, proposal: &Proposal<D>) -> bool {
        self.verified.contains(proposal)
    }

    /// Returns true if we already sent a proposal in this view.
    pub const fn propose_sent(&self) -> bool {
        self.propose_sent
    }

    /// Marks that we sent a proposal in this view.
    pub const fn mark_propose_sent(&mut self) -> bool {
        if self.propose_sent {
            return false;
        }
        self.propose_sent = true;
        true
    }

    /// Returns true if we can vote in this view.
    pub const fn can_vote(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }

    /// Returns true if a timeout nullify is allowed.
    pub const fn can_nullify_timeout(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }

    /// Returns true if condition (b) nullify is allowed.
    pub const fn can_nullify_condition_b(&self) -> bool {
        matches!(self.phase, Phase::Voted { .. })
    }

    /// Records a proposal for this view.
    pub fn set_proposal(&mut self, proposal: Proposal<D>) -> bool {
        self.proposals.insert(proposal)
    }

    /// Marks the proposal as verified.
    pub fn mark_verified(&mut self, proposal: &Proposal<D>) -> bool {
        if !self.proposals.contains(proposal) {
            return false;
        }
        self.verified.insert(proposal.clone())
    }

    /// Returns proposals that have not been verified yet.
    pub fn unverified_proposals(&self) -> impl Iterator<Item = &Proposal<D>> {
        self.proposals
            .iter()
            .filter(|proposal| !self.verified.contains(*proposal))
    }

    /// Records that we voted for a proposal digest.
    pub const fn vote(&mut self, digest: D) -> bool {
        if !self.can_vote() {
            return false;
        }
        self.phase = Phase::Voted { digest };
        true
    }

    /// Records that we nullified the view.
    pub const fn nullify(&mut self) -> bool {
        if matches!(self.phase, Phase::Nullified) {
            return false;
        }
        self.phase = Phase::Nullified;
        true
    }

    /// Marks that we've broadcast a notarize vote.
    pub const fn mark_broadcast_notarize(&mut self) -> bool {
        if self.broadcast_notarize {
            return false;
        }
        self.broadcast_notarize = true;
        true
    }

    /// Marks that we've broadcast a nullify vote.
    pub const fn mark_broadcast_nullify(&mut self) -> bool {
        if self.broadcast_nullify {
            return false;
        }
        self.broadcast_nullify = true;
        true
    }

    /// Marks that we've broadcast an M-notarization certificate.
    ///
    /// Returns true if this M-notarization has not been broadcast for this view.
    pub fn mark_broadcast_m_notarization(&mut self, proposal: &Proposal<D>) -> bool {
        self.broadcast_m_notarizations.insert(proposal.clone())
    }

    /// Marks that we've broadcast a nullification certificate.
    pub const fn mark_broadcast_nullification(&mut self) -> bool {
        if self.broadcast_nullification {
            return false;
        }
        self.broadcast_nullification = true;
        true
    }

    /// Returns true if the notarize vote was broadcast.
    pub const fn broadcast_notarize(&self) -> bool {
        self.broadcast_notarize
    }

    /// Returns true if the nullify vote was broadcast.
    pub const fn broadcast_nullify(&self) -> bool {
        self.broadcast_nullify
    }

    /// Returns true if an M-notarization certificate was broadcast for this view.
    pub fn has_broadcast_m_notarization(&self) -> bool {
        !self.broadcast_m_notarizations.is_empty()
    }

    /// Returns true if the nullification certificate was broadcast.
    pub const fn broadcast_nullification(&self) -> bool {
        self.broadcast_nullification
    }

    /// Returns true if a certificate of the same type was already broadcast.
    ///
    /// For M-notarizations, this returns true only if the same proposal was already
    /// broadcast in this view.
    ///
    /// For Finalizations, this always returns false since Finalizations are never
    /// broadcast (per the Minimmit paper). Deduplication for Finalizations is
    /// handled by the ancestry tracker.
    pub fn has_certificate<S: Scheme<D>>(&self, certificate: &Certificate<S, D>) -> bool {
        match certificate {
            Certificate::MNotarization(m) => self.broadcast_m_notarizations.contains(&m.proposal),
            Certificate::Nullification(_) => self.broadcast_nullification,
            Certificate::Finalization(_) => false,
        }
    }

    /// Replays a notarize vote from crash recovery.
    ///
    /// Sets internal state to reflect that we already voted for this proposal,
    /// preventing double-voting and double-broadcasting after restart.
    pub fn replay_notarize<S: Scheme<D>>(&mut self, notarize: &Notarize<S, D>) {
        self.proposals.insert(notarize.proposal.clone());
        self.verified.insert(notarize.proposal.clone());
        self.phase = Phase::Voted {
            digest: notarize.proposal.payload,
        };
        self.broadcast_notarize = true;
    }

    /// Replays a nullify vote from crash recovery.
    ///
    /// Sets internal state to reflect that we already nullified this view,
    /// preventing double-nullifying and double-broadcasting after restart.
    pub const fn replay_nullify(&mut self) {
        self.phase = Phase::Nullified;
        self.broadcast_nullify = true;
    }

    /// Replays a certificate from crash recovery.
    ///
    /// Sets internal broadcast flags to prevent double-broadcasting after restart.
    /// Finalizations are not tracked here since they are never broadcast.
    pub fn replay_certificate<S: Scheme<D>>(&mut self, certificate: &Certificate<S, D>) {
        match certificate {
            Certificate::MNotarization(m) => {
                self.broadcast_m_notarizations.insert(m.proposal.clone());
            }
            Certificate::Nullification(_) => {
                self.broadcast_nullification = true;
            }
            Certificate::Finalization(_) => {
                // Finalizations are never broadcast, so no flag to set
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Epoch, Round as Rnd, View};
    use commonware_cryptography::sha256::Digest as Sha256Digest;

    #[test]
    fn phase_transitions_block_double_vote() {
        let mut state: ViewState<Sha256Digest> = ViewState::default();
        assert!(state.can_vote());
        assert!(state.vote(Sha256Digest::from([1u8; 32])));
        assert!(!state.can_vote());
        assert!(!state.vote(Sha256Digest::from([2u8; 32])));
    }

    #[test]
    fn nullify_blocks_vote() {
        let mut state: ViewState<Sha256Digest> = ViewState::default();
        assert!(state.nullify());
        assert!(!state.can_vote());
        assert!(!state.vote(Sha256Digest::from([3u8; 32])));
    }

    #[test]
    fn proposal_flow() {
        let view = View::new(3);
        let mut state: ViewState<Sha256Digest> = ViewState::default();
        let parent_payload = Sha256Digest::from([2u8; 32]);
        let proposal = Proposal::new(
            Rnd::new(Epoch::new(1), view),
            View::new(2),
            parent_payload,
            Sha256Digest::from([4u8; 32]),
        );
        assert!(state.set_proposal(proposal.clone()));
        assert!(!state.set_proposal(proposal.clone()));
        assert!(state.mark_verified(&proposal));
        assert!(!state.mark_verified(&proposal));
        assert!(state.is_verified(&proposal));
    }
}
