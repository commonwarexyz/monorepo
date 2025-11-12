use super::proposal_slot::{ProposalChange, ProposalSlot, ProposalStatus};
use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{
            Attributable, Context, Finalization, Finalize, Notarization, Notarize, Nullification,
            Nullify, OrderedExt, Proposal, VoteTracker, Voter,
        },
    },
    types::{Round as Rnd, View},
};
use commonware_cryptography::{Digest, PublicKey};
use std::time::{Duration, SystemTime};
use tracing::debug;

/// Tracks the leader of a round.
#[derive(Debug, Clone)]
pub struct Leader<P: PublicKey> {
    pub(crate) idx: u32,
    pub(crate) key: P,
}

/// Reasons why preparing or reserving a proposal is not allowed.
#[derive(Debug, Clone)]
pub enum ProposalError<P: PublicKey> {
    LeaderUnknown,
    NotLeader(Leader<P>),
    LocalLeader(Leader<P>),
    TimedOut,
    AlreadyBuilding(Leader<P>),
    MissingProposal,
    AlreadyVerifying,
}

/// Context describing a peer proposal that requires verification.
#[derive(Debug, Clone)]
pub struct VerifyContext<P: PublicKey, D: Digest> {
    pub leader: Leader<P>,
    pub proposal: Proposal<D>,
}

/// Metadata returned when a peer proposal is ready for verification.
#[derive(Debug, Clone)]
pub struct VerifyReady<P: PublicKey, D: Digest> {
    pub context: Context<D, P>,
    pub proposal: Proposal<D>,
}

/// Status of preparing a local proposal for the current view.
#[derive(Debug, Clone)]
pub enum ProposeStatus<P: PublicKey, D: Digest> {
    Ready(Context<D, P>),
    MissingAncestor(View),
    NotReady,
}

/// Status of preparing a peer proposal for verification.
#[derive(Debug, Clone)]
pub enum VerifyStatus<P: PublicKey, D: Digest> {
    Ready(VerifyReady<P, D>),
    NotReady,
}

/// Reasons why a proposal completion fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleError {
    TimedOut,
    NotPending,
}

/// Reasons why a peer proposal's parent cannot be validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentValidationError {
    /// Proposed parent must be strictly less than the proposal view.
    ParentNotBeforeProposal { parent: View, view: View },
    /// Proposed parent must not precede the last finalized view.
    ParentBeforeFinalized { parent: View, last_finalized: View },
    /// Current view is zero (should not happen once consensus starts).
    CurrentViewUninitialized,
    /// Parent cannot be equal to or greater than the current view.
    ParentNotBeforeCurrent { parent: View, current: View },
    /// We are missing the notarization for the claimed parent.
    MissingParentNotarization { view: View },
    /// We cannot skip a view without a nullification.
    MissingNullification { view: View },
}

/// Missing certificate data required for safely replaying proposal ancestry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MissingCertificates {
    /// Parent view referenced by the proposal.
    pub parent: View,
    /// All parent views whose notarizations we still need.
    pub notarizations: Vec<View>,
    /// All intermediate views whose nullifications we still need.
    pub nullifications: Vec<View>,
}

impl MissingCertificates {
    /// Returns `true` when no certificates are missing.
    pub fn is_empty(&self) -> bool {
        self.notarizations.is_empty() && self.nullifications.is_empty()
    }
}

/// Per-view state machine shared between actors and tests.
pub struct Round<S: Scheme, D: Digest> {
    start: SystemTime,
    scheme: S,
    round: Rnd,
    leader: Option<Leader<S::PublicKey>>,
    proposal: ProposalSlot<D>,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,
    votes: VoteTracker<S, D>,
    notarization: Option<Notarization<S, D>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,
    nullification: Option<Nullification<S>>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,
    finalization: Option<Finalization<S, D>>,
    broadcast_finalize: bool,
    broadcast_finalization: bool,
}

impl<S: Scheme, D: Digest> Round<S, D> {
    pub fn new(scheme: S, round: Rnd, start: SystemTime) -> Self {
        let participants = scheme.participants().len();
        Self {
            start,
            scheme,
            round,
            leader: None,
            proposal: ProposalSlot::new(),
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,
            votes: VoteTracker::new(participants),
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,
            finalization: None,
            broadcast_finalize: false,
            broadcast_finalization: false,
        }
    }

    // TODO: remove
    #[cfg(test)]
    pub fn force_leader(&mut self, leader: Leader<S::PublicKey>) {
        self.leader = Some(leader);
    }

    pub fn can_begin_propose(&self) -> Result<Leader<S::PublicKey>, ProposalError<S::PublicKey>> {
        let leader = self.leader.clone().ok_or(ProposalError::LeaderUnknown)?;
        if !self.is_local_signer(leader.idx) {
            return Err(ProposalError::NotLeader(leader));
        }
        if self.broadcast_nullify {
            return Err(ProposalError::TimedOut);
        }
        if !self.proposal.should_build() {
            return Err(ProposalError::AlreadyBuilding(leader));
        }
        Ok(leader)
    }

    pub fn reserve_local_proposal(&mut self) {
        self.proposal.set_building();
    }

    pub fn mark_parent_missing(&mut self, parent: View) -> bool {
        self.proposal.mark_parent_missing(parent)
    }

    pub fn clear_parent_missing(&mut self) {
        self.proposal.clear_parent_missing();
    }

    pub fn verify_metadata(
        &self,
    ) -> Result<VerifyContext<S::PublicKey, D>, ProposalError<S::PublicKey>> {
        let leader = self.leader.clone().ok_or(ProposalError::LeaderUnknown)?;
        if self.is_local_signer(leader.idx) {
            return Err(ProposalError::LocalLeader(leader));
        }
        if self.broadcast_nullify {
            return Err(ProposalError::TimedOut);
        }
        let proposal = self
            .proposal
            .proposal()
            .cloned()
            .ok_or(ProposalError::MissingProposal)?;
        Ok(VerifyContext { leader, proposal })
    }

    pub fn reserve_verify(&mut self) -> Result<(), ProposalError<S::PublicKey>> {
        if !self.proposal.request_verify() {
            return Err(ProposalError::AlreadyVerifying);
        }
        Ok(())
    }

    pub fn leader(&self) -> Option<Leader<S::PublicKey>> {
        self.leader.clone()
    }

    pub fn is_local_signer(&self, signer: u32) -> bool {
        self.scheme.me().is_some_and(|me| me == signer)
    }

    pub fn clear_votes(&mut self) {
        self.votes.clear_notarizes();
        self.votes.clear_finalizes();
    }

    /// Drops all votes accumulated so far and returns the leader key when we
    /// discover that the leader equivocated.
    ///
    /// When multiple conflicting proposals slip into the same round we cannot
    /// safely keep any partial certificates that were built on top of the old
    /// payload. Clearing the vote trackers forces the round to rebuild honest
    /// quorums from scratch, while bubbling the equivocator's public key up so
    /// higher layers can quarantine or slash them.
    pub fn record_equivocation_and_clear(&mut self) -> Option<S::PublicKey> {
        self.clear_votes();
        self.leader().map(|leader| leader.key)
    }

    pub fn clear_deadlines(&mut self) {
        self.leader_deadline = None;
        self.advance_deadline = None;
    }

    pub fn set_leader(&mut self, seed: Option<S::Seed>) {
        let (leader, leader_idx) = crate::simplex::select_leader::<S, _>(
            self.scheme.participants().as_ref(),
            self.round,
            seed,
        );
        debug!(round=?self.round, ?leader, ?leader_idx, "leader elected");
        self.leader = Some(Leader {
            idx: leader_idx,
            key: leader,
        });
    }

    pub fn notarization(&self) -> Option<&Notarization<S, D>> {
        self.notarization.as_ref()
    }

    pub fn nullification(&self) -> Option<&Nullification<S>> {
        self.nullification.as_ref()
    }

    pub fn len_nullifies(&self) -> usize {
        self.votes.len_nullifies()
    }

    pub fn len_notarizes(&self) -> usize {
        self.votes.len_notarizes()
    }

    pub fn finalization(&self) -> Option<&Finalization<S, D>> {
        self.finalization.as_ref()
    }

    pub fn len_finalizes(&self) -> usize {
        self.votes.len_finalizes()
    }

    pub fn elapsed_since_start(&self, now: SystemTime) -> Option<Duration> {
        now.duration_since(self.start).ok()
    }

    #[cfg(test)]
    pub fn record_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
        self.proposal.record_proposal(replay, proposal);
    }

    /// Completes the local proposal flow after the automaton returns a payload.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> Result<(), HandleError> {
        if self.broadcast_nullify {
            return Err(HandleError::TimedOut);
        }
        self.proposal.record_proposal(false, proposal);
        self.leader_deadline = None;
        Ok(())
    }

    /// Completes peer proposal verification after the automaton returns.
    pub fn verified(&mut self) -> Result<(), HandleError> {
        if self.broadcast_nullify {
            return Err(HandleError::TimedOut);
        }
        if !self.proposal.mark_verified() {
            return Err(HandleError::NotPending);
        }
        self.leader_deadline = None;
        Ok(())
    }

    pub fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
    }

    pub fn mark_nullify_broadcast(&mut self) -> bool {
        let previous = self.broadcast_nullify;
        self.broadcast_nullify = true;
        previous
    }

    #[cfg(test)]
    pub fn has_broadcast_nullify_vote(&self) -> bool {
        self.broadcast_nullify
    }

    pub fn has_broadcast_notarization(&self) -> bool {
        self.broadcast_notarization
    }

    pub fn mark_notarization_broadcast(&mut self) {
        self.broadcast_notarization = true;
    }

    pub fn has_broadcast_nullification(&self) -> bool {
        self.broadcast_nullification
    }

    pub fn mark_nullification_broadcast(&mut self) {
        self.broadcast_nullification = true;
    }

    pub fn mark_finalize_broadcast(&mut self) {
        self.broadcast_finalize = true;
    }

    #[cfg(test)]
    pub fn has_broadcast_finalize_vote(&self) -> bool {
        self.broadcast_finalize
    }

    pub fn has_broadcast_finalization(&self) -> bool {
        self.broadcast_finalization
    }

    pub fn mark_finalization_broadcast(&mut self) {
        self.broadcast_finalization = true;
    }

    pub fn mark_notarize_broadcast(&mut self) {
        self.broadcast_notarize = true;
    }

    #[cfg(test)]
    pub fn has_broadcast_notarize(&self) -> bool {
        self.broadcast_notarize
    }

    pub fn set_deadlines(&mut self, leader_deadline: SystemTime, advance_deadline: SystemTime) {
        self.leader_deadline = Some(leader_deadline);
        self.advance_deadline = Some(advance_deadline);
    }

    pub fn set_leader_deadline(&mut self, deadline: Option<SystemTime>) {
        self.leader_deadline = deadline;
    }

    pub fn set_nullify_retry(&mut self, when: Option<SystemTime>) {
        self.nullify_retry = when;
    }

    pub fn handle_timeout(&mut self) -> bool {
        let was_retry = self.mark_nullify_broadcast();
        self.clear_deadlines();
        self.set_nullify_retry(None);
        was_retry
    }

    pub fn next_timeout_deadline(&mut self, now: SystemTime, retry: Duration) -> SystemTime {
        if let Some(deadline) = self.leader_deadline {
            return deadline;
        }
        if let Some(deadline) = self.advance_deadline {
            return deadline;
        }
        if let Some(deadline) = self.nullify_retry {
            return deadline;
        }
        let next = now + retry;
        self.nullify_retry = Some(next);
        next
    }

    pub fn add_recovered_proposal(&mut self, proposal: Proposal<D>) -> Option<S::PublicKey> {
        match self.proposal.update(&proposal, true) {
            ProposalChange::New => {
                debug!(?proposal, "setting verified proposal from certificate");
                None
            }
            ProposalChange::Unchanged => None,
            ProposalChange::Replaced { previous, new } => {
                // Receiving a certificate for a conflicting proposal means the
                // leader signed two different payloads for the same (epoch,
                // view). We immediately flag equivocators, wipe any local vote
                // accumulation, and rely on the caller to broadcast evidence.
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "certificate conflicts with proposal (equivocation detected)"
                );
                equivocator
            }
            ProposalChange::Skipped => None,
        }
    }

    pub fn add_verified_notarize(&mut self, notarize: Notarize<S, D>) -> Option<S::PublicKey> {
        // ProposalSlot::update deduplicates notarize messages and detects when
        // a leader sends us a second, conflicting proposal before we insert the
        // vote. That way we never allow mixed notarize sets that would mask the
        // equivocation.
        match self.proposal.update(&notarize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { previous, new } => {
                // Once we detect equivocation we clear all votes and return the
                // leader key so the caller can surface slashable evidence.
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "notarize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.votes.insert_notarize(notarize);
        None
    }

    pub fn add_verified_nullify(&mut self, nullify: Nullify<S>) {
        self.votes.insert_nullify(nullify);
    }

    pub fn add_verified_finalize(&mut self, finalize: Finalize<S, D>) -> Option<S::PublicKey> {
        // Finalize votes must refer to the same proposal we accepted for
        // notarization. Replaying ProposalSlot::update here gives us the same
        // equivocation detection guarantees as notarize handling above.
        match self.proposal.update(&finalize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { previous, new } => {
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?new,
                    ?previous,
                    "finalize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.votes.insert_finalize(finalize);
        None
    }

    pub fn add_verified_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        if self.notarization.is_some() {
            return (false, None);
        }
        self.clear_deadlines();
        // Certificates we recover from storage may carry a proposal that
        // conflicts with the one we tentatively built from individual votes.
        // `add_recovered_proposal` reruns the equivocation check and returns
        // the leader key if the certificate proves double-signing.
        let equivocator = self.add_recovered_proposal(notarization.proposal.clone());
        self.notarization = Some(notarization);
        (true, equivocator)
    }

    pub fn add_verified_nullification(&mut self, nullification: Nullification<S>) -> bool {
        if self.nullification.is_some() {
            return false;
        }
        self.clear_deadlines();
        self.nullification = Some(nullification);
        true
    }

    pub fn add_verified_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        if self.finalization.is_some() {
            return (false, None);
        }
        self.clear_deadlines();

        // Finalization certificates carry the same proposal as the notarization
        // they extend. If they differ, the leader equivocated and we must raise
        // the accusation upstream.
        let equivocator = self.add_recovered_proposal(finalization.proposal.clone());
        self.finalization = Some(finalization);
        (true, equivocator)
    }

    pub fn notarizable(&mut self, force: bool) -> Option<Notarization<S, D>> {
        if !force && (self.broadcast_notarization || self.broadcast_nullification) {
            return None;
        }
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_notarizes() < quorum {
            return None;
        }
        let notarization = Notarization::from_notarizes(&self.scheme, self.votes.iter_notarizes())
            .expect("failed to recover notarization certificate");
        self.broadcast_notarization = true;
        Some(notarization)
    }

    pub fn nullifiable(&mut self, force: bool) -> Option<Nullification<S>> {
        if !force && (self.broadcast_nullification || self.broadcast_notarization) {
            return None;
        }
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_nullifies() < quorum {
            return None;
        }
        let nullification =
            Nullification::from_nullifies(&self.scheme, self.votes.iter_nullifies())
                .expect("failed to recover nullification certificate");
        self.broadcast_nullification = true;
        Some(nullification)
    }

    pub fn finalizable(&mut self, force: bool) -> Option<Finalization<S, D>> {
        if !force && self.broadcast_finalization {
            return None;
        }
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_finalizes() < quorum {
            return None;
        }
        if let Some(notarization) = &self.notarization {
            let proposal = self.proposal.proposal().expect("proposal missing");
            assert_eq!(
                notarization.proposal, *proposal,
                "finalization proposal does not match notarization"
            );
        }
        let finalization = Finalization::from_finalizes(&self.scheme, self.votes.iter_finalizes())
            .expect("failed to recover finalization certificate");
        self.broadcast_finalization = true;
        Some(finalization)
    }

    pub fn proposal_ancestry_supported(&self) -> bool {
        if self.proposal.proposal().is_none() {
            return false;
        }
        if self.finalization.is_some() || self.notarization.is_some() {
            return true;
        }
        let max_faults = self.scheme.participants().max_faults() as usize;
        self.votes.len_notarizes() > max_faults
    }

    pub fn notarize_candidate(&mut self) -> Option<&Proposal<D>> {
        if self.broadcast_notarize || self.broadcast_nullify {
            return None;
        }
        if self.proposal.status() != ProposalStatus::Verified {
            return None;
        }
        self.broadcast_notarize = true;
        self.proposal.proposal()
    }

    pub fn finalize_candidate(&mut self) -> Option<&Proposal<D>> {
        if self.broadcast_finalize || self.broadcast_nullify {
            return None;
        }
        if !self.broadcast_notarize || !self.broadcast_notarization {
            return None;
        }
        if self.proposal.status() != ProposalStatus::Verified {
            return None;
        }
        self.broadcast_finalize = true;
        self.proposal.proposal()
    }

    pub fn replay(&mut self, message: &Voter<S, D>) {
        match message {
            Voter::Notarize(notarize) => {
                if self.is_local_signer(notarize.signer()) {
                    self.proposal
                        .record_proposal(true, notarize.proposal.clone());
                    self.mark_notarize_broadcast();
                }
            }
            Voter::Notarization(_) => {
                self.mark_notarization_broadcast();
            }
            Voter::Nullify(nullify) => {
                if self.is_local_signer(nullify.signer()) {
                    self.mark_nullify_broadcast();
                }
            }
            Voter::Nullification(_) => {
                self.mark_nullification_broadcast();
            }
            Voter::Finalize(finalize) => {
                if self.is_local_signer(finalize.signer()) {
                    self.mark_finalize_broadcast();
                }
            }
            Voter::Finalization(_) => {
                self.mark_finalization_broadcast();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        mocks::fixtures::{ed25519, Fixture},
        types::{Finalization, Finalize, Notarization, Notarize, Proposal},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn equivocation_detected_on_notarize_notarization_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"ns";
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519(&mut rng, 4);
        let proposal_a = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([1u8; 32]),
        };
        let proposal_b = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([2u8; 32]),
        };
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(
            leader_scheme.clone(),
            proposal_a.round,
            SystemTime::UNIX_EPOCH,
        );

        // Add verified notarize for some proposal
        let vote_a = Notarize::sign(&leader_scheme, namespace, proposal_a.clone()).unwrap();
        round.set_leader(None);
        assert!(round.add_verified_notarize(vote_a).is_none());

        // Add conflicting notarization
        let notarization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Notarize::sign(scheme, namespace, proposal_b.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter()).unwrap();
        let (accepted, equivocator) = round.add_verified_notarization(certificate);
        assert!(accepted);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.unwrap(), participants[2]);

        // Conflict clears votes
        assert_eq!(round.votes.len_notarizes(), 0);

        // Skip new attempts
        assert!(round.notarize_candidate().is_none());
        assert!(round.finalize_candidate().is_none());

        // Ignore new votes
        let vote = Notarize::sign(&schemes[1], namespace, proposal_a.clone()).unwrap();
        assert!(round.add_verified_notarize(vote).is_none());
        assert_eq!(round.votes.len_notarizes(), 0);
    }

    #[test]
    fn equivocation_detected_on_finalize_notarization_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"ns";
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519(&mut rng, 4);
        let proposal_a = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([1u8; 32]),
        };
        let proposal_b = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([2u8; 32]),
        };
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(
            leader_scheme.clone(),
            proposal_a.round,
            SystemTime::UNIX_EPOCH,
        );

        // Add verified finalize for some proposal
        let vote_a = Finalize::sign(&leader_scheme, namespace, proposal_a.clone()).unwrap();
        round.set_leader(None);
        assert!(round.add_verified_finalize(vote_a).is_none());

        // Add conflicting notarization
        let notarization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Notarize::sign(scheme, namespace, proposal_b.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter()).unwrap();
        let (accepted, equivocator) = round.add_verified_notarization(certificate);
        assert!(accepted);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.unwrap(), participants[2]);

        // Conflict clears votes
        assert_eq!(round.votes.len_finalizes(), 0);

        // Skip new attempts
        assert!(round.notarize_candidate().is_none());
        assert!(round.finalize_candidate().is_none());

        // Ignore new votes
        let vote = Finalize::sign(&schemes[1], namespace, proposal_a.clone()).unwrap();
        assert!(round.add_verified_finalize(vote).is_none());
        assert_eq!(round.votes.len_finalizes(), 0);
    }

    #[test]
    fn equivocation_detected_on_notarize_finalization_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"ns";
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519(&mut rng, 4);
        let proposal_a = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([1u8; 32]),
        };
        let proposal_b = Proposal {
            round: Rnd::new(1, 1),
            parent: 0,
            payload: Sha256Digest::from([2u8; 32]),
        };
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(
            leader_scheme.clone(),
            proposal_a.round,
            SystemTime::UNIX_EPOCH,
        );

        // Add verified notarize for some proposal
        let vote_a = Notarize::sign(&leader_scheme, namespace, proposal_a.clone()).unwrap();
        round.set_leader(None);
        assert!(round.add_verified_notarize(vote_a).is_none());

        // Add conflicting finalization
        let finalization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Finalize::sign(scheme, namespace, proposal_b.clone()).unwrap())
            .collect();
        let certificate =
            Finalization::from_finalizes(&verifier, finalization_votes.iter()).unwrap();
        let (accepted, equivocator) = round.add_verified_finalization(certificate);
        assert!(accepted);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.unwrap(), participants[2]);

        // Conflict clears votes
        assert_eq!(round.votes.len_notarizes(), 0);

        // Skip new attempts
        assert!(round.notarize_candidate().is_none());
        assert!(round.finalize_candidate().is_none());

        // Ignore new votes
        let vote = Notarize::sign(&schemes[1], namespace, proposal_a.clone()).unwrap();
        assert!(round.add_verified_notarize(vote).is_none());
        assert_eq!(round.votes.len_notarizes(), 0);
    }
}
