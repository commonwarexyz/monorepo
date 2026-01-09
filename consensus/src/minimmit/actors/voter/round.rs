//! Per-round state tracking for the minimmit voter actor.
//!
//! Unlike simplex, minimmit has no separate finalize phase - finalization occurs
//! at L notarize votes. Additionally, minimmit supports nullify-by-contradiction,
//! allowing validators to nullify after notarizing if they observe M conflicting votes.

use super::slot::{Change as ProposalChange, Slot as ProposalSlot, Status as ProposalStatus};
use crate::{
    minimmit::types::{Artifact, Attributable, Notarization, Nullification, Proposal, VoteTracker},
    types::Round as Rnd,
};
use commonware_cryptography::{certificate::Scheme, Digest, PublicKey};
use commonware_utils::ordered::Quorum;
use std::{
    mem::replace,
    time::{Duration, SystemTime},
};
use tracing::debug;

/// Tracks the leader of a round.
#[derive(Debug, Clone)]
pub struct Leader<P: PublicKey> {
    pub idx: u32,
    pub key: P,
}

/// Per-[Rnd] state machine for minimmit consensus.
///
/// Key differences from simplex:
/// - No finalization phase (finalization occurs at L notarize votes)
/// - Supports nullify-by-contradiction
/// - Tracks vote counts for M and L thresholds
pub struct Round<S: Scheme, D: Digest> {
    start: SystemTime,
    scheme: S,
    round: Rnd,
    participants: usize,

    // Leader is set as soon as we know the seed for the view (if any).
    leader: Option<Leader<S::PublicKey>>,

    proposal: ProposalSlot<D>,
    leader_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Vote tracking
    votes: VoteTracker<S, D>,

    // Certificates received (constructed or from network).
    notarization: Option<Notarization<S, D>>,
    broadcast_notarize: bool,
    broadcast_notarization: bool,
    nullification: Option<Nullification<S>>,
    broadcast_nullify: bool,
    broadcast_nullification: bool,

    // Minimmit-specific: track if we've sent a nullify due to contradiction
    // (we can nullify after notarizing if we see M conflicting votes)
    contradiction_nullify_sent: bool,

    // Whether finalization has been triggered for this round (at L notarizes)
    finalized: bool,
}

impl<S: Scheme, D: Digest> Round<S, D> {
    pub fn new(scheme: S, round: Rnd, start: SystemTime, participants: usize) -> Self {
        Self {
            start,
            scheme,
            round,
            participants,
            leader: None,
            proposal: ProposalSlot::new(),
            leader_deadline: None,
            nullify_retry: None,
            votes: VoteTracker::new(participants),
            notarization: None,
            broadcast_notarize: false,
            broadcast_notarization: false,
            nullification: None,
            broadcast_nullify: false,
            broadcast_nullification: false,
            contradiction_nullify_sent: false,
            finalized: false,
        }
    }

    /// Returns the round identifier.
    pub const fn round(&self) -> Rnd {
        self.round
    }

    /// Returns whether this round has been finalized.
    pub const fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Marks this round as finalized.
    pub const fn set_finalized(&mut self) {
        self.finalized = true;
    }

    /// Returns the vote tracker for this round.
    pub const fn votes(&self) -> &VoteTracker<S, D> {
        &self.votes
    }

    /// Returns a mutable reference to the vote tracker.
    pub fn votes_mut(&mut self) -> &mut VoteTracker<S, D> {
        &mut self.votes
    }

    /// Returns the leader info if we should propose.
    fn propose_ready(&self) -> Option<Leader<S::PublicKey>> {
        let leader = self.leader.as_ref()?;
        if !self.is_signer(leader.idx) || self.broadcast_nullify || !self.proposal.should_build() {
            return None;
        }
        Some(leader.clone())
    }

    /// Returns true if we should propose.
    pub fn should_propose(&self) -> bool {
        self.propose_ready().is_some()
    }

    /// Returns the leader info when we should start building a proposal locally.
    pub fn try_propose(&mut self) -> Option<Leader<S::PublicKey>> {
        let leader = self.propose_ready()?;
        self.proposal.set_building();
        Some(leader)
    }

    /// Returns the leader info if we should verify a proposal.
    fn verify_ready(&self) -> Option<&Leader<S::PublicKey>> {
        let leader = self.leader.as_ref()?;
        if self.is_signer(leader.idx) || self.broadcast_nullify {
            return None;
        }
        Some(leader)
    }

    /// Returns the leader key and proposal when the view is ready for verification.
    #[allow(clippy::type_complexity)]
    pub fn should_verify(&self) -> Option<(Leader<S::PublicKey>, Proposal<D>)> {
        let leader = self.verify_ready()?;
        let proposal = self.proposal.proposal().cloned()?;
        Some((leader.clone(), proposal))
    }

    /// Marks that verification is in-flight; returns `false` to avoid duplicate requests.
    pub fn try_verify(&mut self) -> bool {
        if self.verify_ready().is_none() {
            return false;
        }
        self.proposal.request_verify()
    }

    /// Returns the elected leader (if any) for this round.
    pub fn leader(&self) -> Option<Leader<S::PublicKey>> {
        self.leader.clone()
    }

    /// Returns true when the local participant controls `signer`.
    pub fn is_signer(&self, signer: u32) -> bool {
        self.scheme.me().is_some_and(|me| me == signer)
    }

    /// Removes the leader deadline so timeouts stop firing.
    pub const fn clear_deadlines(&mut self) {
        self.leader_deadline = None;
    }

    /// Sets the leader for this round using the pre-computed leader index.
    pub fn set_leader(&mut self, leader: u32) {
        let key = self
            .scheme
            .participants()
            .key(leader)
            .cloned()
            .expect("leader index comes from elector, must be within bounds");
        debug!(round=?self.round, ?leader, ?key, "leader elected");
        self.leader = Some(Leader { idx: leader, key });
    }

    /// Returns the notarization certificate if we already reconstructed one.
    pub const fn notarization(&self) -> Option<&Notarization<S, D>> {
        self.notarization.as_ref()
    }

    /// Returns the nullification certificate if we already reconstructed one.
    pub const fn nullification(&self) -> Option<&Nullification<S>> {
        self.nullification.as_ref()
    }

    /// Returns how much time elapsed since the round started, if the clock monotonicity holds.
    pub fn elapsed_since_start(&self, now: SystemTime) -> Duration {
        now.duration_since(self.start).unwrap_or_default()
    }

    /// Completes the local proposal flow after the automaton returns a payload.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> bool {
        if self.broadcast_nullify {
            return false;
        }
        self.proposal.built(proposal);
        self.leader_deadline = None;
        true
    }

    /// Completes peer proposal verification after the automaton returns.
    ///
    /// Returns `true` if the slot was updated, `false` if we already broadcast nullify
    /// or the slot was in an invalid state (e.g., we received a certificate for a
    /// conflicting proposal).
    pub fn verified(&mut self) -> bool {
        if self.broadcast_nullify {
            return false;
        }
        if !self.proposal.mark_verified() {
            // If we receive a certificate for some proposal, we ignore our verification.
            return false;
        }
        self.leader_deadline = None;
        true
    }

    /// Sets a proposal received from network (leader's first notarize vote).
    ///
    /// Returns true if the proposal should trigger verification, false otherwise.
    pub fn set_proposal(&mut self, proposal: Proposal<D>) -> bool {
        if self.broadcast_nullify {
            return false;
        }
        match self.proposal.update(&proposal, false) {
            ProposalChange::New => {
                self.leader_deadline = None;
                true
            }
            ProposalChange::Unchanged
            | ProposalChange::Equivocated { .. }
            | ProposalChange::Skipped => false,
        }
    }

    pub const fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
    }

    pub const fn set_deadline(&mut self, leader_deadline: SystemTime) {
        self.leader_deadline = Some(leader_deadline);
    }

    /// Overrides the nullify retry deadline, allowing callers to reschedule retries deterministically.
    pub const fn set_nullify_retry(&mut self, when: Option<SystemTime>) {
        self.nullify_retry = when;
    }

    /// Returns a nullify vote if we should timeout/retry.
    ///
    /// Returns `Some(true)` if this is a retry (we've already broadcast nullify before),
    /// `Some(false)` if this is the first timeout for this round, and `None` if we
    /// should not timeout.
    ///
    /// In minimmit, we can always nullify (no finalize phase to block it).
    pub fn construct_nullify(&mut self) -> Option<bool> {
        let retry = replace(&mut self.broadcast_nullify, true);
        self.clear_deadlines();
        self.set_nullify_retry(None);
        Some(retry)
    }

    /// Returns a nullify vote for contradiction if conditions are met.
    ///
    /// In minimmit, after notarizing a proposal, we can nullify if we observe M (2f+1)
    /// conflicting votes from OTHER replicas (notarizes for different payloads or nullifies).
    ///
    /// Returns `Some(())` if we should send a contradiction nullify, `None` otherwise.
    pub fn construct_nullify_by_contradiction(&mut self, m_threshold: usize) -> Option<()> {
        // Only trigger if we have notarized something
        if !self.broadcast_notarize {
            return None;
        }
        // Only trigger once
        if self.contradiction_nullify_sent {
            return None;
        }
        // Get our signer index (returns None for verifier-only instances)
        let our_signer = self.scheme.me()?;
        // Check if we have M conflicting votes from OTHER replicas
        let our_payload = self.proposal.proposal().map(|p| &p.payload)?;
        if !self
            .votes
            .should_nullify_by_contradiction(Some(our_payload), our_signer, m_threshold)
        {
            return None;
        }
        self.contradiction_nullify_sent = true;
        self.broadcast_nullify = true;
        Some(())
    }

    /// Returns true if we have sent a nullify due to contradiction.
    pub const fn has_contradiction_nullify(&self) -> bool {
        self.contradiction_nullify_sent
    }

    /// Returns the next timeout deadline for the round.
    pub fn next_timeout_deadline(&mut self, now: SystemTime, retry: Duration) -> SystemTime {
        if let Some(deadline) = self.leader_deadline {
            return deadline;
        }
        if let Some(deadline) = self.nullify_retry {
            return deadline;
        }
        let next = now + retry;
        self.nullify_retry = Some(next);
        next
    }

    /// Adds a proposal recovered from a certificate (notarization).
    ///
    /// Returns the leader's public key if equivocation is detected (conflicting proposals).
    pub fn add_recovered_proposal(&mut self, proposal: Proposal<D>) -> Option<S::PublicKey> {
        match self.proposal.update(&proposal, true) {
            ProposalChange::New => {
                debug!(?proposal, "setting verified proposal from certificate");
                None
            }
            ProposalChange::Unchanged => None,
            ProposalChange::Equivocated { dropped, retained } => {
                // Receiving a certificate for a conflicting proposal means the
                // leader signed two different payloads for the same (epoch, view).
                let equivocator = self.leader().map(|leader| leader.key);
                debug!(
                    ?equivocator,
                    ?dropped,
                    ?retained,
                    "certificate conflicts with proposal (equivocation detected)"
                );
                equivocator
            }
            ProposalChange::Skipped => None,
        }
    }

    /// Adds a verified notarization certificate to the round.
    ///
    /// Returns `(true, equivocator)` if newly added, `(false, None)` if already existed.
    /// Returns the leader's public key if equivocation is detected.
    pub fn add_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        // Conflicting notarization certificates cannot exist unless safety already failed.
        // Once we've accepted one we simply ignore subsequent duplicates.
        if self.notarization.is_some() {
            return (false, None);
        }
        self.clear_deadlines();

        let equivocator = self.add_recovered_proposal(notarization.proposal.clone());
        self.notarization = Some(notarization);
        (true, equivocator)
    }

    /// Adds a verified nullification certificate to the round.
    ///
    /// Returns `true` if newly added, `false` if already existed.
    pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
        // A nullification certificate is unique per view unless safety already failed.
        if self.nullification.is_some() {
            return false;
        }
        self.clear_deadlines();
        self.nullification = Some(nullification);
        true
    }

    /// Returns a notarization certificate for broadcast if we have one and haven't broadcast it yet.
    pub fn broadcast_notarization(&mut self) -> Option<Notarization<S, D>> {
        if self.broadcast_notarization {
            return None;
        }
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }
        None
    }

    /// Returns a nullification certificate for broadcast if we have one and haven't broadcast it yet.
    pub fn broadcast_nullification(&mut self) -> Option<Nullification<S>> {
        if self.broadcast_nullification {
            return None;
        }
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }
        None
    }

    /// Returns a proposal candidate for notarization if we're ready to vote.
    ///
    /// Marks that we've broadcast our notarize vote to prevent duplicates.
    pub fn construct_notarize(&mut self) -> Option<&Proposal<D>> {
        // Ensure we haven't already broadcast a notarize vote or nullify vote.
        // Note: In minimmit, we CAN nullify after notarizing (via contradiction),
        // but we cannot notarize after nullifying.
        if self.broadcast_notarize || self.broadcast_nullify {
            return None;
        }
        // Even if we've already seen a notarization, we still broadcast our notarize vote
        // in case it is useful (in the worst case it lets others observe we are alive).

        // If we don't have a verified proposal, return None.
        //
        // This check prevents us from voting for a proposal if we have observed equivocation (where
        // the proposal would be set to ProposalStatus::Equivocated) or if verification hasn't
        // completed yet.
        if self.proposal.status() != ProposalStatus::Verified {
            return None;
        }
        self.broadcast_notarize = true;
        self.proposal.proposal()
    }

    /// Replays an artifact to restore broadcast flags after recovery.
    pub fn replay(&mut self, artifact: &Artifact<S, D>) {
        match artifact {
            Artifact::Notarize(notarize) => {
                assert!(
                    self.is_signer(notarize.signer()),
                    "replaying notarize from another signer"
                );

                // While we may not be the leader here, we still call
                // built because the effect is the same (there is a proposal
                // and it is verified).
                self.proposal.built(notarize.proposal.clone());
                self.broadcast_notarize = true;
            }
            Artifact::Nullify(nullify) => {
                assert!(
                    self.is_signer(nullify.signer()),
                    "replaying nullify from another signer"
                );
                self.broadcast_nullify = true;
            }
            Artifact::Notarization(_) => {
                self.broadcast_notarization = true;
            }
            Artifact::Nullification(_) => {
                self.broadcast_nullification = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::{
            scheme::ed25519,
            types::{Notarization, Notarize, Nullification, Nullify, Proposal},
        },
        types::{Epoch, View},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use rand::{rngs::StdRng, SeedableRng};

    const NAMESPACE: &[u8] = b"_COMMONWARE_MINIMMIT_TEST";

    #[test]
    fn equivocation_detected_on_proposal_notarization_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519::fixture(&mut rng, 4);
        let proposal_a = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([1u8; 32]),
        );
        let proposal_b = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([2u8; 32]),
        );
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(leader_scheme, proposal_a.round, SystemTime::UNIX_EPOCH, 4);

        // Set proposal from network
        round.set_leader(0);
        assert!(round.set_proposal(proposal_a.clone()));
        assert!(round.verified());

        // Attempt to vote
        assert_eq!(round.construct_notarize(), Some(&proposal_a));

        // Add conflicting notarization certificate
        let notarization_votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .map(|scheme| Notarize::sign(NAMESPACE, scheme, proposal_b.clone()).expect("sign"))
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter()).expect("assemble");
        let (accepted, equivocator) = round.add_notarization(certificate.clone());
        assert!(accepted);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.expect("equivocator"), participants[0]);
        assert_eq!(round.broadcast_notarization(), Some(certificate));

        // Should not vote again
        assert_eq!(round.construct_notarize(), None);
    }

    #[test]
    fn no_equivocation_on_matching_certificate() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, 4);
        let proposal = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([1u8; 32]),
        );
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(leader_scheme, proposal.round, SystemTime::UNIX_EPOCH, 4);

        // Set proposal from network
        round.set_leader(0);
        assert!(round.set_proposal(proposal.clone()));

        // Add matching notarization certificate
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(NAMESPACE, scheme, proposal.clone()).expect("sign"))
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter()).expect("assemble");
        let (accepted, equivocator) = round.add_notarization(certificate);
        assert!(accepted);
        assert!(equivocator.is_none());
    }

    #[test]
    fn replay_message_sets_broadcast_flags() {
        let mut rng = StdRng::seed_from_u64(2029);
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, 4);
        let local_scheme = schemes[0].clone();

        // Setup round and proposal
        let now = SystemTime::UNIX_EPOCH;
        let view = 2;
        let round_id = Rnd::new(Epoch::new(5), View::new(view));
        let proposal = Proposal::new(round_id, View::new(0), Sha256Digest::from([40u8; 32]));

        // Create notarization
        let notarize_local = Notarize::sign(NAMESPACE, &local_scheme, proposal.clone()).expect("notarize");
        let notarize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(NAMESPACE, scheme, proposal.clone()).expect("sign"))
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarize_votes.iter()).expect("notarization");

        // Create nullification
        let nullify_local =
            Nullify::sign::<Sha256Digest>(NAMESPACE, &local_scheme, round_id).expect("nullify");
        let nullify_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(NAMESPACE, scheme, round_id).expect("nullify"))
            .collect();
        let nullification =
            Nullification::from_nullifies(&verifier, &nullify_votes).expect("nullification");

        // Replay messages and verify broadcast flags
        let mut round = Round::new(local_scheme, round_id, now, 4);
        round.set_leader(0);
        round.replay(&Artifact::Notarize(notarize_local));
        assert!(round.broadcast_notarize);
        round.replay(&Artifact::Nullify(nullify_local));
        assert!(round.broadcast_nullify);
        round.replay(&Artifact::Notarization(notarization.clone()));
        assert!(round.broadcast_notarization);
        round.replay(&Artifact::Nullification(nullification.clone()));
        assert!(round.broadcast_nullification);

        // Replaying the certificate again should keep the flags set.
        round.replay(&Artifact::Notarization(notarization));
        assert!(round.broadcast_notarization);
        round.replay(&Artifact::Nullification(nullification));
        assert!(round.broadcast_nullification);
    }

    #[test]
    fn nullify_by_contradiction_triggers_correctly() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, 6);
        let local_scheme = schemes[0].clone();

        // Setup round and proposal
        let now = SystemTime::UNIX_EPOCH;
        let round_id = Rnd::new(Epoch::new(1), View::new(1));
        let proposal_a = Proposal::new(round_id, View::new(0), Sha256Digest::from([1u8; 32]));
        let proposal_b = Proposal::new(round_id, View::new(0), Sha256Digest::from([2u8; 32]));

        let mut round = Round::new(local_scheme.clone(), round_id, now, 6);
        round.set_leader(0);

        // First, notarize proposal_a
        assert!(round.set_proposal(proposal_a.clone()));
        assert!(round.verified());
        assert!(round.construct_notarize().is_some());

        // M threshold for n=6 is 2f+1 = 3 (with f=1)
        let m_threshold = 3;

        // Add our own notarize vote
        let our_vote = Notarize::sign(NAMESPACE, &local_scheme, proposal_a.clone()).expect("sign");
        assert!(round.votes_mut().insert_notarize(our_vote));

        // Should not trigger yet (only 1 vote)
        assert!(round
            .construct_nullify_by_contradiction(m_threshold)
            .is_none());

        // Add conflicting votes from others
        for scheme in schemes.iter().skip(1).take(2) {
            let vote = Notarize::sign(NAMESPACE, scheme, proposal_b.clone()).expect("sign");
            assert!(round.votes_mut().insert_notarize(vote));
        }

        // Now we have 1 matching + 2 conflicting = need to check if conflicting >= M
        // With m_threshold=3, we need 3 conflicting. We only have 2.
        assert!(round
            .construct_nullify_by_contradiction(m_threshold)
            .is_none());

        // Add one more conflicting vote
        let vote = Notarize::sign(NAMESPACE, &schemes[3], proposal_b.clone()).expect("sign");
        assert!(round.votes_mut().insert_notarize(vote));

        // Now we have 3 conflicting votes, should trigger
        assert!(round
            .construct_nullify_by_contradiction(m_threshold)
            .is_some());
        assert!(round.has_contradiction_nullify());

        // Should not trigger again
        assert!(round
            .construct_nullify_by_contradiction(m_threshold)
            .is_none());
    }

    #[test]
    fn nullify_by_contradiction_requires_prior_notarize() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, 6);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_id = Rnd::new(Epoch::new(1), View::new(1));
        let proposal = Proposal::new(round_id, View::new(0), Sha256Digest::from([1u8; 32]));

        let mut round = Round::new(local_scheme, round_id, now, 6);
        round.set_leader(0);

        // Set proposal but don't call construct_notarize yet
        assert!(round.set_proposal(proposal.clone()));
        assert!(round.verified());

        // Add conflicting votes
        let proposal_b = Proposal::new(round_id, View::new(0), Sha256Digest::from([2u8; 32]));
        for scheme in schemes.iter().skip(1).take(3) {
            let vote = Notarize::sign(NAMESPACE, scheme, proposal_b.clone()).expect("sign");
            assert!(round.votes_mut().insert_notarize(vote));
        }

        // Should not trigger because we haven't broadcast our notarize vote yet
        assert!(round.construct_nullify_by_contradiction(3).is_none());

        // Now notarize
        assert!(round.construct_notarize().is_some());

        // Still shouldn't trigger because we need to recheck after notarizing
        // The conflicting votes were already there, just recheck
        assert!(round.construct_nullify_by_contradiction(3).is_some());
    }

    #[test]
    fn nullify_by_contradiction_excludes_own_nullify() {
        // Tests that our own nullify vote (from timeout) is NOT counted as a conflict.
        // This ensures we don't trigger at M-1 external conflicts when we've also
        // sent a timeout nullify.
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, 6);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_id = Rnd::new(Epoch::new(1), View::new(1));
        let proposal_a = Proposal::new(round_id, View::new(0), Sha256Digest::from([1u8; 32]));
        let proposal_b = Proposal::new(round_id, View::new(0), Sha256Digest::from([2u8; 32]));

        let mut round = Round::new(local_scheme.clone(), round_id, now, 6);
        round.set_leader(0);

        // Notarize proposal_a
        assert!(round.set_proposal(proposal_a.clone()));
        assert!(round.verified());
        assert!(round.construct_notarize().is_some());

        let m_threshold = 3; // For n=6, f=1, M=3

        // Add our own nullify vote (simulating what happens after a timeout)
        let our_nullify =
            Nullify::sign::<Sha256Digest>(NAMESPACE, &local_scheme, round_id).expect("sign");
        assert!(round.votes_mut().insert_nullify(our_nullify));

        // Add exactly 2 conflicting notarizes (M-1)
        for scheme in schemes.iter().skip(1).take(2) {
            let vote = Notarize::sign(NAMESPACE, scheme, proposal_b.clone()).expect("sign");
            assert!(round.votes_mut().insert_notarize(vote));
        }

        // Should NOT trigger - we have 1 own nullify (excluded) + 2 conflicting notarizes = 2 < M
        assert!(
            round.construct_nullify_by_contradiction(m_threshold).is_none(),
            "should not trigger when own nullify is the only third vote"
        );

        // Add one more conflicting notarize from another replica
        let vote = Notarize::sign(NAMESPACE, &schemes[3], proposal_b.clone()).expect("sign");
        assert!(round.votes_mut().insert_notarize(vote));

        // Now should trigger - 3 conflicting votes from OTHER replicas
        assert!(
            round.construct_nullify_by_contradiction(m_threshold).is_some(),
            "should trigger when M external conflicting votes observed"
        );
    }

    #[test]
    fn nullify_by_contradiction_counts_other_nullifies() {
        // Tests that nullify votes from OTHER replicas are correctly counted as conflicts.
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, 6);
        let local_scheme = schemes[0].clone();

        let now = SystemTime::UNIX_EPOCH;
        let round_id = Rnd::new(Epoch::new(1), View::new(1));
        let proposal_a = Proposal::new(round_id, View::new(0), Sha256Digest::from([1u8; 32]));
        let proposal_b = Proposal::new(round_id, View::new(0), Sha256Digest::from([2u8; 32]));

        let mut round = Round::new(local_scheme.clone(), round_id, now, 6);
        round.set_leader(0);

        // Notarize proposal_a
        assert!(round.set_proposal(proposal_a.clone()));
        assert!(round.verified());
        assert!(round.construct_notarize().is_some());

        let m_threshold = 3; // For n=6, f=1, M=3

        // Add 2 nullify votes from OTHER replicas
        for scheme in schemes.iter().skip(1).take(2) {
            let vote = Nullify::sign::<Sha256Digest>(NAMESPACE, scheme, round_id).expect("sign");
            assert!(round.votes_mut().insert_nullify(vote));
        }

        // 2 nullifies < M, should not trigger yet
        assert!(round.construct_nullify_by_contradiction(m_threshold).is_none());

        // Add 1 conflicting notarize from another replica
        let vote = Notarize::sign(NAMESPACE, &schemes[3], proposal_b.clone()).expect("sign");
        assert!(round.votes_mut().insert_notarize(vote));

        // Now we have 2 nullifies + 1 conflicting notarize = 3 >= M
        assert!(
            round.construct_nullify_by_contradiction(m_threshold).is_some(),
            "should trigger when 2 external nullifies + 1 conflicting notarize = M"
        );
    }
}
