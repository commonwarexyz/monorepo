use super::slot::{Change as ProposalChange, Slot as ProposalSlot, Status as ProposalStatus};
use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Attributable, Finalization, Notarization, Nullification, Proposal, Voter},
    },
    types::Round as Rnd,
};
use commonware_cryptography::{Digest, PublicKey};
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

/// Per-[Rnd] state machine.
pub struct Round<S: Scheme, D: Digest> {
    start: SystemTime,
    scheme: S,

    round: Rnd,

    // Leader is set as soon as we know the seed for the view (if any).
    leader: Option<Leader<S::PublicKey>>,

    proposal: ProposalSlot<D>,
    leader_deadline: Option<SystemTime>,
    advance_deadline: Option<SystemTime>,
    nullify_retry: Option<SystemTime>,

    // Certificates received from batcher (constructed or from network).
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
        Self {
            start,
            scheme,
            round,
            leader: None,
            proposal: ProposalSlot::new(),
            leader_deadline: None,
            advance_deadline: None,
            nullify_retry: None,
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

    #[allow(clippy::type_complexity)]
    /// Returns the leader key and proposal when the view is ready for verification.
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

    /// Removes the leader and advance deadlines so timeouts stop firing.
    pub fn clear_deadlines(&mut self) {
        self.leader_deadline = None;
        self.advance_deadline = None;
    }

    /// Picks and stores the leader for this round using the deterministic lottery.
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

    /// Returns the notarization certificate if we already reconstructed one.
    pub fn notarization(&self) -> Option<&Notarization<S, D>> {
        self.notarization.as_ref()
    }

    /// Returns the nullification certificate if we already reconstructed one.
    pub fn nullification(&self) -> Option<&Nullification<S>> {
        self.nullification.as_ref()
    }

    /// Returns the finalization certificate if we already reconstructed one.
    pub fn finalization(&self) -> Option<&Finalization<S, D>> {
        self.finalization.as_ref()
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

    /// Sets a proposal received from the batcher (leader's first notarize vote).
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
            | ProposalChange::Replaced { .. }
            | ProposalChange::Skipped => false,
        }
    }

    pub fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
    }

    pub fn set_deadlines(&mut self, leader_deadline: SystemTime, advance_deadline: SystemTime) {
        self.leader_deadline = Some(leader_deadline);
        self.advance_deadline = Some(advance_deadline);
    }

    /// Overrides the nullify retry deadline, allowing callers to reschedule retries deterministically.
    pub fn set_nullify_retry(&mut self, when: Option<SystemTime>) {
        self.nullify_retry = when;
    }

    /// Returns a nullify vote if we should timeout/retry.
    ///
    /// Returns `Some(true)` if this is a retry (we've already broadcast nullify before),
    /// `Some(false)` if this is the first timeout for this round, and `None` if we
    /// should not timeout (e.g. because we have already finalized).
    pub fn construct_nullify(&mut self) -> Option<bool> {
        // Ensure we haven't already broadcast a finalize vote.
        if self.broadcast_finalize {
            return None;
        }
        let retry = replace(&mut self.broadcast_nullify, true);
        self.clear_deadlines();
        self.set_nullify_retry(None);
        Some(retry)
    }

    /// Returns the next timeout deadline for the round.
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

    /// Adds a proposal recovered from a certificate (notarization or finalization).
    ///
    /// Returns the leader's public key if equivocation is detected (conflicting proposals).
    pub fn add_recovered_proposal(&mut self, proposal: Proposal<D>) -> Option<S::PublicKey> {
        match self.proposal.update(&proposal, true) {
            ProposalChange::New => {
                debug!(?proposal, "setting verified proposal from certificate");
                None
            }
            ProposalChange::Unchanged => None,
            ProposalChange::Replaced { dropped, retained } => {
                // Receiving a certificate for a conflicting proposal means the
                // leader signed two different payloads for the same (epoch,
                // view).
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
    pub fn add_verified_notarization(
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
    pub fn add_verified_nullification(&mut self, nullification: Nullification<S>) -> bool {
        // A nullification certificate is unique per view unless safety already failed.
        if self.nullification.is_some() {
            return false;
        }
        self.clear_deadlines();
        self.nullification = Some(nullification);
        true
    }

    /// Adds a verified finalization certificate to the round.
    ///
    /// Returns `(true, equivocator)` if newly added, `(false, None)` if already existed.
    /// Returns the leader's public key if equivocation is detected.
    pub fn add_verified_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        // Only one finalization certificate can exist unless safety already failed, so we ignore
        // later duplicates.
        if self.finalization.is_some() {
            return (false, None);
        }
        self.clear_deadlines();

        let equivocator = self.add_recovered_proposal(finalization.proposal.clone());
        self.finalization = Some(finalization);
        (true, equivocator)
    }

    /// Returns a notarization certificate for broadcast if we have one and haven't broadcast it yet.
    pub fn notarizable(&mut self) -> Option<Notarization<S, D>> {
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
    pub fn nullifiable(&mut self) -> Option<Nullification<S>> {
        if self.broadcast_nullification {
            return None;
        }
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }
        None
    }

    /// Returns a finalization certificate for broadcast if we have one and haven't broadcast it yet.
    pub fn finalizable(&mut self) -> Option<Finalization<S, D>> {
        if self.broadcast_finalization {
            return None;
        }
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }
        None
    }

    /// Returns a proposal candidate for notarization if we're ready to vote.
    ///
    /// Marks that we've broadcast our notarize vote to prevent duplicates.
    pub fn construct_notarize(&mut self) -> Option<&Proposal<D>> {
        // Ensure we haven't already broadcast a notarize vote or nullify vote.
        if self.broadcast_notarize || self.broadcast_nullify {
            return None;
        }

        // If we don't have a verified proposal, return None.
        let status = self.proposal.status();
        if status != ProposalStatus::Verified && status != ProposalStatus::Replaced {
            return None;
        }
        self.broadcast_notarize = true;
        self.proposal.proposal()
    }

    /// Returns a proposal candidate for finalization if we're ready to vote.
    ///
    /// Marks that we've broadcast our finalize vote to prevent duplicates.
    pub fn construct_finalize(&mut self) -> Option<&Proposal<D>> {
        // Ensure we haven't already broadcast a finalize vote or nullify vote.
        if self.broadcast_finalize || self.broadcast_nullify {
            return None;
        }

        // If we haven't broadcast our notarize vote and notarization certificate, return None.
        if !self.broadcast_notarize || !self.broadcast_notarization {
            return None;
        }

        // If we don't have a verified proposal, return None.
        let status = self.proposal.status();
        if status != ProposalStatus::Verified && status != ProposalStatus::Replaced {
            return None;
        }
        self.broadcast_finalize = true;
        self.proposal.proposal()
    }

    pub fn replay(&mut self, message: &Voter<S, D>) {
        match message {
            Voter::Notarize(notarize) => {
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
            Voter::Notarization(_) => {
                self.broadcast_notarization = true;
            }
            Voter::Nullify(nullify) => {
                assert!(
                    self.is_signer(nullify.signer()),
                    "replaying nullify from another signer"
                );
                self.broadcast_nullify = true;
            }
            Voter::Nullification(_) => {
                self.broadcast_nullification = true;
            }
            Voter::Finalize(finalize) => {
                assert!(
                    self.is_signer(finalize.signer()),
                    "replaying finalize from another signer"
                );
                self.broadcast_finalize = true;
            }
            Voter::Finalization(_) => {
                self.broadcast_finalization = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            mocks::fixtures::{ed25519, Fixture},
            types::{Finalization, Finalize, Notarization, Notarize, Nullify, Proposal},
        },
        types::{Epoch, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn equivocation_detected_on_proposal_notarization_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"ns";
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519(&mut rng, 4);
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
        let mut round = Round::new(
            leader_scheme.clone(),
            proposal_a.round,
            SystemTime::UNIX_EPOCH,
        );

        // Set proposal from batcher
        round.set_leader(None);
        assert!(round.set_proposal(proposal_a.clone()));

        // Add conflicting notarization certificate
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

        // Should vote for the certificate's proposal (proposal_b)
        assert_eq!(round.construct_notarize(), Some(&proposal_b));
        assert!(round.construct_finalize().is_none()); // need to broadcast notarization first
    }

    #[test]
    fn equivocation_detected_on_proposal_finalization_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"ns";
        let Fixture {
            schemes,
            participants,
            verifier,
            ..
        } = ed25519(&mut rng, 4);
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
        let mut round = Round::new(
            leader_scheme.clone(),
            proposal_a.round,
            SystemTime::UNIX_EPOCH,
        );

        // Set proposal from batcher
        round.set_leader(None);
        assert!(round.set_proposal(proposal_a.clone()));

        // Add conflicting finalization certificate
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

        // Should vote for the certificate's proposal (proposal_b)
        assert_eq!(round.construct_notarize(), Some(&proposal_b));
        assert!(round.construct_finalize().is_none()); // need to broadcast notarization first
    }

    #[test]
    fn no_equivocation_on_matching_certificate() {
        let mut rng = StdRng::seed_from_u64(42);
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let proposal = Proposal::new(
            Rnd::new(Epoch::new(1), View::new(1)),
            View::new(0),
            Sha256Digest::from([1u8; 32]),
        );
        let leader_scheme = schemes[0].clone();
        let mut round = Round::new(
            leader_scheme.clone(),
            proposal.round,
            SystemTime::UNIX_EPOCH,
        );

        // Set proposal from batcher
        round.set_leader(None);
        assert!(round.set_proposal(proposal.clone()));

        // Add matching notarization certificate
        let notarization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter()).unwrap();
        let (accepted, equivocator) = round.add_verified_notarization(certificate);
        assert!(accepted);
        assert!(equivocator.is_none());
    }

    #[test]
    fn replay_message_sets_broadcast_flags() {
        let mut rng = StdRng::seed_from_u64(2029);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let local_scheme = schemes[0].clone();

        // Setup round and proposal
        let now = SystemTime::UNIX_EPOCH;
        let view = 2;
        let round = Rnd::new(Epoch::new(5), View::new(view));
        let proposal = Proposal::new(round, View::new(0), Sha256Digest::from([40u8; 32]));

        // Create notarization
        let notarize_local =
            Notarize::sign(&local_scheme, namespace, proposal.clone()).expect("notarize");
        let notarize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarize_votes.iter()).expect("notarization");

        // Create nullification
        let nullify_local =
            Nullify::sign::<Sha256Digest>(&local_scheme, namespace, round).expect("nullify");
        let nullify_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, namespace, round).expect("nullify"))
            .collect();
        let nullification =
            Nullification::from_nullifies(&verifier, &nullify_votes).expect("nullification");

        // Create finalize
        let finalize_local =
            Finalize::sign(&local_scheme, namespace, proposal.clone()).expect("finalize");
        let finalize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, namespace, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&verifier, finalize_votes.iter()).expect("finalization");

        // Replay messages and verify broadcast flags
        let mut round = Round::new(local_scheme.clone(), round, now);
        round.set_leader(None);
        round.replay(&Voter::Notarize(notarize_local));
        assert!(round.broadcast_notarize);
        round.replay(&Voter::Nullify(nullify_local));
        assert!(round.broadcast_nullify);
        round.replay(&Voter::Finalize(finalize_local));
        assert!(round.broadcast_finalize);
        round.replay(&Voter::Notarization(notarization.clone()));
        assert!(round.broadcast_notarization);
        round.replay(&Voter::Nullification(nullification.clone()));
        assert!(round.broadcast_nullification);
        round.replay(&Voter::Finalization(finalization.clone()));
        assert!(round.broadcast_finalization);

        // Replaying the certificate again should keep the flags set.
        round.replay(&Voter::Notarization(notarization));
        assert!(round.broadcast_notarization);
        round.replay(&Voter::Nullification(nullification));
        assert!(round.broadcast_nullification);
        round.replay(&Voter::Finalization(finalization));
        assert!(round.broadcast_finalization);
    }

    #[test]
    fn construct_nullify_blocked_by_finalize() {
        let mut rng = StdRng::seed_from_u64(2029);
        let Fixture { schemes, .. } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let local_scheme = schemes[0].clone();

        // Setup round and proposal
        let now = SystemTime::UNIX_EPOCH;
        let view = 2;
        let round_info = Rnd::new(Epoch::new(5), View::new(view));
        let proposal = Proposal::new(round_info, View::new(0), Sha256Digest::from([40u8; 32]));

        // Create finalized vote
        let finalize_local =
            Finalize::sign(&local_scheme, namespace, proposal.clone()).expect("finalize");

        // Replay finalize and verify nullify is blocked
        let mut round = Round::new(local_scheme.clone(), round_info, now);
        round.set_leader(None);
        round.replay(&Voter::Finalize(finalize_local));

        // Check that construct_nullify returns None
        assert!(round.construct_nullify().is_none());
    }
}
