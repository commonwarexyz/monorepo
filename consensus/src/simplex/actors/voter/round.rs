use super::slot::{Change as ProposalChange, Slot as ProposalSlot, Status as ProposalStatus};
use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{
            Attributable, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            OrderedExt, Proposal, VoteTracker, Voter,
        },
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

    // We only receive votes for the leader's proposal, so we don't
    // need to track multiple proposals here.
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
            // On restart, we may both see a notarize/nullify/finalize from replaying our journal and from
            // new messages forwarded from the batcher. To ensure we don't wrongly assume we have enough
            // signatures to construct a notarization/nullification/finalization, we use an AttributableMap
            // to ensure we only count a message from a given signer once.
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

    /// Drops all notarize/finalize votes that were accumulated for this round.
    // TODO (#2228): Remove vote tracking from voter
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

    /// Returns how many nullify votes we currently track.
    pub fn len_nullifies(&self) -> usize {
        self.votes.len_nullifies()
    }

    /// Returns how many notarize votes we currently track.
    pub fn len_notarizes(&self) -> usize {
        self.votes.len_notarizes()
    }

    /// Returns how many finalize votes we currently track.
    pub fn len_finalizes(&self) -> usize {
        self.votes.len_finalizes()
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

    pub fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
    }

    pub fn has_broadcast_notarization(&self) -> bool {
        self.broadcast_notarization
    }

    pub fn has_broadcast_nullification(&self) -> bool {
        self.broadcast_nullification
    }

    pub fn has_broadcast_finalization(&self) -> bool {
        self.broadcast_finalization
    }

    pub fn set_deadlines(&mut self, leader_deadline: SystemTime, advance_deadline: SystemTime) {
        self.leader_deadline = Some(leader_deadline);
        self.advance_deadline = Some(advance_deadline);
    }

    /// Overrides the nullify retry deadline, allowing callers to reschedule retries deterministically.
    pub fn set_nullify_retry(&mut self, when: Option<SystemTime>) {
        self.nullify_retry = when;
    }

    /// Handles a timeout event, marking that we've broadcast a nullify vote.
    ///
    /// Returns `true` if this is a retry (we've already broadcast nullify before),
    /// `false` if this is the first timeout for this round.
    pub fn handle_timeout(&mut self) -> bool {
        let retry = replace(&mut self.broadcast_nullify, true);
        self.clear_deadlines();
        self.set_nullify_retry(None);
        retry
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
                // view). We immediately flag equivocators, wipe any local vote
                // accumulation, and rely on the caller to broadcast evidence.
                let equivocator = self.record_equivocation_and_clear();
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

    /// Adds a verified notarize vote to the round.
    ///
    /// Returns the leader's public key if equivocation is detected (conflicting proposals).
    pub fn add_verified_notarize(&mut self, notarize: Notarize<S, D>) -> Option<S::PublicKey> {
        match self.proposal.update(&notarize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { dropped, retained } => {
                // Once we detect equivocation we clear all votes and return the
                // leader key so the caller can surface slashable evidence.
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?dropped,
                    ?retained,
                    "notarize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.votes.insert_notarize(notarize);
        None
    }

    /// Adds a verified nullify vote to the round.
    pub fn add_verified_nullify(&mut self, nullify: Nullify<S>) {
        self.votes.insert_nullify(nullify);
    }

    /// Adds a verified finalize vote to the round.
    ///
    /// Returns the leader's public key if equivocation is detected (conflicting proposals).
    pub fn add_verified_finalize(&mut self, finalize: Finalize<S, D>) -> Option<S::PublicKey> {
        match self.proposal.update(&finalize.proposal, false) {
            ProposalChange::New | ProposalChange::Unchanged => {}
            ProposalChange::Replaced { dropped, retained } => {
                let equivocator = self.record_equivocation_and_clear();
                debug!(
                    ?equivocator,
                    ?dropped,
                    ?retained,
                    "finalize conflicts with certificate proposal (equivocation detected)"
                );
                return equivocator;
            }
            ProposalChange::Skipped => return None,
        }
        self.votes.insert_finalize(finalize);
        None
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

    /// Constructs a notarization certificate if we have enough votes.
    pub fn notarizable(&mut self) -> Option<Notarization<S, D>> {
        // Ensure we haven't already broadcast a notarization certificate.
        if self.broadcast_notarization {
            return None;
        }

        // If we have a notarization certificate, return it.
        if let Some(notarization) = &self.notarization {
            self.broadcast_notarization = true;
            return Some(notarization.clone());
        }

        // If we don't have a notarization certificate, check if we have enough votes.
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_notarizes() < quorum {
            return None;
        }

        // If we have enough votes, construct a notarization certificate.
        let notarization = Notarization::from_notarizes(&self.scheme, self.votes.iter_notarizes())
            .expect("failed to recover notarization certificate");
        self.broadcast_notarization = true;
        Some(notarization)
    }

    /// Constructs a nullification certificate if we have enough votes.
    pub fn nullifiable(&mut self) -> Option<Nullification<S>> {
        // Ensure we haven't already broadcast a nullification certificate.
        if self.broadcast_nullification {
            return None;
        }

        // If we have a nullification certificate, return it.
        if let Some(nullification) = &self.nullification {
            self.broadcast_nullification = true;
            return Some(nullification.clone());
        }

        // If we don't have a nullification certificate, check if we have enough votes.
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_nullifies() < quorum {
            return None;
        }

        // If we have enough votes, construct a nullification certificate.
        let nullification =
            Nullification::from_nullifies(&self.scheme, self.votes.iter_nullifies())
                .expect("failed to recover nullification certificate");
        self.broadcast_nullification = true;
        Some(nullification)
    }

    /// Constructs a finalization certificate if we have enough votes.
    pub fn finalizable(&mut self) -> Option<Finalization<S, D>> {
        // Ensure we haven't already broadcast a finalization certificate.
        if self.broadcast_finalization {
            return None;
        }

        // If we have a finalization certificate, return it.
        if let Some(finalization) = &self.finalization {
            self.broadcast_finalization = true;
            return Some(finalization.clone());
        }

        // If we don't have a finalization certificate, check if we have enough votes.
        let quorum = self.scheme.participants().quorum() as usize;
        if self.votes.len_finalizes() < quorum {
            return None;
        }

        // If we have enough votes, construct a finalization certificate.
        let finalization = Finalization::from_finalizes(&self.scheme, self.votes.iter_finalizes())
            .expect("failed to recover finalization certificate");
        self.broadcast_finalization = true;
        Some(finalization)
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
        if self.proposal.status() != ProposalStatus::Verified {
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
        if self.proposal.status() != ProposalStatus::Verified {
            return None;
        }
        self.broadcast_finalize = true;
        self.proposal.proposal()
    }

    pub fn replay(&mut self, message: &Voter<S, D>) {
        match message {
            Voter::Notarize(notarize) => {
                if self.is_signer(notarize.signer()) {
                    // While we may not be the leader here, we still call
                    // built because the effect is the same (there is a proposal
                    // and it is verified).
                    self.proposal.built(notarize.proposal.clone());
                    self.broadcast_notarize = true;
                }
            }
            Voter::Notarization(_) => {
                self.broadcast_notarization = true;
            }
            Voter::Nullify(nullify) => {
                if self.is_signer(nullify.signer()) {
                    self.broadcast_nullify = true;
                }
            }
            Voter::Nullification(_) => {
                self.broadcast_nullification = true;
            }
            Voter::Finalize(finalize) => {
                if self.is_signer(finalize.signer()) {
                    self.broadcast_finalize = true;
                }
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
        assert!(round.construct_notarize().is_none());
        assert!(round.construct_finalize().is_none());

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
        assert!(round.construct_notarize().is_none());
        assert!(round.construct_finalize().is_none());

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
        assert!(round.construct_notarize().is_none());
        assert!(round.construct_finalize().is_none());

        // Ignore new votes
        let vote = Notarize::sign(&schemes[1], namespace, proposal_a.clone()).unwrap();
        assert!(round.add_verified_notarize(vote).is_none());
        assert_eq!(round.votes.len_notarizes(), 0);
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
        let round = Rnd::new(5, view);
        let proposal = Proposal::new(round, 0, Sha256Digest::from([40u8; 32]));

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
        assert!(round.has_broadcast_notarization());
        round.replay(&Voter::Nullification(nullification.clone()));
        assert!(round.has_broadcast_nullification());
        round.replay(&Voter::Finalization(finalization.clone()));
        assert!(round.has_broadcast_finalization());

        // Replaying the certificate again should keep the flags set.
        round.replay(&Voter::Notarization(notarization));
        assert!(round.has_broadcast_notarization());
        round.replay(&Voter::Nullification(nullification));
        assert!(round.has_broadcast_nullification());
        round.replay(&Voter::Finalization(finalization));
        assert!(round.has_broadcast_finalization());
    }
}
