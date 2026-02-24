//! Epoch-level consensus logic for Minimmit.
//!
//! This module implements a synchronous state machine that consumes proposals,
//! votes, certificates, and timeouts while emitting actions to execute.

use crate::{
    elector::Elector,
    minimmit::{
        ancestry::Ancestry,
        scheme::Scheme,
        types::{
            Artifact, Attributable, Certificate, Context, Finalization, MNotarization, Notarize,
            Nullification, Nullify, Proposal, Vote, VoteTracker,
        },
        view::{Phase, ViewState},
    },
    types::{Epoch, Participant, Round, View},
    Epochable, Viewable,
};
use commonware_cryptography::Digest;
use commonware_parallel::Strategy;
use commonware_utils::{Faults, M5f1, N5f1};
use rand_core::CryptoRngCore;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const GENESIS_VIEW: View = View::zero();

/// Errors that can occur during journal replay.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Attempted to replay a notarize vote from a different signer.
    #[error("notarize from wrong signer: expected {expected}, got {got}")]
    WrongNotarizeSigner {
        /// Expected signer (our participant ID).
        expected: Participant,
        /// Actual signer from the artifact.
        got: Participant,
    },
    /// Attempted to replay a nullify vote from a different signer.
    #[error("nullify from wrong signer: expected {expected}, got {got}")]
    WrongNullifySigner {
        /// Expected signer (our participant ID).
        expected: Participant,
        /// Actual signer from the artifact.
        got: Participant,
    },
}

/// Actions emitted by the Minimmit state machine.
#[derive(Clone, Debug)]
pub enum Action<S: Scheme<D>, D: Digest> {
    /// Request a proposal from the application.
    Propose {
        /// Metadata for proposal construction.
        context: Context<D, S::PublicKey>,
        /// View for the requested proposal.
        view: View,
    },
    /// Request verification for a proposal.
    VerifyProposal(Proposal<D>),
    /// Broadcast a notarize vote.
    BroadcastNotarize(Notarize<S, D>),
    /// Broadcast a nullify vote.
    BroadcastNullify(Nullify<S>),
    /// Broadcast a certificate.
    BroadcastCertificate(Certificate<S, D>),
    /// Finalization has occurred.
    Finalized(Finalization<S, D>),
    /// View advanced to a new value.
    Advanced(View),
}

/// Result of handling a timeout in the consensus state machine.
#[derive(Clone, Debug)]
pub struct TimeoutResult<S: Scheme<D>, D: Digest> {
    /// Whether this is a retry timeout (already nullified, just re-broadcasting).
    pub is_retry: bool,
    /// Nullify vote to broadcast, if any.
    pub nullify: Option<Nullify<S>>,
    /// Entry certificate for the previous view to help lagging nodes (only on retry).
    pub entry_certificate: Option<Certificate<S, D>>,
}

/// Core Minimmit consensus state.
pub struct State<S, D, E>
where
    S: Scheme<D>,
    D: Digest,
    E: Elector<S>,
{
    epoch: Epoch,
    scheme: S,
    elector: E,
    view: View,
    last_finalized: View,
    last_seen_notarization: View,
    ancestry: Ancestry<S, D>,
    views: BTreeMap<View, ViewState<D>>,
    trackers: BTreeMap<View, VoteTracker<S, D>>,
    leaders: BTreeMap<View, Participant>,
    participants: u32,
    me: Option<Participant>,
    /// Certificate that caused the advance to the current view.
    /// Used by electors like `Random` that derive randomness from certificates.
    advancing_certificate: Option<S::Certificate>,
}

impl<S, D, E> State<S, D, E>
where
    S: Scheme<D>,
    D: Digest,
    E: Elector<S>,
{
    /// Creates a new state machine seeded with genesis data.
    pub fn new(epoch: Epoch, scheme: S, elector: E, genesis: D) -> Self {
        let participants =
            u32::try_from(scheme.participants().len()).expect("participant count must fit in u32");
        let ancestry = Ancestry::new(genesis);
        let view = GENESIS_VIEW.next();
        let me = scheme.me();

        let mut state = Self {
            epoch,
            scheme,
            elector,
            view,
            last_finalized: GENESIS_VIEW,
            last_seen_notarization: GENESIS_VIEW,
            ancestry,
            views: BTreeMap::new(),
            trackers: BTreeMap::new(),
            leaders: BTreeMap::new(),
            participants,
            me,
            advancing_certificate: None, // View 1 has no advancing certificate
        };

        state.ensure_view(view);
        state
    }

    /// Returns the current epoch.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the current view.
    pub const fn view(&self) -> View {
        self.view
    }

    /// Returns the last finalized view.
    pub const fn last_finalized(&self) -> View {
        self.last_finalized
    }

    /// Returns the last seen notarized view.
    pub const fn last_seen_notarization(&self) -> View {
        self.last_seen_notarization
    }

    /// Returns a reference to the signing scheme.
    pub const fn scheme(&self) -> &S {
        &self.scheme
    }

    /// Returns the leader index for a view.
    ///
    /// For the current view, uses the stored `advancing_certificate` if available.
    /// This enables electors like `Random` that derive randomness from certificates.
    pub fn leader(&mut self, view: View, certificate: Option<&S::Certificate>) -> Participant {
        if let Some(leader) = self.leaders.get(&view) {
            return *leader;
        }
        // Use the provided certificate, or the stored advancing certificate for the current view
        let cert_to_use = certificate.or_else(|| {
            if view == self.view {
                self.advancing_certificate.as_ref()
            } else {
                None
            }
        });
        let leader = self
            .elector
            .elect(Round::new(self.epoch, view), cert_to_use);
        self.leaders.insert(view, leader);
        leader
    }

    /// Returns true if this node is the leader for the view.
    pub fn is_leader(&mut self, view: View, certificate: Option<&S::Certificate>) -> bool {
        self.me
            .is_some_and(|me| me == self.leader(view, certificate))
    }

    /// Returns the parent to build on for the provided view.
    pub fn select_parent(&self, view: View) -> Option<(View, D)> {
        self.ancestry.select_parent(view)
    }

    /// Returns the parent payload for a proposal if its ancestry is valid.
    ///
    /// This is used during verification to look up the parent digest
    /// based on what the proposal claims its parent view is.
    pub fn parent_payload(&self, proposal: &Proposal<D>) -> Option<(View, D)> {
        self.ancestry.parent_payload(proposal, self.last_finalized)
    }

    /// Attempts to emit a proposal request if we are leader.
    pub fn try_propose(&mut self) -> Option<Action<S, D>> {
        let view = self.view;
        if view == GENESIS_VIEW {
            return None;
        }
        if !self.is_leader(view, None) {
            return None;
        }
        let already_sent = self
            .views
            .get(&view)
            .is_some_and(|state| state.propose_sent());
        if already_sent {
            return None;
        }
        let (parent_view, parent_payload) = self.select_parent(view)?;
        let leader = self.leader(view, None);
        let leader_key = self
            .scheme
            .participants()
            .get(leader.into())
            .expect("leader index must exist")
            .clone();
        let round = Round::new(self.epoch, view);
        let state = self.ensure_view(view);
        state.mark_propose_sent();
        Some(Action::Propose {
            context: Context {
                round,
                leader: leader_key,
                parent: (parent_view, parent_payload),
            },
            view,
        })
    }

    /// Records a locally-built proposal and returns any actions.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> Vec<Action<S, D>> {
        if proposal.epoch() != self.epoch || proposal.view() != self.view {
            return Vec::new();
        }
        let view = proposal.view();
        let inserted = {
            let state = self.ensure_view(view);
            if !state.set_proposal(proposal.clone()) {
                return Vec::new();
            }
            state.mark_verified(proposal.payload)
        };
        if !inserted {
            return Vec::new();
        }
        self.maybe_vote_for_proposal(&proposal)
    }

    /// Records a proposal received from the network.
    ///
    /// The `sender` parameter identifies who sent the proposal. This must match
    /// the expected leader for the proposal's view. Proposals from non-leaders
    /// are silently rejected.
    pub fn receive_proposal(
        &mut self,
        sender: Participant,
        proposal: Proposal<D>,
    ) -> Vec<Action<S, D>> {
        if proposal.epoch() != self.epoch {
            return Vec::new();
        }
        let view = proposal.view();
        if view != self.view {
            return Vec::new();
        }
        // Verify the sender is the leader for this view
        if sender != self.leader(view, None) {
            return Vec::new();
        }
        let inserted = {
            let state = self.ensure_view(view);
            state.set_proposal(proposal.clone())
        };
        if !inserted {
            return Vec::new();
        }
        vec![Action::VerifyProposal(proposal)]
    }

    /// Marks the proposal as verified and possibly votes.
    pub fn proposal_verified(&mut self, proposal: Proposal<D>, valid: bool) -> Vec<Action<S, D>> {
        if proposal.epoch() != self.epoch || proposal.view() != self.view || !valid {
            return Vec::new();
        }
        let view = proposal.view();
        let marked = {
            let state = self.ensure_view(view);
            state.mark_verified(proposal.payload)
        };
        if !marked {
            return Vec::new();
        }
        self.maybe_vote_for_proposal(&proposal)
    }

    /// Handles a notarize vote.
    ///
    /// Verifies the signature before tracking. Invalid signatures are rejected.
    pub fn receive_notarize<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        vote: Notarize<S, D>,
        strategy: &impl Strategy,
    ) -> Vec<Action<S, D>> {
        if vote.epoch() != self.epoch {
            return Vec::new();
        }
        if vote.view() <= self.last_finalized {
            return Vec::new();
        }
        if !vote.verify(rng, &self.scheme, strategy) {
            return Vec::new();
        }
        self.process_notarize(vote, strategy)
    }

    /// Handles a nullify vote.
    ///
    /// Verifies the signature before tracking. Invalid signatures are rejected.
    /// Votes for finalized views are ignored.
    pub fn receive_nullify<R: CryptoRngCore>(
        &mut self,
        rng: &mut R,
        vote: Nullify<S>,
        strategy: &impl Strategy,
    ) -> Vec<Action<S, D>> {
        if vote.epoch() != self.epoch {
            return Vec::new();
        }
        if vote.view() <= self.last_finalized {
            return Vec::new();
        }
        if !vote.verify::<_, D>(rng, &self.scheme, strategy) {
            return Vec::new();
        }
        self.process_nullify(vote, strategy)
    }

    /// Handles an incoming certificate.
    pub fn receive_certificate(&mut self, certificate: Certificate<S, D>) -> Vec<Action<S, D>> {
        if certificate.epoch() != self.epoch {
            return Vec::new();
        }
        if certificate.view() <= self.last_finalized {
            return Vec::new();
        }
        let mut actions = self.process_certificate(certificate, true);
        actions.extend(self.retry_pending_proposals());
        actions
    }

    /// Re-emits verification actions for proposals that were deferred due to missing ancestry.
    ///
    /// A proposal can be accepted into the current view before all ancestry certificates
    /// needed to validate its parent chain are available locally. When new certificates
    /// arrive and extend ancestry, this method scans unverified proposals in the current
    /// view and retries only those whose parent can now be resolved.
    fn retry_pending_proposals(&self) -> Vec<Action<S, D>> {
        let Some(state) = self.views.get(&self.view) else {
            return Vec::new();
        };
        state
            .unverified_proposals()
            .filter(|proposal| self.parent_payload(proposal).is_some())
            .cloned()
            .map(Action::VerifyProposal)
            .collect()
    }

    /// Handles a pre-verified notarize vote.
    ///
    /// This method is used by the batcher actor which performs batch signature
    /// verification for performance. The signature is assumed to be valid.
    pub fn receive_verified_notarize(
        &mut self,
        vote: Notarize<S, D>,
        strategy: &impl Strategy,
    ) -> Vec<Action<S, D>> {
        if vote.epoch() != self.epoch {
            return Vec::new();
        }
        if vote.view() <= self.last_finalized {
            return Vec::new();
        }
        self.process_notarize(vote, strategy)
    }

    /// Handles a pre-verified nullify vote.
    ///
    /// This method is used by the batcher actor which performs batch signature
    /// verification for performance. The signature is assumed to be valid.
    /// Votes for finalized views are ignored.
    pub fn receive_verified_nullify(
        &mut self,
        vote: Nullify<S>,
        strategy: &impl Strategy,
    ) -> Vec<Action<S, D>> {
        if vote.epoch() != self.epoch {
            return Vec::new();
        }
        if vote.view() <= self.last_finalized {
            return Vec::new();
        }
        self.process_nullify(vote, strategy)
    }

    /// Internal: Process a notarize vote (assumes epoch check passed).
    fn process_notarize(
        &mut self,
        vote: Notarize<S, D>,
        strategy: &impl Strategy,
    ) -> Vec<Action<S, D>> {
        let view = vote.view();
        let inserted = {
            let tracker = self.ensure_tracker(view);
            tracker.insert_notarize(vote.clone())
        };
        if !inserted {
            return Vec::new();
        }
        self.ensure_view(view).set_proposal(vote.proposal.clone());

        let mut actions = Vec::new();
        if self.should_nullify_by_contradiction(view) {
            if let Some(action) = self.broadcast_nullify(view) {
                actions.push(action);
            }
        }
        if let Some(certificate) = self.build_notarize_certificate(view, &vote.proposal, strategy) {
            match certificate {
                Certificate::Finalization(ref finalization) => {
                    // Per the Minimmit paper (Algorithm 1), L-notarisations are NOT broadcast.
                    // However, M-notarisations ARE broadcast (line 433) because other nodes
                    // need them to advance views. When we hit L-quorum, we must ensure the
                    // M-notarisation is also broadcast (it may not have been if votes arrived
                    // in bulk or we're recovering from journal).
                    //
                    // Check if an M-notarization already exists in ancestry for this view.
                    // If not, we need to build and broadcast one.
                    if self.ancestry.any_m_notarization(view).is_none() {
                        // Build and broadcast M-notarisation from the same votes
                        if let Some(m_notarization) = MNotarization::from_notarizes(
                            &self.scheme,
                            self.trackers
                                .get(&view)
                                .into_iter()
                                .flat_map(|t| t.iter_notarizes())
                                .filter(|n| n.proposal == finalization.proposal),
                            strategy,
                        ) {
                            actions.extend(self.process_certificate(
                                Certificate::MNotarization(m_notarization),
                                true,
                            ));
                        }
                    }
                    // Process finalization locally without broadcast
                    actions.extend(self.process_certificate(certificate, false));
                }
                _ => {
                    // M-notarisations and Nullifications are broadcast
                    actions.extend(self.process_certificate(certificate, true));
                }
            }
        }
        actions
    }

    /// Internal: Process a nullify vote (assumes epoch and finalization checks passed).
    fn process_nullify(&mut self, vote: Nullify<S>, strategy: &impl Strategy) -> Vec<Action<S, D>> {
        let view = vote.view();
        let inserted = {
            let tracker = self.ensure_tracker(view);
            tracker.insert_nullify(vote)
        };
        if !inserted {
            return Vec::new();
        }

        let mut actions = Vec::new();
        if self.should_nullify_by_contradiction(view) {
            if let Some(action) = self.broadcast_nullify(view) {
                actions.push(action);
            }
        }
        if let Some(certificate) = self.build_nullification_certificate(view, strategy) {
            actions.extend(self.process_certificate(certificate, true));
        }
        actions
    }

    /// Handles a timeout for the current view.
    ///
    /// Returns a tuple of:
    /// - `is_retry`: true if we already nullified and this is a retry
    /// - `nullify`: the nullify vote to broadcast (if any)
    /// - `entry_cert`: certificate for the previous view (on retry, to help lagging nodes)
    ///
    /// On timeout, we either:
    /// - Send our first nullify vote (if we haven't voted/nullified yet)
    /// - Re-broadcast our nullify vote (if we already nullified but need to retry)
    ///
    /// On retry timeouts, we also return an entry certificate for the previous view.
    /// This helps nodes stuck at the previous view catch up, following Simplex's pattern.
    pub fn handle_timeout(&mut self) -> TimeoutResult<S, D> {
        let view = self.view;
        // Ensure view state exists (may not exist after crash recovery)
        let state = self.ensure_view(view);

        // Check if we can send a nullify vote
        let (is_retry, nullify) = match *state.phase() {
            Phase::Idle => {
                // First-time nullify - use normal flow
                let nullify = self.sign_and_track_nullify(view);
                if nullify.is_some() {
                    self.ensure_view(view).nullify();
                    self.ensure_view(view).mark_broadcast_nullify();
                }
                (false, nullify)
            }
            Phase::Nullified => {
                // Already nullified but need to retry (e.g., after crash recovery).
                // Re-sign and broadcast the nullify vote. This is safe because
                // we're sending the same vote, just retrying the broadcast.
                let nullify = Nullify::sign::<D>(&self.scheme, Round::new(self.epoch, view));
                if let Some(ref n) = nullify {
                    // Ensure our vote is tracked (may not be after crash recovery with replay)
                    self.ensure_tracker(view).insert_nullify(n.clone());
                }
                (true, nullify)
            }
            Phase::Voted { .. } => {
                // Already voted for a proposal - cannot nullify via timeout.
                // (Condition (b) nullification is handled separately via contradiction detection)
                (false, None)
            }
        };

        // On retry, get entry certificate for the previous view to help lagging nodes.
        // Prefer finalization > nullification > M-notarization (strongest to weakest proof).
        let entry_certificate = if is_retry {
            let entry_view = view.previous();
            if let Some(entry_view) = entry_view {
                if let Some(finalization) = self.ancestry.finalization(entry_view) {
                    Some(Certificate::Finalization(finalization.clone()))
                } else if let Some(nullification) = self.ancestry.nullification(entry_view) {
                    Some(Certificate::Nullification(nullification.clone()))
                } else {
                    self.ancestry
                        .any_m_notarization(entry_view)
                        .map(|m_not| Certificate::MNotarization(m_not.clone()))
                }
            } else {
                None
            }
        } else {
            None
        };

        TimeoutResult {
            is_retry,
            nullify,
            entry_certificate,
        }
    }

    /// Signs a nullify vote and inserts it into our tracker.
    fn sign_and_track_nullify(&mut self, view: View) -> Option<Nullify<S>> {
        let vote = Nullify::sign::<D>(&self.scheme, Round::new(self.epoch, view))?;
        self.ensure_tracker(view).insert_nullify(vote.clone());
        Some(vote)
    }

    fn ensure_view(&mut self, view: View) -> &mut ViewState<D> {
        self.views.entry(view).or_default()
    }

    fn ensure_tracker(&mut self, view: View) -> &mut VoteTracker<S, D> {
        self.trackers
            .entry(view)
            .or_insert_with(|| VoteTracker::new(self.participants as usize))
    }

    /// Signs a notarize vote and inserts it into our tracker.
    ///
    /// This ensures that our own vote is counted when building certificates.
    fn sign_and_track_notarize(&mut self, proposal: Proposal<D>) -> Option<Notarize<S, D>> {
        let vote = Notarize::sign(&self.scheme, proposal)?;
        let view = vote.view();
        self.ensure_tracker(view).insert_notarize(vote.clone());
        Some(vote)
    }

    fn maybe_vote_for_proposal(&mut self, proposal: &Proposal<D>) -> Vec<Action<S, D>> {
        let view = proposal.view();
        if view != self.view {
            return Vec::new();
        }
        if !self
            .ancestry
            .is_proposal_valid(proposal, self.last_finalized)
        {
            return Vec::new();
        }
        self.try_vote_for_notarization(view, proposal.clone())
            .into_iter()
            .collect()
    }

    /// Attempts to vote for a notarization on the given proposal.
    ///
    /// This is the core voting logic shared between:
    /// - Normal proposal voting (via maybe_vote_for_proposal)
    /// - Section 6.1 voting for past M-notarizations (via handle_view_progress)
    ///
    /// Returns a BroadcastNotarize action if we successfully voted.
    fn try_vote_for_notarization(
        &mut self,
        view: View,
        proposal: Proposal<D>,
    ) -> Option<Action<S, D>> {
        // Check if we can vote: true if no ViewState exists (never touched this view)
        // or if ViewState exists and we haven't voted/nullified yet
        let can_vote = self.views.get(&view).is_none_or(|state| state.can_vote());
        if !can_vote {
            return None;
        }
        let vote = self.sign_and_track_notarize(proposal.clone())?;
        let state = self.ensure_view(view);
        if state.vote(proposal.payload) && state.mark_broadcast_notarize() {
            Some(Action::BroadcastNotarize(vote))
        } else {
            None
        }
    }

    fn should_nullify_by_contradiction(&self, view: View) -> bool {
        let state = match self.views.get(&view) {
            Some(state) => state,
            None => return false,
        };
        if !state.can_nullify_condition_b() || state.broadcast_nullify() {
            return false;
        }
        if view != self.view {
            return false;
        }
        let Phase::Voted { digest } = *state.phase() else {
            return false;
        };
        let tracker = match self.trackers.get(&view) {
            Some(tracker) => tracker,
            None => return false,
        };
        let voted_proposal = self.voted_proposal(view);
        let mut signers = BTreeSet::new();
        for notarize in tracker.iter_notarizes() {
            let contradicts = voted_proposal.as_ref().map_or_else(
                || notarize.proposal.payload != digest,
                |voted_proposal| notarize.proposal != *voted_proposal,
            );
            if contradicts {
                signers.insert(notarize.attestation.signer);
            }
        }
        for nullify in tracker.iter_nullifies() {
            signers.insert(nullify.attestation.signer);
        }
        u32::try_from(signers.len()).expect("signer count") >= M5f1::quorum(self.participants)
    }

    /// Nullifies by contradiction when receiving an M-notarization certificate for a
    /// different proposal than what we voted for.
    ///
    /// This is condition (b) nullification triggered by certificate evidence rather than
    /// individual votes. An M-notarization proves that M-quorum (2f+1) validators voted
    /// for a different proposal, which is sufficient contradiction evidence.
    ///
    fn nullify_by_certificate_contradiction(
        &mut self,
        view: View,
        certificate_proposal: &Proposal<D>,
    ) -> Option<Action<S, D>> {
        if view != self.view {
            return None;
        }
        // Check if we voted for a different proposal
        let state = self.views.get(&view)?;
        let Phase::Voted { digest } = *state.phase() else {
            return None;
        };

        // If we voted for the same proposal, no contradiction.
        let same_proposal = self.voted_proposal(view).map_or_else(
            || digest == certificate_proposal.payload,
            |voted_proposal| voted_proposal == *certificate_proposal,
        );
        if same_proposal {
            return None;
        }

        // We voted for a different proposal - emit nullify
        self.broadcast_nullify(view)
    }

    fn broadcast_nullify(&mut self, view: View) -> Option<Action<S, D>> {
        let nullify = Nullify::sign::<D>(&self.scheme, Round::new(self.epoch, view))?;
        // Track our own nullify vote so it's counted when building certificates
        self.ensure_tracker(view).insert_nullify(nullify.clone());
        let state = self.ensure_view(view);
        if !state.nullify() {
            return None;
        }
        if !state.mark_broadcast_nullify() {
            return None;
        }
        Some(Action::BroadcastNullify(nullify))
    }

    fn build_notarize_certificate(
        &self,
        view: View,
        proposal: &Proposal<D>,
        strategy: &impl Strategy,
    ) -> Option<Certificate<S, D>> {
        let tracker = self.trackers.get(&view)?;
        let votes: Vec<_> = tracker
            .iter_notarizes()
            .filter(|v| v.proposal == *proposal)
            .collect();

        if votes.len() >= N5f1::l_quorum(self.participants) as usize {
            let finalization =
                Finalization::from_notarizes(&self.scheme, votes.iter().copied(), strategy)?;
            return Some(Certificate::Finalization(finalization));
        }

        if votes.len() >= M5f1::quorum(self.participants) as usize {
            let notarization =
                MNotarization::from_notarizes(&self.scheme, votes.iter().copied(), strategy)?;
            return Some(Certificate::MNotarization(notarization));
        }

        None
    }

    fn build_nullification_certificate(
        &self,
        view: View,
        strategy: &impl Strategy,
    ) -> Option<Certificate<S, D>> {
        let tracker = self.trackers.get(&view)?;
        let votes: Vec<_> = tracker.iter_nullifies().collect();
        if votes.len() < M5f1::quorum(self.participants) as usize {
            return None;
        }
        let nullification =
            Nullification::from_nullifies(&self.scheme, votes.iter().copied(), strategy)?;
        Some(Certificate::Nullification(nullification))
    }

    fn process_certificate(
        &mut self,
        certificate: Certificate<S, D>,
        should_broadcast: bool,
    ) -> Vec<Action<S, D>> {
        let view = certificate.view();

        // For non-M-notarization certificates, skip if we've already processed
        if should_broadcast {
            if let Some(state) = self.views.get(&view) {
                if state.has_certificate(&certificate)
                    && !matches!(certificate, Certificate::MNotarization(_))
                {
                    return Vec::new();
                }
            }
        }

        let mut actions = Vec::new();

        match certificate {
            Certificate::MNotarization(m_not) => {
                let inserted = self.ancestry.add_m_notarization(m_not.clone());
                if inserted {
                    self.last_seen_notarization = self.last_seen_notarization.max(m_not.view());
                }
                let proposal = m_not.proposal.clone();
                let cert = m_not.certificate.clone();
                if should_broadcast {
                    let broadcasted = {
                        let state = self.ensure_view(view);
                        state.mark_broadcast_m_notarization(proposal.payload)
                    };
                    if broadcasted {
                        actions.push(Action::BroadcastCertificate(Certificate::MNotarization(
                            m_not,
                        )));
                    }
                }
                actions.extend(self.handle_view_progress(view, Some(proposal), true, cert));
            }
            Certificate::Nullification(nullification) => {
                let inserted = self.ancestry.add_nullification(nullification.clone());
                if inserted {
                    let cert = nullification.certificate.clone();
                    if should_broadcast {
                        let broadcasted = {
                            let state = self.ensure_view(view);
                            state.mark_broadcast_nullification()
                        };
                        if broadcasted {
                            actions.push(Action::BroadcastCertificate(Certificate::Nullification(
                                nullification,
                            )));
                        }
                    }
                    actions.extend(self.handle_view_progress(view, None, false, cert));
                }
            }
            Certificate::Finalization(finalization) => {
                let inserted = self.ancestry.add_finalization(finalization.clone());
                if inserted {
                    self.last_seen_notarization = self.last_seen_notarization.max(view);
                    if view > self.last_finalized {
                        self.last_finalized = view;
                    }
                    let cert = finalization.certificate.clone();
                    // Per the Minimmit paper (Algorithm 1, lines 431-433):
                    // "Since it is not necessary for liveness, our pseudocode does not
                    // require processors to forward L-notarisations."
                    // Unlike M-notarizations and Nullifications, Finalizations are NOT
                    // broadcast. Each node reaches L-quorum independently by collecting
                    // votes. Broadcasting would create O(n^2) unnecessary messages.
                    actions.push(Action::Finalized(finalization.clone()));
                    actions.extend(self.handle_view_progress(
                        view,
                        Some(finalization.proposal),
                        false,
                        cert,
                    ));
                    self.prune();
                }
            }
        }

        actions
    }

    fn handle_view_progress(
        &mut self,
        view: View,
        proposal: Option<Proposal<D>>,
        is_m_notarization: bool,
        certificate: S::Certificate,
    ) -> Vec<Action<S, D>> {
        let mut actions = Vec::new();

        // Vote2 rule (Algorithm 1, line 22): When we receive an M-notarization, the
        // M-notarization itself proves validity because at least f+1 honest nodes
        // already verified and voted for the block. We can vote without local
        // ancestry verification.
        //
        // Paper Section 3: "the fact that b has already received an M-notarisation
        // means that some correct processors have already voted for b, so it is safe
        // for p_i to do the same."
        //
        // Section 6.1: For past views v'' < current view, we must also vote on M-nots
        // to ensure the block reaches L-quorum for finalization.
        //
        // This is critical for liveness: if a processor advances to the next view
        // before receiving ancestry (due to out-of-order message delivery), they
        // would otherwise never vote. Since the batcher de-duplicates M-nots, the
        // processor wouldn't get another chance to vote when ancestry arrives.

        if is_m_notarization {
            if let Some(ref proposal) = proposal {
                actions.extend(self.try_vote_for_notarization(view, proposal.clone()));
            }
        }

        if view < self.view {
            // Past view certificate: process local catch-up only.
            return actions;
        }

        // Condition (b) nullification via M-notarization certificate:
        // If we voted for a different proposal than this M-notarization, the certificate
        // proves M-quorum exists for another proposal. Our vote can't lead to finalization,
        // so we should nullify. This complements the vote-based contradiction check in
        // should_nullify_by_contradiction() by handling certificates received directly
        // (e.g., from another partition that already formed the M-notarization).
        if let Some(ref proposal) = proposal {
            actions.extend(self.nullify_by_certificate_contradiction(view, proposal));
        }

        let next_view = view.next();
        if next_view > self.view {
            self.view = next_view;
            // Store the certificate that caused this view advance
            // This is used by electors like `Random` to derive randomness
            self.advancing_certificate = Some(certificate);
            self.ensure_view(next_view);
            actions.push(Action::Advanced(next_view));
        }

        actions
    }

    fn voted_proposal(&self, view: View) -> Option<Proposal<D>> {
        let me = self.me?;
        self.trackers
            .get(&view)?
            .notarize(me)
            .map(|n| n.proposal.clone())
    }

    /// Replays a journaled artifact into state during crash recovery.
    ///
    /// This updates internal state to reflect actions we already took before
    /// the crash, preventing double-voting and double-broadcasting.
    ///
    /// # Errors
    ///
    /// Returns an error if the artifact is from a different signer than expected.
    /// This can indicate a corrupt journal or configuration mismatch.
    pub fn replay(&mut self, artifact: &Artifact<S, D>) -> Result<(), ReplayError> {
        let view = artifact.view();
        match artifact {
            Artifact::Notarize(notarize) => {
                // Verify this is our vote
                if let Some(me) = self.me {
                    let signer = notarize.signer();
                    if signer != me {
                        return Err(ReplayError::WrongNotarizeSigner {
                            expected: me,
                            got: signer,
                        });
                    }
                }
                // Update view state to reflect we already voted
                self.ensure_view(view).replay_notarize(notarize);
                // Add to tracker
                self.ensure_tracker(view).insert_notarize(notarize.clone());
            }
            Artifact::MNotarization(m_notarization) => {
                // Add to ancestry
                self.ancestry.add_m_notarization(m_notarization.clone());
                self.last_seen_notarization = self.last_seen_notarization.max(view);
                // Update view state to reflect we already broadcast this certificate
                self.ensure_view(view)
                    .replay_certificate(&Certificate::MNotarization(m_notarization.clone()));
                // Advance view if needed
                let next_view = view.next();
                if next_view > self.view {
                    self.view = next_view;
                    self.advancing_certificate = Some(m_notarization.certificate.clone());
                    self.ensure_view(next_view);
                }
            }
            Artifact::Nullify(nullify) => {
                // Verify this is our vote
                if let Some(me) = self.me {
                    let signer = nullify.signer();
                    if signer != me {
                        return Err(ReplayError::WrongNullifySigner {
                            expected: me,
                            got: signer,
                        });
                    }
                }
                // Update view state to reflect we already nullified
                self.ensure_view(view).replay_nullify();
                // Add to tracker
                self.ensure_tracker(view).insert_nullify(nullify.clone());
            }
            Artifact::Nullification(nullification) => {
                // Add to ancestry
                self.ancestry.add_nullification(nullification.clone());
                // Update view state to reflect we already broadcast this certificate
                self.ensure_view(view)
                    .replay_certificate(&Certificate::Nullification(nullification.clone()));
                // Advance view if needed
                let next_view = view.next();
                if next_view > self.view {
                    self.view = next_view;
                    self.advancing_certificate = Some(nullification.certificate.clone());
                    self.ensure_view(next_view);
                }
            }
            Artifact::Finalization(finalization) => {
                // Add to ancestry
                self.ancestry.add_finalization(finalization.clone());
                self.last_seen_notarization = self.last_seen_notarization.max(view);
                if view > self.last_finalized {
                    self.last_finalized = view;
                }
                // Update view state to reflect we already broadcast this certificate
                self.ensure_view(view)
                    .replay_certificate(&Certificate::Finalization(finalization.clone()));
                // Advance view if needed
                let next_view = view.next();
                if next_view > self.view {
                    self.view = next_view;
                    self.advancing_certificate = Some(finalization.certificate.clone());
                    self.ensure_view(next_view);
                }
                // Prune old state
                self.prune();
            }
        }
        Ok(())
    }

    fn prune(&mut self) {
        let min_view = self.last_finalized;
        self.views.retain(|v, _| *v >= min_view);
        self.trackers.retain(|v, _| *v >= min_view);
        self.ancestry.prune_before(min_view);
    }

    /// Returns our vote for the current view, if any.
    ///
    /// After crash recovery, we need to re-broadcast our vote so other nodes
    /// can receive it and build certificates. This returns our notarize or
    /// nullify vote from the tracker for the current view.
    pub fn our_vote_for_current_view(&self) -> Option<Vote<S, D>> {
        let me = self.me?;
        let tracker = self.trackers.get(&self.view)?;

        // Check for notarize first
        if let Some(notarize) = tracker.notarize(me) {
            return Some(Vote::Notarize(notarize.clone()));
        }

        // Check for nullify
        if let Some(nullify) = tracker.nullify(me) {
            return Some(Vote::Nullify(nullify.clone()));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        elector::{Config as ElectorConfig, RoundRobin, RoundRobinElector},
        minimmit::scheme::ed25519,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, Scheme as CertificateScheme},
        sha256::Digest as Sha256Digest,
        Sha256,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    type Scheme = ed25519::Scheme;

    fn setup_state() -> (
        State<Scheme, Sha256Digest, RoundRobinElector<Scheme>>,
        Vec<Scheme>,
        rand::rngs::StdRng,
    ) {
        let mut rng = test_rng();
        let namespace = b"minimmit";
        let Fixture { schemes, .. } = ed25519::fixture(&mut rng, namespace, 6);
        let elector = RoundRobin::<Sha256>::default().build(schemes[0].participants());
        let state = State::new(
            Epoch::new(1),
            schemes[0].clone(),
            elector,
            Sha256Digest::from([0u8; 32]),
        );
        (state, schemes, rng)
    }

    #[test]
    fn leader_proposes_once() {
        let (mut state, _schemes, _rng) = setup_state();
        let action = state.try_propose();
        assert!(action.is_none());
        let action_again = state.try_propose();
        assert!(action_again.is_none());
    }

    #[test]
    fn m_notarization_advances_view() {
        let (mut state, schemes, mut rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([1u8; 32]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let mut actions = Vec::new();
        for vote in notarizes {
            actions.extend(state.receive_notarize(&mut rng, vote, &Sequential));
        }
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::Advanced(view) if *view == View::new(2))));
        assert_eq!(state.view(), View::new(2));
    }

    #[test]
    fn vote_on_m_notarization_before_advance() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([2u8; 32]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential).unwrap();
        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::BroadcastNotarize(_))));
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::Advanced(view) if *view == View::new(2))));
    }

    #[test]
    fn nullify_by_contradiction() {
        let (mut state, schemes, mut rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([3u8; 32]),
        );
        // Epoch 1, View 1's leader is Participant 2: (1 + 1) % 6 = 2
        state.receive_proposal(Participant::new(2), proposal.clone());
        let actions = state.proposal_verified(proposal, true);
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::BroadcastNotarize(_))));

        let conflicting = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([4u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, conflicting.clone()).unwrap())
            .collect();
        let mut saw_nullify = false;
        for vote in votes {
            let actions = state.receive_notarize(&mut rng, vote, &Sequential);
            if actions
                .iter()
                .any(|action| matches!(action, Action::BroadcastNullify(_)))
            {
                saw_nullify = true;
            }
        }
        assert!(saw_nullify);
    }

    #[test]
    fn finalization_blocks_nullification() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([5u8; 32]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .take(5)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential).unwrap();
        let actions = state.receive_certificate(Certificate::Finalization(finalization));
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::Finalized(_))));

        let nullifies: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential).unwrap();
        let actions = state.receive_certificate(Certificate::Nullification(nullification));
        assert!(actions.is_empty());
    }

    #[test]
    fn view_skipping_on_future_notarization() {
        let (mut state, schemes, _rng) = setup_state();
        // For view 3 with parent view 2, we need a parent_payload for view 2
        let parent_payload = Sha256Digest::from([2u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(3)),
            View::new(2),
            parent_payload,
            Sha256Digest::from([6u8; 32]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential).unwrap();
        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));
        assert!(actions
            .iter()
            .any(|action| matches!(action, Action::Advanced(view) if *view == View::new(4))));
        assert_eq!(state.view(), View::new(4));
    }

    #[test]
    fn timeout_emits_nullify() {
        let (mut state, _schemes, _rng) = setup_state();
        let result = state.handle_timeout();
        assert!(!result.is_retry, "First timeout should not be a retry");
        assert!(
            result.nullify.is_some(),
            "First timeout should emit nullify"
        );
        assert!(
            result.entry_certificate.is_none(),
            "First timeout should not emit entry cert"
        );
    }

    // =============================================================================
    // Regression Tests for Bugs Found in Review
    // =============================================================================

    /// Regression test for BUG #1: broadcast_nullify doesn't track own vote.
    ///
    /// When a node broadcasts a nullify and then receives 2f more nullifies from others,
    /// it should be able to build a nullification certificate (total 2f+1 including its own).
    /// If the node's own nullify isn't tracked, it can only see 2f votes and can't build
    /// the certificate at the quorum boundary.
    #[test]
    fn regression_nullify_self_vote_tracked_for_certificate() {
        let (mut state, schemes, mut rng) = setup_state();

        // First, broadcast our own nullify via timeout
        let result = state.handle_timeout();
        assert!(
            result.nullify.is_some(),
            "Should broadcast nullify on timeout"
        );

        // Now receive exactly 2 more nullifies (for a total of 3 = 2f+1 with n=6, f=1)
        // We need M-quorum = 2f+1 = 3 for nullification
        let nullifies: Vec<_> = schemes
            .iter()
            .skip(1) // Skip our own scheme (index 0)
            .take(2) // Take 2 more
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();

        let mut saw_nullification_cert = false;
        for nullify in nullifies {
            let actions = state.receive_nullify(&mut rng, nullify, &Sequential);
            if actions.iter().any(|a| {
                matches!(
                    a,
                    Action::BroadcastCertificate(Certificate::Nullification(_))
                )
            }) {
                saw_nullification_cert = true;
            }
        }

        assert!(
            saw_nullification_cert,
            "Should build nullification certificate when own nullify + 2 others = 2f+1"
        );
    }

    /// Test for vote2 rule: voting on M-notarization without local ancestry check.
    ///
    /// Per Algorithm 1 line 22 and Section 3 of the paper, when we receive an
    /// M-notarization for any view (past or current), we should vote WITHOUT
    /// re-verifying ancestry locally. The M-notarization itself proves validity
    /// because at least f+1 honest nodes already verified and voted.
    ///
    /// This is critical for liveness: if a processor advances without voting
    /// (due to missing ancestry at the time), the batcher's de-duplication would
    /// prevent them from voting later. By trusting the M-not, we ensure all
    /// correct processors vote and the block reaches L-quorum.
    ///
    /// The test setup:
    /// 1. Advance to view 3 via nullifications (so we never voted in view 1 or 2)
    /// 2. Receive an M-notarization for view 2 (simulating out-of-order delivery)
    /// 3. Should vote because M-notarization proves validity (vote2 rule)
    #[test]
    fn vote2_rule_trusts_m_notarization() {
        let (mut state, schemes, _rng) = setup_state();

        // Advance to view 2 via nullification for view 1 (we don't vote in view 1)
        let nullifies_v1: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();
        let nullification_v1 =
            Nullification::from_nullifies(&schemes[0], nullifies_v1.iter(), &Sequential).unwrap();
        let actions = state.receive_certificate(Certificate::Nullification(nullification_v1));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(2))),
            "Should advance to view 2"
        );

        // Advance to view 3 via nullification for view 2 (we don't vote in view 2)
        let nullifies_v2: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(2)))
                    .unwrap()
            })
            .collect();
        let nullification_v2 =
            Nullification::from_nullifies(&schemes[0], nullifies_v2.iter(), &Sequential).unwrap();
        let actions = state.receive_certificate(Certificate::Nullification(nullification_v2));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(3))),
            "Should advance to view 3"
        );
        assert_eq!(state.view(), View::new(3));

        // Now we're at view 3 and haven't voted in view 2.
        // Create an M-notarization for view 2 with INVALID ancestry
        // (claims a parent_payload that doesn't exist - view 1 was nullified, not notarized)
        let fake_parent_payload = Sha256Digest::from([0xFFu8; 32]); // This doesn't exist in ancestry
        let invalid_proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(2)),
            View::new(1),        // Claims parent is view 1
            fake_parent_payload, // But this payload doesn't exist for view 1
            Sha256Digest::from([2u8; 32]),
        );

        // Create an M-notarization for this proposal (simulating Byzantine behavior)
        let invalid_notarizes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, invalid_proposal.clone()).unwrap())
            .collect();
        let invalid_m_notarization =
            MNotarization::from_notarizes(&schemes[1], invalid_notarizes.iter(), &Sequential)
                .unwrap();

        // Receive this M-notarization for a PAST view (view 2 < view 3)
        // Per Section 6.1 and the vote2 rule (Algorithm 1, line 22), we SHOULD vote
        // because the M-notarization proves validity - at least f+1 honest nodes
        // already verified and voted for the block.
        //
        // Paper Section 3: "the fact that b has already received an M-notarisation
        // means that some correct processors have already voted for b, so it is safe
        // for p_i to do the same."
        //
        // Note: In practice, an M-not with truly invalid ancestry cannot exist because
        // honest nodes verify ancestry before voting. This test simulates an impossible
        // scenario to document the vote2 behavior.
        let actions = state.receive_certificate(Certificate::MNotarization(invalid_m_notarization));

        // We SHOULD vote because the M-notarization proves validity (vote2 rule)
        let voted = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNotarize(_)));
        assert!(
            voted,
            "Should vote on M-notarization per vote2 rule (M-not proves validity)"
        );
    }

    /// Regression test for BUG #3: Timeout blocked when view state missing.
    ///
    /// This test verifies that timeout-nullification works after advancing via certificate.
    /// Note: The implementation correctly creates view state when advancing (via ensure_view),
    /// so this test documents the expected behavior.
    #[test]
    fn regression_timeout_works_after_certificate_advance() {
        let (mut state, schemes, _rng) = setup_state();

        // Advance to view 2 via nullification
        let nullifies: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential).unwrap();
        let actions = state.receive_certificate(Certificate::Nullification(nullification));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(2))),
            "Should advance to view 2"
        );
        assert_eq!(state.view(), View::new(2));

        // Timeout should work for view 2 (view state should exist)
        let result = state.handle_timeout();
        assert!(
            result.nullify.is_some(),
            "Should be able to timeout-nullify in view 2 after advancing via certificate"
        );
    }

    /// Regression test: Ensure own nullify is counted toward contradiction check.
    ///
    /// When checking condition (b) for nullification (2f+1 contradicting messages),
    /// we should count our own nullify vote if we've already sent one.
    #[test]
    fn regression_contradiction_counts_own_nullify() {
        let (mut state, schemes, mut rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // First, vote for a proposal
        let proposal_a = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );
        state.receive_proposal(Participant::new(2), proposal_a.clone());
        let actions = state.proposal_verified(proposal_a, true);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNotarize(_))),
            "Should vote for proposal A"
        );

        // Now receive votes for a DIFFERENT proposal (triggers condition b)
        let proposal_b = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xBBu8; 32]),
        );

        // Receive 3 votes for proposal B (meets M-quorum threshold for contradiction)
        let mut saw_nullify = false;
        for scheme in schemes.iter().skip(1).take(3) {
            let vote = Notarize::sign(scheme, proposal_b.clone()).unwrap();
            let actions = state.receive_notarize(&mut rng, vote, &Sequential);
            if actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNullify(_)))
            {
                saw_nullify = true;
            }
        }

        assert!(
            saw_nullify,
            "Should nullify via condition (b) after seeing M-quorum for different block"
        );
    }

    /// Test: M-notarization certificate for different proposal triggers nullify (current view).
    ///
    /// When we've voted for proposal A and receive an M-notarization certificate for
    /// proposal B, we should emit a nullify. This is condition (b) nullification via
    /// certificate evidence rather than individual votes.
    #[test]
    fn nullify_by_certificate_contradiction_current_view() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Vote for proposal A
        let proposal_a = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );
        // Epoch 1, View 1's leader is Participant 2
        state.receive_proposal(Participant::new(2), proposal_a.clone());
        let actions = state.proposal_verified(proposal_a, true);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNotarize(_))),
            "Should vote for proposal A"
        );

        // Receive M-notarization certificate for different proposal B
        let proposal_b = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xBBu8; 32]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_b.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[1], notarizes.iter(), &Sequential).unwrap();

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));

        // Should emit nullify due to contradiction
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNullify(_))),
            "Should nullify when receiving M-notarization for different proposal"
        );
    }

    /// Regression test: contradiction detection must compare the full proposal,
    /// not just payload digest.
    ///
    /// If two proposals share the same payload but have different parents, they are
    /// still distinct proposals. Receiving an M-notarization for the distinct proposal
    /// after voting should trigger condition (b) nullification.
    #[test]
    fn nullify_by_certificate_contradiction_same_payload_different_parent() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let payload = Sha256Digest::from([0xCCu8; 32]);

        // Vote for proposal A.
        let proposal_a = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            payload,
        );
        state.receive_proposal(Participant::new(2), proposal_a.clone());
        let actions = state.proposal_verified(proposal_a, true);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNotarize(_))),
            "Should vote for proposal A"
        );

        // Receive M-notarization for proposal B with the same payload but different parent payload.
        let proposal_b = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            Sha256Digest::from([0x11u8; 32]),
            payload,
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_b.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[1], notarizes.iter(), &Sequential).unwrap();

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNullify(_))),
            "Should nullify when receiving M-notarization for a distinct proposal with same payload"
        );
    }

    /// Test: M-notarization certificate for same proposal does NOT trigger nullify.
    ///
    /// When we've voted for proposal A and receive an M-notarization for the same
    /// proposal A, there's no contradiction - we should NOT nullify.
    #[test]
    fn no_nullify_by_certificate_same_proposal() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Vote for proposal A
        let proposal_a = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );
        state.receive_proposal(Participant::new(2), proposal_a.clone());
        let actions = state.proposal_verified(proposal_a.clone(), true);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNotarize(_))),
            "Should vote for proposal A"
        );

        // Receive M-notarization certificate for SAME proposal A
        let notarizes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_a.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[1], notarizes.iter(), &Sequential).unwrap();

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));

        // Should NOT emit nullify (no contradiction)
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNullify(_))),
            "Should NOT nullify when receiving M-notarization for same proposal we voted for"
        );
    }

    /// Test: M-notarization certificate for different proposal does not nullify (past view).
    ///
    /// After we've advanced past a view, receiving an M-notarization for a
    /// different proposal should not trigger nullify for that past view.
    #[test]
    fn no_nullify_by_certificate_contradiction_past_view() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Vote for proposal A in view 1
        let proposal_a = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );
        state.receive_proposal(Participant::new(2), proposal_a.clone());
        let actions = state.proposal_verified(proposal_a.clone(), true);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNotarize(_))),
            "Should vote for proposal A"
        );

        // Advance to view 2 via M-notarization for proposal A
        let notarizes_a: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_a.clone()).unwrap())
            .collect();
        let m_notarization_a =
            MNotarization::from_notarizes(&schemes[1], notarizes_a.iter(), &Sequential).unwrap();
        state.receive_certificate(Certificate::MNotarization(m_notarization_a));
        assert_eq!(state.view(), View::new(2), "Should have advanced to view 2");

        // Now receive M-notarization for DIFFERENT proposal B in view 1 (past view)
        let proposal_b = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xBBu8; 32]),
        );
        let notarizes_b: Vec<_> = schemes
            .iter()
            .skip(2)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_b.clone()).unwrap())
            .collect();
        let m_notarization_b =
            MNotarization::from_notarizes(&schemes[2], notarizes_b.iter(), &Sequential).unwrap();

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization_b));

        // Should NOT emit nullify for past view due to contradiction
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNullify(_))),
            "Should NOT nullify when receiving M-notarization for different proposal in past view"
        );
    }

    /// Test: M-notarization certificate for same proposal in past view does NOT trigger nullify.
    #[test]
    fn no_nullify_by_certificate_same_proposal_past_view() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Vote for proposal A in view 1
        let proposal_a = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );
        state.receive_proposal(Participant::new(2), proposal_a.clone());
        state.proposal_verified(proposal_a.clone(), true);

        // Advance to view 2 via nullification (so we don't receive M-not for A yet)
        let nullifies: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential).unwrap();
        state.receive_certificate(Certificate::Nullification(nullification));
        assert_eq!(state.view(), View::new(2), "Should have advanced to view 2");

        // Now receive M-notarization for SAME proposal A in view 1 (past view)
        let notarizes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_a.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[1], notarizes.iter(), &Sequential).unwrap();

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));

        // Should NOT emit nullify (no contradiction - same proposal)
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNullify(_))),
            "Should NOT nullify when receiving M-notarization for same proposal in past view"
        );
    }

    /// Test: M-notarization when not voted yet triggers vote, not nullify.
    ///
    /// When we haven't voted in a view and receive an M-notarization, we should
    /// vote for it (Vote2 rule), not nullify.
    #[test]
    fn m_notarization_triggers_vote_when_not_voted() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Receive M-notarization without having voted first
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[1], notarizes.iter(), &Sequential).unwrap();

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));

        // Should emit vote (Vote2 rule), not nullify
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNotarize(_))),
            "Should vote for M-notarization when not yet voted (Vote2 rule)"
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::BroadcastNullify(_))),
            "Should NOT nullify when not yet voted"
        );
    }

    /// Verify that proposals for past views don't trigger votes.
    ///
    /// When we receive and verify a proposal for a view we've already passed,
    /// we should not vote for it.
    #[test]
    fn past_view_proposal_no_vote() {
        let (mut state, schemes, _rng) = setup_state();

        // Advance to view 2 via nullification
        let nullifies: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential).unwrap();
        state.receive_certificate(Certificate::Nullification(nullification));
        assert_eq!(state.view(), View::new(2));

        // Now receive and verify a proposal for view 1 (past view)
        let genesis = Sha256Digest::from([0u8; 32]);
        let past_proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );

        // Epoch 1, View 1's leader is Participant 2
        state.receive_proposal(Participant::new(2), past_proposal.clone());
        let actions = state.proposal_verified(past_proposal, true);

        // Should NOT vote for past view proposal
        let voted = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNotarize(_)));
        assert!(
            !voted,
            "Should NOT vote for proposal from past view (view 1 < current view 2)"
        );
    }

    #[test]
    fn receive_proposal_rejects_non_current_views() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Proposal for a future view must be rejected at ingress.
        let future = Proposal::new(
            Round::new(Epoch::new(1), View::new(2)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xCAu8; 32]),
        );
        let future_actions = state.receive_proposal(Participant::new(3), future);
        assert!(
            future_actions.is_empty(),
            "future proposals must be ignored"
        );

        // Advance to view 2 via a nullification at view 1.
        let nullifies: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential).unwrap();
        state.receive_certificate(Certificate::Nullification(nullification));
        assert_eq!(state.view(), View::new(2));

        // Proposal for a past view must also be rejected at ingress.
        let past = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xCBu8; 32]),
        );
        let past_actions = state.receive_proposal(Participant::new(2), past);
        assert!(past_actions.is_empty(), "past proposals must be ignored");
    }

    #[test]
    fn late_ancestry_retries_pending_proposal_verification() {
        let (mut state, schemes, _rng) = setup_state();

        let nullifies_v1: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .expect("nullify")
            })
            .collect();
        let nullification_v1 =
            Nullification::from_nullifies(&schemes[0], nullifies_v1.iter(), &Sequential)
                .expect("nullification");
        let actions = state.receive_certificate(Certificate::Nullification(nullification_v1));
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(2))),
            "should advance to view 2"
        );

        let parent_payload = Sha256Digest::from([0x11u8; 32]);
        let proposal_v2 = Proposal::new(
            Round::new(Epoch::new(1), View::new(2)),
            View::new(1),
            parent_payload,
            Sha256Digest::from([0x22u8; 32]),
        );
        let leader_v2 = state.leader(View::new(2), None);
        let actions = state.receive_proposal(leader_v2, proposal_v2.clone());
        assert!(
            actions.iter().any(
                |a| matches!(a, Action::VerifyProposal(p) if p.payload == proposal_v2.payload)
            ),
            "proposal should enter verification"
        );

        let actions = state.proposal_verified(proposal_v2.clone(), false);
        assert!(
            actions.is_empty(),
            "invalid verification should emit no actions"
        );

        let proposal_v1 = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            Sha256Digest::from([0u8; 32]),
            parent_payload,
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .skip(1)
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_v1.clone()).expect("notarize"))
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential)
                .expect("m-notarization");

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));
        assert!(
            actions.iter().any(
                |a| matches!(a, Action::VerifyProposal(p) if p.view() == View::new(2) && p.payload == proposal_v2.payload)
            ),
            "late ancestry should trigger verification retry for pending proposal"
        );
    }

    /// Verify safety invariant: equivocating leader cannot cause double-voting.
    ///
    /// When a Byzantine leader sends two different proposals for the same view,
    /// an honest node must only vote for one. The Phase::Voted state prevents
    /// voting for additional proposals after the first vote.
    #[test]
    fn equivocating_leader_single_vote_only() {
        let (mut state, _schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Leader sends proposal A
        let proposal_a = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xAAu8; 32]),
        );

        // Leader sends proposal B (equivocation - different payload)
        let proposal_b = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([0xBBu8; 32]),
        );

        // Both proposals accepted (stored in view state)
        // Epoch 1, View 1's leader is Participant 2: (1 + 1) % 6 = 2
        state.receive_proposal(Participant::new(2), proposal_a.clone());
        state.receive_proposal(Participant::new(2), proposal_b.clone());

        // Verify first proposal - should trigger vote
        let actions_a = state.proposal_verified(proposal_a, true);
        let voted_a = actions_a
            .iter()
            .any(|a| matches!(a, Action::BroadcastNotarize(_)));
        assert!(voted_a, "Should vote for first verified proposal");

        // Verify second proposal - should NOT trigger another vote
        let actions_b = state.proposal_verified(proposal_b, true);
        let voted_b = actions_b
            .iter()
            .any(|a| matches!(a, Action::BroadcastNotarize(_)));
        assert!(
            !voted_b,
            "Should NOT vote for second proposal (already voted in this view)"
        );
    }

    /// Verify that advancing_certificate is stored when advancing views.
    ///
    /// This is critical for electors like `Random` that derive randomness
    /// from certificates. The certificate that caused the view advance
    /// should be available for leader election in the new view.
    #[test]
    fn advancing_certificate_stored_on_view_advance() {
        let (mut state, schemes, _rng) = setup_state();

        // Initially at view 1, no advancing certificate
        assert_eq!(state.view(), View::new(1));
        assert!(
            state.advancing_certificate.is_none(),
            "View 1 should have no advancing certificate"
        );

        // Advance to view 2 via M-notarization
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([1u8; 32]),
        );
        let notarizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential).unwrap();
        let expected_cert = m_notarization.certificate.clone();

        let actions = state.receive_certificate(Certificate::MNotarization(m_notarization));

        // Should have advanced and stored the certificate
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, Action::Advanced(v) if *v == View::new(2))),
            "Should advance to view 2"
        );
        assert_eq!(state.view(), View::new(2));
        assert!(
            state.advancing_certificate.is_some(),
            "Should store advancing certificate"
        );
        assert_eq!(
            state.advancing_certificate.as_ref().unwrap(),
            &expected_cert,
            "Stored certificate should match the M-notarization certificate"
        );
    }

    // =============================================================================
    // Crash Recovery Tests
    // =============================================================================

    /// Replaying a notarize prevents double-voting in the same view.
    ///
    /// After crash recovery, if we replayed a notarize for view N, we should
    /// not vote again for any proposal in view N.
    #[test]
    fn replay_notarize_prevents_double_vote() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([1u8; 32]),
        );

        // Simulate crash recovery: replay a notarize we sent before crash
        let notarize = Notarize::sign(&schemes[0], proposal).unwrap();
        let artifact = Artifact::Notarize(notarize);
        state.replay(&artifact).expect("replay should succeed");

        // Now try to vote for a different proposal - should be blocked
        let other_proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([2u8; 32]),
        );
        // Leader for epoch 1, view 1 is participant (1+1)%6 = 2
        state.receive_proposal(Participant::new(2), other_proposal.clone());
        let actions = state.proposal_verified(other_proposal, true);

        let voted = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNotarize(_)));
        assert!(
            !voted,
            "Should NOT vote again after replaying notarize (crash recovery safety)"
        );
    }

    /// Replaying a nullify prevents double-nullification in the same view.
    /// After crash recovery, we re-broadcast our nullify on timeout for liveness.
    ///
    /// When we replay a nullify, we know we already sent it before the crash.
    /// However, other nodes may not have received it, so we need to re-broadcast
    /// to ensure progress. The re-signed nullify is identical (deterministic).
    #[test]
    fn replay_nullify_allows_rebroadcast() {
        let (mut state, schemes, _rng) = setup_state();

        // Simulate crash recovery: replay a nullify we sent before crash
        let original_nullify =
            Nullify::sign::<Sha256Digest>(&schemes[0], Round::new(Epoch::new(1), View::new(1)))
                .unwrap();
        let artifact = Artifact::Nullify(original_nullify.clone());
        state.replay(&artifact).expect("replay should succeed");

        // On timeout, we re-broadcast the same nullify for liveness
        let result = state.handle_timeout();

        assert!(result.is_retry, "Should be a retry after replaying nullify");
        assert!(
            result.nullify.is_some(),
            "Should re-broadcast nullify after crash recovery for liveness"
        );

        // The re-broadcast nullify is identical to the original (deterministic signing)
        assert_eq!(
            result.nullify.as_ref().unwrap(),
            &original_nullify,
            "Re-broadcast nullify should be identical to original"
        );
    }

    /// Replaying an M-notarization restores ancestry and advances view.
    #[test]
    fn replay_m_notarization_restores_state() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([1u8; 32]),
        );

        let notarizes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let m_notarization =
            MNotarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential).unwrap();

        // Replay the M-notarization
        let artifact = Artifact::MNotarization(m_notarization);
        state.replay(&artifact).expect("replay should succeed");

        // Verify state was restored
        assert_eq!(state.view(), View::new(2), "Should advance to view 2");
        assert!(
            state.advancing_certificate.is_some(),
            "Should restore advancing certificate"
        );
        assert_eq!(
            state.last_seen_notarization,
            View::new(1),
            "Should update last_seen_notarization"
        );

        // Verify ancestry was restored - select_parent should find the M-not
        let parent = state.ancestry.select_parent(View::new(2));
        assert!(
            parent.is_some(),
            "Should be able to select parent from replayed M-not"
        );
        let (parent_view, parent_payload) = parent.unwrap();
        assert_eq!(parent_view, View::new(1));
        assert_eq!(parent_payload, proposal.payload);
    }

    /// Replaying a nullification restores ancestry and advances view.
    #[test]
    fn replay_nullification_restores_state() {
        let (mut state, schemes, _rng) = setup_state();

        let nullifies: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(1)))
                    .unwrap()
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential).unwrap();

        // Replay the nullification
        let artifact = Artifact::Nullification(nullification);
        state.replay(&artifact).expect("replay should succeed");

        // Verify state was restored
        assert_eq!(state.view(), View::new(2), "Should advance to view 2");
        assert!(
            state.advancing_certificate.is_some(),
            "Should restore advancing certificate"
        );
    }

    /// Replaying a finalization restores ancestry, advances view, and prunes state.
    #[test]
    fn replay_finalization_restores_state() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);
        let proposal = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([1u8; 32]),
        );

        let notarizes: Vec<_> = schemes
            .iter()
            .take(5)
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential).unwrap();

        // Replay the finalization
        let artifact = Artifact::Finalization(finalization);
        state.replay(&artifact).expect("replay should succeed");

        // Verify state was restored
        assert_eq!(state.view(), View::new(2), "Should advance to view 2");
        assert_eq!(
            state.last_finalized,
            View::new(1),
            "Should update last_finalized"
        );
        assert_eq!(
            state.last_seen_notarization,
            View::new(1),
            "Should update last_seen_notarization"
        );
        assert!(
            state.advancing_certificate.is_some(),
            "Should restore advancing certificate"
        );
    }

    /// Replaying multiple artifacts in order restores full state.
    ///
    /// Simulates a node that progressed through several views before crashing.
    #[test]
    fn replay_sequence_restores_full_state() {
        let (mut state, schemes, _rng) = setup_state();
        let genesis = Sha256Digest::from([0u8; 32]);

        // Build artifacts for views 1-3
        let mut artifacts = Vec::new();

        // View 1: Notarize + M-notarization
        let proposal_v1 = Proposal::new(
            Round::new(Epoch::new(1), View::new(1)),
            View::zero(),
            genesis,
            Sha256Digest::from([1u8; 32]),
        );
        let notarize_v1 = Notarize::sign(&schemes[0], proposal_v1.clone()).unwrap();
        artifacts.push(Artifact::Notarize(notarize_v1));

        let notarizes_v1: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, proposal_v1.clone()).unwrap())
            .collect();
        let m_not_v1 =
            MNotarization::from_notarizes(&schemes[0], notarizes_v1.iter(), &Sequential).unwrap();
        artifacts.push(Artifact::MNotarization(m_not_v1));

        // View 2: Nullify + Nullification (timeout scenario)
        let nullify_v2 =
            Nullify::sign::<Sha256Digest>(&schemes[0], Round::new(Epoch::new(1), View::new(2)))
                .unwrap();
        artifacts.push(Artifact::Nullify(nullify_v2));

        let nullifies_v2: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, Round::new(Epoch::new(1), View::new(2)))
                    .unwrap()
            })
            .collect();
        let nullification_v2 =
            Nullification::from_nullifies(&schemes[0], nullifies_v2.iter(), &Sequential).unwrap();
        artifacts.push(Artifact::Nullification(nullification_v2));

        // View 3: Notarize + Finalization
        let proposal_v3 = Proposal::new(
            Round::new(Epoch::new(1), View::new(3)),
            View::new(1), // Parent is view 1's M-notarization
            proposal_v1.payload,
            Sha256Digest::from([3u8; 32]),
        );
        let notarize_v3 = Notarize::sign(&schemes[0], proposal_v3.clone()).unwrap();
        artifacts.push(Artifact::Notarize(notarize_v3));

        let notarizes_v3: Vec<_> = schemes
            .iter()
            .take(5)
            .map(|scheme| Notarize::sign(scheme, proposal_v3.clone()).unwrap())
            .collect();
        let finalization_v3 =
            Finalization::from_notarizes(&schemes[0], notarizes_v3.iter(), &Sequential).unwrap();
        artifacts.push(Artifact::Finalization(finalization_v3));

        // Replay all artifacts
        for artifact in &artifacts {
            state.replay(artifact).expect("replay should succeed");
        }

        // Verify final state
        assert_eq!(state.view(), View::new(4), "Should be at view 4");
        assert_eq!(
            state.last_finalized,
            View::new(3),
            "Should have finalized view 3"
        );

        // Verify we can't double-vote in view 4 (view state should exist)
        let proposal_v4 = Proposal::new(
            Round::new(Epoch::new(1), View::new(4)),
            View::new(3),
            proposal_v3.payload,
            Sha256Digest::from([4u8; 32]),
        );
        // Leader for epoch 1, view 4 is participant (1+4)%6 = 5
        state.receive_proposal(Participant::new(5), proposal_v4.clone());
        let actions = state.proposal_verified(proposal_v4, true);

        // Should be able to vote in view 4 (we haven't replayed a vote for it)
        let voted = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNotarize(_)));
        assert!(voted, "Should be able to vote in view 4 (no replayed vote)");

        // But a second proposal should not trigger another vote
        let other_proposal_v4 = Proposal::new(
            Round::new(Epoch::new(1), View::new(4)),
            View::new(3),
            proposal_v3.payload,
            Sha256Digest::from([0x44u8; 32]),
        );
        state.receive_proposal(Participant::new(5), other_proposal_v4.clone());
        let actions = state.proposal_verified(other_proposal_v4, true);

        let voted_again = actions
            .iter()
            .any(|a| matches!(a, Action::BroadcastNotarize(_)));
        assert!(
            !voted_again,
            "Should NOT vote again for second proposal in view 4"
        );
    }
}
