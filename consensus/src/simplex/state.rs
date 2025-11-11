use crate::{
    simplex::{
        interesting, min_active,
        signing_scheme::Scheme,
        types::{
            Attributable, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            OrderedExt, Proposal, VoteTracker, Voter,
        },
    },
    types::{Epoch, Round as Rnd, View},
    Viewable,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_utils::set::Ordered;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use tracing::debug;

pub const GENESIS_VIEW: View = 0;

/// Tracks the leader of a round.
#[derive(Debug, Clone)]
pub struct Leader<P: PublicKey> {
    pub(crate) idx: u32,
    pub(crate) key: P,
}

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
#[derive(Default)]
pub struct ProposalSlot<D>
where
    D: Digest,
{
    proposal: Option<Proposal<D>>,
    status: ProposalStatus,
    requested_build: bool,
    requested_verify: bool,
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
    }

    pub fn has_requested_verify(&self) -> bool {
        self.requested_verify
    }

    pub fn request_verify(&mut self) -> bool {
        if self.requested_verify {
            return false;
        }
        self.requested_verify = true;
        true
    }

    pub fn record_our_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
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

/// Outcome of handling a timeout for a round.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutOutcome {
    pub was_retry: bool,
}

/// Context describing a peer proposal that requires verification.
#[derive(Debug, Clone)]
pub struct PeerProposalContext<P: PublicKey, D: Digest> {
    pub leader: Leader<P>,
    pub proposal: Proposal<D>,
}

/// Reasons why the local node cannot begin building a proposal.
#[derive(Debug, Clone)]
pub enum ProposalIntentError<P: PublicKey> {
    LeaderUnknown,
    NotLeader(Leader<P>),
    TimedOut(Leader<P>),
    AlreadyBuilding(Leader<P>),
}

/// Reasons why a locally generated proposal cannot be recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProposalError {
    TimedOut,
}

/// Reasons why a peer proposal cannot be verified.
#[derive(Debug, Clone)]
pub enum PeerProposalError<P: PublicKey> {
    LeaderUnknown,
    LocalLeader(Leader<P>),
    TimedOut,
    MissingProposal,
    AlreadyVerifying,
}

/// Reasons why a verification completion fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationError {
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
pub struct RoundState<S: Scheme, D: Digest> {
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

impl<S: Scheme, D: Digest> RoundState<S, D> {
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

    pub fn start(&self) -> SystemTime {
        self.start
    }

    pub fn leader(&self) -> Option<Leader<S::PublicKey>> {
        self.leader.clone()
    }

    fn is_local_signer(&self, signer: u32) -> bool {
        self.scheme.me().map(|me| me == signer).unwrap_or(false)
    }

    fn clear_votes(&mut self) {
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
    fn record_equivocation_and_clear(&mut self) -> Option<S::PublicKey> {
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

    pub fn round_id(&self) -> Rnd {
        self.round
    }

    pub fn elapsed_since_start(&self, now: SystemTime) -> Option<Duration> {
        now.duration_since(self.start).ok()
    }

    pub fn should_build_proposal(&self) -> bool {
        self.proposal.should_build()
    }

    pub fn begin_building_proposal(&mut self) {
        self.proposal.set_building();
    }

    pub fn record_local_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
        self.proposal.record_our_proposal(replay, proposal);
    }

    pub fn begin_local_proposal(
        &mut self,
    ) -> Result<Leader<S::PublicKey>, ProposalIntentError<S::PublicKey>> {
        let leader = self
            .leader
            .clone()
            .ok_or(ProposalIntentError::LeaderUnknown)?;
        if !self.is_local_signer(leader.idx) {
            return Err(ProposalIntentError::NotLeader(leader));
        }
        if self.broadcast_nullify {
            return Err(ProposalIntentError::TimedOut(leader));
        }
        if !self.proposal.should_build() {
            return Err(ProposalIntentError::AlreadyBuilding(leader));
        }
        self.proposal.set_building();
        Ok(leader)
    }

    pub fn accept_local_proposal(
        &mut self,
        proposal: Proposal<D>,
    ) -> Result<(), LocalProposalError> {
        if self.broadcast_nullify {
            return Err(LocalProposalError::TimedOut);
        }
        self.proposal.record_our_proposal(false, proposal);
        self.leader_deadline = None;
        Ok(())
    }

    pub fn claim_peer_proposal(
        &mut self,
    ) -> Result<PeerProposalContext<S::PublicKey, D>, PeerProposalError<S::PublicKey>> {
        let leader = self
            .leader
            .clone()
            .ok_or(PeerProposalError::LeaderUnknown)?;
        if self.is_local_signer(leader.idx) {
            return Err(PeerProposalError::LocalLeader(leader));
        }
        if self.broadcast_nullify {
            return Err(PeerProposalError::TimedOut);
        }
        let proposal = self
            .proposal
            .proposal()
            .cloned()
            .ok_or(PeerProposalError::MissingProposal)?;
        if !self.proposal.request_verify() {
            return Err(PeerProposalError::AlreadyVerifying);
        }
        Ok(PeerProposalContext { leader, proposal })
    }

    pub fn complete_peer_verification(&mut self) -> Result<(), VerificationError> {
        if self.broadcast_nullify {
            return Err(VerificationError::TimedOut);
        }
        if !self.proposal.mark_verified() {
            return Err(VerificationError::NotPending);
        }
        self.leader_deadline = None;
        Ok(())
    }

    pub fn proposal_ref(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
    }

    pub fn has_requested_verify(&self) -> bool {
        self.proposal.has_requested_verify()
    }

    pub fn request_proposal_verify(&mut self) -> bool {
        self.proposal.request_verify()
    }

    pub fn mark_proposal_verified(&mut self) -> bool {
        self.proposal.mark_verified()
    }

    pub fn has_broadcast_nullify(&self) -> bool {
        self.broadcast_nullify
    }

    pub fn mark_nullify_broadcast(&mut self) -> bool {
        let previous = self.broadcast_nullify;
        self.broadcast_nullify = true;
        previous
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

    pub fn has_broadcast_finalize(&self) -> bool {
        self.broadcast_finalize
    }

    pub fn mark_finalize_broadcast(&mut self) {
        self.broadcast_finalize = true;
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

    pub fn has_broadcast_notarize(&self) -> bool {
        self.broadcast_notarize
    }

    pub fn leader_deadline(&self) -> Option<SystemTime> {
        self.leader_deadline
    }

    pub fn advance_deadline(&self) -> Option<SystemTime> {
        self.advance_deadline
    }

    pub fn set_deadlines(&mut self, leader_deadline: SystemTime, advance_deadline: SystemTime) {
        self.leader_deadline = Some(leader_deadline);
        self.advance_deadline = Some(advance_deadline);
    }

    pub fn set_leader_deadline(&mut self, deadline: Option<SystemTime>) {
        self.leader_deadline = deadline;
    }

    pub fn set_advance_deadline(&mut self, deadline: Option<SystemTime>) {
        self.advance_deadline = deadline;
    }

    pub fn nullify_retry(&self) -> Option<SystemTime> {
        self.nullify_retry
    }

    pub fn set_nullify_retry(&mut self, when: Option<SystemTime>) {
        self.nullify_retry = when;
    }

    pub fn handle_timeout(&mut self) -> TimeoutOutcome {
        let was_retry = self.mark_nullify_broadcast();
        self.clear_deadlines();
        self.set_nullify_retry(None);
        TimeoutOutcome { was_retry }
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

    fn add_recovered_proposal(&mut self, proposal: Proposal<D>) -> Option<S::PublicKey> {
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

    pub fn replay_message(&mut self, message: &Voter<S, D>) {
        match message {
            Voter::Notarize(notarize) => {
                if self.is_local_signer(notarize.signer()) {
                    self.proposal
                        .record_our_proposal(true, notarize.proposal.clone());
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

/// Configuration for initializing [`SimplexCore`].
pub struct CoreConfig<S: Scheme> {
    pub scheme: S,
    pub epoch: Epoch,
    pub activity_timeout: View,
    pub start_view: View,
    pub last_finalized: View,
}

/// Core simplex state machine extracted from actors for easier testing and recovery.
pub struct SimplexCore<S: Scheme, D: Digest> {
    scheme: S,
    epoch: Epoch,
    activity_timeout: View,
    view: View,
    last_finalized: View,
    views: BTreeMap<View, RoundState<S, D>>,
}

impl<S: Scheme, D: Digest> SimplexCore<S, D> {
    pub fn new(cfg: CoreConfig<S>) -> Self {
        Self {
            scheme: cfg.scheme,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            view: cfg.start_view,
            last_finalized: cfg.last_finalized,
            views: BTreeMap::new(),
        }
    }

    pub fn scheme(&self) -> &S {
        &self.scheme
    }

    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub fn current_view(&self) -> View {
        self.view
    }

    pub fn set_current_view(&mut self, view: View) {
        self.view = view;
    }

    pub fn last_finalized(&self) -> View {
        self.last_finalized
    }

    pub fn set_last_finalized(&mut self, view: View) {
        self.last_finalized = view;
    }

    pub fn tracked_views(&self) -> usize {
        self.views.len()
    }

    pub fn min_active(&self) -> View {
        min_active(self.activity_timeout, self.last_finalized)
    }

    pub fn is_interesting(&self, pending: View, allow_future: bool) -> bool {
        interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            pending,
            allow_future,
        )
    }

    pub fn is_me(&self, idx: u32) -> bool {
        self.scheme.me().map(|me| me == idx).unwrap_or(false)
    }

    pub fn participants(&self) -> &Ordered<S::PublicKey> {
        self.scheme.participants()
    }

    pub fn enter_view(
        &mut self,
        view: View,
        now: SystemTime,
        leader_deadline: SystemTime,
        advance_deadline: SystemTime,
        seed: Option<S::Seed>,
    ) -> bool {
        if view <= self.view {
            return false;
        }
        let round = self.ensure_round(view, now);
        round.set_deadlines(leader_deadline, advance_deadline);
        round.set_leader(seed);
        self.view = view;
        true
    }

    pub fn ensure_round(&mut self, view: View, start: SystemTime) -> &mut RoundState<S, D> {
        self.views.entry(view).or_insert_with(|| {
            RoundState::new(self.scheme.clone(), Rnd::new(self.epoch, view), start)
        })
    }

    pub fn round(&self, view: View) -> Option<&RoundState<S, D>> {
        self.views.get(&view)
    }

    pub fn round_mut(&mut self, view: View) -> Option<&mut RoundState<S, D>> {
        self.views.get_mut(&view)
    }

    pub fn remove_round(&mut self, view: View) -> Option<RoundState<S, D>> {
        self.views.remove(&view)
    }

    pub fn first_view(&self) -> Option<View> {
        self.views.keys().next().copied()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&View, &RoundState<S, D>)> {
        self.views.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&View, &mut RoundState<S, D>)> {
        self.views.iter_mut()
    }

    pub fn prune(&mut self) -> Vec<View> {
        let min = self.min_active();
        let mut removed = Vec::new();
        while let Some(view) = self.first_view() {
            if view >= min {
                break;
            }
            self.views.remove(&view);
            removed.push(view);
        }
        removed
    }

    pub fn notarized_payload(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(notarization) = &round.notarization {
            return Some(&notarization.proposal.payload);
        }
        let proposal = round.proposal.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.votes.len_notarizes() >= quorum {
            return Some(&proposal.payload);
        }
        None
    }

    pub fn finalized_payload(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(finalization) = &round.finalization {
            return Some(&finalization.proposal.payload);
        }
        let proposal = round.proposal.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.votes.len_finalizes() >= quorum {
            return Some(&proposal.payload);
        }
        None
    }

    pub fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let quorum = self.scheme.participants().quorum() as usize;
        round.nullification.is_some() || round.votes.len_nullifies() >= quorum
    }

    /// Returns the payload of the notarized parent for the provided proposal, validating
    /// all ancestry requirements (finalized parent, notarization presence, and nullifications
    /// for skipped views). Returns a descriptive [`ParentValidationError`] on failure.
    pub fn parent_payload(
        &self,
        current_view: View,
        proposal: &Proposal<D>,
        genesis: &D,
    ) -> Result<D, ParentValidationError> {
        if proposal.view() <= proposal.parent {
            return Err(ParentValidationError::ParentNotBeforeProposal {
                parent: proposal.parent,
                view: proposal.view(),
            });
        }
        if proposal.parent < self.last_finalized {
            return Err(ParentValidationError::ParentBeforeFinalized {
                parent: proposal.parent,
                last_finalized: self.last_finalized,
            });
        }
        if current_view == 0 {
            return Err(ParentValidationError::CurrentViewUninitialized);
        }
        if proposal.parent >= current_view {
            return Err(ParentValidationError::ParentNotBeforeCurrent {
                parent: proposal.parent,
                current: current_view,
            });
        }
        // Walk backwards from the previous view until we reach the parent, ensuring
        // every skipped view is nullified and the parent is notarized.
        let mut cursor = current_view - 1;
        loop {
            if cursor == proposal.parent {
                if cursor == GENESIS_VIEW {
                    return Ok(*genesis);
                }
                let payload = self
                    .notarized_payload(cursor)
                    .copied()
                    .ok_or(ParentValidationError::MissingParentNotarization { view: cursor })?;
                return Ok(payload);
            }
            if cursor == GENESIS_VIEW {
                return Err(ParentValidationError::MissingParentNotarization {
                    view: proposal.parent,
                });
            }
            if !self.is_nullified(cursor) {
                return Err(ParentValidationError::MissingNullification { view: cursor });
            }
            cursor -= 1;
        }
    }

    /// Returns the notarizations/nullifications that must be fetched for `view`
    /// so that callers can safely replay proposal ancestry. Returns `None` if the
    /// core already has enough data to justify the proposal.
    pub fn missing_certificates(&self, view: View) -> Option<MissingCertificates> {
        if view <= self.last_finalized {
            return None;
        }
        let round = self.round(view)?;
        if !round.proposal_ancestry_supported() {
            return None;
        }
        let proposal = round.proposal_ref()?;
        let parent = proposal.parent;
        let mut missing = MissingCertificates {
            parent,
            notarizations: Vec::new(),
            nullifications: Vec::new(),
        };
        if parent != GENESIS_VIEW && self.notarized_payload(parent).is_none() {
            missing.notarizations.push(parent);
        }
        missing.nullifications = ((parent + 1)..view)
            .filter(|candidate| !self.is_nullified(*candidate))
            .collect();
        if missing.is_empty() {
            return None;
        }
        Some(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        mocks::fixtures::{ed25519, Fixture},
        types::{Notarization, Notarize, Nullify, Proposal},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::Duration;

    #[test]
    fn equivocation_detected_on_notarize_conflict() {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture {
            schemes,
            participants,
            ..
        } = ed25519(&mut rng, 4);
        let scheme = schemes.into_iter().next().unwrap();
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
        let vote_a = Notarize::sign(&scheme, b"ns", proposal_a.clone()).unwrap();
        let vote_b = Notarize::sign(&scheme, b"ns", proposal_b.clone()).unwrap();
        let mut round = RoundState::new(scheme.clone(), proposal_a.round, SystemTime::UNIX_EPOCH);
        round.set_leader(None);
        assert!(round.add_verified_notarize(vote_a).is_none());
        let equivocator = round.add_verified_notarize(vote_b);
        assert!(equivocator.is_some());
        assert_eq!(equivocator.unwrap(), participants[2]);
    }

    #[test]
    fn conflicting_certificate_clears_and_blocks_votes() {
        let mut rng = StdRng::seed_from_u64(1338);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let round_id = Rnd::new(1, 3);
        let proposal_a = Proposal::new(round_id, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));
        let proposal_b = Proposal::new(round_id, GENESIS_VIEW, Sha256Digest::from([9u8; 32]));

        let mut round = RoundState::new(verifier.clone(), round_id, SystemTime::UNIX_EPOCH);
        round.set_leader(None);
        let leader_key = round.leader().expect("leader").key;

        for scheme in schemes.iter().take(3) {
            let vote = Notarize::sign(scheme, namespace, proposal_a.clone()).unwrap();
            assert!(round.add_verified_notarize(vote).is_none());
        }
        assert_eq!(round.votes.len_notarizes(), 3);

        let notarization_votes: Vec<_> = schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, namespace, proposal_b.clone()).unwrap())
            .collect();
        let certificate =
            Notarization::from_notarizes(&verifier, notarization_votes.iter()).unwrap();
        let (accepted, equivocator) = round.add_verified_notarization(certificate);
        assert!(accepted);
        assert_eq!(equivocator, Some(leader_key));
        assert_eq!(round.votes.len_notarizes(), 0);

        let ignored_vote = Notarize::sign(&schemes[3], namespace, proposal_a.clone()).unwrap();
        assert!(round.add_verified_notarize(ignored_vote).is_none());
        assert_eq!(round.votes.len_notarizes(), 0);

        let ignored_new_vote = Notarize::sign(&schemes[0], namespace, proposal_b.clone()).unwrap();
        assert!(round.add_verified_notarize(ignored_new_vote).is_none());
        assert_eq!(round.votes.len_notarizes(), 0);
    }

    #[test]
    fn round_prunes_with_min_active() {
        let mut rng = StdRng::seed_from_u64(1337);
        let Fixture { schemes, .. } = ed25519(&mut rng, 4);
        let scheme = schemes.into_iter().next().unwrap();
        let cfg = CoreConfig {
            scheme,
            epoch: 7,
            activity_timeout: 10,
            start_view: 0,
            last_finalized: 0,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        for view in 0..5 {
            core.ensure_round(view, SystemTime::UNIX_EPOCH + Duration::from_secs(view));
        }
        core.set_last_finalized(20);
        let removed = core.prune();
        assert_eq!(removed, vec![0, 1, 2, 3, 4]);
        assert_eq!(core.tracked_views(), 0);
    }

    #[test]
    fn parent_payload_returns_parent_digest() {
        let mut rng = StdRng::seed_from_u64(7);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = CoreConfig {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
            start_view: 0,
            last_finalized: 0,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        let parent_view = 1;
        let parent_payload = Sha256Digest::from([1u8; 32]);
        let parent_proposal = Proposal::new(Rnd::new(1, parent_view), GENESIS_VIEW, parent_payload);
        let parent_round = core.ensure_round(parent_view, now);
        parent_round.record_local_proposal(false, parent_proposal.clone());
        for scheme in &schemes {
            let vote = Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap();
            parent_round.add_verified_notarize(vote);
        }

        core.set_current_view(2);
        let proposal = Proposal::new(Rnd::new(1, 2), parent_view, Sha256Digest::from([9u8; 32]));
        let genesis = Sha256Digest::from([0u8; 32]);

        let digest = core
            .parent_payload(2, &proposal, &genesis)
            .expect("parent payload");

        assert_eq!(digest, parent_payload);
    }

    #[test]
    fn parent_payload_errors_without_nullification() {
        let mut rng = StdRng::seed_from_u64(9);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = CoreConfig {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
            start_view: 0,
            last_finalized: 0,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        let parent_view = 1;
        let parent_proposal = Proposal::new(
            Rnd::new(1, parent_view),
            GENESIS_VIEW,
            Sha256Digest::from([2u8; 32]),
        );
        let parent_round = core.ensure_round(parent_view, now);
        parent_round.record_local_proposal(false, parent_proposal.clone());
        for scheme in &schemes {
            let vote = Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap();
            parent_round.add_verified_notarize(vote);
        }
        core.ensure_round(2, now);
        core.set_current_view(3);

        let proposal = Proposal::new(Rnd::new(1, 3), parent_view, Sha256Digest::from([3u8; 32]));
        let genesis = Sha256Digest::from([0u8; 32]);

        let err = core.parent_payload(3, &proposal, &genesis).unwrap_err();
        assert!(matches!(
            err,
            ParentValidationError::MissingNullification { view } if view == 2
        ));
    }

    #[test]
    fn parent_payload_returns_genesis_payload() {
        let mut rng = StdRng::seed_from_u64(21);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = CoreConfig {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
            start_view: 0,
            last_finalized: 0,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 1)).unwrap())
            .collect();
        {
            let round = core.ensure_round(1, now);
            for vote in votes {
                round.add_verified_nullify(vote);
            }
        }

        core.set_current_view(2);
        let proposal = Proposal::new(Rnd::new(1, 2), GENESIS_VIEW, Sha256Digest::from([8u8; 32]));
        let genesis = Sha256Digest::from([0u8; 32]);
        let digest = core
            .parent_payload(2, &proposal, &genesis)
            .expect("genesis payload");
        assert_eq!(digest, genesis);
    }

    #[test]
    fn parent_payload_rejects_parent_before_finalized() {
        let mut rng = StdRng::seed_from_u64(23);
        let Fixture { verifier, .. } = ed25519(&mut rng, 4);
        let cfg = CoreConfig {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
            start_view: 0,
            last_finalized: 0,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        core.set_last_finalized(3);
        core.set_current_view(4);
        let proposal = Proposal::new(Rnd::new(1, 4), 2, Sha256Digest::from([6u8; 32]));
        let genesis = Sha256Digest::from([0u8; 32]);
        let err = core.parent_payload(4, &proposal, &genesis).unwrap_err();
        assert!(matches!(
            err,
            ParentValidationError::ParentBeforeFinalized { parent, last_finalized }
            if parent == 2 && last_finalized == 3
        ));
    }

    #[test]
    fn missing_certificates_reports_gaps() {
        let mut rng = StdRng::seed_from_u64(11);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = CoreConfig {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
            start_view: 0,
            last_finalized: 1,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        let parent_view = 2;
        let parent_proposal =
            Proposal::new(Rnd::new(1, parent_view), 1, Sha256Digest::from([4u8; 32]));
        let parent_round = core.ensure_round(parent_view, now);
        parent_round.record_local_proposal(false, parent_proposal);

        let nullified_round = core.ensure_round(3, now);
        for scheme in &schemes {
            let vote = Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 3)).unwrap();
            nullified_round.add_verified_nullify(vote);
        }
        core.ensure_round(4, now);

        let proposal = Proposal::new(Rnd::new(1, 5), parent_view, Sha256Digest::from([5u8; 32]));
        let round = core.ensure_round(5, now);
        round.record_local_proposal(false, proposal.clone());
        for scheme in schemes.iter().take(2) {
            let vote = Notarize::sign(scheme, namespace, proposal.clone()).unwrap();
            round.add_verified_notarize(vote);
        }

        let missing = core.missing_certificates(5).expect("missing data");
        assert_eq!(missing.parent, parent_view);
        assert_eq!(missing.notarizations, vec![parent_view]);
        assert_eq!(missing.nullifications, vec![4]);
    }

    #[test]
    fn missing_certificates_none_when_ancestry_complete() {
        let mut rng = StdRng::seed_from_u64(25);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = CoreConfig {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
            start_view: 0,
            last_finalized: 1,
        };
        let mut core: SimplexCore<_, Sha256Digest> = SimplexCore::new(cfg);
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        let parent_view = 2;
        let parent_proposal =
            Proposal::new(Rnd::new(1, parent_view), 1, Sha256Digest::from([7u8; 32]));
        {
            let round = core.ensure_round(parent_view, now);
            round.record_local_proposal(false, parent_proposal.clone());
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap())
                .collect();
            for vote in votes {
                round.add_verified_notarize(vote);
            }
        }

        {
            let round = core.ensure_round(3, now);
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 3)).unwrap()
                })
                .collect();
            for vote in votes {
                round.add_verified_nullify(vote);
            }
        }

        let proposal = Proposal::new(Rnd::new(1, 4), parent_view, Sha256Digest::from([9u8; 32]));
        {
            let round = core.ensure_round(4, now);
            round.record_local_proposal(false, proposal.clone());
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
                .collect();
            for vote in votes {
                round.add_verified_notarize(vote);
            }
        }

        assert!(core.missing_certificates(4).is_none());
    }

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
        slot.record_our_proposal(false, proposal);
        assert!(!slot.should_build());
    }

    #[test]
    fn proposal_slot_records_local_proposal_with_flags() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        assert!(slot.proposal().is_none());

        let round = Rnd::new(9, 1);
        let proposal = Proposal::new(round, 0, Sha256Digest::from([2u8; 32]));
        slot.record_our_proposal(false, proposal.clone());

        match slot.proposal() {
            Some(stored) => assert_eq!(stored, &proposal),
            None => panic!("proposal missing after recording"),
        }
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert!(slot.has_requested_verify());
        assert!(!slot.should_build());
        assert!(!slot.request_verify());
    }

    #[test]
    fn proposal_slot_records_and_prevents_duplicate_build() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(1, 2);
        let proposal = Proposal::new(round, 1, Sha256Digest::from([10u8; 32]));

        slot.record_our_proposal(false, proposal.clone());

        assert_eq!(slot.proposal(), Some(&proposal));
        assert_eq!(slot.status(), ProposalStatus::Verified);
        assert!(slot.has_requested_verify());
        assert!(!slot.should_build());
        assert!(!slot.request_verify());
    }

    #[test]
    fn proposal_slot_replay_allows_existing_proposal() {
        let mut slot = ProposalSlot::<Sha256Digest>::new();
        let round = Rnd::new(17, 6);
        let proposal = Proposal::new(round, 5, Sha256Digest::from([11u8; 32]));

        slot.record_our_proposal(false, proposal.clone());
        slot.record_our_proposal(true, proposal.clone());

        assert!(slot.has_requested_verify());
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
        slot.record_our_proposal(false, honest.clone());
        assert_eq!(slot.status(), ProposalStatus::Replaced);
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
        assert!(slot.has_requested_verify());

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
