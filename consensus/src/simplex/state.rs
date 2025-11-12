use crate::{
    simplex::{
        interesting, min_active,
        signing_scheme::Scheme,
        types::{
            Attributable, Context, Finalization, Finalize, Notarization, Notarize, Nullification,
            Nullify, OrderedExt, Proposal, VoteTracker, Voter,
        },
    },
    types::{Epoch, Round as Rnd, View},
    Viewable,
};
use commonware_cryptography::{Digest, PublicKey};
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};
use tracing::debug;

const GENESIS_VIEW: View = 0;

/// Tracks the leader of a round.
#[derive(Debug, Clone)]
struct Leader<P: PublicKey> {
    pub(crate) idx: u32,
    pub(crate) key: P,
}

/// Proposal verification status within a round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ProposalStatus {
    #[default]
    None,
    Unverified,
    Verified,
    Replaced,
}

/// Context describing a peer proposal that requires verification.
///
/// Instances are produced by [`State::try_verify`] and consumed inside
/// [`Actor::try_verify`](crate::simplex::actors::voter::Actor::try_verify) to
/// build the [`Context`] passed to the application automaton.
#[derive(Debug, Clone)]
struct VerifyContext<P: PublicKey, D: Digest> {
    pub leader: Leader<P>,
    pub proposal: Proposal<D>,
}

/// Metadata returned when a peer proposal is ready for verification.
#[derive(Debug, Clone)]
pub struct VerifyReady<P: PublicKey, D: Digest> {
    pub context: Context<D, P>,
    pub proposal: Proposal<D>,
}

/// Reasons why preparing or reserving a proposal is not allowed.
#[derive(Debug, Clone)]
enum ProposalError<P: PublicKey> {
    LeaderUnknown,
    NotLeader(Leader<P>),
    LocalLeader(Leader<P>),
    TimedOut,
    AlreadyBuilding(Leader<P>),
    MissingProposal,
    AlreadyVerifying,
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
enum ParentValidationError {
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
    fn is_empty(&self) -> bool {
        self.notarizations.is_empty() && self.nullifications.is_empty()
    }
}

/// Describes how a proposal slot changed after an update.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProposalChange<D>
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
struct ProposalSlot<D>
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
    fn new() -> Self {
        Self {
            proposal: None,
            status: ProposalStatus::None,
            requested_build: false,
            requested_verify: false,
            awaiting_parent: None,
        }
    }

    fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.as_ref()
    }

    fn status(&self) -> ProposalStatus {
        self.status
    }

    fn should_build(&self) -> bool {
        !self.requested_build && self.proposal.is_none()
    }

    fn set_building(&mut self) {
        self.requested_build = true;
        self.awaiting_parent = None;
    }

    fn request_verify(&mut self) -> bool {
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
    fn mark_parent_missing(&mut self, parent: View) -> bool {
        match self.awaiting_parent {
            Some(missing) if missing == parent => false,
            None | Some(_) => {
                self.awaiting_parent = Some(parent);
                true
            }
        }
    }

    fn clear_parent_missing(&mut self) {
        self.awaiting_parent = None;
    }

    fn record_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
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

    fn mark_verified(&mut self) -> bool {
        if self.status != ProposalStatus::Unverified {
            return false;
        }
        self.status = ProposalStatus::Verified;
        true
    }

    fn update(&mut self, proposal: &Proposal<D>, recovered: bool) -> ProposalChange<D> {
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

/// Per-view state machine shared between actors and tests.
struct Round<S: Scheme, D: Digest> {
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
    fn new(scheme: S, round: Rnd, start: SystemTime) -> Self {
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

    fn can_begin_propose(&self) -> Result<Leader<S::PublicKey>, ProposalError<S::PublicKey>> {
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

    fn reserve_local_proposal(&mut self) {
        self.proposal.set_building();
    }

    fn mark_parent_missing(&mut self, parent: View) -> bool {
        self.proposal.mark_parent_missing(parent)
    }

    fn clear_parent_missing(&mut self) {
        self.proposal.clear_parent_missing();
    }

    fn verify_metadata(
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

    fn reserve_verify(&mut self) -> Result<(), ProposalError<S::PublicKey>> {
        if !self.proposal.request_verify() {
            return Err(ProposalError::AlreadyVerifying);
        }
        Ok(())
    }

    fn leader(&self) -> Option<Leader<S::PublicKey>> {
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

    fn clear_deadlines(&mut self) {
        self.leader_deadline = None;
        self.advance_deadline = None;
    }

    fn set_leader(&mut self, seed: Option<S::Seed>) {
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

    fn elapsed_since_start(&self, now: SystemTime) -> Option<Duration> {
        now.duration_since(self.start).ok()
    }

    #[cfg(test)]
    fn record_proposal(&mut self, replay: bool, proposal: Proposal<D>) {
        self.proposal.record_proposal(replay, proposal);
    }

    /// Completes the local proposal flow after the automaton returns a payload.
    ///
    /// [`State::proposed`] invokes this once the automaton returns a payload.
    /// When the round has not timed out we store the proposal, mark it as verified (because we
    /// generated it ourselves), and clear the leader deadline so the rest of the pipeline can
    /// continue with notarization.
    fn proposed(&mut self, proposal: Proposal<D>) -> Result<(), HandleError> {
        if self.broadcast_nullify {
            return Err(HandleError::TimedOut);
        }
        self.proposal.record_proposal(false, proposal);
        self.leader_deadline = None;
        Ok(())
    }

    /// Completes peer proposal verification after the automaton returns.
    ///
    /// [`State::verified`] invokes this once the automaton confirms the payload
    /// is valid. The round transitions the proposal into the `Verified` state (enabling
    /// notarization/finalization) as long as the view did not time out while the async
    /// verification was running.
    fn verified(&mut self) -> Result<(), HandleError> {
        if self.broadcast_nullify {
            return Err(HandleError::TimedOut);
        }
        if !self.proposal.mark_verified() {
            return Err(HandleError::NotPending);
        }
        self.leader_deadline = None;
        Ok(())
    }

    fn proposal(&self) -> Option<&Proposal<D>> {
        self.proposal.proposal()
    }

    fn mark_nullify_broadcast(&mut self) -> bool {
        let previous = self.broadcast_nullify;
        self.broadcast_nullify = true;
        previous
    }

    #[cfg(test)]
    fn has_broadcast_nullify_vote(&self) -> bool {
        self.broadcast_nullify
    }

    fn has_broadcast_notarization(&self) -> bool {
        self.broadcast_notarization
    }

    fn mark_notarization_broadcast(&mut self) {
        self.broadcast_notarization = true;
    }

    fn has_broadcast_nullification(&self) -> bool {
        self.broadcast_nullification
    }

    fn mark_nullification_broadcast(&mut self) {
        self.broadcast_nullification = true;
    }

    fn mark_finalize_broadcast(&mut self) {
        self.broadcast_finalize = true;
    }

    #[cfg(test)]
    fn has_broadcast_finalize_vote(&self) -> bool {
        self.broadcast_finalize
    }

    fn has_broadcast_finalization(&self) -> bool {
        self.broadcast_finalization
    }

    fn mark_finalization_broadcast(&mut self) {
        self.broadcast_finalization = true;
    }

    fn mark_notarize_broadcast(&mut self) {
        self.broadcast_notarize = true;
    }

    #[cfg(test)]
    fn has_broadcast_notarize(&self) -> bool {
        self.broadcast_notarize
    }

    fn set_deadlines(&mut self, leader_deadline: SystemTime, advance_deadline: SystemTime) {
        self.leader_deadline = Some(leader_deadline);
        self.advance_deadline = Some(advance_deadline);
    }

    fn set_leader_deadline(&mut self, deadline: Option<SystemTime>) {
        self.leader_deadline = deadline;
    }

    fn set_nullify_retry(&mut self, when: Option<SystemTime>) {
        self.nullify_retry = when;
    }

    fn handle_timeout(&mut self) -> bool {
        let was_retry = self.mark_nullify_broadcast();
        self.clear_deadlines();
        self.set_nullify_retry(None);
        was_retry
    }

    fn next_timeout_deadline(&mut self, now: SystemTime, retry: Duration) -> SystemTime {
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

    fn add_verified_notarize(&mut self, notarize: Notarize<S, D>) -> Option<S::PublicKey> {
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

    fn add_verified_nullify(&mut self, nullify: Nullify<S>) {
        self.votes.insert_nullify(nullify);
    }

    fn add_verified_finalize(&mut self, finalize: Finalize<S, D>) -> Option<S::PublicKey> {
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

    fn add_verified_notarization(
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

    fn add_verified_nullification(&mut self, nullification: Nullification<S>) -> bool {
        if self.nullification.is_some() {
            return false;
        }
        self.clear_deadlines();
        self.nullification = Some(nullification);
        true
    }

    fn add_verified_finalization(
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

    fn notarizable(&mut self, force: bool) -> Option<Notarization<S, D>> {
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

    fn nullifiable(&mut self, force: bool) -> Option<Nullification<S>> {
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

    fn finalizable(&mut self, force: bool) -> Option<Finalization<S, D>> {
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

    fn proposal_ancestry_supported(&self) -> bool {
        if self.proposal.proposal().is_none() {
            return false;
        }
        if self.finalization.is_some() || self.notarization.is_some() {
            return true;
        }
        let max_faults = self.scheme.participants().max_faults() as usize;
        self.votes.len_notarizes() > max_faults
    }

    fn notarize_candidate(&mut self) -> Option<&Proposal<D>> {
        if self.broadcast_notarize || self.broadcast_nullify {
            return None;
        }
        if self.proposal.status() != ProposalStatus::Verified {
            return None;
        }
        self.broadcast_notarize = true;
        self.proposal.proposal()
    }

    fn finalize_candidate(&mut self) -> Option<&Proposal<D>> {
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

    fn replay(&mut self, message: &Voter<S, D>) {
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

/// Configuration for initializing [`State`].
pub struct Config<S: Scheme> {
    pub scheme: S,
    pub epoch: Epoch,
    pub activity_timeout: View,
}

/// Core simplex state machine extracted from actors for easier testing and recovery.
pub struct State<S: Scheme, D: Digest> {
    scheme: S,
    epoch: Epoch,
    activity_timeout: View,
    view: View,
    last_finalized: View,
    genesis: Option<D>,
    views: BTreeMap<View, Round<S, D>>,
}

impl<S: Scheme, D: Digest> State<S, D> {
    pub fn new(cfg: Config<S>) -> Self {
        Self {
            scheme: cfg.scheme,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            view: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            genesis: None,
            views: BTreeMap::new(),
        }
    }

    pub fn set_genesis(&mut self, genesis: D) {
        self.genesis = Some(genesis);
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

    pub fn last_finalized(&self) -> View {
        self.last_finalized
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

    fn ensure_round(&mut self, view: View, start: SystemTime) -> &mut Round<S, D> {
        self.views
            .entry(view)
            .or_insert_with(|| Round::new(self.scheme.clone(), Rnd::new(self.epoch, view), start))
    }

    pub fn next_timeout_deadline(
        &mut self,
        view: View,
        now: SystemTime,
        retry: Duration,
    ) -> SystemTime {
        self.ensure_round(view, now)
            .next_timeout_deadline(now, retry)
    }

    pub fn handle_timeout(&mut self, view: View, now: SystemTime) -> bool {
        self.ensure_round(view, now).handle_timeout()
    }

    pub fn add_verified_notarize(
        &mut self,
        now: SystemTime,
        notarize: Notarize<S, D>,
    ) -> Option<S::PublicKey> {
        self.ensure_round(notarize.view(), now)
            .add_verified_notarize(notarize)
    }

    pub fn add_verified_nullify(&mut self, now: SystemTime, nullify: Nullify<S>) {
        self.ensure_round(nullify.view(), now)
            .add_verified_nullify(nullify);
    }

    pub fn add_verified_finalize(
        &mut self,
        now: SystemTime,
        finalize: Finalize<S, D>,
    ) -> Option<S::PublicKey> {
        self.ensure_round(finalize.view(), now)
            .add_verified_finalize(finalize)
    }

    pub fn add_verified_notarization(
        &mut self,
        now: SystemTime,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        self.ensure_round(notarization.view(), now)
            .add_verified_notarization(notarization)
    }

    pub fn add_verified_nullification(
        &mut self,
        now: SystemTime,
        nullification: Nullification<S>,
    ) -> bool {
        self.ensure_round(nullification.view(), now)
            .add_verified_nullification(nullification)
    }

    pub fn add_verified_finalization(
        &mut self,
        now: SystemTime,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        // If this finalization increases our last finalized view, update it
        if finalization.view() > self.last_finalized {
            self.last_finalized = finalization.view();
        }

        self.ensure_round(finalization.view(), now)
            .add_verified_finalization(finalization)
    }

    #[cfg(test)]
    fn has_broadcast_notarize(&self, view: View) -> bool {
        self.views
            .get(&view)
            .map(|round| round.has_broadcast_notarize())
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn has_broadcast_nullify_vote(&self, view: View) -> bool {
        self.views
            .get(&view)
            .map(|round| round.has_broadcast_nullify_vote())
            .unwrap_or(false)
    }

    #[cfg(test)]
    fn has_broadcast_finalize_vote(&self, view: View) -> bool {
        self.views
            .get(&view)
            .map(|round| round.has_broadcast_finalize_vote())
            .unwrap_or(false)
    }

    pub fn has_broadcast_notarization(&self, view: View) -> bool {
        self.views
            .get(&view)
            .map(|round| round.has_broadcast_notarization())
            .unwrap_or(false)
    }

    pub fn has_broadcast_nullification(&self, view: View) -> bool {
        self.views
            .get(&view)
            .map(|round| round.has_broadcast_nullification())
            .unwrap_or(false)
    }

    pub fn has_broadcast_finalization(&self, view: View) -> bool {
        self.views
            .get(&view)
            .map(|round| round.has_broadcast_finalization())
            .unwrap_or(false)
    }

    pub fn notarize_candidate(&mut self, view: View) -> Option<Proposal<D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.notarize_candidate().cloned())
    }

    pub fn finalize_candidate(&mut self, view: View) -> Option<Proposal<D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.finalize_candidate().cloned())
    }

    pub fn notarization_candidate(
        &mut self,
        view: View,
        force: bool,
    ) -> Option<Notarization<S, D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.notarizable(force))
    }

    pub fn nullification_candidate(&mut self, view: View, force: bool) -> Option<Nullification<S>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.nullifiable(force))
    }

    pub fn finalization_candidate(
        &mut self,
        view: View,
        force: bool,
    ) -> Option<Finalization<S, D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.finalizable(force))
    }

    pub fn replay(&mut self, view: View, now: SystemTime, message: &Voter<S, D>) {
        self.ensure_round(view, now).replay(message);
    }

    pub fn leader_index(&self, view: View) -> Option<u32> {
        self.views
            .get(&view)
            .and_then(|round| round.leader().map(|leader| leader.idx))
    }

    pub fn elapsed_since_start(&self, view: View, now: SystemTime) -> Option<Duration> {
        self.views
            .get(&view)
            .and_then(|round| round.elapsed_since_start(now))
    }

    pub fn set_round_deadlines(
        &mut self,
        view: View,
        now: SystemTime,
        leader_deadline: SystemTime,
        advance_deadline: SystemTime,
    ) {
        self.ensure_round(view, now)
            .set_deadlines(leader_deadline, advance_deadline);
    }

    pub fn set_leader_deadline(
        &mut self,
        view: View,
        now: SystemTime,
        deadline: Option<SystemTime>,
    ) {
        if let Some(round) = self.views.get_mut(&view) {
            round.set_leader_deadline(deadline);
        } else {
            self.ensure_round(view, now).set_leader_deadline(deadline);
        }
    }

    pub fn try_propose(&mut self, now: SystemTime) -> ProposeStatus<S::PublicKey, D> {
        let view = self.view;
        if view == GENESIS_VIEW {
            return ProposeStatus::NotReady;
        }
        let parent = self.find_parent(view);
        let round = self.ensure_round(view, now);
        let (parent_view, parent_payload) = match parent {
            Ok(parent) => {
                round.clear_parent_missing();
                parent
            }
            Err(missing) => {
                // Only surface the missing ancestor once per view to avoid
                // hammering the resolver while we wait for the certificate.
                if round.mark_parent_missing(missing) {
                    return ProposeStatus::MissingAncestor(missing);
                }
                return ProposeStatus::NotReady;
            }
        };
        let leader = match round.can_begin_propose() {
            Ok(leader) => leader,
            Err(_) => return ProposeStatus::NotReady,
        };
        round.reserve_local_proposal();
        ProposeStatus::Ready(Context {
            round: Rnd::new(self.epoch, view),
            leader: leader.key,
            parent: (parent_view, parent_payload),
        })
    }

    /// Records a locally constructed proposal once the automaton finishes building it.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> Option<Result<(), HandleError>> {
        self.views
            .get_mut(&proposal.view())
            .map(|round| round.proposed(proposal))
    }

    pub fn try_verify(&mut self, view: View) -> VerifyStatus<S::PublicKey, D> {
        let peer_ctx = {
            let round = match self.views.get(&view) {
                Some(round) => round,
                None => return VerifyStatus::NotReady,
            };
            round.verify_metadata()
        };
        let VerifyContext { leader, proposal } = match peer_ctx {
            Ok(ctx) => ctx,
            Err(_) => return VerifyStatus::NotReady,
        };
        let parent_payload = match self.parent_payload(view, &proposal) {
            Ok(payload) => payload,
            Err(ParentValidationError::MissingParentNotarization { view: _ }) => {
                return VerifyStatus::NotReady;
            }
            Err(ParentValidationError::MissingNullification { view: _ }) => {
                return VerifyStatus::NotReady;
            }
            Err(_) => return VerifyStatus::NotReady,
        };
        let round = match self.views.get_mut(&view) {
            Some(round) => round,
            None => return VerifyStatus::NotReady,
        };
        if round.reserve_verify().is_err() {
            return VerifyStatus::NotReady;
        }
        let context = Context {
            round: proposal.round,
            leader: leader.key,
            parent: (proposal.parent, parent_payload),
        };
        VerifyStatus::Ready(VerifyReady { context, proposal })
    }

    /// Marks proposal verification as complete when the peer payload validates.
    ///
    /// Returns `None` when the view was already pruned or never entered. Successful completions
    /// yield the (cloned) proposal so callers can log which payload advanced to voting.
    pub fn verified(&mut self, view: View) -> Option<Result<Option<Proposal<D>>, HandleError>> {
        self.views.get_mut(&view).map(|round| {
            let proposal = round.proposal().cloned();
            round.verified().map(|_| proposal)
        })
    }

    fn first_view(&self) -> Option<View> {
        self.views.keys().next().copied()
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

    fn notarized_payload(&self, view: View) -> Option<&D> {
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

    fn finalized_payload(&self, view: View) -> Option<&D> {
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

    fn is_nullified(&self, view: View) -> bool {
        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let quorum = self.scheme.participants().quorum() as usize;
        round.nullification.is_some() || round.votes.len_nullifies() >= quorum
    }

    fn find_parent(&self, view: View) -> Result<(View, D), View> {
        if view == GENESIS_VIEW {
            return Ok((GENESIS_VIEW, self.genesis.unwrap()));
        }
        let mut cursor = view - 1;
        loop {
            if cursor == GENESIS_VIEW {
                return Ok((GENESIS_VIEW, self.genesis.unwrap()));
            }
            if let Some(parent) = self.notarized_payload(cursor) {
                return Ok((cursor, *parent));
            }
            if let Some(parent) = self.finalized_payload(cursor) {
                return Ok((cursor, *parent));
            }
            if self.is_nullified(cursor) {
                if cursor == GENESIS_VIEW {
                    return Ok((GENESIS_VIEW, self.genesis.unwrap()));
                }
                cursor -= 1;
                continue;
            }
            return Err(cursor);
        }
    }

    /// Returns the payload of the notarized parent for the provided proposal, validating
    /// all ancestry requirements (finalized parent, notarization presence, and nullifications
    /// for skipped views). Returns a descriptive [`ParentValidationError`] on failure.
    fn parent_payload(
        &self,
        current_view: View,
        proposal: &Proposal<D>,
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
                    return Ok(self.genesis.unwrap());
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
        let round = self.views.get(&view)?;
        if !round.proposal_ancestry_supported() {
            return None;
        }
        let proposal = round.proposal()?;
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
        types::{
            Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal, Voter,
        },
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use rand::{rngs::StdRng, SeedableRng};
    use std::time::Duration;

    fn test_genesis() -> Sha256Digest {
        Sha256Digest::from([0u8; 32])
    }

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

    #[test]
    fn replay_message_sets_broadcast_flags() {
        let mut rng = StdRng::seed_from_u64(2029);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let local_scheme = schemes[0].clone();
        let cfg = Config {
            scheme: local_scheme.clone(),
            epoch: 5,
            activity_timeout: 3,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());

        // Setup round and proposal
        let now = SystemTime::UNIX_EPOCH;
        let view = 2;
        let round = Rnd::new(5, view);
        let proposal = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([40u8; 32]));
        {
            let round = state.ensure_round(view, now);
            round.set_leader(None);
            round.record_proposal(false, proposal.clone());
        }

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
        state.replay(view, now, &Voter::Notarize(notarize_local));
        assert!(state.has_broadcast_notarize(view));
        state.replay(view, now, &Voter::Nullify(nullify_local));
        assert!(state.has_broadcast_nullify_vote(view));
        state.replay(view, now, &Voter::Finalize(finalize_local));
        assert!(state.has_broadcast_finalize_vote(view));
        state.replay(view, now, &Voter::Notarization(notarization.clone()));
        assert!(state.has_broadcast_notarization(view));
        state.replay(view, now, &Voter::Nullification(nullification.clone()));
        assert!(state.has_broadcast_nullification(view));
        state.replay(view, now, &Voter::Finalization(finalization.clone()));
        assert!(state.has_broadcast_finalization(view));

        // Replaying the certificate again should keep the flags set.
        state.replay(view, now, &Voter::Notarization(notarization));
        assert!(state.has_broadcast_notarization(view));
        state.replay(view, now, &Voter::Nullification(nullification));
        assert!(state.has_broadcast_nullification(view));
        state.replay(view, now, &Voter::Finalization(finalization));
        assert!(state.has_broadcast_finalization(view));
    }

    #[test]
    fn certificate_candidates_respect_force_flag() {
        let mut rng = StdRng::seed_from_u64(2030);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let mut state: State<_, Sha256Digest> = State::new(Config {
            scheme: verifier.clone(),
            epoch: 11,
            activity_timeout: 6,
        });
        state.set_genesis(test_genesis());
        let now = SystemTime::UNIX_EPOCH;

        // Add notarization
        let notarize_view = 3;
        let notarize_round = Rnd::new(11, notarize_view);
        let notarize_proposal =
            Proposal::new(notarize_round, GENESIS_VIEW, Sha256Digest::from([50u8; 32]));
        let notarize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, namespace, notarize_proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarize_votes.iter()).expect("notarization");
        state.add_verified_notarization(now, notarization);

        // Produce candidate once
        assert!(state.notarization_candidate(notarize_view, false).is_some());
        assert!(state.notarization_candidate(notarize_view, false).is_none());

        // Produce candidate again if forced
        assert!(state.notarization_candidate(notarize_view, true).is_some());

        // Add nullification
        let nullify_view = 4;
        let nullify_round = Rnd::new(11, nullify_view);
        let nullify_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| {
                Nullify::sign::<Sha256Digest>(scheme, namespace, nullify_round).expect("nullify")
            })
            .collect();
        let nullification =
            Nullification::from_nullifies(&verifier, &nullify_votes).expect("nullification");
        state.add_verified_nullification(now, nullification);

        // Produce candidate once
        assert!(state.nullification_candidate(nullify_view, false).is_some());
        assert!(state.nullification_candidate(nullify_view, false).is_none());

        // Produce candidate again if forced
        assert!(state.nullification_candidate(nullify_view, true).is_some());

        // Add finalization
        let finalize_view = 5;
        let finalize_round = Rnd::new(11, finalize_view);
        let finalize_proposal =
            Proposal::new(finalize_round, GENESIS_VIEW, Sha256Digest::from([51u8; 32]));
        {
            let round = state.ensure_round(finalize_view, now);
            round.set_leader(None);
            round.record_proposal(false, finalize_proposal.clone());
        }
        let finalize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, namespace, finalize_proposal.clone()).unwrap())
            .collect();
        let finalization =
            Finalization::from_finalizes(&verifier, finalize_votes.iter()).expect("finalization");
        state.add_verified_finalization(now, finalization);

        // Produce candidate once
        assert!(state.finalization_candidate(finalize_view, false).is_some());
        assert!(state.finalization_candidate(finalize_view, false).is_none());

        // Produce candidate again if forced
        assert!(state.finalization_candidate(finalize_view, true).is_some());
    }

    #[test]
    fn missing_parent_only_triggers_fetch_once() {
        let mut rng = StdRng::seed_from_u64(2050);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let local_scheme = schemes[0].clone();
        let cfg = Config {
            scheme: local_scheme.clone(),
            epoch: 7,
            activity_timeout: 3,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let now = SystemTime::UNIX_EPOCH;

        // Start proposal with missing parent
        state.enter_view(1, now, now, now, None);
        state.enter_view(2, now, now, now, None);
        {
            let me = state.scheme.me().expect("local signer");
            let key = state
                .scheme
                .participants()
                .key(me)
                .expect("local key")
                .clone();
            let round = state.ensure_round(2, now);
            round.leader = Some(Leader { idx: me, key });
        }

        // First proposal should return missing ancestors
        match state.try_propose(now) {
            ProposeStatus::MissingAncestor(view) => assert_eq!(view, 1),
            other => panic!("expected missing ancestor, got {other:?}"),
        }
        assert!(matches!(state.try_propose(now), ProposeStatus::NotReady));

        // Add notarization for parent view
        let parent_round = Rnd::new(state.epoch(), 1);
        let parent_proposal =
            Proposal::new(parent_round, GENESIS_VIEW, Sha256Digest::from([11u8; 32]));
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, votes.iter()).expect("notarization");
        state.add_verified_notarization(now, notarization);

        // Second call should be ready
        assert!(matches!(state.try_propose(now), ProposeStatus::Ready(_)));
    }

    #[test]
    fn missing_parent_reemerges_after_partial_progress() {
        let mut rng = StdRng::seed_from_u64(2051);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let local_scheme = schemes[0].clone();
        let cfg = Config {
            scheme: local_scheme.clone(),
            epoch: 9,
            activity_timeout: 4,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let now = SystemTime::UNIX_EPOCH;

        // Advance to view 5 and ensure we are the elected leader
        for view in 1..=5 {
            state.enter_view(view, now, now, now, None);
        }
        let me = state.scheme.me().expect("local signer");
        let key = state
            .scheme
            .participants()
            .key(me)
            .expect("local key")
            .clone();
        {
            let round = state.ensure_round(5, now);
            round.leader = Some(Leader { idx: me, key });
        }

        // Initially the missing ancestor is view 4 (we have neither certificates nor nullify)
        match state.try_propose(now) {
            ProposeStatus::MissingAncestor(view) => assert_eq!(view, 4),
            other => panic!("expected missing ancestor 4, got {other:?}"),
        }

        // Provide the nullification for view 4 but still leave the parent notarization absent
        let null_round = Rnd::new(state.epoch(), 4);
        let null_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, namespace, null_round).unwrap())
            .collect();
        let nullification =
            Nullification::from_nullifies(&verifier, &null_votes).expect("nullification");
        state.add_verified_nullification(now, nullification);

        // The next attempt should complain about the parent view (3) instead of 4
        match state.try_propose(now) {
            ProposeStatus::MissingAncestor(view) => assert_eq!(view, 3),
            other => panic!("expected missing ancestor 3, got {other:?}"),
        }

        // Provide the notarization for view 3 to unblock proposals entirely
        let parent_round = Rnd::new(state.epoch(), 3);
        let parent = Proposal::new(parent_round, GENESIS_VIEW, Sha256Digest::from([0xAA; 32]));
        let notarize_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, namespace, parent.clone()).unwrap())
            .collect();
        let notarization =
            Notarization::from_notarizes(&verifier, notarize_votes.iter()).expect("notarization");
        state.add_verified_notarization(now, notarization);

        // Third call should be ready
        assert!(matches!(state.try_propose(now), ProposeStatus::Ready(_)));
    }

    #[test]
    fn timeout_helpers_reuse_and_reset_deadlines() {
        let mut rng = StdRng::seed_from_u64(2031);
        let Fixture { schemes, .. } = ed25519(&mut rng, 4);
        let scheme = schemes.into_iter().next().unwrap();
        let cfg = Config {
            scheme,
            epoch: 4,
            activity_timeout: 2,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let now = SystemTime::UNIX_EPOCH;
        let view = 1;
        let retry = Duration::from_secs(5);

        // Should return same deadline until something done
        let first = state.next_timeout_deadline(view, now, retry);
        let second = state.next_timeout_deadline(view, now, retry);
        assert_eq!(first, second, "cached deadline should be reused");

        // Handle timeout should return false (not a retry)
        let outcome = state.handle_timeout(view, now);
        assert!(!outcome, "first timeout is not a retry");

        // Set retry deadline
        let later = now + Duration::from_secs(2);
        let third = state.next_timeout_deadline(view, later, retry);
        assert_eq!(third, later + retry, "new retry scheduled after timeout");

        // Confirm retry deadline is set
        let fourth = state.next_timeout_deadline(view, later, retry);
        assert_eq!(fourth, later + retry, "retry deadline should be set");

        // Confirm works if later is far in the future
        let fifth = state.next_timeout_deadline(view, later + Duration::from_secs(100), retry);
        assert_eq!(fifth, later + retry, "retry deadline should be set");

        // Handle timeout should return true whenever called (can be before registered deadline)
        let outcome = state.handle_timeout(view, later);
        assert!(outcome, "subsequent timeout should be treated as retry");
    }

    #[test]
    fn round_prunes_with_min_active() {
        let mut rng = StdRng::seed_from_u64(1337);
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = Config {
            scheme: schemes[0].clone(),
            epoch: 7,
            activity_timeout: 10,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());

        // Add initial rounds
        for view in 0..5 {
            state.ensure_round(view, SystemTime::UNIX_EPOCH + Duration::from_secs(view));
        }

        // Create finalization for view 20
        let proposal_a = Proposal {
            round: Rnd::new(1, 20),
            parent: 0,
            payload: Sha256Digest::from([1u8; 32]),
        };
        let finalization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, namespace, proposal_a.clone()).unwrap())
            .collect();
        let finalization = Finalization::from_finalizes(&verifier, finalization_votes.iter())
            .expect("finalization");
        state.add_verified_finalization(
            SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            finalization,
        );

        // Update last finalize to be in the future
        let removed = state.prune();
        assert_eq!(removed, vec![0, 1, 2, 3, 4]);
        assert_eq!(state.tracked_views(), 1);
    }

    #[test]
    fn parent_payload_returns_parent_digest() {
        let mut rng = StdRng::seed_from_u64(7);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = Config {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        // Create proposal
        let parent_view = 1;
        let parent_payload = Sha256Digest::from([1u8; 32]);
        let parent_proposal = Proposal::new(Rnd::new(1, parent_view), GENESIS_VIEW, parent_payload);
        {
            let parent_round = state.ensure_round(parent_view, now);
            parent_round.record_proposal(false, parent_proposal.clone());
        }

        // Attempt to get parent payload
        let proposal = Proposal::new(Rnd::new(1, 2), parent_view, Sha256Digest::from([9u8; 32]));
        let result = state.parent_payload(2, &proposal);
        assert!(
            matches!(result, Err(ParentValidationError::MissingParentNotarization{ view }) if view == 1),
            "expected missing parent notarization error"
        );

        // Add notarize votes
        {
            let parent_round = state.ensure_round(parent_view, now);
            for scheme in &schemes {
                let vote = Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap();
                parent_round.add_verified_notarize(vote);
            }
        }

        // Get parent
        let digest = state.parent_payload(2, &proposal).expect("parent payload");
        assert_eq!(digest, parent_payload);
    }

    #[test]
    fn parent_payload_errors_without_nullification() {
        let mut rng = StdRng::seed_from_u64(9);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = Config {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        // Create parent proposal
        let parent_view = 1;
        let parent_proposal = Proposal::new(
            Rnd::new(1, parent_view),
            GENESIS_VIEW,
            Sha256Digest::from([2u8; 32]),
        );
        let parent_round = state.ensure_round(parent_view, now);
        parent_round.record_proposal(false, parent_proposal.clone());
        for scheme in &schemes {
            let vote = Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap();
            parent_round.add_verified_notarize(vote);
        }
        state.ensure_round(2, now);

        // Attempt to get parent payload
        let proposal = Proposal::new(Rnd::new(1, 3), parent_view, Sha256Digest::from([3u8; 32]));
        let result = state.parent_payload(3, &proposal);
        assert!(
            matches!(result, Err(ParentValidationError::MissingNullification{ view }) if view == 2),
            "expected missing parent nullification error"
        );
    }

    #[test]
    fn parent_payload_returns_genesis_payload() {
        let mut rng = StdRng::seed_from_u64(21);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = Config {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        // Add nullify votes
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 1)).unwrap())
            .collect();
        {
            let round = state.ensure_round(1, now);
            for vote in votes {
                round.add_verified_nullify(vote);
            }
        }

        // Get genesis payload
        let proposal = Proposal::new(Rnd::new(1, 2), GENESIS_VIEW, Sha256Digest::from([8u8; 32]));
        let genesis = Sha256Digest::from([0u8; 32]);
        let digest = state.parent_payload(2, &proposal).expect("genesis payload");
        assert_eq!(digest, genesis);
    }

    #[test]
    fn parent_payload_rejects_parent_before_finalized() {
        let mut rng = StdRng::seed_from_u64(23);
        let namespace = b"ns";
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = Config {
            scheme: verifier.clone(),
            epoch: 1,
            activity_timeout: 5,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());

        // Add finalization
        let proposal_a = Proposal {
            round: Rnd::new(1, 3),
            parent: 0,
            payload: Sha256Digest::from([1u8; 32]),
        };
        let finalization_votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, namespace, proposal_a.clone()).unwrap())
            .collect();
        let finalization = Finalization::from_finalizes(&verifier, finalization_votes.iter())
            .expect("finalization");
        state.add_verified_finalization(
            SystemTime::UNIX_EPOCH + Duration::from_secs(20),
            finalization,
        );

        // Attempt to verify before finalized
        let proposal = Proposal::new(Rnd::new(1, 4), 2, Sha256Digest::from([6u8; 32]));
        let err = state.parent_payload(4, &proposal).unwrap_err();
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
        let cfg = Config {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        // Create parent proposal
        let parent_view = 2;
        let parent_proposal = Proposal::new(
            Rnd::new(1, parent_view),
            GENESIS_VIEW,
            Sha256Digest::from([4u8; 32]),
        );
        let parent_round = state.ensure_round(parent_view, now);
        parent_round.record_proposal(false, parent_proposal);

        // Create nullified round
        let nullified_round = state.ensure_round(3, now);
        for scheme in &schemes {
            let vote = Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 3)).unwrap();
            nullified_round.add_verified_nullify(vote);
        }

        // Create round with no data
        state.ensure_round(4, now);

        // Create proposal
        let proposal = Proposal::new(Rnd::new(1, 5), parent_view, Sha256Digest::from([5u8; 32]));
        let round = state.ensure_round(5, now);
        round.record_proposal(false, proposal.clone());
        for scheme in schemes.iter().take(2) {
            let vote = Notarize::sign(scheme, namespace, proposal.clone()).unwrap();
            round.add_verified_notarize(vote);
        }

        // Get missing certificates
        let missing = state.missing_certificates(5).expect("missing data");
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
        let cfg = Config {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        // Create parent proposal
        let parent_view = 2;
        let parent_proposal =
            Proposal::new(Rnd::new(1, parent_view), 1, Sha256Digest::from([7u8; 32]));
        {
            let round = state.ensure_round(parent_view, now);
            round.record_proposal(false, parent_proposal.clone());
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap())
                .collect();
            for vote in votes {
                round.add_verified_notarize(vote);
            }
        }

        // Create nullified round
        {
            let round = state.ensure_round(3, now);
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

        // Create proposal
        let proposal = Proposal::new(Rnd::new(1, 4), parent_view, Sha256Digest::from([9u8; 32]));
        {
            let round = state.ensure_round(4, now);
            round.record_proposal(false, proposal.clone());
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
                .collect();
            for vote in votes {
                round.add_verified_notarize(vote);
            }
        }

        // No missing certificates
        assert!(state.missing_certificates(4).is_none());
    }

    #[test]
    fn missing_certificates_none_when_ancestry_not_supported() {
        let mut rng = StdRng::seed_from_u64(27);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let cfg = Config {
            scheme: verifier,
            epoch: 1,
            activity_timeout: 5,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let namespace = b"ns";
        let now = SystemTime::UNIX_EPOCH;

        // Create parent proposal
        let parent_view = 2;
        let parent_proposal =
            Proposal::new(Rnd::new(1, parent_view), 1, Sha256Digest::from([10u8; 32]));
        {
            let round = state.ensure_round(parent_view, now);
            round.record_proposal(false, parent_proposal);
        }

        // Create proposal (with minimal support)
        let proposal_view = 4;
        let proposal = Proposal::new(
            Rnd::new(1, proposal_view),
            parent_view,
            Sha256Digest::from([11u8; 32]),
        );
        {
            let round = state.ensure_round(proposal_view, now);
            round.record_proposal(false, proposal.clone());
            let scheme = schemes.first().expect("at least one signer");
            let vote = Notarize::sign(scheme, namespace, proposal).unwrap();
            round.add_verified_notarize(vote);
            assert!(!round.proposal_ancestry_supported());
        }

        // No missing certificates (not enough support for proposal)
        assert!(state.missing_certificates(proposal_view).is_none());
    }

    #[test]
    fn replay_restores_conflict_state() {
        let mut rng = StdRng::seed_from_u64(2027);
        let Fixture {
            schemes, verifier, ..
        } = ed25519(&mut rng, 4);
        let namespace = b"ns";
        let mut scheme_iter = schemes.into_iter();
        let local_scheme = scheme_iter.next().unwrap();
        let other_schemes: Vec<_> = scheme_iter.collect();
        let epoch = 3;
        let activity_timeout = 5;
        let mut state: State<_, Sha256Digest> = State::new(Config {
            scheme: local_scheme.clone(),
            epoch,
            activity_timeout,
        });
        state.set_genesis(test_genesis());
        let view = 4;
        let now = SystemTime::UNIX_EPOCH;
        let round = Rnd::new(epoch, view);
        let proposal_a = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([21u8; 32]));
        let proposal_b = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([22u8; 32]));
        let local_vote = Notarize::sign(&local_scheme, namespace, proposal_a.clone()).unwrap();

        // Add local vote and replay
        state.add_verified_notarize(now, local_vote.clone());
        state.replay(view, now, &Voter::Notarize(local_vote.clone()));

        // Add conflicting notarization and replay
        let votes_b: Vec<_> = other_schemes
            .iter()
            .take(3)
            .map(|scheme| Notarize::sign(scheme, namespace, proposal_b.clone()).unwrap())
            .collect();
        let conflicting =
            Notarization::from_notarizes(&verifier, votes_b.iter()).expect("certificate");
        state.add_verified_notarization(now, conflicting.clone());
        state.replay(view, now, &Voter::Notarization(conflicting.clone()));

        // No finalize candidate (conflict detected)
        assert!(state.finalize_candidate(view).is_none());

        // Restart state and replay
        let mut restarted: State<_, Sha256Digest> = State::new(Config {
            scheme: local_scheme,
            epoch,
            activity_timeout,
        });
        restarted.set_genesis(test_genesis());
        restarted.add_verified_notarize(now, local_vote.clone());
        restarted.replay(view, now, &Voter::Notarize(local_vote));
        restarted.add_verified_notarization(now, conflicting.clone());
        restarted.replay(view, now, &Voter::Notarization(conflicting));

        // No finalize candidate (conflict detected)
        assert!(restarted.finalize_candidate(view).is_none());
    }

    #[test]
    fn only_notarize_before_nullify() {
        let mut rng = StdRng::seed_from_u64(2031);
        let namespace = b"ns";
        let Fixture { schemes, .. } = ed25519(&mut rng, 4);
        let cfg = Config {
            scheme: schemes[0].clone(),
            epoch: 4,
            activity_timeout: 2,
        };
        let mut state: State<_, Sha256Digest> = State::new(cfg);
        state.set_genesis(test_genesis());
        let now = SystemTime::UNIX_EPOCH;
        let view = 1;
        state.enter_view(
            view,
            now,
            now + Duration::from_secs(1),
            now + Duration::from_secs(2),
            None,
        );

        // Get notarize from another leader
        let proposal = Proposal::new(Rnd::new(1, view), 0, Sha256Digest::from([1u8; 32]));
        let notarize = Notarize::sign(&schemes[0], namespace, proposal.clone()).unwrap();
        state.add_verified_notarize(now, notarize);

        // Attempt to verify
        assert!(matches!(
            state.try_verify(view),
            VerifyStatus::Ready(VerifyReady { .. })
        ));
        assert!(matches!(
            state.verified(view),
            Some(Ok(Some(p))) if p == proposal
        ));

        // Check if willing to notarize
        assert!(matches!(
            state.notarize_candidate(view),
            Some(p) if p == proposal
        ));

        // Handle timeout (not a retry)
        assert!(!state.handle_timeout(view, now));
        let nullify =
            Nullify::sign::<Sha256Digest>(&schemes[1], namespace, Rnd::new(1, view)).unwrap();
        state.add_verified_nullify(now, nullify);

        // Attempt to notarize
        assert!(state.notarize_candidate(view).is_none());
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
