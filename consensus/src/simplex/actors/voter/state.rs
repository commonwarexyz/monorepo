use super::round::Round;
use crate::{
    simplex::{
        elector::{Config as ElectorConfig, Elector},
        interesting,
        metrics::{Leader, Timeout, TimeoutReason},
        min_active,
        scheme::Scheme,
        types::{
            Artifact, Certificate, Context, Finalization, Finalize, Notarization, Notarize,
            Nullification, Nullify, Proposal,
        },
    },
    types::{Epoch, Participant, Round as Rnd, View, ViewDelta},
    Viewable,
};
use commonware_cryptography::{certificate, Digest};
use commonware_runtime::{
    telemetry::metrics::{CounterFamily, Gauge, GaugeExt, MetricsExt as _},
    Clock, Metrics,
};
use commonware_utils::futures::Aborter;
use core::num::NonZeroU64;
use rand_core::CryptoRngCore;
use std::{
    collections::{BTreeMap, BTreeSet},
    mem::{replace, take},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// The view number of the genesis block.
const GENESIS_VIEW: View = View::zero();

/// Reasons a proposal's ancestry cannot yet produce a verification context.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
enum ParentPayloadError {
    #[error("proposal view {proposal_view} is not after parent view {parent_view}")]
    ParentNotBeforeProposal {
        proposal_view: View,
        parent_view: View,
    },
    #[error("intra-term proposal view {proposal_view} skips views between parent view {parent_view} and itself")]
    IntraTermProposalSkipsViews {
        proposal_view: View,
        parent_view: View,
    },
    #[error(
        "proposal view {proposal_view} references parent view {parent_view} below last finalized view {last_finalized}"
    )]
    ParentBeforeFinalized {
        proposal_view: View,
        parent_view: View,
        last_finalized: View,
    },
    #[error(
        "proposal view {proposal_view} references parent view {parent_view} but view {missing_view} is not nullified"
    )]
    MissingNullification {
        proposal_view: View,
        parent_view: View,
        missing_view: View,
    },
    #[error(
        "proposal view {proposal_view} references parent view {parent_view} but the parent is not certified"
    )]
    ParentNotCertified {
        proposal_view: View,
        parent_view: View,
    },
}

impl ParentPayloadError {
    /// Returns whether the ancestry error permanently invalidates the proposal.
    const fn invalid_proposal(self) -> bool {
        match self {
            Self::ParentNotBeforeProposal { .. }
            | Self::IntraTermProposalSkipsViews { .. }
            | Self::ParentBeforeFinalized { .. } => true,
            Self::MissingNullification { .. } | Self::ParentNotCertified { .. } => false,
        }
    }
}

/// Configuration for initializing [`State`].
pub struct Config<S: certificate::Scheme, L: ElectorConfig<S>> {
    pub scheme: S,
    pub elector: L,
    pub epoch: Epoch,
    pub activity_timeout: ViewDelta,
    pub leader_timeout: Duration,
    pub certification_timeout: Duration,
    pub timeout_retry: Duration,
    pub term_length: NonZeroU64,
    pub term_stop_notarize_on_nullify: bool,
    pub same_term_finalization_timeout: Duration,
}

/// Per-[Epoch] state machine.
///
/// Tracks proposals and certificates for each view. Vote aggregation and verification
/// is handled by the [crate::simplex::actors::batcher].
pub struct State<E: Clock + CryptoRngCore + Metrics, S: Scheme<D>, L: ElectorConfig<S>, D: Digest> {
    context: E,
    scheme: S,
    elector: L::Elector,
    epoch: Epoch,
    activity_timeout: ViewDelta,
    leader_timeout: Duration,
    certification_timeout: Duration,
    timeout_retry: Duration,
    term_length: NonZeroU64,
    term_stop_notarize_on_nullify: bool,
    same_term_finalization_timeout: Duration,
    view: View,
    last_finalized: View,
    genesis: Option<D>,
    views: BTreeMap<View, Round<S, D>>,

    /// Views for which we have voted to nullify.
    ///
    /// Used to enforce the term safety rules that suppress later same-term
    /// finalize votes, and optionally later same-term notarize votes.
    nullify_views: BTreeSet<View>,

    /// Views for which we have nullification certificates. Used to answer term-level
    /// nullification queries efficiently (for parent validation and entry certificate fallback)
    /// without scanning all tracked rounds.
    nullification_views: BTreeSet<View>,

    certification_candidates: BTreeSet<View>,
    outstanding_certifications: BTreeSet<View>,

    current_view: Gauge,
    tracked_views: Gauge,
    timeouts: CounterFamily<Timeout>,
    nullifications: CounterFamily<Leader<S::PublicKey>>,
}

impl<E: Clock + CryptoRngCore + Metrics, S: Scheme<D>, L: ElectorConfig<S>, D: Digest>
    State<E, S, L, D>
{
    pub fn new(context: E, cfg: Config<S, L>) -> Self {
        let current_view = context.gauge("current_view", "current view");
        let tracked_views = context.gauge("tracked_views", "tracked views");
        let timeouts = context.family("timeouts", "timed out views");
        let nullifications = context.family("nullifications", "nullifications");

        // Build elector with participants
        let elector = cfg
            .elector
            .build(cfg.scheme.participants(), cfg.term_length);

        Self {
            context,
            scheme: cfg.scheme,
            elector,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            leader_timeout: cfg.leader_timeout,
            certification_timeout: cfg.certification_timeout,
            timeout_retry: cfg.timeout_retry,
            term_length: cfg.term_length,
            term_stop_notarize_on_nullify: cfg.term_stop_notarize_on_nullify,
            same_term_finalization_timeout: cfg.same_term_finalization_timeout,
            view: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            genesis: None,
            views: BTreeMap::new(),
            nullify_views: BTreeSet::new(),
            nullification_views: BTreeSet::new(),
            certification_candidates: BTreeSet::new(),
            outstanding_certifications: BTreeSet::new(),
            current_view,
            tracked_views,
            timeouts,
            nullifications,
        }
    }

    /// Seeds the state machine with the genesis payload and advances into view 1.
    pub fn set_genesis(&mut self, genesis: D) {
        self.genesis = Some(genesis);
        self.enter_view(GENESIS_VIEW.next());
        self.set_leader(GENESIS_VIEW.next(), None);
    }

    /// Returns the epoch managed by this state machine.
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the view currently being driven.
    pub const fn current_view(&self) -> View {
        self.view
    }

    /// Returns the highest finalized view we have observed.
    pub const fn last_finalized(&self) -> View {
        self.last_finalized
    }

    /// Returns the lowest view that must remain in memory to satisfy the activity timeout.
    pub const fn min_active(&self) -> View {
        min_active(self.activity_timeout, self.last_finalized)
    }

    /// Returns the lowest view whose journaled evidence may still affect progress or safety.
    pub fn retention_floor(&self) -> View {
        let first_unfinalized = self.last_finalized.next();
        self.min_active()
            .min(first_unfinalized.term_start(self.term_length))
    }

    /// Returns whether a vote for `pending` is still relevant for progress.
    pub fn is_interesting_vote(&self, pending: View) -> bool {
        interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            pending,
            false,
            self.term_length,
        )
    }

    /// Returns whether a certificate for `pending` is relevant for progress.
    pub fn is_interesting_certificate(&self, pending: View) -> bool {
        interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            pending,
            true,
            self.term_length,
        )
    }

    /// Returns true when the local signer is the participant with index `idx`.
    pub fn is_me(&self, idx: Participant) -> bool {
        self.scheme.me().is_some_and(|me| me == idx)
    }

    /// Advances the view.
    fn enter_view(&mut self, view: View) -> bool {
        if view <= self.view {
            return false;
        }

        let now = self.context.current();
        let leader_deadline = now + self.leader_timeout;
        let certification_deadline = now + self.certification_timeout;
        let same_term_finalization_deadline = now + self.same_term_finalization_timeout;

        let round = self.create_round(view);
        round.set_deadlines(
            leader_deadline,
            certification_deadline,
            same_term_finalization_deadline,
        );
        self.view = view;

        // Update metrics
        let _ = self.current_view.try_set(view.get());
        true
    }

    /// Sets the leader for the given view if it is not already set.
    fn set_leader(&mut self, view: View, certificate: Option<&S::Certificate>) {
        let leader = self.elector.elect(Rnd::new(self.epoch, view), certificate);
        let round = self.create_round(view);
        if round.leader().is_some() {
            return;
        }
        round.set_leader(leader);
    }

    /// Ensures a round exists for the given view.
    fn create_round(&mut self, view: View) -> &mut Round<S, D> {
        self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.scheme.clone(),
                Rnd::new(self.epoch, view),
                self.context.current(),
            )
        })
    }

    /// Returns the next timeout deadline and its reason.
    pub fn next_timeout(&mut self) -> (SystemTime, TimeoutReason) {
        let now = self.context.current();
        let timeout_retry = self.timeout_retry;
        let round_timeout = {
            let round = self.create_round(self.view);
            round
                .next_timeout(now, timeout_retry)
                .expect("current round must always have a timeout")
        };
        // Once the current view is retrying a nullify, retry cadence should be governed
        // by timeout_retry. An older expired same-term finalization deadline may still
        // exist for the first unfinalized view in the term.
        if matches!(round_timeout.1, TimeoutReason::Retry) {
            return round_timeout;
        }
        self.next_same_term_timeout()
            .filter(|(deadline, _)| *deadline <= round_timeout.0)
            .unwrap_or(round_timeout)
    }

    fn next_same_term_timeout(&self) -> Option<(SystemTime, TimeoutReason)> {
        let term_start = self.view.term_start(self.term_length);
        let unfinalized_view = self.last_finalized.next().max(term_start);
        self.views
            .get(&unfinalized_view)
            .and_then(|round| round.same_term_finalization_deadline())
            .map(|deadline| (deadline, TimeoutReason::SameTermFinalizationTimeout))
    }

    /// Constructs a nullify vote for the current view, if eligible.
    ///
    /// Returns `Some((is_retry, nullify))` where `is_retry` is true when this is not the first
    /// nullify emission for `view`. Returns `None` if `view` is not the current view or if we
    /// have already broadcast a finalize vote for this view.
    pub fn construct_nullify(&mut self, view: View) -> Option<(bool, Nullify<S>)> {
        if view != self.view {
            return None;
        }
        let (is_retry, reason, leader) = {
            let round = self.create_round(view);
            let is_retry = round.construct_nullify()?;
            let reason = if is_retry {
                TimeoutReason::Retry
            } else {
                round.timeout_reason().unwrap_or_else(|| {
                    if round.proposal().is_some() {
                        TimeoutReason::CertificationTimeout
                    } else {
                        TimeoutReason::LeaderTimeout
                    }
                })
            };
            (is_retry, reason, round.leader())
        };
        let nullify = Nullify::sign::<D>(&self.scheme, Rnd::new(self.epoch, view))?;
        self.nullify_views.insert(view);
        if let Some(leader) = leader {
            self.timeouts
                .get_or_create(&Timeout::new(&leader.key, reason))
                .inc();
        }
        Some((is_retry, nullify))
    }

    /// Returns the best certificate to help peers enter the current view.
    ///
    /// Finalization is strongest, then nullification, then notarization.
    ///
    /// With stable leaders, if the current view follows a skipped term, prefer
    /// a nullification from that term over a notarization at the previous view.
    /// The nullification is what proves the skipped views were abandoned, which
    /// is the evidence peers need to enter the new term safely.
    pub fn get_best_certificate(&self) -> Option<Certificate<S, D>> {
        let prev = self
            .view
            .previous()
            .expect("we should never be in the genesis view");

        // The genesis view has no certificates.
        if prev == GENESIS_VIEW {
            return None;
        }

        // Check if there was a finalization in the previous view
        if let Some(finalization) = self.finalization(prev).cloned() {
            return Some(Certificate::Finalization(finalization));
        }

        // At a term boundary, prefer the highest nullification from the previous
        // term because it proves the skipped views were abandoned.
        if self.view.is_term_start(self.term_length) {
            let term_start = prev.term_start(self.term_length);
            // Check for the highest nullification in the previous term
            if let Some(nullification) = self
                .nullification_views
                .range(term_start..=prev)
                .next_back()
                .copied()
                .and_then(|v| self.nullification(v).cloned())
            {
                return Some(Certificate::Nullification(nullification));
            }
        }

        // Check if there was a notarization in the previous view
        if let Some(notarization) = self.notarization(prev).cloned() {
            return Some(Certificate::Notarization(notarization));
        }

        warn!(%prev, "entry certificate not found");
        None
    }

    /// Inserts a notarization certificate and prepares the next view's leader.
    ///
    /// Does not advance into the next view until certification passes.
    /// Adds to certification candidates if successful.
    pub fn add_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        let view = notarization.view();
        // Do not advance to the next view until the certification passes
        self.set_leader(view.next(), Some(&notarization.certificate));
        let result = self.create_round(view).add_notarization(notarization);
        if result.0 && view > self.last_finalized {
            self.certification_candidates.insert(view);
        }
        result
    }

    /// Inserts a nullification certificate and advances to the first view of the next term.
    /// When `term_length` is 1 this is equivalent to advancing by one view.
    ///
    /// Unlike finalization, nullification does not cancel pending certification work for the
    /// same view. The next proposer may build on a certified notarization we haven't finished processing
    /// yet and stopping here could halt the network (stability relies on coming to a shared understanding
    /// of what can be considered a valid parent, otherwise two regions of the network could build on ancestries
    /// the other considers invalid with no way to resolve the conflict).
    pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
        let view = nullification.view();

        // Skip to the start of the next term.
        let next_view = view.next_term_start(self.term_length);
        self.enter_view(next_view);
        self.set_leader(next_view, Some(&nullification.certificate));

        // Track nullification metric per leader (if we know who the leader was)
        let round = self.create_round(view);
        let added = round.add_nullification(nullification);
        let leader = added.then(|| round.leader()).flatten();
        self.nullification_views.insert(view);

        if let Some(leader) = leader {
            self.nullifications.get_or_create_by(&leader.key).inc();
        }

        added
    }

    /// Inserts a finalization certificate, updates the finalized height, and advances the view.
    pub fn add_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        let view = finalization.view();
        if view > self.last_finalized {
            self.last_finalized = view;

            // Prune certification candidates at or below finalized view.
            // Finalization is definitive, so these certifications are no longer relevant.
            self.certification_candidates.retain(|v| *v > view);

            // Abort outstanding certifications at or below finalized view for the same reason.
            let keep = self.outstanding_certifications.split_off(&view.next());
            for v in replace(&mut self.outstanding_certifications, keep) {
                if let Some(round) = self.views.get_mut(&v) {
                    round.abort_certify();
                }
            }
        }

        self.enter_view(view.next());
        self.set_leader(view.next(), Some(&finalization.certificate));
        self.create_round(view).add_finalization(finalization)
    }

    /// Construct a notarize vote for this view when we're ready to sign.
    ///
    /// When `term_stop_notarize_on_nullify` is enabled, a prior local nullify in
    /// the same term suppresses later same-term notarize votes.
    pub fn construct_notarize(&mut self, view: View) -> Option<Notarize<S, D>> {
        if self.term_stop_notarize_on_nullify && self.has_prior_local_nullify_in_term(view) {
            return None;
        }
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_notarize().cloned())?;

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Notarize::sign(&self.scheme, candidate)
    }

    /// Construct a finalize vote if the round provides a candidate and it is safe to do so.
    ///
    /// The term safety rule applies: do not vote to finalize a later view in a
    /// term if we already voted to nullify an earlier view in that same term.
    pub fn construct_finalize(&mut self, view: View) -> Option<Finalize<S, D>> {
        // We don't need to finalize views that are already finalized.
        if view <= self.last_finalized {
            return None;
        }

        if self.has_prior_local_nullify_in_term(view) {
            return None;
        }

        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_finalize().cloned())?;

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Finalize::sign(&self.scheme, candidate)
    }

    /// Construct a notarization certificate once the round has quorum.
    pub fn broadcast_notarization(&mut self, view: View) -> Option<Notarization<S, D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.broadcast_notarization())
    }

    /// Return a notarization certificate, if one exists.
    pub fn notarization(&self, view: View) -> Option<&Notarization<S, D>> {
        self.views.get(&view).and_then(|round| round.notarization())
    }

    /// Return a nullification certificate, if one exists.
    pub fn nullification(&self, view: View) -> Option<&Nullification<S>> {
        self.views
            .get(&view)
            .and_then(|round| round.nullification())
    }

    /// Return a finalization certificate, if one exists.
    pub fn finalization(&self, view: View) -> Option<&Finalization<S, D>> {
        self.views.get(&view).and_then(|round| round.finalization())
    }

    /// Returns the proposal for `view` if it is eligible for forwarding.
    pub fn forwardable_proposal(&self, view: View) -> Option<Proposal<D>> {
        let round = self.views.get(&view)?;
        if round.finalization().is_some() || round.is_certified() {
            return round.proposal().cloned();
        }
        None
    }

    /// Construct a nullification certificate once the round has quorum.
    pub fn broadcast_nullification(&mut self, view: View) -> Option<Nullification<S>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.broadcast_nullification())
    }

    /// Construct a finalization certificate once the round has quorum.
    pub fn broadcast_finalization(&mut self, view: View) -> Option<Finalization<S, D>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.broadcast_finalization())
    }

    /// Replays a journaled artifact into the appropriate round during recovery.
    ///
    /// Restores round-level broadcast flags (via [`Round::replay`]) and
    /// tracking sets (`nullify_views`, `nullification_views`) so that
    /// term-safety checks work correctly after a restart.
    pub fn replay(&mut self, artifact: &Artifact<S, D>) {
        if let Artifact::Nullify(n) = artifact {
            self.nullify_views.insert(n.view());
        }
        if let Artifact::Nullification(n) = artifact {
            self.nullification_views.insert(n.view());
        }
        self.create_round(artifact.view()).replay(artifact);
    }

    /// Returns the leader index for `view` if we already entered it.
    pub fn leader_index(&self, view: View) -> Option<Participant> {
        self.views
            .get(&view)
            .and_then(|round| round.leader().map(|leader| leader.idx))
    }

    /// Returns how long `view` has been live based on the clock samples stored by its round.
    pub fn elapsed_since_start(&self, view: View) -> Option<Duration> {
        let now = self.context.current();
        self.views
            .get(&view)
            .map(|round| round.elapsed_since_start(now))
    }

    /// Immediately expires `view` on first timeout, forcing deadlines to trigger on the next tick.
    ///
    /// If the round has already been marked timed out, this preserves the existing
    /// retry schedule.
    ///
    /// This only records the first timeout reason for the view. Metrics are emitted
    /// when the first timeout nullify vote is constructed.
    pub fn trigger_timeout(&mut self, view: View, reason: TimeoutReason) {
        if view != self.view {
            return;
        }

        let now = self.context.current();
        let round = self.create_round(view);
        if round.is_retrying_nullify() {
            return;
        }
        let (_, is_first_timeout) = round.set_timeout_reason(reason);
        if is_first_timeout {
            round.set_deadlines(now, now, now);
        }
    }

    /// Attempt to propose a new block.
    pub fn try_propose(&mut self) -> Option<Context<D, S::PublicKey>> {
        // Perform fast checks before lookback
        let view = self.view;
        if view == GENESIS_VIEW {
            return None;
        }
        if !self
            .views
            .get_mut(&view)
            .expect("view must exist")
            .should_propose()
        {
            return None;
        }

        // Look for parent
        let parent = self.find_parent(view);
        let (parent_view, parent_payload) = match parent {
            Ok(parent) => parent,
            Err(missing) => {
                debug!(%view, %missing, "missing parent during proposal");
                return None;
            }
        };
        let leader = self
            .views
            .get_mut(&view)
            .expect("view must exist")
            .try_propose()?;
        Some(Context {
            round: Rnd::new(self.epoch, view),
            leader: leader.key,
            parent: (parent_view, parent_payload),
        })
    }

    /// Records a locally constructed proposal once the automaton finishes building it.
    pub fn proposed(&mut self, proposal: Proposal<D>) -> bool {
        self.views
            .get_mut(&proposal.view())
            .map(|round| round.proposed(proposal))
            .unwrap_or(false)
    }

    /// Sets a proposal received from the batcher (leader's first notarize vote).
    ///
    /// Returns true if the proposal should trigger verification, false otherwise.
    pub fn set_proposal(&mut self, view: View, proposal: Proposal<D>) -> bool {
        self.create_round(view).set_proposal(proposal)
    }

    /// Attempt to verify a proposed block.
    ///
    /// Unlike during proposal, we don't use a verification opportunity
    /// to backfill missing certificates (a malicious proposer could
    /// ask us to fetch junk).
    #[allow(clippy::type_complexity)]
    pub fn try_verify(&mut self) -> Option<(Context<D, S::PublicKey>, Proposal<D>)> {
        let view = self.view;
        let (leader, proposal) = self.views.get(&view)?.should_verify()?;
        let parent_payload = match self.parent_payload(&proposal) {
            Ok(parent_payload) => parent_payload,
            Err(err) => {
                if err.invalid_proposal() {
                    warn!(round = ?proposal.round, ?err, "proposal failed verification");
                    self.trigger_timeout(view, TimeoutReason::InvalidProposal);
                } else {
                    debug!(
                        %view,
                        ?proposal,
                        ?err,
                        "proposal exists but ancestry is not yet certified"
                    );
                }
                return None;
            }
        };
        if !self.views.get_mut(&view)?.try_verify() {
            return None;
        }
        let context = Context {
            round: proposal.round,
            leader: leader.key,
            parent: (proposal.parent, parent_payload),
        };
        Some((context, proposal))
    }

    /// Marks proposal verification as complete when the peer payload validates.
    pub fn verified(&mut self, view: View) -> bool {
        self.views
            .get_mut(&view)
            .map(|round| round.verified())
            .unwrap_or(false)
    }

    /// Store the abort handle for an in-flight certification request.
    pub fn set_certify_handle(&mut self, view: View, handle: Aborter) {
        let Some(round) = self.views.get_mut(&view) else {
            return;
        };
        round.set_certify_handle(handle);
        self.outstanding_certifications.insert(view);
    }

    /// Takes all certification candidates and returns proposals ready for
    /// certification, along with whether the proposal was built locally.
    ///
    /// Certification may be inferred only when we have explicit evidence that we
    /// proposed this exact payload for the round, either in the current process
    /// or via replay of our durable local vote. In certain cases for Byzantine nodes,
    /// it is possible that a certificate is received for a proposal that we did not propose (although
    /// we are the leader).
    pub fn certify_candidates(&mut self) -> Vec<(Proposal<D>, bool)> {
        let candidates = take(&mut self.certification_candidates);
        candidates
            .into_iter()
            .filter_map(|view| {
                if view <= self.last_finalized {
                    return None;
                }
                let candidate = self.views.get_mut(&view)?.try_certify()?;
                Some(candidate)
            })
            .collect()
    }

    /// Marks proposal certification as complete and returns the notarization.
    ///
    /// Returns `None` if the view was already pruned. Otherwise returns the notarization
    /// regardless of success/failure.
    pub fn certified(&mut self, view: View, is_success: bool) -> Option<Notarization<S, D>> {
        let round = self.views.get_mut(&view)?;
        round.certified(is_success);

        // Remove from outstanding since certification is complete
        self.outstanding_certifications.remove(&view);

        // Get notarization before advancing state
        let notarization = round
            .notarization()
            .cloned()
            .expect("notarization must exist for certified view");

        if is_success {
            self.enter_view(view.next());
        } else {
            self.trigger_timeout(view, TimeoutReason::FailedCertification);
        }

        Some(notarization)
    }

    /// Drops tracked rounds below the activity horizon and stale safety-evidence indexes.
    pub fn prune(&mut self) -> Vec<View> {
        let min = self.min_active();
        let kept = self.views.split_off(&min);
        let removed = replace(&mut self.views, kept).into_keys().collect();

        // A nullification can cover the rest of its term, and a local nullify
        // blocks finalization in the same term. Use the same floor as journal
        // pruning so restart preserves the safety evidence we keep in memory.
        let retain_from = self.retention_floor();
        self.nullification_views = self.nullification_views.split_off(&retain_from);
        self.nullify_views = self.nullify_views.split_off(&retain_from);

        // Update metrics
        let _ = self.tracked_views.try_set(self.views.len());
        removed
    }

    /// Returns the payload of the proposal if it is certified (including finalized).
    fn is_certified(&self, view: View) -> Option<&D> {
        // Special case for genesis view
        if view == GENESIS_VIEW {
            return Some(self.genesis.as_ref().expect("genesis must be present"));
        }

        // Check for explicit certification
        let round = self.views.get(&view)?;
        if round.finalization().is_some() || round.is_certified() {
            return Some(&round.proposal().expect("proposal must exist").payload);
        }
        None
    }

    /// Returns whether `view` is covered by a prior-or-equal nullification in its term.
    fn covered_by_term_nullification(&self, view: View) -> bool {
        let term_start = view.term_start(self.term_length);
        self.nullification_views
            .range(term_start..=view)
            .next_back()
            .is_some()
    }

    /// Returns whether we have already locally nullified an earlier view in `view`'s term.
    fn has_prior_local_nullify_in_term(&self, view: View) -> bool {
        let term_start = view.term_start(self.term_length);
        self.nullify_views
            .range(term_start..view)
            .next_back()
            .is_some()
    }

    /// Returns the first non-nullified view in the open interval (after, before).
    ///
    /// A nullification nullifies all views in the rest of its term.
    fn first_unnullified_view(&self, after: View, before: View) -> Option<View> {
        if before <= after {
            return None;
        }

        let mut cursor = after.next();
        while cursor < before {
            if !self.covered_by_term_nullification(cursor) {
                return Some(cursor);
            }
            cursor = cursor.next_term_start(self.term_length);
        }
        None
    }

    /// Returns true if certification for the view was aborted due to finalization.
    #[cfg(test)]
    pub fn is_certify_aborted(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.is_certify_aborted())
    }

    /// Finds the parent payload for a given view: the highest certified view
    /// below `view`, if it has no missing required nullification. When there is
    /// no certified view below `view`, the parent is the genesis view and the
    /// genesis payload.
    fn find_parent(&self, view: View) -> Result<(View, D), View> {
        if !view.is_term_start(self.term_length) {
            let parent = view
                .previous()
                .expect("non-genesis views must have a previous view");
            return self
                .is_certified(parent)
                .copied()
                .map(|payload| (parent, payload))
                .ok_or(parent);
        }

        // Find the highest certified view below `view`, or use genesis when none.
        let result = self
            .views
            .range(..view)
            .rev()
            .find_map(|(&v, _)| self.is_certified(v).map(|p| (v, p)));
        let (candidate, payload) = match result {
            Some((v, p)) => (v, p),
            None => (
                GENESIS_VIEW,
                self.genesis
                    .as_ref()
                    .expect("genesis must be set when finding parent with no certified views"),
            ),
        };

        // If there are any missing nullifications, return an error.
        // Any lower certified views would also result in an error.
        if let Some(missing_view) = self.first_unnullified_view(candidate, view) {
            return Err(missing_view);
        }

        // Return the valid parent
        Ok((candidate, *payload))
    }

    /// Returns the payload of the proposal's parent if:
    /// - It is less-than the proposal view.
    /// - It is greater-than-or-equal-to the last finalized view.
    /// - It is certified (or finalized, which implies certification).
    /// - All views between it and the proposal view have been nullified.
    fn parent_payload(&self, proposal: &Proposal<D>) -> Result<D, ParentPayloadError> {
        // Sanity check that the parent view is less than the proposal view.
        let (view, parent) = (proposal.view(), proposal.parent);
        if view <= parent {
            return Err(ParentPayloadError::ParentNotBeforeProposal {
                proposal_view: view,
                parent_view: parent,
            });
        }

        // Ignore any requests for outdated parent views.
        if parent < self.last_finalized {
            return Err(ParentPayloadError::ParentBeforeFinalized {
                proposal_view: view,
                parent_view: parent,
                last_finalized: self.last_finalized,
            });
        }

        // Check that intra-term proposals do not skip any views.
        if !view.is_term_start(self.term_length) && view != parent.next() {
            return Err(ParentPayloadError::IntraTermProposalSkipsViews {
                proposal_view: view,
                parent_view: parent,
            });
        }

        // Check that required nullifications exist between the parent and proposal views.
        if let Some(missing_view) = self.first_unnullified_view(parent, view) {
            return Err(ParentPayloadError::MissingNullification {
                proposal_view: view,
                parent_view: parent,
                missing_view,
            });
        }

        // May return `None` if the parent view is not yet either:
        // - notarized and certified
        // - finalized
        self.is_certified(parent)
            .copied()
            .ok_or(ParentPayloadError::ParentNotCertified {
                proposal_view: view,
                parent_view: parent,
            })
    }

    /// Returns the certificate for the parent of the proposal at the given view.
    pub fn parent_certificate(&mut self, view: View) -> Option<Certificate<S, D>> {
        let parent = {
            let view = self.views.get(&view)?.proposal()?.parent;
            self.views.get(&view)?
        };

        if let Some(f) = parent.finalization().cloned() {
            return Some(Certificate::Finalization(f));
        }
        if let Some(n) = parent.notarization().cloned() {
            return Some(Certificate::Notarization(n));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        elector::RoundRobin,
        scheme::ed25519,
        types::{Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner, Supervisor as _};
    use commonware_utils::{futures::AbortablePool, NZU64};
    use std::time::Duration;

    fn test_genesis() -> Sha256Digest {
        Sha256Digest::from([0u8; 32])
    }

    type TestState = State<deterministic::Context, ed25519::Scheme, RoundRobin, Sha256Digest>;

    fn setup_state(
        context: &mut deterministic::Context,
        validators: usize,
        epoch: u64,
        activity_timeout: u64,
        term_length: u64,
    ) -> (Fixture<ed25519::Scheme>, TestState) {
        let namespace = b"ns".to_vec();
        let fixture = ed25519::fixture(
            context,
            &namespace,
            validators.try_into().expect("validator count fits in u32"),
        );
        let state = State::new(
            context.child("state"),
            Config {
                scheme: fixture.verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(epoch),
                activity_timeout: ViewDelta::new(activity_timeout),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: std::num::NonZeroU64::new(term_length)
                    .expect("term length must be non-zero"),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(30),
            },
        );
        let mut state = state;
        state.set_genesis(test_genesis());
        (fixture, state)
    }

    #[test]
    fn certificate_candidates_respect_force_flag() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(11),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(1),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());

            // Add notarization
            let notarize_view = View::new(3);
            let notarize_round = Rnd::new(Epoch::new(11), notarize_view);
            let notarize_proposal =
                Proposal::new(notarize_round, GENESIS_VIEW, Sha256Digest::from([50u8; 32]));
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, notarize_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);

            // Produce candidate once
            assert!(state.broadcast_notarization(notarize_view).is_some());
            assert!(state.broadcast_notarization(notarize_view).is_none());
            assert!(state.notarization(notarize_view).is_some());

            // Add nullification
            let nullify_view = View::new(4);
            let nullify_round = Rnd::new(Epoch::new(11), nullify_view);
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, nullify_round).expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            state.add_nullification(nullification);

            // Produce candidate once
            assert!(state.broadcast_nullification(nullify_view).is_some());
            assert!(state.broadcast_nullification(nullify_view).is_none());
            assert!(state.nullification(nullify_view).is_some());

            // Add finalization
            let finalize_view = View::new(5);
            let finalize_round = Rnd::new(Epoch::new(11), finalize_view);
            let finalize_proposal =
                Proposal::new(finalize_round, GENESIS_VIEW, Sha256Digest::from([51u8; 32]));
            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, finalize_proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Produce candidate once
            assert!(state.broadcast_finalization(finalize_view).is_some());
            assert!(state.broadcast_finalization(finalize_view).is_none());
            assert!(state.finalization(finalize_view).is_some());
        });
    }

    #[test]
    fn timeout_helpers_reuse_and_reset_deadlines() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[0].clone(); // leader of view 1
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: local_scheme.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(30),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Should return same deadline until something done
            let first = state.next_timeout();
            let second = state.next_timeout();
            assert_eq!(first, second, "cached timeout should be reused");

            // Timeout-mode nullify: first emission should not be marked as retry.
            let (was_retry, _) = state
                .construct_nullify(state.current_view())
                .expect("first timeout nullify should exist");
            assert!(!was_retry, "first timeout is not a retry");

            // Set retry deadline
            context.sleep(Duration::from_secs(2)).await;
            let later = context.current();

            // Confirm retry deadline is set
            let third = state.next_timeout();
            assert_eq!(
                third,
                (later + retry, TimeoutReason::Retry),
                "new retry scheduled after timeout"
            );

            // Confirm retry deadline remains set
            let fourth = state.next_timeout();
            assert_eq!(fourth, third, "retry deadline should be set");

            // Confirm works if later is far in the future
            context.sleep(Duration::from_secs(10)).await;
            let fifth = state.next_timeout();
            assert_eq!(
                fifth,
                (later + retry, TimeoutReason::Retry),
                "retry deadline should be set"
            );

            // Timeout-mode nullify: second emission should be marked as retry.
            let (was_retry, _) = state
                .construct_nullify(state.current_view())
                .expect("retry timeout nullify should exist");
            assert!(was_retry, "subsequent timeout should be treated as retry");

            // Confirm retry deadline is set
            let sixth = state.next_timeout();
            let later = context.current();
            assert_eq!(
                sixth,
                (later + retry, TimeoutReason::Retry),
                "retry deadline should be set"
            );
        });
    }

    #[test]
    fn nullify_preserves_retry_backoff_after_first_timeout_vote() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes,
                participants,
                ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(30),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(30),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("first timeout nullify should exist");
            assert!(!was_retry, "first timeout should not be marked as retry");

            let leader = state.leader_index(view).expect("leader must be set");
            let leader_key = &participants[leader.get() as usize];
            let label = Timeout::new(leader_key, TimeoutReason::LeaderTimeout);
            assert_eq!(
                state.timeouts.get_or_create(&label).get(),
                1,
                "first timeout nullify should record a leader-timeout metric"
            );

            context.sleep(Duration::from_secs(2)).await;
            let now = context.current();
            let retry_deadline = state.next_timeout();
            assert_eq!(
                retry_deadline,
                (now + retry, TimeoutReason::Retry),
                "first retry should honor configured nullify backoff"
            );

            // Repeated timeout hints for the same view should not reset retry backoff.
            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            assert_eq!(
                state.next_timeout(),
                retry_deadline,
                "retry backoff should be preserved after repeated timeout hints"
            );
        });
    }

    #[test]
    fn nullify_without_reason_reuses_first_recorded_reason() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes,
                participants,
                ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(31),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(30),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            state.trigger_timeout(view, TimeoutReason::MissingProposal);
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);

            let leader = state.leader_index(view).expect("leader must be set");
            let leader_key = &participants[leader.get() as usize];
            let missing = Timeout::new(leader_key, TimeoutReason::MissingProposal);
            let leader_timeout = Timeout::new(leader_key, TimeoutReason::LeaderTimeout);
            assert_eq!(state.timeouts.get_or_create(&missing).get(), 1);
            assert_eq!(state.timeouts.get_or_create(&leader_timeout).get(), 0);

            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("retry timeout nullify should exist");
            assert!(was_retry);
            assert_eq!(state.timeouts.get_or_create(&missing).get(), 1);
        });
    }

    #[test]
    fn notarization_keeps_certification_timeout_pending_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(32),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let proposal = Proposal::new(
                Rnd::new(state.epoch(), view),
                GENESIS_VIEW,
                Sha256Digest::from([52u8; 32]),
            );

            // Proposal arrival clears leader timeout and leaves only the certification timeout.
            assert!(state.set_proposal(view, proposal.clone()));
            let certification_deadline = state.next_timeout();
            assert_eq!(
                certification_deadline,
                (
                    context.current() + Duration::from_secs(2),
                    TimeoutReason::CertificationTimeout,
                )
            );

            // Receiving a notarization should not clear the certification timeout while certification is pending.
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
                .collect();
            let notarization = Notarization::from_notarizes(&verifier, votes.iter(), &Sequential)
                .expect("notarization");
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_none());
            assert_eq!(
                state.next_timeout(),
                certification_deadline,
                "certification timeout must continue to bound certification latency"
            );

            // If certification stalls beyond the certification timeout, timeout handling should fire immediately.
            context.sleep(Duration::from_secs(3)).await;
            assert!(
                state.next_timeout().0 <= context.current(),
                "stalled certification should leave the view timed out"
            );
        });
    }

    #[test]
    fn same_term_finalization_timeout_tracks_oldest_unfinalized_view() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(33),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(3),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            let oldest_deadline = context.current() + Duration::from_secs(4);

            let certify_view = |state: &mut TestState,
                                schemes: &[ed25519::Scheme],
                                verifier: &ed25519::Scheme,
                                view: View,
                                parent: View,
                                payload: [u8; 32]| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(33), view),
                    parent,
                    Sha256Digest::from(payload),
                );
                assert!(state.set_proposal(view, proposal.clone()));
                assert!(state.try_verify().is_some());
                assert!(state.verified(view));
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
                    .collect();
                let notarization =
                    Notarization::from_notarizes(verifier, votes.iter(), &Sequential)
                        .expect("notarization");
                assert!(state.add_notarization(notarization).0);
            };

            certify_view(
                &mut state,
                &schemes,
                &verifier,
                View::new(1),
                GENESIS_VIEW,
                [1u8; 32],
            );
            context.sleep(Duration::from_secs(1)).await;
            assert!(state.certified(View::new(1), true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            certify_view(
                &mut state,
                &schemes,
                &verifier,
                View::new(2),
                View::new(1),
                [2u8; 32],
            );
            context.sleep(Duration::from_millis(1500)).await;
            assert!(state.certified(View::new(2), true).is_some());
            assert_eq!(state.current_view(), View::new(3));

            let proposal_v3 = Proposal::new(
                Rnd::new(Epoch::new(33), View::new(3)),
                View::new(2),
                Sha256Digest::from([3u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), proposal_v3));
            assert!(state.try_verify().is_some());
            assert!(state.verified(View::new(3)));

            assert_eq!(
                state.next_timeout(),
                (oldest_deadline, TimeoutReason::SameTermFinalizationTimeout,),
                "oldest unfinalized view in the term should drive the timeout"
            );

            context.sleep(Duration::from_secs(2)).await;
            assert_eq!(
                state.next_timeout(),
                (oldest_deadline, TimeoutReason::SameTermFinalizationTimeout,)
            );
        });
    }

    #[test]
    fn same_term_finalization_timeout_ignores_prior_terms() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(34),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(11),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(3),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(12),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            context.sleep(Duration::from_secs(3)).await;

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(34), View::new(1)))
                        .expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(4));
            let leader_deadline = context.current() + Duration::from_secs(10);

            // At this point the same-term deadline from view 1 has elapsed, but
            // the current view's leader deadline has not. If prior-term same-term
            // deadlines leaked, they would win here.
            context.sleep(Duration::from_millis(9500)).await;
            assert_eq!(
                state.next_timeout(),
                (leader_deadline, TimeoutReason::LeaderTimeout)
            );
        });
    }

    #[test]
    fn retry_takes_precedence_over_expired_same_term_timeout() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let retry = Duration::from_millis(3);
            let same_term_timeout = Duration::from_millis(30);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(35),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_millis(10),
                certification_timeout: Duration::from_millis(20),
                timeout_retry: retry,
                term_length: NZU64!(3),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: same_term_timeout,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            let oldest_deadline = context.current() + same_term_timeout;

            // Certify view 1 late enough that its same-term finalization deadline expires
            // after we enter view 2, then ensure view 2 nullify retries are rate-limited.
            let view_1 = View::new(1);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(35), view_1),
                GENESIS_VIEW,
                Sha256Digest::from([35u8; 32]),
            );
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
                .collect();
            let notarization = Notarization::from_notarizes(&verifier, votes.iter(), &Sequential)
                .expect("notarization");
            assert!(state.add_notarization(notarization).0);

            context.sleep(Duration::from_millis(25)).await;
            assert!(state.certified(view_1, true).is_some());
            assert_eq!(state.current_view(), View::new(2));

            context.sleep(Duration::from_millis(5)).await;
            assert_eq!(
                state.next_timeout(),
                (oldest_deadline, TimeoutReason::SameTermFinalizationTimeout,)
            );

            let view_2 = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view_2)
                .expect("same-term timeout should nullify current view");
            assert!(!was_retry);

            assert_eq!(
                state.next_timeout(),
                (context.current() + retry, TimeoutReason::Retry),
                "expired same-term deadline must not override nullify retry cadence"
            );
        });
    }

    #[test]
    fn local_nullify_preserves_same_term_finalization_timeout() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let same_term_timeout = Duration::from_secs(4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(36),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(3),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: same_term_timeout,
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view_1 = state.current_view();
            let oldest_deadline = context.current() + same_term_timeout;
            let (was_retry, _) = state
                .construct_nullify(view_1)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);

            let proposal = Proposal::new(
                Rnd::new(Epoch::new(36), view_1),
                GENESIS_VIEW,
                Sha256Digest::from([36u8; 32]),
            );
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("notarize"))
                .collect();
            let notarization = Notarization::from_notarizes(&verifier, votes.iter(), &Sequential)
                .expect("notarization");
            assert!(state.add_notarization(notarization).0);

            context.sleep(same_term_timeout).await;
            assert!(state.certified(view_1, true).is_some());
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(
                state.next_timeout(),
                (oldest_deadline, TimeoutReason::SameTermFinalizationTimeout,),
                "oldest unfinalized view should remain tracked after local nullify"
            );
        });
    }

    #[test]
    fn expire_old_round_is_noop() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(12),
                activity_timeout: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Expiring a non-current view should do nothing.
            let deadline_v1 = state.next_timeout();
            state.trigger_timeout(View::zero(), TimeoutReason::Inactivity);
            assert_eq!(state.current_view(), View::new(1));
            assert_eq!(state.next_timeout(), deadline_v1);
            assert!(
                !state.views.contains_key(&View::zero()),
                "old round should not be created when expire is ignored"
            );

            // Move to view 2 so view 1 becomes stale.
            let view_1 = View::new(1);
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(state.epoch(), view_1))
                        .expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &votes, &Sequential).expect("nullify");
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(2));

            let deadline_v2 = state.next_timeout();
            state.trigger_timeout(view_1, TimeoutReason::Inactivity);
            assert_eq!(state.current_view(), View::new(2));
            assert_eq!(state.next_timeout(), deadline_v2);
        });
    }

    #[test]
    fn entering_next_view_resets_expired_timeout_state() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let leader_timeout = Duration::from_secs(1);
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(13),
                activity_timeout: ViewDelta::new(3),
                leader_timeout,
                certification_timeout: Duration::from_secs(2),
                timeout_retry: retry,
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view_1 = state.current_view();
            assert_eq!(view_1, View::new(1));

            // Force the current view into timeout mode and schedule a retry.
            state.trigger_timeout(view_1, TimeoutReason::LeaderTimeout);
            assert!(
                state.next_timeout().0 <= context.current(),
                "current view should be expired after timeout is triggered"
            );
            let (was_retry, _) = state
                .construct_nullify(view_1)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);
            let retry_deadline = state.next_timeout();
            assert_eq!(
                retry_deadline,
                (context.current() + retry, TimeoutReason::Retry),
                "timed-out view should schedule a retry"
            );

            // Advancing into the next view must install fresh deadlines instead of reusing
            // the expired/retrying state from the previous view.
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(state.epoch(), view_1))
                        .expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &votes, &Sequential).expect("nullify");
            assert!(state.add_nullification(nullification));

            let view_2 = state.current_view();
            assert_eq!(view_2, View::new(2));
            let next_deadline = state.next_timeout();
            assert_eq!(
                next_deadline,
                (
                    context.current() + leader_timeout,
                    TimeoutReason::LeaderTimeout
                ),
                "next view should start with a fresh leader timeout"
            );
            assert_ne!(
                next_deadline, retry_deadline,
                "next view must not inherit the previous view retry deadline"
            );
        });
    }

    #[test]
    fn nullify_only_records_metric_once() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes,
                participants,
                ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(12),
                activity_timeout: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let leader = state.leader_index(view).unwrap();
            let leader_key = &participants[leader.get() as usize];
            let label = Timeout::new(leader_key, TimeoutReason::LeaderNullify);

            // Fast-path trigger should not record metrics until we emit nullify.
            state.trigger_timeout(view, TimeoutReason::LeaderNullify);
            let expired_at = state.next_timeout();
            context.sleep(Duration::from_secs(1)).await;

            // Repeated timeout hints before emitting nullify should preserve the first timeout.
            state.trigger_timeout(view, TimeoutReason::LeaderTimeout);
            assert_eq!(
                state.next_timeout(),
                expired_at,
                "repeated timeout hints should not reset the expired deadline"
            );
            assert_eq!(state.timeouts.get_or_create(&label).get(), 0);

            // First emitted nullify should record the metric.
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("first timeout nullify should exist");
            assert!(!was_retry);
            assert_eq!(state.timeouts.get_or_create(&label).get(), 1);

            // Retries are classified separately from the original timeout reason.
            state.trigger_timeout(view, TimeoutReason::LeaderTimeout);
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("retry timeout nullify should exist");
            assert!(was_retry);
            assert_eq!(state.timeouts.get_or_create(&label).get(), 1);

            let retry_label = Timeout::new(leader_key, TimeoutReason::Retry);
            assert_eq!(state.timeouts.get_or_create(&retry_label).get(), 1);
        });
    }

    #[test]
    fn construct_nullify_current_view_only() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[0].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());
            let current = state.current_view();
            let next = current.next();

            // Non-current views are not eligible.
            assert!(state.construct_nullify(next).is_none());

            // Observe a nullification for current view, which advances us to the next view.
            let current_round = Rnd::new(Epoch::new(4), current);
            let current_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, current_round).expect("nullify")
                })
                .collect();
            let current_nullification =
                Nullification::from_nullifies(&verifier, &current_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(current_nullification));
            assert_eq!(state.current_view(), next);

            // Past views remain ineligible even if they have a nullification certificate.
            assert!(state.construct_nullify(current).is_none());

            // Timeout path on current view: first attempt then retry.
            let (was_retry, _) = state
                .construct_nullify(next)
                .expect("first timeout nullify for current view should be emitted");
            assert!(!was_retry);
            let (was_retry, _) = state
                .construct_nullify(next)
                .expect("retry timeout nullify for current view should be emitted");
            assert!(was_retry);
        });
    }

    #[test]
    fn round_prunes_with_min_active() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(7),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            // Add initial rounds
            for view in 0..5 {
                state.create_round(View::new(view));
            }

            // Create finalization for view 20
            let proposal_a = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(20)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_a.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Update last finalize to be in the future
            let removed = state.prune();
            assert_eq!(
                removed,
                vec![
                    View::new(0),
                    View::new(1),
                    View::new(2),
                    View::new(3),
                    View::new(4)
                ]
            );
            assert_eq!(state.views.len(), 2); // 20 and 21
        });
    }

    #[test]
    fn parent_payload_returns_parent_digest() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[2].clone(); // leader of view 1
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Create proposal
            let parent_view = View::new(1);
            let parent_payload = Sha256Digest::from([1u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );

            // Attempt to get parent payload without certificate
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                parent_view,
                Sha256Digest::from([9u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::ParentNotCertified {
                    proposal_view: View::new(2),
                    parent_view,
                })
            );

            // Add notarization certificate
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .unwrap();
            state.add_notarization(notarization);

            // The parent is still not certified
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::ParentNotCertified {
                    proposal_view: View::new(2),
                    parent_view,
                })
            );

            // Set certify handle then certify the parent
            let mut pool = AbortablePool::<()>::default();
            let handle = pool.push(futures::future::pending());
            state.set_certify_handle(parent_view, handle);
            state.certified(parent_view, true);
            assert_eq!(state.parent_payload(&proposal), Ok(parent_payload));
        });
    }

    #[test]
    fn parent_certificate_prefers_finalization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let local_scheme = schemes[1].clone(); // leader of view 2
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(7),
                activity_timeout: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add notarization for parent view
            let parent_round = Rnd::new(state.epoch(), View::new(1));
            let parent_proposal =
                Proposal::new(parent_round, GENESIS_VIEW, Sha256Digest::from([11u8; 32]));
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization.clone());

            // Insert proposal at view 2 with parent at view 1
            let proposal = Proposal::new(
                Rnd::new(state.epoch(), View::new(2)),
                View::new(1),
                Sha256Digest::from([22u8; 32]),
            );
            state.set_proposal(View::new(2), proposal);

            // parent_certificate returns the notarization
            let cert = state.parent_certificate(View::new(2)).unwrap();
            assert!(matches!(cert, Certificate::Notarization(n) if n == notarization));

            // Add finalization for the same parent view
            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization.clone());

            // parent_certificate now returns the finalization (preferred)
            let cert = state.parent_certificate(View::new(2)).unwrap();
            assert!(matches!(cert, Certificate::Finalization(f) if f == finalization));
        });
    }

    #[test]
    fn parent_payload_errors_without_nullification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 5, 1);

            // Create parent proposal and certificate
            let parent_view = View::new(1);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([2u8; 32]),
            );
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .unwrap();
            state.add_notarization(notarization);
            state.create_round(View::new(2));

            // Attempt to get parent payload
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                parent_view,
                Sha256Digest::from([3u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::MissingNullification {
                    proposal_view: View::new(3),
                    parent_view,
                    missing_view: View::new(2),
                })
            );
        });
    }

    #[test]
    fn parent_payload_uses_term_skip_nullification_anchors() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5);

            let parent_view = View::new(3);
            let parent_payload = Sha256Digest::from([42u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);
            assert!(state.certified(parent_view, true).is_some());

            for v in [View::new(4), View::new(6)] {
                let nullify_votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| {
                        Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), v)).unwrap()
                    })
                    .collect();
                let nullification =
                    Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                        .expect("nullification");
                assert!(state.add_nullification(nullification));
            }

            // View 11 is the start of term 3, so the intra-term skip check does not apply.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(11)),
                parent_view,
                Sha256Digest::from([7u8; 32]),
            );
            assert_eq!(state.parent_payload(&proposal), Ok(parent_payload));
        });
    }

    #[test]
    fn parent_payload_reports_missing_term_anchor() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5);

            let parent_view = View::new(3);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([9u8; 32]),
            );
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);
            assert!(state.certified(parent_view, true).is_some());

            {
                let v = View::new(4);
                let nullify_votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| {
                        Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), v)).unwrap()
                    })
                    .collect();
                let nullification =
                    Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                        .expect("nullification");
                assert!(state.add_nullification(nullification));
            }

            // View 11 is a term start so the intra-term skip check does not apply,
            // but the nullification for term 2 (view 6) is missing.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(11)),
                parent_view,
                Sha256Digest::from([10u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::MissingNullification {
                    proposal_view: View::new(11),
                    parent_view,
                    missing_view: View::new(6),
                })
            );
        });
    }

    #[test]
    fn nullification_sets_entry_certificate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5);

            let view = View::new(1);
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view)).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification.clone()));
            assert_eq!(state.current_view(), View::new(6));
            let entry = state.get_best_certificate();
            assert!(
                matches!(
                    entry,
                    Some(Certificate::Nullification(ref cert)) if cert == &nullification
                ),
                "expected nullification entry certificate"
            );
        });
    }

    #[test]
    fn entry_certificate_prioritizes_finalization_then_nullification_then_notarization() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 1);

            let view = View::new(1);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([17u8; 32]),
            );

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization.clone());
            assert!(state.certified(view, true).is_some());
            assert!(matches!(
                state.get_best_certificate(),
                Some(Certificate::Notarization(ref n)) if n == &notarization
            ));

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view)).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification.clone()));
            assert!(matches!(
                state.get_best_certificate(),
                Some(Certificate::Nullification(ref n)) if n == &nullification
            ));

            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                    .expect("finalization");
            let _ = state.add_finalization(finalization.clone());
            assert!(matches!(
                state.get_best_certificate(),
                Some(Certificate::Finalization(ref f)) if f == &finalization
            ));
        });
    }

    #[test]
    fn parent_payload_returns_genesis_payload() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 5, 1);

            // Add nullification certificate for view 1
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), View::new(1)))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential).unwrap();
            state.add_nullification(nullification);

            // Get genesis payload
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                GENESIS_VIEW,
                Sha256Digest::from([8u8; 32]),
            );
            let genesis = Sha256Digest::from([0u8; 32]);
            assert_eq!(state.parent_payload(&proposal), Ok(genesis));
        });
    }

    #[test]
    fn parent_payload_rejects_parent_before_finalized() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 5, 1);

            // Add finalization
            let proposal_a = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_a.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Attempt to verify before finalized
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(4)),
                View::new(2),
                Sha256Digest::from([6u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::ParentBeforeFinalized {
                    proposal_view: View::new(4),
                    parent_view: View::new(2),
                    last_finalized: View::new(3),
                })
            );
        });
    }

    #[test]
    fn parent_payload_rejects_intra_term_view_skip() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 20, 5);

            // Certify view 1 so it can serve as a valid parent.
            let parent_view = View::new(1);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);
            state.certified(parent_view, true);

            // Propose at view 3 with parent view 1. Both are within the same term
            // (term_length=5, term 1 = views 1-5), so view 3 is intra-term yet
            // skips view 2.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                parent_view,
                Sha256Digest::from([2u8; 32]),
            );
            assert_eq!(
                state.parent_payload(&proposal),
                Err(ParentPayloadError::IntraTermProposalSkipsViews {
                    proposal_view: View::new(3),
                    parent_view,
                })
            );
        });
    }

    #[test]
    fn try_verify_fast_paths_intra_term_view_skip() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(1);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(20),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    term_length: NZU64!(5),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());

            // Notarize view 2 so the leader is set for view 3.
            let notarization_proposal = Proposal::new(
                Rnd::new(epoch, View::new(2)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, notarization_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);
            assert!(state.enter_view(View::new(3)));

            // Inject a proposal at view 3 whose parent is view 1. Both are
            // in the same term (views 1-5), so this is an intra-term skip.
            let proposal = Proposal::new(
                Rnd::new(epoch, View::new(3)),
                View::new(1),
                Sha256Digest::from([2u8; 32]),
            );
            assert!(state.set_proposal(View::new(3), proposal));

            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());

            // Permanent ancestry error should immediately expire the timeout.
            assert!(state.try_verify().is_none());
            assert!(state.next_timeout().0 <= context.current());
        });
    }

    #[test]
    fn try_verify_fast_paths_parent_before_finalized() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(1);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    term_length: NZU64!(1),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());

            // Finalize view 3 so view 4 is current and any parent below 3 is permanently invalid.
            let finalized_view = View::new(3);
            let finalized_proposal = Proposal::new(
                Rnd::new(epoch, finalized_view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, finalized_proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalization_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            // Inject a proposal whose parent is below the finalized floor.
            let view = state.current_view();
            assert_eq!(view, View::new(4));
            let proposal = Proposal::new(
                Rnd::new(epoch, view),
                View::new(2),
                Sha256Digest::from([6u8; 32]),
            );
            assert!(state.set_proposal(view, proposal));

            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());

            // Permanent ancestry errors should immediately expire the timeout.
            assert!(state.try_verify().is_none());
            assert!(state.next_timeout().0 <= context.current());
        });
    }

    #[test]
    fn try_verify_waits_for_missing_parent_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { verifier, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let epoch = Epoch::new(1);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: verifier,
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(10),
                    certification_timeout: Duration::from_secs(10),
                    timeout_retry: Duration::from_secs(30),
                    term_length: NZU64!(1),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());

            // Move into view 2 without certifying view 1 so the parent could still arrive later.
            assert!(state.enter_view(View::new(2)));

            // Inject a proposal whose parent is missing certification but is not permanently invalid.
            let proposal = Proposal::new(
                Rnd::new(epoch, View::new(2)),
                View::new(1),
                Sha256Digest::from([7u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal));

            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());

            // Missing parent certification should wait instead of forcing an immediate timeout.
            assert!(state.try_verify().is_none());
            assert_eq!(state.next_timeout(), initial_deadline);
        });
    }

    /// Replaying a local notarize vote for a leader-owned proposal should
    /// restore the proposal as verified and suppress duplicate vote construction.
    #[test]
    fn replayed_local_notarize_restores_verified_leader_proposal() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let epoch = Epoch::new(2);
            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(epoch, view),
                View::new(1),
                Sha256Digest::from([42u8; 32]),
            );
            let local_vote = Notarize::sign(&schemes[0], proposal.clone()).expect("notarize");

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[0].clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(1),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());

            // Enter the view where we are the leader.
            assert!(state.enter_view(view));
            state.set_leader(view, None);
            assert_eq!(state.leader_index(view), Some(Participant::new(0)));

            // Replay our own notarize vote.
            state.replay(&Artifact::Notarize(local_vote));

            // Proposal should be restored in the round.
            let round = state.views.get(&view).expect("replayed round must exist");
            assert_eq!(round.proposal(), Some(&proposal));

            // No duplicate notarize vote should be constructed.
            assert!(
                state.construct_notarize(view).is_none(),
                "replay should restore that we already emitted the local notarize vote"
            );

            // No verification request should be emitted (leader-owned).
            assert!(state.try_verify().is_none());

            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0.round.view(), view);
            assert!(candidates[0].1);
        });
    }

    #[test]
    fn certify_external_candidates_for_leader_controlled_views() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let epoch = Epoch::new(2);
            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(epoch, view),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[0].clone(),
                    elector: <RoundRobin>::default(),
                    epoch,
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(1),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());
            assert!(state.enter_view(view));
            state.set_leader(view, None);
            assert_eq!(state.leader_index(view), Some(Participant::new(0)));

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, equivocator) = state.add_notarization(notarization);
            assert!(added);
            assert!(equivocator.is_none());

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            let (candidate, is_local) = &candidates[0];
            assert_eq!(*candidate, proposal);
            assert!(
                !*is_local,
                "leader-owned recovered proposal must not inherit local certification"
            );
        });
    }

    #[test]
    fn replay_restores_conflict_state() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let mut scheme_iter = schemes.into_iter();
            let local_scheme = scheme_iter.next().unwrap();
            let other_schemes: Vec<_> = scheme_iter.collect();
            let epoch: Epoch = Epoch::new(3);
            let mut state = State::new(
                context.child("state"),
                Config {
                    scheme: local_scheme.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(1),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());
            let view = View::new(4);
            let round = Rnd::new(epoch, view);
            let proposal_a = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([21u8; 32]));
            let proposal_b = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([22u8; 32]));
            let local_vote = Notarize::sign(&local_scheme, proposal_a).unwrap();

            // Replay local notarize vote
            state.replay(&Artifact::Notarize(local_vote.clone()));

            // Add conflicting notarization certificate and replay
            let votes_b: Vec<_> = other_schemes
                .iter()
                .take(3)
                .map(|scheme| Notarize::sign(scheme, proposal_b.clone()).unwrap())
                .collect();
            let conflicting = Notarization::from_notarizes(&verifier, votes_b.iter(), &Sequential)
                .expect("certificate");
            state.add_notarization(conflicting.clone());
            state.replay(&Artifact::Notarization(conflicting.clone()));

            // Shouldn't finalize the certificate's proposal (proposal_b)
            assert!(state.construct_finalize(view).is_none());

            // Restart state and replay
            let mut restarted = State::new(
                context.child("state_restarted"),
                Config {
                    scheme: local_scheme,
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(1),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            restarted.set_genesis(test_genesis());
            restarted.replay(&Artifact::Notarize(local_vote));
            restarted.add_notarization(conflicting.clone());
            restarted.replay(&Artifact::Notarization(conflicting));

            // Shouldn't finalize the certificate's proposal (proposal_b)
            assert!(restarted.construct_finalize(view).is_none());
        });
    }

    #[test]
    fn certification_lifecycle() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: verifier.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Helper to create notarization for a view
            let make_notarization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|s| Notarize::sign(s, proposal.clone()).unwrap())
                    .collect();
                Notarization::from_notarizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            // Helper to create finalization for a view
            let make_finalization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|s| Finalize::sign(s, proposal.clone()).unwrap())
                    .collect();
                Finalization::from_finalizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            let mut pool = AbortablePool::<()>::default();

            // Add notarizations for views 3-8
            for i in 3..=8u64 {
                state.add_notarization(make_notarization(View::new(i)));
            }

            // All 6 views should be candidates
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 6);
            assert!(candidates.iter().all(|(_, is_local)| !is_local));

            // Set certify handles for views 3, 4, 5, 7 (NOT 6 or 8)
            for i in [3u64, 4, 5, 7] {
                let handle = pool.push(futures::future::pending());
                state.set_certify_handle(View::new(i), handle);
            }

            // Candidates empty (consumed by certify_candidates, handles block re-fetching)
            assert!(state.certify_candidates().is_empty());

            // Complete certification for view 7 (success)
            let notarization = state.certified(View::new(7), true);
            assert!(notarization.is_some());

            // View 7 should not be aborted (it was certified successfully)
            assert!(!state.is_certify_aborted(View::new(7)));

            // Add finalization for view 5 - aborts handles for views 3, 4, 5
            state.add_finalization(make_finalization(View::new(5)));

            // Verify views 3, 4, 5 had their certification aborted
            assert!(state.is_certify_aborted(View::new(3)));
            assert!(state.is_certify_aborted(View::new(4)));
            assert!(state.is_certify_aborted(View::new(5)));

            // View 7 still not aborted (was certified, and 7 > 5)
            assert!(!state.is_certify_aborted(View::new(7)));

            // Views 6, 8 never had handles set, so they're not aborted (still Ready)
            assert!(!state.is_certify_aborted(View::new(6)));
            assert!(!state.is_certify_aborted(View::new(8)));

            // Candidates empty: 3-5 finalized, 6/8 consumed, 7 certified
            assert!(state.certify_candidates().is_empty());

            // Add view 9, should be returned as candidate
            state.add_notarization(make_notarization(View::new(9)));
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0.round.view(), View::new(9));
            assert!(!candidates[0].1);

            // Set handle for view 9, add view 10
            let handle9 = pool.push(futures::future::pending());
            state.set_certify_handle(View::new(9), handle9);
            state.add_notarization(make_notarization(View::new(10)));

            // View 10 returned (view 9 has handle)
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0.round.view(), View::new(10));
            assert!(!candidates[0].1);

            // Finalize view 9 - aborts view 9's handle
            state.add_finalization(make_finalization(View::new(9)));
            assert!(state.is_certify_aborted(View::new(9)));

            // Add view 11, should be returned
            state.add_notarization(make_notarization(View::new(11)));
            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0.round.view(), View::new(11));
            assert!(!candidates[0].1);
        });
    }

    #[test]
    fn certify_candidates_skips_views_at_or_below_last_finalized() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let make_notarization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                Notarization::from_notarizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            let make_finalization = |view: View| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    GENESIS_VIEW,
                    Sha256Digest::from([view.get() as u8; 32]),
                );
                let votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                Finalization::from_finalizes(&verifier, votes.iter(), &Sequential).unwrap()
            };

            let stale_view = View::new(2);
            let live_view = View::new(3);

            state.add_notarization(make_notarization(stale_view));
            state.add_notarization(make_notarization(live_view));
            state.add_finalization(make_finalization(stale_view));

            // Reinsert a stale candidate to exercise the defensive finalized-view guard.
            state.certification_candidates.insert(stale_view);
            assert_eq!(state.last_finalized(), stale_view);

            // The stale round still looks certifiable without the finalized-view filter.
            assert!(state
                .views
                .get_mut(&stale_view)
                .expect("stale round must exist")
                .try_certify()
                .is_some());

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0.round.view(), live_view);
            assert!(!candidates[0].1);
        });
    }

    #[test]
    fn nullification_keeps_notarization_as_certification_candidate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 10, 1);

            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view)).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0.round.view(), view);
            assert!(!candidates[0].1);
        });
    }

    #[test]
    fn nullification_does_not_abort_inflight_certification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (
                Fixture {
                    schemes, verifier, ..
                },
                mut state,
            ) = setup_state(&mut context, 4, 1, 10, 1);

            let view = View::new(2);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([24u8; 32]),
            );

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let candidates = state.certify_candidates();
            assert_eq!(candidates.len(), 1);
            assert_eq!(candidates[0].0.round.view(), view);
            assert!(!candidates[0].1);

            let mut pool = AbortablePool::<()>::default();
            let handle = pool.push(futures::future::pending());
            state.set_certify_handle(view, handle);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view)).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert!(!state.is_certify_aborted(view));

            // Late certification completion is still accepted until the view is finalized.
            assert!(state.certified(view, true).is_some());
            assert!(state.is_certified(view).is_some());
        });
    }

    #[test]
    fn nullification_then_late_certification_allows_child_to_build_on_parent() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let local_scheme = schemes[0].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let parent_view = View::new(2);
            let child_view = parent_view.next();
            let payload = Sha256Digest::from([91u8; 32]);
            let proposal =
                Proposal::new(Rnd::new(Epoch::new(1), parent_view), GENESIS_VIEW, payload);

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), parent_view))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));

            // With RoundRobin and 4 participants, epoch=1 implies view=3 leader is index 0 (our signer).
            assert_eq!(state.leader_index(child_view), Some(Participant::new(0)));

            // Before late certification arrives, we cannot build a child because parent ancestry
            // is still incomplete for this node.
            assert!(state.try_propose().is_none());

            // Late certification after nullification is still recorded.
            assert!(state.certified(parent_view, true).is_some());

            // Child proposal selection should build on the now-certified parent view.
            let propose_context = state
                .try_propose()
                .expect("child view should be able to build on certified parent");
            assert_eq!(propose_context.round.view(), child_view);
            assert_eq!(propose_context.parent, (parent_view, payload));
        });
    }

    #[test]
    fn nullification_then_late_certification_unblocks_follower_verify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            // With RoundRobin (epoch=1), child view=3 has leader index 0, so signer index 1 is a follower.
            let local_scheme = schemes[1].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let parent_view = View::new(2);
            let child_view = parent_view.next();
            let parent_payload = Sha256Digest::from([77u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), parent_view))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), child_view);
            assert_eq!(state.leader_index(child_view), Some(Participant::new(0)));

            // Proposal at child view depends on the parent view.
            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                parent_view,
                Sha256Digest::from([78u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal.clone()));

            // Before late certification of parent, follower cannot verify this child proposal.
            assert!(state.try_verify().is_none());

            // Late certification after nullification should unblock parent check for verification.
            assert!(state.certified(parent_view, true).is_some());
            let verified = state.try_verify();
            assert!(verified.is_some());
            let (ctx, proposal) = verified.expect("verify context should exist");
            assert_eq!(ctx.round.view(), child_view);
            assert_eq!(ctx.parent, (parent_view, parent_payload));
            assert_eq!(proposal, child_proposal);
        });
    }

    #[test]
    fn try_propose_requires_immediate_parent_within_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[2].clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(10),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(5),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());

            let parent_view = View::new(1);
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([93u8; 32]),
            );
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(parent_view, true).is_some());

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), View::new(2)))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            state.replay(&Artifact::Nullification(nullification));

            assert!(state.enter_view(View::new(3)));
            state.set_leader(View::new(3), None);
            assert_eq!(state.leader_index(View::new(3)), Some(Participant::new(2)));
            assert!(state.try_propose().is_none());
        });
    }

    #[test]
    fn try_propose_allows_cross_term_parent_at_term_start() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[3].clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(20),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(5),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            state.set_genesis(test_genesis());

            let parent_view = View::new(3);
            let parent_payload = Sha256Digest::from([94u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(parent_view, true).is_some());

            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), View::new(4)))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));

            assert_eq!(state.current_view(), View::new(6));
            state.set_leader(View::new(6), None);
            assert_eq!(state.leader_index(View::new(6)), Some(Participant::new(3)));

            let proposal = state
                .try_propose()
                .expect("term-start proposal should use prior-term certified parent");
            assert_eq!(proposal.round.view(), View::new(6));
            assert_eq!(proposal.parent, (parent_view, parent_payload));
        });
    }

    #[test]
    fn late_nullification_unblocks_follower_verify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);

            // With RoundRobin (epoch=1), view 3 leader is index 0, so signer index 1 is a follower.
            let local_scheme = schemes[1].clone();
            let cfg = Config {
                scheme: local_scheme,
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(10),
                certification_timeout: Duration::from_secs(10),
                timeout_retry: Duration::from_secs(30),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let parent_view = View::new(1);
            let blocked_view = parent_view.next();
            let child_view = blocked_view.next();
            let parent_payload = Sha256Digest::from([88u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );

            // Certify the parent view, but leave the intermediate view missing its nullification.
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            let (added, _) = state.add_notarization(notarization);
            assert!(added);
            assert!(state.certified(parent_view, true).is_some());

            // Move into the child view as a follower and inject a proposal that depends on view 1.
            assert!(state.enter_view(child_view));
            state.set_leader(child_view, None);
            assert_eq!(state.current_view(), child_view);
            assert_eq!(state.leader_index(child_view), Some(Participant::new(0)));

            let child_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), child_view),
                parent_view,
                Sha256Digest::from([89u8; 32]),
            );
            assert!(state.set_proposal(child_view, child_proposal.clone()));

            // Missing nullification should stall verification without expiring the timeout.
            let initial_deadline = state.next_timeout();
            assert!(initial_deadline.0 > context.current());
            assert!(state.try_verify().is_none());
            assert_eq!(state.next_timeout(), initial_deadline);

            // Once the intermediate nullification arrives, the same proposal should become verifiable.
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), blocked_view))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));

            let verified = state.try_verify().expect("verify context should exist");
            let (ctx, proposal) = verified;
            assert_eq!(ctx.round.view(), child_view);
            assert_eq!(ctx.parent, (parent_view, parent_payload));
            assert_eq!(proposal, child_proposal);
        });
    }

    #[test]
    fn only_notarize_before_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());
            let view = state.current_view();

            // Set proposal
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            state.set_proposal(view, proposal);

            // We should not want to verify (already timeout)
            assert!(state.try_verify().is_some());
            assert!(state.verified(view));

            // Timeout path emits a first-attempt nullify.
            let (retry, _) = state
                .construct_nullify(view)
                .expect("timeout nullify should exist");
            assert!(!retry);

            // Attempt to notarize after timeout
            assert!(state.construct_notarize(view).is_none());
        });
    }

    #[test]
    fn nullification_skips_to_next_term_start() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(5),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // We start in view 1 (first view of term [1,5]).
            assert_eq!(state.current_view(), View::new(1));

            // Nullify view 1: should skip to view 6 (start of next term [6,10]).
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), View::new(1)))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert_eq!(
                state.current_view(),
                View::new(6),
                "nullification in term should skip to next term start"
            );
        });
    }

    #[test]
    fn nullification_at_term_end_skips_correctly() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(3),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Term [1,3]. Advance to view 3 via finalization of view 1 and 2.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([10u8; 32]),
            );
            let fin_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_v1.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, fin_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(2));

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([11u8; 32]),
            );
            let fin_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_v2.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, fin_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(3));

            // Nullify view 3 (last view of term [1,3]). Should go to view 4 (start of [4,6]).
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), View::new(3)))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert_eq!(
                state.current_view(),
                View::new(4),
                "nullification at term end should advance to next term start"
            );
        });
    }

    #[test]
    fn term_length_one_nullification_advances_by_one() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(1),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            assert_eq!(state.current_view(), View::new(1));

            // With term_length=1, nullification should advance by exactly 1.
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), View::new(1)))
                        .unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert_eq!(
                state.current_view(),
                View::new(2),
                "term_length=1 should advance by exactly one view"
            );
        });
    }

    #[test]
    fn term_safety_blocks_finalize_after_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(5),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // View 1, first view of term [1,5].
            let view = state.current_view();
            assert_eq!(view, View::new(1));

            // Emit a timeout nullify vote for view 1.
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("timeout nullify should exist");
            assert!(!was_retry);

            // Now suppose view 1 finalizes and view 2 is certified in the same
            // term. The earlier local nullify should still prevent a later
            // finalize vote in the term.
            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );
            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_v1.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);

            let view = View::new(2);
            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );
            assert!(state.set_proposal(view, proposal_v2.clone()));
            assert!(state.try_verify().is_some());
            assert!(state.verified(view));

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal_v2.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            assert!(state.add_notarization(notarization).0);
            assert!(state.certified(view, true).is_some());

            assert!(
                state.construct_finalize(view).is_none(),
                "should not finalize a later view after nullifying in same term"
            );
        });
    }

    #[test]
    fn term_stop_notarize_on_nullify_blocks_same_term_notarize() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(5),
                term_stop_notarize_on_nullify: true,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("timeout nullify should exist");
            assert!(!was_retry);

            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );
            let fin_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_v1.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, fin_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(2));

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2));
            assert!(state.try_verify().is_some());
            assert!(state.verified(View::new(2)));
            assert!(
                state.construct_notarize(View::new(2)).is_none(),
                "same-term nullify should block later notarize when flag is enabled"
            );
        });
    }

    #[test]
    fn term_stop_notarize_on_nullify_allows_same_term_notarize_when_disabled() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(5),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let view = state.current_view();
            let (was_retry, _) = state
                .construct_nullify(view)
                .expect("timeout nullify should exist");
            assert!(!was_retry);

            let proposal_v1 = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([42u8; 32]),
            );
            let fin_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal_v1.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, fin_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(2));

            let proposal_v2 = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([43u8; 32]),
            );
            assert!(state.set_proposal(View::new(2), proposal_v2));
            assert!(state.try_verify().is_some());
            assert!(state.verified(View::new(2)));

            assert!(
                state.construct_notarize(View::new(2)).is_some(),
                "same-term nullify should not block later notarize when flag is disabled"
            );
        });
    }

    #[test]
    fn replay_restores_nullify_views_for_term_safety() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(5),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };

            // Helper that prepares a certified notarization at view 2.
            let build_certified_view_2 = |state: &mut State<_, _, _, _>| {
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), View::new(2)),
                    View::new(1),
                    Sha256Digest::from([99u8; 32]),
                );
                assert!(state.set_proposal(View::new(2), proposal.clone()));

                let notarize_votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                let notarization =
                    Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                        .expect("notarization");
                assert!(state.add_notarization(notarization).0);
                assert!(state.certified(View::new(2), true).is_some());
            };

            // Baseline: without replayed nullify, finalization is allowed at view 2.
            let mut baseline = State::new(context.child("baseline"), cfg);
            baseline.set_genesis(test_genesis());
            build_certified_view_2(&mut baseline);
            assert!(
                baseline.construct_finalize(View::new(2)).is_some(),
                "finalize should be allowed without prior nullify"
            );

            // Restarted state: replay local nullify at view 1, then same certified view 2.
            let mut restarted = State::new(
                context.child("restarted"),
                Config {
                    scheme: schemes[0].clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(20),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(5),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            restarted.set_genesis(test_genesis());
            let nullify =
                Nullify::sign::<Sha256Digest>(&schemes[0], Rnd::new(Epoch::new(1), View::new(1)))
                    .expect("nullify");
            restarted.replay(&Artifact::Nullify(nullify));
            build_certified_view_2(&mut restarted);

            assert!(
                restarted.construct_finalize(View::new(2)).is_none(),
                "replayed nullify should restore term-safety lock after restart"
            );
        });
    }

    #[test]
    fn prune_retains_local_nullify_for_current_term_safety() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(20),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context.child("state"), cfg);
            state.set_genesis(test_genesis());

            let (was_retry, nullify) = state
                .construct_nullify(View::new(1))
                .expect("timeout nullify should exist");
            assert!(!was_retry);
            let nullify_artifact = Artifact::Nullify(nullify);

            let finalized_view = View::new(10);
            let finalized_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), finalized_view),
                GENESIS_VIEW,
                Sha256Digest::from([10u8; 32]),
            );
            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, finalized_proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, finalize_votes.iter(), &Sequential)
                    .expect("finalization");
            let finalization_artifact = Artifact::Finalization(finalization.clone());
            state.add_finalization(finalization.clone());
            assert_eq!(state.last_finalized(), finalized_view);
            assert_eq!(state.min_active(), View::new(8));
            assert_eq!(state.retention_floor(), View::new(1));

            let removed = state.prune();
            assert!(removed.contains(&View::new(1)));

            let certify_view = |state: &mut TestState| {
                let view = View::new(11);
                let proposal = Proposal::new(
                    Rnd::new(Epoch::new(1), view),
                    finalized_view,
                    Sha256Digest::from([11u8; 32]),
                );
                assert!(state.set_proposal(view, proposal.clone()));
                assert!(state.try_verify().is_some());
                assert!(state.verified(view));

                let notarize_votes: Vec<_> = schemes
                    .iter()
                    .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
                    .collect();
                let notarization =
                    Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                        .expect("notarization");
                assert!(state.add_notarization(notarization).0);
                assert!(state.certified(view, true).is_some());
                view
            };

            let view = certify_view(&mut state);

            assert!(
                state.construct_finalize(view).is_none(),
                "pruned round must not prune same-term local nullify state"
            );

            let mut restarted = State::new(
                context.child("restarted"),
                Config {
                    scheme: schemes[0].clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(2),
                    leader_timeout: Duration::from_secs(1),
                    certification_timeout: Duration::from_secs(2),
                    timeout_retry: Duration::from_secs(3),
                    term_length: NZU64!(20),
                    term_stop_notarize_on_nullify: false,
                    same_term_finalization_timeout: Duration::from_secs(4),
                },
            );
            restarted.set_genesis(test_genesis());
            restarted.replay(&nullify_artifact);
            restarted.replay(&finalization_artifact);
            restarted.add_finalization(finalization);
            assert_eq!(restarted.last_finalized(), finalized_view);

            let view = certify_view(&mut restarted);
            assert!(
                restarted.construct_finalize(view).is_none(),
                "journal retention floor must preserve same-term local nullify after restart"
            );
        });
    }

    #[test]
    fn retention_floor_tracks_first_unfinalized_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let (_, mut state) = setup_state(&mut context, 4, 1, 2, 20);

            // First unfinalized view remains in term [1, 20], so same-term
            // safety evidence from that term must remain durable.
            state.last_finalized = View::new(10);
            assert_eq!(state.retention_floor(), View::new(1));

            // Once the term is fully finalized, only the activity horizon keeps
            // recent evidence from the finalized term.
            state.last_finalized = View::new(20);
            assert_eq!(state.retention_floor(), View::new(18));

            // If the first unfinalized view is inside a term, retain from that
            // term start even when the activity horizon is higher.
            state.last_finalized = View::new(25);
            assert_eq!(state.retention_floor(), View::new(21));
        });
    }

    #[test]
    fn term_safety_allows_finalize_in_new_term_after_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(3),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Vote to nullify in term [1,3], activating the term safety lock.
            let view1 = View::new(1);
            let (was_retry, _) = state
                .construct_nullify(view1)
                .expect("timeout nullify should exist");
            assert!(!was_retry);

            // Receive nullification certificate for view 1 and skip to next term start (view 4).
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, Rnd::new(Epoch::new(1), view1)).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes, &Sequential)
                    .expect("nullification");
            assert!(state.add_nullification(nullification));
            assert_eq!(state.current_view(), View::new(4));

            // Build, verify, notarize, and certify view 4 (term [4,6]).
            let view4 = View::new(4);
            let proposal_v4 = Proposal::new(
                Rnd::new(Epoch::new(1), view4),
                GENESIS_VIEW,
                Sha256Digest::from([55u8; 32]),
            );
            state.set_proposal(view4, proposal_v4.clone());
            assert!(state.try_verify().is_some());
            assert!(state.verified(view4));

            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal_v4.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarize_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);
            assert!(state.certified(view4, true).is_some());

            // Finalization in a different term should not be blocked by the lock.
            assert!(
                state.construct_finalize(view4).is_some(),
                "finalize should be allowed in a new term after prior-term nullify"
            );
        });
    }

    #[test]
    fn same_leader_within_term() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, &namespace, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(20),
                leader_timeout: Duration::from_secs(1),
                certification_timeout: Duration::from_secs(2),
                timeout_retry: Duration::from_secs(3),
                term_length: NZU64!(3),
                term_stop_notarize_on_nullify: false,
                same_term_finalization_timeout: Duration::from_secs(4),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // View 1 is in term [1,3]. Get its leader.
            let leader_v1 = state.leader_index(View::new(1)).unwrap();

            // Advance to view 2 via finalization.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(1)),
                GENESIS_VIEW,
                Sha256Digest::from([10u8; 32]),
            );
            let fin_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, fin_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(2));

            let leader_v2 = state.leader_index(View::new(2)).unwrap();
            assert_eq!(
                leader_v1, leader_v2,
                "views within the same term should have the same leader"
            );

            // Advance to view 3.
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                View::new(1),
                Sha256Digest::from([11u8; 32]),
            );
            let fin_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, fin_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(3));

            let leader_v3 = state.leader_index(View::new(3)).unwrap();
            assert_eq!(
                leader_v1, leader_v3,
                "last view in same term should have the same leader"
            );

            // Advance to view 4 (new term [4,6]).
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                View::new(2),
                Sha256Digest::from([12u8; 32]),
            );
            let fin_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
                .collect();
            let finalization =
                Finalization::from_finalizes(&verifier, fin_votes.iter(), &Sequential)
                    .expect("finalization");
            state.add_finalization(finalization);
            assert_eq!(state.current_view(), View::new(4));

            // Leader of view 4 may differ since it's a new term (depends on election).
            // Just verify the leader is set.
            assert!(state.leader_index(View::new(4)).is_some());
        });
    }
}
