//! Per-epoch state machine for the minimmit voter actor.
//!
//! Unlike simplex, minimmit has no separate finalize phase - finalization occurs
//! at L notarize votes. Additionally, minimmit supports nullify-by-contradiction,
//! allowing validators to nullify after notarizing if they observe M conflicting votes.

use super::round::Round;
use crate::{
    minimmit::{
        elector::{Config as ElectorConfig, Elector},
        scheme::Scheme,
        types::{
            Artifact, Attributable, Certificate, ConflictingNotarize, Context, Notarization,
            Notarize, Nullification, Nullify,
        },
    },
    types::{Epoch, Round as Rnd, View, ViewDelta},
    Viewable,
};
use commonware_cryptography::{certificate, Digest};
use commonware_runtime::{telemetry::metrics::status::GaugeExt, Clock, Metrics};
use commonware_utils::ordered::Quorum;
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};
use rand_core::CryptoRngCore;
use std::{
    collections::BTreeMap,
    mem::replace,
    sync::atomic::AtomicI64,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// The view number of the genesis block.
const GENESIS_VIEW: View = View::zero();

/// Returns the lowest view that must remain in memory to satisfy the activity timeout.
pub(crate) const fn min_active(activity_timeout: ViewDelta, last_finalized: View) -> View {
    last_finalized.saturating_sub(activity_timeout)
}

/// Whether or not a view is interesting to us.
///
/// A view is interesting if it is:
/// - Not genesis (view 0)
/// - At or above the activity window floor (min_active)
/// - Not too far in the future (unless allow_future is true)
pub(crate) fn interesting(
    activity_timeout: ViewDelta,
    last_finalized: View,
    current: View,
    pending: View,
    allow_future: bool,
) -> bool {
    // Genesis view doesn't have votes
    if pending.is_zero() {
        return false;
    }
    if pending < min_active(activity_timeout, last_finalized) {
        return false;
    }
    if !allow_future && pending > current.next() {
        return false;
    }
    true
}

/// Configuration for initializing [`State`].
pub struct Config<S: certificate::Scheme, L: ElectorConfig<S>> {
    pub scheme: S,
    pub elector: L,
    pub epoch: Epoch,
    pub activity_timeout: ViewDelta,
    pub leader_timeout: Duration,
    pub nullify_retry: Duration,
}

/// Per-[Epoch] state machine for minimmit consensus.
///
/// Tracks proposals and certificates for each view. Vote aggregation and verification
/// is handled directly by this actor (unlike simplex which has a separate batcher).
///
/// Key differences from simplex:
/// - No separate finalize phase (finalization occurs at L notarize votes)
/// - Supports nullify-by-contradiction
/// - Only tracks notarization and nullification certificates
pub struct State<E: Clock + CryptoRngCore + Metrics, S: Scheme<D>, L: ElectorConfig<S>, D: Digest> {
    context: E,
    scheme: S,
    elector: L::Elector,
    epoch: Epoch,
    activity_timeout: ViewDelta,
    leader_timeout: Duration,
    nullify_retry: Duration,
    view: View,
    last_finalized: View,
    genesis: Option<D>,
    views: BTreeMap<View, Round<S, D>>,

    // Metrics
    current_view_metric: Gauge,
    tracked_views_metric: Gauge,
    skipped_views_metric: Counter,
}

impl<E: Clock + CryptoRngCore + Metrics, S: Scheme<D>, L: ElectorConfig<S>, D: Digest>
    State<E, S, L, D>
{
    /// Creates a new state machine for the given epoch.
    pub fn new(context: E, cfg: Config<S, L>) -> Self {
        let current_view_metric = Gauge::<i64, AtomicI64>::default();
        let tracked_views_metric = Gauge::<i64, AtomicI64>::default();
        let skipped_views_metric = Counter::default();
        context.register("current_view", "current view", current_view_metric.clone());
        context.register(
            "tracked_views",
            "tracked views",
            tracked_views_metric.clone(),
        );
        context.register(
            "skipped_views",
            "skipped views",
            skipped_views_metric.clone(),
        );

        // Build elector with participants
        let elector = cfg.elector.build(cfg.scheme.participants());

        Self {
            context,
            scheme: cfg.scheme,
            elector,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            leader_timeout: cfg.leader_timeout,
            nullify_retry: cfg.nullify_retry,
            view: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            genesis: None,
            views: BTreeMap::new(),
            current_view_metric,
            tracked_views_metric,
            skipped_views_metric,
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

    /// Returns whether `pending` is still relevant for progress, optionally allowing future views.
    pub fn is_interesting(&self, pending: View, allow_future: bool) -> bool {
        interesting(
            self.activity_timeout,
            self.last_finalized,
            self.view,
            pending,
            allow_future,
        )
    }

    /// Returns true when the local signer is the participant with index `idx`.
    pub fn is_me(&self, idx: u32) -> bool {
        self.scheme
            .me()
            .is_some_and(|me| me == commonware_utils::Participant::new(idx))
    }

    /// Advances the view and updates timeouts.
    fn enter_view(&mut self, view: View) -> bool {
        if view <= self.view {
            return false;
        }

        let now = self.context.current();
        let leader_deadline = now + self.leader_timeout;

        let round = self.create_round(view);
        round.set_deadline(leader_deadline);
        self.view = view;

        // Update metrics
        let _ = self.current_view_metric.try_set(view.get());
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
        let epoch = self.epoch;
        let now = self.context.current();
        let participants = self.scheme.participants().len();
        self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.scheme.clone(),
                Rnd::new(epoch, view),
                now,
                participants,
            )
        })
    }

    /// Returns the deadline for the next timeout (leader or retry).
    pub fn next_timeout_deadline(&mut self) -> SystemTime {
        let now = self.context.current();
        let nullify_retry = self.nullify_retry;
        let round = self.create_round(self.view);
        round.next_timeout_deadline(now, nullify_retry)
    }

    /// Handle a timeout event for the current view.
    ///
    /// Returns `(is_retry, nullify_vote, entry_certificate)`.
    /// - `is_retry`: true if this is a retry timeout (we've already sent nullify)
    /// - `nullify_vote`: the nullify vote to broadcast (if we can sign)
    /// - `entry_certificate`: a certificate for the previous view (if this is a retry)
    pub fn handle_timeout(&mut self) -> (bool, Option<Nullify<S>>, Option<Certificate<S, D>>) {
        let view = self.view;
        let Some(retry) = self.create_round(view).construct_nullify() else {
            return (false, None, None);
        };
        let nullify = Nullify::sign::<D>(&self.scheme, Rnd::new(self.epoch, view));

        // If was retry, we need to get entry certificate for the previous view
        let entry_view = view.previous().unwrap_or(GENESIS_VIEW);
        if !retry || entry_view == GENESIS_VIEW {
            return (retry, nullify, None);
        }

        // Get the certificate for the previous view.
        // In minimmit we only have notarization or nullification (no finalization).
        // Prefer nullifications since they indicate the view was skipped.
        #[allow(clippy::option_if_let_else)]
        let cert = if let Some(nullification) = self.nullification(entry_view).cloned() {
            Some(Certificate::Nullification(nullification))
        } else if let Some(notarization) = self.notarization(entry_view).cloned() {
            Some(Certificate::Notarization(notarization))
        } else {
            warn!(%entry_view, "entry certificate not found during timeout");
            None
        };
        (retry, nullify, cert)
    }

    /// Inserts a notarization certificate and prepares the next view's leader.
    ///
    /// Returns `(accepted, equivocator)` where:
    /// - `accepted`: true if this was a new notarization
    /// - `equivocator`: the leader's public key if equivocation was detected
    pub fn add_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        let view = notarization.view();
        // Set leader for next view based on this certificate
        self.set_leader(view.next(), Some(&notarization.certificate));
        // Enter next view
        self.enter_view(view.next());
        self.create_round(view).add_notarization(notarization)
    }

    /// Inserts a nullification certificate and advances into the next view.
    pub fn add_nullification(&mut self, nullification: Nullification<S>) -> bool {
        let view = nullification.view();
        self.enter_view(view.next());
        self.set_leader(view.next(), Some(&nullification.certificate));
        self.create_round(view).add_nullification(nullification)
    }

    /// Updates the last finalized view.
    ///
    /// In minimmit, finalization occurs at L notarize votes (not via separate finalize phase).
    pub fn set_finalized(&mut self, view: View) {
        if view > self.last_finalized {
            self.last_finalized = view;
        }
    }

    /// Construct a notarize vote for this view when we're ready to sign.
    pub fn construct_notarize(&mut self, view: View) -> Option<Notarize<S, D>> {
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_notarize().cloned())?;

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Notarize::sign(&self.scheme, candidate)
    }

    /// Construct a nullify vote for contradiction if conditions are met.
    ///
    /// Returns a nullify vote if we've notarized but observed M conflicting votes.
    pub fn construct_nullify_by_contradiction(
        &mut self,
        view: View,
        m_threshold: usize,
    ) -> Option<Nullify<S>> {
        self.views
            .get_mut(&view)?
            .construct_nullify_by_contradiction(m_threshold)?;
        Nullify::sign::<D>(&self.scheme, Rnd::new(self.epoch, view))
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

    /// Construct a nullification certificate once the round has quorum.
    pub fn broadcast_nullification(&mut self, view: View) -> Option<Nullification<S>> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.broadcast_nullification())
    }

    /// Replays a journaled artifact into the appropriate round during recovery.
    pub fn replay(&mut self, artifact: &Artifact<S, D>) {
        self.create_round(artifact.view()).replay(artifact);
    }

    /// Returns the leader index for `view` if we already entered it.
    pub fn leader_index(&self, view: View) -> Option<u32> {
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

    /// Immediately expires `view`, forcing its timeouts to trigger on the next tick.
    pub fn expire_round(&mut self, view: View) {
        let now = self.context.current();
        self.create_round(view).set_deadline(now);

        // Update metrics
        self.skipped_views_metric.inc();
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
    pub fn proposed(&mut self, proposal: crate::minimmit::types::Proposal<D>) -> bool {
        self.views
            .get_mut(&proposal.view())
            .map(|round| round.proposed(proposal))
            .unwrap_or(false)
    }

    /// Sets a proposal received from the network (leader's first notarize vote).
    ///
    /// Returns true if the proposal should trigger verification, false otherwise.
    pub fn set_proposal(
        &mut self,
        view: View,
        proposal: crate::minimmit::types::Proposal<D>,
    ) -> bool {
        self.create_round(view).set_proposal(proposal)
    }

    /// Attempt to verify a proposed block.
    #[allow(clippy::type_complexity)]
    pub fn try_verify(
        &mut self,
    ) -> Option<(
        Context<D, S::PublicKey>,
        crate::minimmit::types::Proposal<D>,
    )> {
        let view = self.view;
        let (leader, proposal) = self.views.get(&view)?.should_verify()?;
        let parent_payload = self.parent_payload(&proposal)?;
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

    /// Drops any views that fall below the activity horizon and returns them for logging.
    pub fn prune(&mut self) -> Vec<View> {
        let min = self.min_active();
        let kept = self.views.split_off(&min);
        let removed = replace(&mut self.views, kept).into_keys().collect();

        // Update metrics
        let _ = self.tracked_views_metric.try_set(self.views.len());
        removed
    }

    /// Returns the payload of the proposal if it is notarized.
    fn is_notarized(&self, view: View) -> Option<&D> {
        // Special case for genesis view
        if view == GENESIS_VIEW {
            return Some(self.genesis.as_ref().expect("genesis must be present"));
        }

        // Check for notarization
        let round = self.views.get(&view)?;
        if round.notarization().is_some() {
            return Some(&round.proposal().expect("proposal must exist").payload);
        }
        None
    }

    /// Returns true if the view is nullified.
    fn is_nullified(&self, view: View) -> bool {
        // Special case for genesis view (although it should also not be in the views map).
        if view == GENESIS_VIEW {
            return false;
        }

        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        round.nullification().is_some()
    }

    /// Finds the parent payload for a given view by walking backwards through
    /// the chain, skipping nullified views until finding a notarized payload.
    fn find_parent(&self, view: View) -> Result<(View, D), View> {
        // If the view is the genesis view, consider it to be its own parent.
        let mut cursor = view.previous().unwrap_or(GENESIS_VIEW);

        loop {
            // Return the first notarized parent.
            if let Some(parent) = self.is_notarized(cursor) {
                return Ok((cursor, *parent));
            }

            // If the view is also not nullified, there is a gap in certificates.
            if !self.is_nullified(cursor) {
                return Err(cursor);
            }

            cursor = cursor.previous().expect("cursor must not wrap");
        }
    }

    /// Returns the payload of the proposal's parent if:
    /// - It is less-than the proposal view.
    /// - It is greater-than-or-equal-to the last finalized view.
    /// - It is notarized.
    /// - There exist nullifications for all views between it and the proposal view.
    fn parent_payload(&self, proposal: &crate::minimmit::types::Proposal<D>) -> Option<D> {
        // Sanity check that the parent view is less than the proposal view.
        let (view, parent) = (proposal.view(), proposal.parent);
        if view <= parent {
            return None;
        }

        // Ignore any requests for outdated parent views.
        if parent < self.last_finalized {
            return None;
        }

        // Check that there are nullifications for all views between the parent and the proposal view.
        if !View::range(parent.next(), view).all(|v| self.is_nullified(v)) {
            return None;
        }

        // May return `None` if the parent view is not yet notarized.
        self.is_notarized(parent).copied()
    }

    /// Returns a reference to the signing scheme.
    pub const fn scheme(&self) -> &S {
        &self.scheme
    }

    /// Adds a notarize vote from the network.
    ///
    /// Returns `(added, equivocator, conflict)` where:
    /// - `added`: true if the vote was new (not duplicate)
    /// - `equivocator`: the signer's public key if they voted differently
    /// - `conflict`: the conflicting notarize if equivocation was detected
    pub fn add_notarize_vote(
        &mut self,
        view: View,
        vote: Notarize<S, D>,
    ) -> (
        bool,
        Option<S::PublicKey>,
        Option<ConflictingNotarize<S, D>>,
    ) {
        let signer = vote.signer();

        // Get equivocator key upfront to avoid borrow conflicts
        let equivocator_key = self
            .scheme
            .participants()
            .key(commonware_utils::Participant::new(signer))
            .cloned();

        let round = self.create_round(view);

        // Check for duplicate notarize (same signer, same or different payload)
        if let Some(existing) = round.votes().get_notarize(signer) {
            // Already voted notarize - check if it's for a different payload
            if existing.proposal.payload != vote.proposal.payload {
                // Equivocation detected: same signer voted for different payloads
                let conflict = ConflictingNotarize {
                    first: existing.clone(),
                    second: vote,
                };
                return (false, equivocator_key, Some(conflict));
            }
            // Same vote, just a duplicate
            return (false, None, None);
        }

        let added = round.votes_mut().insert_notarize(vote);
        (added, None, None)
    }

    /// Adds a nullify vote from the network.
    ///
    /// Returns `(added, equivocator)` where:
    /// - `added`: true if the vote was new (not duplicate)
    /// - `equivocator`: the signer's public key if they already voted differently
    pub fn add_nullify_vote(
        &mut self,
        view: View,
        vote: Nullify<S>,
    ) -> (bool, Option<S::PublicKey>) {
        let signer = vote.signer();
        let round = self.create_round(view);

        // Check for equivocation (already voted notarize without contradiction allowance)
        // In minimmit, nullify after notarize is allowed for contradiction, but
        // duplicate nullifies are not.
        if round.votes().has_nullify(signer) {
            return (false, None);
        }

        let added = round.votes_mut().insert_nullify(vote);
        (added, None)
    }

    /// Tries to assemble a notarization certificate if M threshold is reached.
    ///
    /// Returns `Some(notarization)` if we have enough votes and haven't assembled yet.
    /// Uses the stored leader's proposal for filtering votes to handle Byzantine conflicting votes.
    pub fn try_assemble_notarization(
        &mut self,
        view: View,
        m_quorum: usize,
        strategy: &impl commonware_parallel::Strategy,
    ) -> Option<Notarization<S, D>> {
        let round = self.views.get_mut(&view)?;

        // Check if we already have a notarization
        if round.notarization().is_some() {
            return None;
        }

        // Check if we have enough votes
        if round.votes().notarize_count() < m_quorum {
            return None;
        }

        // Use the stored proposal (from leader) if available, otherwise fall back to first vote
        let notarization = if let Some(proposal) = round.proposal() {
            Notarization::from_notarizes_for_proposal(
                &self.scheme,
                proposal.clone(),
                round.votes().notarizes(),
                strategy,
            )
        } else {
            Notarization::from_notarizes(&self.scheme, round.votes().notarizes(), strategy)
        }?;
        Some(notarization)
    }

    /// Tries to assemble a nullification certificate if M threshold is reached.
    ///
    /// Returns `Some(nullification)` if we have enough votes and haven't assembled yet.
    pub fn try_assemble_nullification(
        &mut self,
        view: View,
        m_quorum: usize,
        strategy: &impl commonware_parallel::Strategy,
    ) -> Option<Nullification<S>> {
        let round = self.views.get_mut(&view)?;

        // Check if we already have a nullification
        if round.nullification().is_some() {
            return None;
        }

        // Check if we have enough votes
        if round.votes().nullify_count() < m_quorum {
            return None;
        }

        // Assemble the nullification
        let nullification =
            Nullification::from_nullifies(&self.scheme, round.votes().nullifies(), strategy)?;
        Some(nullification)
    }

    /// Checks if finalization threshold (L votes) is reached and updates state.
    ///
    /// Returns `true` if finalization occurred, `false` otherwise.
    pub fn check_finalization(&mut self, view: View, l_quorum: usize) -> bool {
        let round = match self.views.get_mut(&view) {
            Some(r) => r,
            None => return false,
        };

        // Check if already finalized
        if round.is_finalized() {
            return false;
        }

        // Finalization requires notarization to exist first (need to know which proposal)
        let notarization = match round.notarization() {
            Some(n) => n,
            None => return false,
        };

        // Count votes for the notarized proposal only
        let payload = &notarization.proposal.payload;
        if round.votes().notarize_count_for_payload(payload) < l_quorum {
            return false;
        }

        // Mark as finalized
        round.set_finalized();
        self.set_finalized(view);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::minimmit::{
        elector::RoundRobin,
        scheme::ed25519,
        types::{Notarization, Notarize, Nullification, Nullify, Proposal},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Runner};

    const NAMESPACE: &[u8] = b"_COMMONWARE_MINIMMIT_TEST";

    fn test_genesis() -> Sha256Digest {
        Sha256Digest::from([0u8; 32])
    }

    #[test]
    fn test_interesting_helper() {
        let activity_timeout = ViewDelta::new(10);

        // Genesis view is never interesting
        assert!(!interesting(
            activity_timeout,
            View::zero(),
            View::zero(),
            View::zero(),
            false
        ));
        assert!(!interesting(
            activity_timeout,
            View::zero(),
            View::new(1),
            View::zero(),
            true
        ));

        // View below min_active is not interesting
        assert!(!interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(5), // below min_active (10)
            false
        ));

        // View at min_active boundary is interesting
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(10), // exactly min_active
            false
        ));

        // Future view beyond current.next() is not interesting when allow_future is false
        assert!(!interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(27),
            false
        ));

        // Future view beyond current.next() is interesting when allow_future is true
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(27),
            true
        ));

        // View at current.next() is interesting
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(26),
            false
        ));

        // View within valid range is interesting
        assert!(interesting(
            activity_timeout,
            View::new(20),
            View::new(25),
            View::new(22),
            false
        ));

        // When last_finalized is 0 and activity_timeout would underflow
        // min_active saturates at 0, so view 1 should still be interesting
        assert!(interesting(
            activity_timeout,
            View::zero(),
            View::new(5),
            View::new(1),
            false
        ));
    }

    #[test]
    fn certificate_candidates_respect_broadcast_flag() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(11),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
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
                .map(|scheme| Notarize::sign(scheme, notarize_proposal.clone()).expect("sign"))
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
        });
    }

    #[test]
    fn timeout_helpers_reuse_and_reset_deadlines() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let local_scheme = schemes[0].clone(); // leader of view 1
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: local_scheme.clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                nullify_retry: retry,
            };
            let mut state = State::new(context.clone(), cfg);
            state.set_genesis(test_genesis());

            // Should return same deadline until something done
            let first = state.next_timeout_deadline();
            let second = state.next_timeout_deadline();
            assert_eq!(first, second, "cached deadline should be reused");

            // Handle timeout should return false (not a retry)
            let (was_retry, _, _) = state.handle_timeout();
            assert!(!was_retry, "first timeout is not a retry");

            // Set retry deadline
            context.sleep(Duration::from_secs(2)).await;
            let later = context.current();

            // Confirm retry deadline is set
            let third = state.next_timeout_deadline();
            assert_eq!(third, later + retry, "new retry scheduled after timeout");

            // Confirm retry deadline remains set
            let fourth = state.next_timeout_deadline();
            assert_eq!(fourth, third, "retry deadline should be set");

            // Confirm works if later is far in the future
            context.sleep(Duration::from_secs(10)).await;
            let fifth = state.next_timeout_deadline();
            assert_eq!(fifth, later + retry, "retry deadline should be set");

            // Handle timeout should return true whenever called (can be before registered deadline)
            let (was_retry, _, _) = state.handle_timeout();
            assert!(was_retry, "subsequent timeout should be treated as retry");

            // Confirm retry deadline is set
            let sixth = state.next_timeout_deadline();
            let later = context.current();
            assert_eq!(sixth, later + retry, "retry deadline should be set");
        });
    }

    #[test]
    fn round_prunes_with_min_active() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(7),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add initial rounds
            for view in 0..5 {
                state.create_round(View::new(view));
            }

            // Create notarization for view 20
            let proposal_a = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(20)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let notarization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, proposal_a.clone()).expect("sign"))
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, notarization_votes.iter(), &Sequential)
                    .expect("notarization");
            state.add_notarization(notarization);

            // Finalize view 20
            state.set_finalized(View::new(20));

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
    fn only_notarize_before_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                nullify_retry: Duration::from_secs(3),
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

            // We should want to verify (received proposal)
            assert!(state.try_verify().is_some());
            assert!(state.verified(view));

            // Handle timeout
            assert!(!state.handle_timeout().0);

            // Attempt to notarize after timeout
            assert!(state.construct_notarize(view).is_none());
        });
    }

    #[test]
    fn test_check_finalization_normal() {
        // L votes for same proposal triggers finalization
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));

            // Add L=4 notarize votes for the same proposal
            for scheme in schemes.iter() {
                let vote = Notarize::sign(scheme, proposal.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Add notarization so check_finalization knows which proposal to check
            let notarization = Notarization::from_notarizes(
                &verifier,
                schemes
                    .iter()
                    .map(|s| Notarize::sign(s, proposal.clone()).expect("sign"))
                    .collect::<Vec<_>>()
                    .iter(),
                &Sequential,
            )
            .expect("notarization");
            state.add_notarization(notarization);

            // L=4 votes for same proposal should trigger finalization
            assert!(state.check_finalization(view, 4));
            assert_eq!(state.last_finalized, view);
        });
    }

    #[test]
    fn test_check_finalization_byzantine_split_votes() {
        // L total votes split across proposals does NOT trigger finalization
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal_a = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));
            let proposal_b = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([2u8; 32]));

            // Add 2 votes for proposal_a
            for scheme in schemes.iter().take(2) {
                let vote = Notarize::sign(scheme, proposal_a.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Add 2 votes for proposal_b (Byzantine split)
            for scheme in schemes.iter().skip(2) {
                let vote = Notarize::sign(scheme, proposal_b.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Add notarization for proposal_a (the one we're checking finalization for)
            let notarization = Notarization::from_notarizes(
                &verifier,
                schemes
                    .iter()
                    .take(3)
                    .map(|s| Notarize::sign(s, proposal_a.clone()).expect("sign"))
                    .collect::<Vec<_>>()
                    .iter(),
                &Sequential,
            )
            .expect("notarization");
            state.add_notarization(notarization);

            // Total votes = 4, but only 2 are for proposal_a
            // With L=4, finalization should NOT trigger
            assert!(!state.check_finalization(view, 4));

            // Even with L=3, finalization should NOT trigger (only 2 for proposal_a)
            assert!(!state.check_finalization(view, 3));
        });
    }

    #[test]
    fn test_check_finalization_already_finalized() {
        // Returns false when already finalized
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));

            // Add votes and notarization
            for scheme in schemes.iter() {
                let vote = Notarize::sign(scheme, proposal.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }
            let notarization = Notarization::from_notarizes(
                &verifier,
                schemes
                    .iter()
                    .map(|s| Notarize::sign(s, proposal.clone()).expect("sign"))
                    .collect::<Vec<_>>()
                    .iter(),
                &Sequential,
            )
            .expect("notarization");
            state.add_notarization(notarization);

            // First finalization should succeed
            assert!(state.check_finalization(view, 4));

            // Second finalization should return false (already finalized)
            assert!(!state.check_finalization(view, 4));
        });
    }

    #[test]
    fn test_check_finalization_view_not_found() {
        // Returns false for non-existent view
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { verifier, .. } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier,
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            // View 99 doesn't exist
            assert!(!state.check_finalization(View::new(99), 4));
        });
    }

    #[test]
    fn test_check_finalization_no_notarization() {
        // Returns false when no notarization exists
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier,
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));

            // Add L=4 notarize votes but NO notarization certificate
            for scheme in schemes.iter() {
                let vote = Notarize::sign(scheme, proposal.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Without notarization, finalization should not trigger
            assert!(!state.check_finalization(view, 4));
        });
    }

    #[test]
    fn test_assemble_notarization_filters_by_proposal() {
        // Only counts votes for leader's proposal when assembling certificate
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context.clone(),
                Config {
                    scheme: schemes[0].clone(), // schemes[0] is leader of view 1
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal_a = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));
            let proposal_b = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([2u8; 32]));

            // Set proposal_a as the leader's proposal
            state.set_proposal(view, proposal_a.clone());

            // Add 2 votes for proposal_a (not enough for N3f1 quorum which requires 3)
            for scheme in schemes.iter().take(2) {
                let vote = Notarize::sign(scheme, proposal_a.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Add 2 votes for proposal_b (Byzantine)
            for scheme in schemes.iter().skip(2) {
                let vote = Notarize::sign(scheme, proposal_b.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Total votes = 4, but only 2 for proposal_a
            // Even though m_quorum check passes (4 >= 3), assembly fails because
            // the scheme requires N3f1 (3 votes) for the same proposal
            assert!(state
                .try_assemble_notarization(view, 3, &Sequential)
                .is_none());

            // The assembly filters by proposal, so even with m_quorum=2 passing,
            // we still need 3 votes for proposal_a to assemble (N3f1 requirement)
            assert!(state
                .try_assemble_notarization(view, 2, &Sequential)
                .is_none());
        });
    }

    #[test]
    fn test_assemble_notarization_already_exists() {
        // Returns None if notarization already assembled
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));

            // Add notarization directly
            let notarization = Notarization::from_notarizes(
                &verifier,
                schemes
                    .iter()
                    .map(|s| Notarize::sign(s, proposal.clone()).expect("sign"))
                    .collect::<Vec<_>>()
                    .iter(),
                &Sequential,
            )
            .expect("notarization");
            state.add_notarization(notarization);

            // Add votes
            for scheme in schemes.iter() {
                let vote = Notarize::sign(scheme, proposal.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Assembly should return None since notarization already exists
            assert!(state
                .try_assemble_notarization(view, 3, &Sequential)
                .is_none());
        });
    }

    #[test]
    fn test_assemble_notarization_insufficient_votes() {
        // Returns None if fewer than M votes for proposal
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let mut state = State::new(
                context,
                Config {
                    scheme: schemes[0].clone(),
                    elector: <RoundRobin>::default(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));

            // Set proposal
            state.set_proposal(view, proposal.clone());

            // Add only 2 votes (less than M=3 early check, also less than N3f1=3 for assembly)
            for scheme in schemes.iter().take(2) {
                let vote = Notarize::sign(scheme, proposal.clone()).expect("sign");
                state.add_notarize_vote(view, vote);
            }

            // Assembly should fail with M=3 (fails early check: 2 < 3)
            assert!(state
                .try_assemble_notarization(view, 3, &Sequential)
                .is_none());

            // Assembly should still fail with M=2 because N3f1 requires 3 votes
            assert!(state
                .try_assemble_notarization(view, 2, &Sequential)
                .is_none());

            // Add a 3rd vote to reach N3f1 threshold
            let vote = Notarize::sign(&schemes[2], proposal).expect("sign");
            state.add_notarize_vote(view, vote);

            // Now assembly should succeed with M=3 (3 votes >= 3, and N3f1 satisfied)
            assert!(state
                .try_assemble_notarization(view, 3, &Sequential)
                .is_some());
        });
    }

    #[test]
    fn test_notarize_after_nullify_allowed() {
        // Test that receiving notarize AFTER nullify (due to network reordering)
        // does NOT block the sender - this is legitimate nullify-by-contradiction.
        //
        // Per minimmit protocol: validators send notarize FIRST, then nullify
        // (after seeing M conflicting votes). Network reordering may deliver
        // nullify before notarize at the receiver.
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { schemes, .. } = ed25519::fixture(&mut context, NAMESPACE, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                elector: <RoundRobin>::default(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state = State::new(context, cfg);
            state.set_genesis(test_genesis());

            let view = View::new(1);
            let round = Rnd::new(Epoch::new(1), view);
            let proposal = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([1u8; 32]));

            // Validator 1 sends both notarize and nullify (nullify-by-contradiction)
            // Due to network reordering, nullify arrives FIRST
            let nullify_vote = Nullify::sign::<Sha256Digest>(&schemes[1], round).expect("sign");
            let (nullify_added, nullify_equivocator) = state.add_nullify_vote(view, nullify_vote);
            assert!(nullify_added, "nullify should be added");
            assert!(nullify_equivocator.is_none(), "no equivocator for nullify");

            // Now notarize arrives (sent first by validator, but arrived second)
            let notarize_vote = Notarize::sign(&schemes[1], proposal).expect("sign");
            let (notarize_added, notarize_equivocator, conflict) =
                state.add_notarize_vote(view, notarize_vote);

            // Notarize should be accepted - this is NOT equivocation
            assert!(
                notarize_added,
                "notarize after nullify should be accepted (network reordering)"
            );
            assert!(
                notarize_equivocator.is_none(),
                "no equivocator - this is legitimate nullify-by-contradiction"
            );
            assert!(conflict.is_none(), "no conflicting notarize");
        });
    }
}
