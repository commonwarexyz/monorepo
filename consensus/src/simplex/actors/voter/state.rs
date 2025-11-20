use super::round::Round;
use crate::{
    simplex::{
        interesting, min_active,
        signing_scheme::Scheme,
        types::{
            Context, Finalization, Finalize, Notarization, Notarize, Nullification, Nullify,
            OrderedExt, Proposal, Voter,
        },
    },
    types::{Epoch, Round as Rnd, View, ViewDelta},
    Viewable,
};
use commonware_cryptography::Digest;
use commonware_runtime::{
    telemetry::metrics::{
        histogram::{self, Buckets},
        status::GaugeExt,
    },
    Clock, Metrics,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
use rand::{CryptoRng, Rng};
use std::{
    collections::BTreeMap,
    mem::replace,
    sync::{atomic::AtomicI64, Arc},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

/// The view number of the genesis block.
const GENESIS_VIEW: View = View::zero();

/// Action to take after processing a message.
pub enum Action {
    /// Skip processing the message.
    Skip,
    /// Block the peer from sending any more messages.
    Block,
    /// Process the message.
    Process,
}

/// Configuration for initializing [`State`].
pub struct Config<S: Scheme> {
    pub scheme: S,
    pub namespace: Vec<u8>,
    pub epoch: Epoch,
    pub activity_timeout: ViewDelta,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
}

/// Per-[Epoch] state machine.
///
/// # Vote Tracking Semantics
///
/// Votes that conflict with the first leader proposal we observe for a view are discarded once an
/// equivocation is detected. This relies on the [crate::simplex::actors::batcher] to enforce that honest replicas only emit
/// notarize/finalize votes for a single leader payload per view. After we clear the trackers, any
/// additional conflicting votes are ignored because they can never form a quorum under the batcher
/// invariants, so retaining them would just waste memory.
pub struct State<E: Clock + Rng + CryptoRng + Metrics, S: Scheme, D: Digest> {
    context: E,
    scheme: S,
    namespace: Vec<u8>,
    epoch: Epoch,
    activity_timeout: ViewDelta,
    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    view: View,
    last_finalized: View,
    genesis: Option<D>,
    views: BTreeMap<View, Round<S, D>>,

    current_view: Gauge,
    tracked_views: Gauge,
    skipped_views: Counter,
    recover_latency: histogram::Timed<E>,
}

impl<E: Clock + Rng + CryptoRng + Metrics, S: Scheme, D: Digest> State<E, S, D> {
    pub fn new(context: E, cfg: Config<S>) -> Self {
        let current_view = Gauge::<i64, AtomicI64>::default();
        let tracked_views = Gauge::<i64, AtomicI64>::default();
        let skipped_views = Counter::default();
        let recover_latency = Histogram::new(Buckets::CRYPTOGRAPHY);
        context.register("current_view", "current view", current_view.clone());
        context.register("tracked_views", "tracked views", tracked_views.clone());
        context.register("skipped_views", "skipped views", skipped_views.clone());
        context.register(
            "recover_latency",
            "certificate recover latency",
            recover_latency.clone(),
        );
        let clock = Arc::new(context.clone());
        Self {
            context,
            scheme: cfg.scheme,
            namespace: cfg.namespace,
            epoch: cfg.epoch,
            activity_timeout: cfg.activity_timeout,
            leader_timeout: cfg.leader_timeout,
            notarization_timeout: cfg.notarization_timeout,
            nullify_retry: cfg.nullify_retry,
            view: GENESIS_VIEW,
            last_finalized: GENESIS_VIEW,
            genesis: None,
            views: BTreeMap::new(),
            current_view,
            tracked_views,
            skipped_views,
            recover_latency: histogram::Timed::new(recover_latency, clock),
        }
    }

    /// Seeds the state machine with the genesis payload and advances into view 1.
    pub fn set_genesis(&mut self, genesis: D) {
        self.genesis = Some(genesis);
        self.enter_view(GENESIS_VIEW.next(), None);
    }

    /// Returns the epoch managed by this state machine.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Returns the view currently being driven.
    pub fn current_view(&self) -> View {
        self.view
    }

    /// Returns the highest finalized view we have observed.
    pub fn last_finalized(&self) -> View {
        self.last_finalized
    }

    /// Returns the lowest view that must remain in memory to satisfy the activity timeout.
    pub fn min_active(&self) -> View {
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
        self.scheme.me().is_some_and(|me| me == idx)
    }

    /// Advances the view and updates the leader.
    fn enter_view(&mut self, view: View, seed: Option<S::Seed>) -> bool {
        if view <= self.view {
            return false;
        }
        let now = self.context.current();
        let leader_deadline = now + self.leader_timeout;
        let advance_deadline = now + self.notarization_timeout;
        let round = self.create_round(view);
        round.set_deadlines(leader_deadline, advance_deadline);
        round.set_leader(seed); // may not be set until we actually enter
        self.view = view;

        // Update metrics
        let _ = self.current_view.try_set(view.get());
        true
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

    /// Returns the deadline for the next timeout (leader, notarization, or retry).
    pub fn next_timeout_deadline(&mut self) -> SystemTime {
        let now = self.context.current();
        let nullify_retry = self.nullify_retry;
        let round = self.create_round(self.view);
        round.next_timeout_deadline(now, nullify_retry)
    }

    /// Handle a timeout event for the current view.
    /// Returns the nullify vote and optionally an entry certificate for the previous view
    /// (if this is a retry timeout and we can construct one).
    pub fn handle_timeout(&mut self) -> (bool, Option<Nullify<S>>, Option<Voter<S, D>>) {
        let view = self.view;
        let retry = self.create_round(view).handle_timeout();
        let nullify = Nullify::sign::<D>(&self.scheme, &self.namespace, Rnd::new(self.epoch, view));

        // If was retry, we need to get entry certificates for the previous view
        if !retry || view.previous().is_none_or(|v| v == GENESIS_VIEW) {
            return (retry, nullify, None);
        }
        let entry_view = view.previous().expect("checked to be non-zero above");

        // Try to construct entry certificates for the previous view
        // Prefer the strongest proof available so lagging replicas can re-enter quickly.
        if let Some(finalization) = self.finalization(entry_view).cloned() {
            return (retry, nullify, Some(Voter::Finalization(finalization)));
        }
        if let Some(notarization) = self.notarization(entry_view).cloned() {
            return (retry, nullify, Some(Voter::Notarization(notarization)));
        }
        if let Some(nullification) = self.nullification(entry_view).cloned() {
            return (retry, nullify, Some(Voter::Nullification(nullification)));
        }

        // If we couldn't find any entry certificates, return the nullify
        warn!(%entry_view, "entry certificate not found during timeout");
        (retry, nullify, None)
    }

    /// Creates (if necessary) the round for this view and inserts the notarize vote.
    pub fn add_verified_notarize(&mut self, notarize: Notarize<S, D>) -> Option<S::PublicKey> {
        self.create_round(notarize.view())
            .add_verified_notarize(notarize)
    }

    /// Creates (if necessary) the round for this view and inserts the nullify vote.
    pub fn add_verified_nullify(&mut self, nullify: Nullify<S>) {
        self.create_round(nullify.view())
            .add_verified_nullify(nullify);
    }

    /// Creates (if necessary) the round for this view and inserts the finalize vote.
    pub fn add_verified_finalize(&mut self, finalize: Finalize<S, D>) -> Option<S::PublicKey> {
        self.create_round(finalize.view())
            .add_verified_finalize(finalize)
    }

    /// Inserts a notarization certificate and advances into the next view.
    pub fn add_verified_notarization(
        &mut self,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        let view = notarization.view();
        let seed = self
            .scheme
            .seed(notarization.round(), &notarization.certificate);
        let added = self
            .create_round(view)
            .add_verified_notarization(notarization);
        self.enter_view(view.next(), seed);
        added
    }

    /// Inserts a nullification certificate and advances into the next view.
    pub fn add_verified_nullification(&mut self, nullification: Nullification<S>) -> bool {
        let view = nullification.view();
        let seed = self
            .scheme
            .seed(nullification.round(), &nullification.certificate);
        let added = self
            .create_round(view)
            .add_verified_nullification(nullification);
        self.enter_view(view.next(), seed);
        added
    }

    /// Inserts a finalization certificate, updates the finalized height, and advances the view.
    pub fn add_verified_finalization(
        &mut self,
        finalization: Finalization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        // If this finalization increases our last finalized view, update it
        let view = finalization.view();
        if view > self.last_finalized {
            self.last_finalized = view;
        }

        let seed = self
            .scheme
            .seed(finalization.round(), &finalization.certificate);
        let added = self
            .create_round(view)
            .add_verified_finalization(finalization);
        self.enter_view(view.next(), seed);
        added
    }

    fn has_broadcast_notarization(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.has_broadcast_notarization())
    }

    fn has_broadcast_nullification(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.has_broadcast_nullification())
    }

    fn has_broadcast_finalization(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.has_broadcast_finalization())
    }

    /// Construct a notarize vote for this view when we're ready to sign.
    pub fn construct_notarize(&mut self, view: View) -> Option<Notarize<S, D>> {
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_notarize().cloned())?;

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Notarize::sign(&self.scheme, &self.namespace, candidate)
    }

    /// Construct a finalize vote if the round provides a candidate.
    pub fn construct_finalize(&mut self, view: View) -> Option<Finalize<S, D>> {
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.construct_finalize().cloned())?;

        // Signing can only fail if we are a verifier, so we don't need to worry about
        // unwinding our broadcast toggle.
        Finalize::sign(&self.scheme, &self.namespace, candidate)
    }

    /// Construct a notarization certificate once the round has quorum.
    pub fn construct_notarization(&mut self, view: View) -> Option<Notarization<S, D>> {
        let mut timer = self.recover_latency.timer();
        let notarization = self
            .views
            .get_mut(&view)
            .and_then(|round| round.notarizable());
        if notarization.is_some() {
            timer.observe();
        } else {
            timer.cancel();
        }
        notarization
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

    /// Verifies whether a notarization is sound and still helpful for local progress.
    pub fn verify_notarization(&mut self, notarization: &Notarization<S, D>) -> Action {
        // Check if we are still in a view where this notarization could help
        let view = notarization.view();
        if !self.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        //
        // Once we've broadcast a notarization for this view, any additional notarizations
        // must be identical unless a safety failure already occurred (conflicting certificates
        // cannot exist otherwise). We therefore skip re-processing to reduce work.
        if self.has_broadcast_notarization(view) {
            return Action::Skip;
        }

        // Verify notarization
        if !notarization.verify(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }
        Action::Process
    }

    /// Construct a nullification certificate once the round has quorum.
    pub fn construct_nullification(&mut self, view: View) -> Option<Nullification<S>> {
        let mut timer = self.recover_latency.timer();
        let nullification = self
            .views
            .get_mut(&view)
            .and_then(|round| round.nullifiable());
        if nullification.is_some() {
            timer.observe();
        } else {
            timer.cancel();
        }
        nullification
    }

    /// Verifies whether a nullification is sound and still useful.
    pub fn verify_nullification(&mut self, nullification: &Nullification<S>) -> Action {
        // Check if we are still in a view where this nullification could help
        if !self.is_interesting(nullification.view(), true) {
            return Action::Skip;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        //
        // Additional nullifications after we've already broadcast ours would imply a safety
        // failure (conflicting certificates), so there is nothing useful to do with them.
        if self.has_broadcast_nullification(nullification.view()) {
            return Action::Skip;
        }

        // Verify nullification
        if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }
        Action::Process
    }

    /// Construct a finalization certificate once the round has quorum.
    pub fn construct_finalization(&mut self, view: View) -> Option<Finalization<S, D>> {
        let mut timer = self.recover_latency.timer();
        let finalization = self
            .views
            .get_mut(&view)
            .and_then(|round| round.finalizable());
        if finalization.is_some() {
            timer.observe();
        } else {
            timer.cancel();
        }
        finalization
    }

    /// Verifies whether a finalization proof is valid and still relevant.
    pub fn verify_finalization(&mut self, finalization: &Finalization<S, D>) -> Action {
        // Check if we are still in a view where this finalization could help
        let view = finalization.view();
        if !self.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        //
        // After we broadcast a finalization certificate there should never be a conflicting one
        // unless the protocol safety has already been violated (equivocation at certificate level),
        // so we skip redundant processing.
        if self.has_broadcast_finalization(view) {
            return Action::Skip;
        }

        // Verify finalization
        if !finalization.verify(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }
        Action::Process
    }

    /// Replays a journaled message into the appropriate round during recovery.
    pub fn replay(&mut self, message: &Voter<S, D>) {
        self.create_round(message.view()).replay(message);
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
        self.create_round(view).set_deadlines(now, now);

        // Update metrics
        self.skipped_views.inc();
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

    /// Attempt to verify a proposed block.
    ///
    /// Unlike during proposal, we don't use a verification opportunity
    /// to backfill missing certificates (a malicious proposer could
    /// ask us to fetch junk).
    #[allow(clippy::type_complexity)]
    pub fn try_verify(&mut self) -> Option<(Context<D, S::PublicKey>, Proposal<D>)> {
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
        let _ = self.tracked_views.try_set(self.views.len());
        removed
    }

    /// Returns the quorum payload for a view, checking certificates first,
    /// then falling back to checking if we have quorum votes.
    fn quorum_payload(&self, view: View) -> Option<&D> {
        // Special case for genesis view
        if view == GENESIS_VIEW {
            return Some(self.genesis.as_ref().expect("genesis must be present"));
        }

        // Ensure proposal exists
        let round = self.views.get(&view)?;
        let payload = &round.proposal()?.payload;

        // Check certificates
        if round.finalization().is_some() || round.notarization().is_some() {
            return Some(payload);
        }

        // Check votes
        let quorum = self.scheme.participants().quorum() as usize;
        if round.len_finalizes() >= quorum || round.len_notarizes() >= quorum {
            return Some(payload);
        }
        None
    }

    fn is_nullified(&self, view: View) -> bool {
        // Special case for genesis view (although it should also not be in the views map).
        if view == GENESIS_VIEW {
            return false;
        }

        let round = match self.views.get(&view) {
            Some(round) => round,
            None => return false,
        };
        let quorum = self.scheme.participants().quorum() as usize;
        round.nullification().is_some() || round.len_nullifies() >= quorum
    }

    /// Finds the parent payload for a given view by walking backwards through
    /// the chain, skipping nullified views until finding a certified payload.
    fn find_parent(&self, view: View) -> Result<(View, D), View> {
        // If the view is the genesis view, consider it to be its own parent.
        let mut cursor = view.previous().unwrap_or(GENESIS_VIEW);

        loop {
            // Return the first notarized or finalized parent.
            if let Some(parent) = self.quorum_payload(cursor) {
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
    /// - It is notarized or finalized.
    /// - There exist nullifications for all views between it and the proposal view.
    fn parent_payload(&self, proposal: &Proposal<D>) -> Option<D> {
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

        // May return `None` if the parent view is not yet notarized or finalized.
        self.quorum_payload(parent).copied()
    }

    /// Emits the best notarization or finalization available (i.e. the "floor"), if we were the leader
    /// in the provided view (regardless of whether we built a proposal).
    pub fn emit_floor(&mut self, view: View) -> Option<Voter<S, D>> {
        // Check if we were the leader in the provided view.
        let leader = self.leader_index(view)?;
        if self.scheme.me().is_none_or(|me| me != leader) {
            return None;
        }

        // Walk backwards through the chain, emitting the best notarization or finalization available.
        for cursor in View::range(GENESIS_VIEW.next(), self.view.next()).rev() {
            let Some(round) = self.views.get(&cursor) else {
                continue;
            };
            if let Some(finalization) = round.finalization() {
                return Some(Voter::Finalization(finalization.clone()));
            }
            if let Some(notarization) = round.notarization() {
                return Some(Voter::Notarization(notarization.clone()));
            }
        }
        None
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
    use commonware_runtime::{deterministic, Runner};
    use std::time::Duration;

    fn test_genesis() -> Sha256Digest {
        Sha256Digest::from([0u8; 32])
    }

    #[test]
    fn certificate_candidates_respect_force_flag() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let mut state: State<_, _, Sha256Digest> = State::new(
                context,
                Config {
                    scheme: verifier.clone(),
                    namespace: namespace.clone(),
                    epoch: Epoch::new(11),
                    activity_timeout: ViewDelta::new(6),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
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
                .map(|scheme| {
                    Notarize::sign(scheme, &namespace, notarize_proposal.clone()).unwrap()
                })
                .collect();
            let notarization = Notarization::from_notarizes(&verifier, notarize_votes.iter())
                .expect("notarization");
            state.add_verified_notarization(notarization);

            // Produce candidate once
            assert!(state.construct_notarization(notarize_view).is_some());
            assert!(state.construct_notarization(notarize_view).is_none());
            assert!(state.notarization(notarize_view).is_some());

            // Add nullification
            let nullify_view = View::new(4);
            let nullify_round = Rnd::new(Epoch::new(11), nullify_view);
            let nullify_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, &namespace, nullify_round)
                        .expect("nullify")
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &nullify_votes).expect("nullification");
            state.add_verified_nullification(nullification);

            // Produce candidate once
            assert!(state.construct_nullification(nullify_view).is_some());
            assert!(state.construct_nullification(nullify_view).is_none());
            assert!(state.nullification(nullify_view).is_some());

            // Add finalization
            let finalize_view = View::new(5);
            let finalize_round = Rnd::new(Epoch::new(11), finalize_view);
            let finalize_proposal =
                Proposal::new(finalize_round, GENESIS_VIEW, Sha256Digest::from([51u8; 32]));
            let finalize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Finalize::sign(scheme, &namespace, finalize_proposal.clone()).unwrap()
                })
                .collect();
            let finalization = Finalization::from_finalizes(&verifier, finalize_votes.iter())
                .expect("finalization");
            state.add_verified_finalization(finalization);

            // Produce candidate once
            assert!(state.construct_finalization(finalize_view).is_some());
            assert!(state.construct_finalization(finalize_view).is_none());
            assert!(state.finalization(finalize_view).is_some());
        });
    }

    #[test]
    fn emit_uses_best_certificate() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let local_scheme = schemes[1].clone(); // leader of view 2
            let cfg = Config {
                scheme: local_scheme.clone(),
                namespace: namespace.clone(),
                epoch: Epoch::new(7),
                activity_timeout: ViewDelta::new(3),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Start proposal with missing parent
            state.enter_view(View::new(1), None);
            state.enter_view(View::new(2), None);

            // First proposal should return none
            assert!(state.try_propose().is_none());
            assert!(state.emit_floor(View::new(2)).is_none());

            // Add notarization for parent view
            let parent_round = Rnd::new(state.epoch(), View::new(1));
            let parent_proposal =
                Proposal::new(parent_round, GENESIS_VIEW, Sha256Digest::from([11u8; 32]));
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, &namespace, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, votes.iter()).expect("notarization");
            state.add_verified_notarization(notarization.clone());

            // Emitted returns as soon as we have some certificate (even if we haven't proposed yet)
            let emitted = state.emit_floor(View::new(2)).unwrap();
            match emitted {
                Voter::Notarization(emitted) => {
                    assert_eq!(emitted, notarization);
                }
                _ => panic!("unexpected emitted message"),
            }

            // Second call should return the context
            assert!(state.try_propose().is_some());

            // Insert proposal
            let proposal = Proposal::new(
                Rnd::new(state.epoch(), View::new(2)),
                View::new(1),
                Sha256Digest::from([22u8; 32]),
            );
            state.proposed(proposal);

            // New certificate shows
            let future_proposal = Proposal::new(
                Rnd::new(state.epoch(), View::new(99)),
                View::new(97),
                Sha256Digest::from([11u8; 32]),
            );
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, &namespace, future_proposal.clone()).unwrap())
                .collect();
            let future_notarization =
                Notarization::from_notarizes(&verifier, votes.iter()).expect("notarization");
            state.add_verified_notarization(future_notarization.clone());

            // Emitted returns the same certificate
            let emitted = state.emit_floor(View::new(2)).unwrap();
            match emitted {
                Voter::Notarization(emitted) => {
                    assert_eq!(emitted, future_notarization);
                }
                _ => panic!("unexpected emitted message"),
            }
        });
    }

    #[test]
    fn timeout_helpers_reuse_and_reset_deadlines() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture { schemes, .. } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let local_scheme = schemes[0].clone(); // leader of view 1
            let retry = Duration::from_secs(3);
            let cfg = Config {
                scheme: local_scheme.clone(),
                namespace: namespace.clone(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: retry,
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context.clone(), cfg);
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
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                namespace: namespace.clone(),
                epoch: Epoch::new(7),
                activity_timeout: ViewDelta::new(10),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
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
                .map(|scheme| Finalize::sign(scheme, &namespace, proposal_a.clone()).unwrap())
                .collect();
            let finalization = Finalization::from_finalizes(&verifier, finalization_votes.iter())
                .expect("finalization");
            state.add_verified_finalization(finalization);

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
            let Fixture { schemes, .. } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let local_scheme = schemes[2].clone(); // leader of view 1
            let cfg = Config {
                scheme: local_scheme.clone(),
                namespace: namespace.clone(),
                epoch: Epoch::new(4),
                activity_timeout: ViewDelta::new(2),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Create proposal
            let parent_view = View::new(1);
            let parent_payload = Sha256Digest::from([1u8; 32]);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                parent_payload,
            );
            {
                let parent_round = state.create_round(parent_view);
                parent_round.add_verified_notarize(
                    Notarize::sign(&local_scheme, &namespace, parent_proposal.clone()).unwrap(),
                );
            }

            // Attempt to get parent payload
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                parent_view,
                Sha256Digest::from([9u8; 32]),
            );
            assert!(state.parent_payload(&proposal).is_none());

            // Add notarize votes
            {
                let parent_round = state.create_round(parent_view);
                for scheme in &schemes[1..] {
                    let vote = Notarize::sign(scheme, &namespace, parent_proposal.clone()).unwrap();
                    parent_round.add_verified_notarize(vote);
                }
            }

            // Get parent
            let digest = state.parent_payload(&proposal).expect("parent payload");
            assert_eq!(digest, parent_payload);
        });
    }

    #[test]
    fn parent_payload_errors_without_nullification() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let cfg = Config {
                scheme: verifier,
                namespace: namespace.clone(),
                epoch: Epoch::new(1),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
                activity_timeout: ViewDelta::new(5),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Create parent proposal
            let parent_view = View::new(1);
            let parent_proposal = Proposal::new(
                Rnd::new(Epoch::new(1), parent_view),
                GENESIS_VIEW,
                Sha256Digest::from([2u8; 32]),
            );
            let parent_round = state.create_round(parent_view);
            for scheme in &schemes {
                let vote = Notarize::sign(scheme, &namespace, parent_proposal.clone()).unwrap();
                parent_round.add_verified_notarize(vote);
            }
            state.create_round(View::new(2));

            // Attempt to get parent payload
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                parent_view,
                Sha256Digest::from([3u8; 32]),
            );
            assert!(state.parent_payload(&proposal).is_none());
        });
    }

    #[test]
    fn parent_payload_returns_genesis_payload() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let cfg = Config {
                scheme: verifier,
                namespace: namespace.clone(),
                epoch: Epoch::new(1),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
                activity_timeout: ViewDelta::new(5),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add nullify votes
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(
                        scheme,
                        &namespace,
                        Rnd::new(Epoch::new(1), View::new(1)),
                    )
                    .unwrap()
                })
                .collect();
            {
                let round = state.create_round(View::new(1));
                for vote in votes {
                    round.add_verified_nullify(vote);
                }
            }

            // Get genesis payload
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(2)),
                GENESIS_VIEW,
                Sha256Digest::from([8u8; 32]),
            );
            let genesis = Sha256Digest::from([0u8; 32]);
            let digest = state.parent_payload(&proposal).expect("genesis payload");
            assert_eq!(digest, genesis);
        });
    }

    #[test]
    fn parent_payload_rejects_parent_before_finalized() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let cfg = Config {
                scheme: verifier.clone(),
                namespace: namespace.clone(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add finalization
            let proposal_a = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(3)),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, &namespace, proposal_a.clone()).unwrap())
                .collect();
            let finalization = Finalization::from_finalizes(&verifier, finalization_votes.iter())
                .expect("finalization");
            state.add_verified_finalization(finalization);

            // Attempt to verify before finalized
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), View::new(4)),
                View::new(2),
                Sha256Digest::from([6u8; 32]),
            );
            assert!(state.parent_payload(&proposal).is_none());
        });
    }

    #[test]
    fn replay_restores_conflict_state() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let mut scheme_iter = schemes.into_iter();
            let local_scheme = scheme_iter.next().unwrap();
            let other_schemes: Vec<_> = scheme_iter.collect();
            let epoch: Epoch = Epoch::new(3);
            let mut state: State<_, _, Sha256Digest> = State::new(
                context.clone(),
                Config {
                    scheme: local_scheme.clone(),
                    namespace: namespace.clone(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());
            let view = View::new(4);
            let round = Rnd::new(epoch, view);
            let proposal_a = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([21u8; 32]));
            let proposal_b = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([22u8; 32]));
            let local_vote = Notarize::sign(&local_scheme, &namespace, proposal_a.clone()).unwrap();

            // Add local vote and replay
            state.add_verified_notarize(local_vote.clone());
            state.replay(&Voter::Notarize(local_vote.clone()));

            // Add conflicting notarization and replay
            let votes_b: Vec<_> = other_schemes
                .iter()
                .take(3)
                .map(|scheme| Notarize::sign(scheme, &namespace, proposal_b.clone()).unwrap())
                .collect();
            let conflicting =
                Notarization::from_notarizes(&verifier, votes_b.iter()).expect("certificate");
            state.add_verified_notarization(conflicting.clone());
            state.replay(&Voter::Notarization(conflicting.clone()));

            // No finalize candidate (conflict detected)
            assert!(state.construct_finalize(view).is_none());

            // Restart state and replay
            let mut restarted: State<_, _, Sha256Digest> = State::new(
                context,
                Config {
                    scheme: local_scheme,
                    namespace: namespace.clone(),
                    epoch: Epoch::new(1),
                    activity_timeout: ViewDelta::new(5),
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            restarted.set_genesis(test_genesis());
            restarted.add_verified_notarize(local_vote.clone());
            restarted.replay(&Voter::Notarize(local_vote));
            restarted.add_verified_notarization(conflicting.clone());
            restarted.replay(&Voter::Notarization(conflicting));

            // No finalize candidate (conflict detected)
            assert!(restarted.construct_finalize(view).is_none());
        });
    }

    #[test]
    fn only_notarize_before_nullify() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let namespace = b"ns".to_vec();
            let Fixture { schemes, .. } = ed25519(&mut context, 4);
            let cfg = Config {
                scheme: schemes[0].clone(),
                namespace: namespace.clone(),
                epoch: Epoch::new(1),
                activity_timeout: ViewDelta::new(5),
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());
            let view = state.current_view();

            // Get notarize from another leader
            let proposal = Proposal::new(
                Rnd::new(Epoch::new(1), view),
                GENESIS_VIEW,
                Sha256Digest::from([1u8; 32]),
            );
            let notarize = Notarize::sign(&schemes[0], &namespace, proposal.clone()).unwrap();
            state.add_verified_notarize(notarize);

            // Attempt to verify
            assert!(matches!(state.try_verify(), Some((_, p)) if p == proposal));
            assert!(state.verified(view));

            // Check if willing to notarize
            assert!(matches!(
                state.construct_notarize(view),
                Some(n) if n.proposal == proposal
            ));

            // Handle timeout (not a retry)
            assert!(!state.handle_timeout().0);
            let nullify = Nullify::sign::<Sha256Digest>(
                &schemes[1],
                &namespace,
                Rnd::new(Epoch::new(1), view),
            )
            .unwrap();
            state.add_verified_nullify(nullify);

            // Attempt to notarize
            assert!(state.construct_notarize(view).is_none());
        });
    }
}
