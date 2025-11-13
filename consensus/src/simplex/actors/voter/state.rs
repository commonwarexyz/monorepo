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
    types::{Epoch, Round as Rnd, View},
    Viewable,
};
use commonware_cryptography::{Digest, PublicKey};
use commonware_runtime::{
    telemetry::metrics::histogram::{self, Buckets},
    Clock, Metrics,
};
use prometheus_client::metrics::histogram::Histogram;
use rand::{CryptoRng, Rng};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Action to take after processing a message.
pub enum Action {
    /// Skip processing the message.
    Skip,
    /// Block the peer from sending any more messages.
    Block,
    /// Process the message.
    Process,
}

const GENESIS_VIEW: View = 0;

/// Status of preparing a local proposal for the current view.
#[derive(Debug, Clone)]
pub enum ProposeResult<P: PublicKey, D: Digest> {
    Ready(Context<D, P>),
    Missing(View),
    Pending,
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

/// Configuration for initializing [`State`].
pub struct Config<S: Scheme> {
    pub scheme: S,
    pub namespace: Vec<u8>,
    pub epoch: Epoch,
    pub activity_timeout: View,
    pub leader_timeout: Duration,
    pub notarization_timeout: Duration,
    pub nullify_retry: Duration,
}

/// Core simplex state machine extracted from actors for easier testing and recovery.
pub struct State<E: Clock + Rng + CryptoRng + Metrics, S: Scheme, D: Digest> {
    context: E,
    scheme: S,
    namespace: Vec<u8>,
    epoch: Epoch,
    activity_timeout: View,
    leader_timeout: Duration,
    notarization_timeout: Duration,
    nullify_retry: Duration,
    view: View,
    last_finalized: View,
    genesis: Option<D>,
    views: BTreeMap<View, Round<S, D>>,
    recover_latency: histogram::Timed<E>,
}

impl<E: Clock + Rng + CryptoRng + Metrics, S: Scheme, D: Digest> State<E, S, D> {
    pub fn new(context: E, cfg: Config<S>) -> Self {
        let recover_latency = Histogram::new(Buckets::CRYPTOGRAPHY.into_iter());
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
            recover_latency: histogram::Timed::new(recover_latency, clock),
        }
    }

    pub fn set_genesis(&mut self, genesis: D) {
        self.genesis = Some(genesis);
        self.enter_view(1, None);
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
        self.scheme.me().is_some_and(|me| me == idx)
    }

    fn enter_view(&mut self, view: View, seed: Option<S::Seed>) -> bool {
        if view <= self.view {
            return false;
        }
        let now = self.context.current();
        let leader_deadline = now + self.leader_timeout;
        let advance_deadline = now + self.notarization_timeout;
        let round = self.create_round(view);
        round.set_deadlines(leader_deadline, advance_deadline);
        round.set_leader(seed);
        self.view = view;
        true
    }

    fn create_round(&mut self, view: View) -> &mut Round<S, D> {
        self.views.entry(view).or_insert_with(|| {
            Round::new(
                self.scheme.clone(),
                Rnd::new(self.epoch, view),
                self.context.current(),
            )
        })
    }

    pub fn next_timeout_deadline(&mut self) -> SystemTime {
        let now = self.context.current();
        let nullify_retry = self.nullify_retry;
        let round = self.create_round(self.view);
        round.next_timeout_deadline(now, nullify_retry)
    }

    pub fn handle_timeout(&mut self, view: View) -> (bool, Option<Nullify<S>>) {
        let was_retry = self.create_round(view).handle_timeout();
        (
            was_retry,
            Nullify::sign::<D>(&self.scheme, &self.namespace, Rnd::new(self.epoch, view)),
        )
    }

    pub fn add_verified_notarize(&mut self, notarize: Notarize<S, D>) -> Option<S::PublicKey> {
        self.create_round(notarize.view())
            .add_verified_notarize(notarize)
    }

    pub fn add_verified_nullify(&mut self, nullify: Nullify<S>) {
        self.create_round(nullify.view())
            .add_verified_nullify(nullify);
    }

    pub fn add_verified_finalize(&mut self, finalize: Finalize<S, D>) -> Option<S::PublicKey> {
        self.create_round(finalize.view())
            .add_verified_finalize(finalize)
    }

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
        self.enter_view(view + 1, seed);
        added
    }

    pub fn add_verified_nullification(&mut self, nullification: Nullification<S>) -> bool {
        let view = nullification.view();
        let seed = self
            .scheme
            .seed(nullification.round(), &nullification.certificate);
        let added = self
            .create_round(view)
            .add_verified_nullification(nullification);
        self.enter_view(view + 1, seed);
        added
    }

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
        self.enter_view(view + 1, seed);
        added
    }

    pub fn has_broadcast_notarization(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.has_broadcast_notarization())
    }

    pub fn has_broadcast_nullification(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.has_broadcast_nullification())
    }

    pub fn has_broadcast_finalization(&self, view: View) -> bool {
        self.views
            .get(&view)
            .is_some_and(|round| round.has_broadcast_finalization())
    }

    pub fn construct_notarize(&mut self, view: View) -> Option<Notarize<S, D>> {
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.notarize_candidate().cloned())?;
        Notarize::sign(&self.scheme, &self.namespace, candidate)
    }

    pub fn construct_finalize(&mut self, view: View) -> Option<Finalize<S, D>> {
        let candidate = self
            .views
            .get_mut(&view)
            .and_then(|round| round.finalize_candidate().cloned())?;
        Finalize::sign(&self.scheme, &self.namespace, candidate)
    }

    pub fn construct_notarization(
        &mut self,
        view: View,
        force: bool,
    ) -> Option<Notarization<S, D>> {
        let mut timer = self.recover_latency.timer();
        let Some((new, notarization)) = self
            .views
            .get_mut(&view)
            .and_then(|round| round.notarizable(force))
        else {
            timer.cancel();
            return None;
        };
        if new {
            timer.observe();
        } else {
            timer.cancel();
        }
        Some(notarization)
    }

    pub fn verify_notarization(&mut self, notarization: &Notarization<S, D>) -> Action {
        // Check if we are still in a view where this notarization could help
        let view = notarization.view();
        if !self.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast notarization for this view (in which
        // case we can ignore this message)
        if self.has_broadcast_notarization(view) {
            return Action::Skip;
        }

        // Verify notarization
        if !notarization.verify(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }
        Action::Process
    }

    pub fn construct_nullification(&mut self, view: View, force: bool) -> Option<Nullification<S>> {
        let mut timer = self.recover_latency.timer();
        let Some((new, nullification)) = self
            .views
            .get_mut(&view)
            .and_then(|round| round.nullifiable(force))
        else {
            timer.cancel();
            return None;
        };
        if new {
            timer.observe();
        } else {
            timer.cancel();
        }
        Some(nullification)
    }

    pub fn verify_nullification(&mut self, nullification: &Nullification<S>) -> Action {
        // Check if we are still in a view where this notarization could help
        if !self.is_interesting(nullification.view(), true) {
            return Action::Skip;
        }

        // Determine if we already broadcast nullification for this view (in which
        // case we can ignore this message)
        if self.has_broadcast_nullification(nullification.view()) {
            return Action::Skip;
        }

        // Verify nullification
        if !nullification.verify::<_, D>(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }
        Action::Process
    }

    pub fn construct_finalization(
        &mut self,
        view: View,
        force: bool,
    ) -> Option<Finalization<S, D>> {
        let mut timer = self.recover_latency.timer();
        let Some((new, finalization)) = self
            .views
            .get_mut(&view)
            .and_then(|round| round.finalizable(force))
        else {
            timer.cancel();
            return None;
        };
        if new {
            timer.observe();
        } else {
            timer.cancel();
        }
        Some(finalization)
    }

    pub fn verify_finalization(&mut self, finalization: &Finalization<S, D>) -> Action {
        // Check if we are still in a view where this finalization could help
        let view = finalization.view();
        if !self.is_interesting(view, true) {
            return Action::Skip;
        }

        // Determine if we already broadcast finalization for this view (in which
        // case we can ignore this message)
        if self.has_broadcast_finalization(view) {
            return Action::Skip;
        }

        // Verify finalization
        if !finalization.verify(&mut self.context, &self.scheme, &self.namespace) {
            return Action::Block;
        }
        Action::Process
    }

    pub fn replay(&mut self, message: &Voter<S, D>) {
        self.create_round(message.view()).replay(message);
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

    pub fn expire_round(&mut self, view: View) {
        let now = self.context.current();
        self.create_round(view).set_deadlines(now, now);
    }

    pub fn try_propose(&mut self) -> ProposeResult<S::PublicKey, D> {
        let view = self.view;
        if view == GENESIS_VIEW {
            return ProposeResult::Pending;
        }
        let parent = self.find_parent(view);
        let round = self.create_round(view);
        let (parent_view, parent_payload) = match parent {
            Ok(parent) => {
                round.clear_parent_missing();
                parent
            }
            Err(missing) => {
                // Only surface the missing ancestor once per view to avoid
                // hammering the resolver while we wait for the certificate.
                if round.mark_parent_missing(missing) {
                    return ProposeResult::Missing(missing);
                }
                return ProposeResult::Pending;
            }
        };
        let Some(leader) = round.try_propose() else {
            return ProposeResult::Pending;
        };
        ProposeResult::Ready(Context {
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

    #[allow(clippy::type_complexity)]
    pub fn try_verify(&mut self, view: View) -> Option<(Context<D, S::PublicKey>, Proposal<D>)> {
        let (leader, proposal) = self.views.get(&view)?.should_verify()?;
        let parent_payload = self.parent_payload(view, &proposal)?;
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
    ///
    /// Returns `None` when the view was already pruned or never entered. Successful completions
    /// yield the (cloned) proposal so callers can log which payload advanced to voting.
    pub fn verified(&mut self, view: View) -> bool {
        self.views
            .get_mut(&view)
            .map(|round| round.verified())
            .unwrap_or(false)
    }

    pub fn prune(&mut self) -> Vec<View> {
        let min = self.min_active();
        let mut removed = Vec::new();
        while let Some(view) = self.views.keys().next().copied() {
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
        if let Some(notarization) = round.notarization() {
            return Some(&notarization.proposal.payload);
        }
        let proposal = round.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.len_notarizes() >= quorum {
            return Some(&proposal.payload);
        }
        None
    }

    fn finalized_payload(&self, view: View) -> Option<&D> {
        let round = self.views.get(&view)?;
        if let Some(finalization) = round.finalization() {
            return Some(&finalization.proposal.payload);
        }
        let proposal = round.proposal()?;
        let quorum = self.scheme.participants().quorum() as usize;
        if round.len_finalizes() >= quorum {
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
        round.nullification().is_some() || round.len_nullifies() >= quorum
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
    /// for skipped views).
    fn parent_payload(&self, current_view: View, proposal: &Proposal<D>) -> Option<D> {
        if proposal.view() <= proposal.parent {
            return None;
        }
        if proposal.parent < self.last_finalized {
            return None;
        }
        if current_view == 0 {
            return None;
        }
        if proposal.parent >= current_view {
            return None;
        }
        // Walk backwards from the previous view until we reach the parent, ensuring
        // every skipped view is nullified and the parent is notarized.
        let mut cursor = current_view - 1;
        loop {
            if cursor == proposal.parent {
                if cursor == GENESIS_VIEW {
                    return Some(self.genesis.unwrap());
                }
                let payload = self.notarized_payload(cursor).copied()?;
                return Some(payload);
            }
            if cursor == GENESIS_VIEW {
                return None;
            }
            if !self.is_nullified(cursor) {
                return None;
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
    use commonware_runtime::{deterministic, Runner};
    use rand::{rngs::StdRng, SeedableRng};
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
                    epoch: 11,
                    activity_timeout: 6,
                    leader_timeout: Duration::from_secs(1),
                    notarization_timeout: Duration::from_secs(2),
                    nullify_retry: Duration::from_secs(3),
                },
            );
            state.set_genesis(test_genesis());

            // Add notarization
            let notarize_view = 3;
            let notarize_round = Rnd::new(11, notarize_view);
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
            assert!(state.construct_notarization(notarize_view, false).is_some());
            assert!(state.construct_notarization(notarize_view, false).is_none());

            // Produce candidate again if forced
            assert!(state.construct_notarization(notarize_view, true).is_some());

            // Add nullification
            let nullify_view = 4;
            let nullify_round = Rnd::new(11, nullify_view);
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
            assert!(state.construct_nullification(nullify_view, false).is_some());
            assert!(state.construct_nullification(nullify_view, false).is_none());

            // Produce candidate again if forced
            assert!(state.construct_nullification(nullify_view, true).is_some());

            // Add finalization
            let finalize_view = 5;
            let finalize_round = Rnd::new(11, finalize_view);
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
            assert!(state.construct_finalization(finalize_view, false).is_some());
            assert!(state.construct_finalization(finalize_view, false).is_none());

            // Produce candidate again if forced
            assert!(state.construct_finalization(finalize_view, true).is_some());
        });
    }

    #[test]
    fn missing_parent_only_triggers_fetch_once() {
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
                epoch: 7,
                activity_timeout: 3,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Start proposal with missing parent
            state.enter_view(1, None);
            state.enter_view(2, None);

            // First proposal should return missing ancestors
            match state.try_propose() {
                ProposeResult::Missing(view) => assert_eq!(view, 1),
                other => panic!("expected missing ancestor, got {other:?}"),
            }
            assert!(matches!(state.try_propose(), ProposeResult::Pending));

            // Add notarization for parent view
            let parent_round = Rnd::new(state.epoch(), 1);
            let parent_proposal =
                Proposal::new(parent_round, GENESIS_VIEW, Sha256Digest::from([11u8; 32]));
            let votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, &namespace, parent_proposal.clone()).unwrap())
                .collect();
            let notarization =
                Notarization::from_notarizes(&verifier, votes.iter()).expect("notarization");
            state.add_verified_notarization(notarization);

            // Second call should be ready
            assert!(matches!(state.try_propose(), ProposeResult::Ready(_)));
        });
    }

    #[test]
    fn missing_parent_reemerges_after_partial_progress() {
        let runtime = deterministic::Runner::default();
        runtime.start(|mut context| async move {
            let Fixture {
                schemes, verifier, ..
            } = ed25519(&mut context, 4);
            let namespace = b"ns".to_vec();
            let local_scheme = schemes[2].clone(); // leader of view 5
            let cfg = Config {
                scheme: local_scheme.clone(),
                namespace: namespace.clone(),
                epoch: 9,
                activity_timeout: 4,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Advance to view 5 and ensure we are the elected leader
            for view in 1..=5 {
                state.enter_view(view, None);
            }

            // Initially the missing ancestor is view 4 (we have neither certificates nor nullify)
            match state.try_propose() {
                ProposeResult::Missing(view) => assert_eq!(view, 4),
                other => panic!("expected missing ancestor 4, got {other:?}"),
            }

            // Provide the nullification for view 4 but still leave the parent notarization absent
            let null_round = Rnd::new(state.epoch(), 4);
            let null_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| {
                    Nullify::sign::<Sha256Digest>(scheme, &namespace, null_round).unwrap()
                })
                .collect();
            let nullification =
                Nullification::from_nullifies(&verifier, &null_votes).expect("nullification");
            state.add_verified_nullification(nullification);

            // The next attempt should complain about the parent view (3) instead of 4
            match state.try_propose() {
                ProposeResult::Missing(view) => assert_eq!(view, 3),
                other => panic!("expected missing ancestor 3, got {other:?}"),
            }

            // Provide the notarization for view 3 to unblock proposals entirely
            let parent_round = Rnd::new(state.epoch(), 3);
            let parent = Proposal::new(parent_round, GENESIS_VIEW, Sha256Digest::from([0xAA; 32]));
            let notarize_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Notarize::sign(scheme, &namespace, parent.clone()).unwrap())
                .collect();
            let notarization = Notarization::from_notarizes(&verifier, notarize_votes.iter())
                .expect("notarization");
            state.add_verified_notarization(notarization);

            // Third call should be ready
            assert!(matches!(state.try_propose(), ProposeResult::Ready(_)));
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
                epoch: 4,
                activity_timeout: 2,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: retry,
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context.clone(), cfg);
            state.set_genesis(test_genesis());
            let view = state.current_view();

            // Should return same deadline until something done
            let first = state.next_timeout_deadline();
            let second = state.next_timeout_deadline();
            assert_eq!(first, second, "cached deadline should be reused");

            // Handle timeout should return false (not a retry)
            let (outcome, _) = state.handle_timeout(view);
            assert!(!outcome, "first timeout is not a retry");

            // Set retry deadline
            context.sleep(Duration::from_secs(2)).await;
            let later = context.current();
            let third = state.next_timeout_deadline();
            assert_eq!(third, later + retry, "new retry scheduled after timeout");

            // Confirm retry deadline is set
            let fourth = state.next_timeout_deadline();
            assert_eq!(fourth, later + retry, "retry deadline should be set");

            // Confirm works if later is far in the future
            context.sleep(Duration::from_secs(10)).await;
            let fifth = state.next_timeout_deadline();
            assert_eq!(fifth, later + retry, "retry deadline should be set");

            // Handle timeout should return true whenever called (can be before registered deadline)
            let (outcome, _) = state.handle_timeout(view);
            assert!(outcome, "subsequent timeout should be treated as retry");
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
                epoch: 7,
                activity_timeout: 10,
                leader_timeout: Duration::from_secs(1),
                notarization_timeout: Duration::from_secs(2),
                nullify_retry: Duration::from_secs(3),
            };
            let mut state: State<_, _, Sha256Digest> = State::new(context, cfg);
            state.set_genesis(test_genesis());

            // Add initial rounds
            for view in 0..5 {
                state.create_round(view);
            }

            // Create finalization for view 20
            let proposal_a = Proposal {
                round: Rnd::new(1, 20),
                parent: 0,
                payload: Sha256Digest::from([1u8; 32]),
            };
            let finalization_votes: Vec<_> = schemes
                .iter()
                .map(|scheme| Finalize::sign(scheme, &namespace, proposal_a.clone()).unwrap())
                .collect();
            let finalization = Finalization::from_finalizes(&verifier, finalization_votes.iter())
                .expect("finalization");
            state.add_verified_finalization(finalization);

            // Update last finalize to be in the future
            let removed = state.prune();
            assert_eq!(removed, vec![0, 1, 2, 3, 4]);
            assert_eq!(state.tracked_views(), 2); // 20 and 21
        });
    }

    // #[test]
    // fn parent_payload_returns_parent_digest() {
    //     let mut rng = StdRng::seed_from_u64(7);
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: verifier,
    //         epoch: 1,
    //         activity_timeout: 5,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());
    //     let namespace = b"ns";
    //     let now = SystemTime::UNIX_EPOCH;

    //     // Create proposal
    //     let parent_view = 1;
    //     let parent_payload = Sha256Digest::from([1u8; 32]);
    //     let parent_proposal = Proposal::new(Rnd::new(1, parent_view), GENESIS_VIEW, parent_payload);
    //     {
    //         let parent_round = state.create_round(parent_view, now);
    //         parent_round.add_verified_notarize(
    //             Notarize::sign(&schemes[0], namespace, parent_proposal.clone()).unwrap(),
    //         );
    //     }

    //     // Attempt to get parent payload
    //     let proposal = Proposal::new(Rnd::new(1, 2), parent_view, Sha256Digest::from([9u8; 32]));
    //     assert!(state.parent_payload(2, &proposal).is_none());

    //     // Add notarize votes
    //     {
    //         let parent_round = state.create_round(parent_view, now);
    //         for scheme in &schemes[1..] {
    //             let vote = Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap();
    //             parent_round.add_verified_notarize(vote);
    //         }
    //     }

    //     // Get parent
    //     let digest = state.parent_payload(2, &proposal).expect("parent payload");
    //     assert_eq!(digest, parent_payload);
    // }

    // #[test]
    // fn parent_payload_errors_without_nullification() {
    //     let mut rng = StdRng::seed_from_u64(9);
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: verifier,
    //         epoch: 1,
    //         activity_timeout: 5,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());
    //     let namespace = b"ns";
    //     let now = SystemTime::UNIX_EPOCH;

    //     // Create parent proposal
    //     let parent_view = 1;
    //     let parent_proposal = Proposal::new(
    //         Rnd::new(1, parent_view),
    //         GENESIS_VIEW,
    //         Sha256Digest::from([2u8; 32]),
    //     );
    //     let parent_round = state.create_round(parent_view, now);
    //     for scheme in &schemes {
    //         let vote = Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap();
    //         parent_round.add_verified_notarize(vote);
    //     }
    //     state.create_round(2, now);

    //     // Attempt to get parent payload
    //     let proposal = Proposal::new(Rnd::new(1, 3), parent_view, Sha256Digest::from([3u8; 32]));
    //     assert!(state.parent_payload(3, &proposal).is_none());
    // }

    // #[test]
    // fn parent_payload_returns_genesis_payload() {
    //     let mut rng = StdRng::seed_from_u64(21);
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: verifier,
    //         epoch: 1,
    //         activity_timeout: 5,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());
    //     let namespace = b"ns";
    //     let now = SystemTime::UNIX_EPOCH;

    //     // Add nullify votes
    //     let votes: Vec<_> = schemes
    //         .iter()
    //         .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 1)).unwrap())
    //         .collect();
    //     {
    //         let round = state.create_round(1, now);
    //         for vote in votes {
    //             round.add_verified_nullify(vote);
    //         }
    //     }

    //     // Get genesis payload
    //     let proposal = Proposal::new(Rnd::new(1, 2), GENESIS_VIEW, Sha256Digest::from([8u8; 32]));
    //     let genesis = Sha256Digest::from([0u8; 32]);
    //     let digest = state.parent_payload(2, &proposal).expect("genesis payload");
    //     assert_eq!(digest, genesis);
    // }

    // #[test]
    // fn parent_payload_rejects_parent_before_finalized() {
    //     let mut rng = StdRng::seed_from_u64(23);
    //     let namespace = b"ns";
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: verifier.clone(),
    //         epoch: 1,
    //         activity_timeout: 5,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());

    //     // Add finalization
    //     let proposal_a = Proposal {
    //         round: Rnd::new(1, 3),
    //         parent: 0,
    //         payload: Sha256Digest::from([1u8; 32]),
    //     };
    //     let finalization_votes: Vec<_> = schemes
    //         .iter()
    //         .map(|scheme| Finalize::sign(scheme, namespace, proposal_a.clone()).unwrap())
    //         .collect();
    //     let finalization = Finalization::from_finalizes(&verifier, finalization_votes.iter())
    //         .expect("finalization");
    //     state.add_verified_finalization(
    //         SystemTime::UNIX_EPOCH + Duration::from_secs(20),
    //         finalization,
    //     );

    //     // Attempt to verify before finalized
    //     let proposal = Proposal::new(Rnd::new(1, 4), 2, Sha256Digest::from([6u8; 32]));
    //     assert!(state.parent_payload(4, &proposal).is_none());
    // }

    // #[test]
    // fn missing_certificates_reports_gaps() {
    //     let mut rng = StdRng::seed_from_u64(11);
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: verifier,
    //         epoch: 1,
    //         activity_timeout: 5,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());
    //     let namespace = b"ns";
    //     let now = SystemTime::UNIX_EPOCH;

    //     // Create parent proposal
    //     let parent_view = 2;
    //     let parent_proposal = Proposal::new(
    //         Rnd::new(1, parent_view),
    //         GENESIS_VIEW,
    //         Sha256Digest::from([4u8; 32]),
    //     );
    //     let parent_round = state.create_round(parent_view, now);
    //     let vote = Notarize::sign(&schemes[0], namespace, parent_proposal.clone()).unwrap();
    //     parent_round.add_verified_notarize(vote);

    //     // Create nullified round
    //     let nullified_round = state.create_round(3, now);
    //     for scheme in &schemes {
    //         let vote = Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 3)).unwrap();
    //         nullified_round.add_verified_nullify(vote);
    //     }

    //     // Create round with no data
    //     state.create_round(4, now);

    //     // Create proposal
    //     let proposal = Proposal::new(Rnd::new(1, 5), parent_view, Sha256Digest::from([5u8; 32]));
    //     let round = state.create_round(5, now);
    //     for scheme in schemes.iter().take(2) {
    //         let vote = Notarize::sign(scheme, namespace, proposal.clone()).unwrap();
    //         round.add_verified_notarize(vote);
    //     }

    //     // Get missing certificates
    //     let missing = state.missing_certificates(5).expect("missing data");
    //     assert_eq!(missing.parent, parent_view);
    //     assert_eq!(missing.notarizations, vec![parent_view]);
    //     assert_eq!(missing.nullifications, vec![4]);
    // }

    // #[test]
    // fn missing_certificates_none_when_ancestry_complete() {
    //     let mut rng = StdRng::seed_from_u64(25);
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: verifier,
    //         epoch: 1,
    //         activity_timeout: 5,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());
    //     let namespace = b"ns";
    //     let now = SystemTime::UNIX_EPOCH;

    //     // Create parent proposal
    //     let parent_view = 2;
    //     let parent_proposal =
    //         Proposal::new(Rnd::new(1, parent_view), 1, Sha256Digest::from([7u8; 32]));
    //     {
    //         let round = state.create_round(parent_view, now);
    //         let votes: Vec<_> = schemes
    //             .iter()
    //             .map(|scheme| Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap())
    //             .collect();
    //         for vote in votes {
    //             round.add_verified_notarize(vote);
    //         }
    //     }

    //     // Create nullified round
    //     {
    //         let round = state.create_round(3, now);
    //         let votes: Vec<_> = schemes
    //             .iter()
    //             .map(|scheme| {
    //                 Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 3)).unwrap()
    //             })
    //             .collect();
    //         for vote in votes {
    //             round.add_verified_nullify(vote);
    //         }
    //     }

    //     // Create proposal
    //     let proposal = Proposal::new(Rnd::new(1, 4), parent_view, Sha256Digest::from([9u8; 32]));
    //     {
    //         let round = state.create_round(4, now);
    //         let votes: Vec<_> = schemes
    //             .iter()
    //             .map(|scheme| Notarize::sign(scheme, namespace, proposal.clone()).unwrap())
    //             .collect();
    //         for vote in votes {
    //             round.add_verified_notarize(vote);
    //         }
    //     }

    //     // No missing certificates
    //     assert!(state.missing_certificates(4).is_none());
    // }

    // #[test]
    // fn missing_certificates_none_when_ancestry_not_supported() {
    //     let mut rng = StdRng::seed_from_u64(27);
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: verifier,
    //         epoch: 1,
    //         activity_timeout: 5,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());
    //     let namespace = b"ns";
    //     let now = SystemTime::UNIX_EPOCH;

    //     // Create parent proposal
    //     let parent_view = 2;
    //     let parent_proposal =
    //         Proposal::new(Rnd::new(1, parent_view), 1, Sha256Digest::from([10u8; 32]));
    //     {
    //         let round = state.create_round(parent_view, now);
    //         let vote = Notarize::sign(&schemes[0], namespace, parent_proposal.clone()).unwrap();
    //         round.add_verified_notarize(vote);
    //     }

    //     // Create proposal (with minimal support)
    //     let proposal_view = 4;
    //     let proposal = Proposal::new(
    //         Rnd::new(1, proposal_view),
    //         parent_view,
    //         Sha256Digest::from([11u8; 32]),
    //     );
    //     {
    //         let round = state.create_round(proposal_view, now);
    //         let vote = Notarize::sign(&schemes[0], namespace, proposal.clone()).unwrap();
    //         round.add_verified_notarize(vote);
    //         assert!(!round.proposal_ancestry_supported());
    //     }

    //     // No missing certificates (not enough support for proposal)
    //     assert!(state.missing_certificates(proposal_view).is_none());
    // }

    // #[test]
    // fn replay_restores_conflict_state() {
    //     let mut rng = StdRng::seed_from_u64(2027);
    //     let Fixture {
    //         schemes, verifier, ..
    //     } = ed25519(&mut rng, 4);
    //     let namespace = b"ns";
    //     let mut scheme_iter = schemes.into_iter();
    //     let local_scheme = scheme_iter.next().unwrap();
    //     let other_schemes: Vec<_> = scheme_iter.collect();
    //     let epoch = 3;
    //     let activity_timeout = 5;
    //     let mut state: State<_, Sha256Digest> = State::new(Config {
    //         scheme: local_scheme.clone(),
    //         epoch,
    //         activity_timeout,
    //     });
    //     state.set_genesis(test_genesis());
    //     let view = 4;
    //     let now = SystemTime::UNIX_EPOCH;
    //     let round = Rnd::new(epoch, view);
    //     let proposal_a = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([21u8; 32]));
    //     let proposal_b = Proposal::new(round, GENESIS_VIEW, Sha256Digest::from([22u8; 32]));
    //     let local_vote = Notarize::sign(&local_scheme, namespace, proposal_a.clone()).unwrap();

    //     // Add local vote and replay
    //     state.add_verified_notarize(now, local_vote.clone());
    //     state.replay(now, &Voter::Notarize(local_vote.clone()));

    //     // Add conflicting notarization and replay
    //     let votes_b: Vec<_> = other_schemes
    //         .iter()
    //         .take(3)
    //         .map(|scheme| Notarize::sign(scheme, namespace, proposal_b.clone()).unwrap())
    //         .collect();
    //     let conflicting =
    //         Notarization::from_notarizes(&verifier, votes_b.iter()).expect("certificate");
    //     state.add_verified_notarization(now, conflicting.clone());
    //     state.replay(now, &Voter::Notarization(conflicting.clone()));

    //     // No finalize candidate (conflict detected)
    //     assert!(state.finalize_candidate(view).is_none());

    //     // Restart state and replay
    //     let mut restarted: State<_, Sha256Digest> = State::new(Config {
    //         scheme: local_scheme,
    //         epoch,
    //         activity_timeout,
    //     });
    //     restarted.set_genesis(test_genesis());
    //     restarted.add_verified_notarize(now, local_vote.clone());
    //     restarted.replay(now, &Voter::Notarize(local_vote));
    //     restarted.add_verified_notarization(now, conflicting.clone());
    //     restarted.replay(now, &Voter::Notarization(conflicting));

    //     // No finalize candidate (conflict detected)
    //     assert!(restarted.finalize_candidate(view).is_none());
    // }

    // #[test]
    // fn only_notarize_before_nullify() {
    //     let mut rng = StdRng::seed_from_u64(2031);
    //     let namespace = b"ns";
    //     let Fixture { schemes, .. } = ed25519(&mut rng, 4);
    //     let cfg = Config {
    //         scheme: schemes[0].clone(),
    //         epoch: 4,
    //         activity_timeout: 2,
    //     };
    //     let mut state: State<_, Sha256Digest> = State::new(cfg);
    //     state.set_genesis(test_genesis());
    //     let now = SystemTime::UNIX_EPOCH;
    //     let view = 1;
    //     state.enter_view(
    //         view,
    //         now,
    //         now + Duration::from_secs(1),
    //         now + Duration::from_secs(2),
    //         None,
    //     );

    //     // Get notarize from another leader
    //     let proposal = Proposal::new(Rnd::new(1, view), 0, Sha256Digest::from([1u8; 32]));
    //     let notarize = Notarize::sign(&schemes[0], namespace, proposal.clone()).unwrap();
    //     state.add_verified_notarize(now, notarize);

    //     // Attempt to verify
    //     assert!(matches!(state.try_verify(view), Some((_, p)) if p == proposal));
    //     assert!(state.verified(view));

    //     // Check if willing to notarize
    //     assert!(matches!(
    //         state.notarize_candidate(view),
    //         Some(p) if p == proposal
    //     ));

    //     // Handle timeout (not a retry)
    //     assert!(!state.handle_timeout(view, now));
    //     let nullify =
    //         Nullify::sign::<Sha256Digest>(&schemes[1], namespace, Rnd::new(1, view)).unwrap();
    //     state.add_verified_nullify(now, nullify);

    //     // Attempt to notarize
    //     assert!(state.notarize_candidate(view).is_none());
    // }
}
