use super::round::{MissingCertificates, ParentValidationError, ProposeStatus, Round};
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
use commonware_cryptography::Digest;
use std::{
    collections::BTreeMap,
    time::{Duration, SystemTime},
};

const GENESIS_VIEW: View = 0;

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
        self.scheme.me().is_some_and(|me| me == idx)
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
        let round = self.create_round(view, now);
        round.set_deadlines(leader_deadline, advance_deadline);
        round.set_leader(seed);
        self.view = view;
        true
    }

    fn create_round(&mut self, view: View, start: SystemTime) -> &mut Round<S, D> {
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
        self.create_round(view, now)
            .next_timeout_deadline(now, retry)
    }

    pub fn handle_timeout(&mut self, view: View, now: SystemTime) -> bool {
        self.create_round(view, now).handle_timeout()
    }

    pub fn add_verified_notarize(
        &mut self,
        now: SystemTime,
        notarize: Notarize<S, D>,
    ) -> Option<S::PublicKey> {
        self.create_round(notarize.view(), now)
            .add_verified_notarize(notarize)
    }

    pub fn add_verified_nullify(&mut self, now: SystemTime, nullify: Nullify<S>) {
        self.create_round(nullify.view(), now)
            .add_verified_nullify(nullify);
    }

    pub fn add_verified_finalize(
        &mut self,
        now: SystemTime,
        finalize: Finalize<S, D>,
    ) -> Option<S::PublicKey> {
        self.create_round(finalize.view(), now)
            .add_verified_finalize(finalize)
    }

    pub fn add_verified_notarization(
        &mut self,
        now: SystemTime,
        notarization: Notarization<S, D>,
    ) -> (bool, Option<S::PublicKey>) {
        self.create_round(notarization.view(), now)
            .add_verified_notarization(notarization)
    }

    pub fn add_verified_nullification(
        &mut self,
        now: SystemTime,
        nullification: Nullification<S>,
    ) -> bool {
        self.create_round(nullification.view(), now)
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

        self.create_round(finalization.view(), now)
            .add_verified_finalization(finalization)
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
    ) -> Option<(bool, Notarization<S, D>)> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.notarizable(force))
    }

    pub fn nullification_candidate(
        &mut self,
        view: View,
        force: bool,
    ) -> Option<(bool, Nullification<S>)> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.nullifiable(force))
    }

    pub fn finalization_candidate(
        &mut self,
        view: View,
        force: bool,
    ) -> Option<(bool, Finalization<S, D>)> {
        self.views
            .get_mut(&view)
            .and_then(|round| round.finalizable(force))
    }

    pub fn replay(&mut self, view: View, now: SystemTime, message: &Voter<S, D>) {
        self.create_round(view, now).replay(message);
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
        self.create_round(view, now)
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
            self.create_round(view, now).set_leader_deadline(deadline);
        }
    }

    pub fn try_propose(&mut self, now: SystemTime) -> ProposeStatus<S::PublicKey, D> {
        let view = self.view;
        if view == GENESIS_VIEW {
            return ProposeStatus::NotReady;
        }
        let parent = self.find_parent(view);
        let round = self.create_round(view, now);
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
        let Some(leader) = round.try_propose() else {
            return ProposeStatus::NotReady;
        };
        ProposeStatus::Ready(Context {
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
        // TODO: this logic looks horrible
        let (leader, proposal) = {
            let round = match self.views.get(&view) {
                Some(round) => round,
                None => return None,
            };
            round.should_verify()?
        };
        let parent_payload = match self.parent_payload(view, &proposal) {
            Ok(payload) => payload,
            Err(ParentValidationError::MissingParentNotarization { view: _ }) => {
                return None;
            }
            Err(ParentValidationError::MissingNullification { view: _ }) => {
                return None;
            }
            Err(_) => return None,
        };
        let round = match self.views.get_mut(&view) {
            Some(round) => round,
            None => return None,
        };
        if !round.try_verify() {
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
            let round = state.create_round(finalize_view, now);
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
        let local_scheme = schemes[1].clone(); // leader of view 2
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
        let local_scheme = schemes[2].clone(); // leader of view 5
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
            state.create_round(view, SystemTime::UNIX_EPOCH + Duration::from_secs(view));
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
            let parent_round = state.create_round(parent_view, now);
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
            let parent_round = state.create_round(parent_view, now);
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
        let parent_round = state.create_round(parent_view, now);
        parent_round.record_proposal(false, parent_proposal.clone());
        for scheme in &schemes {
            let vote = Notarize::sign(scheme, namespace, parent_proposal.clone()).unwrap();
            parent_round.add_verified_notarize(vote);
        }
        state.create_round(2, now);

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
            let round = state.create_round(1, now);
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
        let parent_round = state.create_round(parent_view, now);
        parent_round.record_proposal(false, parent_proposal);

        // Create nullified round
        let nullified_round = state.create_round(3, now);
        for scheme in &schemes {
            let vote = Nullify::sign::<Sha256Digest>(scheme, namespace, Rnd::new(1, 3)).unwrap();
            nullified_round.add_verified_nullify(vote);
        }

        // Create round with no data
        state.create_round(4, now);

        // Create proposal
        let proposal = Proposal::new(Rnd::new(1, 5), parent_view, Sha256Digest::from([5u8; 32]));
        let round = state.create_round(5, now);
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
            let round = state.create_round(parent_view, now);
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
            let round = state.create_round(3, now);
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
            let round = state.create_round(4, now);
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
            let round = state.create_round(parent_view, now);
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
            let round = state.create_round(proposal_view, now);
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
        assert!(matches!(state.try_verify(view), Some((_, p)) if p == proposal));
        assert!(state.verified(view));

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
}
