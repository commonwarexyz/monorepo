use crate::{
    simplex::types::{Certificate, Notarization, Nullification},
    types::{TermLength, View},
    Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use core::num::NonZeroUsize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Why a resolver fetch was requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FetchReason {
    MissingNullification,
    CertificationFailed,
    SatisfiedByFailedNotarization,
}

impl FetchReason {
    /// Returns the stable trace field value for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingNullification => "missing_nullification",
            Self::CertificationFailed => "certification_failed",
            Self::SatisfiedByFailedNotarization => "satisfied_by_failed_notarization",
        }
    }
}

/// Side effects requested by resolver state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Effect {
    /// Issue a resolver fetch for `view`.
    Fetch {
        /// The view to fetch.
        view: View,
        /// The view whose processing caused this fetch.
        cause: View,
        /// Why the fetch is needed.
        reason: FetchReason,
    },
    /// Drop all subscribers for this view.
    Remove(View),
    /// Retain only subscribers outside this inclusive view range.
    RetainOutside { start: View, end: View },
    /// Retain only views above this floor.
    RetainAbove(View),
}

/// Tracks all known certificates from the last
/// certified notarization or finalized view to the current view.
pub struct State<S: Scheme, D: Digest> {
    /// Highest seen view.
    current_view: View,
    /// Most recent certified notarization or finalization.
    floor: Option<Certificate<S, D>>,
    /// Notarizations pending certification (possible floors).
    notarizations: BTreeMap<View, Notarization<S, D>>,
    /// Nullifications that cover any view greater than the floor.
    nullifications: BTreeMap<View, Nullification<S>>,
    /// Window of requests to send to the resolver.
    fetch_concurrent: usize,
    /// Number of views in each leader term.
    term_length: TermLength,
    /// Maps notarization view -> request views it satisfied.
    /// When a higher-view notarization satisfies a lower-view request,
    /// we track it here so we can re-request on certification failure.
    satisfied_by: HashMap<View, BTreeSet<View>>,
    /// Views where certification has failed. Only nullifications
    /// are accepted for these views.
    failed_views: HashSet<View>,
}

impl<S: Scheme, D: Digest> State<S, D> {
    /// Create a new instance of [State].
    pub fn new(fetch_concurrent: NonZeroUsize, term_length: TermLength) -> Self {
        Self {
            current_view: View::zero(),
            floor: None,
            notarizations: BTreeMap::new(),
            nullifications: BTreeMap::new(),
            fetch_concurrent: fetch_concurrent.get(),
            term_length,
            satisfied_by: HashMap::new(),
            failed_views: HashSet::new(),
        }
    }

    /// Returns true if the given view has failed certification.
    pub fn is_failed(&self, view: View) -> bool {
        self.failed_views.contains(&view)
    }

    /// Handle a new certificate and return any effects the resolver actor should apply.
    ///
    /// The `request` parameter is the view that was originally requested
    /// when this certificate was fetched. If the certificate is a notarization
    /// at a higher view, we track that the request was "satisfied by" this
    /// notarization so we can re-request on certification failure.
    pub fn handle(&mut self, certificate: Certificate<S, D>, request: Option<View>) -> Vec<Effect> {
        let cause = certificate.view();
        let mut effects = Vec::new();
        match certificate {
            Certificate::Nullification(nullification) => {
                let view = nullification.view();
                if self.encounter_nullification(view) {
                    self.nullifications.insert(view, nullification);
                    effects.push(Effect::RetainOutside {
                        start: view,
                        end: view.term_end(self.term_length),
                    });
                }
            }
            Certificate::Notarization(notarization) => {
                let view = notarization.view();
                if self.encounter_view(view) {
                    self.notarizations.insert(view, notarization);
                    if let Some(request) = request {
                        self.satisfied_by.entry(view).or_default().insert(request);
                    }
                }
            }
            Certificate::Finalization(finalization) => {
                let view = finalization.view();
                if self.encounter_view(view) || self.can_upgrade_floor(view) {
                    self.floor = Some(Certificate::Finalization(finalization));
                    effects.push(self.prune());
                }
            }
        }

        effects.extend(self.fetch(cause, FetchReason::MissingNullification));
        effects
    }

    /// Handle a certification result from the voter.
    pub fn handle_certified(&mut self, view: View, success: bool) -> Vec<Effect> {
        let mut effects = Vec::new();
        if success {
            if let Some(notarization) = self.notarizations.remove(&view) {
                if view > self.floor_view() {
                    self.floor = Some(Certificate::Notarization(notarization));
                    effects.push(self.prune());
                }
            }

            self.satisfied_by.remove(&view);
            effects.extend(self.fetch(view, FetchReason::MissingNullification));
        } else {
            self.notarizations.remove(&view);
            self.failed_views.insert(view);

            let floor = self.floor_view();
            if view > floor {
                effects.push(Effect::Fetch {
                    view,
                    cause: view,
                    reason: FetchReason::CertificationFailed,
                });
            }

            if let Some(satisfied_views) = self.satisfied_by.remove(&view) {
                for &v in satisfied_views.iter().filter(|v| **v > floor) {
                    effects.push(Effect::Fetch {
                        view: v,
                        cause: view,
                        reason: FetchReason::SatisfiedByFailedNotarization,
                    });
                }
            }
        }
        effects
    }

    /// Get the best certificate for a given view (or the floor
    /// if the view is below the floor).
    pub fn get(&self, view: View) -> Option<Certificate<S, D>> {
        if let Some(floor) = &self.floor {
            if view <= floor.view() {
                return Some(floor.clone());
            }
        }

        let start = view.term_start(self.term_length);
        self.nullifications
            .range(start..=view)
            .next_back()
            .map(|(_, n)| Certificate::Nullification(n.clone()))
    }

    /// Updates the current view if the new view is greater.
    ///
    /// Returns true if the view is "interesting" (i.e. greater than the floor).
    fn encounter_view(&mut self, view: View) -> bool {
        self.current_view = self.current_view.max(view);
        view > self.floor_view()
    }

    /// Updates the current view and returns true if this nullification can still cover
    /// unresolved views. A nullification at or below the floor can remain useful when the
    /// floor is inside the same term.
    fn encounter_nullification(&mut self, view: View) -> bool {
        self.current_view = self.current_view.max(view);
        view.term_end(self.term_length) > self.floor_view()
    }

    /// Get the view of the floor.
    fn floor_view(&self) -> View {
        self.floor
            .as_ref()
            .map(|floor| floor.view())
            .unwrap_or(View::zero())
    }

    /// Returns true if the floor can be upgraded at the given view.
    fn can_upgrade_floor(&self, view: View) -> bool {
        matches!(
            self.floor.as_ref(),
            Some(Certificate::Notarization(n)) if n.view() == view
        )
    }

    /// Return requests for any missing nullifications.
    fn fetch(&mut self, cause: View, reason: FetchReason) -> Vec<Effect> {
        let mut effects = Vec::with_capacity(self.fetch_concurrent);
        let mut cursor = self.floor_view().next();
        while cursor < self.current_view && effects.len() < self.fetch_concurrent {
            let term_start = cursor.term_start(self.term_length);
            if self
                .nullifications
                .range(term_start..=cursor)
                .next_back()
                .is_none()
            {
                effects.push(Effect::Fetch {
                    view: cursor,
                    cause,
                    reason,
                });
            }
            cursor = cursor.next_term_start(self.term_length);
        }
        effects
    }

    /// Prune stored certificates and requests that are not higher than the floor.
    fn prune(&mut self) -> Effect {
        let floor = self.floor_view();
        self.notarizations.retain(|view, _| *view > floor);
        self.nullifications
            .retain(|view, _| view.term_end(self.term_length) > floor);
        self.satisfied_by.retain(|view, _| *view > floor);
        self.failed_views.retain(|view| *view > floor);
        Effect::RetainAbove(floor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            scheme::ed25519,
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
            },
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_utils::{test_rng, NZU64, NZUsize};

    const NAMESPACE: &[u8] = b"resolver-state";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;

    fn ed25519_fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = test_rng();
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, NAMESPACE, 5);
        (schemes, verifier)
    }

    fn build_nullification(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> Nullification<TestScheme> {
        let round = Round::new(EPOCH, view);
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).unwrap())
            .collect();
        Nullification::from_nullifies(verifier, &votes, &Sequential).expect("nullification quorum")
    }

    fn build_notarization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> Notarization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(EPOCH, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(verifier, &votes, &Sequential).expect("notarization quorum")
    }

    fn build_finalization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(EPOCH, view),
            view.previous().unwrap_or(View::zero()),
            Sha256Digest::from([view.get() as u8; 32]),
        );
        let votes: Vec<_> = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(verifier, &votes, &Sequential).expect("finalization quorum")
    }

    fn fetch(view: u64, cause: u64, reason: FetchReason) -> Effect {
        Effect::Fetch {
            view: View::new(view),
            cause: View::new(cause),
            reason,
        }
    }

    fn retain_outside(start: u64, end: u64) -> Effect {
        Effect::RetainOutside {
            start: View::new(start),
            end: View::new(end),
        }
    }

    fn apply_effects(outstanding: &mut BTreeSet<View>, effects: &[Effect]) {
        for effect in effects {
            match *effect {
                Effect::Fetch { view, .. } => {
                    outstanding.insert(view);
                }
                Effect::Remove(view) => {
                    outstanding.remove(&view);
                }
                Effect::RetainOutside { start, end } => {
                    outstanding.retain(|view| *view < start || *view > end);
                }
                Effect::RetainAbove(floor) => {
                    outstanding.retain(|view| *view > floor);
                }
            }
        }
    }

    fn outstanding(views: &BTreeSet<View>) -> Vec<u64> {
        views.iter().map(|view| view.get()).collect()
    }

    #[test]
    fn handle_nullification_requests_missing_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(2), TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        let effects = state.handle(Certificate::Nullification(nullification_v4.clone()), None);
        assert_eq!(effects[0], retain_outside(4, 4));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert_eq!(outstanding(&outstanding), vec![1, 2]);

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        let effects = state.handle(Certificate::Nullification(nullification_v2.clone()), None);
        assert_eq!(effects[0], retain_outside(2, 2));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert_eq!(outstanding(&outstanding), vec![1, 3]);

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        let effects = state.handle(Certificate::Nullification(nullification_v1.clone()), None);
        assert_eq!(effects[0], retain_outside(1, 1));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Nullification(n)) if n == nullification_v1)
        );
        assert_eq!(outstanding(&outstanding), vec![3]);
    }

    #[test]
    fn fetch_requests_only_term_anchor_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU64!(5)));
        let mut outstanding = BTreeSet::new();

        let nullification_v14 = build_nullification(&schemes, &verifier, View::new(14));
        let effects = state.handle(Certificate::Nullification(nullification_v14), None);
        assert_eq!(
            effects,
            vec![
                retain_outside(14, 15),
                fetch(1, 14, FetchReason::MissingNullification),
                fetch(6, 14, FetchReason::MissingNullification),
                fetch(11, 14, FetchReason::MissingNullification),
            ]
        );
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding(&outstanding), vec![1, 6, 11]);

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        let effects = state.handle(Certificate::Nullification(nullification_v1), None);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding(&outstanding), vec![6, 11]);

        let nullification_v6 = build_nullification(&schemes, &verifier, View::new(6));
        let effects = state.handle(Certificate::Nullification(nullification_v6), None);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding(&outstanding), vec![11]);
    }

    #[test]
    fn same_term_nullification_serves_later_views_until_pruned() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU64!(5)));

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state.handle(Certificate::Nullification(nullification_v2.clone()), None);

        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert!(
            matches!(state.get(View::new(5)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert!(state.get(View::new(6)).is_none());

        let finalization_v3 = build_finalization(&schemes, &verifier, View::new(3));
        state.handle(Certificate::Finalization(finalization_v3), None);
        assert_eq!(state.nullifications.len(), 1);
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );

        let finalization_v5 = build_finalization(&schemes, &verifier, View::new(5));
        state.handle(Certificate::Finalization(finalization_v5), None);
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn nullification_below_floor_can_cover_unresolved_term_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU64!(5)));
        let mut outstanding = BTreeSet::new();

        let finalization_v3 = build_finalization(&schemes, &verifier, View::new(3));
        let effects = state.handle(Certificate::Finalization(finalization_v3), None);
        apply_effects(&mut outstanding, &effects);

        let nullification_v6 = build_nullification(&schemes, &verifier, View::new(6));
        let effects = state.handle(Certificate::Nullification(nullification_v6), None);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding(&outstanding), vec![4]);

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        let effects = state.handle(Certificate::Nullification(nullification_v2.clone()), None);
        apply_effects(&mut outstanding, &effects);

        assert!(outstanding.is_empty());
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert!(
            matches!(state.get(View::new(5)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
    }

    #[test]
    fn floor_prunes_outstanding_requests() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, View::new(view));
            let effects = state.handle(Certificate::Nullification(nullification), None);
            apply_effects(&mut outstanding, &effects);
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(outstanding(&outstanding), vec![1, 2, 3]);

        let notarization = build_notarization(&schemes, &verifier, View::new(6));
        let effects = state.handle(Certificate::Notarization(notarization), None);
        apply_effects(&mut outstanding, &effects);
        assert!(state.floor.is_none());
        assert_eq!(state.nullifications.len(), 3);
        assert_eq!(outstanding(&outstanding), vec![1, 2, 3]);

        let finalization = build_finalization(&schemes, &verifier, View::new(6));
        let effects = state.handle(Certificate::Finalization(finalization.clone()), None);
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(6))]);
        apply_effects(&mut outstanding, &effects);
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(state.notarizations.is_empty());
        assert!(state.nullifications.is_empty());
        assert!(outstanding.is_empty());
    }

    #[test]
    fn produce_returns_floor_or_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(2), TermLength::ONE);

        let finalization = build_finalization(&schemes, &verifier, View::new(3));
        let effects = state.handle(Certificate::Finalization(finalization.clone()), None);
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(3))]);
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == finalization)
        );

        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        let effects = state.handle(Certificate::Nullification(nullification_v4.clone()), None);
        assert_eq!(effects, vec![retain_outside(4, 4)]);
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == finalization)
        );

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        let effects = state.handle(Certificate::Nullification(nullification_v1), None);
        assert!(effects.is_empty());
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
    }

    #[test]
    fn certification_failure_re_requests_satisfied_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::ONE);

        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        let effects = state.handle(
            Certificate::Notarization(notarization_v5),
            Some(View::new(2)),
        );
        assert_eq!(
            effects,
            vec![
                fetch(1, 5, FetchReason::MissingNullification),
                fetch(2, 5, FetchReason::MissingNullification),
                fetch(3, 5, FetchReason::MissingNullification),
                fetch(4, 5, FetchReason::MissingNullification),
            ]
        );

        assert!(state.satisfied_by.contains_key(&View::new(5)));
        assert!(state.satisfied_by[&View::new(5)].contains(&View::new(2)));
        assert!(!state.is_failed(View::new(5)));

        let effects = state.handle_certified(View::new(5), false);

        assert!(state.is_failed(View::new(5)));
        assert!(!state.satisfied_by.contains_key(&View::new(5)));
        assert_eq!(
            effects,
            vec![
                fetch(5, 5, FetchReason::CertificationFailed),
                fetch(2, 5, FetchReason::SatisfiedByFailedNotarization),
            ]
        );
    }

    #[test]
    fn certification_success_clears_tracking() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::ONE);

        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        let effects = state.handle(
            Certificate::Notarization(notarization_v5.clone()),
            Some(View::new(2)),
        );
        assert_eq!(
            effects,
            vec![
                fetch(1, 5, FetchReason::MissingNullification),
                fetch(2, 5, FetchReason::MissingNullification),
                fetch(3, 5, FetchReason::MissingNullification),
                fetch(4, 5, FetchReason::MissingNullification),
            ]
        );
        assert!(state.satisfied_by.contains_key(&View::new(5)));

        let effects = state.handle_certified(View::new(5), true);

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);
        assert!(!state.satisfied_by.contains_key(&View::new(5)));
        assert!(!state.is_failed(View::new(5)));
    }

    #[test]
    fn certification_success_refills_next_term_anchor_window() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(1), TermLength::new(NZU64!(5)));
        let mut outstanding = BTreeSet::new();

        let nullification_v14 = build_nullification(&schemes, &verifier, View::new(14));
        let effects = state.handle(Certificate::Nullification(nullification_v14), None);
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding(&outstanding), vec![1]);

        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        let effects = state.handle(
            Certificate::Notarization(notarization_v5.clone()),
            Some(View::new(1)),
        );
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding(&outstanding), vec![1]);

        let effects = state.handle_certified(View::new(5), true);
        apply_effects(&mut outstanding, &effects);

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(state.current_view, View::new(14));
        assert_eq!(outstanding(&outstanding), vec![6]);
    }

    #[test]
    fn finalization_upgrades_certified_notarization_at_same_view() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::ONE);

        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        let effects = state.handle(Certificate::Notarization(notarization_v5.clone()), None);
        assert_eq!(
            effects,
            vec![
                fetch(1, 5, FetchReason::MissingNullification),
                fetch(2, 5, FetchReason::MissingNullification),
                fetch(3, 5, FetchReason::MissingNullification),
                fetch(4, 5, FetchReason::MissingNullification),
            ]
        );
        let effects = state.handle_certified(View::new(5), true);
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(state.floor_view(), View::new(5));

        let finalization_v5 = build_finalization(&schemes, &verifier, View::new(5));
        let effects = state.handle(Certificate::Finalization(finalization_v5.clone()), None);

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization_v5)
        );
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);
    }
}
