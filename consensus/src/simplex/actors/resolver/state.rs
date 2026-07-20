use crate::{
    Viewable,
    simplex::types::{Certificate, Notarization},
    types::{TermLength, View},
};
use commonware_cryptography::{Digest, certificate::Scheme};
use core::num::NonZeroUsize;
use std::collections::{BTreeMap, HashSet};

/// Why a resolver fetch was requested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FetchReason {
    MissingNullification,
    CertificationFailed,
}

impl FetchReason {
    /// Returns the stable trace field value for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingNullification => "missing_nullification",
            Self::CertificationFailed => "certification_failed",
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
    /// Retain only subscribers outside this inclusive view range.
    ///
    /// A nullification at `start` covers every pending request through `end`,
    /// so those subscribers no longer need an individual certificate response.
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
    nullifications: BTreeMap<View, Certificate<S, D>>,
    /// Window of requests to send to the resolver.
    fetch_concurrent: usize,
    /// Lowest anchor that fetch scans still need to consider (see
    /// [Self::fetch_missing]). Anchors below this cursor have already been
    /// requested or are covered by a stored nullification. A floor raise
    /// landing mid-term pulls it back to just above the floor (see
    /// [Self::prune]).
    fetch_floor: View,
    /// Number of views in each leader term.
    term_length: TermLength,
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
            fetch_floor: View::zero(),
            term_length,
            failed_views: HashSet::new(),
        }
    }

    /// Returns true if the given view has failed certification.
    pub fn is_failed(&self, view: View) -> bool {
        self.failed_views.contains(&view)
    }

    /// Returns the term length this state was built with.
    pub const fn term_length(&self) -> TermLength {
        self.term_length
    }

    /// Handle a new certificate and return any effects the resolver actor should apply.
    pub fn handle(&mut self, certificate: Certificate<S, D>) -> Vec<Effect> {
        let cause = certificate.view();
        self.current_view = self.current_view.max(cause);
        let mut effects = Vec::new();
        match certificate {
            Certificate::Nullification(nullification) => {
                let view = nullification.view();
                if covers_above_floor(view, self.term_length, self.floor_view()) {
                    self.nullifications
                        .insert(view, Certificate::Nullification(nullification));
                    effects.push(Effect::RetainOutside {
                        start: view,
                        end: view.term_end(self.term_length),
                    });
                }
            }
            Certificate::Notarization(notarization) => {
                let view = notarization.view();
                if view > self.floor_view() {
                    self.notarizations.insert(view, notarization);
                }
            }
            Certificate::Finalization(finalization) => {
                let view = finalization.view();
                if view > self.floor_view() || self.can_upgrade_floor(view) {
                    self.floor = Some(Certificate::Finalization(finalization));
                    effects.push(self.prune());
                }
            }
        }

        effects.extend(self.fetch_missing(cause));
        effects
    }

    /// Handle a certification result from the voter.
    pub fn handle_certified(&mut self, view: View, success: bool) -> Vec<Effect> {
        let mut effects = Vec::new();
        if success {
            // Certification passed: raise the floor to the notarization if we
            // still hold it. This may occur before or after a nullification
            // for the same view (and should always be favored). Finalization
            // remains the stronger proof and can later supersede this floor
            // at the same or higher view.
            if let Some(notarization) = self.notarizations.remove(&view)
                && view > self.floor_view()
            {
                self.floor = Some(Certificate::Notarization(notarization));
                effects.push(self.prune());
            }

            // Re-scan for missing nullifications: a floor raise landing
            // mid-term pulls the fetch cursor back (see [Self::prune]), and a
            // previously truncated scan can resume.
            effects.extend(self.fetch_missing(view));
        } else {
            self.notarizations.remove(&view);
            self.failed_views.insert(view);

            // Request a nullification for this view (if not already covered).
            // The views the failed notarization was fetched for are not
            // re-requested: the actor answers their responses with the
            // certification verdict, so the resolver engine retries those
            // requests itself.
            if self.needs_nullification(view) {
                effects.push(Effect::Fetch {
                    view,
                    cause: view,
                    reason: FetchReason::CertificationFailed,
                });
            }
        }
        effects
    }

    /// Get the best certificate for a given view (or the floor
    /// if the view is below the floor).
    pub fn get(&self, view: View) -> Option<&Certificate<S, D>> {
        // If view is <= floor, return the floor
        if let Some(floor) = &self.floor
            && view <= floor.view()
        {
            return Some(floor);
        }

        // Otherwise, return the nullification covering the view if it exists.
        self.covering_nullification(view)
    }

    /// Returns the stored nullification covering `view`, if any.
    ///
    /// Since a nullification covers the rest of its term, it may be keyed at
    /// an earlier view in `view`'s term.
    fn covering_nullification(&self, view: View) -> Option<&Certificate<S, D>> {
        self.nullifications
            .range(view.covering_range(self.term_length))
            .next_back()
            .map(|(_, n)| n)
    }

    /// Get the view of the floor.
    fn floor_view(&self) -> View {
        self.floor
            .as_ref()
            .map(|floor| floor.view())
            .unwrap_or(View::zero())
    }

    /// Returns whether `view` still needs a covering nullification to make
    /// progress: it is above the floor and no stored nullification covers it.
    fn needs_nullification(&self, view: View) -> bool {
        view > self.floor_view() && self.covering_nullification(view).is_none()
    }

    /// Returns true if the floor can be upgraded at the given view.
    fn can_upgrade_floor(&self, view: View) -> bool {
        matches!(
            self.floor.as_ref(),
            Some(Certificate::Notarization(n)) if n.view() == view
        )
    }

    /// Return requests for any missing nullifications.
    ///
    /// Scans from the cursor (never below the floor), requesting each term's
    /// anchor and advancing the cursor past everything scanned. Requests
    /// stay pending in the resolver until answered or retained out (we must
    /// eventually receive a nullification at the anchor or a
    /// notarization/finalization at a higher view). See the
    /// [module docs](super) for the full strategy, including how mid-term
    /// floor raises pull the cursor back.
    fn fetch_missing(&mut self, cause: View) -> Vec<Effect> {
        let mut effects = Vec::with_capacity(self.fetch_concurrent);
        let mut cursor = self.fetch_floor.max(self.floor_view().next());
        while cursor < self.current_view && effects.len() < self.fetch_concurrent {
            if self.covering_nullification(cursor).is_none() {
                effects.push(Effect::Fetch {
                    view: cursor,
                    cause,
                    reason: FetchReason::MissingNullification,
                });
            }
            cursor = cursor.next_term_start(self.term_length);
        }
        self.fetch_floor = cursor;
        effects
    }

    /// Prune stored certificates and requests that are not higher than the floor.
    fn prune(&mut self) -> Effect {
        let floor = self.floor_view();
        self.notarizations.retain(|view, _| *view > floor);
        let term_length = self.term_length;
        self.nullifications
            .retain(|view, _| covers_above_floor(*view, term_length, floor));
        self.failed_views.retain(|view| *view > floor);

        // A floor inside a partially-fetched term strands the term's tail
        // (see the module docs). Pull the cursor back to just above the
        // floor so a later scan re-requests the tail (the cursor may exceed
        // the current view here, so an eager fetch could not).
        let next = floor.next();
        if !next.is_term_start(self.term_length) {
            self.fetch_floor = self.fetch_floor.min(next);
        }
        Effect::RetainAbove(floor)
    }
}

/// Returns whether a nullification at `view` covers any view above `floor`.
///
/// A nullification covers the rest of its term, so it remains relevant while
/// its term end is above the floor (even when the nullification itself is at
/// or below the floor). Admission (`handle`) and retention (`prune`) must
/// agree on this boundary.
fn covers_above_floor(view: View, term_length: TermLength, floor: View) -> bool {
    view.term_end(term_length) > floor
}

#[cfg(test)]
mod tests {
    use super::{super::test_helpers::*, *};
    use crate::{simplex::scheme::ed25519, types::Epoch};
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_utils::{NZU32, NZUsize, test_rng};
    use std::collections::BTreeSet;

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
                Effect::RetainOutside { start, end } => {
                    outstanding.retain(|view| *view < start || *view > end);
                }
                Effect::RetainAbove(floor) => {
                    outstanding.retain(|view| *view > floor);
                }
            }
        }
    }

    fn outstanding_views(views: &BTreeSet<View>) -> Vec<u64> {
        views.iter().map(|view| view.get()).collect()
    }

    #[test]
    fn handle_nullification_requests_missing_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(2), TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        let nullification_v4 = build_nullification(&schemes, &verifier, EPOCH, View::new(4));
        let effects = state.handle(Certificate::Nullification(nullification_v4.clone()));
        assert_eq!(effects[0], retain_outside(4, 4));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        assert_eq!(outstanding_views(&outstanding), vec![1, 2]);

        let nullification_v2 = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
        let effects = state.handle(Certificate::Nullification(nullification_v2.clone()));
        assert_eq!(effects[0], retain_outside(2, 2));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
        assert_eq!(outstanding_views(&outstanding), vec![1, 3]);

        let nullification_v1 = build_nullification(&schemes, &verifier, EPOCH, View::new(1));
        let effects = state.handle(Certificate::Nullification(nullification_v1.clone()));
        assert_eq!(effects[0], retain_outside(1, 1));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Nullification(n)) if n == &nullification_v1)
        );
        assert_eq!(outstanding_views(&outstanding), vec![3]);
    }

    #[test]
    fn fetch_requests_only_term_anchor_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let nullification_v14 = build_nullification(&schemes, &verifier, EPOCH, View::new(14));
        let effects = state.handle(Certificate::Nullification(nullification_v14));
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
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        let nullification_v1 = build_nullification(&schemes, &verifier, EPOCH, View::new(1));
        let effects = state.handle(Certificate::Nullification(nullification_v1));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![6, 11]);

        let nullification_v6 = build_nullification(&schemes, &verifier, EPOCH, View::new(6));
        let effects = state.handle(Certificate::Nullification(nullification_v6));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![11]);
    }

    #[test]
    fn same_term_nullification_serves_later_views_until_pruned() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));

        let nullification_v2 = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
        state.handle(Certificate::Nullification(nullification_v2.clone()));

        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
        assert!(
            matches!(state.get(View::new(5)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
        assert!(state.get(View::new(6)).is_none());

        let finalization_v3 = build_finalization(&schemes, &verifier, EPOCH, View::new(3));
        state.handle(Certificate::Finalization(finalization_v3));
        assert_eq!(state.nullifications.len(), 1);
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );

        let finalization_v5 = build_finalization(&schemes, &verifier, EPOCH, View::new(5));
        state.handle(Certificate::Finalization(finalization_v5));
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn nullification_below_floor_can_cover_unresolved_term_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let finalization_v3 = build_finalization(&schemes, &verifier, EPOCH, View::new(3));
        let effects = state.handle(Certificate::Finalization(finalization_v3));
        apply_effects(&mut outstanding, &effects);

        let nullification_v6 = build_nullification(&schemes, &verifier, EPOCH, View::new(6));
        let effects = state.handle(Certificate::Nullification(nullification_v6));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![4]);

        let nullification_v2 = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
        let effects = state.handle(Certificate::Nullification(nullification_v2.clone()));
        apply_effects(&mut outstanding, &effects);

        assert!(outstanding.is_empty());
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
        assert!(
            matches!(state.get(View::new(5)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
    }

    #[test]
    fn nullification_admission_matches_pruning_boundary() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));

        let finalization_v3 = build_finalization(&schemes, &verifier, EPOCH, View::new(3));
        let effects = state.handle(Certificate::Finalization(finalization_v3));
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(3))]);

        let nullification_v2 = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
        let effects = state.handle(Certificate::Nullification(nullification_v2.clone()));
        assert_eq!(effects, vec![retain_outside(2, 5)]);
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );

        let finalization_v5 = build_finalization(&schemes, &verifier, EPOCH, View::new(5));
        let effects = state.handle(Certificate::Finalization(finalization_v5));
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);
        assert!(state.nullifications.is_empty());

        let effects = state.handle(Certificate::Nullification(nullification_v2));
        assert!(effects.is_empty());
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn floor_prunes_outstanding_requests() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10), TermLength::ONE);
        let mut outstanding = BTreeSet::new();

        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(view));
            let effects = state.handle(Certificate::Nullification(nullification));
            apply_effects(&mut outstanding, &effects);
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(outstanding_views(&outstanding), vec![1, 2, 3]);

        let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(6));
        let effects = state.handle(Certificate::Notarization(notarization));
        apply_effects(&mut outstanding, &effects);
        assert!(state.floor.is_none());
        assert_eq!(state.nullifications.len(), 3);
        assert_eq!(outstanding_views(&outstanding), vec![1, 2, 3]);

        let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(6));
        let effects = state.handle(Certificate::Finalization(finalization.clone()));
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

        let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(3));
        let effects = state.handle(Certificate::Finalization(finalization.clone()));
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(3))]);
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        let nullification_v4 = build_nullification(&schemes, &verifier, EPOCH, View::new(4));
        let effects = state.handle(Certificate::Nullification(nullification_v4.clone()));
        assert_eq!(effects, vec![retain_outside(4, 4)]);
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        let nullification_v1 = build_nullification(&schemes, &verifier, EPOCH, View::new(1));
        let effects = state.handle(Certificate::Nullification(nullification_v1));
        assert!(effects.is_empty());
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
    }

    #[test]
    fn certification_failure_re_requests_failed_view() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10), TermLength::ONE);

        // Handling a notarization requests the missing nullifications below it
        let notarization_v5 = build_notarization(&schemes, &verifier, EPOCH, View::new(5));
        let effects = state.handle(Certificate::Notarization(notarization_v5));
        assert_eq!(
            effects,
            vec![
                fetch(1, 5, FetchReason::MissingNullification),
                fetch(2, 5, FetchReason::MissingNullification),
                fetch(3, 5, FetchReason::MissingNullification),
                fetch(4, 5, FetchReason::MissingNullification),
            ]
        );
        assert!(!state.is_failed(View::new(5)));

        // Certification fails for view 5
        let effects = state.handle_certified(View::new(5), false);

        // View 5 is marked failed and only the failed view is re-requested: the
        // requests its notarization answered are retried by the resolver engine
        assert!(state.is_failed(View::new(5)));
        assert_eq!(effects, vec![fetch(5, 5, FetchReason::CertificationFailed)]);
    }

    #[test]
    fn certification_success_sets_floor() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10), TermLength::ONE);

        // Handling a notarization requests the missing nullifications below it
        let notarization_v5 = build_notarization(&schemes, &verifier, EPOCH, View::new(5));
        let effects = state.handle(Certificate::Notarization(notarization_v5.clone()));
        assert_eq!(
            effects,
            vec![
                fetch(1, 5, FetchReason::MissingNullification),
                fetch(2, 5, FetchReason::MissingNullification),
                fetch(3, 5, FetchReason::MissingNullification),
                fetch(4, 5, FetchReason::MissingNullification),
            ]
        );

        // Certification succeeds for view 5
        let effects = state.handle_certified(View::new(5), true);

        // The certified notarization becomes the floor and view 5 is not marked failed
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);
        assert!(!state.is_failed(View::new(5)));
    }

    #[test]
    fn certification_success_refills_next_term_anchor_window() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(1), TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let nullification_v14 = build_nullification(&schemes, &verifier, EPOCH, View::new(14));
        let effects = state.handle(Certificate::Nullification(nullification_v14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1]);

        // The notarization answers the request for anchor 1, so the fetch
        // cursor advances to the next missing anchor instead of re-requesting.
        let notarization_v5 = build_notarization(&schemes, &verifier, EPOCH, View::new(5));
        let effects = state.handle(Certificate::Notarization(notarization_v5.clone()));
        assert_eq!(
            effects,
            vec![fetch(6, 5, FetchReason::MissingNullification)]
        );
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6]);

        // Certification raises the floor past anchor 1 and refills the window.
        let effects = state.handle_certified(View::new(5), true);
        apply_effects(&mut outstanding, &effects);

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(state.current_view, View::new(14));
        assert_eq!(outstanding_views(&outstanding), vec![6, 11]);
    }

    #[test]
    fn certification_success_at_mid_term_floor_refetches_term_tail() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        let nullification_v14 = build_nullification(&schemes, &verifier, EPOCH, View::new(14));
        let effects = state.handle(Certificate::Nullification(nullification_v14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // A mid-term notarization answers the request for anchor 1, but once
        // certified it only covers views 1..=3 of term [1, 5].
        let notarization_v3 = build_notarization(&schemes, &verifier, EPOCH, View::new(3));
        let effects = state.handle(Certificate::Notarization(notarization_v3.clone()));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1, 6, 11]);

        // Certification raises the floor to 3 and prunes the anchor-1 request.
        // Views 4-5 still need a covering nullification, which only a request
        // at a view in [4, 5] can retrieve (the outstanding requests at 6 and
        // 11 accept nothing from term [1, 5]), so the fetch scan must resume
        // from just above the mid-term floor rather than from the cursor.
        let effects = state.handle_certified(View::new(3), true);
        apply_effects(&mut outstanding, &effects);
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v3)
        );
        assert_eq!(outstanding_views(&outstanding), vec![4, 6, 11]);
    }

    #[test]
    fn mid_term_floor_at_current_view_refetches_term_tail_later() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));
        let mut outstanding = BTreeSet::new();

        // A gossiped notarization at view 4 is the highest view seen: the
        // fetch scan requests anchor 1, and the cursor jumps past the
        // current view to the next term anchor.
        let notarization_v4 = build_notarization(&schemes, &verifier, EPOCH, View::new(4));
        let effects = state.handle(Certificate::Notarization(notarization_v4.clone()));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![1]);

        // Certification raises the floor to 4 (the current view itself),
        // mid-term of [1, 5]. The anchor-1 request is pruned and no view
        // above the floor is below the current view yet, so nothing can be
        // fetched here.
        let effects = state.handle_certified(View::new(4), true);
        apply_effects(&mut outstanding, &effects);
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v4)
        );
        assert!(outstanding_views(&outstanding).is_empty());

        // Once the current view grows, the scan must resume from just above
        // the mid-term floor: view 5 is only coverable by a nullification
        // from term [1, 5], which the requests at anchors 6 and 11 reject.
        let nullification_v14 = build_nullification(&schemes, &verifier, EPOCH, View::new(14));
        let effects = state.handle(Certificate::Nullification(nullification_v14));
        apply_effects(&mut outstanding, &effects);
        assert_eq!(outstanding_views(&outstanding), vec![5, 6, 11]);
    }

    #[test]
    fn fetch_requests_each_anchor_once() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));

        let nullification_v14 = build_nullification(&schemes, &verifier, EPOCH, View::new(14));
        let effects = state.handle(Certificate::Nullification(nullification_v14));
        assert_eq!(
            effects,
            vec![
                retain_outside(14, 15),
                fetch(1, 14, FetchReason::MissingNullification),
                fetch(6, 14, FetchReason::MissingNullification),
                fetch(11, 14, FetchReason::MissingNullification),
            ]
        );

        // A notarization satisfying the request for anchor 1 must not trigger
        // a re-request of anchor 1 while its certification is pending, no
        // matter how many times it is delivered.
        let notarization_v5 = build_notarization(&schemes, &verifier, EPOCH, View::new(5));
        for _ in 0..3 {
            let effects = state.handle(Certificate::Notarization(notarization_v5.clone()));
            assert!(effects.is_empty(), "anchor re-requested: {effects:?}");
        }

        // A later certificate must only request newly-uncovered anchors, not
        // re-issue the outstanding ones (the p2p resolver owns retries).
        let nullification_v20 = build_nullification(&schemes, &verifier, EPOCH, View::new(20));
        let effects = state.handle(Certificate::Nullification(nullification_v20));
        assert_eq!(
            effects,
            vec![
                retain_outside(20, 20),
                fetch(16, 20, FetchReason::MissingNullification),
            ]
        );
    }

    #[test]
    fn certification_failure_skips_covered_re_requests() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> =
            State::new(NZUsize!(10), TermLength::new(NZU32!(5)));

        let nullification_v14 = build_nullification(&schemes, &verifier, EPOCH, View::new(14));
        state.handle(Certificate::Nullification(nullification_v14));

        let notarization_v5 = build_notarization(&schemes, &verifier, EPOCH, View::new(5));
        state.handle(Certificate::Notarization(notarization_v5));

        // A nullification at view 1 covers the whole term [1, 5], so the
        // failed view needs no re-request.
        let nullification_v1 = build_nullification(&schemes, &verifier, EPOCH, View::new(1));
        state.handle(Certificate::Nullification(nullification_v1));

        let effects = state.handle_certified(View::new(5), false);
        assert!(state.is_failed(View::new(5)));
        assert!(effects.is_empty(), "covered view re-requested: {effects:?}");
    }

    #[test]
    fn finalization_upgrades_certified_notarization_at_same_view() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10), TermLength::ONE);

        let notarization_v5 = build_notarization(&schemes, &verifier, EPOCH, View::new(5));
        let effects = state.handle(Certificate::Notarization(notarization_v5.clone()));
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

        let finalization_v5 = build_finalization(&schemes, &verifier, EPOCH, View::new(5));
        let effects = state.handle(Certificate::Finalization(finalization_v5.clone()));

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization_v5)
        );
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);
    }
}
