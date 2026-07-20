use crate::{
    Viewable,
    simplex::types::{Certificate, Notarization},
    types::View,
};
use commonware_cryptography::{Digest, certificate::Scheme};
use std::{
    collections::{BTreeMap, HashSet},
    num::NonZeroUsize,
};

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
    /// Drop all subscribers for this view.
    Remove(View),
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
    /// Nullifications for any view greater than the floor.
    nullifications: BTreeMap<View, Certificate<S, D>>,
    /// Window of requests to send to the resolver.
    fetch_concurrent: usize,
    /// Next view to consider when fetching. Avoids re-scanning
    /// views we've already requested or have nullifications for.
    fetch_floor: View,
    /// Views where certification has failed. Only nullifications
    /// are accepted for these views.
    failed_views: HashSet<View>,
}

impl<S: Scheme, D: Digest> State<S, D> {
    /// Create a new instance of [State].
    pub fn new(fetch_concurrent: NonZeroUsize) -> Self {
        Self {
            current_view: View::zero(),
            floor: None,
            notarizations: BTreeMap::new(),
            nullifications: BTreeMap::new(),
            fetch_concurrent: fetch_concurrent.get(),
            fetch_floor: View::zero(),
            failed_views: HashSet::new(),
        }
    }

    /// Returns true if the given view has failed certification.
    pub fn is_failed(&self, view: View) -> bool {
        self.failed_views.contains(&view)
    }

    /// Handle a new certificate and return any effects the resolver actor should apply.
    pub fn handle(&mut self, certificate: Certificate<S, D>) -> Vec<Effect> {
        let cause = certificate.view();
        let mut effects = Vec::new();
        match certificate {
            Certificate::Nullification(nullification) => {
                let view = nullification.view();
                if self.encounter_view(view) {
                    self.nullifications
                        .insert(view, Certificate::Nullification(nullification));
                    effects.push(Effect::Remove(view));
                }
            }
            Certificate::Notarization(notarization) => {
                // Store as pending (waiting for certification result).
                let view = notarization.view();
                if self.encounter_view(view) {
                    self.notarizations.insert(view, notarization);
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

        // Request missing nullifications
        effects.extend(self.fetch(cause, FetchReason::MissingNullification));
        effects
    }

    /// Handle a certification result from the voter.
    pub fn handle_certified(&mut self, view: View, success: bool) -> Vec<Effect> {
        let mut effects = Vec::new();
        if success {
            // Certification passed - set floor to notarization if we have it.
            //
            // This may occur before or after a nullification for the same view (and should always be favored).
            // Finalization remains the stronger proof and can later supersede this floor at the same or higher view.
            if let Some(notarization) = self.notarizations.remove(&view)
                && view > self.floor_view()
            {
                self.floor = Some(Certificate::Notarization(notarization));
                effects.push(self.prune());
            }
        } else {
            // Discard notarization and mark view as failed (ensures we can penalize
            // malicious peers that hand us useless notarizations)
            self.notarizations.remove(&view);
            self.failed_views.insert(view);

            // Request nullification for this view (if above floor). The views the
            // failed notarization was fetched for are not re-requested: the actor
            // answers their responses with the certification verdict, so the
            // resolver engine retries those requests itself.
            let floor = self.floor_view();
            if view > floor {
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

        // Otherwise, return the nullification for the view if it exists
        self.nullifications.get(&view)
    }

    /// Updates the current view if the new view is greater.
    ///
    /// Returns true if the view is "interesting" (i.e. greater than or equal to the floor).
    fn encounter_view(&mut self, view: View) -> bool {
        self.current_view = self.current_view.max(view);
        view > self.floor_view()
    }

    /// Get the view of the floor.
    fn floor_view(&self) -> View {
        self.floor
            .as_ref()
            .map(|floor| floor.view())
            .unwrap_or(View::zero())
    }

    /// Returns true if the floor can be upgraded at the given view.
    ///
    /// A finalization can upgrade a notarization at the same view since
    /// finalization is a stronger proof than notarization.
    fn can_upgrade_floor(&self, view: View) -> bool {
        matches!(
            self.floor.as_ref(),
            Some(Certificate::Notarization(n)) if n.view() == view
        )
    }

    /// Return requests for any missing nullifications.
    fn fetch(&mut self, cause: View, reason: FetchReason) -> Vec<Effect> {
        // We must either receive a nullification at the current view or a notarization/finalization at the current
        // view or higher, so we don't need to worry about getting stuck (where peers cannot resolve our requests).
        let start = self.fetch_floor.max(self.floor_view().next());
        let views: Vec<_> = View::range(start, self.current_view)
            .filter(|view| !self.nullifications.contains_key(view))
            .take(self.fetch_concurrent)
            .collect();

        // Update the fetch floor to reduce duplicate iteration in the future.
        if let Some(&last) = views.last() {
            self.fetch_floor = last.next();
        }

        views
            .into_iter()
            .map(|view| Effect::Fetch {
                view,
                cause,
                reason,
            })
            .collect()
    }

    /// Prune stored certificates and requests that are not higher than the floor.
    fn prune(&mut self) -> Effect {
        let floor = self.floor_view();
        self.notarizations.retain(|view, _| *view > floor);
        self.nullifications.retain(|view, _| *view > floor);
        self.failed_views.retain(|view| *view > floor);
        Effect::RetainAbove(floor)
    }
}

#[cfg(test)]
mod tests {
    use super::{super::test_helpers::*, *};
    use crate::{simplex::scheme::ed25519, types::Epoch};
    use commonware_cryptography::{certificate::mocks::Fixture, sha256::Digest as Sha256Digest};
    use commonware_utils::{NZUsize, test_rng};

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

    #[test]
    fn handle_nullification_requests_missing_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(2));

        let nullification_v4 = build_nullification(&schemes, &verifier, EPOCH, View::new(4));
        let effects = state.handle(Certificate::Nullification(nullification_v4.clone()));
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        assert_eq!(
            effects,
            vec![
                Effect::Remove(View::new(4)),
                fetch(1, 4, FetchReason::MissingNullification),
                fetch(2, 4, FetchReason::MissingNullification),
            ]
        );

        let nullification_v2 = build_nullification(&schemes, &verifier, EPOCH, View::new(2));
        let effects = state.handle(Certificate::Nullification(nullification_v2.clone()));
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
        assert_eq!(
            effects,
            vec![
                Effect::Remove(View::new(2)),
                fetch(3, 2, FetchReason::MissingNullification),
            ]
        );

        let nullification_v1 = build_nullification(&schemes, &verifier, EPOCH, View::new(1));
        let effects = state.handle(Certificate::Nullification(nullification_v1.clone()));
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Nullification(n)) if n == &nullification_v1)
        );
        assert_eq!(effects, vec![Effect::Remove(View::new(1))]);
    }

    #[test]
    fn floor_prunes_outstanding_requests() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10));

        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, EPOCH, View::new(view));
            let effects = state.handle(Certificate::Nullification(nullification));
            if view == 4 {
                assert_eq!(
                    effects,
                    vec![
                        Effect::Remove(View::new(4)),
                        fetch(1, 4, FetchReason::MissingNullification),
                        fetch(2, 4, FetchReason::MissingNullification),
                        fetch(3, 4, FetchReason::MissingNullification),
                    ]
                );
            } else {
                assert_eq!(effects, vec![Effect::Remove(View::new(view))]);
            }
        }
        assert_eq!(state.current_view, View::new(6));

        // Notarization does not set floor or prune
        let notarization = build_notarization(&schemes, &verifier, EPOCH, View::new(6));
        let effects = state.handle(Certificate::Notarization(notarization));

        assert!(state.floor.is_none());
        assert_eq!(state.nullifications.len(), 3); // nullifications remain
        assert!(effects.is_empty());

        // Finalization sets floor and prunes
        let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(6));
        let effects = state.handle(Certificate::Finalization(finalization.clone()));
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(6))]);
        assert!(state.notarizations.is_empty());
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn produce_returns_floor_or_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(2));

        // Finalization sets floor
        let finalization = build_finalization(&schemes, &verifier, EPOCH, View::new(3));
        let effects = state.handle(Certificate::Finalization(finalization.clone()));
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(3))]);
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        // New nullification is kept
        let nullification_v4 = build_nullification(&schemes, &verifier, EPOCH, View::new(4));
        let effects = state.handle(Certificate::Nullification(nullification_v4.clone()));
        assert_eq!(effects, vec![Effect::Remove(View::new(4))]);
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        // Old nullification is ignored
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
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10));

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
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10));

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
    fn finalization_upgrades_certified_notarization_at_same_view() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZUsize!(10));

        // Create and certify a notarization at view 5
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

        // Floor should be the notarization at view 5
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(state.floor_view(), View::new(5));

        // A finalization at the same view should upgrade the floor
        let finalization_v5 = build_finalization(&schemes, &verifier, EPOCH, View::new(5));
        let effects = state.handle(Certificate::Finalization(finalization_v5.clone()));

        // Floor should now be the finalization (stronger proof)
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization_v5)
        );
        assert_eq!(effects, vec![Effect::RetainAbove(View::new(5))]);
    }
}
