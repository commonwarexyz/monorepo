use crate::{
    simplex::types::{Certificate, Notarization, Nullification},
    types::View,
    Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
use core::num::NonZeroU64;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

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
    term_length: NonZeroU64,
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
    pub fn new(fetch_concurrent: NonZeroU64, term_length: NonZeroU64) -> Self {
        Self {
            current_view: View::zero(),
            floor: None,
            notarizations: BTreeMap::new(),
            nullifications: BTreeMap::new(),
            fetch_concurrent: fetch_concurrent
                .get()
                .try_into()
                .expect("fetch_concurrent must fit in usize"),
            term_length,
            satisfied_by: HashMap::new(),
            failed_views: HashSet::new(),
        }
    }

    /// Returns true if the given view has failed certification.
    pub fn is_failed(&self, view: View) -> bool {
        self.failed_views.contains(&view)
    }

    /// Handle a new certificate and update the [Resolver] accordingly.
    ///
    /// The `request` parameter is the view that was originally requested
    /// when this certificate was fetched. If the certificate is a notarization
    /// at a higher view, we track that the request was "satisfied by" this
    /// notarization so we can re-request on certification failure.
    pub fn handle(
        &mut self,
        certificate: Certificate<S, D>,
        request: Option<View>,
        resolver: &mut impl Resolver<Key = U64>,
    ) {
        match certificate {
            Certificate::Nullification(nullification) => {
                let view = nullification.view();
                if self.encounter_nullification(view) {
                    self.nullifications.insert(view, nullification);
                    // The view and the rest of the term are considered nullified.
                    // Retain requests for views outside of this range.
                    let end = view.term_end(self.term_length);
                    let start: U64 = view.into();
                    let end: U64 = end.into();
                    let predicate = move |v: &U64| !(v >= &start && v <= &end);
                    resolver.retain(predicate);
                }
            }
            Certificate::Notarization(notarization) => {
                // Store as pending (waiting for certification result).
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
                    self.prune(resolver);
                }
            }
        }

        // Request missing nullifications
        self.fetch(resolver);
    }

    /// Handle a certification result from the voter.
    pub fn handle_certified(
        &mut self,
        view: View,
        success: bool,
        resolver: &mut impl Resolver<Key = U64>,
    ) {
        if success {
            // Certification passed - set floor to notarization if we have it.
            //
            // This may occur before or after a nullification for the same view (and should always be favored).
            // Finalization remains the stronger proof and can later supersede this floor at the same or higher view.
            if let Some(notarization) = self.notarizations.remove(&view) {
                if view > self.floor_view() {
                    self.floor = Some(Certificate::Notarization(notarization));
                    self.prune(resolver);
                }
            }

            // Clean up satisfaction tracking
            self.satisfied_by.remove(&view);

            // Advancing the floor can expose the next missing term anchor.
            self.fetch(resolver);
        } else {
            // Discard notarization and mark view as failed (ensures we can penalize
            // malicious peers that hand us useless notarizations)
            self.notarizations.remove(&view);
            self.failed_views.insert(view);

            // Request nullification for this view (if above floor)
            let floor = self.floor_view();
            if view > floor {
                resolver.fetch(view.into());
            }

            // Re-request any lower views this notarization had satisfied
            if let Some(satisfied_views) = self.satisfied_by.remove(&view) {
                for &v in satisfied_views.iter().filter(|v| **v > floor) {
                    resolver.fetch(v.into());
                }
            }
        }
    }

    /// Get the best certificate for a given view (or the floor
    /// if the view is below the floor).
    pub fn get(&self, view: View) -> Option<Certificate<S, D>> {
        // If view is <= floor, return the floor
        if let Some(floor) = &self.floor {
            if view <= floor.view() {
                return Some(floor.clone());
            }
        }

        // Otherwise, return the nullification for the view if it exists.
        // Since nullifications cover the rest of the term,
        // a nullification covering `view` may exist keyed in a previous view earlier in the term.
        let start = view.term_start(self.term_length);
        self.nullifications
            .range(start..=view)
            .next_back()
            .map(|(_, n)| Certificate::Nullification(n.clone()))
    }

    /// Updates the current view if the new view is greater.
    ///
    /// Returns true if the view is "interesting" (i.e. greater than or equal to the floor).
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
    ///
    /// A finalization can upgrade a notarization at the same view since
    /// finalization is a stronger proof than notarization.
    fn can_upgrade_floor(&self, view: View) -> bool {
        matches!(
            self.floor.as_ref(),
            Some(Certificate::Notarization(n)) if n.view() == view
        )
    }

    /// Inform the [Resolver] of any missing nullifications.
    fn fetch(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        // Check each required term anchor directly. Unlike `get`, advancing
        // the floor needs the exact nullifications for those boundaries.
        let mut requests = Vec::with_capacity(self.fetch_concurrent);
        let mut cursor = self.floor_view().next();
        while cursor < self.current_view && requests.len() < self.fetch_concurrent {
            // If the cursor does not have a nullification at the view (or earlier in the term),
            // add it to the requests.
            let term_start = cursor.term_start(self.term_length);
            if self
                .nullifications
                .range(term_start..=cursor)
                .next_back()
                .is_none()
            {
                requests.push(cursor);
            }
            cursor = cursor.next_term_start(self.term_length);
        }

        // Send the requests to the resolver.
        let requests: Vec<U64> = requests.into_iter().map(U64::from).collect();
        resolver.fetch_all(requests);
    }

    /// Prune stored certificates and requests that are not higher than the floor.
    fn prune(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        let floor = self.floor_view();
        self.notarizations.retain(|view, _| *view > floor);
        // Nullifications cover the rest of the term.
        // Don't prune them until the term end is below the floor.
        self.nullifications
            .retain(|view, _| view.term_end(self.term_length) > floor);
        self.satisfied_by.retain(|view, _| *view > floor);
        self.failed_views.retain(|view| *view > floor);
        resolver.retain(move |key| *key > floor.into());
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
    use commonware_actor::Feedback;
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest,
    };
    use commonware_parallel::Sequential;
    use commonware_utils::{sync::Mutex, test_rng, vec::NonEmptyVec, NZU64};
    use std::{collections::BTreeSet, sync::Arc};

    const NAMESPACE: &[u8] = b"resolver-state";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed25519::Scheme;

    #[derive(Clone, Default)]
    struct MockResolver {
        outstanding: Arc<Mutex<BTreeSet<U64>>>,
    }

    impl MockResolver {
        fn outstanding(&self) -> Vec<u64> {
            self.outstanding
                .lock()
                .iter()
                .map(|key| key.into())
                .collect()
        }
    }

    impl Resolver for MockResolver {
        type Key = U64;
        type PublicKey = PublicKey;

        fn fetch(&mut self, key: U64) -> Feedback {
            self.outstanding.lock().insert(key);
            Feedback::Ok
        }

        fn fetch_all(&mut self, keys: Vec<U64>) -> Feedback {
            for key in keys {
                self.outstanding.lock().insert(key);
            }
            Feedback::Ok
        }

        fn fetch_targeted(&mut self, key: U64, _targets: NonEmptyVec<PublicKey>) -> Feedback {
            // For testing, just treat targeted fetch the same as regular fetch
            self.outstanding.lock().insert(key);
            Feedback::Ok
        }

        fn fetch_all_targeted(&mut self, requests: Vec<(U64, NonEmptyVec<PublicKey>)>) -> Feedback {
            // For testing, just treat targeted fetch the same as regular fetch
            for (key, _targets) in requests {
                self.outstanding.lock().insert(key);
            }
            Feedback::Ok
        }

        fn cancel(&mut self, key: U64) -> Feedback {
            self.outstanding.lock().remove(&key);
            Feedback::Ok
        }

        fn clear(&mut self) -> Feedback {
            self.outstanding.lock().clear();
            Feedback::Ok
        }

        fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) -> Feedback {
            self.outstanding.lock().retain(|key| predicate(key));
            Feedback::Ok
        }
    }

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

    #[test]
    fn handle_nullification_requests_missing_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(2), NZU64!(1));
        let mut resolver = MockResolver::default();

        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state.handle(
            Certificate::Nullification(nullification_v4.clone()),
            None,
            &mut resolver,
        );
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert_eq!(resolver.outstanding(), vec![1, 2]); // limited to concurrency

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state.handle(
            Certificate::Nullification(nullification_v2.clone()),
            None,
            &mut resolver,
        );
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert_eq!(resolver.outstanding(), vec![1, 3]); // limited to concurrency

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state.handle(
            Certificate::Nullification(nullification_v1.clone()),
            None,
            &mut resolver,
        );
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Nullification(n)) if n == nullification_v1)
        );
        assert_eq!(resolver.outstanding(), vec![3]);
    }

    #[test]
    fn fetch_requests_only_term_anchor_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(10), NZU64!(5));
        let mut resolver = MockResolver::default();

        // Encountering a certificate at view 14 should request only required anchors
        // from floor=0: 1, 6, and 11.
        let nullification_v14 = build_nullification(&schemes, &verifier, View::new(14));
        state.handle(
            Certificate::Nullification(nullification_v14),
            None,
            &mut resolver,
        );
        assert_eq!(resolver.outstanding(), vec![1, 6, 11]);

        // Once anchor 1 is present, only 6 and 11 remain needed.
        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state.handle(
            Certificate::Nullification(nullification_v1),
            None,
            &mut resolver,
        );
        assert_eq!(resolver.outstanding(), vec![6, 11]);

        // Then only 11 remains.
        let nullification_v6 = build_nullification(&schemes, &verifier, View::new(6));
        state.handle(
            Certificate::Nullification(nullification_v6),
            None,
            &mut resolver,
        );
        assert_eq!(resolver.outstanding(), vec![11]);
    }

    #[test]
    fn same_term_nullification_serves_later_views_until_pruned() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(10), NZU64!(5));
        let mut resolver = MockResolver::default();

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state.handle(
            Certificate::Nullification(nullification_v2.clone()),
            None,
            &mut resolver,
        );

        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert!(
            matches!(state.get(View::new(5)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert!(state.get(View::new(6)).is_none());

        let finalization_v3 = build_finalization(&schemes, &verifier, View::new(3));
        state.handle(
            Certificate::Finalization(finalization_v3),
            None,
            &mut resolver,
        );
        assert_eq!(state.nullifications.len(), 1);
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );

        let finalization_v5 = build_finalization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::Finalization(finalization_v5),
            None,
            &mut resolver,
        );
        assert!(state.nullifications.is_empty());
    }

    #[test]
    fn nullification_below_floor_can_cover_unresolved_term_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(10), NZU64!(5));
        let mut resolver = MockResolver::default();

        let finalization_v3 = build_finalization(&schemes, &verifier, View::new(3));
        state.handle(
            Certificate::Finalization(finalization_v3),
            None,
            &mut resolver,
        );

        let nullification_v6 = build_nullification(&schemes, &verifier, View::new(6));
        state.handle(
            Certificate::Nullification(nullification_v6),
            None,
            &mut resolver,
        );
        assert_eq!(resolver.outstanding(), vec![4]);

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state.handle(
            Certificate::Nullification(nullification_v2.clone()),
            None,
            &mut resolver,
        );

        assert!(resolver.outstanding().is_empty());
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
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(10), NZU64!(1));
        let mut resolver = MockResolver::default();

        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, View::new(view));
            state.handle(
                Certificate::Nullification(nullification),
                None,
                &mut resolver,
            );
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        // Notarization does not set floor or prune
        let notarization = build_notarization(&schemes, &verifier, View::new(6));
        state.handle(Certificate::Notarization(notarization), None, &mut resolver);

        assert!(state.floor.is_none());
        assert_eq!(state.nullifications.len(), 3); // nullifications remain
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]); // requests remain

        // Finalization sets floor and prunes
        let finalization = build_finalization(&schemes, &verifier, View::new(6));
        state.handle(
            Certificate::Finalization(finalization.clone()),
            None,
            &mut resolver,
        );
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization)
        );
    }

    #[test]
    fn produce_returns_floor_or_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(2), NZU64!(1));
        let mut resolver = MockResolver::default();

        // Finalization sets floor
        let finalization = build_finalization(&schemes, &verifier, View::new(3));
        state.handle(
            Certificate::Finalization(finalization.clone()),
            None,
            &mut resolver,
        );
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == finalization)
        );

        // New nullification is kept
        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state.handle(
            Certificate::Nullification(nullification_v4.clone()),
            None,
            &mut resolver,
        );
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == finalization)
        );

        // Old nullification is ignored
        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state.handle(
            Certificate::Nullification(nullification_v1),
            None,
            &mut resolver,
        );
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert!(resolver.outstanding().is_empty());
    }

    #[test]
    fn certification_failure_re_requests_satisfied_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(10), NZU64!(1));
        let mut resolver = MockResolver::default();

        // Notarization at view 5 satisfies request for view 2
        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::Notarization(notarization_v5),
            Some(View::new(2)),
            &mut resolver,
        );

        // Verify tracking
        assert!(state.satisfied_by.contains_key(&View::new(5)));
        assert!(state.satisfied_by[&View::new(5)].contains(&View::new(2)));
        assert!(!state.is_failed(View::new(5)));

        // Certification fails for view 5
        state.handle_certified(View::new(5), false, &mut resolver);

        // View 5 should be marked as failed
        assert!(state.is_failed(View::new(5)));
        // Satisfied_by should be cleaned up
        assert!(!state.satisfied_by.contains_key(&View::new(5)));
        // Both view 5 and view 2 should have requests
        let outstanding = resolver.outstanding();
        assert!(outstanding.contains(&5));
        assert!(outstanding.contains(&2));
    }

    #[test]
    fn certification_success_clears_tracking() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(10), NZU64!(1));
        let mut resolver = MockResolver::default();

        // Notarization at view 5 satisfies request for view 2
        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::Notarization(notarization_v5.clone()),
            Some(View::new(2)),
            &mut resolver,
        );

        assert!(state.satisfied_by.contains_key(&View::new(5)));

        // Certification succeeds for view 5
        state.handle_certified(View::new(5), true, &mut resolver);

        // Floor should be set
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        // Tracking should be cleaned up
        assert!(!state.satisfied_by.contains_key(&View::new(5)));
        // View 5 should not be marked as failed
        assert!(!state.is_failed(View::new(5)));
    }

    #[test]
    fn certification_success_refills_next_term_anchor_window() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(1), NZU64!(5));
        let mut resolver = MockResolver::default();

        let nullification_v14 = build_nullification(&schemes, &verifier, View::new(14));
        state.handle(
            Certificate::Nullification(nullification_v14),
            None,
            &mut resolver,
        );
        assert_eq!(resolver.outstanding(), vec![1]);

        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::Notarization(notarization_v5.clone()),
            Some(View::new(1)),
            &mut resolver,
        );
        assert_eq!(resolver.outstanding(), vec![1]);

        state.handle_certified(View::new(5), true, &mut resolver);

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(state.current_view, View::new(14));
        assert_eq!(resolver.outstanding(), vec![6]);
    }

    #[test]
    fn finalization_upgrades_certified_notarization_at_same_view() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(NZU64!(10), NZU64!(1));
        let mut resolver = MockResolver::default();

        // Create and certify a notarization at view 5
        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::Notarization(notarization_v5.clone()),
            None,
            &mut resolver,
        );
        state.handle_certified(View::new(5), true, &mut resolver);

        // Floor should be the notarization at view 5
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(state.floor_view(), View::new(5));

        // A finalization at the same view should upgrade the floor
        let finalization_v5 = build_finalization(&schemes, &verifier, View::new(5));
        state.handle(
            Certificate::Finalization(finalization_v5.clone()),
            None,
            &mut resolver,
        );

        // Floor should now be the finalization (stronger proof)
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization_v5)
        );
    }
}
