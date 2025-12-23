use crate::{
    simplex::types::{Certificate, Notarization},
    types::View,
    Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
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
    /// Nullifications for any view greater than the floor.
    nullifications: BTreeMap<View, Certificate<S, D>>,
    /// Window of requests to send to the resolver.
    fetch_concurrent: usize,
    /// Next view to consider when fetching. Avoids re-scanning
    /// views we've already requested or have nullifications for.
    fetch_floor: View,
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
    pub fn new(fetch_concurrent: usize) -> Self {
        Self {
            current_view: View::zero(),
            floor: None,
            notarizations: BTreeMap::new(),
            nullifications: BTreeMap::new(),
            fetch_concurrent,
            fetch_floor: View::zero(),
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
    pub async fn handle(
        &mut self,
        certificate: Certificate<S, D>,
        request: Option<View>,
        resolver: &mut impl Resolver<Key = U64>,
    ) {
        match certificate {
            Certificate::Nullification(nullification) => {
                let view = nullification.view();
                if self.encounter_view(view) {
                    self.nullifications
                        .insert(view, Certificate::Nullification(nullification));
                    resolver.cancel(view.into()).await;
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
                    self.prune(resolver).await;
                }
            }
        }

        // Request missing nullifications
        self.fetch(resolver).await;
    }

    /// Handle a certification result from the voter.
    pub async fn handle_certified(
        &mut self,
        view: View,
        success: bool,
        resolver: &mut impl Resolver<Key = U64>,
    ) {
        if success {
            // Certification passed - set floor to notarization if we have it
            if let Some(notarization) = self.notarizations.remove(&view) {
                if view > self.floor_view() {
                    self.floor = Some(Certificate::Notarization(notarization));
                    self.prune(resolver).await;
                }
            }

            // Clean up satisfaction tracking
            self.satisfied_by.remove(&view);
        } else {
            // Discard notarization and mark view as failed (ensures we can penalize
            // malicious peers that hand us useless notarizations)
            self.notarizations.remove(&view);
            self.failed_views.insert(view);

            // Request nullification for this view (if above floor)
            let floor = self.floor_view();
            if view > floor {
                resolver.fetch(view.into()).await;
            }

            // Re-request any lower views this notarization had satisfied
            if let Some(satisfied_views) = self.satisfied_by.remove(&view) {
                for &v in satisfied_views.iter().filter(|v| **v > floor) {
                    resolver.fetch(v.into()).await;
                }
            }
        }
    }

    /// Get the best certificate for a given view (or the floor
    /// if the view is below the floor).
    pub fn get(&self, view: View) -> Option<&Certificate<S, D>> {
        // If view is <= floor, return the floor
        if let Some(floor) = &self.floor {
            if view <= floor.view() {
                return Some(floor);
            }
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

    /// Inform the [Resolver] of any missing nullifications.
    async fn fetch(&mut self, resolver: &mut impl Resolver<Key = U64>) {
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

        // Send the requests to the resolver.
        let requests = views.into_iter().map(U64::from).collect();
        resolver.fetch_all(requests).await;
    }

    /// Prune stored certificates and requests that are not higher than the floor.
    async fn prune(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        let floor = self.floor_view();
        self.notarizations.retain(|view, _| *view > floor);
        self.nullifications.retain(|view, _| *view > floor);
        self.satisfied_by.retain(|view, _| *view > floor);
        self.failed_views.retain(|view| *view > floor);
        resolver.retain(move |key| *key > floor.into()).await;
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
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_async;
    use commonware_utils::vec::NonEmptyVec;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

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
                .unwrap()
                .iter()
                .map(|key| key.into())
                .collect()
        }
    }

    impl Resolver for MockResolver {
        type Key = U64;
        type PublicKey = PublicKey;

        async fn fetch(&mut self, key: U64) {
            self.outstanding.lock().unwrap().insert(key);
        }

        async fn fetch_all(&mut self, keys: Vec<U64>) {
            for key in keys {
                self.outstanding.lock().unwrap().insert(key);
            }
        }

        async fn fetch_targeted(&mut self, key: U64, _targets: NonEmptyVec<PublicKey>) {
            // For testing, just treat targeted fetch the same as regular fetch
            self.outstanding.lock().unwrap().insert(key);
        }

        async fn fetch_all_targeted(&mut self, requests: Vec<(U64, NonEmptyVec<PublicKey>)>) {
            // For testing, just treat targeted fetch the same as regular fetch
            for (key, _targets) in requests {
                self.outstanding.lock().unwrap().insert(key);
            }
        }

        async fn cancel(&mut self, key: U64) {
            self.outstanding.lock().unwrap().remove(&key);
        }

        async fn clear(&mut self) {
            self.outstanding.lock().unwrap().clear();
        }

        async fn retain(&mut self, predicate: impl Fn(&Self::Key) -> bool + Send + 'static) {
            self.outstanding
                .lock()
                .unwrap()
                .retain(|key| predicate(key));
        }
    }

    fn ed25519_fixture() -> (Vec<TestScheme>, TestScheme) {
        let mut rng = StdRng::seed_from_u64(42);
        let Fixture {
            schemes, verifier, ..
        } = ed25519::fixture(&mut rng, 5);
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
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, NAMESPACE, round).unwrap())
            .collect();
        Nullification::from_nullifies(verifier, &votes).expect("nullification quorum")
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
            .map(|scheme| Notarize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
            .collect();
        Notarization::from_notarizes(verifier, &votes).expect("notarization quorum")
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
            .map(|scheme| Finalize::sign(scheme, NAMESPACE, proposal.clone()).unwrap())
            .collect();
        Finalization::from_finalizes(verifier, &votes).expect("finalization quorum")
    }

    #[test_async]
    async fn handle_nullification_requests_missing_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state
            .handle(
                Certificate::Nullification(nullification_v4.clone()),
                None,
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        assert_eq!(resolver.outstanding(), vec![1, 2]); // limited to concurrency

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state
            .handle(
                Certificate::Nullification(nullification_v2.clone()),
                None,
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == &nullification_v2)
        );
        assert_eq!(resolver.outstanding(), vec![1, 3]); // limited to concurrency

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state
            .handle(
                Certificate::Nullification(nullification_v1.clone()),
                None,
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Nullification(n)) if n == &nullification_v1)
        );
        assert_eq!(resolver.outstanding(), vec![3]);
    }

    #[test_async]
    async fn floor_prunes_outstanding_requests() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, View::new(view));
            state
                .handle(
                    Certificate::Nullification(nullification),
                    None,
                    &mut resolver,
                )
                .await;
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        // Notarization does not set floor or prune
        let notarization = build_notarization(&schemes, &verifier, View::new(6));
        state
            .handle(
                Certificate::Notarization(notarization.clone()),
                None,
                &mut resolver,
            )
            .await;

        assert!(state.floor.is_none());
        assert_eq!(state.nullifications.len(), 3); // nullifications remain
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]); // requests remain

        // Finalization sets floor and prunes
        let finalization = build_finalization(&schemes, &verifier, View::new(6));
        state
            .handle(
                Certificate::Finalization(finalization.clone()),
                None,
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization)
        );
    }

    #[test_async]
    async fn produce_returns_floor_or_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        // Finalization sets floor
        let finalization = build_finalization(&schemes, &verifier, View::new(3));
        state
            .handle(
                Certificate::Finalization(finalization.clone()),
                None,
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == &finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        // New nullification is kept
        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state
            .handle(
                Certificate::Nullification(nullification_v4.clone()),
                None,
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == &nullification_v4)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == &finalization)
        );

        // Old nullification is ignored
        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state
            .handle(
                Certificate::Nullification(nullification_v1.clone()),
                None,
                &mut resolver,
            )
            .await;
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
        assert!(resolver.outstanding().is_empty());
    }

    #[test_async]
    async fn certification_failure_re_requests_satisfied_views() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        // Notarization at view 5 satisfies request for view 2
        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        state
            .handle(
                Certificate::Notarization(notarization_v5.clone()),
                Some(View::new(2)),
                &mut resolver,
            )
            .await;

        // Verify tracking
        assert!(state.satisfied_by.contains_key(&View::new(5)));
        assert!(state.satisfied_by[&View::new(5)].contains(&View::new(2)));
        assert!(!state.is_failed(View::new(5)));

        // Certification fails for view 5
        state
            .handle_certified(View::new(5), false, &mut resolver)
            .await;

        // View 5 should be marked as failed
        assert!(state.is_failed(View::new(5)));
        // Satisfied_by should be cleaned up
        assert!(!state.satisfied_by.contains_key(&View::new(5)));
        // Both view 5 and view 2 should have requests
        let outstanding = resolver.outstanding();
        assert!(outstanding.contains(&5));
        assert!(outstanding.contains(&2));
    }

    #[test_async]
    async fn certification_success_clears_tracking() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        // Notarization at view 5 satisfies request for view 2
        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        state
            .handle(
                Certificate::Notarization(notarization_v5.clone()),
                Some(View::new(2)),
                &mut resolver,
            )
            .await;

        assert!(state.satisfied_by.contains_key(&View::new(5)));

        // Certification succeeds for view 5
        state
            .handle_certified(View::new(5), true, &mut resolver)
            .await;

        // Floor should be set
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        // Tracking should be cleaned up
        assert!(!state.satisfied_by.contains_key(&View::new(5)));
        // View 5 should not be marked as failed
        assert!(!state.is_failed(View::new(5)));
    }

    #[test_async]
    async fn finalization_upgrades_certified_notarization_at_same_view() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        // Create and certify a notarization at view 5
        let notarization_v5 = build_notarization(&schemes, &verifier, View::new(5));
        state
            .handle(
                Certificate::Notarization(notarization_v5.clone()),
                None,
                &mut resolver,
            )
            .await;
        state
            .handle_certified(View::new(5), true, &mut resolver)
            .await;

        // Floor should be the notarization at view 5
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization_v5)
        );
        assert_eq!(state.floor_view(), View::new(5));

        // A finalization at the same view should upgrade the floor
        let finalization_v5 = build_finalization(&schemes, &verifier, View::new(5));
        state
            .handle(
                Certificate::Finalization(finalization_v5.clone()),
                None,
                &mut resolver,
            )
            .await;

        // Floor should now be the finalization (stronger proof)
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Finalization(f)) if f == &finalization_v5)
        );
    }
}
