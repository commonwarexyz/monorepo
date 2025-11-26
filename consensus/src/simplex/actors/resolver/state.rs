use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Finalization, Notarization, Nullification, Voter},
    },
    types::View,
    Viewable,
};
use commonware_cryptography::Digest;
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
use std::collections::BTreeMap;

/// Tracks all known certificates from the last
/// notarized or finalized view to the current view.
pub struct State<S: Scheme, D: Digest> {
    /// Highest seen view.
    current_view: View,
    /// Highest certified view.
    certified_view: View,
    /// Most recent finalized/certified certificate.
    floor: Option<Finalization<S, D>>,
    /// Notarizations for any view greater than the floor.
    notarizations: BTreeMap<View, Notarization<S, D>>,
    /// Nullifications for any view greater than the floor.
    nullifications: BTreeMap<View, Nullification<S>>,
    /// Window of requests to send to the resolver.
    fetch_concurrent: usize,
}

impl<S: Scheme, D: Digest> State<S, D> {
    /// Create a new instance of [State].
    pub fn new(fetch_concurrent: usize) -> Self {
        Self {
            fetch_concurrent,
            current_view: View::zero(),
            certified_view: View::zero(),
            floor: None,
            notarizations: BTreeMap::new(),
            nullifications: BTreeMap::new(),
        }
    }

    /// Handle a new message and update the [Resolver] accordingly.
    pub async fn handle(&mut self, message: Voter<S, D>, resolver: &mut impl Resolver<Key = U64>) {
        match message {
            Voter::Nullification(nullification) => {
                let view = nullification.view();
                if self.encounter_view(view) {
                    self.nullifications.insert(view, nullification);
                    resolver.cancel(view.into()).await;
                }
            }
            Voter::Notarization(notarization) => {
                let view = notarization.view();
                if self.encounter_view(view) {
                    self.notarizations.insert(view, notarization);
                }
            }
            Voter::Finalization(finalization) => {
                let view = finalization.view();
                if self.encounter_view(view) {
                    self.floor = Some(finalization);
                    self.prune(resolver).await;
                }
            }
            Voter::Certification(round, success) => {
                if !success {
                    return;
                }
                let view = round.view();
                if self.encounter_view(view) && view > self.certified_view {
                    self.certified_view = view;
                    self.prune(resolver).await;
                }
            }
            _ => unreachable!("unexpected message type"),
        }

        // Request missing nullifications
        self.fetch(resolver).await;
    }

    /// Get the best certificate for a given view (or the floor if the view is below the floor).
    pub fn get(&self, view: View) -> Option<Voter<S, D>> {
        // If view is <= floor, return the floor
        if let Some(floor) = &self.floor {
            if view <= floor.view() {
                return Some(Voter::Finalization(floor.clone()));
            }
        }

        // Otherwise, return the nullification for the view if it exists
        self.nullifications
            .get(&view)
            .map(|nullification| Voter::Nullification(nullification.clone()))
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

    /// Inform the [Resolver] of any missing nullifications.
    async fn fetch(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        // We must either receive a nullification or a notarization (at the view or higher),
        // so we don't need to worry about getting stuck. All requests will be resolved or pruned.
        let start = self.certified_view.max(self.floor_view()).next();
        let requests = View::range(start, self.current_view)
            .filter(|view| !self.nullifications.contains_key(view))
            .take(self.fetch_concurrent)
            .map(U64::from)
            .collect();
        resolver.fetch_all(requests).await;
    }

    /// Prune stored certificates below the floor.
    /// Prune requests for certificates above the highest certified view, which may be higher.
    async fn prune(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        // Prune stored certificates.
        let stored_floor = self.floor_view();
        self.nullifications.retain(|view, _| *view > stored_floor);
        self.notarizations.retain(|view, _| *view > stored_floor);

        // Prune requests for certificates.
        let resolver_floor = self.certified_view.max(stored_floor);
        resolver
            .retain(move |key| key > &resolver_floor.into())
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            mocks::fixtures::{ed25519 as build_fixture, Fixture},
            signing_scheme::ed25519 as ed_scheme,
            types::{
                Finalization, Finalize, Notarization, Notarize, Nullification, Nullify, Proposal,
            },
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_macros::test_async;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

    const NAMESPACE: &[u8] = b"resolver-state";
    const EPOCH: Epoch = Epoch::new(9);

    type TestScheme = ed_scheme::Scheme;

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

        async fn fetch(&mut self, key: U64) {
            self.outstanding.lock().unwrap().insert(key);
        }

        async fn fetch_all(&mut self, keys: Vec<U64>) {
            for key in keys {
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
        } = build_fixture(&mut rng, 5);
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
                Voter::Nullification(nullification_v4.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Voter::Nullification(n)) if n == nullification_v4)
        );
        assert_eq!(resolver.outstanding(), vec![1, 2]); // limited to concurrency

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state
            .handle(
                Voter::Nullification(nullification_v2.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Voter::Nullification(n)) if n == nullification_v2)
        );
        assert_eq!(resolver.outstanding(), vec![1, 3]); // limited to concurrency

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state
            .handle(
                Voter::Nullification(nullification_v1.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Voter::Nullification(n)) if n == nullification_v1)
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
                .handle(Voter::Nullification(nullification), &mut resolver)
                .await;
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        // Notarization alone does not set floor
        let notarization = build_notarization(&schemes, &verifier, View::new(6));
        state
            .handle(Voter::Notarization(notarization.clone()), &mut resolver)
            .await;

        assert!(state.floor.is_none());
        assert_eq!(state.nullifications.len(), 3);
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        // Certification of that notarization does not set floor
        state
            .handle(
                Voter::Certification(Round::new(EPOCH, View::new(6)), true),
                &mut resolver,
            )
            .await;
        assert!(state.floor.is_none());

        // Finalization at the same view sets floor
        let finalization = build_finalization(&schemes, &verifier, View::new(6));
        state
            .handle(Voter::Finalization(finalization.clone()), &mut resolver)
            .await;

        assert!(matches!(state.floor.as_ref(), Some(f) if f == &finalization));
        assert!(state.nullifications.is_empty());
        assert!(resolver.outstanding().is_empty());

        // Old finalization is ignored
        let finalization_old = build_finalization(&schemes, &verifier, View::new(4));
        state
            .handle(Voter::Finalization(finalization_old.clone()), &mut resolver)
            .await;
        assert!(matches!(state.floor.as_ref(), Some(f) if f == &finalization));
    }

    #[test_async]
    async fn produce_returns_floor_or_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        // Finalization sets floor
        let finalization = build_finalization(&schemes, &verifier, View::new(3));
        state
            .handle(Voter::Finalization(finalization.clone()), &mut resolver)
            .await;
        assert!(
            matches!(state.get(View::new(1)), Some(Voter::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Voter::Finalization(f)) if f == finalization)
        );

        // New nullification is kept
        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state
            .handle(
                Voter::Nullification(nullification_v4.clone()),
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.get(View::new(4)), Some(Voter::Nullification(n)) if n == nullification_v4)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Voter::Finalization(f)) if f == finalization)
        );

        // Old nullification is ignored
        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state
            .handle(
                Voter::Nullification(nullification_v1.clone()),
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.get(View::new(1)), Some(Voter::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Voter::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Voter::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(4)), Some(Voter::Nullification(n)) if n == nullification_v4)
        );
        assert!(resolver.outstanding().is_empty());
    }

    #[test_async]
    async fn limit_requests_and_raise_certified_view_with_certified_notarization() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        // Move to view 10
        state.encounter_view(View::new(10));
        state.fetch(&mut resolver).await;

        // Should only request 1 and 2
        assert_eq!(resolver.outstanding(), vec![1, 2]);

        // Add certified notarization for view 5
        let notarization = build_notarization(&schemes, &verifier, View::new(5));
        state
            .handle(Voter::Notarization(notarization.clone()), &mut resolver)
            .await;
        state
            .handle(
                Voter::Certification(Round::new(EPOCH, View::new(5)), true),
                &mut resolver,
            )
            .await;

        // Floor should still be None (since we only update on finalization)
        assert!(state.floor.is_none());

        // Next request should start at 6. Limit 2 -> 6, 7
        // Outstanding should be 6, 7 (1, 2 pruned)
        assert_eq!(resolver.outstanding(), vec![6, 7]);
    }
}
