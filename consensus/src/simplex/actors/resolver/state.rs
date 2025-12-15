use crate::{
    simplex::types::{Certificate, Nullification},
    types::View,
    Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
use std::collections::BTreeMap;
use tracing::debug;

/// Tracks all known certificates from the last
/// notarized or finalized view to the current view.
pub struct State<S: Scheme, D: Digest> {
    nullifications: BTreeMap<View, Nullification<S>>,
    current_view: View,
    floor: Option<Certificate<S, D>>,

    fetch_concurrent: usize,
}

impl<S: Scheme, D: Digest> State<S, D> {
    /// Create a new instance of [State].
    pub const fn new(fetch_concurrent: usize) -> Self {
        Self {
            nullifications: BTreeMap::new(),
            current_view: View::zero(),
            floor: None,
            fetch_concurrent,
        }
    }

    /// Handle a new message and update the [Resolver] accordingly.
    pub async fn handle(
        &mut self,
        certificate: Certificate<S, D>,
        resolver: &mut impl Resolver<Key = U64>,
    ) {
        match certificate {
            Certificate::Nullification(nullification) => {
                // Update current view
                let view = nullification.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // If greater than the floor, store
                if self.floor.as_ref().is_none_or(|floor| view > floor.view()) {
                    self.nullifications.insert(view, nullification);
                }

                // Remove from pending and cancel request
                resolver.cancel(view.into()).await;
            }
            Certificate::Notarization(notarization) => {
                // Update current view
                let view = notarization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last notarized
                if self.floor.as_ref().is_none_or(|floor| view > floor.view()) {
                    self.floor = Some(Certificate::Notarization(notarization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
            Certificate::Finalization(finalization) => {
                // Update current view
                let view = finalization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last finalized
                if self.floor.as_ref().is_none_or(|floor| {
                    (matches!(floor, Certificate::Notarization(_)) && view == floor.view())
                        || view > floor.view()
                }) {
                    self.floor = Some(Certificate::Finalization(finalization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
        }

        // Request missing nullifications
        self.fetch(resolver).await;
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

        // Otherwise, return the nullification for the view
        self.nullifications
            .get(&view)
            .map(|nullification| Certificate::Nullification(nullification.clone()))
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
        // so we don't need to worry about getting stuck. All requests will be resolved.
        let mut cursor = self.floor_view().next();
        let mut requests = Vec::new();
        while cursor < self.current_view && requests.len() < self.fetch_concurrent {
            // Request the nullification if it is not known and not already pending
            if !self.nullifications.contains_key(&cursor) {
                requests.push(cursor.into());
                debug!(%cursor, "requested missing nullification");
            }

            // Increment cursor
            cursor = cursor.next();
        }
        resolver.fetch_all(requests).await;
    }

    /// Prune certificates (and requests for certificates) below the floor.
    async fn prune(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        let min = self.floor_view();
        self.nullifications.retain(|view, _| *view > min);

        let min = U64::from(min);
        resolver.retain(move |key| key > &min).await;
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
    use commonware_macros::test_async;
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
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert_eq!(resolver.outstanding(), vec![1, 2]); // limited to concurrency

        let nullification_v2 = build_nullification(&schemes, &verifier, View::new(2));
        state
            .handle(
                Certificate::Nullification(nullification_v2.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Nullification(n)) if n == nullification_v2)
        );
        assert_eq!(resolver.outstanding(), vec![1, 3]); // limited to concurrency

        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state
            .handle(
                Certificate::Nullification(nullification_v1.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, View::new(4));
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Nullification(n)) if n == nullification_v1)
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
                .handle(Certificate::Nullification(nullification), &mut resolver)
                .await;
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        let notarization = build_notarization(&schemes, &verifier, View::new(6));
        state
            .handle(
                Certificate::Notarization(notarization.clone()),
                &mut resolver,
            )
            .await;

        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization)
        );
        assert!(state.nullifications.is_empty());
        assert!(resolver.outstanding().is_empty());

        // Old finalization is ignored
        let finalization = build_finalization(&schemes, &verifier, View::new(4));
        state
            .handle(
                Certificate::Finalization(finalization.clone()),
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.floor.as_ref(), Some(Certificate::Notarization(n)) if n == &notarization)
        );

        // Finalization at same view overwrites notarization
        let finalization = build_finalization(&schemes, &verifier, View::new(6));
        state
            .handle(
                Certificate::Finalization(finalization.clone()),
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
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Finalization(f)) if f == finalization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Finalization(f)) if f == finalization)
        );

        // New nullification is kept
        let nullification_v4 = build_nullification(&schemes, &verifier, View::new(4));
        state
            .handle(
                Certificate::Nullification(nullification_v4.clone()),
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Finalization(f)) if f == finalization)
        );

        // Old nullification is ignored
        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state
            .handle(
                Certificate::Nullification(nullification_v1.clone()),
                &mut resolver,
            )
            .await;
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
}
