//! Resolver state machine for minimmit consensus.
//!
//! Unlike simplex, minimmit has no certification phase and no finalization certificates.
//! The resolver only tracks notarizations and nullifications.

use crate::{
    minimmit::types::{Certificate, Notarization},
    types::View,
    Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
use std::collections::BTreeMap;

/// Tracks all known certificates from the highest known notarization view to the current view.
pub struct State<S: Scheme, D: Digest> {
    /// Highest seen view.
    current_view: View,
    /// Most recent notarization (acts as floor).
    floor: Option<Notarization<S, D>>,
    /// Nullifications for any view greater than the floor.
    nullifications: BTreeMap<View, Certificate<S, D>>,
    /// Window of requests to send to the resolver.
    fetch_concurrent: usize,
    /// Next view to consider when fetching. Avoids re-scanning
    /// views we've already requested or have nullifications for.
    fetch_floor: View,
}

impl<S: Scheme, D: Digest> State<S, D> {
    /// Create a new instance of [State].
    pub const fn new(fetch_concurrent: usize) -> Self {
        Self {
            current_view: View::zero(),
            floor: None,
            nullifications: BTreeMap::new(),
            fetch_concurrent,
            fetch_floor: View::zero(),
        }
    }

    /// Handle a new certificate and update the [Resolver] accordingly.
    pub async fn handle(
        &mut self,
        certificate: Certificate<S, D>,
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
                let view = notarization.view();
                if self.encounter_view(view) {
                    // In minimmit, notarizations act as the floor directly
                    // (no separate certification step needed)
                    if view > self.floor_view() {
                        self.floor = Some(notarization);
                        self.prune(resolver).await;
                    }
                }
            }
        }

        // Request missing nullifications
        self.fetch(resolver).await;
    }

    /// Get the best certificate for a given view (or the floor if the view is below the floor).
    pub fn get(&self, view: View) -> Option<Certificate<S, D>> {
        // If view is <= floor, return the floor as notarization
        if let Some(floor) = &self.floor {
            if view <= floor.view() {
                return Some(Certificate::Notarization(floor.clone()));
            }
        }

        // Otherwise, return the nullification for the view if it exists
        self.nullifications.get(&view).cloned()
    }

    /// Updates the current view if the new view is greater.
    ///
    /// Returns true if the view is "interesting" (i.e. greater than the floor).
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
        // We must either receive a nullification at the current view or a notarization
        // at the current view or higher, so we don't need to worry about getting stuck.
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
        self.nullifications.retain(|view, _| *view > floor);
        resolver.retain(move |key| *key > floor.into()).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        minimmit::{
            scheme::ed25519,
            types::{Notarization, Notarize, Nullification, Nullify, Proposal},
        },
        types::{Epoch, Round, View},
    };
    use commonware_cryptography::{
        certificate::mocks::Fixture, ed25519::PublicKey, sha256::Digest as Sha256Digest,
    };
    use commonware_macros::test_async;
    use commonware_parallel::Sequential;
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
            self.outstanding.lock().unwrap().insert(key);
        }

        async fn fetch_all_targeted(&mut self, requests: Vec<(U64, NonEmptyVec<PublicKey>)>) {
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
            .map(|scheme| Nullify::sign::<Sha256Digest>(scheme, round).expect("sign"))
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
            .map(|scheme| Notarize::sign(scheme, proposal.clone()).expect("sign"))
            .collect();
        Notarization::from_notarizes(verifier, votes.iter(), &Sequential).expect("notarization quorum")
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
    async fn notarization_sets_floor_and_prunes() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        // Add some nullifications
        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, View::new(view));
            state
                .handle(Certificate::Nullification(nullification), &mut resolver)
                .await;
        }
        assert_eq!(state.current_view, View::new(6));
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        // Notarization sets floor and prunes
        let notarization = build_notarization(&schemes, &verifier, View::new(6));
        state
            .handle(
                Certificate::Notarization(notarization.clone()),
                &mut resolver,
            )
            .await;

        assert!(state.floor.is_some());
        assert_eq!(state.floor_view(), View::new(6));
        assert!(state.nullifications.is_empty()); // pruned
        assert!(resolver.outstanding().is_empty()); // pruned
    }

    #[test_async]
    async fn get_returns_floor_or_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        // Notarization sets floor
        let notarization = build_notarization(&schemes, &verifier, View::new(3));
        state
            .handle(
                Certificate::Notarization(notarization.clone()),
                &mut resolver,
            )
            .await;
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Notarization(n)) if n == notarization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Notarization(n)) if n == notarization)
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
            matches!(state.get(View::new(2)), Some(Certificate::Notarization(n)) if n == notarization)
        );

        // Old nullification is ignored
        let nullification_v1 = build_nullification(&schemes, &verifier, View::new(1));
        state
            .handle(Certificate::Nullification(nullification_v1), &mut resolver)
            .await;
        assert!(
            matches!(state.get(View::new(1)), Some(Certificate::Notarization(n)) if n == notarization)
        );
        assert!(
            matches!(state.get(View::new(2)), Some(Certificate::Notarization(n)) if n == notarization)
        );
        assert!(
            matches!(state.get(View::new(3)), Some(Certificate::Notarization(n)) if n == notarization)
        );
        assert!(
            matches!(state.get(View::new(4)), Some(Certificate::Nullification(n)) if n == nullification_v4)
        );
        assert!(resolver.outstanding().is_empty());
    }
}
