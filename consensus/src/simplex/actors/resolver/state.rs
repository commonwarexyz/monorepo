use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Nullification, Voter},
    },
    types::View,
    Viewable,
};
use commonware_cryptography::Digest;
use commonware_resolver::Resolver;
use commonware_utils::sequence::U64;
use std::collections::{BTreeMap, BTreeSet};
use tracing::debug;

pub struct State<S: Scheme, D: Digest> {
    nullifications: BTreeMap<View, Nullification<S>>,
    pending: BTreeSet<View>,
    current_view: View,
    floor: Option<Voter<S, D>>,

    fetch_concurrent: usize,
}

impl<S: Scheme, D: Digest> State<S, D> {
    pub fn new(fetch_concurrent: usize) -> Self {
        Self {
            nullifications: BTreeMap::new(),
            pending: BTreeSet::new(),
            current_view: 0,
            floor: None,
            fetch_concurrent,
        }
    }

    pub async fn handle(&mut self, message: Voter<S, D>, resolver: &mut impl Resolver<Key = U64>) {
        match message {
            Voter::Nullification(nullification) => {
                // Update current view
                let view = nullification.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // If greater than the floor, store
                self.pending.remove(&view);
                resolver.cancel(U64::new(view)).await;
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.nullifications.insert(view, nullification);
                    }
                } else {
                    self.nullifications.insert(view, nullification);
                }
            }
            Voter::Notarization(notarization) => {
                // Update current view
                let view = notarization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last notarized
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.floor = Some(Voter::Notarization(notarization));
                    }
                } else {
                    self.floor = Some(Voter::Notarization(notarization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
            Voter::Finalization(finalization) => {
                // Update current view
                let view = finalization.view();
                if view > self.current_view {
                    self.current_view = view;
                }

                // Set last finalized
                if let Some(floor) = &self.floor {
                    if view > floor.view() {
                        self.floor = Some(Voter::Finalization(finalization));
                    }
                } else {
                    self.floor = Some(Voter::Finalization(finalization));
                }

                // Prune old nullifications
                self.prune(resolver).await;
            }
            _ => unreachable!("unexpected message type"),
        }

        // Request missing nullifications
        self.fetch(resolver).await;
    }

    async fn fetch(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        let mut cursor = self
            .floor
            .as_ref()
            .map(|floor| floor.view().saturating_add(1))
            .unwrap_or(1);

        // We must either receive a nullification or a notarization (at the view or higher),
        // so we don't need to worry about getting stuck because we've only made requests for the
        // next FETCH_BATCH views (which none of which may be resolvable). All will be resolved.
        while cursor < self.current_view && self.pending.len() < self.fetch_concurrent {
            if self.nullifications.contains_key(&cursor) || !self.pending.insert(cursor) {
                cursor = cursor.checked_add(1).expect("view overflow");
                continue;
            }
            self.pending.insert(cursor);
            resolver.fetch(U64::new(cursor)).await;
            debug!(cursor, "requested missing nullification");

            // Increment cursor
            cursor = cursor.checked_add(1).expect("view overflow");
        }
    }

    async fn prune(&mut self, resolver: &mut impl Resolver<Key = U64>) {
        let min = self.floor.as_ref().unwrap().view();
        self.nullifications.retain(|view, _| *view > min);
        self.pending.retain(|view| *view > min);

        let min = U64::from(min);
        resolver.retain(move |key| key > &min).await;
    }

    pub fn get(&self, view: View) -> Option<Voter<S, D>> {
        // If view is <= floor, return the floor
        if let Some(floor) = &self.floor {
            if view <= floor.view() {
                return Some(floor.clone());
            }
        }

        // Otherwise, return the nullification for the view
        self.nullifications
            .get(&view)
            .map(|nullification| Voter::Nullification(nullification.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::simplex::{
        mocks::fixtures::{ed25519 as build_fixture, Fixture},
        signing_scheme::ed25519 as ed_scheme,
        types::{Finalization, Finalize, Nullification, Nullify, Proposal},
    };
    use crate::types::{Round, View};
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_macros::test_async;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        collections::BTreeSet,
        sync::{Arc, Mutex},
    };

    const NAMESPACE: &[u8] = b"resolver-state";
    const EPOCH: u64 = 9;

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

    fn build_finalization(
        schemes: &[TestScheme],
        verifier: &TestScheme,
        view: View,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(EPOCH, view),
            view.saturating_sub(1),
            Sha256Digest::from([view as u8; 32]),
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

        let nullification_v3 = build_nullification(&schemes, &verifier, 3);
        state
            .handle(
                Voter::Nullification(nullification_v3.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, 3);
        assert!(state.pending.contains(&1));
        assert!(state.pending.contains(&2));
        assert_eq!(state.pending.len(), 2);
        assert!(matches!(state.get(3), Some(Voter::Nullification(n)) if n == nullification_v3));
        assert_eq!(resolver.outstanding(), vec![1, 2]);

        let nullification_v2 = build_nullification(&schemes, &verifier, 2);
        state
            .handle(
                Voter::Nullification(nullification_v2.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, 3);
        assert!(state.pending.contains(&1));
        assert_eq!(state.pending.len(), 1);
        assert!(matches!(state.get(2), Some(Voter::Nullification(n)) if n == nullification_v2));
        assert_eq!(resolver.outstanding(), vec![1]);

        let nullification_v1 = build_nullification(&schemes, &verifier, 1);
        state
            .handle(
                Voter::Nullification(nullification_v1.clone()),
                &mut resolver,
            )
            .await;
        assert_eq!(state.current_view, 3);
        assert!(matches!(state.get(1), Some(Voter::Nullification(n)) if n == nullification_v1));
        assert!(state.pending.is_empty());
        assert!(resolver.outstanding().is_empty());
    }

    #[test_async]
    async fn finalization_prunes_stale_state() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(10);
        let mut resolver = MockResolver::default();

        for view in 4..=6 {
            let nullification = build_nullification(&schemes, &verifier, view);
            state
                .handle(Voter::Nullification(nullification), &mut resolver)
                .await;
        }
        assert_eq!(state.current_view, 6);
        assert_eq!(resolver.outstanding(), vec![1, 2, 3]);

        let finalization = build_finalization(&schemes, &verifier, 6);
        state
            .handle(Voter::Finalization(finalization.clone()), &mut resolver)
            .await;

        assert!(matches!(state.floor.as_ref(), Some(Voter::Finalization(f)) if f == &finalization));
        assert!(state.nullifications.is_empty());
        assert!(state.pending.is_empty());
        assert!(resolver.outstanding().is_empty());
    }

    #[test_async]
    async fn produce_returns_floor_or_nullifications() {
        let (schemes, verifier) = ed25519_fixture();
        let mut state: State<TestScheme, Sha256Digest> = State::new(2);
        let mut resolver = MockResolver::default();

        // Finalization sets floor
        let finalization = build_finalization(&schemes, &verifier, 3);
        state
            .handle(Voter::Finalization(finalization.clone()), &mut resolver)
            .await;
        assert!(matches!(state.get(1), Some(Voter::Finalization(f)) if f == finalization));
        assert!(matches!(state.get(3), Some(Voter::Finalization(f)) if f == finalization));

        // New nullification is kept
        let nullification_v4 = build_nullification(&schemes, &verifier, 4);
        state
            .handle(
                Voter::Nullification(nullification_v4.clone()),
                &mut resolver,
            )
            .await;
        assert!(matches!(state.get(4), Some(Voter::Nullification(n)) if n == nullification_v4));
        assert!(matches!(state.get(2), Some(Voter::Finalization(f)) if f == finalization));

        // Old nullification is ignored
        let nullification_v1 = build_nullification(&schemes, &verifier, 1);
        state
            .handle(
                Voter::Nullification(nullification_v1.clone()),
                &mut resolver,
            )
            .await;
        assert!(matches!(state.get(1), Some(Voter::Finalization(f)) if f == finalization));
        assert!(matches!(state.get(2), Some(Voter::Finalization(f)) if f == finalization));
        assert!(matches!(state.get(3), Some(Voter::Finalization(f)) if f == finalization));
        assert!(matches!(state.get(4), Some(Voter::Nullification(n)) if n == nullification_v4));
        assert!(resolver.outstanding().is_empty());
    }
}
