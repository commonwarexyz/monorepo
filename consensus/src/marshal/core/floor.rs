use crate::{
    marshal::resolver::handler::{Annotation, Key, Request},
    simplex::types::Finalization,
    types::{Epoch, Height, Round},
};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_resolver::{Resolver, TargetedResolver};
use commonware_utils::vec::NonEmptyVec;

/// Durable processed floor used to admit or reject resolver fetches.
#[derive(Clone, Copy)]
struct ProcessedFloor {
    height: Option<Height>,
    round: Round,
}

impl ProcessedFloor {
    /// Returns true when the resolver request is above all processed floors.
    fn permits<C: Digest>(&self, fetch: &Request<C>) -> bool {
        if let Some(height) = self.height
            && !fetch.above_height_floor(height)
        {
            return false;
        }

        fetch.above_round_floor(self.round)
    }
}

#[must_use = "fetch admission must be handled explicitly"]
pub(super) enum FetchAdmission {
    Issued,
    Denied,
}

impl FetchAdmission {
    pub(super) const fn denied(self) -> bool {
        matches!(self, Self::Denied)
    }

    pub(super) const fn ignore(self) {}
}

/// The processed floor plus any pending floor update awaiting its anchor block.
pub(super) struct Floor<S: Scheme, C: Digest> {
    processed: ProcessedFloor,
    pending: Option<Finalization<S, C>>,
    hint_activation: Option<Epoch>,
}

impl<S: Scheme, C: Digest> Floor<S, C> {
    pub(super) const fn resolved(
        height: Option<Height>,
        round: Round,
        hint_activation: Option<Epoch>,
    ) -> Self {
        Self {
            processed: ProcessedFloor { height, round },
            pending: None,
            hint_activation,
        }
    }

    pub(super) const fn awaiting_anchor(
        height: Option<Height>,
        round: Round,
        hint_activation: Option<Epoch>,
        finalization: Finalization<S, C>,
    ) -> Self {
        Self {
            processed: ProcessedFloor { height, round },
            pending: Some(finalization),
            hint_activation,
        }
    }

    /// Returns true once the processed round has reached the hint activation
    /// epoch.
    ///
    /// Certification hints change the peer-visible request encoding, so they
    /// activate hardfork-style: every provider must be upgraded before the
    /// activation epoch begins. Requests issued before activation use the
    /// legacy hint-free encoding.
    fn hints_active(&self) -> bool {
        self.hint_activation
            .is_some_and(|activation| self.processed.round.epoch() >= activation)
    }

    pub(super) const fn processed_height(&self) -> Height {
        match self.processed.height {
            Some(height) => height,
            None => Height::zero(),
        }
    }

    pub(super) const fn processed_round(&self) -> Round {
        self.processed.round
    }

    pub(super) const fn set_processed_height(&mut self, height: Height) {
        self.processed.height = Some(height);
    }

    pub(super) const fn set_processed_round(&mut self, round: Round) {
        self.processed.round = round;
    }

    /// Returns true while repair and application dispatch must wait for the floor anchor.
    pub(super) const fn blocks_progress(&self) -> bool {
        self.pending.is_some()
    }

    /// Returns true if a pending floor already supersedes the candidate floor round.
    pub(super) fn has_pending_anchor_at_or_after(&self, round: Round) -> bool {
        matches!(&self.pending, Some(pending) if pending.round() >= round)
    }

    /// Returns true when `commitment` is the awaited anchor.
    pub(super) fn matches_pending_anchor(&self, commitment: C) -> bool {
        matches!(&self.pending, Some(pending) if pending.proposal.payload == commitment)
    }

    /// Records a verified floor finalization whose block anchor still needs to arrive.
    pub(super) fn await_anchor(&mut self, finalization: Finalization<S, C>) {
        self.pending = Some(finalization);
    }

    /// Takes the pending anchor finalization, if any.
    #[must_use]
    pub(super) const fn take_pending_anchor(&mut self) -> Option<Finalization<S, C>> {
        self.pending.take()
    }

    pub(super) fn fetch_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetch: Request<C>,
    ) -> FetchAdmission
    where
        R: Resolver<Key = Key<C>, Subscriber = Annotation>,
    {
        if !self.processed.permits(&fetch) {
            return FetchAdmission::Denied;
        }
        resolver.fetch(fetch.into_inner(self.hints_active()));
        FetchAdmission::Issued
    }

    pub(super) fn fetch_targeted_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetch: Request<C>,
        targets: NonEmptyVec<R::PublicKey>,
    ) -> FetchAdmission
    where
        R: TargetedResolver<Key = Key<C>, Subscriber = Annotation>,
    {
        if !self.processed.permits(&fetch) {
            return FetchAdmission::Denied;
        }
        resolver.fetch_targeted(fetch.into_inner(self.hints_active()), targets);
        FetchAdmission::Issued
    }

    pub(super) fn fetch_all_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetches: Vec<Request<C>>,
    ) -> FetchAdmission
    where
        R: Resolver<Key = Key<C>, Subscriber = Annotation>,
    {
        let hinted = self.hints_active();
        let fetches = fetches
            .into_iter()
            .filter(|fetch| self.processed.permits(fetch))
            .map(|fetch| fetch.into_inner(hinted))
            .collect::<Vec<_>>();
        if fetches.is_empty() {
            return FetchAdmission::Denied;
        }
        resolver.fetch_all(fetches);
        FetchAdmission::Issued
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        marshal::resolver::handler::Finalized,
        simplex::scheme::ed25519 as simplex_ed25519,
        types::{Epoch, View},
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{Signer as _, ed25519 as crypto_ed25519, sha256::Sha256};
    use commonware_math::algebra::Random as _;
    use commonware_resolver::Fetch;
    use commonware_utils::sync::Mutex;
    use std::sync::Arc;

    type TestDigest = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type TestScheme = simplex_ed25519::Scheme;
    type FetchRecord = Fetch<Key<TestDigest>, Annotation>;
    type RecordedFetches = Arc<Mutex<Vec<FetchRecord>>>;
    type RecordedTargets = Arc<Mutex<Vec<Key<TestDigest>>>>;

    #[derive(Clone, Default)]
    struct TestResolver {
        fetches: RecordedFetches,
        targeted: RecordedTargets,
    }

    impl TestResolver {
        fn fetches(&self) -> Vec<FetchRecord> {
            self.fetches.lock().clone()
        }

        fn targeted(&self) -> Vec<Key<TestDigest>> {
            self.targeted.lock().clone()
        }
    }

    impl Resolver for TestResolver {
        type Key = Key<TestDigest>;
        type Subscriber = Annotation;

        fn fetch<F>(&mut self, fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            self.fetches.lock().push(fetch.into());
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, fetches: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            self.fetches
                .lock()
                .extend(fetches.into_iter().map(Into::into));
            Feedback::Ok
        }

        fn retain(
            &mut self,
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    impl TargetedResolver for TestResolver {
        type PublicKey = crypto_ed25519::PublicKey;

        fn fetch_targeted(
            &mut self,
            fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            _targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback {
            self.targeted.lock().push(fetch.into().key);
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            self.targeted
                .lock()
                .extend(fetches.into_iter().map(|(fetch, _)| fetch.into().key));
            Feedback::Ok
        }
    }

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn digest(byte: u8) -> TestDigest {
        Sha256::fill(byte)
    }

    fn floor() -> Floor<TestScheme, TestDigest> {
        Floor::resolved(Some(Height::new(5)), round(5), None)
    }

    #[test]
    fn fetch_if_permitted_applies_height_and_round_floors() {
        let floor = floor();
        let mut resolver = TestResolver::default();

        assert!(
            floor
                .fetch_if_permitted(&mut resolver, Request::finalized(Height::new(5)))
                .denied()
        );
        assert!(
            floor
                .fetch_if_permitted(
                    &mut resolver,
                    Request::finalized_block_by_height(digest(1), Height::new(4)),
                )
                .denied()
        );
        assert!(
            floor
                .fetch_if_permitted(&mut resolver, Request::notarized(round(5)))
                .denied()
        );
        assert!(resolver.fetches().is_empty());

        assert!(
            !floor
                .fetch_if_permitted(&mut resolver, Request::finalized(Height::new(6)))
                .denied()
        );
        assert!(
            !floor
                .fetch_if_permitted(&mut resolver, Request::notarized(round(6)))
                .denied()
        );

        let fetches = resolver.fetches();
        assert_eq!(fetches.len(), 2);
        assert!(matches!(
            fetches[0],
            Fetch {
                key: Key::Finalized {
                    height
                },
                subscriber: Annotation::Finalized(Finalized::ByHeight {
                    height: subscriber_height
                }),
                ..
            } if height == Height::new(6) && subscriber_height == Height::new(6)
        ));
        assert!(matches!(
            fetches[1],
            Fetch {
                key: Key::Notarized {
                    round: request_round,
                    ..
                },
                subscriber: Annotation::Notarization {
                    round: subscriber_round
                },
                ..
            } if request_round == round(6) && subscriber_round == round(6)
        ));
    }

    #[test]
    fn fetch_targeted_if_permitted_returns_denied_without_fetching() {
        let floor = floor();
        let mut resolver = TestResolver::default();
        let mut rng = commonware_utils::test_rng();
        let target = crypto_ed25519::PrivateKey::random(&mut rng).public_key();

        assert!(
            floor
                .fetch_targeted_if_permitted(
                    &mut resolver,
                    Request::finalized(Height::new(5)),
                    NonEmptyVec::new(target.clone()),
                )
                .denied()
        );
        assert!(resolver.targeted().is_empty());

        assert!(
            !floor
                .fetch_targeted_if_permitted(
                    &mut resolver,
                    Request::finalized(Height::new(6)),
                    NonEmptyVec::new(target),
                )
                .denied()
        );
        assert_eq!(
            resolver.targeted(),
            vec![Key::Finalized {
                height: Height::new(6)
            }]
        );
    }

    #[test]
    fn fetch_all_if_permitted_filters_denied_requests() {
        let floor = floor();
        let mut resolver = TestResolver::default();

        assert!(
            !floor
                .fetch_all_if_permitted(
                    &mut resolver,
                    vec![
                        Request::finalized(Height::new(5)),
                        Request::finalized(Height::new(6)),
                        Request::notarized(round(5)),
                        Request::notarized(round(6)),
                    ],
                )
                .denied()
        );

        let fetches = resolver.fetches();
        assert_eq!(fetches.len(), 2);
        assert!(matches!(fetches[0].key, Key::Finalized { height } if height == Height::new(6)));
        assert!(
            matches!(fetches[1].key, Key::Notarized { round: request_round, .. } if request_round == round(6))
        );

        let mut resolver = TestResolver::default();
        assert!(
            floor
                .fetch_all_if_permitted(
                    &mut resolver,
                    vec![
                        Request::finalized(Height::new(5)),
                        Request::notarized(round(5)),
                    ],
                )
                .denied()
        );
        assert!(resolver.fetches().is_empty());
    }

    #[test]
    fn hints_activate_at_processed_activation_epoch() {
        let mut floor = Floor::<TestScheme, TestDigest>::resolved(
            Some(Height::new(5)),
            Round::new(Epoch::new(2), View::new(5)),
            Some(Epoch::new(3)),
        );
        let mut resolver = TestResolver::default();

        // Below the activation epoch, requests use the legacy encoding.
        floor
            .fetch_if_permitted(
                &mut resolver,
                Request::certified_block(digest(1), Height::new(6)),
            )
            .ignore();
        floor
            .fetch_if_permitted(
                &mut resolver,
                Request::certified(Round::new(Epoch::new(2), View::new(6))),
            )
            .ignore();

        // Crossing the activation epoch flips new requests to hinted keys.
        floor.set_processed_round(Round::new(Epoch::new(3), View::zero()));
        floor
            .fetch_if_permitted(
                &mut resolver,
                Request::certified_block(digest(2), Height::new(7)),
            )
            .ignore();
        floor
            .fetch_if_permitted(
                &mut resolver,
                Request::certified(Round::new(Epoch::new(3), View::new(1))),
            )
            .ignore();

        // Fully validated notarized fetches never carry the hint.
        floor
            .fetch_if_permitted(
                &mut resolver,
                Request::notarized(Round::new(Epoch::new(3), View::new(2))),
            )
            .ignore();

        let hints = resolver
            .fetches()
            .iter()
            .map(|fetch| match fetch.key {
                Key::Block { certified, .. } | Key::Notarized { certified, .. } => certified,
                Key::Finalized { .. } => unreachable!("no finalized requests issued"),
            })
            .collect::<Vec<_>>();
        assert_eq!(hints, vec![false, false, true, true, false]);
    }

    #[test]
    fn hints_stay_disabled_without_activation_epoch() {
        let floor = Floor::<TestScheme, TestDigest>::resolved(
            Some(Height::new(5)),
            Round::new(Epoch::new(9), View::new(5)),
            None,
        );
        let mut resolver = TestResolver::default();
        let mut rng = commonware_utils::test_rng();
        let target = crypto_ed25519::PrivateKey::random(&mut rng).public_key();

        floor
            .fetch_targeted_if_permitted(
                &mut resolver,
                Request::certified_block(digest(1), Height::new(6)),
                NonEmptyVec::new(target),
            )
            .ignore();
        floor
            .fetch_all_if_permitted(
                &mut resolver,
                vec![Request::certified(Round::new(Epoch::new(9), View::new(6)))],
            )
            .ignore();

        assert!(matches!(
            resolver.targeted()[..],
            [Key::Block {
                certified: false,
                ..
            }]
        ));
        assert!(matches!(
            resolver.fetches()[..],
            [Fetch {
                key: Key::Notarized {
                    certified: false,
                    ..
                },
                ..
            }]
        ));
    }

    #[test]
    fn fetch_if_permitted_without_height_floor_allows_genesis_height() {
        let floor = Floor::<TestScheme, TestDigest>::resolved(None, round(5), None);
        let mut resolver = TestResolver::default();

        assert!(
            !floor
                .fetch_if_permitted(&mut resolver, Request::finalized(Height::zero()))
                .denied()
        );

        let fetches = resolver.fetches();
        assert_eq!(fetches.len(), 1);
        assert!(matches!(
            fetches[0],
            Fetch {
                key: Key::Finalized {
                    height
                },
                subscriber: Annotation::Finalized(Finalized::ByHeight {
                    height: subscriber_height
                }),
                ..
            } if height == Height::zero() && subscriber_height == Height::zero()
        ));
    }
}
