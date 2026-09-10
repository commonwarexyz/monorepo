use crate::{
    marshal::resolver::handler::{Annotation, Key, Request},
    simplex::types::Finalization,
    types::{Height, Round},
};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_resolver::Resolver;

/// Durable height and round bounds restored when marshal initializes.
///
/// The components are independent retention bounds and need not identify the
/// same finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Floor {
    height: Option<Height>,
    round: Round,
}

impl Floor {
    /// Returns the latest durably processed height, if any.
    pub const fn height(&self) -> Option<Height> {
        self.height
    }

    /// Returns the latest durable finalization round floor.
    pub const fn round(&self) -> Round {
        self.round
    }
}

/// Durable floor state plus any update awaiting its anchor block.
pub(super) struct State<S: Scheme, C: Digest> {
    height: Option<Height>,
    round: Round,
    pending: Option<Finalization<S, C>>,
}

impl<S: Scheme, C: Digest> State<S, C> {
    pub(super) const fn resolved(height: Option<Height>, round: Round) -> Self {
        Self {
            height,
            round,
            pending: None,
        }
    }

    pub(super) const fn awaiting_anchor(
        height: Option<Height>,
        round: Round,
        finalization: Finalization<S, C>,
    ) -> Self {
        Self {
            height,
            round,
            pending: Some(finalization),
        }
    }

    pub(super) const fn snapshot(&self) -> Floor {
        Floor {
            height: self.height,
            round: self.round,
        }
    }

    /// Returns the inclusive height floor. Finalized data at or below it is
    /// neither stored nor repaired.
    ///
    /// Nothing processed maps to zero because height zero is genesis, which is
    /// anchored at startup or sits below a floor anchor and never carries a
    /// finalization. Delivery uses the stream cursor, which keeps that state
    /// distinct.
    pub(super) const fn processed_height(&self) -> Height {
        match self.height {
            Some(height) => height,
            None => Height::zero(),
        }
    }

    pub(super) const fn round(&self) -> Round {
        self.round
    }

    pub(super) const fn set_processed_height(&mut self, height: Height) {
        self.height = Some(height);
    }

    pub(super) const fn set_processed_round(&mut self, round: Round) {
        self.round = round;
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

    /// Takes the pending anchor if the processed round floor now covers its round.
    ///
    /// Finalized rounds and heights increase together along the finalized chain, so
    /// an anchor at or below the round floor sits at or below the processed height.
    #[must_use]
    pub(super) fn take_superseded_anchor(&mut self, round: Round) -> Option<Finalization<S, C>> {
        self.pending.take_if(|pending| pending.round() <= round)
    }

    /// Returns true when the resolver request is above all processed floors.
    fn permits(&self, fetch: &Request<C>) -> bool {
        if let Some(height) = self.height
            && !fetch.above_height_floor(height)
        {
            return false;
        }

        fetch.above_round_floor(self.round)
    }

    pub(super) fn fetch_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetch: Request<C>,
    ) -> FetchAdmission
    where
        R: Resolver<Key = Key<C>, Subscriber = Annotation>,
    {
        if !self.permits(&fetch) {
            return FetchAdmission::Denied;
        }
        resolver.fetch(fetch);
        FetchAdmission::Issued
    }
}

/// Whether floor admission issued the resolver fetch.
#[must_use = "fetch admission must be handled explicitly"]
pub(super) enum FetchAdmission {
    Issued,
    Denied,
}

impl FetchAdmission {
    pub(super) const fn ignore(self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::scheme::ed25519 as simplex_ed25519,
        types::{Epoch, View},
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::sha256::Sha256;
    use commonware_resolver::Fetch;
    use commonware_utils::sync::Mutex;
    use std::sync::Arc;

    type TestDigest = <Sha256 as commonware_cryptography::Hasher>::Digest;
    type TestScheme = simplex_ed25519::Scheme;
    type FetchRecord = Fetch<Key<TestDigest>, Annotation>;
    type RecordedFetches = Arc<Mutex<Vec<FetchRecord>>>;

    #[derive(Clone, Default)]
    struct TestResolver {
        fetches: RecordedFetches,
    }

    impl TestResolver {
        fn fetches(&self) -> Vec<FetchRecord> {
            self.fetches.lock().clone()
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

    fn round(view: u64) -> Round {
        Round::new(Epoch::zero(), View::new(view))
    }

    fn digest(byte: u8) -> TestDigest {
        Sha256::fill(byte)
    }

    fn floor() -> State<TestScheme, TestDigest> {
        State::resolved(Some(Height::new(5)), round(5))
    }

    #[test]
    fn fetch_if_permitted_applies_height_and_round_floors() {
        let floor = floor();
        let mut resolver = TestResolver::default();

        for retention in [
            Annotation::Height(Height::new(4)),
            Annotation::Height(Height::new(5)),
            Annotation::Round(round(4)),
            Annotation::Round(round(5)),
        ] {
            assert!(matches!(
                floor.fetch_if_permitted(&mut resolver, Request::new(digest(1), retention)),
                FetchAdmission::Denied
            ));
        }
        assert!(resolver.fetches().is_empty());

        let retained = [
            Annotation::Height(Height::new(6)),
            Annotation::Round(round(6)),
            Annotation::Subscription,
        ];
        for retention in retained {
            assert!(matches!(
                floor.fetch_if_permitted(&mut resolver, Request::new(digest(1), retention)),
                FetchAdmission::Issued
            ));
        }
        let fetches = resolver.fetches();
        assert_eq!(fetches.len(), retained.len());
        for (fetch, retention) in fetches.iter().zip(retained) {
            assert_eq!(fetch.key, Key::Block(digest(1)));
            assert_eq!(fetch.subscriber, retention);
        }
    }

    #[test]
    fn fetch_if_permitted_without_height_floor_allows_genesis_height() {
        let floor = State::<TestScheme, TestDigest>::resolved(None, round(5));
        let mut resolver = TestResolver::default();
        let retention = Annotation::Height(Height::zero());
        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::new(digest(1), retention)),
            FetchAdmission::Issued
        ));
        let fetches = resolver.fetches();
        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].key, Key::Block(digest(1)));
        assert_eq!(fetches[0].subscriber, retention);
    }
}
