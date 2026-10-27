use crate::{
    marshal::resolver::handler::{Annotation, Key, Request},
    simplex::types::Finalization,
    types::{Epoch, Epocher, Height, Round},
};
use commonware_cryptography::{Digest, certificate::Scheme};
use commonware_resolver::{Resolver, TargetedResolver};
use commonware_utils::{futures::Aborter, vec::NonEmptyVec};
use std::{
    cmp::Ordering,
    fmt::{self, Display, Formatter},
};

/// Marshal's durable processed height and the stored block that backs it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Processed {
    /// The block at this height is processed and stored.
    Block(Height),
    /// This height is processed but its block is not stored. A floor was installed at the next
    /// height, and the floor block backs this position.
    Absent(Height),
}

impl Processed {
    /// Returns the processed height.
    pub const fn height(self) -> Height {
        match self {
            Self::Block(height) | Self::Absent(height) => height,
        }
    }

    /// Returns the height of the stored block that backs the processed height.
    pub const fn anchor(self) -> Height {
        match self {
            Self::Block(height) => height,
            Self::Absent(height) => height.next(),
        }
    }
}

/// An inclusive bound on finalization rounds: a round, or the end of an epoch.
///
/// Cutoffs are ordered by the rounds they cover. A cutoff in an earlier epoch sits below one in a
/// later epoch, and within one epoch [`Self::Epoch`] sits above every [`Self::Round`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cutoff {
    /// Covers this round and every earlier round.
    Round(Round),
    /// Covers every round of this epoch and of every earlier epoch.
    Epoch(Epoch),
}

impl Cutoff {
    /// Returns the cutoff that covers only the zero round.
    pub const fn zero() -> Self {
        Self::Round(Round::zero())
    }

    /// Returns true if `round` is at or below the cutoff, that is, if
    /// `self >= Cutoff::Round(round)`.
    pub const fn covers(&self, round: Round) -> bool {
        match *self {
            Self::Round(floor) => {
                round.epoch().get() < floor.epoch().get()
                    || (round.epoch().get() == floor.epoch().get()
                        && round.view().get() <= floor.view().get())
            }
            Self::Epoch(epoch) => round.epoch().get() <= epoch.get(),
        }
    }
}

impl Ord for Cutoff {
    fn cmp(&self, other: &Self) -> Ordering {
        match (*self, *other) {
            (Self::Round(a), Self::Round(b)) => a.cmp(&b),
            (Self::Epoch(a), Self::Epoch(b)) => a.cmp(&b),
            (Self::Round(a), Self::Epoch(b)) => a.epoch().cmp(&b).then(Ordering::Less),
            (Self::Epoch(a), Self::Round(b)) => a.cmp(&b.epoch()).then(Ordering::Greater),
        }
    }
}

impl PartialOrd for Cutoff {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Display for Cutoff {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Round(round) => Display::fmt(round, f),
            Self::Epoch(epoch) => Display::fmt(epoch, f),
        }
    }
}

/// Durable height and round bounds restored when marshal initializes.
///
/// The components are independent retention bounds and need not identify the
/// same finalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Floor {
    processed: Option<Processed>,
    cutoff: Cutoff,
}

impl Floor {
    /// Creates a floor from its independent processed position and round floor.
    pub(super) const fn new(processed: Option<Processed>, cutoff: Cutoff) -> Self {
        Self { processed, cutoff }
    }

    /// Returns the latest durably processed position, if any.
    pub const fn processed(&self) -> Option<Processed> {
        self.processed
    }

    /// Returns the durable round floor.
    ///
    /// Every finalization at a covered round names a block at or below the processed height, or
    /// the stored block just above it.
    pub const fn cutoff(&self) -> Cutoff {
        self.cutoff
    }
}

/// Returns the newest epoch whose last block is at or below `anchor`, or `None` when no epoch
/// ends at or below `anchor` or `epocher` cannot place `anchor`.
///
/// Verification requires every proposal, re-proposals included, to carry a block of its own epoch.
/// [`Epocher`] requires `epocher` to place every height as the validators do. So every
/// finalization an honest quorum produces in the returned epoch or an earlier one names a block at
/// or below `anchor`.
pub(super) fn closed_epoch<E: Epocher>(epocher: &E, anchor: Height) -> Option<Epoch> {
    let info = epocher.containing(anchor)?;
    if info.last() == anchor {
        Some(info.epoch())
    } else {
        info.epoch().previous()
    }
}

/// A floor finalization awaiting its anchor block.
///
/// Dropping the pending floor aborts its buffer waiter, if one exists.
struct Pending<S: Scheme, C: Digest> {
    finalization: Finalization<S, C>,
    _aborter: Option<Aborter>,
}

/// Durable floor state, the configured floor until startup takes it, and any update
/// awaiting its anchor block.
///
/// The processed position and the round floor mirror the stream metadata. The arm that raises
/// one syncs the stream before the actor handles its next event, so the value here is durable
/// whenever another arm or a mailbox caller reads it.
pub(super) struct State<S: Scheme, C: Digest> {
    /// The durable processed position, if any.
    processed: Option<Processed>,
    /// The durable round floor. Start restores it from the stream metadata or derives a higher
    /// one from the archives and the epocher.
    cutoff: Cutoff,
    /// The newest finalization round admitted for a processed block or an installed floor anchor.
    /// Start restores it from the archives, including the finalization of a block stored just
    /// above the processed height. Cache retention follows this round because a round floor that
    /// covers a whole epoch has no view to measure retention from.
    witnessed: Round,
    /// The configured floor until startup takes it.
    configured: Option<Finalization<S, C>>,
    /// A floor finalization awaiting its anchor block.
    pending: Option<Pending<S, C>>,
}

impl<S: Scheme, C: Digest> State<S, C> {
    /// Creates floor state from the configured floor, if any, the restored floor, and the newest
    /// finalization round recovered from the archives.
    pub(super) const fn new(
        configured: Option<Finalization<S, C>>,
        floor: Floor,
        witnessed: Round,
    ) -> Self {
        Self {
            processed: floor.processed,
            cutoff: floor.cutoff,
            witnessed,
            configured,
            pending: None,
        }
    }

    /// Takes the configured floor, if any.
    #[must_use]
    pub(super) const fn take_configured(&mut self) -> Option<Finalization<S, C>> {
        self.configured.take()
    }

    /// Returns the durable floor, without the configured or pending floor.
    pub(super) const fn snapshot(&self) -> Floor {
        Floor::new(self.processed, self.cutoff)
    }

    /// Returns the durable processed position, if any.
    pub(super) const fn processed(&self) -> Option<Processed> {
        self.processed
    }

    /// Returns the inclusive height floor. Finalized blocks at or below it are
    /// neither stored nor repaired.
    ///
    /// Nothing processed maps to zero because height zero is genesis, which is
    /// anchored at startup or sits below a floor anchor and never carries a
    /// finalization. Delivery uses the stream cursor, which keeps that state
    /// distinct.
    pub(super) const fn processed_height(&self) -> Height {
        match self.processed {
            Some(processed) => processed.height(),
            None => Height::zero(),
        }
    }

    /// Returns the durable round floor.
    pub(super) const fn cutoff(&self) -> Cutoff {
        self.cutoff
    }

    /// Returns the newest witnessed finalization round.
    pub(super) const fn witnessed(&self) -> Round {
        self.witnessed
    }

    /// Sets the processed position. The caller buffers the same height in the stream metadata and
    /// syncs the stream before the actor handles its next event.
    pub(super) const fn set_processed(&mut self, processed: Processed) {
        self.processed = Some(processed);
    }

    /// Sets the round floor. The caller buffers the same cutoff in the stream metadata and syncs
    /// the stream before the actor handles its next event.
    pub(super) const fn set_cutoff(&mut self, cutoff: Cutoff) {
        self.cutoff = cutoff;
    }

    /// Records `round` as the newest witnessed finalization round and returns the previous one,
    /// or `None` when `round` is not newer.
    #[must_use]
    pub(super) fn witness(&mut self, round: Round) -> Option<Round> {
        if round <= self.witnessed {
            return None;
        }
        let previous = self.witnessed;
        self.witnessed = round;
        Some(previous)
    }

    /// Returns true while repair and application dispatch must wait for the floor anchor.
    pub(super) const fn blocks_progress(&self) -> bool {
        self.pending.is_some()
    }

    /// Returns true if a pending floor already supersedes the candidate floor round.
    pub(super) fn pending_supersedes(&self, round: Round) -> bool {
        matches!(&self.pending, Some(pending) if pending.finalization.round() >= round)
    }

    /// Records a verified floor finalization whose block anchor still needs to arrive.
    ///
    /// Taking or replacing the pending floor drops `aborter`, which aborts its
    /// buffer waiter.
    pub(super) fn set_pending(
        &mut self,
        finalization: Finalization<S, C>,
        aborter: Option<Aborter>,
    ) {
        self.pending = Some(Pending {
            finalization,
            _aborter: aborter,
        });
    }

    /// Takes the pending floor if `commitment` is its payload.
    #[must_use]
    pub(super) fn take_matching(&mut self, commitment: C) -> Option<Finalization<S, C>> {
        self.pending
            .take_if(|pending| pending.finalization.proposal.payload == commitment)
            .map(|pending| pending.finalization)
    }

    /// Takes the pending floor if the processed round floor covers its round.
    ///
    /// Finalized rounds and heights increase together along the finalized chain, so
    /// an anchor at a covered round sits at or below the processed height.
    #[must_use]
    pub(super) fn take_superseded(&mut self) -> Option<Finalization<S, C>> {
        let floor = self.cutoff;
        self.pending
            .take_if(|pending| floor.covers(pending.finalization.round()))
            .map(|pending| pending.finalization)
    }

    /// Returns true when the resolver request is above all processed floors.
    fn permits(&self, fetch: &Request<C>) -> bool {
        if let Some(processed) = self.processed
            && !fetch.above_height_floor(processed.height())
        {
            return false;
        }

        fetch.above_round_floor(self.cutoff)
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

    pub(super) fn fetch_targeted_if_permitted<R>(
        &self,
        resolver: &mut R,
        fetch: Request<C>,
        targets: NonEmptyVec<R::PublicKey>,
    ) -> FetchAdmission
    where
        R: TargetedResolver<Key = Key<C>, Subscriber = Annotation>,
    {
        if !self.permits(&fetch) {
            return FetchAdmission::Denied;
        }
        resolver.fetch_targeted(fetch, targets);
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
        let fetches = fetches
            .into_iter()
            .filter(|fetch| self.permits(fetch))
            .collect::<Vec<_>>();
        if fetches.is_empty() {
            return FetchAdmission::Denied;
        }
        resolver.fetch_all(fetches);
        FetchAdmission::Issued
    }
}

/// Whether floor admission issued at least one resolver fetch.
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
        marshal::resolver::handler::Finalized,
        simplex::scheme::ed25519 as simplex_ed25519,
        types::{FixedEpocher, View},
    };
    use commonware_actor::Feedback;
    use commonware_cryptography::{Signer as _, ed25519 as crypto_ed25519, sha256::Sha256};
    use commonware_math::algebra::Random as _;
    use commonware_resolver::Fetch;
    use commonware_utils::{NZU64, sync::Mutex};
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

    #[test]
    fn round_floor_orders_by_covered_rounds() {
        let epoch = Epoch::new(3);
        let last_view = Cutoff::Round(Round::new(epoch, View::new(u64::MAX)));
        let next_first = Cutoff::Round(Round::new(epoch.next(), View::zero()));

        // An epoch cutoff sits above every round of its epoch and below the next epoch.
        assert!(Cutoff::Epoch(epoch) > last_view);
        assert!(Cutoff::Epoch(epoch) < next_first);
        assert!(Cutoff::Epoch(epoch) > Cutoff::Round(Round::zero()));
        assert!(Cutoff::Epoch(Epoch::zero()) > Cutoff::zero());

        // Bounds of one kind follow their round or epoch order.
        assert!(last_view > Cutoff::Round(Round::new(epoch, View::new(7))));
        assert!(Cutoff::Epoch(epoch) < Cutoff::Epoch(epoch.next()));
        assert_eq!(
            Cutoff::Epoch(epoch).cmp(&Cutoff::Epoch(epoch)),
            Ordering::Equal
        );
        assert_eq!(Cutoff::Epoch(epoch).max(last_view), Cutoff::Epoch(epoch));
        assert_eq!(Cutoff::Epoch(epoch).max(next_first), next_first);
    }

    #[test]
    fn round_floor_covers_matches_its_order() {
        let epoch = Epoch::new(3);
        let at_round = Cutoff::Round(Round::new(epoch, View::new(10)));
        let whole_epoch = Cutoff::Epoch(epoch);
        let rounds = [
            Round::zero(),
            Round::new(
                epoch.previous().expect("epoch must have a predecessor"),
                View::new(u64::MAX),
            ),
            Round::new(epoch, View::zero()),
            Round::new(epoch, View::new(10)),
            Round::new(epoch, View::new(11)),
            Round::new(epoch, View::new(u64::MAX)),
            Round::new(epoch.next(), View::zero()),
        ];

        // A round cutoff covers its round and every earlier round.
        assert!(at_round.covers(Round::new(epoch, View::new(10))));
        assert!(!at_round.covers(Round::new(epoch, View::new(11))));
        assert!(at_round.covers(Round::new(Epoch::zero(), View::new(u64::MAX))));

        // An epoch cutoff covers every view of its epoch and nothing of the next epoch.
        assert!(whole_epoch.covers(Round::new(epoch, View::new(u64::MAX))));
        assert!(!whole_epoch.covers(Round::new(epoch.next(), View::zero())));

        // The zero cutoff covers only the zero round.
        assert!(Cutoff::zero().covers(Round::zero()));
        assert!(!Cutoff::zero().covers(Round::new(Epoch::zero(), View::new(1))));

        // Coverage equals the order against a round cutoff.
        for floor in [Cutoff::zero(), at_round, whole_epoch] {
            for round in rounds {
                assert_eq!(floor.covers(round), floor >= Cutoff::Round(round));
            }
        }
    }

    #[test]
    fn covering_round_floor_denies_its_epoch_and_admits_the_next() {
        let floor = State::<TestScheme, TestDigest>::new(
            None,
            Floor::new(
                Some(Processed::Block(Height::new(10))),
                Cutoff::Epoch(Epoch::zero()),
            ),
            round(10),
        );
        let mut resolver = TestResolver::default();

        // Every round of the covered epoch is denied, including its last view.
        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::notarized(round(40))),
            FetchAdmission::Denied
        ));
        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::notarized(round(u64::MAX))),
            FetchAdmission::Denied
        ));
        assert!(matches!(
            floor.fetch_if_permitted(
                &mut resolver,
                Request::finalized_by_round(digest(1), round(40)),
            ),
            FetchAdmission::Denied
        ));
        assert!(resolver.fetches().is_empty());

        // The next epoch's first round and height-bound requests above the floor are admitted.
        let next = Round::new(Epoch::new(1), View::zero());
        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::notarized(next)),
            FetchAdmission::Issued
        ));
        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::finalized(Height::new(11))),
            FetchAdmission::Issued
        ));
        assert_eq!(resolver.fetches().len(), 2);
    }

    #[test]
    fn closed_epoch_returns_ended_epochs_only() {
        let epocher = FixedEpocher::new(NZU64!(11));

        // Epoch zero ends at height 10. An anchor inside it closes nothing.
        assert_eq!(closed_epoch(&epocher, Height::zero()), None);
        assert_eq!(closed_epoch(&epocher, Height::new(9)), None);
        assert_eq!(closed_epoch(&epocher, Height::new(10)), Some(Epoch::zero()));

        // An anchor inside epoch one closes epoch zero, and its last block closes epoch one.
        assert_eq!(closed_epoch(&epocher, Height::new(11)), Some(Epoch::zero()));
        assert_eq!(closed_epoch(&epocher, Height::new(20)), Some(Epoch::zero()));
        assert_eq!(closed_epoch(&epocher, Height::new(21)), Some(Epoch::new(1)));

        // Heights the epocher cannot place close nothing.
        assert_eq!(closed_epoch(&epocher, Height::new(u64::MAX)), None);
    }

    fn floor() -> State<TestScheme, TestDigest> {
        State::new(
            None,
            Floor::new(
                Some(Processed::Block(Height::new(5))),
                Cutoff::Round(round(5)),
            ),
            round(5),
        )
    }

    #[test]
    fn fetch_if_permitted_applies_height_and_round_floors() {
        let floor = floor();
        let mut resolver = TestResolver::default();

        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::finalized(Height::new(5))),
            FetchAdmission::Denied
        ));
        assert!(matches!(
            floor.fetch_if_permitted(
                &mut resolver,
                Request::finalized_by_height(digest(1), Height::new(4)),
            ),
            FetchAdmission::Denied
        ));
        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::notarized(round(5))),
            FetchAdmission::Denied
        ));
        assert!(resolver.fetches().is_empty());

        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::finalized(Height::new(6))),
            FetchAdmission::Issued
        ));
        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::notarized(round(6))),
            FetchAdmission::Issued
        ));

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
                    round: request_round
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

        assert!(matches!(
            floor.fetch_targeted_if_permitted(
                &mut resolver,
                Request::finalized(Height::new(5)),
                NonEmptyVec::new(target.clone()),
            ),
            FetchAdmission::Denied
        ));
        assert!(resolver.targeted().is_empty());

        assert!(matches!(
            floor.fetch_targeted_if_permitted(
                &mut resolver,
                Request::finalized(Height::new(6)),
                NonEmptyVec::new(target),
            ),
            FetchAdmission::Issued
        ));
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

        assert!(matches!(
            floor.fetch_all_if_permitted(
                &mut resolver,
                vec![
                    Request::finalized(Height::new(5)),
                    Request::finalized(Height::new(6)),
                    Request::notarized(round(5)),
                    Request::notarized(round(6)),
                ],
            ),
            FetchAdmission::Issued
        ));

        let fetches = resolver.fetches();
        assert_eq!(fetches.len(), 2);
        assert!(matches!(fetches[0].key, Key::Finalized { height } if height == Height::new(6)));
        assert!(
            matches!(fetches[1].key, Key::Notarized { round: request_round } if request_round == round(6))
        );

        let mut resolver = TestResolver::default();
        assert!(matches!(
            floor.fetch_all_if_permitted(
                &mut resolver,
                vec![
                    Request::finalized(Height::new(5)),
                    Request::notarized(round(5)),
                ],
            ),
            FetchAdmission::Denied
        ));
        assert!(resolver.fetches().is_empty());
    }

    #[test]
    fn fetch_if_permitted_without_height_floor_allows_genesis_height() {
        let floor = State::<TestScheme, TestDigest>::new(
            None,
            Floor::new(None, Cutoff::Round(round(5))),
            round(5),
        );
        let mut resolver = TestResolver::default();

        assert!(matches!(
            floor.fetch_if_permitted(&mut resolver, Request::finalized(Height::zero())),
            FetchAdmission::Issued
        ));

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
