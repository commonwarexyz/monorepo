//! The public marshal mailbox, and the requests it sends the router.
//!
//! Lookups, fetches, pruning and progress go straight to the actor that answers them. Staging,
//! block subscriptions, floor installation and consensus hints go through the router, whose work
//! outlives the caller.

use super::{
    actors::{backfill, catalog, metrics::FetchReason},
    bodies::Bodies,
    relay::Staged,
    types::{Custody, Error, Floor, MarshalProgress, MaybeLqc, Prune, Reply},
};
use crate::{
    Reporter, Viewable as _,
    multimmit::{
        actors::util::ask_unreliable,
        types::{Activity, Artifact, BlockRef, Body, CertificateId, Lqc, TransactionBlock},
    },
    types::View,
};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self as actor_mailbox, UnreliablePolicy},
};
use commonware_cryptography::{Digest, Hasher, bls12381::primitives::variant::Variant};
use commonware_utils::sync::{Mutex, Notify};
use std::{collections::VecDeque, num::NonZeroUsize, pin::pin, sync::Arc};
use tracing::Span;

/// A router request, processed under the caller's span.
pub(super) struct Message<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) span: Span,
    pub(super) request: Request<H, V, B>,
}

/// Work the router runs on the caller's behalf.
pub(super) enum Request<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Advisory consensus activity.
    Hint { activity: Activity<V, H::Digest> },
    /// Stages a producer block and replies with the completion of its durable custody.
    StageBlock {
        block: Arc<TransactionBlock<H, B>>,
        reply: Reply<Custody, Error>,
    },
    /// Replies with the block named by `reference` once it is durable custody.
    SubscribeBlock {
        reference: BlockRef<H::Digest>,
        reply: Reply<Arc<TransactionBlock<H, B>>, Error>,
        /// The caller's slot, held until the router drops the caller.
        slot: SubscriptionSlot,
    },
    /// Verifies and installs a state-sync floor.
    InstallFloor {
        floor: Floor<V, H::Digest>,
        reply: Reply<(), Error>,
    },
}

impl<H, V, B> Message<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) fn new(request: Request<H, V, B>) -> Self {
        Self {
            span: Span::current(),
            request,
        }
    }
}

impl<H, V, B> Request<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    /// Returns the stable request label for the request that triggered a router drain.
    pub(super) const fn kind(&self) -> &'static str {
        match self {
            Self::Hint { .. } => "hint",
            Self::StageBlock { .. } => "stage_block",
            Self::SubscribeBlock { .. } => "subscribe_block",
            Self::InstallFloor { .. } => "install_floor",
        }
    }
}

/// Retains block subscriptions whose callers still wait, rejects other exact requests so their
/// callers retry, drops advisory hints, and keeps the richest finality hint of each kind, since
/// nothing else rediscovers the finality frontier.
///
/// Retained subscriptions stay bounded because each holds one of its mailbox's
/// [`SubscriptionSlots`].
impl<H, V, B> UnreliablePolicy for Message<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, command: Self) -> bool {
        let activity = match &command.request {
            Request::Hint { activity } => activity,
            Request::SubscribeBlock { reply, .. } => {
                if !reply.is_closed() {
                    overflow.push_back(command);
                }
                return true;
            }
            Request::StageBlock { .. } | Request::InstallFloor { .. } => return false,
        };
        let Some(hint) = FinalityHint::classify(activity) else {
            return true;
        };
        let retained = overflow
            .iter()
            .enumerate()
            .find_map(|(position, retained)| match &retained.request {
                Request::Hint { activity } => FinalityHint::classify(activity)
                    .filter(|retained| retained.kind == hint.kind)
                    .map(|retained| (position, retained)),
                _ => None,
            });
        if let Some((position, retained)) = retained {
            // A same-view finality update carries more votes, so hints rank by (view, votes).
            if retained.rank() >= hint.rank() {
                return true;
            }
            overflow.remove(position);
        }
        overflow.push_back(command);
        true
    }
}

/// Kinds of reporter hints that advance the finality frontier.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HintKind {
    /// A leader finality fact.
    Finality,
    /// An accepted L-QC.
    Lqc,
}

/// A reporter hint that advances the finality frontier.
#[derive(Clone, Copy)]
struct FinalityHint {
    kind: HintKind,
    /// View the hint speaks for.
    view: View,
    /// Votes carried by a finality fact; zero for an L-QC.
    votes: usize,
}

impl FinalityHint {
    /// Classifies `activity`, returning `None` for hints that do not advance finality.
    fn classify<V: Variant, D: Digest>(activity: &Activity<V, D>) -> Option<Self> {
        match activity {
            Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } => {
                Some(Self {
                    kind: HintKind::Finality,
                    view: fact.round().view(),
                    votes: fact.votes(),
                })
            }
            Activity::ProtocolAccepted { artifact, .. } => match artifact.as_ref() {
                Artifact::Lqc(proof) => Some(Self {
                    kind: HintKind::Lqc,
                    view: proof.view(),
                    votes: 0,
                }),
                _ => None,
            },
            _ => None,
        }
    }

    /// Returns the rank that orders hints of one kind.
    const fn rank(&self) -> (View, usize) {
        (self.view, self.votes)
    }
}

/// Bounds the block subscriptions a mailbox and its clones have in flight.
///
/// The router retains a subscription it cannot take yet instead of rejecting it, so this bound
/// keeps that backlog finite: a caller past it waits for another subscription to end. A slot
/// travels with its request and is released only when the router drops the caller, so queued
/// and registered subscriptions together never exceed the router's caller bound.
pub(super) struct SubscriptionSlots {
    available: Mutex<usize>,
    released: Notify,
}

impl SubscriptionSlots {
    /// Creates `capacity` slots.
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            available: Mutex::new(capacity.get()),
            released: Notify::new(),
        }
    }

    /// Waits for a free slot and holds it until the returned guard drops.
    async fn acquire(self: &Arc<Self>) -> SubscriptionSlot {
        loop {
            let mut released = pin!(self.released.notified());
            // Registered before the check, so every release after it wakes a distinct waiter.
            released.as_mut().enable();
            {
                let mut available = self.available.lock();
                if *available > 0 {
                    *available -= 1;
                    return SubscriptionSlot(Arc::clone(self));
                }
            }
            released.await;
        }
    }
}

/// One held subscription slot, released on drop.
pub(super) struct SubscriptionSlot(Arc<SubscriptionSlots>);

impl Drop for SubscriptionSlot {
    fn drop(&mut self) {
        *self.0.available.lock() += 1;
        self.0.released.notify_one();
    }
}

/// Cloneable public ingress for a Multimmit marshal service.
pub struct Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    router: actor_mailbox::UnreliableSender<Message<H, V, B>>,
    catalog: catalog::Mailbox<H, V, B>,
    bodies: Bodies<H, V, B>,
    backfill: backfill::Mailbox<H, V, B>,
    subscriptions: Arc<SubscriptionSlots>,
    /// Blocks staged through this mailbox, kept for the [`Relay`](super::Relay) when one exists.
    staged: Option<Arc<Mutex<Staged<H, B>>>>,
}

impl<H, V, B> Clone for Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    fn clone(&self) -> Self {
        Self {
            router: self.router.clone(),
            catalog: self.catalog.clone(),
            bodies: self.bodies.clone(),
            backfill: self.backfill.clone(),
            subscriptions: Arc::clone(&self.subscriptions),
            staged: self.staged.clone(),
        }
    }
}

impl<H, V, B> Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    pub(super) const fn new(
        router: actor_mailbox::UnreliableSender<Message<H, V, B>>,
        catalog: catalog::Mailbox<H, V, B>,
        bodies: Bodies<H, V, B>,
        backfill: backfill::Mailbox<H, V, B>,
        subscriptions: Arc<SubscriptionSlots>,
        staged: Option<Arc<Mutex<Staged<H, B>>>>,
    ) -> Self {
        Self {
            router,
            catalog,
            bodies,
            backfill,
            subscriptions,
            staged,
        }
    }

    /// Sends a request to the router, failing with [`Error::Busy`] when its queue rejects it.
    async fn route<T>(
        &self,
        request: impl FnOnce(Reply<T, Error>) -> Request<H, V, B>,
    ) -> Result<T, Error> {
        ask_unreliable(
            |request| self.router.enqueue(Message::new(request)),
            request,
            Error::Closed,
            Error::Busy,
        )
        .await
    }

    /// Stages one complete producer block without broadcasting it.
    ///
    /// The returned token resolves after the block is durably recoverable. Accepted storage work
    /// continues if the token is dropped. With a [`Relay`](super::Relay), a staged block also
    /// becomes available for it to broadcast.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.stage_block",
        level = "info",
        skip_all
    )]
    pub async fn stage_block(
        &self,
        block: impl Into<Arc<TransactionBlock<H, B>>>,
    ) -> Result<Custody, Error> {
        let block = block.into();
        let relayed = self.staged.as_ref().map(|_| Arc::clone(&block));
        let custody = self
            .route(|reply| Request::StageBlock { block, reply })
            .await?;
        if let (Some(staged), Some(block)) = (&self.staged, relayed) {
            staged.lock().insert(block);
        }
        Ok(custody)
    }

    /// Durably submits one complete producer block without broadcasting it.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.put_block", level = "info", skip_all)]
    pub async fn put_block(
        &self,
        block: impl Into<Arc<TransactionBlock<H, B>>>,
    ) -> Result<(), Error> {
        self.stage_block(block).await?.wait().await
    }

    /// Gets a locally admitted L-QC without initiating network work.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.get_certificate",
        level = "debug",
        skip_all
    )]
    pub async fn get_certificate(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<MaybeLqc<V, H::Digest>, Error> {
        self.catalog.lqc(id).await.map_err(Error::from)
    }

    /// Fetches an L-QC locally or from peers. Drop the future to cancel the request.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.fetch_certificate",
        level = "info",
        skip_all
    )]
    pub async fn fetch_certificate(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<Arc<Lqc<V, H::Digest>>, Error> {
        self.backfill
            .lqc(FetchReason::Explicit, id)
            .await
            .map_err(Error::from)
    }

    /// Gets a locally admitted producer block without initiating network work.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.get_block",
        level = "debug",
        skip_all
    )]
    pub async fn get_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        self.bodies.block(reference).await.map_err(Error::from)
    }

    /// Fetches a producer block locally or from peers. Drop the future to cancel it.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.fetch_block",
        level = "info",
        skip_all
    )]
    pub async fn fetch_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        self.backfill
            .block(FetchReason::Explicit, reference)
            .await
            .map_err(Error::from)
    }

    /// Establishes durable custody of a block from buffered ingress or local storage.
    ///
    /// This does not start a peer fetch. Accepted data-availability evidence may independently
    /// complete the subscription through backfill.
    ///
    /// When the marshal already has as many subscriptions in flight as it serves at once, this
    /// waits for one of them to end instead of failing with [`Error::Busy`].
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.subscribe_block",
        level = "info",
        skip_all
    )]
    pub async fn subscribe_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        let slot = self.subscriptions.acquire().await;
        let block = self
            .route(|reply| Request::SubscribeBlock {
                reference,
                reply,
                slot,
            })
            .await?;
        if let Some(staged) = &self.staged {
            staged.lock().remember(Arc::clone(&block));
        }
        Ok(block)
    }

    /// Verifies and installs a state-sync floor before allowing its prefix to be pruned.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.install_floor",
        level = "info",
        skip_all
    )]
    pub async fn install_floor(&self, floor: Floor<V, H::Digest>) -> Result<(), Error> {
        self.route(|reply| Request::InstallFloor { floor, reply })
            .await
    }

    /// Requests pruning for one already installed floor generation.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.prune", level = "info", skip_all)]
    pub async fn prune(&self, request: Prune) -> Result<(), Error> {
        self.catalog
            .prune(request.floor_generation())
            .await
            .map_err(Error::from)
    }

    /// Returns marshal's compact durable progress.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.progress", level = "debug", skip_all)]
    pub async fn progress(&self) -> Result<MarshalProgress<H::Digest>, Error> {
        self.catalog.progress().await.map_err(Error::from)
    }
}

impl<H, V, B> Reporter for Mailbox<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Activity = Activity<V, H::Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // No span here: hints are fire-and-forget, the enqueue never awaits, and `Message::new`
        // already snapshots `Span::current()` so the router can link back to the caller.
        match self
            .router
            .enqueue(Message::new(Request::Hint { activity }))
        {
            Unreliable::Outcome(feedback) => feedback,
            Unreliable::Rejected => Feedback::Backoff,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        multimmit::{
            mocks::Committee,
            types::{ArtifactId, ChainId, Context, FinalityFact, FinalityId, PathLimits},
        },
        simplex::marshal::mocks::block::EmptyBlock,
        types::{Epoch, Height, Round},
    };
    use commonware_cryptography::{
        Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{NZUsize, channel::oneshot};
    use futures::FutureExt as _;
    use std::time::Duration;

    type TestCommand = Message<Sha256, MinPk, EmptyBlock<Sha256>>;

    fn fact(view: u64, votes: usize) -> FinalityFact<Sha256Digest> {
        FinalityFact::new(
            FinalityId::Lqc(ArtifactId::new(Sha256::hash(&[&view.to_be_bytes()]))),
            Round::new(Epoch::new(1), View::new(view)),
            Sha256::hash(&[b"leader"]),
            CertificateId::new(Sha256::hash(&[b"parent"])),
            votes,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    /// Offers a hint to the overflow, returning whether the policy handled it.
    fn offer(
        overflow: &mut VecDeque<TestCommand>,
        activity: Activity<MinPk, Sha256Digest>,
    ) -> bool {
        <TestCommand as UnreliablePolicy>::handle(
            overflow,
            TestCommand::new(Request::Hint { activity }),
        )
    }

    /// Returns the activity of a retained hint.
    fn retained(command: &TestCommand) -> &Activity<MinPk, Sha256Digest> {
        let Request::Hint { activity } = &command.request else {
            panic!("only hints are retained");
        };
        activity
    }

    #[test]
    fn pressure_retains_only_the_newest_finality_fact() {
        let mut overflow = VecDeque::new();
        for view in [5u64, 9, 7] {
            assert!(offer(
                &mut overflow,
                Activity::LeaderFinalized {
                    fact: fact(view, 4),
                },
            ));
        }
        assert_eq!(overflow.len(), 1);
        let Activity::LeaderFinalized { fact } = retained(&overflow[0]) else {
            panic!("the newest finality fact is retained");
        };
        assert_eq!(fact.round().view(), View::new(9));
    }

    #[test]
    fn pressure_keeps_the_latest_same_view_advance() {
        let mut overflow = VecDeque::new();
        // A LeaderFinalized for view 5 with a bare quorum of votes is retained first.
        offer(
            &mut overflow,
            Activity::LeaderFinalized { fact: fact(5, 41) },
        );
        // A same-view advance carries more votes (extension settlement); it must supersede the
        // earlier finalized rather than be dropped.
        offer(
            &mut overflow,
            Activity::LeaderFinalityUpdated { fact: fact(5, 47) },
        );
        assert_eq!(overflow.len(), 1);
        let Activity::LeaderFinalityUpdated { fact: kept } = retained(&overflow[0]) else {
            panic!("the same-view advance must be retained over the earlier finalized");
        };
        assert_eq!(kept.votes(), 47, "the richer same-view fact is kept");
        // A late, stale finalized for the same view (fewer votes) must NOT evict the richer advance.
        offer(
            &mut overflow,
            Activity::LeaderFinalized { fact: fact(5, 41) },
        );
        assert_eq!(overflow.len(), 1);
        let Activity::LeaderFinalityUpdated { fact: kept } = retained(&overflow[0]) else {
            panic!("a stale same-view finalized must not evict the richer advance");
        };
        assert_eq!(
            kept.votes(),
            47,
            "content comparison is arrival-order independent"
        );
    }

    #[test]
    fn pressure_retains_one_hint_per_finality_kind() {
        let committee = Committee::<MinPk>::builder(8, 6)
            .limits(PathLimits::new(4, 0).unwrap())
            .build();
        let lqc = |view| {
            let artifact = Arc::new(Artifact::Lqc(committee.lqc(view)));
            Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }
        };
        let mut overflow = VecDeque::new();
        for hint in [
            Activity::LeaderFinalized { fact: fact(5, 4) },
            lqc(View::new(3)),
            lqc(View::new(4)),
            Activity::LeaderFinalized { fact: fact(4, 4) },
        ] {
            assert!(offer(&mut overflow, hint));
        }
        assert_eq!(overflow.len(), 2);
        let Activity::LeaderFinalized { fact } = retained(&overflow[0]) else {
            panic!("the newest finality fact is retained");
        };
        assert_eq!(fact.round().view(), View::new(5));
        let Activity::ProtocolAccepted { artifact, .. } = retained(&overflow[1]) else {
            panic!("the newest L-QC is retained");
        };
        let Artifact::Lqc(proof) = artifact.as_ref() else {
            panic!("the retained hint is an L-QC");
        };
        assert_eq!(proof.view(), View::new(4));
    }

    #[test]
    fn pressure_rejects_staging() {
        let (reply, mut response) = oneshot::channel();
        let context = Context::new(
            Epoch::new(1),
            ChainId::new(0),
            Height::new(1),
            Sha256::hash(&[b"parent"]),
        )
        .unwrap();
        let body = EmptyBlock::<Sha256>::new(Sha256::hash(&[b"body parent"]), Height::new(1), 0);
        let block = Arc::new(TransactionBlock::from_context(context, body));
        let mut overflow = VecDeque::new();
        let handled = <TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            TestCommand::new(Request::StageBlock { block, reply }),
        );

        assert!(!handled);
        assert!(overflow.is_empty());
        assert!(matches!(
            response.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
    }

    /// A subscription caller's response.
    type Response =
        oneshot::Receiver<Result<Arc<TransactionBlock<Sha256, EmptyBlock<Sha256>>>, Error>>;

    /// Returns a subscription request holding `slot`, and its caller's response.
    fn subscription(slot: SubscriptionSlot) -> (TestCommand, Response) {
        let (reply, response) = oneshot::channel();
        let reference = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"block"]));
        let request = Request::SubscribeBlock {
            reference,
            reply,
            slot,
        };
        (TestCommand::new(request), response)
    }

    #[test]
    fn pressure_retains_subscriptions() {
        let slots = Arc::new(SubscriptionSlots::new(NZUsize!(2)));
        let (command, mut response) = subscription(slots.acquire().now_or_never().unwrap());
        let mut overflow = VecDeque::new();
        assert!(<TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            command
        ));
        assert_eq!(overflow.len(), 1);
        assert!(matches!(
            response.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));

        // A subscription whose caller left is dropped, returning its slot.
        let (command, abandoned) = subscription(slots.acquire().now_or_never().unwrap());
        drop(abandoned);
        assert!(<TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            command
        ));
        assert_eq!(overflow.len(), 1);
        assert_eq!(*slots.available.lock(), 1);
    }

    #[test]
    fn abandoned_subscriptions_keep_the_backlog_bounded() {
        let slots = Arc::new(SubscriptionSlots::new(NZUsize!(2)));
        let mut overflow = VecDeque::new();
        // Callers that leave after their request is retained keep their slots until the router
        // takes the request, so a cancel storm cannot grow the backlog past the slots.
        for _ in 0..16 {
            let Some(slot) = slots.acquire().now_or_never() else {
                continue;
            };
            let (command, response) = subscription(slot);
            assert!(<TestCommand as UnreliablePolicy>::handle(
                &mut overflow,
                command
            ));
            drop(response);
            assert!(overflow.len() <= 2);
        }
        assert_eq!(overflow.len(), 2);
        assert!(slots.acquire().now_or_never().is_none());

        // Taking the abandoned requests returns their slots.
        overflow.clear();
        assert_eq!(*slots.available.lock(), 2);
        assert!(slots.acquire().now_or_never().is_some());
    }

    #[test]
    fn subscription_slots_wake_every_waiter() {
        deterministic::Runner::default().start(|context| async move {
            let slots = Arc::new(SubscriptionSlots::new(NZUsize!(2)));
            let held = [slots.acquire().await, slots.acquire().await];
            let waiters = [1, 2].map(|_| {
                let slots = Arc::clone(&slots);
                context
                    .child("waiter")
                    .spawn(move |_| async move { slots.acquire().await })
            });
            context.sleep(Duration::from_millis(1)).await;
            assert_eq!(*slots.available.lock(), 0);

            // Two releases wake both waiters.
            drop(held);
            for waiter in waiters {
                let _slot = waiter.await.expect("waiter receives a slot");
            }
            assert_eq!(*slots.available.lock(), 2);
        });
    }

    #[test]
    fn subscription_slots_wait_for_a_release() {
        deterministic::Runner::default().start(|context| async move {
            let slots = Arc::new(SubscriptionSlots::new(NonZeroUsize::MIN));
            let held = slots.acquire().await;
            let mut waiting = Box::pin(slots.acquire());
            commonware_macros::select! {
                _ = &mut waiting => panic!("a slot was granted past capacity"),
                () = context.sleep(Duration::from_millis(1)) => {},
            }
            drop(held);
            let _slot = waiting.await;
            assert_eq!(*slots.available.lock(), 0);
        });
    }
}
