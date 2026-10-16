//! The public marshal mailbox, and the requests it sends the router.
//!
//! Lookups, fetches, pruning and progress go straight to the actor that answers them. Staging,
//! block subscriptions, floor installation and consensus hints go through the router, whose work
//! outlives the caller.

use super::{
    actors::{backfill, catalog, metrics::FetchReason},
    bodies::Bodies,
    relay::Staged,
    types::{Custody, Error, Floor, MarshalProgress, MaybeFloor, MaybeLqc, Reply},
};
use crate::{
    Reporter, Viewable as _,
    multimmit::{
        actors::util::ask_unreliable,
        marshal::OutputIndex,
        types::{Activity, BlockRef, Body, CertificateId, Lqc, TransactionBlock},
    },
    types::View,
};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self as actor_mailbox, Overflow, UnreliablePolicy},
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

    const fn is_resolution(&self) -> bool {
        matches!(
            self.request,
            Request::Hint {
                activity: Activity::ViewResolved { .. }
            }
        )
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

/// Most resolved views the router overflow retains.
const MAX_RETAINED_RESOLUTIONS: usize = 1024;

/// Router requests waiting for room in the router's queue, in delivery order.
pub(super) struct RouterOverflow<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    queue: VecDeque<Message<H, V, B>>,
    /// Number of retained resolved views.
    resolutions: usize,
    /// Newest resolved view offered to the overflow.
    newest_resolution: Option<View>,
}

impl<H, V, B> Default for RouterOverflow<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            resolutions: 0,
            newest_resolution: None,
        }
    }
}

impl<H, V, B> Overflow<Message<H, V, B>> for RouterOverflow<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<H, V, B>) -> Option<Message<H, V, B>>,
    {
        while let Some(message) = self.queue.pop_front() {
            let resolution = message.is_resolution();
            if let Some(message) = push(message) {
                self.queue.push_front(message);
                return;
            }
            if resolution {
                self.resolutions -= 1;
            }
        }
    }
}

/// Retains block subscriptions whose callers still wait, rejects other exact requests so their
/// callers retry, drops advisory hints, and keeps the richest finality hint of each kind, since
/// nothing else rediscovers the finality frontier.
///
/// Resolved views are retained in report order, up to [`MAX_RETAINED_RESOLUTIONS`], so their
/// openings are staged locally rather than fetched. Consensus reports views in increasing order,
/// so a resolution at or below the newest one offered is a repeat and is dropped. Beyond the
/// bound the oldest retained resolution is dropped: the synchronizer recovers a missing opening
/// from peers through the next resolution's parent commitment.
///
/// Retained subscriptions stay bounded because each holds one of its mailbox's
/// [`SubscriptionSlots`].
impl<H, V, B> UnreliablePolicy for Message<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Body<H>,
{
    type Overflow = RouterOverflow<H, V, B>;

    fn handle(overflow: &mut Self::Overflow, command: Self) -> bool {
        let activity = match &command.request {
            Request::Hint { activity } => activity,
            Request::SubscribeBlock { reply, .. } => {
                if !reply.is_closed() {
                    overflow.queue.push_back(command);
                }
                return true;
            }
            Request::StageBlock { .. } | Request::InstallFloor { .. } => return false,
        };
        if let Activity::ViewResolved { view, .. } = activity {
            if overflow.newest_resolution >= Some(*view) {
                return true;
            }
            overflow.newest_resolution = Some(*view);
            if overflow.resolutions == MAX_RETAINED_RESOLUTIONS {
                let oldest = overflow
                    .queue
                    .iter()
                    .position(Self::is_resolution)
                    .expect("retained resolutions are queued");
                overflow.queue.remove(oldest);
            } else {
                overflow.resolutions += 1;
            }
            overflow.queue.push_back(command);
            return true;
        }
        let Some(hint) = FinalityHint::classify(activity) else {
            return true;
        };
        let retained = overflow
            .queue
            .iter()
            .enumerate()
            .find_map(|(index, retained)| match &retained.request {
                Request::Hint { activity } => FinalityHint::classify(activity)
                    .filter(|retained| retained.kind == hint.kind)
                    .map(|retained| (index, retained)),
                _ => None,
            });
        if let Some((index, retained)) = retained {
            // Same-view sweeps never retreat, so hints rank by (view, swept blocks).
            if retained.rank() >= hint.rank() {
                return true;
            }
            overflow.queue.remove(index);
        }
        overflow.queue.push_back(command);
        true
    }
}

/// Kinds of reporter hints that advance the finality frontier.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HintKind {
    /// The sweep of the open view.
    Sweep,
    /// A finalized leader block.
    Lqc,
}

/// A reporter hint that advances the finality frontier.
#[derive(Clone, Copy)]
struct FinalityHint {
    kind: HintKind,
    /// View the hint speaks for.
    view: View,
    /// Sum of a sweep's final heights; zero for an L-QC.
    swept: u128,
}

impl FinalityHint {
    /// Classifies `activity`, returning `None` for hints that do not advance finality.
    fn classify<V: Variant, D: Digest>(activity: &Activity<V, D>) -> Option<Self> {
        match activity {
            Activity::ViewSweep { view, finals, .. } => Some(Self {
                kind: HintKind::Sweep,
                view: *view,
                swept: finals
                    .iter()
                    .map(|tip| u128::from(tip.height().get()))
                    .sum(),
            }),
            Activity::LeaderFinalized { lqc, .. } => Some(Self {
                kind: HintKind::Lqc,
                view: lqc.view(),
                swept: 0,
            }),
            _ => None,
        }
    }

    /// Returns the rank that orders hints of one kind.
    const fn rank(&self) -> (View, u128) {
        (self.view, self.swept)
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
    max_pending_acks: NonZeroUsize,
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
            max_pending_acks: self.max_pending_acks,
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
        max_pending_acks: NonZeroUsize,
    ) -> Self {
        Self {
            router,
            catalog,
            bodies,
            backfill,
            subscriptions,
            staged,
            max_pending_acks,
        }
    }

    /// Returns the most delivered outputs that may await application acknowledgement at once.
    pub const fn max_pending_acks(&self) -> NonZeroUsize {
        self.max_pending_acks
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
    /// This does not start a peer fetch. A header that consensus adopts without its body makes
    /// backfill fetch the block from peers, which also completes this subscription.
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

    /// Gets the retained floor with the highest index at or below `at`, with that index.
    ///
    /// Only durably committed floors are returned. Another node can resume from the floor with
    /// [`Self::install_floor`], which verifies it, and then receives the outputs after its
    /// index. Returns `None` if no floor at or below `at` is retained.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.floor_at", level = "debug", skip_all)]
    pub async fn floor_at(&self, at: OutputIndex) -> Result<MaybeFloor<V, H::Digest>, Error> {
        self.catalog.floor_at(at).await.map_err(Error::from)
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

    /// Prunes what the newest retained floor at or below `below` makes obsolete.
    ///
    /// That floor, and every output after it, stay retained: [`Self::floor_at`] still answers
    /// for every index from `below` on, and peers that install the floor can fetch every later
    /// output. So does each chain's newest block at or below the floor, which the chain's next
    /// block builds on. Unacknowledged outputs are never pruned, because `below` is
    /// first lowered to the acknowledgement cursor. Indices are canonical across floor
    /// installations, so a delayed request cannot prune data a newer floor still needs.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.prune", level = "info", skip_all)]
    pub async fn prune(&self, below: OutputIndex) -> Result<(), Error> {
        self.catalog.prune(below).await.map_err(Error::from)
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
        // `Message::new` captures the caller's span, so the router links its work back to it.
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
            types::{ChainId, ChainSet, Context, HistoryRecord, Resolution},
        },
        simplex::marshal::mocks::block::EmptyBlock,
        types::{Epoch, Height},
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

    /// Returns the sweep of `view` with every chain final up to `height`.
    fn sweep(view: u64, height: u64) -> Activity<MinPk, Sha256Digest> {
        let finals = (0..2)
            .map(|chain| {
                BlockRef::new(
                    ChainId::new(chain),
                    Height::new(height),
                    Sha256::hash(&[&height.to_be_bytes()]),
                )
            })
            .collect();
        Activity::ViewSweep {
            view: View::new(view),
            finals,
            settled: ChainSet::empty(2),
        }
    }

    /// Offers a hint to the overflow, returning whether the policy handled it.
    fn offer(
        overflow: &mut RouterOverflow<Sha256, MinPk, EmptyBlock<Sha256>>,
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
    fn pressure_retains_only_the_newest_sweep() {
        let mut overflow = RouterOverflow::default();
        for view in [5u64, 9, 7] {
            assert!(offer(&mut overflow, sweep(view, 4)));
        }
        assert_eq!(overflow.queue.len(), 1);
        let Activity::ViewSweep { view, .. } = retained(&overflow.queue[0]) else {
            panic!("the newest sweep is retained");
        };
        assert_eq!(*view, View::new(9));
    }

    #[test]
    fn pressure_keeps_the_furthest_same_view_sweep() {
        let mut overflow = RouterOverflow::default();
        offer(&mut overflow, sweep(5, 41));
        // A same-view sweep that reaches further supersedes the earlier one.
        offer(&mut overflow, sweep(5, 47));
        assert_eq!(overflow.queue.len(), 1);
        assert_eq!(retained(&overflow.queue[0]), &sweep(5, 47));
        // A late, shorter sweep of the same view does not evict the further one.
        offer(&mut overflow, sweep(5, 41));
        assert_eq!(overflow.queue.len(), 1);
        assert_eq!(retained(&overflow.queue[0]), &sweep(5, 47));
    }

    #[test]
    fn pressure_retains_resolutions_and_one_hint_per_finality_kind() {
        let committee = Committee::<MinPk>::builder(8, 6).build();
        let genesis = committee.config.genesis();
        let opening =
            Arc::new(HistoryRecord::new(genesis.history(), genesis.tips().to_vec()).unwrap());
        let lqc = |view| Activity::LeaderFinalized {
            lqc: Arc::new(committee.lqc(view)),
            opening: Arc::clone(&opening),
        };
        let resolution = |view| Activity::ViewResolved {
            view: View::new(view),
            base: genesis.tips().into(),
            tips: genesis.tips().into(),
            commitment: opening.commitment::<Sha256>(),
            parent_commitment: genesis.history(),
            by: Resolution::Determined,
        };
        let mut overflow = RouterOverflow::default();
        for hint in [
            sweep(5, 4),
            resolution(3),
            lqc(View::new(3)),
            lqc(View::new(4)),
            resolution(4),
            sweep(4, 4),
        ] {
            assert!(offer(&mut overflow, hint));
        }
        assert_eq!(overflow.queue.len(), 4);
        let Activity::ViewSweep { view, .. } = retained(&overflow.queue[0]) else {
            panic!("the newest sweep is retained");
        };
        assert_eq!(*view, View::new(5));
        let Activity::LeaderFinalized { lqc, .. } = retained(&overflow.queue[2]) else {
            panic!("the newest L-QC is retained");
        };
        assert_eq!(lqc.view(), View::new(4));
        // Resolved views are retained in report order.
        let resolved = [1, 3].map(|index| match retained(&overflow.queue[index]) {
            Activity::ViewResolved { view, .. } => *view,
            _ => panic!("resolutions are retained"),
        });
        assert_eq!(resolved, [View::new(3), View::new(4)]);
        // A repeated or older resolution is dropped.
        assert!(offer(&mut overflow, resolution(4)));
        assert!(offer(&mut overflow, resolution(2)));
        assert_eq!(overflow.queue.len(), 4);

        // Delivered resolutions free their retention; past the bound the oldest is dropped.
        overflow.drain(|_| None);
        assert!(overflow.queue.is_empty());
        for view in 5..=5 + MAX_RETAINED_RESOLUTIONS as u64 {
            assert!(offer(&mut overflow, resolution(view)));
        }
        assert_eq!(overflow.queue.len(), MAX_RETAINED_RESOLUTIONS);
        let Activity::ViewResolved { view, .. } = retained(&overflow.queue[0]) else {
            panic!("resolutions are retained");
        };
        assert_eq!(*view, View::new(6));
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
        let mut overflow = RouterOverflow::default();
        let handled = <TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            TestCommand::new(Request::StageBlock { block, reply }),
        );

        assert!(!handled);
        assert!(overflow.queue.is_empty());
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
        let mut overflow = RouterOverflow::default();
        assert!(<TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            command
        ));
        assert_eq!(overflow.queue.len(), 1);
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
        assert_eq!(overflow.queue.len(), 1);
        assert_eq!(*slots.available.lock(), 1);
    }

    #[test]
    fn abandoned_subscriptions_keep_the_backlog_bounded() {
        let slots = Arc::new(SubscriptionSlots::new(NZUsize!(2)));
        let mut overflow = RouterOverflow::default();
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
            assert!(overflow.queue.len() <= 2);
        }
        assert_eq!(overflow.queue.len(), 2);
        assert!(slots.acquire().now_or_never().is_none());

        // Taking the abandoned requests returns their slots.
        overflow.queue.clear();
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
