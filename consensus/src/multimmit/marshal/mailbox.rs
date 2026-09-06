//! Public ingress for the Multimmit marshal service.

use super::types::OutputIndex;
use crate::{
    Reporter, Viewable as _,
    multimmit::{
        machine::Artifact,
        types::{Activity, BlockRef, CertificateId, Context, Lqc, TipRecord, TransactionBlock},
    },
    types::View,
};
use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self as actor_mailbox, UnreliablePolicy},
};
use commonware_broadcast::buffered;
use commonware_codec::Codec;
use commonware_cryptography::{
    Digest, Digestible, Hasher, PublicKey, bls12381::primitives::variant::Variant,
};
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_runtime::Metrics as RuntimeMetrics;
use commonware_utils::channel::oneshot;
use std::{collections::VecDeque, num::NonZeroUsize, sync::Arc};
use tracing::Span;

/// A public marshal request failed.
#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    /// The marshal service has reached its configured ingress capacity.
    #[error("marshal service is busy")]
    Busy,
    /// The marshal service is no longer accepting work.
    #[error("marshal service is closed")]
    Closed,
    /// The request violates a marshal invariant.
    #[error("invalid marshal request: {0}")]
    Invalid(&'static str),
    /// A child component could not complete the request.
    #[error("marshal request failed: {0}")]
    Failed(Arc<str>),
}

impl Error {
    pub(super) fn failed(error: impl std::fmt::Display) -> Self {
        Self::Failed(Arc::from(error.to_string()))
    }
}

/// Completion of one staged producer block's durable custody.
///
/// Staging makes the block available to marshal and allows its storage work to coalesce with
/// adjacent admissions. The block is crash-recoverable only after [`Custody::wait`] succeeds.
#[must_use = "producer-block custody is not established until the token completes"]
pub struct Custody(oneshot::Receiver<Result<(), Error>>);

impl Custody {
    pub(super) fn channel() -> (oneshot::Sender<Result<(), Error>>, Self) {
        let (sender, receiver) = oneshot::channel();
        (sender, Self(receiver))
    }

    /// Waits until the exact staged block is durably recoverable.
    pub async fn wait(self) -> Result<(), Error> {
        self.0.await.unwrap_or(Err(Error::Closed))
    }
}

/// A state-sync checkpoint from which marshal can resume ordering.
///
/// The application snapshot is assumed to contain every block through `emitted`. Marshal verifies
/// the proof, history opening, and frontiers before installing the checkpoint. Output indices are
/// deliberately absent because they are local and monotone across floor installations.
#[derive(Clone, Debug)]
pub struct FloorCheckpoint<V: Variant, D: Digest> {
    pub(super) anchor_id: CertificateId<D>,
    pub(super) anchor: Arc<Lqc<V, D>>,
    pub(super) history: Arc<TipRecord<D>>,
    pub(super) emitted: Vec<BlockRef<D>>,
}

impl<V: Variant, D: Digest> FloorCheckpoint<V, D> {
    /// Creates a candidate floor. The marshal service authenticates it before installation.
    pub const fn new(
        anchor_id: CertificateId<D>,
        anchor: Arc<Lqc<V, D>>,
        history: Arc<TipRecord<D>>,
        emitted: Vec<BlockRef<D>>,
    ) -> Self {
        Self {
            anchor_id,
            anchor,
            history,
            emitted,
        }
    }
}

/// A request to prune data made obsolete by an installed floor generation.
///
/// Naming the generation prevents a delayed request from pruning data selected by a newer floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prune {
    generation: u64,
}

impl Prune {
    /// Creates a pruning request for an installed floor generation.
    pub const fn new(generation: u64) -> Self {
        Self { generation }
    }

    /// Returns the floor generation authorized by the request.
    pub const fn generation(self) -> u64 {
        self.generation
    }
}

/// Marshal's compact durable progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Progress<D: Digest> {
    /// Active state-sync generation.
    pub generation: u64,
    /// Exact retained LQC floor anchor.
    pub floor: CertificateId<D>,
    /// Highest durably committed dense output.
    pub committed: Option<OutputIndex>,
    /// Highest durably acknowledged dense output.
    pub acknowledged: Option<OutputIndex>,
}

type Reply<T> = oneshot::Sender<Result<T, Error>>;
type MaybeLqc<V, D> = Option<Arc<Lqc<V, D>>>;

/// Requests owned by the marshal service rather than its storage or transport children.
pub(super) struct Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    pub(super) span: Span,
    pub(super) request: Request<H, V, B>,
}

pub(super) enum Request<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    Hint(Activity<V, H::Digest>),
    StageBlock(Arc<TransactionBlock<H, B>>, Reply<Custody>),
    GetCertificate(CertificateId<H::Digest>, Reply<MaybeLqc<V, H::Digest>>),
    FetchCertificate(CertificateId<H::Digest>, Reply<Arc<Lqc<V, H::Digest>>>),
    GetBlock(
        BlockRef<H::Digest>,
        Reply<Option<Arc<TransactionBlock<H, B>>>>,
    ),
    FetchBlock(BlockRef<H::Digest>, Reply<Arc<TransactionBlock<H, B>>>),
    SubscribeBlock(BlockRef<H::Digest>, Reply<Arc<TransactionBlock<H, B>>>),
    InstallFloor(FloorCheckpoint<V, H::Digest>, Reply<()>),
    Prune(Prune, Reply<()>),
    Progress(Reply<Progress<H::Digest>>),
}

impl<H, V, B> Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
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
    B: Codec + Digestible<Digest = H::Digest>,
{
    /// Returns the stable request label for the command that triggered a router drain.
    pub(super) const fn kind(&self) -> &'static str {
        match self {
            Self::Hint(_) => "hint",
            Self::StageBlock(_, _) => "stage_block",
            Self::GetCertificate(_, _) => "get_certificate",
            Self::FetchCertificate(_, _) => "fetch_certificate",
            Self::GetBlock(_, _) => "get_block",
            Self::FetchBlock(_, _) => "fetch_block",
            Self::SubscribeBlock(_, _) => "subscribe_block",
            Self::InstallFloor(_, _) => "install_floor",
            Self::Prune(_, _) => "prune",
            Self::Progress(_) => "progress",
        }
    }
}

impl<H, V, B> UnreliablePolicy for Command<H, V, B>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
{
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, command: Self) -> bool {
        // Exact requests must be retried by their caller rather than retained beyond the
        // configured ingress capacity.
        let Request::Hint(activity) = &command.request else {
            return false;
        };
        // Finality hints drive the synchronizer's emission and nothing else re-discovers the
        // finality frontier, so they survive pressure: keep the newest per kind. Other hints are
        // advisory; missing history is recovered through backfill.
        let Some((kind, view, richness)) = finality_hint(activity) else {
            return true;
        };
        if let Some(position) = overflow.iter().position(|retained| {
            matches!(&retained.request, Request::Hint(retained) if finality_hint(retained).is_some_and(|(retained_kind, ..)| retained_kind == kind))
        }) {
            let Request::Hint(retained) = &overflow[position].request else {
                unreachable!("the retained command was matched as a hint");
            };
            // Keep the fact that dominates by (view, settlement), where settlement is the vote
            // count a finality fact carries. A LeaderFinalityUpdated advance shares the view of the
            // LeaderFinalized it supersedes but carries more votes, so a plain view comparison would
            // drop the settling advance under ingress pressure and strand the ordering sweep on
            // unsettled tips. Comparing (view, votes) keeps the richer fact regardless of arrival
            // order; FinalityFact is self-contained and both variants route identically, so
            // replacing the stale entry is safe.
            let dominates = finality_hint(retained)
                .is_some_and(|(_, retained_view, retained_richness)| {
                    (retained_view, retained_richness) >= (view, richness)
                });
            if dominates {
                return true;
            }
            overflow.remove(position);
        }
        overflow.push_back(command);
        true
    }
}

/// Classifies a reporter hint that advances the finality frontier: `0` for a finality fact, `1`
/// for an L-QC, with the view it speaks for.
fn finality_hint<V: Variant, D: Digest>(activity: &Activity<V, D>) -> Option<(u8, View, usize)> {
    match activity {
        Activity::LeaderFinalized { fact } | Activity::LeaderFinalityUpdated { fact } => {
            Some((0, fact.round().view(), fact.votes()))
        }
        Activity::ProtocolAccepted { artifact, .. } => match artifact.as_ref() {
            Artifact::Lqc(proof) => Some((1, proof.view(), 0)),
            _ => None,
        },
        _ => None,
    }
}

/// Cloneable public ingress for a Multimmit marshal service.
pub struct Mailbox<H, V, B, P>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    P: PublicKey,
{
    sender: actor_mailbox::UnreliableSender<Command<H, V, B>>,
    broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
}

impl<H, V, B, P> Clone for Mailbox<H, V, B, P>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    P: PublicKey,
{
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            broadcast: self.broadcast.clone(),
        }
    }
}

impl<H, V, B, P> Mailbox<H, V, B, P>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    P: PublicKey,
{
    pub(super) const fn new(
        sender: actor_mailbox::UnreliableSender<Command<H, V, B>>,
        broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
    ) -> Self {
        Self { sender, broadcast }
    }

    async fn request<T>(
        &self,
        request: impl FnOnce(Reply<T>) -> Request<H, V, B>,
    ) -> Result<T, Error> {
        let (reply, receiver) = oneshot::channel();
        match self.sender.enqueue(Command::new(request(reply))) {
            Unreliable::Rejected => return Err(Error::Busy),
            Unreliable::Outcome(Feedback::Closed) => return Err(Error::Closed),
            Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => {}
        }
        receiver.await.unwrap_or(Err(Error::Closed))
    }

    /// Stages one complete producer block without broadcasting it.
    ///
    /// The returned token resolves after the block is durably recoverable. Accepted storage work
    /// continues if the token is dropped.
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
        self.request(|reply| Request::StageBlock(block, reply))
            .await
    }

    /// Durably submits one complete producer block without broadcasting it.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.put_block", level = "info", skip_all)]
    pub async fn put_block(
        &self,
        block: impl Into<Arc<TransactionBlock<H, B>>>,
    ) -> Result<(), Error> {
        self.stage_block(block).await?.wait().await
    }

    /// Constructs and durably submits the complete block produced for a consensus context.
    pub async fn submit(&self, context: Context<H::Digest>, body: B) -> Result<(), Error> {
        self.put_block(TransactionBlock::<H, B>::from_context(context, body))
            .await
    }

    /// Eagerly broadcasts a complete transaction block through the buffered transport.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.broadcast_block",
        level = "debug",
        skip_all
    )]
    pub fn broadcast_block(
        &self,
        recipients: Recipients<P>,
        block: impl Into<Arc<TransactionBlock<H, B>>>,
    ) -> Feedback {
        self.broadcast.broadcast_shared(recipients, block.into())
    }

    /// Gets an exact locally admitted LQC without initiating network work.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.get_certificate",
        level = "debug",
        skip_all
    )]
    pub async fn get_certificate(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<MaybeLqc<V, H::Digest>, Error> {
        self.request(|reply| Request::GetCertificate(id, reply))
            .await
    }

    /// Fetches an exact LQC locally or from peers. Drop the future to cancel the request.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.fetch_certificate",
        level = "info",
        skip_all
    )]
    pub async fn fetch_certificate(
        &self,
        id: CertificateId<H::Digest>,
    ) -> Result<Arc<Lqc<V, H::Digest>>, Error> {
        self.request(|reply| Request::FetchCertificate(id, reply))
            .await
    }

    /// Gets an exact locally admitted producer block without initiating network work.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.get_block",
        level = "debug",
        skip_all
    )]
    pub async fn get_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Option<Arc<TransactionBlock<H, B>>>, Error> {
        self.request(|reply| Request::GetBlock(reference, reply))
            .await
    }

    /// Fetches an exact producer block locally or from peers. Drop the future to cancel it.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.fetch_block",
        level = "info",
        skip_all
    )]
    pub async fn fetch_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        self.request(|reply| Request::FetchBlock(reference, reply))
            .await
    }

    /// Establishes durable custody of an exact block from buffered ingress or local storage.
    ///
    /// This does not start a peer fetch. Accepted data-availability evidence may independently
    /// promote the storage waiter through resolver backfill.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.subscribe_block",
        level = "info",
        skip_all
    )]
    pub async fn subscribe_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Result<Arc<TransactionBlock<H, B>>, Error> {
        let mut buffered = Box::pin(self.subscribe_buffered_block(reference));
        let mut admitted =
            Box::pin(self.request(|reply| Request::SubscribeBlock(reference, reply)));
        select! {
            block = &mut buffered => match block {
                Some(block) => {
                    drop(admitted);
                    self.put_block(Arc::clone(&block)).await?;
                    Ok(block)
                },
                None => admitted.await,
            },
            result = &mut admitted => match result {
                Ok(block) => Ok(block),
                Err(Error::Busy) => Err(Error::Busy),
                Err(error) => match buffered.await {
                    Some(block) => {
                        self.put_block(Arc::clone(&block)).await?;
                        Ok(block)
                    }
                    None => Err(error),
                },
            },
        }
    }

    /// Gets an exact complete block currently retained by buffered ingress.
    pub async fn get_buffered_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> Option<Arc<TransactionBlock<H, B>>> {
        self.broadcast
            .get(reference.digest())
            .await
            .filter(|block| block.reference() == reference)
    }

    /// Waits for buffered ingress of an exact complete block.
    pub fn subscribe_buffered_block(
        &self,
        reference: BlockRef<H::Digest>,
    ) -> impl std::future::Future<Output = Option<Arc<TransactionBlock<H, B>>>> + Send + 'static
    {
        let receiver = self.broadcast.subscribe(reference.digest());
        async move {
            receiver
                .await
                .ok()
                .filter(|block| block.reference() == reference)
        }
    }

    /// Verifies and installs a state-sync floor before allowing its prefix to be pruned.
    #[tracing::instrument(
        name = "multimmit.marshal.mailbox.install_floor",
        level = "info",
        skip_all
    )]
    pub async fn install_floor(&self, floor: FloorCheckpoint<V, H::Digest>) -> Result<(), Error> {
        self.request(|reply| Request::InstallFloor(floor, reply))
            .await
    }

    /// Requests pruning for one already installed floor generation.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.prune", level = "info", skip_all)]
    pub async fn prune(&self, request: Prune) -> Result<(), Error> {
        self.request(|reply| Request::Prune(request, reply)).await
    }

    /// Returns marshal's compact durable progress.
    #[tracing::instrument(name = "multimmit.marshal.mailbox.progress", level = "debug", skip_all)]
    pub async fn progress(&self) -> Result<Progress<H::Digest>, Error> {
        self.request(Request::Progress).await
    }
}

pub(super) fn channel<H, V, B, P>(
    metrics: impl RuntimeMetrics,
    capacity: NonZeroUsize,
    broadcast: buffered::Mailbox<P, TransactionBlock<H, B>>,
) -> Channel<H, V, B, P>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    P: PublicKey,
{
    let (sender, receiver) = actor_mailbox::new_unreliable(metrics, capacity);
    (Mailbox::new(sender, broadcast), receiver)
}

type Channel<H, V, B, P> = (
    Mailbox<H, V, B, P>,
    actor_mailbox::UnreliableReceiver<Command<H, V, B>>,
);

impl<H, V, B, P> Reporter for Mailbox<H, V, B, P>
where
    H: Hasher,
    V: Variant,
    B: Codec + Digestible<Digest = H::Digest>,
    P: PublicKey,
{
    type Activity = Activity<V, H::Digest>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        // No span here: hints are fire-and-forget, the enqueue never awaits, and `Command::new`
        // already snapshots `Span::current()` so the router can link back to the caller.
        match self.sender.enqueue(Command::new(Request::Hint(activity))) {
            Unreliable::Outcome(feedback) => feedback,
            Unreliable::Rejected => Feedback::Backoff,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{marshal::mocks::block::EmptyBlock, multimmit::types::ChainId, types::Height};
    use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};

    type TestCommand = Command<Sha256, MinPk, EmptyBlock<Sha256>>;

    #[test]
    fn pressure_retains_only_the_newest_finality_fact() {
        use crate::{
            multimmit::{
                machine::{ArtifactId, FinalityFact, FinalityId},
                types::Activity,
            },
            types::{Epoch, Round, View},
        };
        let fact = |view: u64| {
            FinalityFact::for_test(
                FinalityId::Lqc(ArtifactId::new(Sha256::hash(&[&view.to_be_bytes()]))),
                Round::new(Epoch::new(1), View::new(view)),
                Sha256::hash(&[b"leader"]),
                CertificateId::new(Sha256::hash(&[b"parent"])),
                4,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
            )
        };
        let mut overflow = VecDeque::new();
        for view in [5u64, 9, 7] {
            let retained = <TestCommand as UnreliablePolicy>::handle(
                &mut overflow,
                TestCommand::new(Request::Hint(Activity::LeaderFinalized {
                    fact: fact(view),
                })),
            );
            assert!(retained);
        }
        assert_eq!(overflow.len(), 1);
        let Request::Hint(Activity::LeaderFinalized { fact }) = &overflow[0].request else {
            panic!("the newest finality fact is retained");
        };
        assert_eq!(fact.round().view(), View::new(9));
    }

    #[test]
    fn pressure_keeps_the_latest_same_view_advance() {
        use crate::{
            multimmit::{
                machine::{ArtifactId, FinalityFact, FinalityId},
                types::Activity,
            },
            types::{Epoch, Round, View},
        };
        let fact = |view: u64, votes: usize| {
            FinalityFact::for_test(
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
        };
        let mut overflow = VecDeque::new();
        // A LeaderFinalized for view 5 with a bare quorum of votes is retained first.
        <TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            TestCommand::new(Request::Hint(Activity::LeaderFinalized { fact: fact(5, 41) })),
        );
        // A same-view advance carries more votes (extension settlement); it must supersede the
        // earlier finalized rather than be dropped, which the plain view comparison did.
        <TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            TestCommand::new(Request::Hint(Activity::LeaderFinalityUpdated { fact: fact(5, 47) })),
        );
        assert_eq!(overflow.len(), 1);
        let Request::Hint(Activity::LeaderFinalityUpdated { fact: kept }) = &overflow[0].request
        else {
            panic!("the same-view advance must be retained over the earlier finalized");
        };
        assert_eq!(kept.votes(), 47, "the richer same-view fact is kept");
        // A late, stale finalized for the same view (fewer votes) must NOT evict the richer advance.
        <TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            TestCommand::new(Request::Hint(Activity::LeaderFinalized { fact: fact(5, 41) })),
        );
        assert_eq!(overflow.len(), 1);
        let Request::Hint(Activity::LeaderFinalityUpdated { fact: kept }) = &overflow[0].request
        else {
            panic!("a stale same-view finalized must not evict the richer advance");
        };
        assert_eq!(kept.votes(), 47, "content comparison is arrival-order independent");
    }

    #[test]
    fn pressure_rejects_requests() {
        let (reply, mut response) = oneshot::channel();
        let reference = BlockRef::new(ChainId::new(0), Height::new(1), Sha256::hash(&[b"block"]));
        let mut overflow = VecDeque::new();
        let handled = <TestCommand as UnreliablePolicy>::handle(
            &mut overflow,
            TestCommand::new(Request::SubscribeBlock(reference, reply)),
        );

        assert!(!handled);
        assert!(overflow.is_empty());
        assert!(matches!(
            response.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
    }
}
