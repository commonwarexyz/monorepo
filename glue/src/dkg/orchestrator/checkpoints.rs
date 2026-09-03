//! Durable finalized checkpoints for aggregation.
//!
//! Finalized blocks and aggregation proposals share one storage-owning actor.
//! A block acknowledgement is released only after its checkpoint is synced.

use commonware_actor::{
    Feedback, Unreliable,
    mailbox::{self, Overflow, UnreliablePolicy, UnreliableReceiver, UnreliableSender},
};
use commonware_codec::Read;
use commonware_consensus::{Automaton, Block, Reporter, marshal::Update, types::Height};
use commonware_cryptography::Digest;
use commonware_macros::select_loop;
use commonware_runtime::{
    ContextCell, Handle, Spawner, spawn_cell,
    telemetry::metrics::{Counter, MetricsExt as _},
};
use commonware_storage::{
    Context,
    archive::{Archive as _, Identifier, immutable},
};
use commonware_utils::{Acknowledgement, channel::oneshot};
use std::{
    collections::{BTreeMap, VecDeque},
    marker::PhantomData,
    num::NonZeroUsize,
    sync::Arc,
};
use thiserror::Error;

/// A finalized block carrying the global checkpoint used by aggregation.
pub trait FinalizedBlock: Block {
    /// Checkpoint digest proposed for this block's global height.
    type Checkpoint: Digest;

    /// Returns the global height and its canonical checkpoint digest.
    ///
    /// The returned height must equal [`Heightable::height`](commonware_consensus::Heightable::height).
    fn finalized_checkpoint(&self) -> (Height, Self::Checkpoint);
}

/// Persistent checkpoint storage and ingress configuration.
pub struct Config<C> {
    /// Immutable archive indexed by global height.
    pub archive: immutable::Config<C>,
    /// Capacity of the primary ingress queue.
    ///
    /// Overflow is retained losslessly. Total retained ingress and waiter state is
    /// application-bounded: marshal holds finalized delivery behind the acknowledgement,
    /// and aggregation must use a finite live-height window and bounded request concurrency.
    pub mailbox_size: NonZeroUsize,
    /// Maximum unresolved proposal and verification requests.
    ///
    /// Configure at least the sum of all aggregation-engine windows that share
    /// this checkpoint store. Exceeding this limit is a fatal configuration error.
    pub max_pending_requests: NonZeroUsize,
}

/// Fatal checkpoint actor error.
#[derive(Debug, Error)]
pub enum Error {
    /// Immutable archive failure.
    #[error("checkpoint archive error: {0}")]
    Archive(#[from] commonware_storage::archive::Error),
    /// A height was finalized with a digest other than its durable canonical digest.
    #[error("conflicting finalized checkpoint at height {height}")]
    Conflict {
        /// Conflicting global height.
        height: Height,
    },
    /// The finalized-checkpoint height disagreed with the block height.
    #[error("checkpoint height {checkpoint} disagrees with block height {block}")]
    HeightMismatch {
        /// Height returned by [`FinalizedBlock`].
        checkpoint: Height,
        /// Height returned by the consensus block.
        block: Height,
    },
    /// More unresolved requests reached the actor than its configured bound.
    #[error("checkpoint pending request capacity exhausted")]
    RequestCapacity,
}

enum Request<D> {
    Propose(oneshot::Sender<D>),
    Verify(D, oneshot::Sender<bool>),
}

impl<D> Request<D> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Propose(response) => response.is_closed(),
            Self::Verify(_, response) => response.is_closed(),
        }
    }
}

enum Message<B: FinalizedBlock, A: Acknowledgement> {
    Finalized(Arc<B>, A),
    Request {
        height: Height,
        request: Request<B::Checkpoint>,
        maximum: usize,
        capacity_exhaustions: Counter,
    },
}

struct Pending<B: FinalizedBlock, A: Acknowledgement> {
    messages: VecDeque<Message<B, A>>,
    requests: usize,
}

impl<B: FinalizedBlock, A: Acknowledgement> Default for Pending<B, A> {
    fn default() -> Self {
        Self {
            messages: VecDeque::new(),
            requests: 0,
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Pending<B, A> {
    fn prune_closed_requests(&mut self) {
        self.messages.retain(|message| {
            let closed = matches!(
                message,
                Message::Request { request, .. } if request.response_closed()
            );
            if closed {
                self.requests -= 1;
            }
            !closed
        });
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Overflow<Message<B, A>> for Pending<B, A> {
    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    fn drain<F>(&mut self, mut push: F)
    where
        F: FnMut(Message<B, A>) -> Option<Message<B, A>>,
    {
        while let Some(message) = self.messages.pop_front() {
            let request = matches!(message, Message::Request { .. });
            if let Some(message) = push(message) {
                self.messages.push_front(message);
                break;
            }
            if request {
                self.requests -= 1;
            }
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> UnreliablePolicy for Message<B, A> {
    type Overflow = Pending<B, A>;

    fn handle(overflow: &mut Self::Overflow, message: Self) -> bool {
        if let Self::Request {
            request,
            maximum,
            capacity_exhaustions,
            ..
        } = &message
        {
            if request.response_closed() {
                return true;
            }
            overflow.prune_closed_requests();
            if overflow.requests >= *maximum {
                capacity_exhaustions.inc();
                return false;
            }
            overflow.requests += 1;
        }
        overflow.messages.push_back(message);
        true
    }
}

/// Cloneable finalized-block reporter and aggregation automaton.
pub struct Handler<B: FinalizedBlock, A: Acknowledgement> {
    sender: UnreliableSender<Message<B, A>>,
    max_pending_requests: usize,
    capacity_exhaustions: Counter,
    _types: PhantomData<fn() -> (B, A)>,
}

impl<B: FinalizedBlock, A: Acknowledgement> Clone for Handler<B, A> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            max_pending_requests: self.max_pending_requests,
            capacity_exhaustions: self.capacity_exhaustions.clone(),
            _types: PhantomData,
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Reporter for Handler<B, A> {
    type Activity = Update<B, A>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block(block, acknowledgement) = activity else {
            return Feedback::Ok;
        };
        match self
            .sender
            .enqueue(Message::Finalized(block, acknowledgement))
        {
            Unreliable::Outcome(feedback) => feedback,
            Unreliable::Rejected => unreachable!("finalized checkpoints are never rejected"),
        }
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Automaton for Handler<B, A> {
    type Context = Height;
    type Digest = B::Checkpoint;

    async fn propose(&mut self, height: Height) -> oneshot::Receiver<Self::Digest> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::Request {
            height,
            request: Request::Propose(response),
            maximum: self.max_pending_requests,
            capacity_exhaustions: self.capacity_exhaustions.clone(),
        });
        Self::assert_request_accepted(feedback);
        receiver
    }

    async fn verify(&mut self, height: Height, digest: Self::Digest) -> oneshot::Receiver<bool> {
        let (response, receiver) = oneshot::channel();
        let feedback = self.sender.enqueue(Message::Request {
            height,
            request: Request::Verify(digest, response),
            maximum: self.max_pending_requests,
            capacity_exhaustions: self.capacity_exhaustions.clone(),
        });
        Self::assert_request_accepted(feedback);
        receiver
    }
}

impl<B: FinalizedBlock, A: Acknowledgement> Handler<B, A> {
    fn assert_request_accepted(feedback: Unreliable<Feedback>) {
        match feedback {
            Unreliable::Outcome(Feedback::Ok | Feedback::Backoff) => {}
            Unreliable::Outcome(Feedback::Closed) => {
                panic!("checkpoint actor mailbox closed")
            }
            Unreliable::Rejected => {
                panic!("checkpoint request mailbox capacity exhausted")
            }
        }
    }
}

type Archive<E, D> = immutable::Archive<E, D, D>;

/// Storage-owning finalized-checkpoint actor.
pub struct Actor<E, B, A>
where
    E: Context,
    B: FinalizedBlock,
    A: Acknowledgement,
{
    context: ContextCell<E>,
    archive: Option<Archive<E, B::Checkpoint>>,
    receiver: UnreliableReceiver<Message<B, A>>,
    waiters: BTreeMap<Height, Vec<Request<B::Checkpoint>>>,
    pending_requests: usize,
    max_pending_requests: usize,
    capacity_exhaustions: Counter,
}

impl<E, B, A> Actor<E, B, A>
where
    E: Context + Spawner,
    B: FinalizedBlock,
    A: Acknowledgement,
{
    /// Opens the durable archive and creates its application handle.
    pub async fn init(
        context: E,
        config: Config<<B::Checkpoint as Read>::Cfg>,
    ) -> Result<(Self, Handler<B, A>), Error> {
        let archive = immutable::Archive::init(context.child("archive"), config.archive).await?;
        let capacity_exhaustions = context.counter(
            "request_capacity_exhaustions",
            "Checkpoint requests rejected after exhausting configured capacity",
        );
        let (sender, receiver) =
            mailbox::new_unreliable(context.child("mailbox"), config.mailbox_size);
        Ok((
            Self {
                context: ContextCell::new(context),
                archive: Some(archive),
                receiver,
                waiters: BTreeMap::new(),
                pending_requests: 0,
                max_pending_requests: config.max_pending_requests.get(),
                capacity_exhaustions: capacity_exhaustions.clone(),
            },
            Handler {
                sender,
                max_pending_requests: config.max_pending_requests.get(),
                capacity_exhaustions,
                _types: PhantomData,
            },
        ))
    }

    /// Starts the actor. Storage and consistency failures terminate it permanently.
    pub fn start(self) -> Handle<Result<(), Error>> {
        let mut actor = self;
        spawn_cell!(actor.context, actor.run())
    }

    async fn run(mut self) -> Result<(), Error> {
        select_loop! {
            self.context,
            on_stopped => {},
            Some(message) = self.receiver.recv() else break => match message {
                Message::Finalized(block, acknowledgement) => {
                    self.finalized(block, acknowledgement).await?;
                }
                Message::Request { height, request, .. } => self.request(height, request).await?,
            },
        }
        Ok(())
    }

    async fn request(
        &mut self,
        height: Height,
        request: Request<B::Checkpoint>,
    ) -> Result<(), Error> {
        if request.response_closed() {
            return Ok(());
        }
        let archive = self.archive.as_ref().expect("archive unavailable");
        if let Some(digest) = archive.get(Identifier::Index(height.get())).await? {
            Self::resolve(request, digest);
        } else {
            self.prune_closed_waiters();
            if self.pending_requests == self.max_pending_requests {
                self.capacity_exhaustions.inc();
                return Err(Error::RequestCapacity);
            }
            self.waiters.entry(height).or_default().push(request);
            self.pending_requests += 1;
        }
        Ok(())
    }

    fn prune_closed_waiters(&mut self) {
        let mut removed = 0;
        self.waiters.retain(|_, requests| {
            let previous = requests.len();
            requests.retain(|request| !request.response_closed());
            removed += previous - requests.len();
            !requests.is_empty()
        });
        self.pending_requests -= removed;
    }

    async fn finalized(&mut self, block: Arc<B>, acknowledgement: A) -> Result<(), Error> {
        let block_height = block.height();
        let (height, digest) = block.finalized_checkpoint();
        if height != block_height {
            return Err(Error::HeightMismatch {
                checkpoint: height,
                block: block_height,
            });
        }

        let archive = self.archive.as_ref().expect("archive unavailable");
        if let Some(existing) = archive.get(Identifier::Index(height.get())).await? {
            if existing != digest {
                return Err(Error::Conflict { height });
            }
        } else {
            let archive = self.archive.take().expect("archive unavailable");
            self.archive = Some(
                archive
                    .put(height.get(), digest, digest)
                    .await?
                    .sync()
                    .await?,
            );
        }

        if let Some(waiters) = self.waiters.remove(&height) {
            self.pending_requests -= waiters.len();
            for waiter in waiters {
                Self::resolve(waiter, digest);
            }
        }
        acknowledgement.acknowledge();
        Ok(())
    }

    fn resolve(request: Request<B::Checkpoint>, digest: B::Checkpoint) {
        match request {
            Request::Propose(response) => {
                let _ = response.send(digest);
            }
            Request::Verify(candidate, response) => {
                let _ = response.send(candidate == digest);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::tests::mocks::MockBlock;
    use commonware_cryptography::{
        Digestible as _, Hasher as _, Sha256, sha256::Digest as Sha256Digest,
    };
    use commonware_runtime::{
        Metrics as _, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
        reschedule,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, acknowledgement::Exact};
    use futures::FutureExt as _;

    type TestBlock = MockBlock<Sha256Digest, u64>;

    impl FinalizedBlock for TestBlock {
        type Checkpoint = Sha256Digest;

        fn finalized_checkpoint(&self) -> (Height, Self::Checkpoint) {
            (Height::new(*self.context()), self.digest())
        }
    }

    fn block(height: u64, timestamp: u64) -> TestBlock {
        checkpoint_block(height, height, timestamp)
    }

    fn checkpoint_block(height: u64, checkpoint_height: u64, timestamp: u64) -> TestBlock {
        MockBlock::new::<Sha256>(
            checkpoint_height,
            Sha256::hash(&[b"parent"]),
            Height::new(height),
            timestamp,
        )
    }

    fn config(context: &deterministic::Context) -> Config<()> {
        Config {
            archive: immutable::Config {
                metadata_partition: "checkpoint_metadata".into(),
                freezer_table_partition: "checkpoint_table".into(),
                freezer_table_initial_size: 64,
                freezer_table_resize_frequency: 4,
                freezer_table_resize_chunk_size: 32,
                freezer_key_partition: "checkpoint_keys".into(),
                freezer_key_page_cache: CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(10)),
                freezer_value_partition: "checkpoint_values".into(),
                freezer_value_target_size: 1024 * 1024,
                freezer_value_compression: None,
                ordinal_partition: "checkpoint_ordinal".into(),
                items_per_section: NZU64!(64),
                freezer_key_write_buffer: NZUsize!(1024),
                freezer_value_write_buffer: NZUsize!(1024),
                ordinal_write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
                codec_config: (),
            },
            mailbox_size: NZUsize!(1),
            max_pending_requests: NZUsize!(8),
        }
    }

    #[test]
    fn recovery_and_report_propose_race() {
        deterministic::Runner::default().start(|context| async move {
            let finalized = block(7, 1);
            let expected = finalized.digest();
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("first"), config(&context))
                    .await
                    .unwrap();
            let handle = actor.start();

            let proposal = handler.propose(Height::new(7)).await;
            let verification = handler.verify(Height::new(7), expected).await;
            let (acknowledgement, acknowledged) = Exact::handle();
            assert!(
                handler
                    .report(Update::Block(Arc::new(finalized), acknowledgement))
                    .accepted()
            );
            assert_eq!(proposal.await.unwrap(), expected);
            assert!(verification.await.unwrap());
            acknowledged.await.unwrap();

            handle.abort();
            let (recovered, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("second"), config(&context))
                    .await
                    .unwrap();
            let recovered_handle = recovered.start();
            assert_eq!(
                handler.propose(Height::new(7)).await.await.unwrap(),
                expected
            );
            recovered_handle.abort();
        });
    }

    #[test]
    fn conflicting_finalization_is_fatal_and_unacknowledged() {
        deterministic::Runner::default().start(|context| async move {
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), config(&context))
                    .await
                    .unwrap();
            let handle = actor.start();

            let (first_ack, first_waiter) = Exact::handle();
            let _ = handler.report(Update::Block(Arc::new(block(3, 1)), first_ack));
            first_waiter.await.unwrap();

            let (conflict_ack, conflict_waiter) = Exact::handle();
            let _ = handler.report(Update::Block(Arc::new(block(3, 2)), conflict_ack));
            assert!(matches!(
                handle.await,
                Ok(Err(Error::Conflict {
                    height
                })) if height == Height::new(3)
            ));
            assert!(conflict_waiter.await.is_err());
        });
    }

    #[test]
    fn checkpoint_height_mismatch_is_fatal_and_not_persisted() {
        deterministic::Runner::default().start(|context| async move {
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("first"), config(&context))
                    .await
                    .unwrap();
            let handle = actor.start();
            let (acknowledgement, acknowledged) = Exact::handle();
            let _ = handler.report(Update::Block(
                Arc::new(checkpoint_block(3, 4, 1)),
                acknowledgement,
            ));

            assert!(matches!(
                handle.await,
                Ok(Err(Error::HeightMismatch { checkpoint, block }))
                    if checkpoint == Height::new(4) && block == Height::new(3)
            ));
            assert!(acknowledged.await.is_err());

            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("second"), config(&context))
                    .await
                    .unwrap();
            let handle = actor.start();
            let proposal = handler.propose(Height::new(4)).await;
            reschedule().await;
            assert!(proposal.now_or_never().is_none());

            let expected = block(4, 2);
            let digest = expected.digest();
            let proposal = handler.propose(Height::new(4)).await;
            let (acknowledgement, acknowledged) = Exact::handle();
            let _ = handler.report(Update::Block(Arc::new(expected), acknowledgement));
            assert_eq!(proposal.await.unwrap(), digest);
            acknowledged.await.unwrap();
            handle.abort();
        });
    }

    #[test]
    fn overflow_capacity_exhaustion_is_fatal() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config(&context);
            cfg.max_pending_requests = NZUsize!(1);
            let (_actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), cfg)
                    .await
                    .unwrap();

            let _first = handler.propose(Height::new(1)).await;
            let _second = handler.propose(Height::new(2)).await;
            let result = std::panic::AssertUnwindSafe(handler.propose(Height::new(3)))
                .catch_unwind()
                .await;

            assert!(result.is_err());
            assert!(
                context
                    .encode()
                    .contains("request_capacity_exhaustions_total 1")
            );
        });
    }

    #[test]
    fn actor_capacity_exhaustion_is_fatal() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config(&context);
            cfg.mailbox_size = NZUsize!(8);
            cfg.max_pending_requests = NZUsize!(1);
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), cfg)
                    .await
                    .unwrap();
            let handle = actor.start();

            let first = handler.propose(Height::new(1)).await;
            reschedule().await;
            let second = handler.propose(Height::new(2)).await;

            assert!(matches!(handle.await, Ok(Err(Error::RequestCapacity))));
            assert!(first.await.is_err());
            assert!(second.await.is_err());
            assert!(
                context
                    .encode()
                    .contains("request_capacity_exhaustions_total 1")
            );
        });
    }

    #[test]
    fn canceled_waiter_releases_actor_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config(&context);
            cfg.max_pending_requests = NZUsize!(1);
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), cfg)
                    .await
                    .unwrap();
            let handle = actor.start();

            let canceled = handler.propose(Height::new(1)).await;
            reschedule().await;
            drop(canceled);

            let second = handler.propose(Height::new(2)).await;
            reschedule().await;
            let (acknowledgement, acknowledged) = Exact::handle();
            let expected = block(2, 2);
            let digest = expected.digest();
            let _ = handler.report(Update::Block(Arc::new(expected), acknowledgement));

            assert_eq!(second.await.unwrap(), digest);
            acknowledged.await.unwrap();
            handle.abort();
        });
    }

    #[test]
    fn canceled_overflow_request_releases_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config(&context);
            cfg.mailbox_size = NZUsize!(1);
            cfg.max_pending_requests = NZUsize!(1);
            let (_actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), cfg)
                    .await
                    .unwrap();

            let _ready = handler.propose(Height::new(1)).await;
            let canceled = handler.propose(Height::new(2)).await;
            drop(canceled);
            let _replacement = handler.propose(Height::new(3)).await;
        });
    }

    #[test]
    fn canceled_queued_request_releases_capacity() {
        deterministic::Runner::default().start(|context| async move {
            let mut cfg = config(&context);
            cfg.max_pending_requests = NZUsize!(1);
            let (actor, mut handler) =
                Actor::<_, TestBlock, Exact>::init(context.child("actor"), cfg)
                    .await
                    .unwrap();

            let canceled = handler.propose(Height::new(1)).await;
            drop(canceled);
            let replacement = handler.propose(Height::new(2)).await;
            let handle = actor.start();
            reschedule().await;

            let (acknowledgement, acknowledged) = Exact::handle();
            let expected = block(2, 2);
            let digest = expected.digest();
            let _ = handler.report(Update::Block(Arc::new(expected), acknowledgement));

            assert_eq!(replacement.await.unwrap(), digest);
            acknowledged.await.unwrap();
            handle.abort();
        });
    }
}
