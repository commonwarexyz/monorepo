use super::{
    cache,
    mailbox::{CommitmentFallback, Mailbox, Message},
    Buffer, Variant,
};
use crate::{
    marshal::{
        resolver::handler::{
            self, above_height_floor, above_round_floor, Annotation, Finalized, Request,
        },
        store::{Blocks, Certificates},
        Config, Identifier as BlockID, Update,
    },
    simplex::{
        scheme::Scheme,
        types::{verify_certificates, Finalization, Notarization, Subject},
    },
    types::{Epoch, Epocher, Height, Round, ViewDelta},
    Block, Epochable, Heightable, Reporter,
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    Digestible,
};
use commonware_macros::select_loop;
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Fetch, Resolver};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{Gauge, GaugeExt, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::{
    archive::Identifier as ArchiveID,
    metadata::{self, Metadata},
};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    futures::{AbortablePool, Aborter, OptionFuture},
    sequence::U64,
    vec::NonEmptyVec,
    Acknowledgement, BoxedError,
};
use futures::{future::join_all, try_join, FutureExt};
use pin_project::pin_project;
use rand_core::CryptoRngCore;
use std::{
    collections::{btree_map::Entry, BTreeMap, VecDeque},
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
};
use tracing::{debug, error, warn};

/// The key used to store the last processed height in the metadata store.
const LATEST_KEY: U64 = U64::new(0xFF);

/// A parsed-but-unverified resolver delivery awaiting batch certificate verification.
enum PendingVerification<S: CertificateScheme, V: Variant> {
    Notarized {
        notarization: Notarization<S, V::Commitment>,
        block: V::Block,
        response: oneshot::Sender<bool>,
    },
    Finalized {
        finalization: Finalization<S, V::Commitment>,
        block: V::Block,
        response: oneshot::Sender<bool>,
    },
}

impl<S: CertificateScheme, V: Variant> PendingVerification<S, V> {
    fn response_closed(&self) -> bool {
        match self {
            Self::Notarized { response, .. } | Self::Finalized { response, .. } => {
                response.is_closed()
            }
        }
    }
}

/// A pending acknowledgement from the application for a block at the contained height/commitment.
#[pin_project]
struct PendingAck<V: Variant, A: Acknowledgement> {
    height: Height,
    commitment: V::Commitment,
    #[pin]
    receiver: A::Waiter,
}

impl<V: Variant, A: Acknowledgement> Future for PendingAck<V, A> {
    type Output = <A::Waiter as Future>::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().receiver.poll(cx)
    }
}

/// Tracks in-flight application acknowledgements with FIFO semantics.
struct PendingAcks<V: Variant, A: Acknowledgement> {
    current: OptionFuture<PendingAck<V, A>>,
    queue: VecDeque<PendingAck<V, A>>,
    max: usize,
}

impl<V: Variant, A: Acknowledgement> PendingAcks<V, A> {
    /// Creates a new pending-ack tracker with a maximum in-flight capacity.
    fn new(max: usize) -> Self {
        Self {
            current: None.into(),
            queue: VecDeque::with_capacity(max),
            max,
        }
    }

    /// Drops the current ack and all queued acks.
    fn clear(&mut self) {
        self.current = None.into();
        self.queue.clear();
    }

    /// Returns the currently armed ack future (if any) for `select_loop!`.
    const fn current(&mut self) -> &mut OptionFuture<PendingAck<V, A>> {
        &mut self.current
    }

    /// Returns whether we can dispatch another block without exceeding capacity.
    fn has_capacity(&self) -> bool {
        let reserved = usize::from(self.current.is_some());
        self.queue.len() < self.max - reserved
    }

    /// Returns the next height to dispatch while preserving sequential order.
    fn next_dispatch_height(&self, last_processed_height: Height) -> Height {
        self.queue
            .back()
            .map(|ack| ack.height.next())
            .or_else(|| self.current.as_ref().map(|ack| ack.height.next()))
            .unwrap_or_else(|| last_processed_height.next())
    }

    /// Enqueues a newly dispatched ack, arming it immediately when idle.
    fn enqueue(&mut self, ack: PendingAck<V, A>) {
        if self.current.is_none() {
            self.current.replace(ack);
            return;
        }
        self.queue.push_back(ack);
    }

    /// Returns metadata for a completed current ack and arms the next queued ack.
    fn complete_current(
        &mut self,
        result: <A::Waiter as Future>::Output,
    ) -> (Height, V::Commitment, <A::Waiter as Future>::Output) {
        let PendingAck {
            height, commitment, ..
        } = self.current.take().expect("ack state must be present");
        if let Some(next) = self.queue.pop_front() {
            self.current.replace(next);
        }
        (height, commitment, result)
    }

    /// If the current ack is already resolved, takes it and arms the next ack.
    fn pop_ready(&mut self) -> Option<(Height, V::Commitment, <A::Waiter as Future>::Output)> {
        let pending = self.current.as_mut()?;
        let result = Pin::new(&mut pending.receiver).now_or_never()?;
        Some(self.complete_current(result))
    }
}

/// A struct that holds multiple subscriptions for a block.
struct BlockSubscription<V: Variant> {
    // The subscribers that are waiting for the block
    subscribers: Vec<oneshot::Sender<V::Block>>,
    // Aborter that aborts the waiter future when dropped
    _aborter: Aborter,
}

/// The key used to track block subscriptions.
///
/// Digest-scoped and commitment-scoped subscriptions are intentionally distinct
/// so a block that aliases on digest cannot satisfy a different commitment wait.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum BlockSubscriptionKey<C, D> {
    Digest(D),
    Commitment(C),
}

type BlockSubscriptionKeyFor<V> =
    BlockSubscriptionKey<<V as Variant>::Commitment, <<V as Variant>::Block as Digestible>::Digest>;
type ResolverRequestFor<V> = Request<<V as Variant>::Commitment>;

/// Processed floors used to admit or reject resolver fetches.
#[derive(Clone, Copy)]
struct Floor {
    height: Height,
    round: Round,
}

impl Floor {
    /// Returns true when the resolver request is above all processed floors.
    fn permits<D: commonware_cryptography::Digest>(
        &self,
        request: &Request<D>,
        subscriber: &Annotation,
    ) -> bool {
        let height_predicate = above_height_floor::<D>(self.height);
        if !height_predicate(request, subscriber) {
            return false;
        }

        let round_predicate = above_round_floor::<D>(self.round);
        round_predicate(request, subscriber)
    }

    fn fetch_if_permitted<D, R>(
        &self,
        resolver: &mut R,
        fetch: Fetch<Request<D>, Annotation>,
    ) -> bool
    where
        D: commonware_cryptography::Digest,
        R: Resolver<Key = Request<D>, Subscriber = Annotation>,
    {
        if !self.permits(&fetch.key, &fetch.subscriber) {
            return false;
        }
        resolver.fetch(fetch);
        true
    }

    fn fetch_targeted_if_permitted<D, R>(
        &self,
        resolver: &mut R,
        fetch: Fetch<Request<D>, Annotation>,
        targets: NonEmptyVec<R::PublicKey>,
    ) -> bool
    where
        D: commonware_cryptography::Digest,
        R: Resolver<Key = Request<D>, Subscriber = Annotation>,
    {
        if !self.permits(&fetch.key, &fetch.subscriber) {
            return false;
        }
        resolver.fetch_targeted(fetch, targets);
        true
    }

    fn fetch_all_if_permitted<D, R>(
        &self,
        resolver: &mut R,
        fetches: Vec<Fetch<Request<D>, Annotation>>,
    ) -> bool
    where
        D: commonware_cryptography::Digest,
        R: Resolver<Key = Request<D>, Subscriber = Annotation>,
    {
        let fetches = fetches
            .into_iter()
            .filter(|fetch| self.permits(&fetch.key, &fetch.subscriber))
            .collect::<Vec<_>>();
        if fetches.is_empty() {
            return false;
        }
        resolver.fetch_all(fetches);
        true
    }
}

/// The [Actor] is responsible for receiving uncertified blocks from the broadcast mechanism,
/// receiving notarizations and finalizations from consensus, and reconstructing a total order
/// of blocks.
///
/// The actor is designed to be used in a view-based model. Each view corresponds to a
/// potential block in the chain. The actor will only finalize a block if it has a
/// corresponding finalization.
///
/// The actor also provides a backfill mechanism for missing blocks. If the actor receives a
/// finalization for a block that is ahead of its current view, it will request the missing blocks
/// from its peers. This ensures that the actor can catch up to the rest of the network if it falls
/// behind.
pub struct Actor<E, V, P, FC, FB, ES, T, A = Exact>
where
    E: BufferPooler + CryptoRngCore + Spawner + Metrics + Clock + Storage,
    V: Variant,
    P: Provider<Scope = Epoch, Scheme: Scheme<V::Commitment>>,
    FC: Certificates<
        BlockDigest = <V::Block as Digestible>::Digest,
        Commitment = V::Commitment,
        Scheme = P::Scheme,
    >,
    FB: Blocks<Block = V::StoredBlock>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    // ---------- Context ----------
    context: ContextCell<E>,

    // ---------- Message Passing ----------
    // Mailbox
    mailbox: mailbox::Receiver<Message<P::Scheme, V>>,

    // ---------- Configuration ----------
    // Provider for epoch-specific signing schemes
    provider: P,
    // Epoch configuration
    epocher: ES,
    // Minimum number of views to retain temporary data after the application processes a block
    view_retention_timeout: ViewDelta,
    // Maximum number of blocks to repair at once
    max_repair: NonZeroUsize,
    // Codec configuration for block type
    block_codec_config: <V::ApplicationBlock as Read>::Cfg,
    // Strategy for parallel operations
    strategy: T,

    // ---------- State ----------
    // Last proposed block
    last_proposed_block: Option<(Round, V::Commitment, V::Block)>,
    // Last processed height and round
    floor: Floor,
    // Pending application acknowledgements
    pending_acks: PendingAcks<V, A>,
    // Highest known finalized height
    tip: Height,
    // Outstanding subscriptions for blocks
    block_subscriptions: BTreeMap<BlockSubscriptionKeyFor<V>, BlockSubscription<V>>,

    // ---------- Storage ----------
    // Prunable cache
    cache: cache::Manager<E, V, P::Scheme>,
    // Metadata tracking application progress
    application_metadata: Metadata<E, U64, Height>,
    // Finalizations stored by height
    finalizations_by_height: FC,
    // Finalized blocks stored by height
    finalized_blocks: FB,

    // ---------- Metrics ----------
    // Latest height metric
    finalized_height: Gauge,
    // Latest processed height
    processed_height: Gauge,
}

impl<E, V, P, FC, FB, ES, T, A> Actor<E, V, P, FC, FB, ES, T, A>
where
    E: BufferPooler + CryptoRngCore + Spawner + Metrics + Clock + Storage,
    V: Variant,
    P: Provider<Scope = Epoch, Scheme: Scheme<V::Commitment>>,
    FC: Certificates<
        BlockDigest = <V::Block as Digestible>::Digest,
        Commitment = V::Commitment,
        Scheme = P::Scheme,
    >,
    FB: Blocks<Block = V::StoredBlock>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    /// Create a new application actor.
    pub async fn init(
        context: E,
        finalizations_by_height: FC,
        finalized_blocks: FB,
        config: Config<V::ApplicationBlock, P, ES, T>,
    ) -> (Self, Mailbox<P::Scheme, V>, Height) {
        // Initialize cache
        let prunable_config = cache::Config {
            partition_prefix: format!("{}-cache", config.partition_prefix),
            prunable_items_per_section: config.prunable_items_per_section,
            replay_buffer: config.replay_buffer,
            key_write_buffer: config.key_write_buffer,
            value_write_buffer: config.value_write_buffer,
            key_page_cache: config.page_cache.clone(),
        };
        let cache = cache::Manager::init(
            context.child("cache"),
            prunable_config,
            config.block_codec_config.clone(),
        )
        .await;

        // Initialize metadata tracking application progress
        let application_metadata = Metadata::init(
            context.child("application_metadata"),
            metadata::Config {
                partition: format!("{}-application-metadata", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("failed to initialize application metadata");
        let last_processed_height = application_metadata
            .get(&LATEST_KEY)
            .copied()
            .unwrap_or(Height::zero());
        let last_processed_round =
            Self::latest_processed_round(&finalizations_by_height, last_processed_height).await;

        // Create metrics
        let finalized_height = context.gauge("finalized_height", "Finalized height of application");
        let processed_height = context.gauge("processed_height", "Processed height of application");
        let _ = processed_height.try_set(last_processed_height.get());

        // Initialize mailbox
        let (sender, mailbox) = mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                provider: config.provider,
                epocher: config.epocher,
                view_retention_timeout: config.view_retention_timeout,
                max_repair: config.max_repair,
                block_codec_config: config.block_codec_config,
                strategy: config.strategy,
                last_proposed_block: None,
                floor: Floor {
                    height: last_processed_height,
                    round: last_processed_round,
                },
                pending_acks: PendingAcks::new(config.max_pending_acks.get()),
                tip: Height::zero(),
                block_subscriptions: BTreeMap::new(),
                cache,
                application_metadata,
                finalizations_by_height,
                finalized_blocks,
                finalized_height,
                processed_height,
            },
            Mailbox::new(sender),
            last_processed_height,
        )
    }

    /// Start the actor.
    pub fn start<R, Buf>(
        mut self,
        application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: Buf,
        resolver: (handler::Receiver<V::Commitment>, R),
    ) -> Handle<()>
    where
        R: Resolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as CertificateScheme>::PublicKey,
        >,
        Buf: Buffer<V, PublicKey = <P::Scheme as CertificateScheme>::PublicKey>,
    {
        spawn_cell!(self.context, self.run(application, buffer, resolver))
    }

    /// Run the application actor.
    async fn run<R, Buf>(
        mut self,
        mut application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        mut buffer: Buf,
        (mut resolver_rx, mut resolver): (handler::Receiver<V::Commitment>, R),
    ) where
        R: Resolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as CertificateScheme>::PublicKey,
        >,
        Buf: Buffer<V, PublicKey = <P::Scheme as CertificateScheme>::PublicKey>,
    {
        // Create a local pool for waiter futures.
        let mut waiters = AbortablePool::<Result<V::Block, BlockSubscriptionKeyFor<V>>>::default();

        // Get tip and send to application
        let tip = self.get_latest().await;
        if let Some((height, digest, round)) = tip {
            application.report(Update::Tip(round, height, digest));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // Load persisted cache epochs so find_block can discover blocks
        // written before the last shutdown.
        self.cache.load_persisted_epochs().await;

        // Attempt to repair any gaps in the finalized blocks archive, if there are any.
        if self
            .try_repair_gaps(&mut buffer, &mut resolver, &mut application)
            .await
        {
            self.sync_finalized().await;
        }

        // Attempt to dispatch the next finalized block to the application, if it is ready.
        self.try_dispatch_blocks(&mut application).await;

        select_loop! {
            self.context,
            on_start => {
                // Remove any dropped subscribers. If all subscribers dropped, abort the waiter.
                self.block_subscriptions.retain(|_, bs| {
                    bs.subscribers.retain(|tx| !tx.is_closed());
                    !bs.subscribers.is_empty()
                });
            },
            on_stopped => {
                debug!("context shutdown, stopping marshal");
            },
            // Handle waiter completions first
            Ok(completion) = waiters.next_completed() else continue => match completion {
                Ok(block) => self.notify_subscribers(&block),
                Err(key) => {
                    match key {
                        BlockSubscriptionKey::Digest(digest) => {
                            debug!(
                                ?digest,
                                "buffer subscription closed, canceling local subscribers"
                            );
                        }
                        BlockSubscriptionKey::Commitment(commitment) => {
                            debug!(
                                ?commitment,
                                "buffer subscription closed, canceling local subscribers"
                            );
                        }
                    }
                    self.block_subscriptions.remove(&key);
                }
            },
            // Handle application acknowledgements (drain all ready acks, sync once)
            result = self.pending_acks.current() => {
                // Start with the ack that woke this `select_loop!` arm.
                let mut pending = Some(self.pending_acks.complete_current(result));
                let last_acked_commitment = loop {
                    let (height, commitment, result) =
                        pending.take().expect("pending ack must exist");
                    match result {
                        Ok(()) => {
                            // Apply in-memory progress updates for this acknowledged block.
                            self.handle_block_processed(height, commitment, &mut resolver)
                                .await;
                        }
                        Err(e) => {
                            // Ack failures are fatal for marshal/application coordination.
                            error!(e = ?e, height = %height, "application did not acknowledge block");
                            return;
                        }
                    }

                    // Opportunistically drain any additional already-ready acks so we
                    // can persist one metadata sync for the whole batch below.
                    match self.pending_acks.pop_ready() {
                        Some(next) => pending = Some(next),
                        None => break commitment,
                    }
                };

                // Persist buffered processed-height updates once after draining all ready acks.
                if let Err(e) = self.application_metadata.sync().await {
                    error!(?e, "failed to sync application progress");
                    return;
                }

                // Inform the buffer of the last acknowledged commitment (anything below this is safe to prune).
                buffer.finalized(last_acked_commitment);

                // Fill the pipeline
                self.try_dispatch_blocks(&mut application).await;
            },
            // Handle consensus inputs before backfill or resolver traffic
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                break;
            } => {
                if message.response_closed() {
                    continue;
                }

                match message {
                    Message::GetInfo {
                        identifier,
                        response,
                    } => {
                        let info = match identifier {
                            // TODO: Instead of pulling out the entire block, determine the
                            // height directly from the archive by mapping the digest to
                            // the index, which is the same as the height.
                            BlockID::Digest(digest) => self
                                .finalized_blocks
                                .get(ArchiveID::Key(&digest))
                                .await
                                .ok()
                                .flatten()
                                .map(|b| (b.height(), digest)),
                            BlockID::Height(height) => self
                                .finalizations_by_height
                                .get(ArchiveID::Index(height.get()))
                                .await
                                .ok()
                                .flatten()
                                .map(|f| (height, V::commitment_to_inner(f.proposal.payload))),
                            BlockID::Latest => self.get_latest().await.map(|(h, d, _)| (h, d)),
                        };
                        response.send_lossy(info);
                    }
                    Message::GetVerified { round, response } => {
                        let block = self.cache.get_verified(round).await.map(Into::into);
                        response.send_lossy(block);
                    }
                    Message::Forward {
                        round,
                        commitment,
                        recipients,
                    } => {
                        if matches!(&recipients, Recipients::Some(peers) if peers.is_empty()) {
                            continue;
                        }
                        let block = match self.take_proposed(round, commitment) {
                            Some(block) => block,
                            None => {
                                let Some(block) =
                                    self.find_block_by_commitment(&buffer, commitment).await
                                else {
                                    debug!(?commitment, "block not found for forwarding");
                                    continue;
                                };
                                block
                            }
                        };
                        buffer.send(round, block, recipients);
                    }
                    Message::Proposed { round, block, ack } => {
                        // If the round has already been pruned by tip advancement,
                        // `cache_verified` is a no-op because the round is below
                        // the retention floor (and no longer is required by consensus
                        // to make progress).
                        self.cache_verified(round, block.digest(), block.clone())
                            .await;
                        // Retain the block in memory so the subsequent
                        // `Forward` can broadcast it without reloading from
                        // storage. An older retained proposal (if any) is
                        // overwritten.
                        let commitment = V::commitment(&block);
                        self.last_proposed_block = Some((round, commitment, block));
                        ack.expect("durable ack present").send_lossy(());
                    }
                    Message::Verified { round, block, ack } => {
                        // If the round has already been pruned by tip advancement,
                        // `cache_verified` is a no-op because the round is below
                        // the retention floor (and no longer is required by consensus
                        // to make progress).
                        self.cache_verified(round, block.digest(), block).await;
                        ack.expect("durable ack present").send_lossy(());
                    }
                    Message::Certified { round, block, ack } => {
                        // If the round has already been pruned by tip advancement,
                        // `cache_block` is a no-op because the round is below
                        // the retention floor (and no longer is required by consensus
                        // to make progress).
                        self.cache_block(round, block.digest(), block).await;
                        ack.expect("durable ack present").send_lossy(());
                    }
                    Message::Notarization { notarization } => {
                        let round = notarization.round();
                        let commitment = notarization.proposal.payload;
                        let digest = V::commitment_to_inner(commitment);

                        // Store notarization by view
                        self.cache
                            .put_notarization(round, digest, notarization.clone())
                            .await;

                        // Search for block locally. A notarization alone is not
                        // enough to fetch missing proposal data, so remember the
                        // certificate and wait for local availability. Later
                        // finalization/repair paths may backfill data that is
                        // already finalized.
                        if let Some(block) =
                            self.find_block_by_commitment(&buffer, commitment).await
                        {
                            // If found, persist the block
                            self.cache_block(round, digest, block).await;
                        } else {
                            debug!(?round, "notarized block unavailable locally");
                        }
                    }
                    Message::Finalization { finalization } => {
                        // Cache finalization by round
                        let round = finalization.round();
                        let commitment = finalization.proposal.payload;
                        let digest = V::commitment_to_inner(commitment);
                        self.cache
                            .put_finalization(round, digest, finalization.clone())
                            .await;

                        // Search for block locally, otherwise fetch it remotely.
                        if let Some(block) =
                            self.find_block_by_commitment(&buffer, commitment).await
                        {
                            // If found, persist the block
                            let height = block.height();
                            self.update_processed_round_floor(height, round, &mut resolver)
                                .await;
                            if self
                                .store_finalization(
                                    height,
                                    digest,
                                    block,
                                    Some(finalization),
                                    &mut application,
                                )
                                .await
                            {
                                self.try_repair_gaps(&mut buffer, &mut resolver, &mut application)
                                    .await;
                                self.sync_finalized().await;
                                self.try_dispatch_blocks(&mut application).await;
                                debug!(?round, %height, "finalized block stored");
                            }
                        } else {
                            // The finalization carries a round and commitment, but
                            // not a height. Keep the request round-bound until the
                            // block is decoded.
                            debug!(?round, ?commitment, "finalized block missing");
                            self.floor.fetch_if_permitted(
                                &mut resolver,
                                Fetch {
                                    key: Request::Block(commitment),
                                    subscriber: Annotation::Finalized(Finalized::ByRound { round }),
                                },
                            );
                        }
                    }
                    Message::GetBlock {
                        identifier,
                        response,
                    } => match identifier {
                        BlockID::Digest(digest) => {
                            let result = self.find_block_by_digest(&buffer, digest).await;
                            response.send_lossy(result);
                        }
                        BlockID::Height(height) => {
                            let result = self.get_finalized_block(height).await;
                            response.send_lossy(result);
                        }
                        BlockID::Latest => {
                            let block = match self.get_latest().await {
                                Some((_, digest, _)) => {
                                    self.find_block_by_digest(&buffer, digest).await
                                }
                                None => None,
                            };
                            response.send_lossy(block);
                        }
                    },
                    Message::GetFinalization { height, response } => {
                        let finalization = self.get_finalization_by_height(height).await;
                        response.send_lossy(finalization);
                    }
                    Message::HintFinalized { height, targets } => {
                        // Skip if finalization is already available locally
                        if self.get_finalization_by_height(height).await.is_some() {
                            continue;
                        }

                        self.floor.fetch_targeted_if_permitted(
                            &mut resolver,
                            Fetch {
                                key: Request::<V::Commitment>::Finalized { height },
                                subscriber: Annotation::Finalized(Finalized::ByHeight { height }),
                            },
                            targets,
                        );
                    }
                    Message::SubscribeByDigest {
                        digest,
                        fallback,
                        response,
                    } => {
                        self.handle_subscribe(
                            fallback.into(),
                            BlockSubscriptionKey::Digest(digest),
                            response,
                            &mut resolver,
                            &mut waiters,
                            &mut buffer,
                        )
                        .await;
                    }
                    Message::SubscribeByCommitment {
                        commitment,
                        fallback,
                        response,
                    } => {
                        self.handle_subscribe(
                            fallback,
                            BlockSubscriptionKey::Commitment(commitment),
                            response,
                            &mut resolver,
                            &mut waiters,
                            &mut buffer,
                        )
                        .await;
                    }
                    Message::FetchNotarized { round, commitment } => {
                        self.handle_fetch_notarized(
                            round,
                            commitment,
                            &mut resolver,
                            &mut buffer,
                        )
                        .await;
                    }
                    Message::SetFloor { height } => {
                        if self.floor.height >= height {
                            warn!(
                                %height,
                                existing = %self.floor.height,
                                "floor not updated, lower than existing"
                            );
                            continue;
                        }

                        // Update the processed floor
                        self.update_processed_height(height, &mut resolver);
                        self.update_processed_round(height, &mut resolver).await;
                        if let Err(err) = self.application_metadata.sync().await {
                            error!(?err, %height, "failed to update floor");
                            return;
                        }

                        // Drop all pending acknowledgements. We must do this to prevent
                        // an in-process block from being processed that is below the new floor
                        // updating `floor.height`.
                        self.pending_acks.clear();

                        // The floor is durable, so cache/finalized data below it can be pruned.
                        if let Err(err) = self.prune_after_floor(height).await {
                            error!(?err, %height, "failed to prune data below floor");
                            return;
                        }

                        // Intentionally keep existing block subscriptions alive. Canceling
                        // waiters can have catastrophic consequences (nodes can get stuck in
                        // different views) as actors do not retry subscriptions on failed channels.
                    }
                    Message::Prune { height } => {
                        // Only allow pruning at or below the current floor
                        if height > self.floor.height {
                            warn!(%height, floor = %self.floor.height, "prune height above floor, ignoring");
                            continue;
                        }

                        // Prune the finalized block and finalization certificate archives in parallel.
                        if let Err(err) = self.prune_finalized_archives(height).await {
                            error!(?err, %height, "failed to prune finalized archives");
                            return;
                        }

                        // Intentionally keep existing block subscriptions alive. Canceling
                        // waiters can have catastrophic consequences (nodes can get stuck in
                        // different views) as actors do not retry subscriptions on failed channels.
                    }
                }
            },
            // Handle resolver messages last (batched up to max_repair, sync once)
            Some(message) = resolver_rx.recv() else {
                debug!("handler closed, shutting down");
                return;
            } => {
                // Drain up to max_repair messages: blocks handled immediately,
                // certificates batched for verification, produces deferred.
                let mut needs_sync = false;
                let mut handled = false;
                let mut produces = Vec::new();
                let mut delivers = Vec::new();
                for msg in std::iter::once(message)
                    .chain(std::iter::from_fn(|| resolver_rx.try_recv().ok()))
                    .take(self.max_repair.get())
                {
                    if msg.response_closed() {
                        continue;
                    }
                    handled = true;

                    match msg {
                        handler::Message::Produce { key, response } => {
                            produces.push((key, response));
                        }
                        handler::Message::Deliver {
                            delivery,
                            value,
                            response,
                        } => {
                            needs_sync |= self
                                .handle_deliver(
                                    delivery,
                                    value,
                                    response,
                                    &mut delivers,
                                    &mut application,
                                    &mut resolver,
                                )
                                .await;
                        }
                    }
                }
                if !handled {
                    continue;
                }

                // Batch verify and process all delivers.
                needs_sync |= self
                    .verify_delivered(delivers, &mut application, &mut resolver)
                    .await;

                // Attempt to fill gaps before handling produce requests (so we
                // can serve data we just received).
                needs_sync |= self
                    .try_repair_gaps(&mut buffer, &mut resolver, &mut application)
                    .await;

                // Sync archives before responding to peers (prioritize our own
                // durability).
                if needs_sync {
                    self.sync_finalized().await;
                    self.try_dispatch_blocks(&mut application).await;
                }

                // Handle produce requests in parallel.
                join_all(
                    produces
                        .into_iter()
                        .map(|(key, response)| self.handle_produce(key, response, &buffer)),
                )
                .await;
            },
        }
    }

    /// Handle a produce request from a remote peer.
    async fn handle_produce<Buf: Buffer<V>>(
        &self,
        key: ResolverRequestFor<V>,
        response: oneshot::Sender<Bytes>,
        buffer: &Buf,
    ) {
        match key {
            Request::Block(commitment) => {
                let Some(block) = self.find_block_by_commitment(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy(block.encode());
            }
            Request::Finalized { height } => {
                let Some(finalization) = self.get_finalization_by_height(height).await else {
                    debug!(%height, "finalization missing on request");
                    return;
                };
                let Some(block) = self.get_finalized_block(height).await else {
                    debug!(%height, "finalized block missing on request");
                    return;
                };
                response.send_lossy((finalization, block).encode());
            }
            Request::Notarized { round } => {
                let Some(notarization) = self.cache.get_notarization(round).await else {
                    debug!(?round, "notarization missing on request");
                    return;
                };
                let commitment = notarization.proposal.payload;
                let Some(block) = self.find_block_by_commitment(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy((notarization, block).encode());
            }
        }
    }

    /// Handle a local subscription request for a block.
    async fn handle_subscribe<Buf: Buffer<V>>(
        &mut self,
        fallback: CommitmentFallback,
        key: BlockSubscriptionKeyFor<V>,
        response: oneshot::Sender<V::Block>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
        waiters: &mut AbortablePool<Result<V::Block, BlockSubscriptionKeyFor<V>>>,
        buffer: &mut Buf,
    ) {
        let digest = match key {
            BlockSubscriptionKey::Digest(digest) => digest,
            BlockSubscriptionKey::Commitment(commitment) => V::commitment_to_inner(commitment),
        };

        // Check for block locally.
        let block = match key {
            BlockSubscriptionKey::Digest(digest) => self.find_block_by_digest(buffer, digest).await,
            BlockSubscriptionKey::Commitment(commitment) => {
                self.find_block_by_commitment(buffer, commitment).await
            }
        };
        if let Some(block) = block {
            response.send_lossy(block);
            return;
        }

        // We don't have the block locally. Local-only waits reach this point
        // without a round or height, so they only register a subscriber below.
        //
        // Round-based fetching is for notarized proposal lookups whose height is
        // not known before the request. Height-based fetching is only for callers
        // that already have a validated pruning height.
        match fallback {
            CommitmentFallback::FetchByRound { round } => {
                // Fetch the notarized proposal for this round. The response
                // must include a certificate so the commitment is tied to the
                // certified round context. The decoded block is heightable, but
                // that height is not known soon enough to key, coalesce, or prune
                // the in-flight resolver request.
                if !self.floor.fetch_if_permitted(
                    resolver,
                    Fetch {
                        key: Request::Notarized { round },
                        subscriber: Annotation::Notarization { round },
                    },
                ) {
                    return;
                }
                debug!(?round, ?digest, "requested block missing");
            }
            CommitmentFallback::FetchByCommitment { height } => {
                let commitment = match key {
                    BlockSubscriptionKey::Commitment(commitment) => commitment,
                    BlockSubscriptionKey::Digest(_) => {
                        unreachable!("digest subscriptions cannot request commitment fallback")
                    }
                };

                // This path is only for accepted ancestry or finalized repair,
                // never for a candidate block's immediate parent.
                if !self.floor.fetch_if_permitted(
                    resolver,
                    Fetch {
                        key: Request::Block(commitment),
                        subscriber: Annotation::Certified { height },
                    },
                ) {
                    return;
                }
                debug!(%height, ?commitment, ?digest, "requested certified ancestry block missing");
            }
            CommitmentFallback::Wait => {}
        }

        let round = match fallback {
            CommitmentFallback::FetchByRound { round } => Some(round),
            CommitmentFallback::Wait | CommitmentFallback::FetchByCommitment { .. } => None,
        };

        // Register subscriber.
        match key {
            BlockSubscriptionKey::Digest(digest) => {
                debug!(?round, ?digest, "registering subscriber");
            }
            BlockSubscriptionKey::Commitment(commitment) => {
                debug!(?round, ?commitment, ?digest, "registering subscriber");
            }
        }
        match self.block_subscriptions.entry(key) {
            Entry::Occupied(mut entry) => {
                entry.get_mut().subscribers.push(response);
            }
            Entry::Vacant(entry) => {
                let rx = match key {
                    BlockSubscriptionKey::Digest(digest) => buffer.subscribe_by_digest(digest),
                    BlockSubscriptionKey::Commitment(commitment) => {
                        buffer.subscribe_by_commitment(commitment)
                    }
                };
                let waiter_key = key;
                let aborter = waiters.push(async move { rx.await.map_err(|_| waiter_key) });
                entry.insert(BlockSubscription {
                    subscribers: vec![response],
                    _aborter: aborter,
                });
            }
        }
    }

    async fn handle_fetch_notarized<Buf: Buffer<V>>(
        &mut self,
        round: Round,
        commitment: V::Commitment,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
        buffer: &mut Buf,
    ) {
        if self
            .find_block_by_commitment(buffer, commitment)
            .await
            .is_some()
        {
            return;
        }
        self.floor.fetch_if_permitted(
            resolver,
            Fetch {
                key: Request::Notarized { round },
                subscriber: Annotation::Notarization { round },
            },
        );
    }

    /// Handle a deliver message from the resolver. Block delivers are handled
    /// immediately. Finalized/Notarized delivers are parsed and structurally
    /// validated, then collected into `delivers` for batch certificate verification.
    /// Returns true if finalization archives were written and need syncing.
    async fn handle_deliver(
        &mut self,
        delivery: Delivery<ResolverRequestFor<V>, Annotation>,
        mut value: Bytes,
        response: oneshot::Sender<bool>,
        delivers: &mut Vec<PendingVerification<P::Scheme, V>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) -> bool {
        let Delivery { key, subscribers } = delivery;
        match key {
            Request::Block(commitment) => {
                let block_cfg = V::block_cfg(&self.block_codec_config, commitment);
                let Ok(block) = V::Block::decode_cfg(value.as_ref(), &block_cfg) else {
                    response.send_lossy(false);
                    return false;
                };
                if V::commitment(&block) != commitment {
                    response.send_lossy(false);
                    return false;
                }

                // The commitment validates the peer response. Annotation height
                // is local metadata, not a validity condition for the committed
                // block. Subscribers still need the block so their own validation
                // can reject bad ancestry.
                self.notify_subscribers(&block);

                // The peer-visible request only says "give me this block".
                // Local annotations explain why the block was requested and
                // therefore where, if anywhere, it should be stored. Certified
                // annotations carry a pruning hint, but certified storage uses
                // the decoded block height. By-height finalization annotations
                // must match the decoded height before driving finalized storage.
                let height = block.height();
                let digest = block.digest();
                let mut annotations = Vec::new();
                for annotation in subscribers {
                    let keep = match annotation {
                        Annotation::Finalized(Finalized::ByHeight { height: expected }) => {
                            // Height-bound finalization requests are derived from
                            // finalized-chain state, so a matching commitment
                            // must decode at the expected height.
                            assert_eq!(expected, height);
                            true
                        }
                        Annotation::Certified { .. }
                        | Annotation::Finalized(Finalized::ByRound { .. }) => true,
                        // Notarization annotations are only meaningful on
                        // `Request::Notarized` deliveries. They tag
                        // round-bound fetches for resolver pruning, while
                        // notarized delivery validation uses the request key
                        // and should not drive block-keyed storage.
                        Annotation::Notarization { .. } => {
                            unreachable!("notarization annotation on block delivery")
                        }
                    };
                    if keep {
                        annotations.push(annotation);
                    } else {
                        debug!(?commitment, %height, "ignoring stale block annotation");
                    }
                }

                // Round-bound proposal-parent fetches are `Request::Notarized`
                // deliveries and are handled below. In this block-keyed path,
                // `Finalized` means the block belongs in the finalized chain.
                let finalization = self.cache.get_finalization_for(digest).await;
                if let Some(finalization) = &finalization {
                    self.update_processed_round_floor(height, finalization.round(), resolver)
                        .await;
                }
                let wrote = if finalization.is_some()
                    || annotations
                        .iter()
                        .any(|annotation| matches!(annotation, Annotation::Finalized(_)))
                {
                    self.store_finalization(height, digest, block, finalization, application)
                        .await
                } else {
                    if annotations
                        .iter()
                        .any(|annotation| matches!(annotation, Annotation::Certified { .. }))
                        && height > self.floor.height
                    {
                        if let Some(bounds) = self.epocher.containing(height) {
                            self.cache
                                .put_certified(bounds.epoch(), height, digest, block.clone().into())
                                .await;
                        }
                    }
                    false
                };
                debug!(?digest, %height, "received block");
                response.send_lossy(true);
                wrote
            }
            Request::Finalized { height } => {
                let Some(bounds) = self.epocher.containing(height) else {
                    debug!(
                        %height,
                        floor = %self.floor.height,
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return false;
                };
                let Some(scheme) = self.get_scheme_certificate_verifier(bounds.epoch()) else {
                    debug!(
                        %height,
                        floor = %self.floor.height,
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return false;
                };

                let certificate_codec_config = scheme.certificate_codec_config();
                let Ok(finalization) =
                    Finalization::read_cfg(&mut value, &certificate_codec_config)
                else {
                    response.send_lossy(false);
                    return false;
                };

                let commitment = finalization.proposal.payload;
                let block_cfg = V::block_cfg(&self.block_codec_config, commitment);
                let Ok(block) = V::Block::decode_cfg(value, &block_cfg) else {
                    response.send_lossy(false);
                    return false;
                };

                if block.height() != height
                    || V::commitment(&block) != commitment
                    || finalization.epoch() != bounds.epoch()
                {
                    response.send_lossy(false);
                    return false;
                }
                delivers.push(PendingVerification::Finalized {
                    finalization,
                    block,
                    response,
                });
                false
            }
            Request::Notarized { round } => {
                let Some(scheme) = self.get_scheme_certificate_verifier(round.epoch()) else {
                    debug!(
                        ?round,
                        floor = %self.floor.height,
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return false;
                };

                let certificate_codec_config = scheme.certificate_codec_config();
                let Ok(notarization) =
                    Notarization::read_cfg(&mut value, &certificate_codec_config)
                else {
                    response.send_lossy(false);
                    return false;
                };

                let commitment = notarization.proposal.payload;
                let block_cfg = V::block_cfg(&self.block_codec_config, commitment);
                let Ok(block) = V::Block::decode_cfg(value, &block_cfg) else {
                    response.send_lossy(false);
                    return false;
                };

                if notarization.round() != round
                    || V::commitment(&block) != notarization.proposal.payload
                {
                    response.send_lossy(false);
                    return false;
                }
                delivers.push(PendingVerification::Notarized {
                    notarization,
                    block,
                    response,
                });
                false
            }
        }
    }

    /// Batch verify pending certificates and process valid items. Returns true
    /// if finalization archives were written and need syncing.
    async fn verify_delivered(
        &mut self,
        mut delivers: Vec<PendingVerification<P::Scheme, V>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) -> bool {
        delivers.retain(|item| !item.response_closed());
        if delivers.is_empty() {
            return false;
        }

        // Extract (subject, certificate) pairs for batch verification.
        let certs: Vec<_> = delivers
            .iter()
            .map(|item| match item {
                PendingVerification::Finalized { finalization, .. } => (
                    Subject::Finalize {
                        proposal: &finalization.proposal,
                    },
                    &finalization.certificate,
                ),
                PendingVerification::Notarized { notarization, .. } => (
                    Subject::Notarize {
                        proposal: &notarization.proposal,
                    },
                    &notarization.certificate,
                ),
            })
            .collect();

        // Batch verify using the all-epoch verifier if available, otherwise
        // batch verify per epoch using scoped verifiers.
        let verified = if let Some(scheme) = self.provider.all() {
            verify_certificates(
                self.context.as_mut(),
                scheme.as_ref(),
                &certs,
                &self.strategy,
            )
        } else {
            let mut verified = vec![false; delivers.len()];

            // Group indices by epoch.
            let mut by_epoch: BTreeMap<Epoch, Vec<usize>> = BTreeMap::new();
            for (i, item) in delivers.iter().enumerate() {
                let epoch = match item {
                    PendingVerification::Notarized { notarization, .. } => notarization.epoch(),
                    PendingVerification::Finalized { finalization, .. } => finalization.epoch(),
                };
                by_epoch.entry(epoch).or_default().push(i);
            }

            // Batch verify each epoch group.
            for (epoch, indices) in &by_epoch {
                let Some(scheme) = self.provider.scoped(*epoch) else {
                    continue;
                };
                let group: Vec<_> = indices.iter().map(|&i| certs[i]).collect();
                let results = verify_certificates(
                    self.context.as_mut(),
                    scheme.as_ref(),
                    &group,
                    &self.strategy,
                );
                for (j, &idx) in indices.iter().enumerate() {
                    verified[idx] = results[j];
                }
            }
            verified
        };

        // Process each verified item, rejecting unverified ones.
        let mut wrote = false;
        for (index, item) in delivers.drain(..).enumerate() {
            if !verified[index] {
                match item {
                    PendingVerification::Finalized { response, .. }
                    | PendingVerification::Notarized { response, .. } => {
                        response.send_lossy(false);
                    }
                }
                continue;
            }
            match item {
                PendingVerification::Finalized {
                    finalization,
                    block,
                    response,
                } => {
                    // Valid finalization received.
                    response.send_lossy(true);
                    let round = finalization.round();
                    let height = block.height();
                    let digest = block.digest();
                    debug!(?round, %height, "received finalization");
                    self.update_processed_round_floor(height, round, resolver)
                        .await;

                    wrote |= self
                        .store_finalization(height, digest, block, Some(finalization), application)
                        .await;
                }
                PendingVerification::Notarized {
                    notarization,
                    block,
                    response,
                } => {
                    // Valid notarization received.
                    response.send_lossy(true);
                    let round = notarization.round();
                    let commitment = notarization.proposal.payload;
                    let digest = V::commitment_to_inner(commitment);
                    debug!(?round, ?digest, "received notarization");

                    // If there exists a finalization certificate for this block, we
                    // should finalize it. This could finalize the block faster when
                    // a notarization then a finalization are received via consensus
                    // and we resolve the notarization request before the block request.
                    let height = block.height();
                    if let Some(finalization) = self.cache.get_finalization_for(digest).await {
                        self.update_processed_round_floor(height, finalization.round(), resolver)
                            .await;

                        // SAFETY: `digest` identifies a unique `commitment`, so this
                        // cached finalization payload must match `V::commitment(&block)`.
                        wrote |= self
                            .store_finalization(
                                height,
                                digest,
                                block.clone(),
                                Some(finalization),
                                application,
                            )
                            .await;
                    }

                    // Cache the notarization and block.
                    self.cache_block(round, digest, block).await;
                    self.cache
                        .put_notarization(round, digest, notarization)
                        .await;
                }
            }
        }

        wrote
    }

    /// Returns a scheme suitable for verifying certificates at the given epoch.
    ///
    /// Prefers a certificate verifier if available, otherwise falls back
    /// to the scheme for the given epoch.
    fn get_scheme_certificate_verifier(&self, epoch: Epoch) -> Option<Arc<P::Scheme>> {
        self.provider.all().or_else(|| self.provider.scoped(epoch))
    }

    // -------------------- Waiters --------------------

    /// Notify any subscribers for the given digest with the provided block.
    fn notify_subscribers(&mut self, block: &V::Block) {
        if let Some(mut bs) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Digest(block.digest()))
        {
            for subscriber in bs.subscribers.drain(..) {
                subscriber.send_lossy(block.clone());
            }
        }
        if let Some(mut bs) = self
            .block_subscriptions
            .remove(&BlockSubscriptionKey::Commitment(V::commitment(block)))
        {
            for subscriber in bs.subscribers.drain(..) {
                subscriber.send_lossy(block.clone());
            }
        }
    }

    // -------------------- Application Dispatch --------------------

    /// Attempt to dispatch the next finalized block to the application if ready.
    ///
    /// Dispatch finalized blocks to the application until the pipeline is full
    /// or no more blocks are available.
    ///
    /// This does NOT advance `floor.height` or sync metadata. It only
    /// sends blocks to the application and enqueues pending acks. Metadata is
    /// updated later, in a subsequent `select_loop!` iteration, when acks
    /// arrive and [`Self::handle_block_processed`] calls
    /// [`Self::update_processed_height`].
    ///
    /// Callers must only invoke this after [`Self::sync_finalized`] has made any
    /// preceding finalized-archive writes durable. In other words, anything fed
    /// to the application from this method is already durably persisted in marshal.
    ///
    /// Acks are processed in FIFO order so `floor.height` always
    /// advances sequentially.
    ///
    /// # Crash safety
    ///
    /// Because `select_loop!` arms run to completion, the caller's
    /// [`Self::sync_finalized`] always executes before the ack handler runs. This
    /// guarantees archive data is durable before `floor.height`
    /// advances:
    ///
    /// ```text
    /// Iteration N (caller):
    ///   store_finalization  ->  Archive::put (buffered)
    ///   sync_finalized      ->  archive durable
    ///   try_dispatch_blocks  ->  sends blocks to app, enqueues pending acks
    ///
    /// Iteration M (ack handler, M > N):
    ///   handle_block_processed   ->  update_processed_height  ->  metadata buffered
    ///   application_metadata.sync ->  metadata durable
    /// ```
    async fn try_dispatch_blocks(
        &mut self,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) {
        while self.pending_acks.has_capacity() {
            let next_height = self.pending_acks.next_dispatch_height(self.floor.height);
            let Some(block) = self.get_finalized_block(next_height).await else {
                return;
            };
            assert_eq!(
                block.height(),
                next_height,
                "finalized block height mismatch"
            );

            let (height, commitment) = (block.height(), V::commitment(&block));
            let (ack, ack_waiter) = A::handle();
            application.report(Update::Block(V::into_inner(block), ack));
            self.pending_acks.enqueue(PendingAck {
                height,
                commitment,
                receiver: ack_waiter,
            });
        }
    }

    /// Handle acknowledgement from the application that a block has been processed.
    ///
    /// Buffers the processed height update but does NOT sync to durable storage.
    /// The caller must sync metadata after processing all ready acks.
    async fn handle_block_processed(
        &mut self,
        height: Height,
        commitment: V::Commitment,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        // Update the processed height (buffered, not synced)
        self.update_processed_height(height, resolver);

        // Prune any useless requests.
        resolver.retain(
            move |request, _| !matches!(request, Request::Block(pending) if *pending == commitment),
        );

        self.update_processed_round(height, resolver).await;
    }

    // -------------------- Prunable Storage --------------------

    /// Add a verified block to the prunable archive.
    async fn cache_verified(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        block: V::Block,
    ) {
        self.notify_subscribers(&block);
        self.cache.put_verified(round, digest, block.into()).await;
    }

    /// If a block previously accepted via [`Message::Proposed`] matches the
    /// supplied `(round, commitment)`, remove and return it.
    fn take_proposed(&mut self, round: Round, commitment: V::Commitment) -> Option<V::Block> {
        let (cached_round, cached_commitment, _) = self.last_proposed_block.as_ref()?;
        if *cached_round != round || *cached_commitment != commitment {
            return None;
        }
        self.last_proposed_block.take().map(|(_, _, block)| block)
    }

    /// Add a notarized block to the prunable archive.
    async fn cache_block(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        block: V::Block,
    ) {
        self.notify_subscribers(&block);
        self.cache.put_block(round, digest, block.into()).await;
    }

    /// Sync both finalization archives to durable storage.
    ///
    /// Must be called within the same `select_loop!` arm as any preceding
    /// [`Self::store_finalization`] / [`Self::try_repair_gaps`] writes, before yielding back
    /// to the loop. This is the durability barrier for application delivery:
    /// [`Self::try_dispatch_blocks`] must run only after this sync completes.
    /// It also ensures archives are durable before the ack handler advances
    /// `floor.height`. See [`Self::try_dispatch_blocks`] for details.
    async fn sync_finalized(&mut self) {
        if let Err(e) = try_join!(
            async {
                self.finalized_blocks.sync().await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .sync()
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
        ) {
            panic!("failed to sync finalization archives: {e}");
        }
    }

    // -------------------- Immutable Storage --------------------

    /// Get a finalized block from the immutable archive.
    async fn get_finalized_block(&self, height: Height) -> Option<V::Block> {
        match self
            .finalized_blocks
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(stored) => stored.map(|stored| stored.into()),
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    async fn get_finalization_by_height(
        &self,
        height: Height,
    ) -> Option<Finalization<P::Scheme, V::Commitment>> {
        match self
            .finalizations_by_height
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Add a finalized block, and optionally a finalization, to the archive.
    ///
    /// After persisting the block, the caller must sync finalized archives
    /// before dispatching the next contiguous block to the application. The
    /// buffered archive writes from this method are not a sufficient durability
    /// guarantee for downstream application state transitions on their own.
    ///
    /// Writes are buffered and not synced. The caller must call
    /// [sync_finalized](Self::sync_finalized) before yielding to the
    /// `select_loop!` so that archive data is durable before the ack handler
    /// advances `floor.height`. See [`Self::try_dispatch_blocks`] for the
    /// crash safety invariant.
    async fn store_finalization(
        &mut self,
        height: Height,
        digest: <V::Block as Digestible>::Digest,
        block: V::Block,
        finalization: Option<Finalization<P::Scheme, V::Commitment>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) -> bool {
        // Blocks below the last processed height are not useful to us, so we ignore them (this
        // has the nice byproduct of ensuring we don't call a backing store with a block below the
        // pruning boundary)
        if height <= self.floor.height {
            debug!(
                %height,
                floor = %self.floor.height,
                ?digest,
                "dropping finalization at or below processed height floor"
            );
            return false;
        }
        self.notify_subscribers(&block);

        // Convert block to storage format
        let stored: V::StoredBlock = block.into();
        let round = finalization.as_ref().map(|f| f.round());

        // In parallel, update the finalized blocks and finalizations archives
        if let Err(e) = try_join!(
            // Update the finalized blocks archive
            async {
                self.finalized_blocks.put(stored).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            // Update the finalizations archive (if provided)
            async {
                if let Some(finalization) = finalization {
                    self.finalizations_by_height
                        .put(height, digest, finalization)
                        .await
                        .map_err(Box::new)?;
                }
                Ok::<_, BoxedError>(())
            }
        ) {
            panic!("failed to finalize: {e}");
        }

        // Update metrics and application
        if let Some(round) = round.filter(|_| height > self.tip) {
            application.report(Update::Tip(round, height, digest));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        true
    }

    /// Get the latest finalized block information (height and digest tuple).
    ///
    /// Blocks are only finalized directly with a finalization or indirectly via a descendant
    /// block's finalization. Thus, the highest known finalized block must itself have a direct
    /// finalization.
    ///
    /// We return the height and digest using the highest known finalization that we know the
    /// block height for. While it's possible that we have a later finalization, if we do not have
    /// the full block for that finalization, we do not know its height and therefore it would not
    /// yet be found in the `finalizations_by_height` archive. While not checked explicitly, we
    /// should have the associated block (in the `finalized_blocks` archive) for the information
    /// returned.
    async fn get_latest(&mut self) -> Option<(Height, <V::Block as Digestible>::Digest, Round)> {
        let height = self.finalizations_by_height.last_index()?;
        let finalization = self
            .get_finalization_by_height(height)
            .await
            .expect("finalization missing");
        Some((
            height,
            V::commitment_to_inner(finalization.proposal.payload),
            finalization.round(),
        ))
    }

    // -------------------- Mixed Storage --------------------

    /// Looks for a block in cache and finalized storage by digest.
    async fn find_block_in_storage(
        &self,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<V::Block> {
        // Check verified / notarized blocks via cache manager.
        if let Some(block) = self.cache.find_block(digest).await {
            return Some(block.into());
        }
        // Check finalized blocks.
        match self.finalized_blocks.get(ArchiveID::Key(&digest)).await {
            Ok(stored) => stored.map(|stored| stored.into()),
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Looks for a block in cache and finalized storage by inner digest, returning
    /// only blocks that match `predicate`.
    async fn find_block_in_storage_matching(
        &self,
        digest: <V::Block as Digestible>::Digest,
        mut predicate: impl FnMut(&V::Block) -> bool,
    ) -> Option<V::Block> {
        if let Some(block) = self
            .cache
            .find_block_matching(digest, |stored| {
                let block = stored.clone().into();
                predicate(&block)
            })
            .await
        {
            return Some(block.into());
        }

        match self.finalized_blocks.get(ArchiveID::Key(&digest)).await {
            Ok(Some(stored)) => {
                let block = stored.into();
                predicate(&block).then_some(block)
            }
            Ok(None) => None,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Looks for a block anywhere in local storage using only the digest.
    ///
    /// This is used when we only have a digest (during gap repair following
    /// parent links).
    async fn find_block_by_digest<Buf: Buffer<V>>(
        &self,
        buffer: &Buf,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<V::Block> {
        if let Some(block) = buffer.find_by_digest(digest).await {
            return Some(block);
        }
        self.find_block_in_storage(digest).await
    }

    /// Looks for a block anywhere in local storage using the full commitment.
    ///
    /// This is used when we have a full commitment (from notarizations/finalizations).
    /// Having the full commitment may enable additional retrieval mechanisms.
    async fn find_block_by_commitment<Buf: Buffer<V>>(
        &self,
        buffer: &Buf,
        commitment: V::Commitment,
    ) -> Option<V::Block> {
        if let Some(block) = buffer.find_by_commitment(commitment).await {
            return Some(block);
        }
        self.find_block_in_storage_matching(V::commitment_to_inner(commitment), |block| {
            V::commitment(block) == commitment
        })
        .await
    }

    /// Attempt to repair any identified gaps in the finalized blocks archive. The total
    /// number of missing heights that can be repaired at once is bounded by `self.max_repair`,
    /// though multiple gaps may be spanned.
    ///
    /// This also handles the "trailing" case where finalizations exist beyond
    /// the last stored block (the block data was lost before a crash). The
    /// trailing block is anchored first so that backward gap repair can fill
    /// inward from it.
    ///
    /// Writes are buffered. Returns `true` if this call wrote repaired blocks and
    /// needs a subsequent [`sync_finalized`](Self::sync_finalized).
    async fn try_repair_gaps<Buf: Buffer<V>>(
        &mut self,
        buffer: &mut Buf,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) -> bool {
        let mut wrote = false;
        let start = self.floor.height.next();

        // If finalizations extend beyond the last stored block, anchor the
        // trailing block so the gap repair loop below can walk backward from it.
        if let Some(last_finalized) = self.finalizations_by_height.last_index() {
            let have_block = self
                .finalized_blocks
                .last_index()
                .is_some_and(|last| last >= last_finalized);
            if last_finalized > self.floor.height && !have_block {
                // Get the finalization for the last finalized block.
                let finalization = self
                    .get_finalization_by_height(last_finalized)
                    .await
                    .expect("finalization missing");
                let commitment = finalization.proposal.payload;
                if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
                    // If found, persist the block.
                    let digest = block.digest();
                    wrote |= self
                        .store_finalization(
                            last_finalized,
                            digest,
                            block,
                            Some(finalization),
                            application,
                        )
                        .await;
                } else {
                    // Request the missing block.
                    self.floor.fetch_if_permitted(
                        resolver,
                        Fetch {
                            key: Request::Block(commitment),
                            subscriber: Annotation::Finalized(Finalized::ByHeight {
                                height: last_finalized,
                            }),
                        },
                    );
                }
            }
        }

        // Fill internal gaps by walking backward from each gap's end block.
        'cache_repair: loop {
            let (gap_start, Some(gap_end)) = self.finalized_blocks.next_gap(start) else {
                // No gaps detected
                return wrote;
            };

            // Attempt to repair the gap backwards from the end of the gap, using
            // blocks from our local storage.
            let Some(mut cursor) = self.get_finalized_block(gap_end).await else {
                panic!("gapped block missing that should exist: {gap_end}");
            };

            // Compute the lower bound of the recursive repair. `gap_start` is `Some`
            // if `start` is not in a gap. We add one to it to ensure we don't
            // re-persist it to the database in the repair loop below.
            let gap_start = gap_start.map(Height::next).unwrap_or(start);

            // Iterate backwards, repairing blocks as we go.
            while cursor.height() > gap_start {
                let parent_digest = cursor.parent();
                let parent_commitment = V::parent_commitment(&cursor);
                if let Some(block) = self
                    .find_block_by_commitment(buffer, parent_commitment)
                    .await
                {
                    let finalization = self.cache.get_finalization_for(parent_digest).await;
                    wrote |= self
                        .store_finalization(
                            block.height(),
                            parent_digest,
                            block.clone(),
                            finalization,
                            application,
                        )
                        .await;
                    debug!(height = %block.height(), "repaired block");
                    cursor = block;
                } else {
                    // Request the next missing commitment.
                    //
                    // SAFETY: We can rely on this derived parent commitment because
                    // the block is provably a member of the finalized chain due to the end
                    // boundary of the gap being finalized.
                    let parent_height = cursor
                        .height()
                        .previous()
                        .expect("cursor above gap start has a parent");
                    self.floor.fetch_if_permitted(
                        resolver,
                        Fetch {
                            key: Request::Block(parent_commitment),
                            subscriber: Annotation::Finalized(Finalized::ByHeight {
                                height: parent_height,
                            }),
                        },
                    );
                    break 'cache_repair;
                }
            }
        }

        // Request any finalizations for missing items in the archive, up to
        // the `max_repair` quota. This may help shrink the size of the gap
        // closest to the application's processed height if finalizations
        // for the requests' heights exist. If not, we rely on the recursive
        // digest fetches above.
        let missing_items = self
            .finalized_blocks
            .missing_items(start, self.max_repair.get());
        let requests: Vec<_> = missing_items
            .into_iter()
            .map(|height| Fetch {
                key: Request::<V::Commitment>::Finalized { height },
                subscriber: Annotation::Finalized(Finalized::ByHeight { height }),
            })
            .collect();
        if !requests.is_empty() {
            self.floor.fetch_all_if_permitted(resolver, requests);
        }
        wrote
    }

    /// Buffers a processed height update in memory and metrics. Does NOT sync
    /// to durable storage. Sync metadata after buffered updates to make them durable.
    fn update_processed_height(
        &mut self,
        height: Height,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        self.application_metadata.put(LATEST_KEY, height);
        self.floor.height = height;
        let _ = self.processed_height.try_set(self.floor.height.get());

        // Prune any existing requests below the new floor.
        resolver.retain(above_height_floor::<V::Commitment>(height));
    }

    /// Returns the latest known finalization round at or below the processed height.
    async fn latest_processed_round(finalizations_by_height: &FC, height: Height) -> Round {
        let Some(finalization_height) = finalizations_by_height
            .ranges_from(Height::zero())
            .filter_map(|(start, end)| (start <= height).then_some(end.min(height)))
            .max()
        else {
            return Round::zero();
        };

        match finalizations_by_height
            .get(ArchiveID::Index(finalization_height.get()))
            .await
        {
            Ok(Some(finalization)) => finalization.round(),
            Ok(None) => panic!("processed finalization missing from stored range"),
            Err(err) => panic!("failed to get processed finalization: {err}"),
        }
    }

    /// Buffers a processed round update in memory and prunes round-bound requests.
    async fn update_processed_round(
        &mut self,
        height: Height,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        let Some(finalization) = self.get_finalization_by_height(height).await else {
            return;
        };
        self.update_processed_round_floor(height, finalization.round(), resolver)
            .await;
    }

    /// Buffers a processed round floor update in memory and prunes round-bound requests.
    async fn update_processed_round_floor(
        &mut self,
        height: Height,
        round: Round,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) {
        if height > self.floor.height || round <= self.floor.round {
            return;
        }

        let previous = self.floor.round;
        self.floor.round = round;

        // Retain view-indexed cache data for a window behind the previously
        // processed finalized block.
        let prune_round = Round::new(
            previous.epoch(),
            previous.view().saturating_sub(self.view_retention_timeout),
        );
        self.prune_view_cache(prune_round).await;

        // Prune round-bound requests at or below the processed round.
        resolver.retain(above_round_floor::<V::Commitment>(self.floor.round));
    }

    /// Prunes finalized blocks and certificates below the given height.
    async fn prune_finalized_archives(&mut self, height: Height) -> Result<(), BoxedError> {
        try_join!(
            async {
                self.finalized_blocks
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )?;
        Ok(())
    }

    /// Prunes view-indexed cache data below the given round.
    async fn prune_view_cache(&mut self, round: Round) {
        self.cache.prune_by_view(round).await;
    }

    /// Prunes finalized archives and height-indexed certified cache data below the durable floor.
    async fn prune_after_floor(&mut self, height: Height) -> Result<(), BoxedError> {
        let cache = &mut self.cache;
        let finalized_blocks = &mut self.finalized_blocks;
        let finalizations_by_height = &mut self.finalizations_by_height;
        try_join!(
            async {
                cache.prune_by_height(height).await;
                Ok::<_, BoxedError>(())
            },
            async {
                finalized_blocks.prune(height).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                finalizations_by_height
                    .prune(height)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )?;
        Ok(())
    }
}
