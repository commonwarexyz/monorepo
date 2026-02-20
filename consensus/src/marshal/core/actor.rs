use super::{
    cache,
    mailbox::{Mailbox, Message},
    Buffer, IntoBlock, Variant,
};
use crate::{
    marshal::{
        resolver::handler::{self, Request},
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
use commonware_codec::{Decode, Encode, Read};
use commonware_cryptography::{
    certificate::{Provider, Scheme as CertificateScheme},
    Digestible,
};
use commonware_macros::select_loop;
use commonware_parallel::Strategy;
use commonware_resolver::Resolver;
use commonware_runtime::{
    spawn_cell, telemetry::metrics::status::GaugeExt, BufferPooler, Clock, ContextCell, Handle,
    Metrics, Spawner, Storage,
};
use commonware_storage::{
    archive::Identifier as ArchiveID,
    metadata::{self, Metadata},
};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, mpsc, oneshot},
    futures::{AbortablePool, Aborter, OptionFuture},
    sequence::U64,
    Acknowledgement, BoxedError,
};
use futures::{future::join_all, try_join, FutureExt};
use pin_project::pin_project;
use prometheus_client::metrics::gauge::Gauge;
use rand_core::CryptoRngCore;
use std::{
    collections::{btree_map::Entry, BTreeMap, VecDeque},
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    sync::Arc,
};
use tracing::{debug, error, info, warn};

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
    mailbox: mpsc::Receiver<Message<P::Scheme, V>>,

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
    block_codec_config: <V::Block as Read>::Cfg,
    // Strategy for parallel operations
    strategy: T,

    // ---------- State ----------
    // Last view processed
    last_processed_round: Round,
    // Last height processed by the application
    last_processed_height: Height,
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
        config: Config<V::Block, P, ES, T>,
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
            context.with_label("cache"),
            prunable_config,
            config.block_codec_config.clone(),
        )
        .await;

        // Initialize metadata tracking application progress
        let application_metadata = Metadata::init(
            context.with_label("application_metadata"),
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

        // Create metrics
        let finalized_height = Gauge::default();
        context.register(
            "finalized_height",
            "Finalized height of application",
            finalized_height.clone(),
        );
        let processed_height = Gauge::default();
        context.register(
            "processed_height",
            "Processed height of application",
            processed_height.clone(),
        );
        let _ = processed_height.try_set(last_processed_height.get());

        // Initialize mailbox
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
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
                last_processed_round: Round::zero(),
                last_processed_height,
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
        resolver: (mpsc::Receiver<handler::Message<V::Commitment>>, R),
    ) -> Handle<()>
    where
        R: Resolver<
            Key = handler::Request<V::Commitment>,
            PublicKey = <P::Scheme as CertificateScheme>::PublicKey,
        >,
        Buf: Buffer<V>,
    {
        spawn_cell!(self.context, self.run(application, buffer, resolver).await)
    }

    /// Run the application actor.
    async fn run<R, Buf>(
        mut self,
        mut application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        mut buffer: Buf,
        (mut resolver_rx, mut resolver): (mpsc::Receiver<handler::Message<V::Commitment>>, R),
    ) where
        R: Resolver<
            Key = handler::Request<V::Commitment>,
            PublicKey = <P::Scheme as CertificateScheme>::PublicKey,
        >,
        Buf: Buffer<V>,
    {
        // Create a local pool for waiter futures.
        let mut waiters = AbortablePool::<Result<V::Block, BlockSubscriptionKeyFor<V>>>::default();

        // Get tip and send to application
        let tip = self.get_latest().await;
        if let Some((height, digest, round)) = tip {
            application.report(Update::Tip(round, height, digest)).await;
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // Attempt to dispatch the next finalized block to the application, if it is ready.
        self.try_dispatch_blocks(&mut application).await;

        // Attempt to repair any gaps in the finalized blocks archive, if there are any.
        if self
            .try_repair_gaps(&mut buffer, &mut resolver, &mut application)
            .await
        {
            self.sync_finalized().await;
        }

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
                loop {
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
                    let Some(next) = self.pending_acks.pop_ready() else {
                        break;
                    };
                    pending = Some(next);
                }

                // Persist buffered processed-height updates once after draining all ready acks.
                if let Err(e) = self.application_metadata.sync().await {
                    error!(?e, "failed to sync application progress");
                    return;
                }

                // Fill the pipeline
                self.try_dispatch_blocks(&mut application).await;
            },
            // Handle consensus inputs before backfill or resolver traffic
            Some(message) = self.mailbox.recv() else {
                info!("mailbox closed, shutting down");
                break;
            } => {
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
                    Message::Proposed { round, block } => {
                        self.cache_verified(round, block.digest(), block.clone())
                            .await;
                        buffer.proposed(round, block).await;
                    }
                    Message::Verified { round, block } => {
                        self.cache_verified(round, block.digest(), block).await;
                    }
                    Message::Notarization { notarization } => {
                        let round = notarization.round();
                        let commitment = notarization.proposal.payload;
                        let digest = V::commitment_to_inner(commitment);

                        // Store notarization by view
                        self.cache
                            .put_notarization(round, digest, notarization.clone())
                            .await;

                        // Search for block locally, otherwise fetch it remotely.
                        if let Some(block) =
                            self.find_block_by_commitment(&buffer, commitment).await
                        {
                            // If found, persist the block
                            self.cache_block(round, digest, block).await;
                        } else {
                            debug!(?round, "notarized block missing");
                            resolver
                                .fetch(Request::<V::Commitment>::Notarized { round })
                                .await;
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
                            if self
                                .store_finalization(
                                    height,
                                    digest,
                                    block,
                                    Some(finalization),
                                    &mut application,
                                    &mut buffer,
                                )
                                .await
                            {
                                self.try_repair_gaps(&mut buffer, &mut resolver, &mut application)
                                    .await;
                                self.sync_finalized().await;
                                debug!(?round, %height, "finalized block stored");
                            }
                        } else {
                            // Otherwise, fetch the block from the network.
                            debug!(?round, ?commitment, "finalized block missing");
                            resolver
                                .fetch(Request::<V::Commitment>::Block(commitment))
                                .await;
                        }
                    }
                    Message::GetBlock {
                        identifier,
                        response,
                    } => match identifier {
                        BlockID::Digest(digest) => {
                            let result = self.find_block_by_digest(&mut buffer, digest).await;
                            response.send_lossy(result);
                        }
                        BlockID::Height(height) => {
                            let result = self.get_finalized_block(height).await;
                            response.send_lossy(result);
                        }
                        BlockID::Latest => {
                            let block = match self.get_latest().await {
                                Some((_, digest, _)) => {
                                    self.find_block_by_digest(&mut buffer, digest).await
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
                        // Skip if height is at or below the floor
                        if height <= self.last_processed_height {
                            continue;
                        }

                        // Skip if finalization is already available locally
                        if self.get_finalization_by_height(height).await.is_some() {
                            continue;
                        }

                        // Trigger a targeted fetch via the resolver
                        let request = Request::<V::Commitment>::Finalized { height };
                        resolver.fetch_targeted(request, targets).await;
                    }
                    Message::SubscribeByDigest {
                        round,
                        digest,
                        response,
                    } => {
                        self.handle_subscribe(
                            round,
                            BlockSubscriptionKey::Digest(digest),
                            response,
                            &mut resolver,
                            &mut waiters,
                            &mut buffer,
                        )
                        .await;
                    }
                    Message::SubscribeByCommitment {
                        round,
                        commitment,
                        response,
                    } => {
                        self.handle_subscribe(
                            round,
                            BlockSubscriptionKey::Commitment(commitment),
                            response,
                            &mut resolver,
                            &mut waiters,
                            &mut buffer,
                        )
                        .await;
                    }
                    Message::SetFloor { height } => {
                        if self.last_processed_height >= height {
                            warn!(
                                %height,
                                existing = %self.last_processed_height,
                                "floor not updated, lower than existing"
                            );
                            continue;
                        }

                        // Update the processed height
                        self.update_processed_height(height, &mut resolver).await;
                        if let Err(err) = self.application_metadata.sync().await {
                            error!(?err, %height, "failed to update floor");
                            return;
                        }

                        // Drop all pending acknowledgements. We must do this to prevent
                        // an in-process block from being processed that is below the new floor
                        // updating `last_processed_height`.
                        self.pending_acks.clear();

                        // Prune data in the finalized archives below the new floor.
                        if let Err(err) = self.prune_finalized_archives(height).await {
                            error!(?err, %height, "failed to prune finalized archives");
                            return;
                        }

                        // Intentionally keep existing block subscriptions alive. Canceling
                        // waiters can have catastrophic consequences (nodes can get stuck in
                        // different views) as actors do not retry subscriptions on failed channels.
                    }
                    Message::Prune { height } => {
                        // Only allow pruning at or below the current floor
                        if height > self.last_processed_height {
                            warn!(%height, floor = %self.last_processed_height, "prune height above floor, ignoring");
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
                info!("handler closed, shutting down");
                return;
            } => {
                // Drain up to max_repair messages: blocks handled immediately,
                // certificates batched for verification, produces deferred.
                let mut needs_sync = false;
                let mut produces = Vec::new();
                let mut delivers = Vec::new();
                for msg in std::iter::once(message)
                    .chain(std::iter::from_fn(|| resolver_rx.try_recv().ok()))
                    .take(self.max_repair.get())
                {
                    match msg {
                        handler::Message::Produce { key, response } => {
                            produces.push((key, response));
                        }
                        handler::Message::Deliver {
                            key,
                            value,
                            response,
                        } => {
                            needs_sync |= self
                                .handle_deliver(
                                    key,
                                    value,
                                    response,
                                    &mut delivers,
                                    &mut application,
                                    &mut buffer,
                                )
                                .await;
                        }
                    }
                }

                // Batch verify and process all delivers.
                needs_sync |= self
                    .verify_delivered(delivers, &mut application, &mut buffer)
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
        key: Request<V::Commitment>,
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
        round: Option<Round>,
        key: BlockSubscriptionKeyFor<V>,
        response: oneshot::Sender<V::Block>,
        resolver: &mut impl Resolver<Key = Request<V::Commitment>>,
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

        // We don't have the block locally, so fetch by round if we have one.
        if let Some(round) = round {
            if round < self.last_processed_round {
                // At this point, we have failed to find the block locally, and
                // we know that its round is less than the last processed round.
                // This means that something else was finalized in that round,
                // so we drop the response to indicate that the block may never
                // be available.
                return;
            }
            // Attempt to fetch the block (with notarization) from the resolver.
            // If this is a valid view, this request should be fine to keep open
            // until resolution or pruning (even if the oneshot is canceled).
            debug!(?round, ?digest, "requested block missing");
            resolver
                .fetch(Request::<V::Commitment>::Notarized { round })
                .await;
        }

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
                    BlockSubscriptionKey::Digest(digest) => {
                        buffer.subscribe_by_digest(digest).await
                    }
                    BlockSubscriptionKey::Commitment(commitment) => {
                        buffer.subscribe_by_commitment(commitment).await
                    }
                };
                let waiter_key = key;
                let aborter = waiters.push(async move {
                    rx.await
                        .map_or_else(|_| Err(waiter_key), |block| Ok(block.into_block()))
                });
                entry.insert(BlockSubscription {
                    subscribers: vec![response],
                    _aborter: aborter,
                });
            }
        }
    }

    /// Handle a deliver message from the resolver. Block delivers are handled
    /// immediately. Finalized/Notarized delivers are parsed and structurally
    /// validated, then collected into `delivers` for batch certificate verification.
    /// Returns true if finalization archives were written and need syncing.
    async fn handle_deliver<Buf: Buffer<V>>(
        &mut self,
        key: Request<V::Commitment>,
        value: Bytes,
        response: oneshot::Sender<bool>,
        delivers: &mut Vec<PendingVerification<P::Scheme, V>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: &mut Buf,
    ) -> bool {
        match key {
            Request::Block(commitment) => {
                let Ok(block) = V::Block::decode_cfg(value.as_ref(), &self.block_codec_config)
                else {
                    response.send_lossy(false);
                    return false;
                };
                if V::commitment(&block) != commitment {
                    response.send_lossy(false);
                    return false;
                }

                // Persist the block, also storing the finalization if we have it.
                let height = block.height();
                let digest = block.digest();
                let finalization = self.cache.get_finalization_for(digest).await;
                let wrote = self
                    .store_finalization(height, digest, block, finalization, application, buffer)
                    .await;
                debug!(?digest, %height, "received block");
                response.send_lossy(true); // if a valid block is received, we should still send true (even if it was stale)
                wrote
            }
            Request::Finalized { height } => {
                let Some(bounds) = self.epocher.containing(height) else {
                    response.send_lossy(false);
                    return false;
                };
                let Some(scheme) = self.get_scheme_certificate_verifier(bounds.epoch()) else {
                    response.send_lossy(false);
                    return false;
                };

                let Ok((finalization, block)) =
                    <(Finalization<P::Scheme, V::Commitment>, V::Block)>::decode_cfg(
                        value,
                        &(
                            scheme.certificate_codec_config(),
                            self.block_codec_config.clone(),
                        ),
                    )
                else {
                    response.send_lossy(false);
                    return false;
                };

                let commitment = finalization.proposal.payload;
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
                    response.send_lossy(false);
                    return false;
                };

                let Ok((notarization, block)) =
                    <(Notarization<P::Scheme, V::Commitment>, V::Block)>::decode_cfg(
                        value,
                        &(
                            scheme.certificate_codec_config(),
                            self.block_codec_config.clone(),
                        ),
                    )
                else {
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
    async fn verify_delivered<Buf: Buffer<V>>(
        &mut self,
        mut delivers: Vec<PendingVerification<P::Scheme, V>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: &mut Buf,
    ) -> bool {
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
            verify_certificates(&mut self.context, scheme.as_ref(), &certs, &self.strategy)
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
                let results =
                    verify_certificates(&mut self.context, scheme.as_ref(), &group, &self.strategy);
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

                    wrote |= self
                        .store_finalization(
                            height,
                            digest,
                            block,
                            Some(finalization),
                            application,
                            buffer,
                        )
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
                        // Protocol invariant: for this variant, `digest` identifies a
                        // unique commitment, so this cached finalization payload must match
                        // `V::commitment(&block)`.
                        //
                        // This is enforced by assertion in `store_finalization`. It is not
                        // a `CertifiableBlock` property; it is the `Variant` mapping
                        // contract.
                        wrote |= self
                            .store_finalization(
                                height,
                                digest,
                                block.clone(),
                                Some(finalization),
                                application,
                                buffer,
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
    /// This does NOT advance `last_processed_height` or sync metadata. It only
    /// sends blocks to the application and enqueues pending acks. Metadata is
    /// updated later, in a subsequent `select_loop!` iteration, when acks
    /// arrive and [`Self::handle_block_processed`] calls
    /// [`Self::update_processed_height`].
    ///
    /// Acks are processed in FIFO order so `last_processed_height` always
    /// advances sequentially.
    ///
    /// # Crash safety
    ///
    /// Because `select_loop!` arms run to completion, the caller's
    /// [`Self::sync_finalized`] always executes before the ack handler runs. This
    /// guarantees archive data is durable before `last_processed_height`
    /// advances:
    ///
    /// ```text
    /// Iteration N (caller):
    ///   store_finalization  ->  Archive::put (buffered)
    ///   try_dispatch_blocks  ->  sends blocks to app, enqueues pending acks
    ///   sync_finalized      ->  archive durable
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
            let next_height = self
                .pending_acks
                .next_dispatch_height(self.last_processed_height);
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
            application
                .report(Update::Block(V::into_inner(block), ack))
                .await;
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
        resolver: &mut impl Resolver<Key = Request<V::Commitment>>,
    ) {
        // Update the processed height (buffered, not synced)
        self.update_processed_height(height, resolver).await;

        // Cancel any useless requests
        resolver
            .cancel(Request::<V::Commitment>::Block(commitment))
            .await;

        if let Some(finalization) = self.get_finalization_by_height(height).await {
            // Trail the previous processed finalized block by the timeout
            let lpr = self.last_processed_round;
            let prune_round = Round::new(
                lpr.epoch(),
                lpr.view().saturating_sub(self.view_retention_timeout),
            );

            // Prune archives
            self.cache.prune(prune_round).await;

            // Update the last processed round
            let round = finalization.round();
            self.last_processed_round = round;

            // Cancel useless requests
            resolver
                .retain(Request::<V::Commitment>::Notarized { round }.predicate())
                .await;
        }
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
    /// to the loop. This ensures archives are durable before the ack handler
    /// advances `last_processed_height`. See [`Self::try_dispatch_blocks`] for details.
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
    /// After persisting the block, attempt to dispatch the next contiguous block to the application.
    ///
    /// Writes are buffered and not synced. The caller must call
    /// [sync_finalized](Self::sync_finalized) before yielding to the
    /// `select_loop!` so that archive data is durable before the ack handler
    /// advances `last_processed_height`. See [`Self::try_dispatch_blocks`] for the
    /// crash safety invariant.
    async fn store_finalization<Buf: Buffer<V>>(
        &mut self,
        height: Height,
        digest: <V::Block as Digestible>::Digest,
        block: V::Block,
        finalization: Option<Finalization<P::Scheme, V::Commitment>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: &mut Buf,
    ) -> bool {
        if height <= self.last_processed_height {
            debug!(
                %height,
                floor = %self.last_processed_height,
                ?digest,
                "dropping finalization at or below processed height floor"
            );
            return false;
        }

        self.notify_subscribers(&block);

        // Convert block to storage format
        let commitment = V::commitment(&block);
        // Variant mapping rule (1): commitment_to_inner(commitment(block)) == block.digest().
        assert_eq!(
            V::commitment_to_inner(commitment),
            digest,
            "variant commitment_to_inner(commitment(block)) must equal block digest"
        );
        let finalization = finalization.inspect(|finalization| {
            // Variant/protocol rule (2): for blocks/certificates admitted by marshal
            // verification in this variant instance, a given block digest has a unique
            // commitment, so finalization payload must match `V::commitment(&block)`.
            //
            // This invariant comes from the `Variant` commitment mapping contract,
            // not from `CertifiableBlock`.
            assert_eq!(
                &finalization.proposal.payload, &commitment,
                "finalization payload must match block commitment"
            );
        });
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
            application.report(Update::Tip(round, height, digest)).await;
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // Notify buffer that block is finalized (for cache eviction).
        buffer.finalized(commitment).await;

        self.try_dispatch_blocks(application).await;

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

    /// Looks for a block anywhere in local storage using only the digest.
    ///
    /// This is used when we only have a digest (e.g., during gap repair following
    /// parent links).
    async fn find_block_by_digest<Buf: Buffer<V>>(
        &self,
        buffer: &mut Buf,
        digest: <V::Block as Digestible>::Digest,
    ) -> Option<V::Block> {
        if let Some(block) = buffer.find_by_digest(digest).await {
            return Some(block.into_block());
        }
        self.find_block_in_storage(digest).await
    }

    /// Looks for a block anywhere in local storage using the full commitment.
    ///
    /// This is used when we have a full commitment (e.g., from notarizations/finalizations).
    /// Having the full commitment may enable additional retrieval mechanisms.
    async fn find_block_by_commitment<Buf: Buffer<V>>(
        &self,
        buffer: &Buf,
        commitment: V::Commitment,
    ) -> Option<V::Block> {
        if let Some(block) = buffer.find_by_commitment(commitment).await {
            let block = block.into_block();
            if V::commitment(&block) == commitment {
                return Some(block);
            }
            debug!(
                ?commitment,
                actual_commitment = ?V::commitment(&block),
                "buffer returned block with mismatched commitment"
            );
        }
        let block = self
            .find_block_in_storage(V::commitment_to_inner(commitment))
            .await?;
        if V::commitment(&block) == commitment {
            return Some(block);
        }
        debug!(
            ?commitment,
            actual_commitment = ?V::commitment(&block),
            "storage returned block with mismatched commitment"
        );
        None
    }

    /// Attempt to repair any identified gaps in the finalized blocks archive. The total
    /// number of missing heights that can be repaired at once is bounded by `self.max_repair`,
    /// though multiple gaps may be spanned.
    ///
    /// Writes are buffered. Returns `true` if this call wrote repaired blocks and
    /// needs a subsequent [`sync_finalized`](Self::sync_finalized).
    async fn try_repair_gaps<Buf: Buffer<V>>(
        &mut self,
        buffer: &mut Buf,
        resolver: &mut impl Resolver<Key = Request<V::Commitment>>,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) -> bool {
        let mut wrote = false;
        let start = self.last_processed_height.next();
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
                assert_eq!(
                    V::commitment_to_inner(parent_commitment),
                    parent_digest,
                    "variant parent commitment must map to block parent digest"
                );
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
                            buffer,
                        )
                        .await;
                    debug!(height = %block.height(), "repaired block");
                    cursor = block;
                } else {
                    // Request the next missing block digest
                    //
                    // SAFETY: We can rely on this variant-derived parent commitment because
                    // the block is provably a member of the finalized chain due to the end
                    // boundary of the gap being finalized.
                    resolver
                        .fetch(Request::<V::Commitment>::Block(parent_commitment))
                        .await;
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
        let requests = missing_items
            .into_iter()
            .map(|height| Request::<V::Commitment>::Finalized { height })
            .collect::<Vec<_>>();
        if !requests.is_empty() {
            resolver.fetch_all(requests).await
        }
        wrote
    }

    /// Buffers a processed height update in memory and metrics. Does NOT sync
    /// to durable storage. Sync metadata after buffered updates to make them durable.
    async fn update_processed_height(
        &mut self,
        height: Height,
        resolver: &mut impl Resolver<Key = Request<V::Commitment>>,
    ) {
        self.application_metadata.put(LATEST_KEY, height);
        self.last_processed_height = height;
        let _ = self
            .processed_height
            .try_set(self.last_processed_height.get());

        // Cancel any existing requests below the new floor.
        resolver
            .retain(Request::<V::Commitment>::Finalized { height }.predicate())
            .await;
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
}
