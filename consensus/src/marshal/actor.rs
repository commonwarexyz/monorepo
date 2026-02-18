use super::{
    buffer::Buffer,
    cache,
    config::Config,
    ingress::{
        handler::{self, Request},
        mailbox::{Mailbox, Message},
    },
};
use crate::{
    marshal::{
        ingress::mailbox::Identifier as BlockID,
        store::{Blocks, Certificates},
        Update,
    },
    simplex::{
        scheme::Scheme,
        types::{verify_certificates, Finalization, Notarization, Subject},
    },
    types::{Epoch, Epocher, Height, Round, ViewDelta},
    Block, Epochable, Reporter,
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode};
use commonware_cryptography::certificate::{Provider, Scheme as CertificateScheme};
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
enum PendingVerification<S: CertificateScheme, B: Block> {
    Notarized {
        notarization: Notarization<S, B::Commitment>,
        block: B,
        response: oneshot::Sender<bool>,
    },
    Finalized {
        finalization: Finalization<S, B::Commitment>,
        block: B,
        response: oneshot::Sender<bool>,
    },
}

/// A pending acknowledgement from the application for a block at the contained height/commitment.
#[pin_project]
struct PendingAck<B: Block, A: Acknowledgement> {
    height: Height,
    commitment: B::Commitment,
    #[pin]
    receiver: A::Waiter,
}

impl<B: Block, A: Acknowledgement> Future for PendingAck<B, A> {
    type Output = <A::Waiter as Future>::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().receiver.poll(cx)
    }
}

/// Tracks in-flight application acknowledgements with FIFO semantics.
struct PendingAcks<B: Block, A: Acknowledgement> {
    current: OptionFuture<PendingAck<B, A>>,
    queue: VecDeque<PendingAck<B, A>>,
    max: usize,
}

impl<B: Block, A: Acknowledgement> PendingAcks<B, A> {
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
    const fn current(&mut self) -> &mut OptionFuture<PendingAck<B, A>> {
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
    fn enqueue(&mut self, ack: PendingAck<B, A>) {
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
    ) -> (Height, B::Commitment, <A::Waiter as Future>::Output) {
        let PendingAck {
            height, commitment, ..
        } = self.current.take().expect("ack state must be present");
        if let Some(next) = self.queue.pop_front() {
            self.current.replace(next);
        }
        (height, commitment, result)
    }

    /// If the current ack is already resolved, takes it and arms the next ack.
    fn pop_ready(&mut self) -> Option<(Height, B::Commitment, <A::Waiter as Future>::Output)> {
        let pending = self.current.as_mut()?;
        let result = Pin::new(&mut pending.receiver).now_or_never()?;
        Some(self.complete_current(result))
    }
}

/// A struct that holds multiple subscriptions for a block.
struct BlockSubscription<B: Block> {
    // The subscribers that are waiting for the block
    subscribers: Vec<oneshot::Sender<B>>,
    // Aborter that aborts the waiter future when dropped
    _aborter: Option<Aborter>,
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
pub struct Actor<E, B, P, FC, FB, ES, T, A = Exact>
where
    E: BufferPooler + CryptoRngCore + Spawner + Metrics + Clock + Storage,
    B: Block,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Commitment>>,
    FC: Certificates<Commitment = B::Commitment, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    // ---------- Context ----------
    context: ContextCell<E>,

    // ---------- Message Passing ----------
    // Mailbox
    mailbox: mpsc::Receiver<Message<P::Scheme, B>>,

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
    block_codec_config: B::Cfg,
    // Strategy for parallel operations
    strategy: T,

    // ---------- State ----------
    // Last view processed
    last_processed_round: Round,
    // Last height processed by the application
    last_processed_height: Height,
    // Pending application acknowledgements
    pending_acks: PendingAcks<B, A>,
    // Highest known finalized height
    tip: Height,
    // Outstanding subscriptions for blocks
    block_subscriptions: BTreeMap<B::Commitment, BlockSubscription<B>>,

    // ---------- Storage ----------
    // Prunable cache
    cache: cache::Manager<E, B, P::Scheme>,
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

impl<E, B, P, FC, FB, ES, T, A> Actor<E, B, P, FC, FB, ES, T, A>
where
    E: BufferPooler + CryptoRngCore + Spawner + Metrics + Clock + Storage,
    B: Block,
    P: Provider<Scope = Epoch, Scheme: Scheme<B::Commitment>>,
    FC: Certificates<Commitment = B::Commitment, Scheme = P::Scheme>,
    FB: Blocks<Block = B>,
    ES: Epocher,
    T: Strategy,
    A: Acknowledgement,
{
    /// Create a new application actor.
    pub async fn init(
        context: E,
        finalizations_by_height: FC,
        finalized_blocks: FB,
        config: Config<B, P, ES, T>,
    ) -> (Self, Mailbox<P::Scheme, B>, Height) {
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
    pub fn start<R, U>(
        mut self,
        application: impl Reporter<Activity = Update<B, A>>,
        buffer: U,
        resolver: (mpsc::Receiver<handler::Message<B>>, R),
    ) -> Handle<()>
    where
        R: Resolver<
            Key = handler::Request<B>,
            PublicKey = <P::Scheme as CertificateScheme>::PublicKey,
        >,
        U: Buffer<B>,
    {
        spawn_cell!(self.context, self.run(application, buffer, resolver).await)
    }

    /// Run the application actor.
    async fn run<R, U>(
        mut self,
        mut application: impl Reporter<Activity = Update<B, A>>,
        mut buffer: U,
        (mut resolver_rx, mut resolver): (mpsc::Receiver<handler::Message<B>>, R),
    ) where
        R: Resolver<
            Key = handler::Request<B>,
            PublicKey = <P::Scheme as CertificateScheme>::PublicKey,
        >,
        U: Buffer<B>,
    {
        // Create a local pool for waiter futures.
        let mut waiters = AbortablePool::<(B::Commitment, B)>::default();

        // Get tip and send to application
        let tip = self.get_latest().await;
        if let Some((height, commitment, round)) = tip {
            application
                .report(Update::Tip(round, height, commitment))
                .await;
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // Attempt to dispatch the next finalized block to the application, if it is ready.
        self.try_dispatch_blocks(&mut application).await;

        // Attempt to repair any gaps in the finalized blocks archive, if there are any.
        if self
            .try_repair_gaps(&buffer, &mut resolver, &mut application)
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
            // Handle waiter completions first (aborted futures are skipped)
            Ok((commitment, block)) = waiters.next_completed() else continue => {
                self.notify_subscribers(commitment, &block);
            },
            // Handle application acknowledgements (drain all ready acks, sync once)
            result = self.pending_acks.current() => {
                // Start with the ack that woke this `select_loop!` arm.
                let mut pending = Some(self.pending_acks.complete_current(result));
                loop {
                    let (height, commitment, result) = pending.take().expect("pending ack must exist");
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
                            // height directly from the archive by mapping the commitment to
                            // the index, which is the same as the height.
                            BlockID::Commitment(commitment) => self
                                .finalized_blocks
                                .get(ArchiveID::Key(&commitment))
                                .await
                                .ok()
                                .flatten()
                                .map(|b| (b.height(), commitment)),
                            BlockID::Height(height) => self
                                .finalizations_by_height
                                .get(ArchiveID::Index(height.get()))
                                .await
                                .ok()
                                .flatten()
                                .map(|f| (height, f.proposal.payload)),
                            BlockID::Latest => self.get_latest().await.map(|(h, c, _)| (h, c)),
                        };
                        response.send_lossy(info);
                    }
                    Message::Proposed { round, block } => {
                        self.cache_verified(round, block.commitment(), block.clone())
                            .await;
                        buffer.broadcast(block).await;
                    }
                    Message::Verified { round, block } => {
                        self.cache_verified(round, block.commitment(), block).await;
                    }
                    Message::Notarization { notarization } => {
                        let round = notarization.round();
                        let commitment = notarization.proposal.payload;

                        // Store notarization by view
                        self.cache
                            .put_notarization(round, commitment, notarization)
                            .await;

                        // Search for block locally, otherwise fetch it remotely
                        if let Some(block) = self.find_block(&buffer, commitment).await {
                            // If found, persist the block
                            self.cache_block(round, commitment, block).await;
                        } else {
                            debug!(?round, "notarized block missing");
                            resolver.fetch(Request::<B>::Notarized { round }).await;
                        }
                    }
                    Message::Finalization { finalization } => {
                        // Cache finalization by round
                        let round = finalization.round();
                        let commitment = finalization.proposal.payload;
                        self.cache
                            .put_finalization(round, commitment, finalization.clone())
                            .await;

                        // Search for block locally, otherwise fetch it remotely
                        if let Some(block) = self.find_block(&buffer, commitment).await {
                            // If found, persist the block
                            let height = block.height();
                            self.store_finalization(
                                height,
                                commitment,
                                block,
                                Some(finalization),
                                &mut application,
                            )
                            .await;
                            let _ =
                                self.try_repair_gaps(
                                    &buffer,
                                    &mut resolver,
                                    &mut application,
                                )
                                    .await;
                            self.sync_finalized().await;
                            debug!(?round, %height, "finalized block stored");
                        } else {
                            // Otherwise, fetch the block from the network.
                            debug!(?round, ?commitment, "finalized block missing");
                            resolver.fetch(Request::<B>::Block(commitment)).await;
                        }
                    }
                    Message::GetBlock {
                        identifier,
                        response,
                    } => match identifier {
                        BlockID::Commitment(commitment) => {
                            let result = self.find_block(&buffer, commitment).await;
                            response.send_lossy(result);
                        }
                        BlockID::Height(height) => {
                            let result = self.get_finalized_block(height).await;
                            response.send_lossy(result);
                        }
                        BlockID::Latest => {
                            let block = match self.get_latest().await {
                                Some((_, commitment, _)) => {
                                    self.find_block(&buffer, commitment).await
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
                        let request = Request::<B>::Finalized { height };
                        resolver.fetch_targeted(request, targets).await;
                    }
                    Message::Subscribe {
                        round,
                        commitment,
                        response,
                    } => {
                        // Check for block locally
                        if let Some(block) = self.find_block(&buffer, commitment).await {
                            response.send_lossy(block);
                            continue;
                        }

                        // We don't have the block locally, so fetch the block from the network
                        // if we have an associated view. If we only have the digest, don't make
                        // the request as we wouldn't know when to drop it, and the request may
                        // never complete if the block is not finalized.
                        if let Some(round) = round {
                            if round < self.last_processed_round {
                                // At this point, we have failed to find the block locally, and
                                // we know that its round is less than the last processed round.
                                // This means that something else was finalized in that round,
                                // so we drop the response to indicate that the block may never
                                // be available.
                                continue;
                            }
                            // Attempt to fetch the block (with notarization) from the resolver.
                            // If this is a valid view, this request should be fine to keep open
                            // until resolution or pruning (even if the oneshot is canceled).
                            debug!(?round, ?commitment, "requested block missing");
                            resolver.fetch(Request::<B>::Notarized { round }).await;
                        }

                        // Register subscriber
                        debug!(?round, ?commitment, "registering subscriber");
                        match self.block_subscriptions.entry(commitment) {
                            Entry::Occupied(mut entry) => {
                                entry.get_mut().subscribers.push(response);
                            }
                            Entry::Vacant(entry) => {
                                let aborter = if let Some(rx) = buffer.subscribe(commitment).await {
                                    Some(waiters.push(async move {
                                        (commitment, rx.await.expect("buffer subscriber closed"))
                                    }))
                                } else {
                                    None
                                };
                                entry.insert(BlockSubscription {
                                    subscribers: vec![response],
                                    _aborter: aborter,
                                });
                            }
                        }
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

                        // Prune the finalized block and finalization certificate archives in parallel.
                        if let Err(err) = self.prune_finalized_archives(height).await {
                            error!(?err, %height, "failed to prune finalized archives");
                            return;
                        }
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
                    }
                }
            },
            // Handle resolver messages last (batched up to max_repair, sync once)
            Some(message) = resolver_rx.recv() else {
                info!("handler closed, shutting down");
                break;
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
                        handler::Message::Deliver { key, value, response } => {
                            needs_sync |= self.handle_deliver(
                                key,
                                value,
                                response,
                                &mut delivers,
                                &mut application,
                            ).await;
                        }
                    }
                }

                // Batch verify and process all delivers
                needs_sync |= self.verify_delivered(
                    delivers,
                    &mut application,
                ).await;

                // Attempt to fill gaps before handling produce requests (so
                // we can serve data we just received)
                needs_sync |= self
                    .try_repair_gaps(&buffer, &mut resolver, &mut application)
                    .await;

                // Sync archives before responding to peers (prioritize our
                // own durability)
                if needs_sync {
                    self.sync_finalized().await;
                }

                // Handle produce requests in parallel
                join_all(produces.into_iter().map(|(key, response)| {
                    self.handle_produce(key, response, &buffer)
                })).await;
            },
        }
    }

    /// Handle a produce request from a remote peer.
    async fn handle_produce<U: Buffer<B>>(
        &self,
        key: Request<B>,
        response: oneshot::Sender<Bytes>,
        buffer: &U,
    ) {
        match key {
            Request::Block(commitment) => {
                let Some(block) = self.find_block(buffer, commitment).await else {
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
                let Some(block) = self.find_block(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy((notarization, block).encode());
            }
        }
    }

    /// Handle a deliver message from the resolver. Block delivers are handled
    /// immediately. Finalized/Notarized delivers are parsed and structurally
    /// validated, then collected into `delivers` for batch certificate verification.
    /// Returns true if finalization archives were written and need syncing.
    async fn handle_deliver(
        &mut self,
        key: Request<B>,
        value: Bytes,
        response: oneshot::Sender<bool>,
        delivers: &mut Vec<PendingVerification<P::Scheme, B>>,
        application: &mut impl Reporter<Activity = Update<B, A>>,
    ) -> bool {
        match key {
            Request::Block(commitment) => {
                let Ok(block) = B::decode_cfg(value.as_ref(), &self.block_codec_config) else {
                    response.send_lossy(false);
                    return false;
                };
                if block.commitment() != commitment {
                    response.send_lossy(false);
                    return false;
                }

                // Persist the block, also storing the finalization if we have it
                let height = block.height();
                let finalization = self.cache.get_finalization_for(commitment).await;
                self.store_finalization(height, commitment, block, finalization, application)
                    .await;
                debug!(?commitment, %height, "received block");
                response.send_lossy(true);
                true
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
                    <(Finalization<P::Scheme, B::Commitment>, B)>::decode_cfg(
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

                if block.height() != height
                    || finalization.proposal.payload != block.commitment()
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
                    <(Notarization<P::Scheme, B::Commitment>, B)>::decode_cfg(
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
                    || notarization.proposal.payload != block.commitment()
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
        mut delivers: Vec<PendingVerification<P::Scheme, B>>,
        application: &mut impl Reporter<Activity = Update<B, A>>,
    ) -> bool {
        if delivers.is_empty() {
            return false;
        }

        // Extract (subject, certificate) pairs for batch verification
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

        // Batch verify using the all-epoch verifier if available,
        // otherwise batch verify per epoch using scoped verifiers
        let verified = if let Some(scheme) = self.provider.all() {
            verify_certificates(&mut self.context, scheme.as_ref(), &certs, &self.strategy)
        } else {
            let mut verified = vec![false; delivers.len()];

            // Group indices by epoch
            let mut by_epoch: BTreeMap<Epoch, Vec<usize>> = BTreeMap::new();
            for (i, item) in delivers.iter().enumerate() {
                let epoch = match item {
                    PendingVerification::Notarized { notarization, .. } => notarization.epoch(),
                    PendingVerification::Finalized { finalization, .. } => finalization.epoch(),
                };
                by_epoch.entry(epoch).or_default().push(i);
            }

            // Batch verify each epoch group
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

        // Process each verified item, rejecting unverified ones
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
                    // Valid finalization received
                    response.send_lossy(true);
                    let round = finalization.round();
                    let height = block.height();
                    debug!(?round, %height, "received finalization");

                    self.store_finalization(
                        height,
                        block.commitment(),
                        block,
                        Some(finalization),
                        application,
                    )
                    .await;
                    wrote = true;
                }
                PendingVerification::Notarized {
                    notarization,
                    block,
                    response,
                } => {
                    // Valid notarization received
                    response.send_lossy(true);
                    let round = notarization.round();
                    let commitment = block.commitment();
                    debug!(?round, ?commitment, "received notarization");

                    // If there exists a finalization certificate for this block, we
                    // should finalize it. This could finalize the block faster when
                    // a notarization then a finalization are received via consensus
                    // and we resolve the notarization request before the block request.
                    let height = block.height();
                    if let Some(finalization) = self.cache.get_finalization_for(commitment).await {
                        self.store_finalization(
                            height,
                            commitment,
                            block.clone(),
                            Some(finalization),
                            application,
                        )
                        .await;
                        wrote = true;
                    }

                    // Cache the notarization and block
                    self.cache_block(round, commitment, block).await;
                    self.cache
                        .put_notarization(round, commitment, notarization)
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

    /// Notify any subscribers for the given commitment with the provided block.
    fn notify_subscribers(&mut self, commitment: B::Commitment, block: &B) {
        if let Some(mut bs) = self.block_subscriptions.remove(&commitment) {
            for subscriber in bs.subscribers.drain(..) {
                subscriber.send_lossy(block.clone());
            }
        }
    }

    // -------------------- Application Dispatch --------------------

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
    /// [`Self::sync_finalized`] always executes before the ack handler runs.
    /// This guarantees archive data is durable before `last_processed_height`
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
        application: &mut impl Reporter<Activity = Update<B, A>>,
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

            let (height, commitment) = (block.height(), block.commitment());
            let (ack, ack_waiter) = A::handle();
            application.report(Update::Block(block, ack)).await;
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
        commitment: B::Commitment,
        resolver: &mut impl Resolver<Key = Request<B>>,
    ) {
        // Update the processed height (buffered, not synced)
        self.update_processed_height(height, resolver).await;

        // Cancel any useless requests
        resolver.cancel(Request::<B>::Block(commitment)).await;

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
                .retain(Request::<B>::Notarized { round }.predicate())
                .await;
        }
    }

    // -------------------- Prunable Storage --------------------

    /// Add a verified block to the prunable archive.
    async fn cache_verified(&mut self, round: Round, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block);
        self.cache.put_verified(round, commitment, block).await;
    }

    /// Add a notarized block to the prunable archive.
    async fn cache_block(&mut self, round: Round, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block);
        self.cache.put_block(round, commitment, block).await;
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
    async fn get_finalized_block(&self, height: Height) -> Option<B> {
        match self
            .finalized_blocks
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(block) => block,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    async fn get_finalization_by_height(
        &self,
        height: Height,
    ) -> Option<Finalization<P::Scheme, B::Commitment>> {
        match self
            .finalizations_by_height
            .get(ArchiveID::Index(height.get()))
            .await
        {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Add a finalized block, and optionally a finalization, to the archive,
    /// then attempt to dispatch the next contiguous block to the application.
    ///
    /// Writes are buffered and not synced. The caller must call
    /// [sync_finalized](Self::sync_finalized) before yielding to the
    /// `select_loop!` so that archive data is durable before the ack handler
    /// advances `last_processed_height`. See [`Self::try_dispatch_blocks`] for the
    /// crash safety invariant.
    async fn store_finalization(
        &mut self,
        height: Height,
        commitment: B::Commitment,
        block: B,
        finalization: Option<Finalization<P::Scheme, B::Commitment>>,
        application: &mut impl Reporter<Activity = Update<B, A>>,
    ) {
        self.notify_subscribers(commitment, &block);

        // Extract round before finalization is moved into try_join
        let round = finalization.as_ref().map(|f| f.round());

        // In parallel, update the finalized blocks and finalizations archives
        if let Err(e) = try_join!(
            // Update the finalized blocks archive
            async {
                self.finalized_blocks.put(block).await.map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            // Update the finalizations archive (if provided)
            async {
                if let Some(finalization) = finalization {
                    self.finalizations_by_height
                        .put(height, commitment, finalization)
                        .await
                        .map_err(Box::new)?;
                }
                Ok::<_, BoxedError>(())
            }
        ) {
            panic!("failed to finalize: {e}");
        }

        // Update metrics and send tip update to application
        if let Some(round) = round.filter(|_| height > self.tip) {
            application
                .report(Update::Tip(round, height, commitment))
                .await;
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        self.try_dispatch_blocks(application).await;
    }

    /// Get the latest finalized block information (height and commitment tuple).
    ///
    /// Blocks are only finalized directly with a finalization or indirectly via a descendant
    /// block's finalization. Thus, the highest known finalized block must itself have a direct
    /// finalization.
    ///
    /// We return the height and commitment using the highest known finalization that we know the
    /// block height for. While it's possible that we have a later finalization, if we do not have
    /// the full block for that finalization, we do not know it's height and therefore it would not
    /// yet be found in the `finalizations_by_height` archive. While not checked explicitly, we
    /// should have the associated block (in the `finalized_blocks` archive) for the information
    /// returned.
    async fn get_latest(&mut self) -> Option<(Height, B::Commitment, Round)> {
        let height = self.finalizations_by_height.last_index()?;
        let finalization = self
            .get_finalization_by_height(height)
            .await
            .expect("finalization missing");
        Some((height, finalization.proposal.payload, finalization.round()))
    }

    // -------------------- Mixed Storage --------------------

    /// Looks for a block anywhere in local storage.
    async fn find_block<U: Buffer<B>>(&self, buffer: &U, commitment: B::Commitment) -> Option<B> {
        // Check buffer
        if let Some(block) = buffer.get(commitment).await {
            return Some(block);
        }
        // Check verified / notarized blocks via cache manager.
        if let Some(block) = self.cache.find_block(commitment).await {
            return Some(block);
        }
        // Check finalized blocks.
        match self.finalized_blocks.get(ArchiveID::Key(&commitment)).await {
            Ok(block) => block, // may be None
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Attempt to repair any identified gaps in the finalized blocks archive. The total
    /// number of missing heights that can be repaired at once is bounded by `self.max_repair`,
    /// though multiple gaps may be spanned.
    ///
    /// Writes are buffered. Returns `true` if this call wrote repaired blocks and
    /// needs a subsequent [`sync_finalized`](Self::sync_finalized).
    async fn try_repair_gaps<U: Buffer<B>>(
        &mut self,
        buffer: &U,
        resolver: &mut impl Resolver<Key = Request<B>>,
        application: &mut impl Reporter<Activity = Update<B, A>>,
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
            let gap_start = gap_start.map(|s| s.next()).unwrap_or(start);

            // Iterate backwards, repairing blocks as we go.
            while cursor.height() > gap_start {
                let commitment = cursor.parent();
                if let Some(block) = self.find_block(buffer, commitment).await {
                    let finalization = self.cache.get_finalization_for(commitment).await;
                    self.store_finalization(
                        block.height(),
                        commitment,
                        block.clone(),
                        finalization,
                        application,
                    )
                    .await;
                    wrote = true;
                    debug!(height = %block.height(), "repaired block");
                    cursor = block;
                } else {
                    // Request the next missing block digest
                    resolver.fetch(Request::<B>::Block(commitment)).await;
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
            .map(|height| Request::<B>::Finalized { height })
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
        resolver: &mut impl Resolver<Key = Request<B>>,
    ) {
        self.application_metadata.put(LATEST_KEY, height);
        self.last_processed_height = height;
        let _ = self
            .processed_height
            .try_set(self.last_processed_height.get());

        // Cancel any existing requests below the new floor.
        resolver
            .retain(Request::<B>::Finalized { height }.predicate())
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
