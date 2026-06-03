use super::{
    acks::{PendingAck, PendingAcks},
    cache,
    delivery::PendingVerification,
    floor::Floor,
    mailbox::{CommitmentFallback, Mailbox, Message},
    stream::Stream,
    subscriptions::{Key as SubscriptionKey, KeyFor as SubscriptionKeyFor, Subscriptions},
    variant::NoBuffer,
    Buffer, Variant,
};
use crate::{
    marshal::{
        resolver::handler::{self, Annotation, Key, Request},
        store::{Blocks, Certificates},
        Config, Identifier as BlockID, Start, Update,
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
    certificate::{Provider, Verifier},
    Digestible,
};
use commonware_macros::select_loop;
use commonware_p2p::Recipients;
use commonware_parallel::Strategy;
use commonware_resolver::{Delivery, Resolver, TargetedResolver};
use commonware_runtime::{
    spawn_cell,
    telemetry::metrics::{Gauge, GaugeExt, MetricsExt as _},
    BufferPooler, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_storage::archive::Identifier as ArchiveID;
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    futures::AbortablePool,
    Acknowledgement, BoxedError,
};
use futures::{future::join_all, try_join};
use rand_core::CryptoRngCore;
use std::{collections::BTreeMap, future::Future, num::NonZeroUsize};
use tracing::{debug, warn};

// Resolver request keys are expressed in the variant commitment type, which
// may differ from the block digest for coded variants.
type ResolverRequestFor<V> = Key<<V as Variant>::Commitment>;

// A resolver delivery plus the peer-validity response channel. Local
// annotations on the delivery decide how accepted data is used.
struct ResolverDelivery<V: Variant> {
    delivery: Delivery<ResolverRequestFor<V>, Annotation>,
    value: Bytes,
    response: oneshot::Sender<bool>,
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
    // Current processed floor and any pending floor update
    floor: Floor<P::Scheme, V::Commitment>,
    // Application delivery cursor
    stream: Stream<E>,
    // Pending application acknowledgements
    pending_acks: PendingAcks<V, A>,
    // Highest known finalized height
    tip: Height,
    // Outstanding subscriptions for blocks
    block_subscriptions: Subscriptions<V>,

    // ---------- Storage ----------
    // Prunable cache
    cache: cache::Manager<E, V, P::Scheme>,
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
        mut finalized_blocks: FB,
        config: Config<P, ES, T, V::ApplicationBlock, V::Block, V::Commitment>,
    ) -> (Self, Mailbox<P::Scheme, V>, Option<Height>) {
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

        // The application metadata name is retained for legacy support.
        let application_metadata_partition =
            format!("{}-application-metadata", config.partition_prefix);
        let stream = Stream::new(context.child("stream"), &application_metadata_partition).await;
        let last_processed_height = stream.processed_height();

        // Genesis is a local anchor. A floor finalization is verified and
        // resolved after `run` receives the resolver and buffer.
        let pending_floor_anchor = match config.start {
            Start::Genesis(anchor) => {
                assert_eq!(
                    anchor.height(),
                    Height::zero(),
                    "genesis anchor must be at height zero"
                );
                Self::ensure_genesis_anchor(&mut finalized_blocks, anchor, last_processed_height)
                    .await;
                None
            }
            Start::Floor(finalization) => Some(finalization),
        };
        let last_processed_round =
            Self::latest_processed_round(&finalizations_by_height, last_processed_height).await;

        // Create metrics
        let finalized_height = context.gauge("finalized_height", "Finalized height of application");
        let processed_height = context.gauge("processed_height", "Processed height of application");
        if let Some(last_processed_height) = last_processed_height {
            let _ = processed_height.try_set(last_processed_height.get());
        }
        let floor = pending_floor_anchor.map_or_else(
            || Floor::resolved(last_processed_height, last_processed_round),
            |finalization| {
                Floor::awaiting_anchor(last_processed_height, last_processed_round, finalization)
            },
        );

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
                floor,
                stream,
                pending_acks: PendingAcks::new(config.max_pending_acks.get()),
                tip: Height::zero(),
                block_subscriptions: Subscriptions::new(),
                cache,
                finalizations_by_height,
                finalized_blocks,
                finalized_height,
                processed_height,
            },
            Mailbox::new(sender),
            last_processed_height,
        )
    }

    async fn ensure_genesis_anchor(
        finalized_blocks: &mut FB,
        anchor: V::Block,
        last_processed_height: Option<Height>,
    ) {
        let anchor_height = anchor.height();
        let anchor_commitment = V::commitment(&anchor);
        match finalized_blocks
            .get(ArchiveID::Index(anchor_height.get()))
            .await
        {
            Ok(Some(stored)) => {
                let stored: V::Block = stored.into();
                assert_eq!(
                    stored.height(),
                    anchor_height,
                    "stored genesis block height mismatch"
                );
                assert!(
                    V::commitment(&stored) == anchor_commitment,
                    "stored genesis block does not match configured anchor"
                );
            }
            Ok(None) => {
                if let Some(existing) =
                    last_processed_height.filter(|height| anchor_height < *height)
                {
                    warn!(
                        height = %anchor_height,
                        %existing,
                        "ignoring stale anchor"
                    );
                    return;
                }

                finalized_blocks
                    .put(anchor.into())
                    .await
                    .expect("failed to store startup anchor");
                finalized_blocks
                    .sync()
                    .await
                    .expect("failed to sync startup anchor");
                debug!(height = %anchor_height, "stored genesis block");
            }
            Err(err) => panic!("failed to check startup anchor: {err}"),
        }
    }

    /// Start the actor.
    pub fn start<R, Buf>(
        mut self,
        application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: Buf,
        resolver: (handler::Receiver<V::Commitment>, R),
    ) -> Handle<()>
    where
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        spawn_cell!(self.context, self.run(application, buffer, resolver))
    }

    /// Start the actor without a broadcast buffer.
    pub fn start_unbuffered<R>(
        self,
        application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: (handler::Receiver<V::Commitment>, R),
    ) -> Handle<()>
    where
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
    {
        self.start(
            application,
            NoBuffer::<<P::Scheme as Verifier>::PublicKey>::new(),
            resolver,
        )
    }

    /// Run the application actor.
    async fn run<R, Buf>(
        mut self,
        mut application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        mut buffer: Buf,
        (mut resolver_rx, mut resolver): (handler::Receiver<V::Commitment>, R),
    ) where
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
    {
        // Create a local pool for waiter futures.
        let mut waiters = AbortablePool::<Result<V::Block, SubscriptionKeyFor<V>>>::default();

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

        // A configured floor follows the same path as `SetFloor`: verify it,
        // then apply a local anchor or fetch the anchor block.
        if let Some(finalization) = self.floor.take_pending_anchor() {
            self.install_floor(
                finalization,
                false,
                &mut resolver,
                &mut buffer,
                &mut application,
            )
            .await;
        }

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
                self.block_subscriptions.retain_open();
            },
            on_stopped => {
                debug!("context shutdown, stopping marshal");
            },
            // Handle waiter completions first
            Ok(completion) = waiters.next_completed() else continue => match completion {
                Ok(block) => self.block_subscriptions.notify(&block),
                Err(key) => {
                    match key {
                        SubscriptionKey::Digest(digest) => {
                            debug!(
                                ?digest,
                                "buffer subscription closed, canceling local subscribers"
                            );
                        }
                        SubscriptionKey::Commitment(commitment) => {
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
                self.handle_ack(result, &mut application, &mut buffer, &mut resolver)
                    .await;
            },
            // Handle consensus inputs before backfill or resolver traffic
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                break;
            } => {
                self.handle_mailbox_message(
                    message,
                    &mut resolver,
                    &mut waiters,
                    &mut buffer,
                    &mut application,
                )
                .await;
            },
            // Handle resolver messages last (batched up to max_repair, sync once)
            Some(message) = resolver_rx.recv() else {
                debug!("handler closed, shutting down");
                return;
            } => {
                self.handle_resolver_message(
                    message,
                    &mut resolver_rx,
                    &mut resolver,
                    &mut buffer,
                    &mut application,
                )
                .await;
            },
        }
    }

    /// Handles one ready application acknowledgement and drains any queued acks
    /// that are already complete.
    async fn handle_ack<Buf, R>(
        &mut self,
        result: <A::Waiter as Future>::Output,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        buffer: &mut Buf,
        resolver: &mut R,
    ) where
        Buf: Buffer<V>,
        R: Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    {
        // Start with the ack that woke this `select_loop!` arm.
        let mut pending = Some(self.pending_acks.complete_current(result));
        let last_acked_commitment = loop {
            let (height, commitment, result) = pending.take().expect("pending ack must exist");
            match result {
                Ok(()) => {
                    // Apply in-memory progress updates for this acknowledged
                    // block. The metadata sync below makes drained updates durable.
                    self.update_processed_height(height, resolver);
                    self.update_processed_round(height, resolver).await;
                }
                Err(e) => {
                    // Ack failures are fatal for marshal/application coordination.
                    panic!("application did not acknowledge block at height {height}: {e:?}");
                }
            }

            // Opportunistically drain any additional already-ready acks so we
            // can persist one metadata sync for the whole batch below.
            match self.pending_acks.pop_ready() {
                Some(next) => pending = Some(next),
                None => break commitment,
            }
        };

        // Persist buffered progress updates once after draining all ready acks.
        self.stream
            .sync()
            .await
            .expect("failed to sync application progress");

        // Anything below the last acknowledged commitment is safe for the
        // buffer to prune.
        buffer.finalized(last_acked_commitment);

        // Refill the application dispatch pipeline.
        self.try_dispatch_blocks(application).await;
    }

    /// Handles a single mailbox message from local consensus/application callers.
    async fn handle_mailbox_message<Buf, R>(
        &mut self,
        message: Message<P::Scheme, V>,
        resolver: &mut R,
        waiters: &mut AbortablePool<Result<V::Block, SubscriptionKeyFor<V>>>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) where
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: TargetedResolver<
            Key = ResolverRequestFor<V>,
            Subscriber = Annotation,
            PublicKey = <P::Scheme as Verifier>::PublicKey,
        >,
    {
        if message.response_closed() {
            return;
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
                    BlockID::Height(height) => self.get_info_by_height(height).await,
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
                    return;
                }
                let block = match self.take_proposed(round, commitment) {
                    Some(block) => block,
                    None => {
                        let Some(block) = self.find_block_by_commitment(buffer, commitment).await
                        else {
                            debug!(?commitment, "block not found for forwarding");
                            return;
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
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await;

                // Retain the block in memory so the subsequent `Forward` can
                // broadcast it without reloading from storage. An older retained
                // proposal (if any) is overwritten.
                let commitment = V::commitment(&block);
                self.last_proposed_block = Some((round, commitment, block));
                ack.expect("durable ack present").send_lossy(());
            }
            Message::Verified { round, block, ack } => {
                // If the round has already been pruned by tip advancement,
                // `cache_verified` is a no-op because the round is below
                // the retention floor (and no longer is required by consensus
                // to make progress).
                self.cache_verified(round, block.digest(), block.clone())
                    .await;
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await;
                ack.expect("durable ack present").send_lossy(());
            }
            Message::Certified { round, block, ack } => {
                // If the round has already been pruned by tip advancement,
                // `cache_block` is a no-op because the round is below
                // the retention floor (and no longer is required by consensus
                // to make progress).
                self.cache_block(round, block.digest(), block.clone()).await;
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await;
                ack.expect("durable ack present").send_lossy(());
            }
            Message::Notarization { notarization } => {
                let round = notarization.round();
                let commitment = notarization.proposal.payload;
                let digest = V::commitment_to_inner(commitment);

                // Cache notarization by round.
                self.cache
                    .put_notarization(round, digest, notarization.clone())
                    .await;

                // A notarization alone is not enough to fetch missing proposal
                // data. If the block is not locally available, remember the
                // certificate and wait for a later finalization/repair path.
                if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
                    self.cache_block(round, digest, block.clone()).await;
                    self.apply_floor_anchor(&block, buffer, application, resolver)
                        .await;
                } else {
                    debug!(?round, "notarized block unavailable locally");
                }
            }
            Message::Finalization { finalization } => {
                let round = finalization.round();
                let commitment = finalization.proposal.payload;
                let digest = V::commitment_to_inner(commitment);

                // Cache finalization by round.
                self.cache
                    .put_finalization(round, digest, finalization.clone())
                    .await;

                // Search for the finalized block locally, otherwise fetch it remotely.
                if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
                    // The anchor path stores the floor block and finalization,
                    // advances floors, prunes below them, and resumes dispatch.
                    if self
                        .apply_floor_anchor(&block, buffer, application, resolver)
                        .await
                    {
                        return;
                    }

                    let height = block.height();
                    self.update_processed_round_floor(height, round, resolver)
                        .await;
                    if self
                        .store_finalization(height, digest, block, Some(finalization), application)
                        .await
                    {
                        // If a floor anchor is pending, repair and dispatch are
                        // no-ops until the anchor block is stored.
                        self.try_repair_gaps(buffer, resolver, application).await;
                        self.sync_finalized().await;
                        self.try_dispatch_blocks(application).await;
                        debug!(?round, %height, "finalized block stored");
                    }
                } else {
                    // The finalization carries a round and commitment, but not a
                    // height. Keep the request round-bound until the block is decoded.
                    debug!(?round, ?commitment, "finalized block missing");
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_round(commitment, round),
                        )
                        .ignore();
                }
            }
            Message::GetBlock {
                identifier,
                response,
            } => match identifier {
                BlockID::Digest(digest) => {
                    let result = self.find_block_by_digest(buffer, digest).await;
                    response.send_lossy(result);
                }
                BlockID::Height(height) => {
                    let result = self.get_finalized_block(height).await;
                    response.send_lossy(result);
                }
                BlockID::Latest => {
                    let block = match self.get_latest().await {
                        Some((_, digest, _)) => self.find_block_by_digest(buffer, digest).await,
                        None => None,
                    };
                    response.send_lossy(block);
                }
            },
            Message::GetFinalization { height, response } => {
                let finalization = self.get_finalization_by_height(height).await;
                response.send_lossy(finalization);
            }
            Message::GetProcessedHeight { response } => {
                response.send_lossy(self.stream.processed_height());
            }
            Message::HintFinalized { height, targets } => {
                // Skip if finalization is already available locally.
                if self.get_finalization_by_height(height).await.is_some() {
                    return;
                }

                self.floor
                    .fetch_targeted_if_permitted(resolver, Request::finalized(height), targets)
                    .ignore();
            }
            Message::SubscribeByDigest {
                digest,
                fallback,
                response,
            } => {
                self.handle_subscribe(
                    fallback.into(),
                    SubscriptionKey::Digest(digest),
                    response,
                    resolver,
                    waiters,
                    buffer,
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
                    SubscriptionKey::Commitment(commitment),
                    response,
                    resolver,
                    waiters,
                    buffer,
                )
                .await;
            }
            Message::HintNotarized { round, commitment } => {
                if self
                    .find_block_by_commitment(buffer, commitment)
                    .await
                    .is_none()
                {
                    self.floor
                        .fetch_if_permitted(resolver, Request::notarized(round))
                        .ignore();
                }
            }
            Message::SetFloor { finalization } => {
                self.install_floor(finalization, true, resolver, buffer, application)
                    .await;
            }
            Message::Prune { height } => {
                // Only allow pruning at or below the current floor.
                if height > self.floor.processed_height() {
                    warn!(%height, floor = %self.floor.processed_height(), "prune height above floor, ignoring");
                    return;
                }

                self.prune_finalized_archives(height)
                    .await
                    .expect("failed to prune finalized archives");

                // Intentionally keep existing block subscriptions alive. Canceling
                // waiters can have catastrophic consequences because actors do not
                // retry subscriptions on failed channels.
            }
        }
    }

    /// Handles a batch of resolver messages, syncing finalized archives once if
    /// any accepted delivery buffered a write.
    async fn handle_resolver_message<Buf, R>(
        &mut self,
        message: handler::Message<V::Commitment>,
        resolver_rx: &mut handler::Receiver<V::Commitment>,
        resolver: &mut R,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) where
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    {
        let mut needs_sync = false;
        let mut handled = false;
        let mut produces = Vec::new();
        let mut delivers = Vec::new();

        // Drain up to max_repair resolver messages. Block deliveries are handled
        // immediately, certificate-bearing deliveries are batched for verification,
        // and produce responses wait until repair has had a chance to fill gaps.
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
                            ResolverDelivery {
                                delivery,
                                value,
                                response,
                            },
                            &mut delivers,
                            buffer,
                            application,
                            resolver,
                        )
                        .await;
                }
            }
        }
        if !handled {
            return;
        }

        // Batch verify and process all certificate-bearing deliveries.
        needs_sync |= self
            .verify_delivered(delivers, buffer, application, resolver)
            .await;

        // Attempt to fill gaps before handling produce requests so we can serve
        // data received earlier in the same batch.
        needs_sync |= self.try_repair_gaps(buffer, resolver, application).await;

        if needs_sync {
            // Sync archives before responding to peers so accepted repair data is
            // durable before this node serves it.
            self.sync_finalized().await;
            self.try_dispatch_blocks(application).await;
        }

        // Handle produce requests in parallel.
        join_all(
            produces
                .into_iter()
                .map(|(key, response)| self.handle_produce(key, response, buffer)),
        )
        .await;
    }

    /// Handle a produce request from a remote peer.
    async fn handle_produce<Buf: Buffer<V>>(
        &self,
        key: ResolverRequestFor<V>,
        response: oneshot::Sender<Bytes>,
        buffer: &Buf,
    ) {
        match key {
            Key::Block(commitment) => {
                let Some(block) = self.find_block_by_commitment(buffer, commitment).await else {
                    debug!(?commitment, "block missing on request");
                    return;
                };
                response.send_lossy(block.encode());
            }
            Key::Finalized { height } => {
                let Some(finalization) = self.get_finalization_by_height(height).await else {
                    debug!(%height, "finalization missing on request");
                    return;
                };
                let Some(block) = self.get_finalized_block(height).await else {
                    debug!(%height, "finalized block missing on request");
                    return;
                };
                response.send_lossy((finalization, V::into_inner(block)).encode());
            }
            Key::Notarized { round } => {
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
        key: SubscriptionKeyFor<V>,
        response: oneshot::Sender<V::Block>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
        waiters: &mut AbortablePool<Result<V::Block, SubscriptionKeyFor<V>>>,
        buffer: &mut Buf,
    ) {
        let digest = match key {
            SubscriptionKey::Digest(digest) => digest,
            SubscriptionKey::Commitment(commitment) => V::commitment_to_inner(commitment),
        };

        // Check for block locally.
        let block = match key {
            SubscriptionKey::Digest(digest) => self.find_block_by_digest(buffer, digest).await,
            SubscriptionKey::Commitment(commitment) => {
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
                if self
                    .floor
                    .fetch_if_permitted(resolver, Request::notarized(round))
                    .denied()
                {
                    return;
                }
                debug!(?round, ?digest, "requested block missing");
            }
            CommitmentFallback::FetchByCommitment { height } => {
                let commitment = match key {
                    SubscriptionKey::Commitment(commitment) => commitment,
                    SubscriptionKey::Digest(_) => {
                        unreachable!("digest subscriptions cannot request commitment fallback")
                    }
                };

                // This path is only for accepted ancestry or finalized repair,
                // never for a candidate block's immediate parent.
                if self
                    .floor
                    .fetch_if_permitted(resolver, Request::certified_block(commitment, height))
                    .denied()
                {
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
            SubscriptionKey::Digest(digest) => {
                debug!(?round, ?digest, "registering subscriber");
            }
            SubscriptionKey::Commitment(commitment) => {
                debug!(?round, ?commitment, ?digest, "registering subscriber");
            }
        }
        self.block_subscriptions
            .insert(key, response, waiters, buffer);
    }

    /// Verifies and installs a floor, fetching the anchor block if needed.
    async fn install_floor<Buf, R>(
        &mut self,
        finalization: Finalization<P::Scheme, V::Commitment>,
        skip_if_superseded: bool,
        resolver: &mut R,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) where
        Buf: Buffer<V, PublicKey = <P::Scheme as Verifier>::PublicKey>,
        R: Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    {
        let round = finalization.round();
        if round <= self.floor.processed_round() {
            warn!(
                ?round,
                floor = ?self.floor.processed_round(),
                "floor not updated, below existing round floor"
            );
            return;
        }

        let Some(scoped) = self.provider.scoped(finalization.epoch()) else {
            panic!("floor finalization epoch unavailable");
        };
        assert!(
            finalization.verify(self.context.as_mut(), &scoped, &self.strategy),
            "floor finalization must verify"
        );

        let commitment = finalization.proposal.payload;
        let digest = V::commitment_to_inner(commitment);
        self.cache
            .put_finalization(round, digest, finalization.clone())
            .await;

        // A pending anchor at the same or a newer floor already blocks
        // progress. Keep waiting for it instead of replacing it.
        if skip_if_superseded && self.floor.has_pending_anchor_at_or_after(round) {
            return;
        }

        if let Some(block) = self.find_block_by_commitment(buffer, commitment).await {
            self.floor.await_anchor(finalization);
            assert!(
                self.apply_floor_anchor(&block, buffer, application, resolver)
                    .await
            );
            return;
        }

        // The pending floor owns the next application sync point. Drop any
        // in-flight acks before they can advance the processed height past it.
        self.pending_acks.clear();

        debug!(?round, ?commitment, "starting fetch for floor block");
        self.floor.await_anchor(finalization);
        self.floor
            .fetch_if_permitted(
                resolver,
                Request::finalized_block_by_round(commitment, round),
            )
            .ignore();
    }

    /// Applies a block if it satisfies the current floor transition.
    async fn apply_floor_anchor<Buf: Buffer<V>>(
        &mut self,
        block: &V::Block,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) -> bool {
        let commitment = V::commitment(block);
        if !self.floor.matches_pending_anchor(commitment) {
            return false;
        }
        let block = (*block).clone();

        // Floor anchors can bypass the local proposal-verification path. Check
        // the parent relationship before using a non-genesis anchor for walkback.
        let height = block.height();
        if height > Height::zero() {
            let parent_commitment = V::parent_commitment(&block);
            assert!(
                block.parent() == V::commitment_to_inner(parent_commitment),
                "floor block parent commitment mismatch"
            );
        }

        // This anchor cannot move the application sync point, but its
        // finalization round can still prune round-bound resolver work.
        // Keep pending acks intact because processed_height is unchanged.
        if height <= self.floor.processed_height() {
            warn!(
                %height,
                existing = %self.floor.processed_height(),
                "floor not updated, at or below existing"
            );
            let finalization = self
                .floor
                .take_pending_anchor()
                .expect("pending floor anchor missing");
            self.update_processed_round_floor(height, finalization.round(), resolver)
                .await;
            if self.try_repair_gaps(buffer, resolver, application).await {
                self.sync_finalized().await;
            }
            self.try_dispatch_blocks(application).await;
            return true;
        }

        let digest = block.digest();
        let finalization = self
            .floor
            .take_pending_anchor()
            .expect("pending floor anchor missing");
        let round = finalization.round();
        try_join!(
            async {
                self.finalized_blocks
                    .put(block.clone().into())
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            },
            async {
                self.finalizations_by_height
                    .put(height, digest, finalization)
                    .await
                    .map_err(Box::new)?;
                Ok::<_, BoxedError>(())
            }
        )
        .expect("failed to store floor anchor");
        self.sync_finalized().await;
        self.block_subscriptions.notify(&block);

        if height > self.tip {
            application.report(Update::Tip(round, height, digest));
            self.tip = height;
            let _ = self.finalized_height.try_set(height.get());
        }

        // The anchor is durable, but the application still needs to process it.
        // Record the previous height so dispatch resumes at the anchor itself.
        let dispatch_floor = height
            .previous()
            .expect("floor anchor above processed height must have predecessor");
        self.update_processed_height(dispatch_floor, resolver);
        self.update_processed_round_floor(dispatch_floor, round, resolver)
            .await;
        self.stream
            .sync()
            .await
            .expect("failed to sync floor metadata");

        // Drop all pending acknowledgement waiters so any in-flight application
        // acks for blocks below the new floor cannot rewrite the processed floor.
        self.pending_acks.clear();

        // The floor is durable, so cache/finalized data below it can be pruned.
        self.prune_after_floor(height)
            .await
            .expect("failed to prune data below floor");

        // Intentionally keep existing block subscriptions alive. Canceling
        // waiters can have catastrophic consequences (nodes can get stuck in
        // different views) as actors do not retry subscriptions on failed channels.
        if self.try_repair_gaps(buffer, resolver, application).await {
            self.sync_finalized().await;
        }
        self.try_dispatch_blocks(application).await;
        true
    }

    /// Handle a deliver message from the resolver. Block delivers are handled
    /// immediately. Finalized/Notarized delivers are parsed and structurally
    /// validated, then collected into `delivers` for batch certificate verification.
    /// Returns true if finalization archives were written and need syncing.
    async fn handle_deliver<Buf: Buffer<V>>(
        &mut self,
        message: ResolverDelivery<V>,
        delivers: &mut Vec<PendingVerification<P::Scheme, V>>,
        buffer: &mut Buf,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
        resolver: &mut impl Resolver<Key = ResolverRequestFor<V>, Subscriber = Annotation>,
    ) -> bool {
        let ResolverDelivery {
            delivery,
            mut value,
            response,
        } = message;
        let Delivery { key, subscribers } = delivery;
        match key {
            Key::Block(commitment) => {
                let block_cfg = V::block_cfg(&self.block_codec_config, commitment);
                let Ok(block) = V::Block::decode_cfg(value.as_ref(), &block_cfg) else {
                    response.send_lossy(false);
                    return false;
                };
                if V::commitment(&block) != commitment {
                    response.send_lossy(false);
                    return false;
                }

                // This block may match the pending floor request. Whether it
                // installs or is rejected as the floor anchor, do not also
                // process it as an ordinary block delivery.
                if self
                    .apply_floor_anchor(&block, buffer, application, resolver)
                    .await
                {
                    response.send_lossy(true);
                    return false;
                }

                // The commitment validates the peer response. Annotations are
                // local context attached to the request and do not affect peer
                // validity.
                self.block_subscriptions.notify(&block);

                // The peer-visible request only says "give me this block".
                // Local annotations explain why the block was requested and
                // therefore where, if anywhere, it should be stored.
                let height = block.height();
                let digest = block.digest();
                let annotations = subscribers.into_vec();

                // Round-bound proposal-parent fetches are `Key::Notarized`
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
                        && height > self.floor.processed_height()
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
            Key::Finalized { height } => {
                let Some((epoch, certificate_codec_config)) =
                    self.certificate_codec_config_for_height(height)
                else {
                    debug!(
                        %height,
                        floor = %self.floor.processed_height(),
                        "ignoring stale delivery"
                    );
                    response.send_lossy(true);
                    return false;
                };

                let Ok(finalization) =
                    Finalization::read_cfg(&mut value, &certificate_codec_config)
                else {
                    response.send_lossy(false);
                    return false;
                };

                // We decoded the certificate with the codec config for the height's epoch, so the
                // finalization must claim that same epoch. A mismatch means the bytes were bounded
                // against the wrong participant set, so reject before verification.
                if finalization.epoch() != epoch {
                    response.send_lossy(false);
                    return false;
                }

                let Ok(block) =
                    V::ApplicationBlock::decode_cfg(&mut value, &self.block_codec_config)
                else {
                    response.send_lossy(false);
                    return false;
                };

                // In contrast to the `Block` and `Notarization` deliveries, the finalization delivery
                // is guaranteed to be certified (assuming the certificate verifies). Because of this,
                // we can skip broader payload checks and just check that the application block matches
                // the commitment in the finalization proposal.
                //
                // TODO(https://github.com/commonwarexyz/monorepo/issues/3938): Apply this pattern
                // conditionally to `Request::Block` and `Request::Notarized`, if the requester knows
                // the requested block is certified.
                let commitment = finalization.proposal.payload;
                if block.height() != height || block.digest() != V::commitment_to_inner(commitment)
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
            Key::Notarized { round } => {
                let Some(scheme) = self.provider.scheme(round.epoch()) else {
                    debug!(
                        ?round,
                        floor = %self.floor.processed_height(),
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

                // The resolver key binds this response to `round`; a certificate for any other
                // round is a bad response even if it decodes correctly.
                if notarization.round() != round {
                    response.send_lossy(false);
                    return false;
                }

                let commitment = notarization.proposal.payload;
                if !V::check_payload(scheme.as_ref(), commitment) {
                    response.send_lossy(false);
                    return false;
                }
                let block_cfg = V::block_cfg(&self.block_codec_config, commitment);
                let Ok(block) = V::Block::decode_cfg(value, &block_cfg) else {
                    response.send_lossy(false);
                    return false;
                };

                if V::commitment(&block) != notarization.proposal.payload {
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
        buffer: &mut Buf,
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
        let mut verified = vec![false; delivers.len()];
        for (epoch, indices) in &by_epoch {
            let Some(scoped) = self.provider.scoped(*epoch) else {
                continue;
            };
            let group: Vec<_> = indices.iter().map(|&i| certs[i]).collect();
            let results =
                verify_certificates(self.context.as_mut(), &scoped, &group, &self.strategy);
            for (j, &idx) in indices.iter().enumerate() {
                verified[idx] = results[j];
            }
        }

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
                    let block = V::from_application_block(block, finalization.proposal.payload);
                    let round = finalization.round();
                    let height = block.height();
                    let digest = block.digest();
                    debug!(?round, %height, "received finalization");

                    // The floor-anchor path fully handles this finalization
                    // and moves the lower bound past it.
                    if self
                        .apply_floor_anchor(&block, buffer, application, resolver)
                        .await
                    {
                        continue;
                    }

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

                    // Cache the notarization and block.
                    let height = block.height();
                    self.cache_block(round, digest, block.clone()).await;
                    self.cache
                        .put_notarization(round, digest, notarization)
                        .await;

                    // A notarized delivery can carry the pending floor block
                    // after the finalization is cached.
                    if self
                        .apply_floor_anchor(&block, buffer, application, resolver)
                        .await
                    {
                        continue;
                    }

                    // If there exists a finalization certificate for this block, we
                    // should finalize it. This could finalize the block faster when
                    // a notarization then a finalization are received via consensus
                    // and we resolve the notarization request before the block request.
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
                }
            }
        }

        wrote
    }

    /// Returns the certificate codec config for `epoch`.
    fn certificate_codec_config(
        &self,
        epoch: Epoch,
    ) -> Option<<<P::Scheme as Verifier>::Certificate as Read>::Cfg> {
        self.provider
            .scoped(epoch)
            .map(|scoped| scoped.certificate_codec_config())
    }

    /// Returns the epoch containing `height` and its certificate codec config.
    fn certificate_codec_config_for_height(
        &self,
        height: Height,
    ) -> Option<(Epoch, <<P::Scheme as Verifier>::Certificate as Read>::Cfg)> {
        let epoch = self.epocher.containing(height)?.epoch();
        self.certificate_codec_config(epoch)
            .map(|config| (epoch, config))
    }

    // -------------------- Application Dispatch --------------------

    /// Attempt to dispatch the next finalized block to the application if ready.
    ///
    /// Dispatch finalized blocks to the application until the pipeline is full
    /// or no more blocks are available.
    ///
    /// This does NOT advance the processed floor height or sync metadata. It only
    /// sends blocks to the application and enqueues pending acks. Metadata is
    /// updated later, in a subsequent `select_loop!` iteration, when the ack
    /// handler updates the processed height.
    ///
    /// Callers must only invoke this after [`Self::sync_finalized`] has made any
    /// preceding finalized-archive writes durable. In other words, anything fed
    /// to the application from this method is already durably persisted in marshal.
    ///
    /// Acks are processed in FIFO order so the processed floor height always
    /// advances sequentially.
    ///
    /// # Crash safety
    ///
    /// Because `select_loop!` arms run to completion, the caller's
    /// [`Self::sync_finalized`] always executes before the ack handler runs. This
    /// guarantees archive data is durable before the processed floor height
    /// advances:
    ///
    /// ```text
    /// Iteration N (caller):
    ///   store_finalization  ->  Archive::put (buffered)
    ///   sync_finalized      ->  archive durable
    ///   try_dispatch_blocks  ->  sends blocks to app, enqueues pending acks
    ///
    /// Iteration M (ack handler, M > N):
    ///   ack handler       ->  update_processed_height  ->  metadata buffered
    ///   stream.sync       ->  metadata durable
    /// ```
    async fn try_dispatch_blocks(
        &mut self,
        application: &mut impl Reporter<Activity = Update<V::ApplicationBlock, A>>,
    ) {
        // Dispatch resumes after the floor anchor is durably stored.
        if self.floor.blocks_progress() {
            return;
        }

        while self.pending_acks.has_capacity() {
            let next_height = self
                .pending_acks
                .next_dispatch_height(self.stream.next_height());
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

    // -------------------- Prunable Storage --------------------

    /// Add a verified block to the prunable archive.
    async fn cache_verified(
        &mut self,
        round: Round,
        digest: <V::Block as Digestible>::Digest,
        block: V::Block,
    ) {
        self.block_subscriptions.notify(&block);
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
        self.block_subscriptions.notify(&block);
        self.cache.put_block(round, digest, block.into()).await;
    }

    /// Sync both finalization archives to durable storage.
    ///
    /// Must be called within the same `select_loop!` arm as any preceding
    /// [`Self::store_finalization`] / [`Self::try_repair_gaps`] writes, before yielding back
    /// to the loop. This is the durability barrier for application delivery:
    /// [`Self::try_dispatch_blocks`] must run only after this sync completes.
    /// It also ensures archives are durable before the ack handler advances
    /// the processed floor height. See [`Self::try_dispatch_blocks`] for details.
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

    /// Get finalized block information from either the finalization archive or
    /// the finalized-block archive.
    async fn get_info_by_height(
        &self,
        height: Height,
    ) -> Option<(Height, <V::Block as Digestible>::Digest)> {
        if let Some(finalization) = self.get_finalization_by_height(height).await {
            return Some((
                height,
                V::commitment_to_inner(finalization.proposal.payload),
            ));
        }

        self.get_finalized_block(height)
            .await
            .map(|block| (block.height(), block.digest()))
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
    /// advances the processed floor height. See [`Self::try_dispatch_blocks`] for the
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
        if height <= self.floor.processed_height() {
            debug!(
                %height,
                floor = %self.floor.processed_height(),
                ?digest,
                "dropping finalization at or below processed height floor"
            );
            return false;
        }
        self.block_subscriptions.notify(&block);

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
        // Gap repair needs a known processed floor. A floor transition may
        // jump the lower bound once its anchor block arrives.
        if self.floor.blocks_progress() {
            return false;
        }

        let mut wrote = false;
        let start = self.floor.processed_height().next();

        // If finalizations extend beyond the last stored block, anchor the
        // trailing block so the gap repair loop below can walk backward from it.
        if let Some(last_finalized) = self.finalizations_by_height.last_index() {
            let have_block = self
                .finalized_blocks
                .last_index()
                .is_some_and(|last| last >= last_finalized);
            if last_finalized > self.floor.processed_height() && !have_block {
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
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_height(commitment, last_finalized),
                        )
                        .ignore();
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
                    // SAFETY: Finalized blocks are archived only after the
                    // parent relationship needed for walkback has been
                    // validated by marshal.
                    let parent_height = cursor
                        .height()
                        .previous()
                        .expect("cursor above gap start has a parent");
                    self.floor
                        .fetch_if_permitted(
                            resolver,
                            Request::finalized_block_by_height(parent_commitment, parent_height),
                        )
                        .ignore();
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
        let requests: Vec<_> = missing_items.into_iter().map(Request::finalized).collect();
        if !requests.is_empty() {
            self.floor
                .fetch_all_if_permitted(resolver, requests)
                .ignore();
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
        self.stream.acknowledge(height);
        self.floor.set_processed_height(height);
        let _ = self
            .processed_height
            .try_set(self.floor.processed_height().get());

        // Prune any existing requests below the new floor.
        resolver.retain(handler::above_height_floor::<V::Commitment>(height));
    }

    /// Returns the latest known finalization round at or below the processed height.
    async fn latest_processed_round(finalizations_by_height: &FC, height: Option<Height>) -> Round {
        let Some(height) = height else {
            return Round::zero();
        };
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
        if height > self.floor.processed_height() || round <= self.floor.processed_round() {
            return;
        }

        let previous = self.floor.processed_round();
        self.floor.set_processed_round(round);

        // Retain view-indexed cache data for a window behind the previously
        // processed finalized block.
        let prune_round = Round::new(
            previous.epoch(),
            previous.view().saturating_sub(self.view_retention_timeout),
        );
        self.cache.prune_by_view(prune_round).await;

        // Prune round-bound requests at or below the processed round.
        resolver.retain(handler::above_round_floor::<V::Commitment>(
            self.floor.processed_round(),
        ));
    }

    /// Prunes finalized blocks and certificates below the given height.
    async fn prune_finalized_archives(&mut self, height: Height) -> Result<(), BoxedError> {
        // Prune the finalized block and finalization certificate archives in parallel.
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
