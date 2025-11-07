use super::{
    cache,
    config::Config,
    ingress::{
        handler::{self, Request},
        mailbox::{Mailbox, Message},
    },
    SchemeProvider,
};
use crate::{
    marshal::{ingress::mailbox::Identifier as BlockID, Update},
    simplex::{
        signing_scheme::Scheme,
        types::{Finalization, Notarization},
    },
    types::Round,
    utils, Block, Reporter,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::PublicKey;
use commonware_macros::select;
use commonware_p2p::Recipients;
use commonware_resolver::Resolver;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{immutable, Archive as _, Identifier as ArchiveID},
    metadata::{self, Metadata},
};
use commonware_utils::{
    fixed_bytes,
    futures::{AbortablePool, Aborter, OptionFuture},
    sequence::FixedBytes,
};
use futures::{
    channel::{mpsc, oneshot},
    try_join, StreamExt,
};
use governor::clock::Clock as GClock;
use pin_project::pin_project;
use prometheus_client::metrics::gauge::Gauge;
use rand::{CryptoRng, Rng};
use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    future::Future,
    time::Instant,
};
use tracing::{debug, error, info};

// The key used to store the last processed height in the metadata store.
const LATEST_KEY: FixedBytes<1> = fixed_bytes!("00");

/// A pending acknowledgement from the application for processing a block at the contained height/commitment.
#[pin_project]
struct PendingAck<B: Block> {
    height: u64,
    commitment: B::Commitment,
    #[pin]
    receiver: oneshot::Receiver<()>,
}

impl<B: Block> Future for PendingAck<B> {
    type Output = <oneshot::Receiver<()> as Future>::Output;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.project().receiver.poll(cx)
    }
}

/// A struct that holds multiple subscriptions for a block.
struct BlockSubscription<B: Block> {
    // The subscribers that are waiting for the block
    subscribers: Vec<oneshot::Sender<B>>,
    // Aborter that aborts the waiter future when dropped
    _aborter: Aborter,
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
pub struct Actor<
    E: Rng + CryptoRng + Spawner + Metrics + Clock + GClock + Storage,
    B: Block,
    P: SchemeProvider<Scheme = S>,
    S: Scheme,
> {
    // ---------- Context ----------
    context: ContextCell<E>,

    // ---------- Message Passing ----------
    // Mailbox
    mailbox: mpsc::Receiver<Message<S, B>>,

    // ---------- Configuration ----------
    // Provider for epoch-specific signing schemes
    scheme_provider: P,
    // Epoch length (in blocks)
    epoch_length: u64,
    // Unique application namespace
    namespace: Vec<u8>,
    // Minimum number of views to retain temporary data after the application processes a block
    view_retention_timeout: u64,
    // Maximum number of blocks to repair at once
    max_repair: u64,
    // Codec configuration for block type
    block_codec_config: B::Cfg,

    // ---------- State ----------
    // Last view processed
    last_processed_round: Round,
    // Last height processed by the application
    last_processed_height: u64,
    // Pending application acknowledgement, if any
    pending_ack: OptionFuture<PendingAck<B>>,
    // Highest known finalized height
    tip: u64,
    // Outstanding subscriptions for blocks
    block_subscriptions: BTreeMap<B::Commitment, BlockSubscription<B>>,
    // Outstanding requests for finalized blocks
    waiting_finalized: BTreeSet<u64>,

    // ---------- Storage ----------
    // Prunable cache
    cache: cache::Manager<E, B, P, S>,
    // Metadata tracking application progress
    application_metadata: Metadata<E, FixedBytes<1>, u64>,
    // Finalizations stored by height
    finalizations_by_height: immutable::Archive<E, B::Commitment, Finalization<S, B::Commitment>>,
    // Finalized blocks stored by height
    finalized_blocks: immutable::Archive<E, B::Commitment, B>,

    // ---------- Metrics ----------
    // Latest height metric
    finalized_height: Gauge,
    // Latest processed height
    processed_height: Gauge,
}

impl<
        E: Rng + CryptoRng + Spawner + Metrics + Clock + GClock + Storage,
        B: Block,
        P: SchemeProvider<Scheme = S>,
        S: Scheme,
    > Actor<E, B, P, S>
{
    /// Create a new application actor.
    pub async fn init(context: E, config: Config<B, P, S>) -> (Self, Mailbox<S, B>) {
        // Initialize cache
        let prunable_config = cache::Config {
            partition_prefix: format!("{}-cache", config.partition_prefix.clone()),
            prunable_items_per_section: config.prunable_items_per_section,
            replay_buffer: config.replay_buffer,
            write_buffer: config.write_buffer,
            freezer_journal_buffer_pool: config.freezer_journal_buffer_pool.clone(),
        };
        let cache = cache::Manager::init(
            context.with_label("cache"),
            prunable_config,
            config.block_codec_config.clone(),
            config.scheme_provider.clone(),
        )
        .await;

        // Initialize finalizations by height
        let start = Instant::now();
        let finalizations_by_height = immutable::Archive::init(
            context.with_label("finalizations_by_height"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalizations-by-height-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalizations-by-height-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.freezer_table_initial_size,
                freezer_table_resize_frequency: config.freezer_table_resize_frequency,
                freezer_table_resize_chunk_size: config.freezer_table_resize_chunk_size,
                freezer_journal_partition: format!(
                    "{}-finalizations-by-height-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: config.freezer_journal_target_size,
                freezer_journal_compression: config.freezer_journal_compression,
                freezer_journal_buffer_pool: config.freezer_journal_buffer_pool.clone(),
                ordinal_partition: format!(
                    "{}-finalizations-by-height-ordinal",
                    config.partition_prefix
                ),
                items_per_section: config.immutable_items_per_section,
                codec_config: S::certificate_codec_config_unbounded(),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalizations by height archive");
        info!(elapsed = ?start.elapsed(), "restored finalizations by height archive");

        // Initialize finalized blocks
        let start = Instant::now();
        let finalized_blocks = immutable::Archive::init(
            context.with_label("finalized_blocks"),
            immutable::Config {
                metadata_partition: format!(
                    "{}-finalized_blocks-metadata",
                    config.partition_prefix
                ),
                freezer_table_partition: format!(
                    "{}-finalized_blocks-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.freezer_table_initial_size,
                freezer_table_resize_frequency: config.freezer_table_resize_frequency,
                freezer_table_resize_chunk_size: config.freezer_table_resize_chunk_size,
                freezer_journal_partition: format!(
                    "{}-finalized_blocks-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: config.freezer_journal_target_size,
                freezer_journal_compression: config.freezer_journal_compression,
                freezer_journal_buffer_pool: config.freezer_journal_buffer_pool,
                ordinal_partition: format!("{}-finalized_blocks-ordinal", config.partition_prefix),
                items_per_section: config.immutable_items_per_section,
                codec_config: config.block_codec_config.clone(),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

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
        let last_processed_height = *application_metadata.get(&LATEST_KEY).unwrap_or(&0);

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
        processed_height.set(last_processed_height as i64);

        assert!(config.max_repair > 0, "max_repair must be greater than 0");

        // Initialize mailbox
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                scheme_provider: config.scheme_provider,
                epoch_length: config.epoch_length,
                namespace: config.namespace,
                view_retention_timeout: config.view_retention_timeout,
                max_repair: config.max_repair,
                block_codec_config: config.block_codec_config,
                last_processed_round: Round::new(0, 0),
                last_processed_height,
                pending_ack: None.into(),
                tip: 0,
                block_subscriptions: BTreeMap::new(),
                waiting_finalized: BTreeSet::new(),
                cache,
                application_metadata,
                finalizations_by_height,
                finalized_blocks,
                finalized_height,
                processed_height,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the actor.
    pub fn start<R, K>(
        mut self,
        application: impl Reporter<Activity = Update<B>>,
        buffer: buffered::Mailbox<K, B>,
        resolver: (mpsc::Receiver<handler::Message<B>>, R),
    ) -> Handle<()>
    where
        R: Resolver<Key = handler::Request<B>>,
        K: PublicKey,
    {
        spawn_cell!(self.context, self.run(application, buffer, resolver).await)
    }

    /// Run the application actor.
    async fn run<R, K>(
        mut self,
        mut application: impl Reporter<Activity = Update<B>>,
        mut buffer: buffered::Mailbox<K, B>,
        (mut resolver_rx, mut resolver): (mpsc::Receiver<handler::Message<B>>, R),
    ) where
        R: Resolver<Key = handler::Request<B>>,
        K: PublicKey,
    {
        // Create a local pool for waiter futures.
        let mut waiters = AbortablePool::<(B::Commitment, B)>::default();

        // Get tip and send to application
        let tip = self.get_latest().await;
        if let Some((height, commitment)) = tip {
            application.report(Update::Tip(height, commitment)).await;
            self.tip = height;
            self.finalized_height.set(height as i64);
        }

        loop {
            // Remove any dropped subscribers. If all subscribers dropped, abort the waiter.
            self.block_subscriptions.retain(|_, bs| {
                bs.subscribers.retain(|tx| !tx.is_canceled());
                !bs.subscribers.is_empty()
            });

            // Select messages
            select! {
                // Handle waiter completions first
                result = waiters.next_completed() => {
                    let Ok((commitment, block)) = result else {
                        continue; // Aborted future
                    };
                    self.notify_subscribers(commitment, &block).await;
                },
                // Handle application acknowledgements next
                ack = &mut self.pending_ack => {
                    let PendingAck { height, commitment, .. } = self.pending_ack.take().expect("ack state must be present");

                    match ack {
                        Ok(()) => {
                            if let Err(e) = self
                                .handle_block_processed(height, commitment, &mut resolver)
                                .await
                            {
                                error!(?e, height, "failed to update application progress");
                                return;
                            }
                            self.try_dispatch_block(&mut application).await;
                        }
                        Err(e) => {
                            error!(?e, height, "application did not acknowledge block");
                            return;
                        }
                    }
                },
                // Handle consensus inputs before backfill or resolver traffic
                mailbox_message = self.mailbox.next() => {
                    let Some(message) = mailbox_message else {
                        info!("mailbox closed, shutting down");
                        return;
                    };
                    match message {
                        Message::GetInfo { identifier, response } => {
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
                                    .get(ArchiveID::Index(height))
                                    .await
                                    .ok()
                                    .flatten()
                                    .map(|f| (height, f.proposal.payload)),
                                BlockID::Latest => self.get_latest().await,
                            };
                            let _ = response.send(info);
                        }
                        Message::Broadcast { block } => {
                            let _peers = buffer.broadcast(Recipients::All, block).await;
                        }
                        Message::Verified { round, block } => {
                            self.cache_verified(round, block.commitment(), block).await;
                        }
                        Message::Notarization { notarization } => {
                            let round = notarization.round();
                            let commitment = notarization.proposal.payload;

                            // Store notarization by view
                            self.cache.put_notarization(round, commitment, notarization.clone()).await;

                            // Search for block locally, otherwise fetch it remotely
                            if let Some(block) = self.find_block(&mut buffer, commitment).await {
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
                            self.cache.put_finalization(round, commitment, finalization.clone()).await;

                            // Search for block locally, otherwise fetch it remotely
                            if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                // If found, persist the block
                                let height = block.height();
                                self.finalize(
                                    height,
                                    commitment,
                                    block,
                                    Some(finalization),
                                    &mut application,
                                    &mut buffer,
                                    &mut resolver,
                                )
                                .await;
                                debug!(?round, height, "finalized block stored");
                            } else {
                                // Otherwise, fetch the block from the network.
                                debug!(?round, ?commitment, "finalized block missing");
                                resolver.fetch(Request::<B>::Block(commitment)).await;
                            }
                        }
                        Message::GetBlock { identifier, response } => {
                            match identifier {
                                BlockID::Commitment(commitment) => {
                                    let result = self.find_block(&mut buffer, commitment).await;
                                    let _ = response.send(result);
                                }
                                BlockID::Height(height) => {
                                    let result = self.get_finalized_block(height).await;
                                    let _ = response.send(result);
                                }
                                BlockID::Latest => {
                                    let block = match self.get_latest().await {
                                        Some((_, commitment)) => self.find_block(&mut buffer, commitment).await,
                                        None => None,
                                    };
                                    let _ = response.send(block);
                                }
                            }
                        }
                        Message::GetFinalization { height, response } => {
                            let finalization = self.get_finalization_by_height(height).await;
                            let _ = response.send(finalization);
                        }
                        Message::Subscribe { round, commitment, response } => {
                            // Check for block locally
                            if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                let _ = response.send(block);
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
                                    let (tx, rx) = oneshot::channel();
                                    buffer.subscribe_prepared(None, commitment, None, tx).await;
                                    let aborter = waiters.push(async move {
                                        (commitment, rx.await.expect("buffer subscriber closed"))
                                    });
                                    entry.insert(BlockSubscription {
                                        subscribers: vec![response],
                                        _aborter: aborter,
                                    });
                                }
                            }
                        }
                    }
                },
                // Handle resolver messages last
                message = resolver_rx.next() => {
                    let Some(message) = message else {
                        info!("handler closed, shutting down");
                        return;
                    };
                    match message {
                        handler::Message::Produce { key, response } => {
                            match key {
                                Request::Block(commitment) => {
                                    // Check for block locally
                                    let Some(block) = self.find_block(&mut buffer, commitment).await else {
                                        debug!(?commitment, "block missing on request");
                                        continue;
                                    };
                                    let _ = response.send(block.encode().into());
                                }
                                Request::Finalized { height } => {
                                    // Get finalization
                                    let Some(finalization) = self.get_finalization_by_height(height).await else {
                                        debug!(height, "finalization missing on request");
                                        continue;
                                    };

                                    // Get block
                                    let Some(block) = self.get_finalized_block(height).await else {
                                        debug!(height, "finalized block missing on request");
                                        continue;
                                    };

                                    // Send finalization
                                    let _ = response.send((finalization, block).encode().into());
                                }
                                Request::Notarized { round } => {
                                    // Get notarization
                                    let Some(notarization) = self.cache.get_notarization(round).await else {
                                        debug!(?round, "notarization missing on request");
                                        continue;
                                    };

                                    // Get block
                                    let commitment = notarization.proposal.payload;
                                    let Some(block) = self.find_block(&mut buffer, commitment).await else {
                                        debug!(?commitment, "block missing on request");
                                        continue;
                                    };
                                    let _ = response.send((notarization, block).encode().into());
                                }
                            }
                        },
                        handler::Message::Deliver { key, value, response } => {
                            match key {
                                Request::Block(commitment) => {
                                    // Parse block
                                    let Ok(block) = B::decode_cfg(value.as_ref(), &self.block_codec_config) else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Validation
                                    if block.commitment() != commitment {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Persist the block, also persisting the finalization if we have it
                                    let height = block.height();
                                    let finalization = self.cache.get_finalization_for(commitment).await;
                                    self.finalize(
                                        height,
                                        commitment,
                                        block,
                                        finalization,
                                        &mut application,
                                        &mut buffer,
                                        &mut resolver,
                                    )
                                    .await;
                                    debug!(?commitment, height, "received block");
                                    let _ = response.send(true);
                                },
                                Request::Finalized { height } => {
                                    let epoch = utils::epoch(self.epoch_length, height);
                                    let Some(scheme) = self.scheme_provider.scheme(epoch) else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Parse finalization
                                    let Ok((finalization, block)) =
                                        <(Finalization<S, B::Commitment>, B)>::decode_cfg(
                                            value,
                                            &(scheme.certificate_codec_config(), self.block_codec_config.clone()),
                                        )
                                    else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Validation
                                    if block.height() != height
                                        || finalization.proposal.payload != block.commitment()
                                        || !finalization.verify(&mut self.context, &scheme, &self.namespace)
                                    {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Valid finalization received
                                    debug!(height, "received finalization");
                                    let _ = response.send(true);
                                    self.finalize(
                                        height,
                                        block.commitment(),
                                        block,
                                        Some(finalization),
                                        &mut application,
                                        &mut buffer,
                                        &mut resolver,
                                    )
                                    .await;
                                },
                                Request::Notarized { round } => {
                                    let Some(scheme) = self.scheme_provider.scheme(round.epoch()) else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Parse notarization
                                    let Ok((notarization, block)) =
                                        <(Notarization<S, B::Commitment>, B)>::decode_cfg(
                                            value,
                                            &(scheme.certificate_codec_config(), self.block_codec_config.clone()),
                                        )
                                    else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Validation
                                    if notarization.round() != round
                                        || notarization.proposal.payload != block.commitment()
                                        || !notarization.verify(&mut self.context, &scheme, &self.namespace)
                                    {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Valid notarization received
                                    let _ = response.send(true);
                                    let commitment = block.commitment();
                                    debug!(?round, ?commitment, "received notarization");

                                    // If there exists a finalization certificate for this block, we
                                    // should finalize it. While not necessary, this could finalize
                                    // the block faster in the case where a notarization then a
                                    // finalization is received via the consensus engine and we
                                    // resolve the request for the notarization before we resolve
                                    // the request for the block.
                                    let height = block.height();
                                    if let Some(finalization) = self.cache.get_finalization_for(commitment).await {
                                        self.finalize(
                                            height,
                                            commitment,
                                            block.clone(),
                                            Some(finalization),
                                            &mut application,
                                            &mut buffer,
                                            &mut resolver,
                                        )
                                        .await;
                                    }

                                    // Cache the notarization and block
                                    self.cache_block(round, commitment, block).await;
                                    self.cache.put_notarization(round, commitment, notarization).await;
                                },
                            }
                        },
                    }
                },
            }
        }
    }

    // -------------------- Waiters --------------------

    /// Notify any subscribers for the given commitment with the provided block.
    async fn notify_subscribers(&mut self, commitment: B::Commitment, block: &B) {
        if let Some(mut bs) = self.block_subscriptions.remove(&commitment) {
            for subscriber in bs.subscribers.drain(..) {
                let _ = subscriber.send(block.clone());
            }
        }
    }

    // -------------------- Application Dispatch --------------------

    /// Attempt to dispatch the next finalized block to the application if ready.
    async fn try_dispatch_block(&mut self, application: &mut impl Reporter<Activity = Update<B>>) {
        if self.pending_ack.is_some() {
            return;
        }

        let next_height = self.last_processed_height.saturating_add(1);
        let Some(block) = self.get_finalized_block(next_height).await else {
            return;
        };
        assert_eq!(
            block.height(),
            next_height,
            "finalized block height mismatch"
        );

        let (height, commitment) = (block.height(), block.commitment());
        let (ack_tx, ack_rx) = oneshot::channel();
        application.report(Update::Block(block, ack_tx)).await;
        self.pending_ack.replace(PendingAck {
            height,
            commitment,
            receiver: ack_rx,
        });
    }

    /// Handle acknowledgement from the application that a block has been processed.
    async fn handle_block_processed(
        &mut self,
        height: u64,
        digest: B::Commitment,
        resolver: &mut impl Resolver<Key = Request<B>>,
    ) -> Result<(), metadata::Error> {
        self.processed_height.set(height as i64);
        self.last_processed_height = height;
        self.application_metadata
            .put_sync(LATEST_KEY.clone(), height)
            .await?;

        resolver.cancel(Request::<B>::Block(digest)).await;
        resolver
            .retain(Request::<B>::Finalized { height }.predicate())
            .await;

        self.waiting_finalized.remove(&height);

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

        Ok(())
    }

    // -------------------- Prunable Storage --------------------

    /// Add a verified block to the prunable archive.
    async fn cache_verified(&mut self, round: Round, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block).await;
        self.cache.put_verified(round, commitment, block).await;
    }

    /// Add a notarized block to the prunable archive.
    async fn cache_block(&mut self, round: Round, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block).await;
        self.cache.put_block(round, commitment, block).await;
    }

    // -------------------- Immutable Storage --------------------

    /// Get a finalized block from the immutable archive.
    async fn get_finalized_block(&self, height: u64) -> Option<B> {
        match self.finalized_blocks.get(ArchiveID::Index(height)).await {
            Ok(block) => block,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    async fn get_finalization_by_height(
        &self,
        height: u64,
    ) -> Option<Finalization<S, B::Commitment>> {
        match self
            .finalizations_by_height
            .get(ArchiveID::Index(height))
            .await
        {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Add a finalized block, and optionally a finalization, to the archive, and
    /// attempt to identify + repair any gaps in the archive.
    #[allow(clippy::too_many_arguments)]
    async fn finalize(
        &mut self,
        height: u64,
        commitment: B::Commitment,
        block: B,
        finalization: Option<Finalization<S, B::Commitment>>,
        application: &mut impl Reporter<Activity = Update<B>>,
        buffer: &mut buffered::Mailbox<impl PublicKey, B>,
        resolver: &mut impl Resolver<Key = Request<B>>,
    ) {
        self.store_finalization(height, commitment, block, finalization, application)
            .await;

        self.try_repair_gaps(buffer, resolver, application).await;
    }

    /// Add a finalized block, and optionally a finalization, to the archive.
    ///
    /// After persisting the block, attempt to dispatch the next contiguous block to the
    /// application.
    async fn store_finalization(
        &mut self,
        height: u64,
        commitment: B::Commitment,
        block: B,
        finalization: Option<Finalization<S, B::Commitment>>,
        application: &mut impl Reporter<Activity = Update<B>>,
    ) {
        self.notify_subscribers(commitment, &block).await;

        // In parallel, update the finalized blocks and finalizations archives
        if let Err(e) = try_join!(
            // Update the finalized blocks archive
            self.finalized_blocks.put_sync(height, commitment, block),
            // Update the finalizations archive (if provided)
            async {
                if let Some(finalization) = finalization {
                    self.finalizations_by_height
                        .put_sync(height, commitment, finalization)
                        .await?;
                }
                Ok::<_, _>(())
            }
        ) {
            panic!("failed to finalize: {e}");
        }

        // Update metrics and send tip update to application
        if height > self.tip {
            application.report(Update::Tip(height, commitment)).await;
            self.tip = height;
            self.finalized_height.set(height as i64);
        }

        self.try_dispatch_block(application).await;
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
    async fn get_latest(&mut self) -> Option<(u64, B::Commitment)> {
        let height = self.finalizations_by_height.last_index()?;
        let finalization = self
            .get_finalization_by_height(height)
            .await
            .expect("finalization missing");
        Some((height, finalization.proposal.payload))
    }

    // -------------------- Mixed Storage --------------------

    /// Looks for a block anywhere in local storage.
    async fn find_block<K: PublicKey>(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        commitment: B::Commitment,
    ) -> Option<B> {
        // Check buffer.
        if let Some(block) = buffer.get(None, commitment, None).await.into_iter().next() {
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
    async fn try_repair_gaps<K: PublicKey>(
        &mut self,
        buffer: &mut buffered::Mailbox<K, B>,
        resolver: &mut impl Resolver<Key = Request<B>>,
        application: &mut impl Reporter<Activity = Update<B>>,
    ) {
        for (gap_start, gap_end) in self.identify_gaps() {
            // Attempt to repair the gap backwards from the end of the gap, using
            // blocks from our local storage.
            let Some(mut cursor) = self.get_finalized_block(gap_end).await else {
                panic!("gapped block missing that should exist: {gap_end}");
            };

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
                    debug!(height = block.height(), "repaired block");
                    cursor = block;
                } else {
                    // Request the next missing block digest
                    resolver.fetch(Request::<B>::Block(commitment)).await;
                    break;
                }
            }

            // If we haven't fully repaired the gap, then also request any possible
            // finalizations for the blocks in the remaining gap. This may help
            // shrink the size of the gap if finalizations for the requests heights
            // exist. If not, we rely on the recursive digest fetch above.
            let gap_end = std::cmp::min(cursor.height(), gap_start);
            debug!(gap_start, gap_end, "requesting any finalized blocks");
            for height in gap_start..gap_end {
                if !self.waiting_finalized.insert(height) {
                    continue;
                }
                resolver.fetch(Request::<B>::Finalized { height }).await;
            }
        }
    }

    /// Identifies one or more of the earliest gaps in the finalized blocks archive. The gaps
    /// returned are half-open ranges, where `start` is inclusive and `end` is exclusive. The total
    /// number of missing heights covered by the returned gaps is bounded by `self.max_repair`.
    fn identify_gaps(&self) -> Vec<(u64, u64)> {
        const FIRST_HEIGHT_IN_ARCHIVE: u64 = 1;

        let mut remaining = self.max_repair;
        let mut gaps = Vec::new();
        let mut previous_end = FIRST_HEIGHT_IN_ARCHIVE.saturating_sub(1);

        for (range_start, range_end) in self.finalized_blocks.ranges() {
            if remaining == 0 {
                break;
            }

            let next_expected = previous_end.saturating_add(1);
            if range_start > next_expected {
                let gap_size = range_start - next_expected;
                let take = gap_size.min(remaining);
                let gap_start = range_start.saturating_sub(take);
                gaps.push((gap_start, range_start));
                remaining -= take;
            }

            previous_end = range_end;
        }

        gaps
    }
}
