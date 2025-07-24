use super::{
    config::Config,
    finalizer::Finalizer,
    handler::{self, Handler},
    ingress::{Mailbox, Message, Orchestration, Orchestrator},
    types::{Finalized, Notarized},
};
use crate::{threshold_simplex::types::Finalization, Block};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{Decode, Encode};
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_macros::select;
use commonware_p2p::{utils::requester, Receiver, Recipients, Sender};
use commonware_resolver::{
    p2p::{self, Coordinator},
    Resolver,
};
use commonware_runtime::{Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{self, immutable, prunable, Archive as _, Identifier},
    metadata::{self, Metadata},
    translator::TwoCap,
};
use commonware_utils::{array::U64, Array};
use futures::{channel::mpsc, try_join, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    collections::BTreeSet,
    marker::PhantomData,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

/// Application actor.
pub struct Actor<
    B: Block,
    R: Rng + Spawner + Metrics + Clock + GClock + Storage,
    V: Variant,
    P: PublicKey,
    Z: Coordinator<PublicKey = P>,
> {
    context: R,
    public_key: P,
    identity: V::Public,
    coordinator: Z,
    mailbox: mpsc::Receiver<Message<V, B>>,
    mailbox_size: usize,
    backfill_quota: Quota,
    namespace: Vec<u8>,

    // Blocks verified stored by view<>digest
    verified: prunable::Archive<TwoCap, R, B::Commitment, B>,
    // Blocks notarized stored by view<>digest
    notarized: prunable::Archive<TwoCap, R, B::Commitment, Notarized<V, B>>,

    // Finalizations stored by height
    finalized: immutable::Archive<R, B::Commitment, Finalization<V, B::Commitment>>,
    // Blocks finalized stored by height
    //
    // We store this separately because we may not have the finalization for a block
    blocks: immutable::Archive<R, B::Commitment, B>,

    // Latest height metric
    finalized_height: Gauge,
    // Indexed height metric
    contiguous_height: Gauge,

    // Timeout for block activity (in views)
    activity_timeout: u64,

    // Codec configuration
    codec_config: B::Cfg,

    // Partition prefix
    partition_prefix: String,

    _variant: PhantomData<V>,
}

impl<
        B: Block,
        R: Rng + Spawner + Metrics + Clock + GClock + Storage,
        V: Variant,
        P: PublicKey,
        Z: Coordinator<PublicKey = P>,
    > Actor<B, R, V, P, Z>
{
    /// Create a new application actor.
    pub async fn init(context: R, config: Config<V, P, Z, B>) -> (Self, Mailbox<V, B>) {
        // Initialize verified blocks
        let start = Instant::now();
        let verified = prunable::Archive::init(
            context.with_label("verified"),
            prunable::Config {
                partition: format!("{}-verified", config.partition_prefix),
                translator: TwoCap,
                items_per_section: config.prunable_items_per_section,
                compression: None,
                codec_config: config.codec_config.clone(),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("Failed to initialize verified archive");
        info!(elapsed = ?start.elapsed(), "restored verified archive");

        // Initialize notarized blocks
        let start = Instant::now();
        let notarized = prunable::Archive::init(
            context.with_label("notarized"),
            prunable::Config {
                partition: format!("{}-notarized", config.partition_prefix),
                translator: TwoCap,
                items_per_section: config.prunable_items_per_section,
                compression: None,
                codec_config: config.codec_config.clone(),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("Failed to initialize notarized archive");
        info!(elapsed = ?start.elapsed(), "restored notarized archive");

        // Initialize finalizations
        let start = Instant::now();
        let finalized = immutable::Archive::init(
            context.with_label("finalized"),
            immutable::Config {
                metadata_partition: format!("{}-finalized-metadata", config.partition_prefix),
                freezer_table_partition: format!(
                    "{}-finalized-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.finalized_freezer_table_initial_size,
                freezer_table_resize_frequency: config.freezer_table_resize_frequency,
                freezer_table_resize_chunk_size: config.freezer_table_resize_chunk_size,
                freezer_journal_partition: format!(
                    "{}-finalized-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: config.freezer_journal_target_size,
                freezer_journal_compression: config.freezer_journal_compression,
                ordinal_partition: format!("{}-finalized-ordinal", config.partition_prefix),
                items_per_section: config.immutable_items_per_section,
                codec_config: (),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("Failed to initialize finalized archive");
        info!(elapsed = ?start.elapsed(), "restored finalized archive");

        // Initialize blocks
        let start = Instant::now();
        let blocks = immutable::Archive::init(
            context.with_label("blocks"),
            immutable::Config {
                metadata_partition: format!("{}-blocks-metadata", config.partition_prefix),
                freezer_table_partition: format!(
                    "{}-blocks-freezer-table",
                    config.partition_prefix
                ),
                freezer_table_initial_size: config.blocks_freezer_table_initial_size,
                freezer_table_resize_frequency: config.freezer_table_resize_frequency,
                freezer_table_resize_chunk_size: config.freezer_table_resize_chunk_size,
                freezer_journal_partition: format!(
                    "{}-blocks-freezer-journal",
                    config.partition_prefix
                ),
                freezer_journal_target_size: config.freezer_journal_target_size,
                freezer_journal_compression: config.freezer_journal_compression,
                ordinal_partition: format!("{}-blocks-ordinal", config.partition_prefix),
                items_per_section: config.immutable_items_per_section,
                codec_config: config.codec_config.clone(),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("Failed to initialize blocks archive");
        info!(elapsed = ?start.elapsed(), "restored block archive");

        // Create metrics
        let finalized_height = Gauge::default();
        context.register(
            "finalized_height",
            "Finalized height of application",
            finalized_height.clone(),
        );
        let contiguous_height = Gauge::default();
        context.register(
            "contiguous_height",
            "Contiguous height of application",
            contiguous_height.clone(),
        );

        // Initialize mailbox
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                public_key: config.public_key,
                identity: config.identity,
                coordinator: config.coordinator,
                mailbox,
                mailbox_size: config.mailbox_size,
                backfill_quota: config.backfill_quota,
                namespace: config.namespace.clone(),
                verified,
                notarized,
                finalized,
                blocks,

                finalized_height,
                contiguous_height,
                activity_timeout: config.activity_timeout,
                codec_config: config.codec_config,
                partition_prefix: config.partition_prefix,
                _variant: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Helper to initialize a resolver.
    fn init_resolver<K: Array>(
        context: &R,
        coordinator: Z,
        mailbox_size: usize,
        public_key: P,
        backfill_quota: Quota,
        backfill: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> (mpsc::Receiver<handler::Message<K>>, p2p::Mailbox<K>) {
        let (handler, receiver) = mpsc::channel(mailbox_size);
        let handler = Handler::new(handler);
        let (resolver_engine, resolver) = p2p::Engine::new(
            context.with_label("resolver"),
            p2p::Config {
                coordinator,
                consumer: handler.clone(),
                producer: handler,
                mailbox_size,
                requester_config: requester::Config {
                    public_key,
                    rate_limit: backfill_quota,
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        resolver_engine.start(backfill);
        (receiver, resolver)
    }

    /// Start the actor.
    pub fn start(
        mut self,
        buffer: buffered::Mailbox<P, B>,
        backfill_by_digest: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_height: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_view: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(
            buffer,
            backfill_by_digest,
            backfill_by_height,
            backfill_by_view,
        ))
    }

    /// Run the application actor.
    async fn run(
        mut self,
        mut buffer: buffered::Mailbox<P, B>,
        backfill_by_digest: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_height: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_view: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        // Initialize resolver by digest
        let (mut by_digest_receiver, mut resolver_by_digest) = Self::init_resolver(
            &self.context,
            self.coordinator.clone(),
            self.mailbox_size,
            self.public_key.clone(),
            self.backfill_quota,
            backfill_by_digest,
        );

        // Initialize resolver by height
        let (mut by_height_receiver, mut resolver_by_height) = Self::init_resolver(
            &self.context,
            self.coordinator.clone(),
            self.mailbox_size,
            self.public_key.clone(),
            self.backfill_quota,
            backfill_by_height,
        );

        // Initialize resolver by view
        let (mut by_view_receiver, mut resolver_by_view) = Self::init_resolver(
            &self.context,
            self.coordinator.clone(),
            self.mailbox_size,
            self.public_key.clone(),
            self.backfill_quota,
            backfill_by_view,
        );

        // Initialize finalizer metadata
        let metadata = Metadata::init(
            self.context.with_label("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", self.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("Failed to initialize metadata");

        // Process all finalized blocks in order (fetching any that are missing)
        let (mut finalizer_sender, finalizer_receiver) = mpsc::channel::<()>(1);
        let (orchestrator_sender, mut orchestrator_receiver) = mpsc::channel(2); // buffer to send processed while moving forward
        let orchestrator = Orchestrator::new(orchestrator_sender);
        let finalizer = Finalizer::new(
            metadata,
            self.contiguous_height.clone(),
            orchestrator,
            finalizer_receiver,
        );
        self.context
            .with_label("finalizer")
            .spawn(|_| finalizer.run());

        // Handle messages
        let mut latest_view = 0;
        let mut requested_blocks = BTreeSet::new();
        let mut last_view_processed: u64 = 0;
        let mut outstanding_notarize: BTreeSet<u64> = BTreeSet::new();
        loop {
            // Cancel useless requests
            let (to_cancel, still_outstanding): (BTreeSet<_>, BTreeSet<_>) = outstanding_notarize
                .into_iter()
                .partition(|&view| view < latest_view);
            outstanding_notarize = still_outstanding;
            for view in to_cancel {
                resolver_by_view.cancel(U64::new(view)).await;
            }

            // Select messages
            select! {
                // Handle consensus before finalizer or backfiller
                mailbox_message = self.mailbox.next() => {
                    let Some(message) = mailbox_message else {
                        info!("Mailbox closed, shutting down");
                        return;
                    };
                    match message {
                        Message::Broadcast { payload } => {
                            let ack = buffer.broadcast(Recipients::All, payload).await;
                            drop(ack);
                        }
                        Message::Verified { view, payload } => {
                            match self.verified
                                .put_sync(view, payload.commitment(), payload)
                                .await {
                                    Ok(_) => {
                                        debug!(view, "verified block stored");
                                    },
                                    Err(archive::Error::AlreadyPrunedTo(_)) => {
                                        debug!(view, "verified block already pruned");
                                    }
                                    Err(e) => {
                                        panic!("Failed to insert verified block: {e}");
                                    }
                                };
                        }
                        Message::Notarization { notarization } => {
                            let view = notarization.proposal.view;

                            // Check if in buffer
                            let proposal = &notarization.proposal;
                            let mut block = buffer.get(None, proposal.payload, None).await.into_iter().next();

                            // Check if in verified blocks
                            if block.is_none() {
                                block = self.get_verified(Identifier::Key(&proposal.payload)).await;
                            }

                            // If found, store notarization
                            if let Some(block) = block {
                                let height = block.height();
                                let commitment = proposal.payload;
                                let notarization = Notarized::new(notarization, block);

                                // Persist the notarization
                                match self.notarized
                                    .put_sync(view, commitment, notarization)
                                    .await {
                                    Ok(_) => {
                                        debug!(view, height, "notarized block stored");
                                    },
                                    Err(archive::Error::AlreadyPrunedTo(_)) => {
                                        debug!(view, "notarized already pruned");
                                    },
                                    Err(e) => {
                                        panic!("Failed to insert notarized block: {e}");
                                    }
                                };
                                continue;
                            }

                            // Fetch from network
                            //
                            // We don't worry about retaining the proof because any peer must provide
                            // it to us when serving the notarization.
                            debug!(view, "notarized block missing");
                            outstanding_notarize.insert(view);
                            resolver_by_view.fetch(U64::new(view)).await;
                        }
                        Message::Finalization { finalization } => {
                            // Check if in buffer
                            let proposal = &finalization.proposal;
                            let mut block = buffer.get(None, proposal.payload, None).await.into_iter().next();

                            // Check if in verified
                            if block.is_none() {
                                block = self.get_verified(Identifier::Key(&proposal.payload)).await;
                            }

                            // Check if in notarized
                            if block.is_none() {
                                block = self.get_notarization(Identifier::Key(&proposal.payload)).await.map(|n| n.block);
                            }

                            // If found, store finalization
                            let view = finalization.proposal.view;
                            if let Some(block) = block {
                                let digest = proposal.payload;
                                let height = block.height();

                                // Persist the finalization and block
                                let finalized = self.finalized
                                    .put_sync(height, proposal.payload, finalization);
                                let blocks = self.blocks
                                    .put_sync(height, digest, block);
                                if let Err(e) = try_join!(finalized, blocks) {
                                    panic!("Failed to persist finalization and block: {e}");
                                };
                                debug!(view, height, "finalized block stored");

                                // Prune blocks
                                let min_view = last_view_processed.saturating_sub(self.activity_timeout);
                                let verified = self.verified.prune(min_view);
                                let notarized = self.notarized.prune(min_view);
                                if let Err(e) = try_join!(verified, notarized) {
                                    panic!("Failed to prune verified and notarized blocks: {e}");
                                };
                                debug!(min_view, "pruned verified and notarized archives");

                                // Notify finalizer
                                let _ = finalizer_sender.try_send(());

                                // Update latest
                                latest_view = view;

                                // Update metrics
                                self.finalized_height.set(height as i64);

                                continue;
                            }

                            // Fetch from network
                            warn!(view, digest = ?proposal.payload, "finalized block missing");
                            resolver_by_digest.fetch(proposal.payload).await;
                        }
                        Message::Get { view, payload, response } => {
                            // Check if in buffer
                            let buffered = buffer.get(None, payload, None).await.into_iter().next();
                            if let Some(buffered) = buffered {
                                debug!(height = buffered.height(), "found block in buffer");
                                let _ = response.send(buffered);
                                continue;
                            }

                            // Check verified blocks
                            if let Some(block) = self.get_verified(Identifier::Key(&payload)).await {
                                debug!(height = block.height(), "found block in verified");
                                let _ = response.send(block);
                                continue;
                            }

                            // Check if in notarized blocks
                            if let Some(notarization) = self.get_notarization(Identifier::Key(&payload)).await {
                                let block = notarization.block;
                                debug!(height = block.height(), "found block in notarized");
                                let _ = response.send(block);
                                continue;
                            }

                            // Check if in finalized blocks
                            if let Some(block) = self.get_block(Identifier::Key(&payload)).await {
                                debug!(height = block.height(), "found block in finalized");
                                let _ = response.send(block);
                                continue;
                            }

                            // Fetch from network if notarized (view is non-nil)
                            if let Some(view) = view {
                                debug!(view, ?payload, "required block missing");
                                resolver_by_view.fetch(U64::new(view)).await;
                            }

                            // Register waiter
                            debug!(view, ?payload, "registering waiter");
                            buffer.subscribe_prepared(None, payload, None, response).await;
                        }
                    }
                },
                // Handle finalizer messages next
                orchestrator_message = orchestrator_receiver.next() => {
                    let Some(orchestrator_message) = orchestrator_message else {
                        info!("Orchestrator closed, shutting down");
                        return;
                    };
                    match orchestrator_message {
                        Orchestration::Get { next, result } => {
                            // Check if in blocks
                            let block = self.get_block(Identifier::Index(next)).await;
                            result.send(block).unwrap_or_else(|_| warn!(?next, "Failed to send block to orchestrator"));
                        }
                        Orchestration::Processed { next, digest } => {
                            // Cancel any outstanding requests (by height and by digest)
                            resolver_by_height.cancel(U64::new(next)).await;
                            resolver_by_digest.cancel(digest).await;

                            // If finalization exists, mark as last_view_processed
                            if let Some(finalization) = self.get_finalization(Identifier::Index(next)).await {
                                last_view_processed = finalization.proposal.view;
                            }

                            // Drain requested blocks less than next
                            requested_blocks.retain(|height| *height > next);
                        }
                        Orchestration::Repair { next, result } => {
                            // Find next gap
                            let (_, Some(start_next)) = self.blocks.next_gap(next) else {
                                result.send(false).unwrap_or_else(|_| warn!(?next, "Failed to send repair result"));
                                continue;
                            };

                            // If we are at some height greater than genesis, attempt to repair the parent
                            if next > 0 {
                                // Get gapped block
                                let Some(gapped_block) = self.get_block(Identifier::Index(start_next)).await else {
                                    panic!("Gapped block missing that should exist: {start_next}");
                                };

                                // Attempt to repair one block from other sources
                                let target_block = gapped_block.parent();
                                if let Some(verified) = self.get_verified(Identifier::Key(&target_block)).await {
                                    let height = verified.height();
                                    if let Err(e) = self.blocks.put_sync(height, target_block, verified).await {
                                        panic!("Failed to insert finalized block: {e}");
                                    }
                                    debug!(height, "repaired block from verified");
                                    result.send(true).unwrap_or_else(|_| warn!("Failed to send repair result"));
                                    continue;
                                }
                                if let Some(notarization) = self.get_notarization(Identifier::Key(&target_block)).await {
                                    let height = notarization.block.height();
                                    if let Err(e) = self.blocks.put_sync(height, target_block, notarization.block).await {
                                        panic!("Failed to insert finalized block: {e}");
                                    }
                                    debug!(height, "repaired block from notarizations");
                                    result.send(true).unwrap_or_else(|_| warn!("Failed to send repair result"));
                                    continue;
                                }

                                // Request the parent block digest
                                resolver_by_digest.fetch(target_block).await;
                            }

                            // Enqueue next items (by index)
                            let range = next..std::cmp::min(start_next, next + 20);
                            debug!(range.start, range.end, "requesting missing finalized blocks");
                            for height in range {
                                // Check if we've already requested
                                if requested_blocks.contains(&height) {
                                    continue;
                                }

                                // Request the block
                                resolver_by_height.fetch(U64::new(height)).await;
                                requested_blocks.insert(height);
                            }
                            result.send(false).unwrap_or_else(|_| warn!("Failed to send repair result"));
                        }
                    }
                },
                // Handle resolver messages last
                handler_message = by_digest_receiver.next() => {
                    let Some(message) = handler_message else {
                        info!("Handler closed, shutting down");
                        return;
                    };
                    match message {
                        handler::Message::Produce { key: commitment, response } => {
                            // Check buffer
                            let block = buffer.get(None, commitment, None).await.into_iter().next();
                            if let Some(block) = block {
                                let _ = response.send(block.encode().into());
                                continue;
                            }

                            // Get verified block
                            if let Some(block) = self.get_verified(Identifier::Key(&commitment)).await {
                                let _ = response.send(block.encode().into());
                                continue;
                            }

                            // Get notarized block
                            if let Some(notarized) = self.get_notarization(Identifier::Key(&commitment)).await {
                                let _ = response.send(notarized.block.encode().into());
                                continue;
                            }

                            // Get block
                            if let Some(block) = self.get_block(Identifier::Key(&commitment)).await {
                                let _ = response.send(block.encode().into());
                                continue;
                            };

                            // No record of block
                            debug!(?commitment, "block missing on request");
                        },
                        handler::Message::Deliver { key: commitment, value, response } => {
                            // Parse block
                            let Ok(block) = B::decode_cfg(value.as_ref(), &self.codec_config) else {
                                let _ = response.send(false);
                                continue;
                            };

                            // Ensure the received payload is for the correct digest
                            if block.commitment() != commitment {
                                let _ = response.send(false);
                                continue;
                            }

                            // Persist the block
                            debug!(?commitment, height = block.height(), "received block");
                            let _ = response.send(true);
                            if let Err(e) = self.blocks
                                .put_sync(block.height(), commitment, block)
                                .await {
                                panic!("Failed to insert finalized block: {e}");
                            }

                            // Notify finalizer
                            let _ = finalizer_sender.try_send(());
                        }
                    }
                },
                handler_message = by_height_receiver.next() => {
                    let Some(message) = handler_message else {
                        info!("Handler closed, shutting down");
                        return;
                    };
                    match message {
                        handler::Message::Produce { key, response } => {
                            let height = key.to_u64();
                            // Get finalization
                            let Some(finalization) = self.get_finalization(Identifier::Index(height)).await else {
                                debug!(height, "finalization missing on request");
                                continue;
                            };

                            // Get block
                            let Some(block) = self.get_block(Identifier::Index(height)).await else {
                                debug!(height, "finalized block missing on request");
                                continue;
                            };

                            // Send finalization
                            let payload = Finalized::new(finalization, block);
                            let _ = response.send(payload.encode().into());
                        },
                        handler::Message::Deliver { key, value, response } => {
                            let height = key.to_u64();
                            // Parse finalization
                            let Ok(finalization) = Finalized::<V, B>::decode_cfg(value, &self.codec_config) else {
                                let _ = response.send(false);
                                continue;
                            };
                            if !finalization.verify(&self.namespace, &self.identity) {
                                let _ = response.send(false);
                                continue;
                            }

                            // Ensure the received payload is for the correct height
                            if finalization.block.height() != height {
                                let _ = response.send(false);
                                continue;
                            }

                            // Indicate the finalization was valid
                            debug!(height, "received finalization");
                            let _ = response.send(true);

                            // Persist the finalization and block
                            let finalized = self.finalized
                                .put_sync(height, finalization.block.commitment(), finalization.proof);
                            let blocks = self.blocks
                                .put_sync(height, finalization.block.commitment(), finalization.block);
                            if let Err(e) = try_join!(finalized, blocks) {
                                panic!("Failed to persist finalization and block: {e}");
                            }

                            // Notify finalizer
                            let _ = finalizer_sender.try_send(());
                        },
                    }
                },
                handler_message = by_view_receiver.next() => {
                    let Some(message) = handler_message else {
                        info!("Handler closed, shutting down");
                        return;
                    };
                    match message {
                        handler::Message::Produce { key, response } => {
                            let view = key.to_u64();
                            if let Some(notarized) = self.get_notarization(Identifier::Index(view)).await {
                                let _ = response.send(notarized.encode().into());
                            } else {
                                debug!(view, "notarization missing on request");
                            }
                        },
                        handler::Message::Deliver { key, value, response } => {
                            let view = key.to_u64();
                            // Parse notarization
                            let Ok(notarization) = Notarized::<V, B>::decode_cfg(value, &self.codec_config) else {
                                let _ = response.send(false);
                                continue;
                            };
                            if !notarization.verify(&self.namespace, &self.identity) {
                                let _ = response.send(false);
                                continue;
                            }

                            // Ensure the received payload is for the correct view
                            if notarization.proof.proposal.view != view {
                                let _ = response.send(false);
                                continue;
                            }

                            // Persist the notarization
                            let _ = response.send(true);
                            match self.notarized
                                .put_sync(view, notarization.block.commitment(), notarization)
                                .await {
                                Ok(_) => {
                                    debug!(view, "notarized stored");
                                },
                                Err(archive::Error::AlreadyPrunedTo(_)) => {
                                    debug!(view, "notarized already pruned");

                                }
                                Err(e) => {
                                    panic!("Failed to insert notarized block: {e}");
                                }
                            };
                        },
                    }
                },
            }
        }
    }

    async fn get_block<'a>(&'a self, id: Identifier<'a, B::Commitment>) -> Option<B> {
        match self.blocks.get(id).await {
            Ok(block) => block,
            Err(e) => panic!("Failed to get finalized block: {e}"),
        }
    }

    async fn get_finalization<'a>(
        &'a self,
        id: Identifier<'a, B::Commitment>,
    ) -> Option<Finalization<V, B::Commitment>> {
        match self.finalized.get(id).await {
            Ok(finalization) => finalization,
            Err(e) => panic!("Failed to get finalization: {e}"),
        }
    }

    async fn get_notarization<'a>(
        &'a self,
        id: Identifier<'a, B::Commitment>,
    ) -> Option<Notarized<V, B>> {
        match self.notarized.get(id).await {
            Ok(notarization) => notarization,
            Err(e) => panic!("Failed to get notarization: {e}"),
        }
    }

    async fn get_verified<'a>(&'a self, id: Identifier<'a, B::Commitment>) -> Option<B> {
        match self.verified.get(id).await {
            Ok(verified) => verified,
            Err(e) => panic!("Failed to get verified block: {e}"),
        }
    }
}
