use super::{
    config::Config,
    handler::{self, Handler},
    ingress::{Mailbox, Message, Orchestration, Orchestrator},
    types::{Block, Finalized, Notarized},
};
use crate::threshold_simplex::types::Finalization;
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::{
    bls12381::primitives::variant::Variant, Digest, Digestible, PublicKey,
};
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
use commonware_utils::array::{FixedBytes, U64};
use futures::{channel::mpsc, try_join, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    collections::BTreeSet,
    marker::PhantomData,
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};

/// Application actor.
pub struct Actor<
    D: Digest,
    R: Rng + Spawner + Metrics + Clock + GClock + Storage,
    V: Variant,
    P: PublicKey,
    Z: Coordinator<PublicKey = P>,
> {
    context: R,
    public_key: P,
    identity: V::Public,
    coordinator: Z,
    mailbox: mpsc::Receiver<Message<V, D>>,
    mailbox_size: usize,
    backfill_quota: Quota,
    activity_timeout: u64,
    namespace: Vec<u8>,

    // Blocks verified stored by view<>digest
    verified: prunable::Archive<TwoCap, R, D, Block<D>>,
    // Blocks notarized stored by view<>digest
    notarized: prunable::Archive<TwoCap, R, D, Notarized<V, D>>,

    // Finalizations stored by height
    finalized: immutable::Archive<R, D, Finalization<V, D>>,
    // Blocks finalized stored by height
    //
    // We store this separately because we may not have the finalization for a block
    blocks: immutable::Archive<R, D, Block<D>>,

    // Finalizer storage
    metadata: Metadata<R, FixedBytes<1>, U64>,

    // Latest height metric
    finalized_height: Gauge,
    // Indexed height metric
    contiguous_height: Gauge,

    _variant: PhantomData<V>,
}

impl<
        D: Digest,
        R: Rng + Spawner + Metrics + Clock + GClock + Storage,
        V: Variant,
        P: PublicKey,
        Z: Coordinator<PublicKey = P>,
    > Actor<D, R, V, P, Z>
{
    /// Create a new application actor.
    pub async fn init(context: R, config: Config<V, P, Z>) -> (Self, Mailbox<V, D>) {
        // Initialize verified blocks
        let start = Instant::now();
        let verified = prunable::Archive::init(
            context.with_label("verified"),
            prunable::Config {
                partition: format!("{}-verified", config.partition_prefix),
                translator: TwoCap,
                items_per_section: config.prunable_items_per_section,
                compression: None,
                codec_config: (),
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
                codec_config: (),
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
                freezer_table_initial_size: config.finalized_freezer_table_initial_size as u32,
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
                freezer_table_initial_size: config.blocks_freezer_table_initial_size as u32,
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
                codec_config: (),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("Failed to initialize finalized archive");
        info!(elapsed = ?start.elapsed(), "restored block archive");

        // Initialize finalizer metadata
        let metadata = Metadata::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", config.partition_prefix),
                codec_config: (),
            },
        )
        .await
        .expect("Failed to initialize metadata");

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
                activity_timeout: config.activity_timeout,
                namespace: config.namespace.clone(),
                verified,
                notarized,
                finalized,
                blocks,
                metadata,

                finalized_height,
                contiguous_height,
                _variant: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(
        mut self,
        buffer: buffered::Mailbox<P, Block<D>>,
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
        mut buffer: buffered::Mailbox<P, Block<D>>,
        backfill_by_digest: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_height: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_view: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        // Initialize resolver by digest
        let (handler, mut by_digest_receiver) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler);
        let (resolver_by_digest_engine, mut resolver_by_digest) = p2p::Engine::new(
            self.context.with_label("resolver"),
            p2p::Config {
                coordinator: self.coordinator.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                requester_config: requester::Config {
                    public_key: self.public_key.clone(),
                    rate_limit: self.backfill_quota,
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
                fetch_retry_timeout: Duration::from_millis(100), // prevent busy loop
                priority_requests: false,
                priority_responses: false,
            },
        );
        resolver_by_digest_engine.start(backfill_by_digest);

        // Initialize resolver by height
        let (handler, mut by_height_receiver) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler);
        let (resolver_by_height_engine, mut resolver_by_height) = p2p::Engine::new(
            self.context.with_label("resolver"),
            p2p::Config {
                coordinator: self.coordinator.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                requester_config: requester::Config {
                    public_key: self.public_key.clone(),
                    rate_limit: self.backfill_quota,
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
                fetch_retry_timeout: Duration::from_millis(100), // prevent busy loop
                priority_requests: false,
                priority_responses: false,
            },
        );
        resolver_by_height_engine.start(backfill_by_height);

        // Initialize resolver by view
        let (handler, mut by_view_receiver) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler);
        let (resolver_by_view_engine, mut resolver_by_view) = p2p::Engine::new(
            self.context.with_label("resolver"),
            p2p::Config {
                coordinator: self.coordinator.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                requester_config: requester::Config {
                    public_key: self.public_key.clone(),
                    rate_limit: self.backfill_quota,
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
                fetch_retry_timeout: Duration::from_millis(100), // prevent busy loop
                priority_requests: false,
                priority_responses: false,
            },
        );
        resolver_by_view_engine.start(backfill_by_view);

        // Process all finalized blocks in order (fetching any that are missing)
        let (mut finalizer_sender, mut finalizer_receiver) = mpsc::channel::<()>(1);
        let (orchestrator_sender, mut orchestrator_receiver) = mpsc::channel(2); // buffer to send processed while moving forward
        let mut orchestor = Orchestrator::new(orchestrator_sender);
        self.context
            .with_label("finalizer")
            .spawn(move |_| async move {
                // Initialize last indexed from metadata store
                let latest_key = FixedBytes::new([0u8]);
                let mut last_indexed = if let Some(bytes) = self.metadata.get(&latest_key) {
                    bytes
                        .to_vec()
                        .try_into()
                        .map(u64::from_be_bytes)
                        .unwrap_or(0)
                } else {
                    0
                };

                // Index all finalized blocks.
                //
                // If using state sync, this is not necessary.
                loop {
                    // Check if the next block is available
                    let next = last_indexed + 1;
                    if let Some(block) = orchestor.get(next).await {
                        // In an application that maintains state, you would compute the state transition function here.
                        //
                        // After an unclean shutdown (where the finalizer metadata is not synced after some height is processed by the application),
                        // it is possible that the application may be asked to process a block it has already seen (which it can simply ignore).

                        // Update finalizer metadata.
                        //
                        // If we updated the finalizer metadata before the application applied its state transition function, an unclean
                        // shutdown could put the application in an unrecoverable state where the last indexed height (the height we
                        // start processing at after restart) is ahead of the application's last processed height (requiring the application
                        // to process a non-contiguous log). For the same reason, the application should sync any cached disk changes after processing
                        // its state transition function to ensure that the application can continue processing from the the last synced indexed height
                        // (on restart).
                        if let Err(e) = self
                            .metadata
                            .put_sync(latest_key.clone(), next.into())
                            .await
                        {
                            error!("Failed to update metadata: {e}");
                            return;
                        }

                        // Update the latest indexed
                        self.contiguous_height.set(next as i64);
                        last_indexed = next;
                        info!(height = next, "indexed finalized block");

                        // Update last view processed (if we have a finalization for this block)
                        orchestor.processed(next, block.digest()).await;
                        continue;
                    }

                    // Try to connect to our latest handled block (may not exist finalizations for some heights)
                    if orchestor.repair(next).await {
                        continue;
                    }

                    // If nothing to do, wait for some message from someone that the finalized store was updated
                    debug!(height = next, "waiting to index finalized block");
                    let _ = finalizer_receiver.next().await;
                }
            });

        // Handle messages
        let mut latest_view = 0;
        let mut requested_blocks = BTreeSet::new();
        let mut last_view_processed: u64 = 0;
        let mut outstanding_notarize: BTreeSet<u64> = BTreeSet::new();
        loop {
            // Cancel useless requests
            let mut to_cancel = Vec::<u64>::new();
            outstanding_notarize.retain(|view| {
                if *view < latest_view {
                    to_cancel.push(*view);
                    false
                } else {
                    true
                }
            });
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
                                .put_sync(view, payload.digest(), payload)
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
                            // Check if in buffer
                            let proposal = &notarization.proposal;
                            let mut block =  buffer.get(None, proposal.payload, Some(proposal.payload)).await.into_iter().next();

                            // Check if in verified blocks
                            if block.is_none() {
                                block = match self.verified.get(Identifier::Key(&proposal.payload)).await {
                                    Ok(block) => block,
                                    Err(e) => panic!("Failed to get verified block: {e}"),
                                };
                            }

                            // If found, store notarization
                            let view = notarization.proposal.view;
                            if let Some(block) = block {
                                let height = block.height;
                                let digest = proposal.payload;
                                let notarization = Notarized::new(notarization, block);

                                // Persist the notarization
                                match self.notarized
                                    .put_sync(view, digest, notarization)
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
                            let mut block = buffer.get(None, proposal.payload, Some(proposal.payload)).await.into_iter().next();

                            // Check if in verified
                            if block.is_none() {
                                block = match self.verified.get(Identifier::Key(&proposal.payload)).await {
                                    Ok(block) => block,
                                    Err(e) => panic!("Failed to get verified block: {e}"),
                                };
                            }

                            // Check if in notarized
                            if block.is_none() {
                                block = match self.notarized.get(Identifier::Key(&proposal.payload)).await {
                                    Ok(notarized) => notarized.map(|n| n.block),
                                    Err(e) => panic!("Failed to get notarized block: {e}"),
                                };
                            }

                            // If found, store finalization
                            let view = finalization.proposal.view;
                            if let Some(block) = block {
                                let digest = proposal.payload;
                                let height = block.height;

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
                            let buffered = buffer.get(None, payload, Some(payload)).await.into_iter().next();
                            if let Some(buffered) = buffered {
                                debug!(height = buffered.height, "found block in buffer");
                                let _ = response.send(buffered);
                                continue;
                            }

                            // Check verified blocks
                            let block = match self.verified.get(Identifier::Key(&payload)).await {
                                Ok(block) => block,
                                Err(e) => panic!("Failed to get verified block: {e}"),
                            };
                            if let Some(block) = block {
                                debug!(height = block.height, "found block in verified");
                                let _ = response.send(block);
                                continue;
                            }

                            // Check if in notarized blocks
                            let notarization = match self.notarized.get(Identifier::Key(&payload)).await {
                                Ok(notarized) => notarized,
                                Err(e) => panic!("Failed to get notarized block: {e}"),
                            };
                            if let Some(notarization) = notarization {
                                let block = notarization.block;
                                debug!(height = block.height, "found block in notarized");
                                let _ = response.send(block);
                                continue;
                            }

                            // Check if in finalized blocks
                            let block = match self.blocks.get(Identifier::Key(&payload)).await {
                                Ok(block) => block,
                                Err(e) => panic!("Failed to get finalized block: {e}"),
                            };
                            if let Some(block) = block {
                                debug!(height = block.height, "found block in finalized");
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
                            buffer.subscribe_prepared(None, payload, Some(payload), response).await;
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
                            let block = match self.blocks.get(Identifier::Index(next)).await {
                                Ok(block) => block,
                                Err(e) => panic!("Failed to get finalized block: {e}"),
                            };
                            result.send(block).unwrap_or_else(|_| warn!("Failed to send block to orchestrator"));
                        }
                        Orchestration::Processed { next, digest } => {
                            // Cancel any outstanding requests (by height and by digest)
                            resolver_by_height.cancel(U64::new(next)).await;
                            resolver_by_digest.cancel(digest).await;

                            // If finalization exists, mark as last_view_processed
                            let finalization = match self.finalized.get(Identifier::Index(next)).await {
                                Ok(finalization) => finalization,
                                Err(e) => panic!("Failed to get finalized block: {e}"),
                            };
                            if let Some(finalization) = finalization {
                                last_view_processed = finalization.proposal.view;
                            }

                            // Drain requested blocks less than next
                            requested_blocks.retain(|height| *height > next);
                        }
                        Orchestration::Repair { next, result } => {
                            // Find next gap
                            let (_, start_next) = self.blocks.next_gap(next);
                            let Some(start_next) = start_next else {
                                result.send(false).unwrap_or_else(|_| warn!("Failed to send repair result"));
                                continue;
                            };

                            // If we are at some height greater than genesis, attempt to repair the parent
                            if next > 0 {
                                // Get gapped block
                                let gapped_block = match self.blocks.get(Identifier::Index(start_next)).await {
                                    Ok(Some(block)) => block,
                                    Ok(None) => panic!("Gapped block missing that should exist: {start_next}"),
                                    Err(e) => panic!("Failed to get finalized block: {e}"),
                                };

                                // Attempt to repair one block from other sources
                                let target_block = gapped_block.parent;
                                let verified = match self.verified.get(Identifier::Key(&target_block)).await {
                                    Ok(block) => block,
                                    Err(e) => panic!("Failed to get verified block: {e}"),
                                };
                                if let Some(verified) = verified {
                                    let height = verified.height;
                                    if let Err(e) = self.blocks.put_sync(height, target_block, verified).await {
                                        panic!("Failed to insert finalized block: {e}");
                                    }
                                    debug!(height, "repaired block from verified");
                                    result.send(true).unwrap_or_else(|_| warn!("Failed to send repair result"));
                                    continue;
                                }
                                let notarization = match self.notarized.get(Identifier::Key(&target_block)).await {
                                    Ok(notarized) => notarized,
                                    Err(e) => panic!("Failed to get notarized block: {e}"),
                                };
                                if let Some(notarization) = notarization {
                                let height = notarization.block.height;
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
                        handler::Message::Produce { key: digest, response } => {
                            // Check buffer
                            let block = buffer.get(None, digest, Some(digest)).await.into_iter().next();
                            if let Some(block) = block {
                                let _ = response.send(block.encode().into());
                                continue;
                            }

                            // Get verified block
                            let block = match self.verified.get(Identifier::Key(&digest)).await {
                                Ok(block) => block,
                                Err(e) => panic!("Failed to get verified block: {e}"),
                            };
                            if let Some(block) = block {
                                let _ = response.send(block.encode().into());
                                continue;
                            }

                            // Get notarized block
                            let notarization = match self.notarized.get(Identifier::Key(&digest)).await {
                                Ok(notarized) => notarized,
                                Err(e) => panic!("Failed to get notarized block: {e}"),
                            };
                            if let Some(notarized) = notarization {
                                let _ = response.send(notarized.block.encode().into());
                                continue;
                            }

                            // Get block
                            let block = match self.blocks.get(Identifier::Key(&digest)).await {
                                Ok(block) => block,
                                Err(e) => panic!("Failed to get finalized block: {e}"),
                            };
                            if let Some(block) = block {
                                let _ = response.send(block.encode().into());
                                continue;
                            };

                            // No record of block
                            debug!(?digest, "block missing on request");
                        },
                        handler::Message::Deliver { key: digest, value, response } => {
                            // Parse block
                            let Ok(block) = Block::decode(value.as_ref()) else {
                                let _ = response.send(false);
                                continue;
                            };

                            // Ensure the received payload is for the correct digest
                            if block.digest() != digest {
                                let _ = response.send(false);
                                continue;
                            }

                            // Persist the block
                            debug!(?digest, height = block.height, "received block");
                            let _ = response.send(true);
                            if let Err(e) = self.blocks
                                .put_sync(block.height, digest, block)
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
                            let finalization = match self.finalized.get(Identifier::Index(height)).await {
                                Ok(finalization) => finalization,
                                Err(e) => panic!("Failed to get finalization: {e}"),
                            };
                            let Some(finalization) = finalization else {
                                debug!(height, "finalization missing on request");
                                continue;
                            };

                            // Get block
                            let block = match self.blocks.get(Identifier::Index(height)).await {
                                Ok(block) => block,
                                Err(e) => panic!("Failed to get finalized block: {e}"),
                            };
                            let Some(block) = block else {
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
                            let Ok(finalization) = Finalized::decode(value.as_ref()) else {
                                let _ = response.send(false);
                                continue;
                            };
                            if !finalization.verify(&self.namespace, &self.identity) {
                                let _ = response.send(false);
                                continue;
                            }

                            // Ensure the received payload is for the correct height
                            if finalization.block.height != height {
                                let _ = response.send(false);
                                continue;
                            }

                            // Indicate the finalization was valid
                            debug!(height, "received finalization");
                            let _ = response.send(true);

                            // Persist the finalization and block
                            let finalized = self.finalized
                                .put_sync(height, finalization.block.digest(), finalization.proof);
                            let blocks = self.blocks
                                .put_sync(height, finalization.block.digest(), finalization.block);
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
                            let notarization = match self.notarized.get(Identifier::Index(view)).await {
                                Ok(notarized) => notarized,
                                Err(e) => panic!("Failed to get notarized block: {e}"),
                            };
                            if let Some(notarized) = notarization {
                                let _ = response.send(notarized.encode().into());
                            } else {
                                debug!(view, "notarization missing on request");
                            }
                        },
                        handler::Message::Deliver { key, value, response } => {
                            let view = key.to_u64();
                            // Parse notarization
                            let Ok(notarization) = Notarized::decode(value.as_ref()) else {
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
                                .put_sync(view, notarization.block.digest(), notarization)
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
}
