use super::{
    config::Config,
    finalizer::Finalizer,
    ingress::{
        handler::{self, Handler},
        mailbox::{Mailbox, Message},
        orchestrator::{Orchestration, Orchestrator},
    },
};
use crate::{
    threshold_simplex::types::{Finalization, Notarization},
    Block, Reporter,
};
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
    translator::TwoCap,
};
use commonware_utils::{array::U64, Array};
use futures::{channel::mpsc, try_join, StreamExt};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    marker::PhantomData,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

/// When searching for a block locally, the depth of the search.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SearchDepth {
    Verified = 1,
    Notarized = 2,
    Finalized = 3,
}

/// Application actor.
pub struct Actor<
    B: Block,
    R: Rng + Spawner + Metrics + Clock + GClock + Storage,
    V: Variant,
    P: PublicKey,
    Z: Coordinator<PublicKey = P>,
> {
    // ---------- Context ----------
    context: R,

    // ---------- Message Passing ----------
    // Coordinator
    coordinator: Z,
    // Mailbox
    mailbox: mpsc::Receiver<Message<V, B>>,

    // ---------- Configuration ----------
    // Public key
    public_key: P,
    // Identity
    identity: V::Public,
    // Mailbox size
    mailbox_size: usize,
    // Backfill quota
    backfill_quota: Quota,
    // Unique application namespace
    namespace: Vec<u8>,
    /// Minimum grace period for retaining activity after the application has processed the block
    grace_period: u64,
    // Maximum number of blocks to repair at once
    max_repair: u64,
    // Codec configuration
    codec_config: B::Cfg,
    // Partition prefix
    partition_prefix: String,

    // ---------- State ----------
    // Last view processed
    last_processed_view: u64,

    // ---------- Storage ----------
    // Blocks verified stored by view<>digest
    verified: prunable::Archive<TwoCap, R, B::Commitment, B>,
    // Notarizations stored by view<>digest
    //
    // We also store the blocks here since they may not match the block in `verified`
    #[allow(clippy::type_complexity)]
    notarized: prunable::Archive<TwoCap, R, B::Commitment, (Notarization<V, B::Commitment>, B)>,
    // Finalizations stored by view, stored temporarily
    finalization_by_view:
        prunable::Archive<TwoCap, R, B::Commitment, Finalization<V, B::Commitment>>,
    // Finalizations stored by height
    finalized: immutable::Archive<R, B::Commitment, Finalization<V, B::Commitment>>,
    // Blocks finalized stored by height
    //
    // We store this separately because we may not have the finalization for a block
    blocks: immutable::Archive<R, B::Commitment, B>,

    // ---------- Metrics ----------
    // Latest height metric
    finalized_height: Gauge,
    // Latest processed height
    processed_height: Gauge,

    // ---------- Phantom data ----------
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
                codec_config: ((), config.codec_config.clone()),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("Failed to initialize notarized archive");
        info!(elapsed = ?start.elapsed(), "restored notarized archive");

        // Initialize finalizations by view
        let start = Instant::now();
        let finalization_by_view = prunable::Archive::init(
            context.with_label("finalization_by_view"),
            prunable::Config {
                partition: format!("{}-finalization-by-view", config.partition_prefix),
                translator: TwoCap,
                items_per_section: config.prunable_items_per_section,
                compression: None,
                codec_config: (),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("Failed to initialize finalization by view archive");
        info!(elapsed = ?start.elapsed(), "restored finalization by view archive");

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
        let processed_height = Gauge::default();
        context.register(
            "processed_height",
            "Processed height of application",
            processed_height.clone(),
        );

        // Initialize mailbox
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,

                coordinator: config.coordinator,
                mailbox,

                public_key: config.public_key,
                identity: config.identity,
                mailbox_size: config.mailbox_size,
                backfill_quota: config.backfill_quota,
                namespace: config.namespace.clone(),
                grace_period: config.grace_period,
                max_repair: config.max_repair,
                codec_config: config.codec_config.clone(),
                partition_prefix: config.partition_prefix,

                last_processed_view: 0,

                verified,
                notarized,
                finalization_by_view,
                finalized,
                blocks,

                finalized_height,
                processed_height,

                _variant: PhantomData,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the actor.
    pub fn start(
        mut self,
        application: impl Reporter<Activity = B>,
        buffer: buffered::Mailbox<P, B>,
        backfill_by_digest: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_height: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_view: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(
            application,
            buffer,
            backfill_by_digest,
            backfill_by_height,
            backfill_by_view,
        ))
    }

    /// Run the application actor.
    async fn run(
        mut self,
        application: impl Reporter<Activity = B>,
        mut buffer: buffered::Mailbox<P, B>,
        backfill_by_digest: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_height: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
        backfill_by_view: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        // Initialize resolvers
        let (mut resolver_by_digest_rx, mut resolver_by_digest) =
            self.init_resolver::<B::Commitment>(backfill_by_digest);
        let (mut resolver_by_height_rx, mut resolver_by_height) =
            self.init_resolver::<U64>(backfill_by_height);
        let (mut resolver_by_view_rx, mut resolver_by_view) =
            self.init_resolver::<U64>(backfill_by_view);

        // Process all finalized blocks in order (fetching any that are missing)
        let (mut notifier_tx, notifier_rx) = mpsc::channel::<()>(1);
        let (orchestrator_sender, mut orchestrator_receiver) = mpsc::channel(self.mailbox_size);
        let orchestrator = Orchestrator::new(orchestrator_sender);
        let finalizer = Finalizer::new(
            self.context.with_label("finalizer"),
            self.partition_prefix.clone(),
            application,
            orchestrator,
            notifier_rx,
        )
        .await;
        self.context
            .with_label("finalizer")
            .spawn(|_| finalizer.run());

        // Handle messages
        loop {
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
                            self.put_verified(view, payload.commitment(), payload).await;
                        }
                        Message::Notarization { notarization } => {
                            let view = notarization.proposal.view;
                            let commitment = notarization.proposal.payload;

                            // If found, store notarization
                            if let Some(block) = self.search_for_block(&mut buffer, commitment, SearchDepth::Verified).await {
                                self.put_notarization(view, commitment, notarization, block).await;
                                continue;
                            }

                            // Fetch from network
                            //
                            // We don't worry about retaining the proof because any peer must provide
                            // it to us when serving the notarization.
                            debug!(view, "notarized block missing");
                            resolver_by_view.fetch(view.into()).await;
                        }
                        Message::Finalization { finalization } => {
                            // Store finalization by view
                            let view = finalization.proposal.view;
                            let commitment = finalization.proposal.payload;
                            self.put_finalization_by_view(view, commitment, finalization.clone()).await;

                            // Search for block locally, otherwise fetch it remotely
                            if let Some(block) = self.search_for_block(&mut buffer, commitment, SearchDepth::Notarized).await {
                                // If found, persist the finalization and block
                                let height = block.height();
                                self.put_finalized_block(height, commitment, finalization, block, &mut notifier_tx).await;
                                debug!(view, height, "finalized block stored");
                                self.finalized_height.set(height as i64);

                                // Cancel useless requests
                                resolver_by_view.retain(move|k| k > &view.into()).await;
                            } else {
                                // Otherwise, fetch from resolver
                                warn!(view, ?commitment, "finalized block missing");
                                resolver_by_digest.fetch(commitment).await;
                            }
                        }
                        Message::Get { view, payload, response } => {
                            // Check for block locally
                            if let Some(block) = self.search_for_block(&mut buffer, payload, SearchDepth::Finalized).await {
                                let _ = response.send(block);
                                continue;
                            }

                            // Fetch from network
                            if let Some(view) = view {
                                debug!(view, ?payload, "required block missing");
                                resolver_by_view.fetch(view.into()).await;
                            }

                            // Register waiter
                            debug!(view, ?payload, "registering waiter");
                            buffer.subscribe_prepared(None, payload, None, response).await;
                        }
                    }
                },
                // Handle finalizer messages next
                message = orchestrator_receiver.next() => {
                    let Some(message) = message else {
                        info!("Orchestrator closed, shutting down");
                        return;
                    };
                    match message {
                        Orchestration::Get { height, result } => {
                            // Check if in blocks
                            let block = self.get_block(Identifier::Index(height)).await;
                            result.send(block).unwrap_or_else(|_| warn!(?height, "Failed to send block to orchestrator"));
                        }
                        Orchestration::Processed { height, digest } => {
                            // Update metrics
                            self.processed_height.set(height as i64);

                            // Cancel any outstanding requests (by height and by digest)
                            resolver_by_digest.cancel(digest).await;
                            resolver_by_height.retain(move |k| k > &height.into()).await;

                            // If finalization exists, prune the archives
                            if let Some(finalization) = self.get_finalization(Identifier::Index(height)).await {
                                // Trail the previous processed finalized block by the grace period
                                let min_view = self.last_processed_view.saturating_sub(self.grace_period);

                                // Prune archives
                                match try_join!(
                                    self.verified.prune(min_view),
                                    self.notarized.prune(min_view),
                                    self.finalization_by_view.prune(min_view),
                                ) {
                                    Ok(_) => debug!(min_view, "pruned archives"),
                                    Err(e) => panic!("Failed to prune archives: {e}"),
                                }

                                // Update the last processed height and view
                                self.last_processed_view = finalization.proposal.view;
                            }
                        }
                        Orchestration::Repair { height } => {
                            // Find the end of the "gap" of missing blocks, starting at `height`
                            let (_, Some(gap_end)) = self.blocks.next_gap(height) else {
                                // No gap found; height-1 is the last known finalized block
                                continue;
                            };
                            assert!(gap_end > height, "gap end must be greater than height");

                            // Attempt to repair the gap backwards from the end of the gap, using
                            // blocks from our local storage.
                            let Some(mut cursor) = self.get_block(Identifier::Index(gap_end)).await else {
                                panic!("Gapped block missing that should exist: {gap_end}");
                            };

                            // Iterate backwards, repairing blocks as we go.
                            while cursor.height() > height {
                                let commitment = cursor.parent();
                                if let Some(block) = self.search_for_block(&mut buffer, commitment, SearchDepth::Notarized).await {
                                    self.put_block(block.height(), commitment, block.clone(), &mut notifier_tx).await;
                                    debug!(height = block.height(), "repaired block");
                                    cursor = block;
                                } else {
                                    // Request the next missing block digest
                                    resolver_by_digest.fetch(commitment).await;
                                    break;
                                }
                            }

                            // If we haven't fully repaired the gap, then also request any possible
                            // finalizations for the blocks in the remaining gap. This may help
                            // shrink the size of the gap.
                            let gap_end = cursor.height();
                            let gap_start = std::cmp::max(height, gap_end.saturating_sub(self.max_repair));
                            debug!(gap_start, gap_end, "requesting any finalized blocks");
                            for height in gap_start..gap_end {
                                resolver_by_height.fetch(height.into()).await;
                            }
                        }
                    }
                },
                // Handle resolver messages last
                message = resolver_by_digest_rx.next() => {
                    let Some(message) = message else {
                        info!("Handler closed, shutting down");
                        return;
                    };
                    match message {
                        handler::Message::Produce { key: commitment, response } => {
                            // If found, send block
                            if let Some(block) = self.search_for_block(&mut buffer, commitment, SearchDepth::Finalized).await {
                                let _ = response.send(block.encode().into());
                            } else {
                                debug!(?commitment, "block missing on request");
                            }
                        },
                        handler::Message::Deliver { key: commitment, value, response } => {
                            // Parse block
                            let Ok(block) = B::decode_cfg(value.as_ref(), &self.codec_config) else {
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
                            if let Some(finalization) = self.get_finalization_by_view(Identifier::Key(&commitment)).await {
                                self.put_finalized_block(height, commitment, finalization, block, &mut notifier_tx).await;
                            } else {
                                self.put_block(height, commitment, block, &mut notifier_tx).await;
                            }
                            debug!(?commitment, height, "received block");
                            let _ = response.send(true);
                        }
                    }
                },
                message = resolver_by_height_rx.next() => {
                    let Some(message) = message else {
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
                            let _ = response.send((finalization, block).encode().into());
                        },
                        handler::Message::Deliver { key, value, response } => {
                            let height = key.to_u64();
                            // Parse finalization
                            let Ok((finalization, block)) = <(Finalization<V, B::Commitment>, B)>::decode_cfg(value, &((), self.codec_config.clone())) else {
                                let _ = response.send(false);
                                continue;
                            };

                            // Validation
                            if block.height() != height
                                || finalization.proposal.payload != block.commitment()
                                || !finalization.verify(&self.namespace, &self.identity)
                            {
                                let _ = response.send(false);
                                continue;
                            }

                            // Valid finalization received
                            debug!(height, "received finalization");
                            let _ = response.send(true);
                            self.put_finalized_block(height, block.commitment(), finalization, block, &mut notifier_tx).await;
                        },
                    }
                },
                message = resolver_by_view_rx.next() => {
                    let Some(message) = message else {
                        info!("Handler closed, shutting down");
                        return;
                    };
                    match message {
                        handler::Message::Produce { key, response } => {
                            let view = key.to_u64();
                            if let Some((notarization, block)) = self.get_notarization(Identifier::Index(view)).await {
                                let _ = response.send((notarization, block).encode().into());
                            } else {
                                debug!(view, "notarization missing on request");
                            }
                        },
                        handler::Message::Deliver { key, value, response } => {
                            let view = key.to_u64();
                            // Parse notarization
                            let Ok((notarization, block)) = <(Notarization<V, B::Commitment>, B)>::decode_cfg(value, &((), self.codec_config.clone())) else {
                                let _ = response.send(false);
                                continue;
                            };

                            // Validation
                            if notarization.proposal.view != view
                                || notarization.proposal.payload != block.commitment()
                                || !notarization.verify(&self.namespace, &self.identity)
                            {
                                let _ = response.send(false);
                                continue;
                            }

                            // Valid notarization received
                            debug!(view, "received notarization");
                            let _ = response.send(true);
                            self.put_notarization(view, block.commitment(), notarization, block).await;
                        },
                    }
                },
            }
        }
    }

    // -------------------- Resolver --------------------

    /// Helper to initialize a resolver.
    fn init_resolver<K: Array>(
        &self,
        backfill: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> (mpsc::Receiver<handler::Message<K>>, p2p::Mailbox<K>) {
        let (handler, receiver) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler);
        let (resolver_engine, resolver) = p2p::Engine::new(
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
                fetch_retry_timeout: Duration::from_millis(100),
                priority_requests: false,
                priority_responses: false,
            },
        );
        resolver_engine.start(backfill);
        (receiver, resolver)
    }

    // -------------------- Storage --------------------

    /// Add a verified block to the archive.
    async fn put_verified(&mut self, view: u64, commitment: B::Commitment, block: B) {
        match self.verified.put_sync(view, commitment, block).await {
            Ok(_) => {
                debug!(view, "verified stored");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(view, "verified already pruned");
            }
            Err(e) => {
                panic!("Failed to insert verified block: {e}");
            }
        }
    }

    /// Add a finalization to the archive by view.
    async fn put_finalization_by_view(
        &mut self,
        view: u64,
        commitment: B::Commitment,
        finalization: Finalization<V, B::Commitment>,
    ) {
        match self
            .finalization_by_view
            .put_sync(view, commitment, finalization)
            .await
        {
            Ok(_) => {
                debug!(view, "finalization by view stored");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(view, "finalization by view already pruned");
            }
            Err(e) => {
                panic!("Failed to insert finalization by view: {e}");
            }
        }
    }

    /// Add a notarization (with block) to the archive.
    async fn put_notarization(
        &mut self,
        view: u64,
        commitment: B::Commitment,
        notarization: Notarization<V, B::Commitment>,
        block: B,
    ) {
        match self
            .notarized
            .put_sync(view, commitment, (notarization, block))
            .await
        {
            Ok(_) => {
                debug!(view, "notarized stored");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(view, "notarized already pruned");
            }
            Err(e) => {
                panic!("Failed to insert notarization: {e}");
            }
        }
    }

    /// Add a (finalized) block to the archive.
    ///
    /// At the end of the method, the notifier is notified to indicate that there has been an update
    /// to the archive of (finalized) blocks.
    async fn put_block(
        &mut self,
        height: u64,
        commitment: B::Commitment,
        block: B,
        notifier: &mut mpsc::Sender<()>,
    ) {
        if let Err(e) = self.blocks.put_sync(height, commitment, block).await {
            panic!("Failed to insert block: {e}");
        }
        let _ = notifier.try_send(());
    }

    /// Add a finalization (with block) to the archive.
    async fn put_finalized_block(
        &mut self,
        height: u64,
        commitment: B::Commitment,
        finalization: Finalization<V, B::Commitment>,
        block: B,
        notifier: &mut mpsc::Sender<()>,
    ) {
        if let Err(e) = try_join!(
            self.finalized.put_sync(height, commitment, finalization),
            self.blocks.put_sync(height, commitment, block),
        ) {
            panic!("Failed to insert finalization: {e}");
        }
        let _ = notifier.try_send(());
    }

    /// Looks for a block in local storage.
    ///
    /// Tries to find the block efficiently, starting with the buffer, then verified,
    /// then notarized, and finally the blocks archive.
    async fn search_for_block(
        &mut self,
        buffer: &mut buffered::Mailbox<P, B>,
        commitment: B::Commitment,
        depth: SearchDepth,
    ) -> Option<B> {
        // Check buffer
        if let Some(block) = buffer.get(None, commitment, None).await.into_iter().next() {
            return Some(block);
        }

        // Check verified
        if let Some(block) = self.get_verified(Identifier::Key(&commitment)).await {
            return Some(block);
        }
        if depth < SearchDepth::Notarized {
            return None;
        }

        // Check notarized
        if let Some((_, block)) = self.get_notarization(Identifier::Key(&commitment)).await {
            return Some(block);
        }
        if depth < SearchDepth::Finalized {
            return None;
        }

        // Check blocks
        if let Some(block) = self.get_block(Identifier::Key(&commitment)).await {
            return Some(block);
        }

        // Not found
        None
    }

    /// Get a (finalized) block from the archive.
    async fn get_block<'a>(&'a self, id: Identifier<'a, B::Commitment>) -> Option<B> {
        match self.blocks.get(id).await {
            Ok(block) => block,
            Err(e) => panic!("Failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive.
    async fn get_finalization<'a>(
        &'a self,
        id: Identifier<'a, B::Commitment>,
    ) -> Option<Finalization<V, B::Commitment>> {
        match self.finalized.get(id).await {
            Ok(finalization) => finalization,
            Err(e) => panic!("Failed to get finalization: {e}"),
        }
    }

    /// Get a finalization from the archive by view.
    async fn get_finalization_by_view<'a>(
        &'a self,
        id: Identifier<'a, B::Commitment>,
    ) -> Option<Finalization<V, B::Commitment>> {
        match self.finalization_by_view.get(id).await {
            Ok(finalization) => finalization,
            Err(e) => panic!("Failed to get finalization by view: {e}"),
        }
    }

    /// Get a verified block from the archive.
    async fn get_verified<'a>(&'a self, id: Identifier<'a, B::Commitment>) -> Option<B> {
        match self.verified.get(id).await {
            Ok(verified) => verified,
            Err(e) => panic!("Failed to get verified block: {e}"),
        }
    }

    /// Get a notarization (with block) from the archive.
    async fn get_notarization<'a>(
        &'a self,
        id: Identifier<'a, B::Commitment>,
    ) -> Option<(Notarization<V, B::Commitment>, B)> {
        match self.notarized.get(id).await {
            Ok(notarization) => notarization,
            Err(e) => panic!("Failed to get notarization: {e}"),
        }
    }
}
