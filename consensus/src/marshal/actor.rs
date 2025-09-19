use super::{
    config::Config,
    finalizer::Finalizer,
    ingress::{
        handler::{self, Handler, Request},
        mailbox::{Mailbox, Message},
        orchestrator::{Orchestration, Orchestrator},
    },
};
use crate::{
    threshold_simplex::types::{Finalization, Notarization},
    Block, Reporter,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{Codec, Decode, Encode};
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
use commonware_utils::futures::{AbortablePool, Aborter};
use futures::{
    channel::{mpsc, oneshot},
    try_join, StreamExt,
};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    collections::{btree_map::Entry, BTreeMap},
    marker::PhantomData,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

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
    /// Minimum number of views to retain temporary data after the application processes a block
    view_retention_timeout: u64,
    // Maximum number of blocks to repair at once
    max_repair: u64,
    // Codec configuration
    codec_config: B::Cfg,
    // Partition prefix
    partition_prefix: String,

    // ---------- State ----------
    // Last view processed
    last_processed_view: u64,

    // Outstanding subscriptions for blocks
    block_subscriptions: BTreeMap<B::Commitment, BlockSubscription<B>>,

    // ---------- Prunable Storage ----------
    // Verified blocks stored by view
    verified_blocks: prunable::Archive<TwoCap, R, B::Commitment, B>,
    // Notarized blocks stored by view. Stored separately from the verified blocks since they may
    // be different (e.g. from an equivocation).
    notarized_blocks: prunable::Archive<TwoCap, R, B::Commitment, B>,
    // Notarizations stored by view
    notarizations_by_view:
        prunable::Archive<TwoCap, R, B::Commitment, Notarization<V, B::Commitment>>,
    // Finalizations stored by view
    finalizations_by_view:
        prunable::Archive<TwoCap, R, B::Commitment, Finalization<V, B::Commitment>>,

    // ---------- Immutable Storage ----------
    // Finalizations stored by height
    finalizations_by_height: immutable::Archive<R, B::Commitment, Finalization<V, B::Commitment>>,
    // Finalized blocks stored by height
    finalized_blocks: immutable::Archive<R, B::Commitment, B>,

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
        // Initialize prunable
        let verified_blocks = Self::init_prunable_archive(
            &context,
            "verified_blocks",
            &config,
            config.codec_config.clone(),
        )
        .await;
        let notarized_blocks = Self::init_prunable_archive(
            &context,
            "notarized_blocks",
            &config,
            config.codec_config.clone(),
        )
        .await;
        let notarizations_by_view =
            Self::init_prunable_archive(&context, "notarizations_by_view", &config, ()).await;
        let finalizations_by_view =
            Self::init_prunable_archive(&context, "finalizations_by_view", &config, ()).await;

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
                codec_config: (),
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
                codec_config: config.codec_config.clone(),
                replay_buffer: config.replay_buffer,
                write_buffer: config.write_buffer,
            },
        )
        .await
        .expect("failed to initialize finalized blocks archive");
        info!(elapsed = ?start.elapsed(), "restored finalized blocks archive");

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
                view_retention_timeout: config.view_retention_timeout,
                max_repair: config.max_repair,
                codec_config: config.codec_config.clone(),
                partition_prefix: config.partition_prefix,

                last_processed_view: 0,
                block_subscriptions: BTreeMap::new(),

                verified_blocks,
                notarized_blocks,
                notarizations_by_view,
                finalizations_by_view,
                finalizations_by_height,
                finalized_blocks,

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
        backfill: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> Handle<()> {
        self.context.spawn_ref()(self.run(application, buffer, backfill))
    }

    /// Run the application actor.
    async fn run(
        mut self,
        application: impl Reporter<Activity = B>,
        mut buffer: buffered::Mailbox<P, B>,
        backfill: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) {
        // Initialize resolvers
        let (mut resolver_rx, mut resolver) = self.init_resolver(backfill);

        // Process all finalized blocks in order (fetching any that are missing)
        let (mut notifier_tx, notifier_rx) = mpsc::channel::<()>(1);
        let (orchestrator_sender, mut orchestrator_receiver) = mpsc::channel(self.mailbox_size);
        let orchestrator = Orchestrator::new(orchestrator_sender);
        let (finalizer, latest_processed) = Finalizer::new(
            self.context.with_label("finalizer"),
            self.partition_prefix.clone(),
            application,
            orchestrator,
            notifier_rx,
        )
        .await;
        self.processed_height.set(latest_processed as i64);
        self.context
            .with_label("finalizer")
            .spawn(|_| finalizer.run());

        // Create a local pool for waiter futures
        let mut waiters = AbortablePool::<(B::Commitment, B)>::default();

        // Handle messages
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
                // Handle consensus before finalizer or backfiller
                mailbox_message = self.mailbox.next() => {
                    let Some(message) = mailbox_message else {
                        info!("mailbox closed, shutting down");
                        return;
                    };
                    match message {
                        Message::Broadcast { block } => {
                            let ack = buffer.broadcast(Recipients::All, block).await;
                            drop(ack);
                        }
                        Message::Verified { view, block } => {
                            self.put_verified_block(view, block.commitment(), block).await;
                        }
                        Message::Notarization { notarization } => {
                            let view = notarization.proposal.view;
                            let commitment = notarization.proposal.payload;

                            // Store notarization by view
                            self.put_notarization_by_view(view, commitment, notarization.clone()).await;

                            // Search for block locally, otherwise fetch it remotely
                            if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                // If found, persist the block
                                self.put_notarized_block(view, commitment, block).await;
                                continue;
                            } else {
                                debug!(view, "notarized block missing");
                                resolver.fetch(Request::<B>::Notarized { view }).await;
                            }
                        }
                        Message::Finalization { finalization } => {
                            // Store finalization by view
                            let view = finalization.proposal.view;
                            let commitment = finalization.proposal.payload;
                            self.put_finalization_by_view(view, commitment, finalization.clone()).await;

                            // Search for block locally, otherwise fetch it remotely
                            if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                // If found, persist the block
                                let height = block.height();
                                self.put_finalized_block(height, commitment, block, &mut notifier_tx).await;
                                debug!(view, height, "finalized block stored");
                                self.finalized_height.set(height as i64);

                                // Cancel useless requests
                                resolver.retain(Request::<B>::Notarized { view }.predicate()).await;
                            } else {
                                // Otherwise, fetch the block from the network
                                debug!(view, ?commitment, "finalized block missing");
                                resolver.fetch(Request::<B>::Block(commitment)).await;
                            }
                        }
                        Message::Get { commitment, response } => {
                            // Check for block locally
                            let result = self.find_block(&mut buffer, commitment).await;
                            let _ = response.send(result);
                        }
                        Message::GetBlockByHeight { height, response } => {
                            let block = self.get_finalized_block(Identifier::Index(height)).await;
                            let _ = response.send(block);
                        }
                        Message::GetFinalized { response } => {
                            // TODO: make this genesis rather than none
                            let height = self.finalized_blocks.last_index().unwrap_or(0);
                            if height == 0 {
                                let _ = response.send(None);
                                println!("no finalizations by height");
                                continue;
                            }

                            // TODO: make this faster
                            let block = self.finalized_blocks.get(Identifier::Index(height)).await.unwrap().unwrap();
                            let _ = response.send(Some((height, block.commitment())));
                        }
                        Message::GetProcessedHeight { response } => {
                            let height = self.processed_height.get();
                            let _ = response.send(height as u64);
                        }
                        Message::Subscribe { view, commitment, response } => {
                            // Check for block locally
                            if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                let _ = response.send(block);
                                continue;
                            }

                            // We don't have the block locally, so fetch the block from the network
                            // if we have an associated view. If we only have the digest, don't make
                            // the request as we wouldn't know when to drop it, and the request may
                            // never complete if the block is not finalized.
                            if let Some(view) = view {
                                // Fetch from network
                                //
                                // If this is a valid view, this request should be fine to "keep
                                // open" even if the oneshot is cancelled.
                                debug!(view, ?commitment, "requested block missing");
                                resolver.fetch(Request::<B>::Notarized { view }).await;
                            }

                            // Register subscriber
                            debug!(view, ?commitment, "registering subscriber");
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
                // Handle finalizer messages next
                message = orchestrator_receiver.next() => {
                    let Some(message) = message else {
                        info!("orchestrator closed, shutting down");
                        return;
                    };
                    match message {
                        Orchestration::Get { height, result } => {
                            // Check if in blocks
                            let block = self.get_finalized_block(Identifier::Index(height)).await;
                            result.send(block).unwrap_or_else(|_| warn!(?height, "Failed to send block to orchestrator"));
                        }
                        Orchestration::Processed { height, digest } => {
                            // Update metrics
                            self.processed_height.set(height as i64);

                            // Cancel any outstanding requests (by height and by digest)
                            resolver.cancel(Request::<B>::Block(digest)).await;
                            resolver.retain(Request::<B>::Finalized { height }.predicate()).await;

                            // If finalization exists, prune the archives
                            if let Some(finalization) = self.get_finalization_by_height(Identifier::Index(height)).await {
                                // Trail the previous processed finalized block by the timeout
                                let min_view = self.last_processed_view.saturating_sub(self.view_retention_timeout);

                                // Prune archives
                                match try_join!(
                                    self.verified_blocks.prune(min_view),
                                    self.notarized_blocks.prune(min_view),
                                    self.notarizations_by_view.prune(min_view),
                                    self.finalizations_by_view.prune(min_view),
                                ) {
                                    Ok(_) => debug!(min_view, "pruned archives"),
                                    Err(e) => panic!("failed to prune archives: {e}"),
                                }

                                // Update the last processed height and view
                                self.last_processed_view = finalization.proposal.view;
                            }
                        }
                        Orchestration::Repair { height } => {
                            // Find the end of the "gap" of missing blocks, starting at `height`
                            let (_, Some(gap_end)) = self.finalized_blocks.next_gap(height) else {
                                // No gap found; height-1 is the last known finalized block
                                continue;
                            };
                            assert!(gap_end > height, "gap end must be greater than height");

                            // Attempt to repair the gap backwards from the end of the gap, using
                            // blocks from our local storage.
                            let Some(mut cursor) = self.get_finalized_block(Identifier::Index(gap_end)).await else {
                                panic!("gapped block missing that should exist: {gap_end}");
                            };

                            // Iterate backwards, repairing blocks as we go.
                            while cursor.height() > height {
                                let commitment = cursor.parent();
                                if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                    self.put_finalized_block(block.height(), commitment, block.clone(), &mut notifier_tx).await;
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
                            let gap_start = height;
                            let gap_end = std::cmp::min(cursor.height(), gap_start.saturating_add(self.max_repair));
                            debug!(gap_start, gap_end, "requesting any finalized blocks");
                            for height in gap_start..gap_end {
                                resolver.fetch(Request::<B>::Finalized { height }).await;
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
                                    let Some(finalization) = self.get_finalization_by_height(Identifier::Index(height)).await else {
                                        debug!(height, "finalization missing on request");
                                        continue;
                                    };

                                    // Get block
                                    let Some(block) = self.get_finalized_block(Identifier::Index(height)).await else {
                                        debug!(height, "finalized block missing on request");
                                        continue;
                                    };

                                    // Send finalization
                                    let _ = response.send((finalization, block).encode().into());
                                }
                                Request::Notarized { view } => {
                                    // Get notarization
                                    let Some(notarization) = self.get_notarization_by_view(Identifier::Index(view)).await else {
                                        debug!(view, "notarization missing on request");
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
                                    if let Some(finalization) = self.get_finalization_from_view(Identifier::Key(&commitment)).await {
                                        self.put_finalization_and_finalized_block(height, commitment, finalization, block, &mut notifier_tx).await;
                                    } else {
                                        self.put_finalized_block(height, commitment, block, &mut notifier_tx).await;
                                    }
                                    debug!(?commitment, height, "received block");
                                    let _ = response.send(true);
                                },
                                Request::Finalized { height } => {
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
                                    self.put_finalization_and_finalized_block(height, block.commitment(), finalization, block, &mut notifier_tx).await;
                                },
                                Request::Notarized { view } => {
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
                                    let commitment = block.commitment();
                                    debug!(view, ?commitment, "received notarization");
                                    self.put_notarized_block(view, commitment, block).await;
                                    self.put_notarization_by_view(view, commitment, notarization).await;
                                    let _ = response.send(true);
                                },
                            }
                        },
                    }
                },
            }
        }
    }

    // -------------------- Initialization --------------------

    /// Helper to initialize an archive.
    async fn init_prunable_archive<T: Codec>(
        context: &R,
        name: &str,
        config: &Config<V, P, Z, B>,
        codec_config: T::Cfg,
    ) -> prunable::Archive<TwoCap, R, B::Commitment, T> {
        let start = Instant::now();
        let prunable_config = prunable::Config {
            partition: format!("{}-{name}", config.partition_prefix),
            translator: TwoCap,
            items_per_section: config.prunable_items_per_section,
            compression: None,
            codec_config,
            buffer_pool: config.freezer_journal_buffer_pool.clone(),
            replay_buffer: config.replay_buffer,
            write_buffer: config.write_buffer,
        };
        let archive = prunable::Archive::init(context.with_label(name), prunable_config)
            .await
            .unwrap_or_else(|_| panic!("failed to initialize {name} archive"));
        info!(elapsed = ?start.elapsed(), "restored {name} archive");
        archive
    }

    /// Helper to initialize a resolver.
    fn init_resolver(
        &self,
        backfill: (impl Sender<PublicKey = P>, impl Receiver<PublicKey = P>),
    ) -> (
        mpsc::Receiver<handler::Message<B>>,
        p2p::Mailbox<Request<B>>,
    ) {
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

    // -------------------- Waiters --------------------

    /// Notify any subscribers for the given commitment with the provided block.
    async fn notify_subscribers(&mut self, commitment: B::Commitment, block: &B) {
        if let Some(mut bs) = self.block_subscriptions.remove(&commitment) {
            for subscriber in bs.subscribers.drain(..) {
                let _ = subscriber.send(block.clone());
            }
        }
    }

    // -------------------- Storage --------------------

    /// Add a verified block to the archive.
    async fn put_verified_block(&mut self, view: u64, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block).await;

        match self.verified_blocks.put_sync(view, commitment, block).await {
            Ok(_) => {
                debug!(view, "verified stored");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(view, "verified already pruned");
            }
            Err(e) => {
                panic!("failed to insert verified block: {e}");
            }
        }
    }

    /// Add a notarization to the archive by view.
    async fn put_notarization_by_view(
        &mut self,
        view: u64,
        commitment: B::Commitment,
        notarization: Notarization<V, B::Commitment>,
    ) {
        match self
            .notarizations_by_view
            .put_sync(view, commitment, notarization)
            .await
        {
            Ok(_) => {
                debug!(view, "notarization by view stored");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(view, "notarization by view already pruned");
            }
            Err(e) => {
                panic!("failed to insert notarization by view: {e}");
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
            .finalizations_by_view
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
                panic!("failed to insert finalization by view: {e}");
            }
        }
    }

    /// Add a notarized block to the archive.
    async fn put_notarized_block(&mut self, view: u64, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block).await;

        match self
            .notarized_blocks
            .put_sync(view, commitment, block)
            .await
        {
            Ok(_) => {
                debug!(view, "notarized stored");
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(view, "notarized already pruned");
            }
            Err(e) => {
                panic!("failed to insert notarization: {e}");
            }
        }
    }

    /// Add a finalized block to the archive.
    ///
    /// At the end of the method, the notifier is notified to indicate that there has been an update
    /// to the archive of finalized blocks.
    async fn put_finalized_block(
        &mut self,
        height: u64,
        commitment: B::Commitment,
        block: B,
        notifier: &mut mpsc::Sender<()>,
    ) {
        self.notify_subscribers(commitment, &block).await;

        if let Err(e) = self
            .finalized_blocks
            .put_sync(height, commitment, block)
            .await
        {
            panic!("failed to insert block: {e}");
        }
        let _ = notifier.try_send(());
    }

    /// Add a finalization and finalized block to the archive.
    async fn put_finalization_and_finalized_block(
        &mut self,
        height: u64,
        commitment: B::Commitment,
        finalization: Finalization<V, B::Commitment>,
        block: B,
        notifier: &mut mpsc::Sender<()>,
    ) {
        self.notify_subscribers(commitment, &block).await;

        if let Err(e) = try_join!(
            self.finalizations_by_height
                .put_sync(height, commitment, finalization),
            self.finalized_blocks.put_sync(height, commitment, block),
        ) {
            panic!("failed to insert finalization: {e}");
        }
        let _ = notifier.try_send(());
    }

    /// Looks for a block anywhere in local storage.
    async fn find_block(
        &mut self,
        buffer: &mut buffered::Mailbox<P, B>,
        commitment: B::Commitment,
    ) -> Option<B> {
        // Check buffer.
        if let Some(block) = buffer.get(None, commitment, None).await.into_iter().next() {
            return Some(block);
        }
        // Check verified.
        if let Some(block) = self.get_verified_block(Identifier::Key(&commitment)).await {
            return Some(block);
        }
        // Check notarized blocks.
        if let Some(block) = self.get_notarized_block(Identifier::Key(&commitment)).await {
            return Some(block);
        }
        // Check finalized blocks.
        if let Some(block) = self.get_finalized_block(Identifier::Key(&commitment)).await {
            return Some(block);
        }
        None
    }

    /// Get a finalized block from the archive.
    async fn get_finalized_block(&self, id: Identifier<'_, B::Commitment>) -> Option<B> {
        match self.finalized_blocks.get(id).await {
            Ok(block) => block,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    async fn get_finalization_by_height(
        &self,
        id: Identifier<'_, B::Commitment>,
    ) -> Option<Finalization<V, B::Commitment>> {
        match self.finalizations_by_height.get(id).await {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Get a notarization from the archive by view.
    async fn get_notarization_by_view(
        &self,
        id: Identifier<'_, B::Commitment>,
    ) -> Option<Notarization<V, B::Commitment>> {
        match self.notarizations_by_view.get(id).await {
            Ok(notarization) => notarization,
            Err(e) => panic!("failed to get notarization by view: {e}"),
        }
    }

    /// Get a finalization from the archive by view.
    async fn get_finalization_from_view(
        &self,
        id: Identifier<'_, B::Commitment>,
    ) -> Option<Finalization<V, B::Commitment>> {
        match self.finalizations_by_view.get(id).await {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization by view: {e}"),
        }
    }

    /// Get a verified block from the archive.
    async fn get_verified_block(&self, id: Identifier<'_, B::Commitment>) -> Option<B> {
        match self.verified_blocks.get(id).await {
            Ok(verified) => verified,
            Err(e) => panic!("failed to get verified block: {e}"),
        }
    }

    /// Get a notarized block from the archive.
    async fn get_notarized_block(&self, id: Identifier<'_, B::Commitment>) -> Option<B> {
        match self.notarized_blocks.get(id).await {
            Ok(block) => block,
            Err(e) => panic!("failed to get notarized block: {e}"),
        }
    }
}
