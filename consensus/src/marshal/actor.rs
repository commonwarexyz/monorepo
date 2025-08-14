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
    types::{Epoch, Round, View},
    Block, Reporter,
};
use commonware_broadcast::{buffered, Broadcaster};
use commonware_codec::{Codec, Decode, Encode, RangeCfg};
use commonware_cryptography::{bls12381::primitives::variant::Variant, PublicKey};
use commonware_macros::select;
use commonware_p2p::{utils::requester, Receiver, Recipients, Sender};
use commonware_resolver::{
    p2p::{self, Coordinator},
    Resolver,
};
use commonware_runtime::{buffer::PoolRef, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{self, immutable, prunable, Archive as _, Identifier},
    metadata::{self, Metadata},
    translator::TwoCap,
};
use commonware_utils::{
    futures::{AbortablePool, Aborter},
    sequence::FixedBytes,
};
use futures::{
    channel::{mpsc, oneshot},
    try_join, StreamExt,
};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    cmp::max,
    collections::{btree_map::Entry, BTreeMap},
    marker::PhantomData,
    num::{NonZero, NonZeroUsize},
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

// The key used to store the current epoch in the metadata store.
const CACHED_EPOCHS_KEY: FixedBytes<1> = FixedBytes::new([0u8]);

/// A struct that holds multiple subscriptions for a block.
struct BlockSubscription<B: Block> {
    // The subscribers that are waiting for the block
    subscribers: Vec<oneshot::Sender<B>>,
    // Aborter that aborts the waiter future when dropped
    _aborter: Aborter,
}

/// A struct that holds the configuration for the prunable archives.
struct PrunableCfg {
    partition_prefix: String,
    prunable_items_per_section: NonZero<u64>,
    replay_buffer: NonZeroUsize,
    write_buffer: NonZeroUsize,
    freezer_journal_buffer_pool: PoolRef,
}

/// A struct that holds the prunable archives for a single epoch.
struct Cache<R: Rng + Spawner + Metrics + Clock + GClock + Storage, B: Block, V: Variant> {
    /// Verified blocks stored by view
    verified_blocks: prunable::Archive<TwoCap, R, B::Commitment, B>,
    /// Notarized blocks stored by view. Stored separately from the verified blocks since they may
    /// be different (e.g. from an equivocation).
    notarized_blocks: prunable::Archive<TwoCap, R, B::Commitment, B>,
    /// Notarizations stored by view
    notarizations: prunable::Archive<TwoCap, R, B::Commitment, Notarization<V, B::Commitment>>,
    /// Finalizations stored by view
    finalizations: prunable::Archive<TwoCap, R, B::Commitment, Finalization<V, B::Commitment>>,
}

impl<R: Rng + Spawner + Metrics + Clock + GClock + Storage, B: Block, V: Variant> Cache<R, B, V> {
    /// Prune the archives for the given view.
    async fn prune(&mut self, min_view: View) {
        match try_join!(
            self.verified_blocks.prune(min_view),
            self.notarized_blocks.prune(min_view),
            self.notarizations.prune(min_view),
            self.finalizations.prune(min_view),
        ) {
            Ok(_) => debug!(min_view, "pruned archives"),
            Err(e) => panic!("failed to prune archives: {e}"),
        }
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
    // Partition configuration
    prunable_config: PrunableCfg,

    // ---------- State ----------
    // Last view processed
    last_processed_round: Round,

    // Outstanding subscriptions for blocks
    block_subscriptions: BTreeMap<B::Commitment, BlockSubscription<B>>,

    // ---------- Metadata ----------
    // Last indexed height
    metadata: Metadata<R, FixedBytes<1>, Vec<Epoch>>,

    // ---------- Prunable Storage ----------
    // Prunable archives by epoch
    cache: BTreeMap<Epoch, Cache<R, B, V>>,

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
        // Initialize metadata
        let metadata = Metadata::init(
            context.with_label("metadata"),
            metadata::Config {
                partition: format!("{}-metadata", config.partition_prefix),
                codec_config: (RangeCfg::from(..), ()),
            },
        )
        .await
        .expect("failed to initialize metadata");

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
                freezer_journal_buffer_pool: config.freezer_journal_buffer_pool.clone(),
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
                prunable_config: PrunableCfg {
                    partition_prefix: config.partition_prefix,
                    prunable_items_per_section: config.prunable_items_per_section,
                    replay_buffer: config.replay_buffer,
                    write_buffer: config.write_buffer,
                    freezer_journal_buffer_pool: config.freezer_journal_buffer_pool,
                },

                last_processed_round: Round::new(0, 0),
                block_subscriptions: BTreeMap::new(),

                cache: BTreeMap::new(),

                finalizations_by_height,
                finalized_blocks,

                metadata,

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
        // Initialize caches from metadata
        self.init_caches_from_metadata().await;

        // Initialize resolvers
        let (mut resolver_rx, mut resolver) = self.init_resolver(backfill);

        // Process all finalized blocks in order (fetching any that are missing)
        let (mut notifier_tx, notifier_rx) = mpsc::channel::<()>(1);
        let (orchestrator_sender, mut orchestrator_receiver) = mpsc::channel(self.mailbox_size);
        let orchestrator = Orchestrator::new(orchestrator_sender);
        let finalizer = Finalizer::new(
            self.context.with_label("finalizer"),
            format!("{}-finalizer", self.prunable_config.partition_prefix),
            application,
            orchestrator,
            notifier_rx,
        )
        .await;
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
                            let _peers = buffer.broadcast(Recipients::All, block).await;
                        }
                        Message::Verified { round, block } => {
                            self.cache_verified(round, block.commitment(), block).await;
                        }
                        Message::Notarization { notarization } => {
                            let round = notarization.round();
                            let commitment = notarization.proposal.payload;

                            // Store notarization by view
                            self.cache_notarization(round, commitment, notarization.clone()).await;

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
                            self.cache_finalization(round, commitment, finalization.clone()).await;

                            // Search for block locally, otherwise fetch it remotely
                            if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                // If found, persist the block
                                let height = block.height();
                                self.finalize(height, commitment, block, Some(finalization), &mut notifier_tx).await;
                                debug!(?round, height, "finalized block stored");
                            } else {
                                // Otherwise, fetch the block from the network.
                                debug!(?round, ?commitment, "finalized block missing");
                                resolver.fetch(Request::<B>::Block(commitment)).await;
                            }
                        }
                        Message::Get { commitment, response } => {
                            // Check for block locally
                            let result = self.find_block(&mut buffer, commitment).await;
                            let _ = response.send(result);
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
                                    continue;
                                }
                                // Fetch from network
                                //
                                // If this is a valid view, this request should be fine to "keep
                                // open" even if the oneshot is cancelled.
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
                // Handle finalizer messages next
                message = orchestrator_receiver.next() => {
                    let Some(message) = message else {
                        info!("orchestrator closed, shutting down");
                        return;
                    };
                    match message {
                        Orchestration::Get { height, result } => {
                            // Check if in blocks
                            let block = self.get_finalized_block(height).await;
                            result.send(block).unwrap_or_else(|_| warn!(?height, "Failed to send block to orchestrator"));
                        }
                        Orchestration::Processed { height, digest } => {
                            // Update metrics
                            self.processed_height.set(height as i64);

                            // Cancel any outstanding requests (by height and by digest)
                            resolver.cancel(Request::<B>::Block(digest)).await;
                            resolver.retain(Request::<B>::Finalized { height }.predicate()).await;

                            // If finalization exists, prune the archives
                            if let Some(finalization) = self.get_finalization_by_height(height).await {
                                // Trail the previous processed finalized block by the timeout
                                let lpr = self.last_processed_round;
                                let prune_round = Round::new(lpr.epoch(), lpr.view().saturating_sub(self.view_retention_timeout));

                                // Prune archives
                                self.prune(prune_round).await;

                                // Update the last processed round
                                let round = finalization.round();
                                self.last_processed_round = round;

                                // Cancel useless requests
                                resolver.retain(Request::<B>::Notarized { round }.predicate()).await;
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
                            let Some(mut cursor) = self.get_finalized_block(gap_end).await else {
                                panic!("gapped block missing that should exist: {gap_end}");
                            };

                            // Iterate backwards, repairing blocks as we go.
                            while cursor.height() > height {
                                let commitment = cursor.parent();
                                if let Some(block) = self.find_block(&mut buffer, commitment).await {
                                    let finalization = self.get_cached_finalization(commitment).await;
                                    self.finalize(block.height(), commitment, block.clone(), finalization, &mut notifier_tx).await;
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
                                    let Some(notarization) = self.get_notarization(round).await else {
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
                                    let finalization = self.get_cached_finalization(commitment).await;
                                    self.finalize(height, commitment, block, finalization, &mut notifier_tx).await;
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
                                    self.finalize(height, block.commitment(), block, Some(finalization), &mut notifier_tx).await;
                                },
                                Request::Notarized { round } => {
                                    // Parse notarization
                                    let Ok((notarization, block)) = <(Notarization<V, B::Commitment>, B)>::decode_cfg(value, &((), self.codec_config.clone())) else {
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Validation
                                    if notarization.round() != round
                                        || notarization.proposal.payload != block.commitment()
                                        || !notarization.verify(&self.namespace, &self.identity)
                                    {
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Valid notarization received
                                    let _ = response.send(true);
                                    let commitment = block.commitment();
                                    debug!(?round, ?commitment, "received notarization");

                                    // If there's a finalization for this view, we should process it
                                    let height = block.height();
                                    if let Some(finalization) = self.get_cached_finalization(commitment).await {
                                        self.finalize(height, commitment, block.clone(), Some(finalization), &mut notifier_tx).await;
                                    }

                                    // Cache the notarization and block
                                    self.cache_block(round, commitment, block).await;
                                    self.cache_notarization(round, commitment, notarization).await;
                                },
                            }
                        },
                    }
                },
            }
        }
    }

    // -------------------- Initialization --------------------

    /// Restore caches deterministically from metadata at startup.
    ///
    /// Invariant: if metadata lists an epoch, initializing that epoch is idempotent and safe
    /// to retry after a crash.
    async fn init_caches_from_metadata(&mut self) {
        let cached_epochs = self
            .metadata
            .get(&CACHED_EPOCHS_KEY)
            .cloned()
            .unwrap_or(vec![0]);
        for epoch in cached_epochs {
            self.init_cache(epoch).await;
        }
    }

    /// Persist the currently-open cache epochs to metadata.
    ///
    /// Optionally, add a key to the set of cached epochs if it's about to be initialized.
    async fn persist_cached_epochs(&mut self, add_key: Option<Epoch>) {
        let mut keys = self.cache.keys().copied().collect::<Vec<_>>();
        if let Some(key) = add_key {
            keys.push(key);
        }
        keys.sort();
        self.metadata
            .put_sync(CACHED_EPOCHS_KEY, keys)
            .await
            .expect("failed to write metadata");
    }

    /// Get the cache for the given epoch, initializing it if it doesn't exist.
    ///
    /// If the epoch is less than the minimum cached epoch, then it has already been pruned,
    /// and this will return `None`.
    async fn get_or_init_cache(&mut self, epoch: Epoch) -> Option<&mut Cache<R, B, V>> {
        // If the cache exists, return it
        if self.cache.contains_key(&epoch) {
            return self.cache.get_mut(&epoch);
        }

        // If the epoch is less than the minimum cached epoch, then it has already been pruned
        let min_epoch = self
            .cache
            .first_key_value()
            .map(|(epoch, _)| *epoch)
            .unwrap_or(0);
        if epoch < min_epoch {
            return None;
        };

        // Update the metadata (metadata-first is safe; init is idempotent)
        self.persist_cached_epochs(Some(epoch)).await;

        // Initialize and return the epoch
        self.init_cache(epoch).await;
        self.cache.get_mut(&epoch) // Should always be Some
    }

    /// Helper to initialize the cache for a given epoch.
    async fn init_cache(&mut self, epoch: Epoch) {
        let verified_blocks = Self::init_prunable_archive(
            &self.context,
            &self.prunable_config,
            epoch,
            "verified_blocks_cache",
            self.codec_config.clone(),
        )
        .await;
        let notarized_blocks = Self::init_prunable_archive(
            &self.context,
            &self.prunable_config,
            epoch,
            "notarized_blocks_cache",
            self.codec_config.clone(),
        )
        .await;
        let notarizations = Self::init_prunable_archive(
            &self.context,
            &self.prunable_config,
            epoch,
            "notarizations_cache",
            (),
        )
        .await;
        let finalizations = Self::init_prunable_archive(
            &self.context,
            &self.prunable_config,
            epoch,
            "finalizations_cache",
            (),
        )
        .await;
        let existing = self.cache.insert(
            epoch,
            Cache {
                verified_blocks,
                notarized_blocks,
                notarizations,
                finalizations,
            },
        );
        assert!(existing.is_none(), "cache already exists for epoch {epoch}");
    }

    /// Helper to initialize an archive.
    async fn init_prunable_archive<T: Codec>(
        context: &R,
        config: &PrunableCfg,
        epoch: Epoch,
        name: &str,
        codec_config: T::Cfg,
    ) -> prunable::Archive<TwoCap, R, B::Commitment, T> {
        let start = Instant::now();
        let prunable_config = prunable::Config {
            partition: format!("{}-{name}-{epoch}", config.partition_prefix),
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

    // -------------------- Prunable Storage --------------------

    /// Add a verified block to the prunable archive.
    async fn cache_verified(&mut self, round: Round, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block).await;

        let Some(cache) = self.get_or_init_cache(round.epoch()).await else {
            return;
        };

        let result = cache
            .verified_blocks
            .put_sync(round.view(), commitment, block)
            .await;
        Self::debug_cache(result, round, "verified");
    }

    /// Add a notarized block to the prunable archive.
    async fn cache_block(&mut self, round: Round, commitment: B::Commitment, block: B) {
        self.notify_subscribers(commitment, &block).await;

        let Some(cache) = self.get_or_init_cache(round.epoch()).await else {
            return;
        };

        let result = cache
            .notarized_blocks
            .put_sync(round.view(), commitment, block)
            .await;
        Self::debug_cache(result, round, "notarized");
    }

    /// Add a notarization to the prunable archive.
    async fn cache_notarization(
        &mut self,
        round: Round,
        commitment: B::Commitment,
        notarization: Notarization<V, B::Commitment>,
    ) {
        let Some(cache) = self.get_or_init_cache(round.epoch()).await else {
            return;
        };

        let result = cache
            .notarizations
            .put_sync(round.view(), commitment, notarization)
            .await;
        Self::debug_cache(result, round, "notarization");
    }

    /// Add a finalization to the prunable archive.
    async fn cache_finalization(
        &mut self,
        round: Round,
        commitment: B::Commitment,
        finalization: Finalization<V, B::Commitment>,
    ) {
        let Some(cache) = self.get_or_init_cache(round.epoch()).await else {
            return;
        };

        let result = cache
            .finalizations
            .put_sync(round.view(), commitment, finalization)
            .await;
        Self::debug_cache(result, round, "finalization");
    }

    /// Helper to debug cache results.
    fn debug_cache(result: Result<(), archive::Error>, round: Round, name: &str) {
        match result {
            Ok(_) => {
                debug!(?round, "{} cached", name);
            }
            Err(archive::Error::AlreadyPrunedTo(_)) => {
                debug!(?round, "{} already pruned", name);
            }
            Err(e) => {
                panic!("failed to insert {name}: {e}");
            }
        }
    }

    /// Get a notarization from the prunable archive by round.
    async fn get_notarization(&self, round: Round) -> Option<Notarization<V, B::Commitment>> {
        let cache = self.cache.get(&round.epoch())?;
        cache
            .notarizations
            .get(Identifier::Index(round.view()))
            .await
            .expect("failed to get notarization")
    }

    /// Get a finalization from the prunable archive by commitment.
    async fn get_cached_finalization(
        &self,
        commitment: B::Commitment,
    ) -> Option<Finalization<V, B::Commitment>> {
        for cache in self.cache.values().rev() {
            match cache.finalizations.get(Identifier::Key(&commitment)).await {
                Ok(Some(finalization)) => return Some(finalization),
                Ok(None) => continue,
                Err(e) => panic!("failed to get cached finalization: {e}"),
            }
        }
        None
    }

    /// Prune the caches below the given round.
    async fn prune(&mut self, round: Round) {
        // Remove and close prunable archives from older epochs
        let old_epochs: Vec<Epoch> = self
            .cache
            .keys()
            .copied()
            .filter(|epoch| *epoch < round.epoch())
            .collect();
        for epoch in old_epochs.iter() {
            let Cache::<R, B, V> {
                verified_blocks: vb,
                notarized_blocks: nb,
                notarizations: nv,
                finalizations: fv,
            } = self.cache.remove(epoch).unwrap();
            vb.close().await.expect("failed to destroy vb");
            nb.close().await.expect("failed to destroy nb");
            nv.close().await.expect("failed to destroy nv");
            fv.close().await.expect("failed to destroy fv");
        }
        if !old_epochs.is_empty() {
            self.persist_cached_epochs(None).await;
        }

        // Prune archives for the given epoch
        let min_view = round.view();
        if let Some(prunable) = self.cache.get_mut(&round.epoch()) {
            prunable.prune(min_view).await;
        }
    }

    // -------------------- Immutable Storage --------------------

    /// Get a finalized block from the immutable archive.
    async fn get_finalized_block(&self, height: u64) -> Option<B> {
        match self.finalized_blocks.get(Identifier::Index(height)).await {
            Ok(block) => block,
            Err(e) => panic!("failed to get block: {e}"),
        }
    }

    /// Get a finalization from the archive by height.
    async fn get_finalization_by_height(
        &self,
        height: u64,
    ) -> Option<Finalization<V, B::Commitment>> {
        match self
            .finalizations_by_height
            .get(Identifier::Index(height))
            .await
        {
            Ok(finalization) => finalization,
            Err(e) => panic!("failed to get finalization: {e}"),
        }
    }

    /// Add a finalized block, and optionally a finalization, to the archive.
    ///
    /// At the end of the method, the notifier is notified to indicate that there has been an update
    /// to the archive of finalized blocks.
    async fn finalize(
        &mut self,
        height: u64,
        commitment: B::Commitment,
        block: B,
        finalization: Option<Finalization<V, B::Commitment>>,
        notifier: &mut mpsc::Sender<()>,
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

        // Update metrics
        let new_value: i64 = height as i64;
        let old_value: i64 = self.finalized_height.get();
        self.finalized_height.set(max(new_value, old_value));

        // Notify the finalizer
        let _ = notifier.try_send(());
    }

    // -------------------- Mixed Storage --------------------

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
        // Check verified / notarized blocks.
        // Reverse order of epochs to check the most recent blocks first.
        for cache in self.cache.values().rev() {
            if let Some(block) = cache
                .verified_blocks
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get verified block")
            {
                return Some(block);
            }
            if let Some(block) = cache
                .notarized_blocks
                .get(Identifier::Key(&commitment))
                .await
                .expect("failed to get notarized block")
            {
                return Some(block);
            }
        }
        // Check finalized blocks.
        match self
            .finalized_blocks
            .get(Identifier::Key(&commitment))
            .await
        {
            Ok(block) => block, // may be None
            Err(e) => panic!("failed to get block: {e}"),
        }
    }
}
