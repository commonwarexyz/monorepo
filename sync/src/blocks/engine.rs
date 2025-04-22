use super::{
    archive::Wrapped,
    handler::Handler,
    ingress::{Mailbox, Message},
    key::{MultiIndex, Value},
    Config, Indexer,
};
use alto_types::{Block, Finalization, Finalized, Notarized};
use commonware_broadcast::buffered::{
    Config as BroadcastConfig, Engine as BroadcastEngine, Mailbox as BroadcastMailbox,
};
use commonware_codec::Config as CodecCfg;
use commonware_cryptography::{bls12381, ed25519::PublicKey, sha256::Digest};
use commonware_macros::select;
use commonware_p2p::{utils::requester, Receiver, Sender};
use commonware_resolver::{
    p2p::{self, Coordinator},
    Resolver,
};
use commonware_runtime::{Blob, Clock, Handle, Metrics, Spawner, Storage};
use commonware_storage::{
    archive::{self, Archive, Identifier},
    index::translator::{EightCap, TwoCap},
    journal::{self, variable::Journal},
    metadata::{self, Metadata},
};
use commonware_utils::{array::FixedBytes, Array};
use futures::{
    channel::{mpsc, oneshot},
    lock::Mutex,
    StreamExt,
};
use governor::{clock::Clock as GClock, Quota};
use prometheus_client::metrics::gauge::Gauge;
use rand::Rng;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};
use tracing::{debug, info};

/// Application Engine.
pub struct Engine<
    P: Array,
    B: Blob,
    R: Rng + Spawner + Metrics + Clock + GClock + Storage<Blob = B>,
    I: Indexer,
    D: Coordinator<PublicKey = P>,
    C: CodecCfg,
> {
    context: R,
    public_key: PublicKey,
    public: bls12381::PublicKey,
    mailbox: mpsc::Receiver<Message>,
    mailbox_size: usize,
    backfill_quota: Quota,
    activity_timeout: u64,
    indexer: Option<I>,

    // Blocks verified stored by view<>digest
    verified: Archive<TwoCap, Digest, R>,
    // Blocks notarized stored by view<>digest
    notarized: Archive<TwoCap, Digest, R>,

    // Finalizations stored by height
    finalized: Archive<EightCap, Digest, R>,
    // Blocks finalized stored by height
    //
    // We store this separately because we may not have the finalization for a block
    blocks: Archive<EightCap, Digest, R>,

    // Finalizer storage
    finalizer: Metadata<B, R, FixedBytes>,

    coordinator: D,

    // Latest height metric
    finalized_height: Gauge,
    // Indexed height metric
    contiguous_height: Gauge,

    // Broadcast
    broadcast_mailbox: BroadcastMailbox<Digest, Block>,
    broadcast_decode_config: C,
}

impl<
        P: Array,
        B: Blob,
        R: Rng + Spawner + Metrics + Clock + GClock + Storage<Blob = B>,
        I: Indexer,
        D: Coordinator<PublicKey = P>,
        C: CodecCfg,
    > Actor<P, B, R, I, D, C>
{
    /// Create a new application engine.
    pub async fn init(
        context: R,
        config: Config<I, D>,
        broadcast_decode_config: C,
    ) -> (Self, Mailbox, BroadcastMailbox<Digest, Block>) {
        // Initialize verified blocks
        let verified_journal = Journal::init(
            context.with_label("verified_journal"),
            journal::variable::Config {
                partition: format!("{}-verifications", config.partition_prefix),
            },
        )
        .await
        .expect("Failed to initialize verified journal");
        let verified_archive = Archive::init(
            context.with_label("verified_archive"),
            verified_journal,
            archive::Config {
                translator: TwoCap,
                section_mask: 0xffff_ffff_ffff_f000u64,
                pending_writes: 0,
                replay_concurrency: 4,
                compression: Some(3),
            },
        )
        .await
        .expect("Failed to initialize verified archive");

        // Initialize notarized blocks
        let notarized_journal = Journal::init(
            context.with_label("notarized_journal"),
            journal::variable::Config {
                partition: format!("{}-notarizations", config.partition_prefix),
            },
        )
        .await
        .expect("Failed to initialize notarized journal");
        let notarized_archive = Archive::init(
            context.with_label("notarized_archive"),
            notarized_journal,
            archive::Config {
                translator: TwoCap,
                section_mask: 0xffff_ffff_ffff_f000u64,
                pending_writes: 0,
                replay_concurrency: 4,
                compression: Some(3),
            },
        )
        .await
        .expect("Failed to initialize notarized archive");

        // Initialize finalizations
        let finalized_journal = Journal::init(
            context.with_label("finalized_journal"),
            journal::variable::Config {
                partition: format!("{}-finalizations", config.partition_prefix),
            },
        )
        .await
        .expect("Failed to initialize finalized journal");
        let finalized_archive = Archive::init(
            context.with_label("finalized_archive"),
            finalized_journal,
            archive::Config {
                translator: EightCap,
                section_mask: 0xffff_ffff_fff0_0000u64,
                pending_writes: 0,
                replay_concurrency: 4,
                compression: Some(3),
            },
        )
        .await
        .expect("Failed to initialize finalized archive");

        // Initialize blocks
        let block_journal = Journal::init(
            context.with_label("block_journal"),
            journal::variable::Config {
                partition: format!("{}-blocks", config.partition_prefix),
            },
        )
        .await
        .expect("Failed to initialize block journal");
        let block_archive = Archive::init(
            context.with_label("block_archive"),
            block_journal,
            archive::Config {
                translator: EightCap,
                section_mask: 0xffff_ffff_fff0_0000u64,
                pending_writes: 0,
                replay_concurrency: 4,
                compression: Some(3),
            },
        )
        .await
        .expect("Failed to initialize finalized archive");

        // Initialize finalizer metadata
        let finalizer_metadata = Metadata::init(
            context.with_label("finalizer_metadata"),
            metadata::Config {
                partition: format!("{}-finalizer_metadata", config.partition_prefix),
            },
        )
        .await
        .expect("Failed to initialize finalizer metadata");

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

        // Initialize broadcast engine
        let broadcast_config = BroadcastConfig {
            public_key: config.public_key,
            mailbox_size: config.mailbox_size,
            deque_size: config.broadcast_cache_size,
            priority: false,
            decode_config: broadcast_decode_config.clone(),
        };
        let (_broadcast_engine, broadcast_mailbox) =
            BroadcastEngine::<_, _, Digest, C, Block, _, _>::new(
                context.with_label("broadcast"),
                broadcast_config,
            );

        // Initialize mailbox
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                context,
                public_key: config.public_key,
                public: config.identity.into(),
                coordinator: config.coordinator,
                mailbox,
                mailbox_size: config.mailbox_size,
                backfill_quota: config.backfill_quota,
                activity_timeout: config.activity_timeout,
                indexer: config.indexer,

                verified: verified_archive,
                notarized: notarized_archive,

                finalized: finalized_archive,
                blocks: block_archive,

                finalizer: finalizer_metadata,

                finalized_height,
                contiguous_height,
                broadcast_mailbox: broadcast_mailbox.clone(),
                broadcast_decode_config,
            },
            Mailbox::new(sender),
            broadcast_mailbox,
        )
    }

    pub fn start(
        mut self,
        backfill_network: (
            impl Sender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
            impl Receiver<PublicKey = PublicKey> + Send + Sync + 'static,
        ),
    ) -> Handle<()> {
        // Start broadcast engine
        let broadcast_config = BroadcastConfig {
            public_key: self.public_key,
            mailbox_size: self.mailbox_size,
            deque_size: 10, // TODO: Get from config if needed
            priority: false,
            decode_config: self.broadcast_decode_config.clone(),
        };
        let (broadcast_engine, _) = BroadcastEngine::<_, _, Digest, C, Block, _, _>::new(
            self.context.with_label("broadcast_engine_start"),
            broadcast_config,
        );
        broadcast_engine.start(backfill_network.clone());

        self.context.spawn_ref()(self.run(backfill_network))
    }

    /// Run the application engine.
    async fn run(
        mut self,
        backfill_network: (
            impl Sender<PublicKey = PublicKey> + Clone + Send + Sync + 'static,
            impl Receiver<PublicKey = PublicKey> + Send + Sync + 'static,
        ),
    ) {
        // Initialize resolver
        let (handler_sender, mut handler_receiver) = mpsc::channel(self.mailbox_size);
        let handler = Handler::new(handler_sender);
        let (resolver_engine, mut resolver) = p2p::Engine::new(
            self.context.with_label("resolver"),
            p2p::Config {
                coordinator: self.coordinator.clone(),
                consumer: handler.clone(),
                producer: handler,
                mailbox_size: self.mailbox_size,
                requester_config: requester::Config {
                    public_key: self.public_key,
                    rate_limit: self.backfill_quota.clone(),
                    initial: Duration::from_secs(1),
                    timeout: Duration::from_secs(2),
                },
                fetch_retry_timeout: Duration::from_millis(100), // prevent busy loop
                priority_requests: false,
                priority_responses: false,
            },
        );
        resolver_engine.start(backfill_network);

        // Process all finalized blocks in order (fetching any that are missing)
        let last_view_processed = Arc::new(Mutex::new(0));
        let verified = Wrapped::new(self.verified);
        let notarized = Wrapped::new(self.notarized);
        let finalized = Wrapped::new(self.finalized);
        let blocks = Wrapped::new(self.blocks);
        let (mut finalizer_sender, mut finalizer_receiver) = mpsc::channel::<()>(1);

        self.context.with_label("finalizer").spawn({
            let mut resolver = resolver.clone();
            let last_view_processed = last_view_processed.clone();
            let verified = verified.clone();
            let notarized = notarized.clone();
            let finalized = finalized.clone();
            let blocks = blocks.clone();
            let mut finalizer = self.finalizer.clone();
            let mut contiguous_height_metric = self.contiguous_height.clone();
            move |_| async move {
                // Initialize last indexed from metadata store
                let latest_key = FixedBytes::new([0u8]);
                let mut last_indexed = if let Some(bytes) = finalizer.get(&latest_key) {
                    u64::from_be_bytes(bytes.to_vec().try_into().unwrap())
                } else {
                    0
                };

                // Index all finalized blocks
                //
                // If using state sync, this is not necessary.
                let mut requested_blocks = BTreeSet::new();
                loop {
                    // Check if the next block is available
                    let next = last_indexed + 1;
                    let block = blocks
                        .get(Identifier::Index(next))
                        .await
                        .expect("Failed to get finalized block");
                    if let Some(block_bytes) = block {
                        // Update metadata
                        finalizer.put(latest_key.clone(), next.to_be_bytes().to_vec().into());
                        finalizer.sync().await.expect("Failed to sync finalizer");

                        // In an application that maintains state, you would compute the state transition function here.

                        // Cancel any outstanding requests (by height and by digest)
                        resolver
                            .cancel(MultiIndex::new(Value::Finalized(next)))
                            .await;
                        let block =
                            Block::deserialize(&block_bytes).expect("Failed to deserialize block");
                        resolver
                            .cancel(MultiIndex::new(Value::Digest(block.digest())))
                            .await;

                        // Update the latest indexed
                        contiguous_height_metric.set(next as i64);
                        last_indexed = next;
                        info!(height = next, "indexed finalized block");

                        // Update last view processed (if we have a finalization for this block)
                        let finalization = finalized
                            .get(Identifier::Index(next))
                            .await
                            .expect("Failed to get finalization");
                        if let Some(finalization_bytes) = finalization {
                            let finalization = Finalization::deserialize(None, &finalization_bytes)
                                .expect("Failed to deserialize finalization");
                            *last_view_processed.lock().await = finalization.view;
                        }
                        continue;
                    }

                    // Try to connect to our latest handled block (may not exist finalizations for some heights)
                    let (_, start_next) = blocks.next_gap(next).await;
                    if let Some(start_next) = start_next {
                        if last_indexed > 0 {
                            // Get gapped block
                            let gapped_block_bytes = blocks
                                .get(Identifier::Index(start_next))
                                .await
                                .expect("Failed to get finalized block")
                                .expect("Gapped block missing");
                            let gapped_block = Block::deserialize(&gapped_block_bytes)
                                .expect("Failed to deserialize block");

                            // Attempt to repair one block from other sources
                            let target_block = gapped_block.parent;
                            let verified_bytes = verified
                                .get(Identifier::Key(&target_block))
                                .await
                                .expect("Failed to get verified block");
                            if let Some(verified_bytes) = verified_bytes {
                                let verified_block = Block::deserialize(&verified_bytes)
                                    .expect("Failed to deserialize block");
                                blocks
                                    .put(verified_block.height, target_block, verified_bytes)
                                    .await
                                    .expect("Failed to insert finalized block");
                                debug!(
                                    height = verified_block.height,
                                    "repaired block from verified"
                                );
                                continue;
                            }
                            let notarization_bytes = notarized
                                .get(Identifier::Key(&target_block))
                                .await
                                .expect("Failed to get notarized block");
                            if let Some(notarization_bytes) = notarization_bytes {
                                let notarization =
                                    Notarized::deserialize(None, &notarization_bytes)
                                        .expect("Failed to deserialize block");
                                blocks
                                    .put(
                                        notarization.block.height,
                                        target_block,
                                        notarization.block.serialize().into(),
                                    )
                                    .await
                                    .expect("Failed to insert finalized block");
                                debug!(
                                    height = notarization.block.height,
                                    "repaired block from notarizations"
                                );
                                continue;
                            }

                            // Request the parent block digest
                            resolver
                                .fetch(MultiIndex::new(Value::Digest(target_block)))
                                .await;
                        }

                        // Enqueue next items (by index)
                        let range = next..std::cmp::min(start_next, next + 20);
                        debug!(
                            range.start,
                            range.end, "requesting missing finalized blocks"
                        );
                        for height in range {
                            // Check if we've already requested
                            if requested_blocks.contains(&height) {
                                continue;
                            }

                            // Request the block
                            let key = MultiIndex::new(Value::Finalized(height));
                            resolver.fetch(key).await;
                            requested_blocks.insert(height);
                        }
                    };

                    // If not finalized, wait for some message from someone that finalized store was updated
                    debug!(height = next, "waiting to index finalized block");
                    let _ = finalizer_receiver.next().await;
                }
            }
        });

        // Handle messages
        let mut waiters: HashMap<Digest, Vec<oneshot::Sender<Block>>> = HashMap::new();
        let mut latest_view = 0;
        let mut outstanding_notarize = BTreeSet::new();
        loop {
            // Clear dead waiters
            waiters.retain(|_, waiters| {
                waiters.retain(|waiter| !waiter.is_canceled());
                !waiters.is_empty()
            });

            // Cancel useless requests
            let mut to_cancel = Vec::new();
            outstanding_notarize.retain(|view| {
                if *view < latest_view {
                    to_cancel.push(MultiIndex::new(Value::Notarized(*view)));
                    false
                } else {
                    true
                }
            });
            for view in to_cancel {
                resolver.cancel(view).await;
            }

            // Select messages
            select! {
                // Handle mailbox before resolver messages
                mailbox_message = self.mailbox.next() => {
                    let message = mailbox_message.expect("Mailbox closed");
                    match message {
                        Message::Verified { view, payload } => {
                            // Broadcast the verified block
                            self.broadcast_mailbox.broadcast(payload.clone()).await;

                            verified
                                .put(view, payload.digest(), payload.serialize().into())
                                .await
                                .expect("Failed to insert verified block");
                        }
                        Message::Notarized { proof, seed } => {
                            // Upload seed to indexer (if available)
                            if let Some(indexer) = self.indexer.as_ref() {
                                self.context.with_label("indexer").spawn({
                                    let indexer = indexer.clone();
                                    let view = proof.view;
                                    let seed_bytes: Bytes = seed.serialize().into()
                                    move |_| async move {
                                        let result = indexer.seed_upload(seed_bytes).await;
                                        if let Err(e) = result {
                                            warn!(?e, "failed to upload seed");
                                            return;
                                        }
                                        debug!(view, "seed uploaded to indexer");
                                    }
                                });
                            }

                            let payload_digest = proof.payload

                            // Check broadcast cache first
                            let mut block = None;
                            match self.broadcast_mailbox.get(payload_digest).await {
                                Ok(block_from_broadcast) => {
                                    debug!(height = block_from_broadcast.height, "found block for notarization in broadcast cache");
                                    block = Some(block_from_broadcast);
                                },
                                Err(_) => {
                                    // Check verified blocks if not in broadcast cache
                                    if let Some(verified_bytes) = verified.get(Identifier::Key(&payload_digest)).await.expect("Failed to get verified block") {
                                        block = Some(Block::deserialize(&verified_bytes).expect("Failed to deserialize block"));
                                    }
                                }
                            };

                            // If found, store notarization
                            if let Some(block) = block {
                                let view = proof.view;
                                let height = block.height;
                                let digest = proof.payload;
                                let notarization = Notarized::new(proof, block);
                                let notarization_bytes: Bytes = notarization.serialize().into();
                                notarized
                                    .put(view, digest, notarization_bytes.clone()) // Clone here
                                    .await
                                    .expect("Failed to insert notarized block");
                                debug!(view, height, "notarized block stored");

                                // Upload to indexer (if available)
                                if let Some(indexer) = self.indexer.as_ref() {
                                    self.context.with_label("indexer").spawn({
                                        let indexer = indexer.clone();
                                        // notarization_bytes is already cloned above
                                        move |_| async move {
                                            let result = indexer
                                                .notarization_upload(notarization_bytes)
                                                .await;
                                            if let Err(e) = result {
                                                warn!(?e, "failed to upload notarization");
                                                return;
                                            }
                                            debug!(view, "notarization uploaded to indexer");
                                        }
                                    });
                                }

                                // Notify waiters (using digest from proof)
                                if let Some(waiters) = waiters.remove(&digest) {
                                     debug!(view, ?height, "waiter resolved via notarization");
                                     for waiter in waiters {
                                         let _ = waiter.send(notarization.block.clone());
                                     }
                                }
                                continue;
                            }

                            // Fetch from network if not found
                            // We don't worry about retaining the proof because any peer must provide
                            // it to us when serving the notarization.
                            debug!(view = proof.view, "notarized block missing, fetching via resolver");
                            outstanding_notarize.insert(proof.view);
                            resolver.fetch(MultiIndex::new(Value::Notarized(proof.view))).await;
                        }
                        Message::Finalized { proof, seed } => {
                            // Upload seed to indexer (if available)
                             if let Some(indexer) = self.indexer.as_ref() {
                                self.context.with_label("indexer").spawn({
                                    let indexer = indexer.clone();
                                    let view = proof.view;
                                    let seed_bytes: Bytes = seed.serialize().into()
                                    move |_| async move {
                                        let result = indexer.seed_upload(seed_bytes).await;
                                        if let Err(e) = result {
                                            warn!(?e, "failed to upload seed");
                                            return;
                                        }
                                        debug!(view, "seed uploaded to indexer");
                                    }
                                });
                            }

                            let payload_digest = proof.payload

                            // Check broadcast cache first
                            let mut block = None;
                             match self.broadcast_mailbox.get(payload_digest).await {
                                Ok(block_from_broadcast) => {
                                    debug!(height = block_from_broadcast.height, "found block for finalization in broadcast cache");
                                    block = Some(block_from_broadcast);
                                },
                                Err(_) => {
                                    // Check verified if not in broadcast
                                    if let Some(verified_bytes) = verified.get(Identifier::Key(&payload_digest)).await.expect("Failed to get verified block") {
                                        block = Some(Block::deserialize(&verified_bytes).expect("Failed to deserialize block"));
                                    }
                                    // Check notarized if not in verified/broadcast
                                    else if let Some(notarized_bytes) = notarized.get(Identifier::Key(&payload_digest)).await.expect("Failed to get notarized block") {
                                        block = Some(Notarized::deserialize(None, &notarized_bytes).expect("Failed to deserialize block").block);
                                    }
                                }
                            };


                            // If found, store finalization
                            if let Some(block) = block {
                                let view = proof.view;
                                let digest = proof.payload;
                                let height = block.height;
                                finalized
                                    .put(height, proof.payload, proof.serialize().into())
                                    .await
                                    .expect("Failed to insert finalization");
                                blocks
                                    .put(height, digest, block.serialize().into())
                                    .await
                                    .expect("Failed to insert finalized block");
                                debug!(view, height, "finalized block stored");

                                // Prune blocks
                                let last_view_processed_val = *last_view_processed.lock().await
                                let min_view = last_view_processed_val.saturating_sub(self.activity_timeout);
                                verified
                                    .prune(min_view)
                                    .await
                                    .expect("Failed to prune verified block");
                                notarized
                                    .prune(min_view)
                                    .await
                                    .expect("Failed to prune notarized block");

                                // Notify finalizer
                                let _ = finalizer_sender.try_send(());

                                // Update latest
                                latest_view = view;

                                // Update metrics
                                self.finalized_height.set(height as i64);

                                // Upload to indexer (if available)
                                if let Some(indexer) = self.indexer.as_ref() {
                                    self.context.with_label("indexer").spawn({
                                        let indexer = indexer.clone();
                                        let finalization = Finalized::new(proof, block.clone()).serialize().into()
                                        move |_| async move {
                                            let result = indexer
                                                .finalization_upload(finalization)
                                                .await;
                                            if let Err(e) = result {
                                                warn!(?e, "failed to upload finalization");
                                                return;
                                            }
                                            debug!(height, "finalization uploaded to indexer");
                                        }
                                    });
                                }

                                 // Notify waiters (using digest from proof)
                                if let Some(waiters) = waiters.remove(&digest) {
                                     debug!(view, ?height, "waiter resolved via finalization");
                                     for waiter in waiters {
                                         let _ = waiter.send(block.clone())
                                     }
                                }
                                continue;
                            }

                            // Fetch from network if not found anywhere
                            warn!(view = proof.view, digest = ?payload_digest, "finalized block missing, fetching via resolver");
                            resolver.fetch(MultiIndex::new(Value::Digest(payload_digest))).await;
                        }
                        Message::Get { view, payload, response } => {

                            // Check verified blocks
                            let verified_block_bytes = verified.get(Identifier::Key(&payload)).await.expect("Failed to get verified block");
                            if let Some(verified_block_bytes) = verified_block_bytes {
                                let block = Block::deserialize(&verified_block_bytes).expect("Failed to deserialize block");
                                debug!(height = block.height, "found block in verified");
                                let _ = response.send(block);
                                continue;
                            }

                            // Check if in notarized blocks
                            let notarization_bytes = notarized.get(Identifier::Key(&payload)).await.expect("Failed to get notarized block");
                            if let Some(notarization_bytes) = notarization_bytes {
                                let notarization = Notarized::deserialize(None, &notarization_bytes).expect("Failed to deserialize block");
                                let block = notarization.block;
                                debug!(height = block.height, "found block in notarized");
                                let _ = response.send(block);
                                continue;
                            }

                            // Check if in finalized blocks
                            let finalized_block_bytes = blocks.get(Identifier::Key(&payload)).await.expect("Failed to get finalized block");
                            if let Some(finalized_block_bytes) = finalized_block_bytes {
                                let block = Block::deserialize(&finalized_block_bytes).expect("Failed to deserialize block");
                                debug!(height = block.height, "found block in finalized");
                                let _ = response.send(block);
                                continue;
                            }

                             // Check broadcast cache if not found elsewhere
                            match self.broadcast_mailbox.get(payload).await {
                                 Ok(block_from_broadcast) => {
                                      debug!(height = block_from_broadcast.height, "found block in broadcast cache");
                                      let _ = response.send(block_from_broadcast);
                                      continue;
                                 },
                                 Err(_) => {
                                     // Not found in broadcast cache either
                                     debug!(?payload, "block not found locally or in broadcast cache");
                                 }
                             };

                            // Fetch from network if notarized (view is non-nil)
                            if let Some(view) = view {
                                debug!(view, ?payload, "required block missing, fetching via resolver");
                                resolver.fetch(MultiIndex::new(Value::Notarized(view))).await;
                            } else {
                                debug!(?payload, "non-essential block missing, fetching via resolver");
                                // Optionally fetch non-essential blocks by digest if needed
                                resolver.fetch(MultiIndex::new(Value::Digest(payload))).await;
                            }

                            // Register waiter
                            debug!(view, ?payload, "registering waiter");
                            waiters.entry(payload).or_default().push(response);
                        }
                    }
                },
                // Handle resolver messages last
                handler_message = handler_receiver.next() => {
                    let message = handler_message.expect("Handler closed");
                    match message {
                        handler::Message::Produce { key, response } => {
                            match key.to_value() {
                                key::Value::Notarized(view) => {
                                    let notarization = notarized.get(Identifier::Index(view)).await.expect("Failed to get notarized block");
                                    if let Some(notarized_bytes) = notarization {
                                        let _ = response.send(notarized_bytes);
                                    } else {
                                        debug!(view, "notarization missing on request");
                                    }
                                },
                                key::Value::Finalized(height) => {
                                    // Get finalization
                                    let finalization_bytes = finalized.get(Identifier::Index(height)).await.expect("Failed to get finalization");
                                    let Some(finalization_bytes) = finalization_bytes else {
                                        debug!(height, "finalization missing on request");
                                        continue;
                                    };
                                    let finalization = Finalization::deserialize(None, &finalization_bytes).expect("Failed to deserialize finalization");

                                    // Get block
                                    let block_bytes = blocks.get(Identifier::Index(height)).await.expect("Failed to get finalized block");
                                    let Some(block_bytes) = block_bytes else {
                                        debug!(height, "finalized block missing on request");
                                        continue;
                                    };
                                    let block = Block::deserialize(&block_bytes).expect("Failed to deserialize block");

                                    // Send finalization
                                    let payload = Finalized::new(finalization, block);
                                    let _ = response.send(payload.serialize().into());
                                },
                                key::Value::Digest(digest) => {
                                     // Check broadcast cache first
                                     match self.broadcast_mailbox.get(digest).await {
                                         Ok(block_from_broadcast) => {
                                             let _ = response.send(block_from_broadcast.serialize().into());
                                             continue;
                                         },
                                         Err(_) => { /* Not found, continue checking other sources */ }
                                     };

                                    // Get verified block
                                    let verified_block_bytes = verified.get(Identifier::Key(&digest)).await.expect("Failed to get verified block");
                                    if let Some(verified_block_bytes) = verified_block_bytes {
                                        let _ = response.send(verified_block_bytes);
                                        continue;
                                    }

                                    // Get notarized block
                                    let notarization_bytes = notarized.get(Identifier::Key(&digest)).await.expect("Failed to get notarized block");
                                    if let Some(notarized_bytes) = notarization_bytes {
                                        let notarization = Notarized::deserialize(None, &notarized_bytes).expect("Failed to deserialize notarization");
                                        let _ = response.send(notarization.block.serialize().into());
                                        continue;
                                    }

                                    // Get block
                                    let finalized_block_bytes = blocks.get(Identifier::Key(&digest)).await.expect("Failed to get finalized block");
                                    if let Some(finalized_block_bytes) = finalized_block_bytes {
                                        let _ = response.send(finalized_block_bytes);
                                        continue;
                                    };

                                    // No record of block
                                    debug!(?digest, "block missing on request");
                                }
                            }
                        }
                        handler::Message::Deliver { key, value, response } => {
                            match key.to_value() {
                                key::Value::Notarized(view) => {
                                    // Parse notarization
                                    let Some(notarization) = Notarized::deserialize(Some(&self.public), &value) else {
                                        warn!(view, "failed to deserialize delivered notarization");
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Ensure the received payload is for the correct view
                                    if notarization.proof.view != view {
                                         warn!(view, received_view = notarization.proof.view, "delivered notarization has wrong view");
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Persist the notarization
                                    debug!(view, "received notarization via resolver");
                                    let _ = response.send(true);
                                    let digest = notarization.block.digest()
                                    notarized
                                        .put(view, digest, value)
                                        .await
                                        .expect("Failed to insert notarized block");

                                    // Notify waiters
                                    if let Some(waiters) = waiters.remove(&digest) {
                                        debug!(view, ?notarization.block.height, "waiter resolved via notarization (resolver)");
                                        for waiter in waiters {
                                            let _ = waiter.send(notarization.block.clone());
                                        }
                                    }
                                },
                                key::Value::Finalized(height) => {
                                    // Parse finalization
                                    let Some(finalization) = Finalized::deserialize(Some(&self.public), &value) else {
                                         warn!(height, "failed to deserialize delivered finalization");
                                        let _ = response.send(false);
                                        continue;
                                    };

                                    // Ensure the received payload is for the correct height
                                    if finalization.block.height != height {
                                         warn!(height, received_height = finalization.block.height, "delivered finalization has wrong height");
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Indicate the finalization was valid
                                    debug!(height, "received finalization via resolver");
                                    let _ = response.send(true);

                                    // Persist the finalization
                                    let digest = finalization.block.digest()
                                    finalized
                                        .put(height, digest, finalization.proof.serialize().into())
                                        .await
                                        .expect("Failed to insert finalization");

                                    // Persist the block
                                    blocks
                                        .put(height, digest, finalization.block.serialize().into())
                                        .await
                                        .expect("Failed to insert finalized block");

                                    // Notify waiters
                                    if let Some(waiters) = waiters.remove(&digest) {
                                        debug!(?finalization.block.height, "waiter resolved via finalization (resolver)");
                                        for waiter in waiters {
                                            let _ = waiter.send(finalization.block.clone());
                                        }
                                    }

                                    // Notify finalizer
                                    let _ = finalizer_sender.try_send(());
                                },
                                key::Value::Digest(digest) => {
                                    // Parse block
                                    let Ok(block) = Block::deserialize(&value) else {
                                        warn!(?digest, "failed to deserialize delivered block");
                                         let _ = response.send(false);
                                        continue;
                                    };

                                    // Ensure the received payload is for the correct digest
                                    if block.digest() != digest {
                                         warn!(?digest, received_digest = ?block.digest(), "delivered block has wrong digest");
                                        let _ = response.send(false);
                                        continue;
                                    }

                                    // Persist the block (e.g., in finalized, though might need more context)
                                    // For simplicity, let's assume fetched blocks by digest are finalized ones we missed.
                                    // A more robust system might store them temporarily or in a dedicated "fetched_blocks" archive.
                                    debug!(?digest, height = block.height, "received block via resolver");
                                    let _ = response.send(true);
                                    blocks
                                        .put(block.height, digest, value) // Store in finalized blocks archive
                                        .await
                                        .expect("Failed to insert finalized block");

                                    // Notify waiters
                                    if let Some(waiters) = waiters.remove(&digest) {
                                        debug!(?block.height, "waiter resolved via block (resolver)");
                                        for waiter in waiters {
                                            let _ = waiter.send(block.clone());
                                        }
                                    }

                                    // Notify finalizer as a block was added
                                    let _ = finalizer_sender.try_send(());
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}
