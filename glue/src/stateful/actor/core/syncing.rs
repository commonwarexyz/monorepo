use crate::stateful::{
    actor::{
        core::{
            keep_resolvers_alive,
            mailbox::{ErasedAncestorStream, Message},
            processing::Processing,
        },
        metrics::Metrics as StatefulMetrics,
        processor::{FinalizeStatus, Processor},
        syncer::{self, StateSyncMetadata, SyncResult},
    },
    db::{Anchor, AttachableResolverSet},
    Application, PruneConfig,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    Epochable, Heightable, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::select_loop;
use commonware_runtime::{
    telemetry::metrics::GaugeExt, Clock, ContextCell, Metrics, Spawner, Storage,
};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
    sync::AsyncMutex,
    Acknowledgement,
};
use rand::Rng;
use std::{num::NonZeroUsize, sync::Arc};
use tracing::{debug, error, info_span, Instrument as _, Span};

/// Verify request buffered while state sync is still in progress.
pub(super) struct HeldVerify<C, B> {
    span: Span,
    context: C,
    ancestry: ErasedAncestorStream<B>,
    response: oneshot::Sender<bool>,
}

type HeldVerifyRequest<E, A> =
    HeldVerify<(E, <A as Application<E>>::Context), <A as Application<E>>::Block>;

enum FinalizedHandoff<B> {
    Reflected(B, Exact),
    Apply(B, Exact),
}

pub(super) struct Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    R: AttachableResolverSet<A::Databases>,
{
    /// Runtime context.
    pub(super) context: ContextCell<E>,

    /// Actor ingress.
    pub(super) mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// Inner application.
    pub(super) application: A,

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub(super) input_provider: A::InputProvider,

    /// Marshal actor mailbox.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// Durable state-sync metadata.
    pub(super) sync_metadata: Arc<AsyncMutex<StateSyncMetadata<E, V::Commitment>>>,

    /// Syncer actor mailbox.
    pub(super) syncer: syncer::Mailbox<E, A>,

    /// Verify requests held while syncing.
    pub(super) held_verify_requests: Vec<HeldVerifyRequest<E, A>>,

    /// Open subscriptions to the synced databases.
    pub(super) database_subscribers: Vec<oneshot::Sender<A::Databases>>,

    /// The cached [`SyncResult`], populated when sync completes.
    pub(super) artifact: Option<SyncResult<E, A>>,

    /// The state sync resolvers used for state sync fetching and post-bootstrap
    /// serving.
    pub(super) resolvers: R,

    /// Signals that the syncer has produced a usable artifact.
    pub(super) sync_completed: oneshot::Receiver<SyncResult<E, A>>,

    /// Marshal ack window, used to derive automatic prune retention.
    pub(super) max_pending_acks: NonZeroUsize,

    /// Periodic prune configuration.
    pub(super) prune_config: Option<PruneConfig>,

    /// Metrics shared across syncing and processing.
    pub(super) metrics: StatefulMetrics,
}

impl<E, A, S, V, R> Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    R: AttachableResolverSet<A::Databases>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.held_verify_requests
                    .retain(|request| !request.response.is_closed());
                self.database_subscribers
                    .retain(|subscriber| !subscriber.is_closed());
            },
            on_stopped => {
                debug!("processor received shutdown signal");
            },
            Ok(artifact) = &mut self.sync_completed else {
                error!("syncer stopped before publishing state sync artifact");
                break;
            } => {
                self.artifact = Some(artifact);
                self.transition(None).await;
                return;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down processor");
                break;
            } => match message {
                Message::Propose {
                    span,
                    context: (_, context),
                    response,
                    ..
                } => {
                    span.in_scope(|| {
                        debug!(epoch = %context.epoch(), view = %context.view(), "proposal rejected: state sync in progress");
                        response.send_lossy(None);
                    });
                }
                Message::Verify {
                    span,
                    context,
                    ancestry,
                    response,
                } => {
                    let process = info_span!(parent: &span, "stateful.actor.hold_verify");
                    self.held_verify_requests
                        .retain(|request| !request.response.is_closed());
                    self.held_verify_requests.push(HeldVerify {
                        span,
                        context,
                        ancestry,
                        response,
                    });
                    process.in_scope(|| {
                        debug!(
                            held_verify_requests = self.held_verify_requests.len(),
                            "verify held: state sync in progress"
                        );
                    });
                }
                Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                } => {
                    let process = info_span!(parent: &span, "stateful.actor.syncing_finalized");
                    let handoff = self
                        .process_finalized(block, acknowledgement)
                        .instrument(process)
                        .await;
                    if let Some(handoff) = handoff {
                        self.transition(Some(handoff)).await;
                        return;
                    }
                }
                Message::SubscribeDatabases { response } => {
                    self.database_subscribers
                        .retain(|subscriber| !subscriber.is_closed());
                    if !response.is_closed() {
                        self.database_subscribers.push(response);
                    }
                }
            },
        }
    }

    /// Processes a finalized block during state sync.
    async fn process_finalized(
        &mut self,
        block: A::Block,
        acknowledgement: Exact,
    ) -> Option<FinalizedHandoff<A::Block>> {
        if self.artifact.is_none() {
            let anchor = Anchor::from(&block);
            let targets = A::sync_targets(&block);

            // Do not acknowledge marshal until the live sync session has recorded this
            // block's tip update. If we ack after merely enqueueing it, sync can still
            // complete on the previous anchor and handoff would observe marshal ahead of
            // `artifact.anchor.height.next()`.
            if let Some(artifact) = self.syncer.update_targets(anchor, targets).await {
                self.artifact = Some(artifact);
            } else {
                acknowledgement.acknowledge();
                return None;
            }
        }

        let artifact = self
            .artifact
            .as_ref()
            .expect("sync artifact must exist after sync handoff");

        if block.height() == artifact.anchor.height {
            assert_eq!(
                block.digest(),
                artifact.anchor.digest,
                "finalized block at sync anchor height must match sync anchor digest",
            );
            return Some(FinalizedHandoff::Reflected(block, acknowledgement));
        }

        assert_eq!(
            block.height(),
            artifact.anchor.height.next(),
            "finalized block after sync anchor must be the next finalized block",
        );
        Some(FinalizedHandoff::Apply(block, acknowledgement))
    }

    /// Transitions to [`Processing`] state once the database set has converged
    /// on the state sync [`Anchor`].
    async fn transition(mut self, handoff: Option<FinalizedHandoff<A::Block>>) {
        let artifact = self.artifact.take().expect("transition must have artifact");
        let synced_height = artifact.anchor.height;

        let _ = self.metrics.sync_done.try_set(1);
        let mut processor = Processor::new(
            self.application,
            artifact.databases,
            artifact.anchor,
            self.metrics,
            self.max_pending_acks,
            self.prune_config,
        );

        self.sync_metadata
            .lock()
            .await
            .set_complete(synced_height)
            .await;

        if let Some(handoff) = handoff {
            match handoff {
                FinalizedHandoff::Reflected(block, acknowledgement) => {
                    processor
                        .notify_finalized(self.context.as_present(), &block)
                        .await;
                    acknowledgement.acknowledge();
                }
                FinalizedHandoff::Apply(block, acknowledgement) => {
                    let (status, prune) =
                        processor.finalize(self.context.as_present(), block).await;
                    if let Some(prune) = prune {
                        prune.run(processor.databases_mut(), &self.marshal).await;
                    }
                    if let FinalizeStatus::Persisted { height } = status {
                        debug!(
                            height = height.get(),
                            "persisted finalized database batch during sync handoff"
                        );
                    }
                    acknowledgement.acknowledge();
                }
            }
        }

        // Attach the resolvers to the initialized databases before starting the processor,
        // so that this instance can serve peers database operations and proofs.
        self.resolvers
            .attach_databases(processor.databases().clone())
            .await;

        // `subscribe_databases` promises a database set that is already attached to the
        // serving actor, so keep subscribers waiting until the resolver handoff is complete.
        for subscriber in self.database_subscribers.drain(..) {
            subscriber.send_lossy(processor.databases().clone());
        }

        for request in self.held_verify_requests.drain(..) {
            let process = info_span!(parent: &request.span, "stateful.actor.replay_verify");
            processor
                .verify(
                    self.context.as_present(),
                    self.marshal.clone(),
                    request.context,
                    request.ancestry,
                    request.response,
                )
                .instrument(process)
                .await;
        }

        keep_resolvers_alive(self.context.as_present(), self.resolvers);

        Processing {
            context: self.context,
            mailbox: self.mailbox,
            input_provider: self.input_provider,
            marshal: self.marshal,
            processor,
            skip_finalized_until: Some(synced_height),
        }
        .start()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{FinalizedHandoff, Syncing};
    use crate::stateful::{
        actor::{
            metrics::Metrics as StatefulMetrics,
            syncer::{self, StateSyncMetadata, SyncResult},
        },
        db::{Anchor, AttachableResolver},
        tests::mocks::{anchor, test_databases, TestApp, TestBlock, TestScheme, TestVariant},
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        marshal::{self, core::Actor as MarshalActor},
        simplex::mocks::scheme as scheme_mocks,
        types::{FixedEpocher, Height, ViewDelta},
        Heightable,
    };
    use commonware_cryptography::{certificate::ConstantProvider, sha256::Digest as Sha256Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, ContextCell, Runner as _, Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        acknowledgement::Exact,
        channel::oneshot,
        sync::{AsyncMutex, TracedAsyncRwLock},
        Acknowledgement, NZUsize, NZU16, NZU64,
    };
    use futures::{pin_mut, poll, FutureExt};
    use std::sync::Arc;

    #[derive(Clone)]
    struct NoopResolver;

    impl<DB: Send + Sync + 'static> AttachableResolver<DB> for NoopResolver {
        async fn attach_database(&self, _db: Arc<TracedAsyncRwLock<DB>>) {}
    }

    struct TestHarness {
        syncing: Syncing<deterministic::Context, TestApp, TestScheme, TestVariant, NoopResolver>,
    }

    impl TestHarness {
        async fn new(context: deterministic::Context, anchor: Anchor<Sha256Digest>) -> Self {
            let (_mailbox_sender, mailbox) =
                actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let (syncer_sender, _syncer_receiver) =
                actor_mailbox::new(context.child("syncer_mailbox"), NZUsize!(1));
            let (_sync_complete, sync_completed) = oneshot::channel();

            Self {
                syncing: Syncing {
                    context: ContextCell::new(context.child("syncing")),
                    mailbox,
                    application: TestApp,
                    input_provider: (),
                    marshal: init_marshal_mailbox(context.child("marshal")).await,
                    sync_metadata: Arc::new(AsyncMutex::new(
                        StateSyncMetadata::init(&context, "syncing-test").await,
                    )),
                    syncer: syncer::Mailbox::new(syncer_sender),
                    held_verify_requests: Vec::new(),
                    database_subscribers: Vec::new(),
                    artifact: Some(SyncResult {
                        databases: test_databases(),
                        anchor,
                    }),
                    resolvers: NoopResolver,
                    sync_completed,
                    max_pending_acks: NZUsize!(1),
                    prune_config: None,
                    metrics: StatefulMetrics::new(&context),
                },
            }
        }
    }

    fn archive_config(page_cache: CacheRef, partition: &str) -> immutable::Config<()> {
        immutable::Config {
            metadata_partition: format!("{partition}-metadata"),
            freezer_table_partition: format!("{partition}-table"),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 2,
            freezer_key_partition: format!("{partition}-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition}-value"),
            freezer_value_target_size: 128,
            freezer_value_compression: None,
            ordinal_partition: format!("{partition}-ordinal"),
            items_per_section: NZU64!(4),
            codec_config: (),
            replay_buffer: NZUsize!(64),
            freezer_key_write_buffer: NZUsize!(64),
            freezer_value_write_buffer: NZUsize!(64),
            ordinal_write_buffer: NZUsize!(64),
        }
    }

    async fn init_marshal_mailbox(
        mut context: deterministic::Context,
    ) -> commonware_consensus::marshal::core::Mailbox<TestScheme, TestVariant> {
        let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(page_cache.clone(), "syncing-finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), "syncing-blocks"),
        )
        .await
        .expect("failed to initialize blocks archive");

        let (_actor, mailbox, _height) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
            context.child("marshal_actor"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider,
                epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                start: marshal::Start::Genesis(TestBlock::new(0, 0)),
                partition_prefix: "syncing-harness".to_string(),
                mailbox_size: NZUsize!(8),
                view_retention_timeout: ViewDelta::new(1),
                prunable_items_per_section: NZU64!(4),
                page_cache,
                replay_buffer: NZUsize!(64),
                key_write_buffer: NZUsize!(64),
                value_write_buffer: NZUsize!(64),
                block_codec_config: (),
                max_repair: NZUsize!(1),
                max_pending_acks: NZUsize!(1),
                strategy: Sequential,
            },
        )
        .await;
        mailbox
    }

    #[test]
    fn anchor_height_block_acknowledges_and_transitions_without_handoff() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context.child("harness"), anchor(7, 9)).await;
            let (acknowledgement, mut waiter) = Exact::handle();

            let action = harness
                .syncing
                .process_finalized(TestBlock::new(7, 9), acknowledgement)
                .await;

            assert!(poll!(&mut waiter).is_pending());
            assert!(matches!(action, Some(FinalizedHandoff::Reflected(_, _))));
            harness.syncing.transition(action).await;
            assert!(waiter.await.is_ok());
        });
    }

    #[test]
    fn next_height_block_transitions_with_handoff_without_early_ack() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, waiter) = Exact::handle();

            let action = harness
                .syncing
                .process_finalized(TestBlock::new(8, 10), acknowledgement)
                .await;

            assert!(waiter.now_or_never().is_none());

            let Some(FinalizedHandoff::Apply(block, acknowledgement)) = action else {
                panic!("post-anchor block should be handed off to processor");
            };
            assert_eq!(block.height().get(), 8);
            acknowledgement.acknowledge();
        });
    }

    #[test]
    #[should_panic(expected = "sync anchor digest")]
    fn anchor_height_block_with_conflicting_digest_panics() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, _waiter) = Exact::handle();
            let _ = harness
                .syncing
                .process_finalized(TestBlock::new(7, 10), acknowledgement)
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "next finalized block")]
    fn non_anchor_non_next_block_panics() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, _waiter) = Exact::handle();
            let _ = harness
                .syncing
                .process_finalized(TestBlock::new(9, 10), acknowledgement)
                .await;
        });
    }

    #[test]
    fn transition_marks_sync_complete_before_handoff_acknowledgement() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context.child("harness"), anchor(7, 9)).await;
            let sync_metadata = harness.syncing.sync_metadata.clone();
            let metadata_guard = sync_metadata.lock().await;
            let (acknowledgement, mut waiter) = Exact::handle();

            let transition = harness.syncing.transition(Some(FinalizedHandoff::Apply(
                TestBlock::new(8, 10),
                acknowledgement,
            )));
            pin_mut!(transition);
            assert!(
                poll!(&mut transition).is_pending(),
                "transition must wait for sync-complete metadata"
            );
            assert!(
                poll!(&mut waiter).is_pending(),
                "handoff must not be acknowledged while sync-complete metadata is blocked",
            );

            drop(metadata_guard);
            transition.await;
            waiter
                .await
                .expect("handoff acknowledgement should complete");

            assert_eq!(
                sync_metadata.lock().await.sync_height(),
                Some(Height::new(7)),
            );
        });
    }
}
