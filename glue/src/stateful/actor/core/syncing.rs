use crate::stateful::{
    Application, PruneConfig,
    actor::{
        core::{mailbox::Message, processing::Processing},
        metrics::Metrics as StatefulMetrics,
        processor::{Applied, Processor},
        syncer::{self, StateSyncMetadata, SyncResult},
    },
    db::{Anchor, AttachableResolverSet},
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    Block, Epochable, Heightable, Viewable,
    marshal::{
        Identifier,
        ancestry::{BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant},
    },
    types::Height,
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::{select, select_loop};
use commonware_runtime::{ContextCell, Spawner, telemetry::metrics::GaugeExt};
use commonware_storage::Context;
use commonware_utils::{
    Acknowledgement,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
};
use futures::future::{BoxFuture, Either, pending};
use rand_core::Rng;
use std::{collections::VecDeque, sync::Arc, time::Duration};
use tracing::{Instrument as _, Span, debug, error, info_span};

/// Verify request buffered while state sync is still in progress.
pub(super) struct HeldVerify<C, B: Block> {
    span: Span,
    context: C,
    ancestry: BoxedAncestry<B>,
    response: oneshot::Sender<bool>,
}

type HeldVerifyRequest<E, A> =
    HeldVerify<(E, <A as Application<E>>::Context), <A as Application<E>>::Block>;

enum FinalizedHandoff<B> {
    Covered(B, Exact),
    Reflected(B, Exact),
    Apply(B, Exact),
}

pub(super) struct RetargetGrace<B> {
    timeout: BoxFuture<'static, ()>,
    finalized: VecDeque<(Arc<B>, Exact)>,
}

pub(super) struct Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Context,
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

    /// Provider cloned into each proposal after state sync.
    pub(super) provider: A::Provider,

    /// Marshal actor mailbox.
    pub(super) marshal: MarshalMailbox<S, V>,

    /// Durable state-sync metadata.
    pub(super) sync_metadata: StateSyncMetadata<E, S, V::Commitment>,

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

    /// Duration of each fixed-target sync window.
    pub(super) retarget_grace: Duration,

    /// Fixed marshal frontier being drained before the next sync window.
    pub(super) retarget_frontier: Option<Height>,

    /// Finalized messages held while the current target receives its sync window.
    pub(super) pending_retarget: Option<RetargetGrace<A::Block>>,

    /// Periodic prune configuration.
    pub(super) prune_config: Option<PruneConfig>,

    /// Metrics shared across syncing and processing.
    pub(super) metrics: StatefulMetrics,
}

impl<E, A, S, V, R> Syncing<E, A, S, V, R>
where
    E: Rng + Spawner + Context,
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
                let retarget_timeout = match self.pending_retarget.as_mut() {
                    Some(grace) => Either::Left(grace.timeout.as_mut()),
                    None => Either::Right(pending()),
                };
            },
            on_stopped => {
                debug!("processor received shutdown signal");
            },
            Ok(artifact) = &mut self.sync_completed else {
                error!("syncer stopped before publishing state sync artifact");
                break;
            } => {
                self.artifact = Some(artifact);
                let finalized = self
                    .pending_retarget
                    .take()
                    .map(|grace| grace.finalized)
                    .unwrap_or_default();
                let handoffs = self.prepare_handoffs(finalized);
                self.transition_many(handoffs).await;
                return;
            },
            _ = retarget_timeout => {
                let handoffs;
                (self, handoffs) = self.expire_retarget_grace().await;
                if let Some(handoffs) = handoffs {
                    self.transition_many(handoffs).await;
                    return;
                }
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
                    if let Some(grace) = self.pending_retarget.as_mut() {
                        grace.finalized.push_back((block, acknowledgement));
                        continue;
                    }
                    let process = info_span!(parent: &span, "stateful.actor.syncing_finalized");
                    let handoff;
                    (self, handoff) = self
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
        mut self,
        block: Arc<A::Block>,
        acknowledgement: Exact,
    ) -> (Self, Option<FinalizedHandoff<Arc<A::Block>>>) {
        if self.artifact.is_none() {
            let frontier;
            (self, frontier) = self.record_target(&block).await;
            let Some(frontier) = frontier else {
                return (self, None);
            };
            if self.artifact.is_none() {
                if block.height() < frontier {
                    acknowledgement.acknowledge();
                } else {
                    assert_eq!(block.height(), frontier);
                    self.arm_retarget_grace(VecDeque::from([(block, acknowledgement)]));
                }
                return (self, None);
            }
        }

        let handoffs = self.prepare_handoffs(VecDeque::from([(block, acknowledgement)]));
        let handoff = handoffs
            .into_iter()
            .next()
            .expect("one finalized block must produce one handoff");
        (self, Some(handoff))
    }

    /// Persist a fixed certified frontier, then record `block` as the live sync target.
    async fn record_target(mut self, block: &Arc<A::Block>) -> (Self, Option<Height>) {
        let frontier = match self.retarget_frontier {
            Some(frontier) => {
                assert!(
                    block.height() <= frontier,
                    "finalized block cannot advance past an unserved retarget frontier",
                );
                frontier
            }
            None => {
                let (frontier, _) = select! {
                    _ = self.context.stopped() => return (self, None),
                    latest = self.marshal.get_info(Identifier::Latest) => {
                        latest.expect("marshal must retain a certificate for each finalized block")
                    },
                };
                assert!(
                    frontier >= block.height(),
                    "certifying marshal tip cannot precede a finalized block",
                );
                let finalization = select! {
                    _ = self.context.stopped() => return (self, None),
                    finalization = self.marshal.get_finalization(frontier) => {
                        finalization.expect("latest finalized marshal block must have a certificate")
                    },
                };
                self.sync_metadata = self.sync_metadata.begin_sync(finalization).await;
                self.retarget_frontier = Some(frontier);
                frontier
            }
        };

        let artifact = select! {
            _ = self.context.stopped() => return (self, None),
            artifact = self.syncer.update_targets(
                Anchor::from(block.as_ref()),
                A::sync_targets(block.as_ref()),
            ) => artifact,
        };
        if let Some(artifact) = artifact {
            self.artifact = Some(artifact);
        }
        (self, Some(frontier))
    }

    /// Start one uninterrupted sync window without blocking the actor loop.
    fn arm_retarget_grace(&mut self, finalized: VecDeque<(Arc<A::Block>, Exact)>) {
        assert!(self.pending_retarget.is_none());
        assert!(!finalized.is_empty());

        self.pending_retarget = Some(RetargetGrace {
            timeout: Box::pin(self.context.sleep(self.retarget_grace)),
            finalized,
        });
    }

    /// Release an expired target and coalesce any finalized blocks received during its window.
    async fn expire_retarget_grace(
        mut self,
    ) -> (Self, Option<VecDeque<FinalizedHandoff<Arc<A::Block>>>>) {
        let mut grace = self
            .pending_retarget
            .take()
            .expect("retarget grace timer requires pending state");
        let (_, acknowledgement) = grace
            .finalized
            .pop_front()
            .expect("retarget grace requires a finalized block");
        acknowledgement.acknowledge();
        self.retarget_frontier = None;

        let Some((newest, _)) = grace.finalized.back() else {
            return (self, None);
        };
        let newest = newest.clone();
        let frontier;
        (self, frontier) = self.record_target(&newest).await;
        let Some(frontier) = frontier else {
            return (self, None);
        };
        if self.artifact.is_some() {
            let handoffs = self.prepare_handoffs(grace.finalized);
            return (self, Some(handoffs));
        }

        if newest.height() < frontier {
            for (_, acknowledgement) in grace.finalized {
                acknowledgement.acknowledge();
            }
            return (self, None);
        }

        assert_eq!(newest.height(), frontier);
        while grace.finalized.len() > 1 {
            let (_, acknowledgement) = grace.finalized.pop_front().expect("length checked above");
            acknowledgement.acknowledge();
        }
        self.arm_retarget_grace(grace.finalized);
        (self, None)
    }

    /// Classify finalized messages relative to the completed sync artifact.
    fn prepare_handoffs(
        &self,
        finalized: VecDeque<(Arc<A::Block>, Exact)>,
    ) -> VecDeque<FinalizedHandoff<Arc<A::Block>>> {
        let artifact = self
            .artifact
            .as_ref()
            .expect("sync artifact must exist after sync handoff");
        let mut previous_height = artifact.anchor.height;
        let mut reflected = false;
        let mut handoffs = VecDeque::with_capacity(finalized.len());

        for (block, acknowledgement) in finalized {
            if block.height() < artifact.anchor.height {
                handoffs.push_back(FinalizedHandoff::Covered(block, acknowledgement));
                continue;
            }
            if block.height() == artifact.anchor.height {
                assert!(!reflected, "sync anchor can be reflected only once");
                assert_eq!(
                    block.digest(),
                    artifact.anchor.digest,
                    "finalized block at sync anchor height must match sync anchor digest",
                );
                reflected = true;
                handoffs.push_back(FinalizedHandoff::Reflected(block, acknowledgement));
                continue;
            }

            assert_eq!(
                block.height(),
                previous_height.next(),
                "finalized block after sync anchor must be the next finalized block",
            );
            previous_height = block.height();
            handoffs.push_back(FinalizedHandoff::Apply(block, acknowledgement));
        }
        handoffs
    }

    /// Transitions to [`Processing`] state once the database set has converged
    /// on the state sync [`Anchor`].
    async fn transition(self, handoff: Option<FinalizedHandoff<Arc<A::Block>>>) {
        self.transition_many(handoff.into_iter().collect()).await;
    }

    async fn transition_many(mut self, mut handoffs: VecDeque<FinalizedHandoff<Arc<A::Block>>>) {
        let artifact = self.artifact.take().expect("transition must have artifact");
        let synced_height = artifact.anchor.height;

        let _ = self.metrics.sync_done.try_set(1);
        let mut processor = Processor::new(
            self.application,
            artifact.databases,
            artifact.anchor,
            self.metrics,
            self.prune_config,
        );

        self.sync_metadata = self.sync_metadata.set_complete(synced_height).await;

        while let Some(handoff) = handoffs.pop_front() {
            match handoff {
                FinalizedHandoff::Covered(block, acknowledgement)
                | FinalizedHandoff::Reflected(block, acknowledgement) => {
                    processor
                        .notify_finalized(self.context.as_present(), block.as_ref())
                        .await;
                    acknowledgement.acknowledge();
                }
                FinalizedHandoff::Apply(block, acknowledgement) => {
                    let Applied { barrier, prune } = processor
                        .finalize(self.context.as_present(), block.as_ref())
                        .await
                        .expect("sync handoff block cannot be a duplicate");

                    // The processing loop's flush pool does not exist yet, so
                    // observe the deferred flush inline. Acknowledging only
                    // once durable preserves the startup rewind contract.
                    if !barrier.durable().await {
                        // Runtime shutdown before the flush completed: marshal
                        // redelivers the block on the next startup.
                        return;
                    }
                    if let Some(prune) = prune {
                        prune.run(processor.databases_mut(), &self.marshal).await;
                    }
                    debug!(
                        height = block.height().get(),
                        "persisted finalized database batch during sync handoff"
                    );
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

        Processing {
            context: self.context,
            mailbox: self.mailbox,
            provider: self.provider,
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
    use super::{super::Mailbox as StatefulMailbox, FinalizedHandoff, Syncing};
    use crate::stateful::{
        actor::{
            metrics::Metrics as StatefulMetrics,
            syncer::{self, StateSyncMetadata, SyncResult},
        },
        db::{Anchor, AttachableResolver, Shared},
        tests::mocks::{
            TestApp, TestBlock, TestDb, TestScheme, TestVariant, anchor, test_databases,
        },
    };
    use commonware_actor::{Feedback, mailbox as actor_mailbox};
    use commonware_consensus::{
        Application as _, CertifiableBlock as _, Heightable, Reporter,
        marshal::{
            self, Update, ancestry,
            core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
            resolver::handler,
        },
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, FixedEpocher, Height, Round, View, ViewDelta},
    };
    use commonware_cryptography::{
        Digestible,
        certificate::ConstantProvider,
        ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_resolver::{Fetch, Resolver, TargetedResolver};
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Runner as _, Spawner as _,
        Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, next_pending_sync},
    };
    use commonware_storage::archive::{Archive as _, immutable};
    use commonware_utils::{
        Acknowledgement, NZU16, NZU64, NZUsize, acknowledgement::Exact, channel::oneshot,
        vec::NonEmptyVec,
    };
    use futures::{FutureExt, poll};
    use std::{collections::VecDeque, sync::Arc, time::Duration};

    const TEST_RETARGET_GRACE: Duration = Duration::from_secs(1);

    #[derive(Clone)]
    struct NoopResolver;

    impl<DB: Send + Sync + 'static> AttachableResolver<DB> for NoopResolver {
        async fn attach_database(&self, _db: Shared<DB>) {}
    }

    /// Reporter for the started marshal fixture that acknowledges every dispatched block.
    #[derive(Clone)]
    struct NoopReporter;

    impl Reporter for NoopReporter {
        type Activity = Update<TestBlock>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let Update::Block(_, ack) = activity {
                ack.acknowledge();
            }
            Feedback::Ok
        }
    }

    /// Backfill resolver for the started marshal fixture: its archives are pre-seeded, so
    /// every fetch is ignored.
    #[derive(Clone)]
    struct IgnoreResolver;

    impl Resolver for IgnoreResolver {
        type Key = handler::Key<Sha256Digest>;
        type Subscriber = handler::Annotation;

        fn fetch<F>(&mut self, _key: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _keys: Vec<F>) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn retain(
            &mut self,
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> Feedback {
            Feedback::Ok
        }
    }

    impl TargetedResolver for IgnoreResolver {
        type PublicKey = ed25519::PublicKey;

        fn fetch_targeted(
            &mut self,
            _fetch: impl Into<Fetch<Self::Key, Self::Subscriber>> + Send,
            _targets: NonEmptyVec<Self::PublicKey>,
        ) -> Feedback {
            Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            _keys: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }
    }

    /// Builds a finalization for `view` whose payload is the digest `[digest_byte; 32]`.
    fn finalization(
        schemes: &[TestScheme],
        view: u64,
        digest_byte: u8,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal {
            round: Round::new(Epoch::zero(), View::new(view)),
            parent: View::new(view.saturating_sub(1)),
            payload: Sha256::fill(digest_byte),
        };
        let finalizes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("sign finalize"))
            .collect::<Vec<_>>();
        Finalization::from_finalizes(&schemes[0], &finalizes, &Sequential)
            .expect("recover finalization")
    }

    struct TestHarness<E>
    where
        E: rand_core::Rng + commonware_runtime::Spawner + commonware_storage::Context,
    {
        syncing: Syncing<E, TestApp, TestScheme, TestVariant, NoopResolver>,
    }

    impl TestHarness<deterministic::Context> {
        async fn new(context: deterministic::Context, anchor: Anchor<Sha256Digest>) -> Self {
            Self::new_on(context.child("fixture"), context, anchor).await
        }

        /// Build the harness mid-sync: no artifact yet, the provided marshal mailbox, and a
        /// live syncer receiver for a coordinator mock to service.
        async fn new_syncing(
            context: deterministic::Context,
            marshal: MarshalMailbox<TestScheme, TestVariant>,
        ) -> (
            Self,
            StatefulMailbox<deterministic::Context, TestApp>,
            actor_mailbox::Receiver<syncer::mailbox::Message<deterministic::Context, TestApp>>,
            oneshot::Sender<SyncResult<deterministic::Context, TestApp>>,
        ) {
            let syncing_context = context.child("syncing_context");
            Self::new_syncing_on(context, syncing_context, marshal).await
        }
    }

    impl<E> TestHarness<E>
    where
        E: rand_core::Rng + commonware_runtime::Spawner + commonware_storage::Context,
    {
        async fn new_syncing_on(
            context: deterministic::Context,
            syncing_context: E,
            marshal: MarshalMailbox<TestScheme, TestVariant>,
        ) -> (
            Self,
            StatefulMailbox<E, TestApp>,
            actor_mailbox::Receiver<syncer::mailbox::Message<E, TestApp>>,
            oneshot::Sender<SyncResult<E, TestApp>>,
        ) {
            let (mailbox_sender, mailbox) =
                actor_mailbox::new(syncing_context.child("mailbox"), NZUsize!(1));
            let (syncer_sender, syncer_receiver) =
                actor_mailbox::new(syncing_context.child("syncer_mailbox"), NZUsize!(1));
            let (sync_complete, sync_completed) = oneshot::channel();

            let harness = Self {
                syncing: Syncing {
                    context: ContextCell::new(syncing_context.child("syncing")),
                    mailbox,
                    application: TestApp,
                    provider: (),
                    marshal,
                    sync_metadata: StateSyncMetadata::init(&syncing_context, "syncing-test").await,
                    syncer: syncer::Mailbox::new(syncer_sender),
                    held_verify_requests: Vec::new(),
                    database_subscribers: Vec::new(),
                    artifact: None,
                    resolvers: NoopResolver,
                    sync_completed,
                    retarget_grace: TEST_RETARGET_GRACE,
                    retarget_frontier: None,
                    pending_retarget: None,
                    prune_config: None,
                    metrics: StatefulMetrics::new(&context),
                },
            };
            (
                harness,
                StatefulMailbox::new(mailbox_sender),
                syncer_receiver,
                sync_complete,
            )
        }

        /// Build the harness with `syncing_context` owning the syncing actor and its
        /// state-sync metadata, while the marshal fixture runs on the plain `context`.
        async fn new_on(
            context: deterministic::Context,
            syncing_context: E,
            anchor: Anchor<Sha256Digest>,
        ) -> Self {
            let (_mailbox_sender, mailbox) =
                actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let (syncer_sender, _syncer_receiver) =
                actor_mailbox::new(context.child("syncer_mailbox"), NZUsize!(1));
            let (_sync_complete, sync_completed) = oneshot::channel();

            Self {
                syncing: Syncing {
                    context: ContextCell::new(syncing_context.child("syncing")),
                    mailbox,
                    application: TestApp,
                    provider: (),
                    marshal: init_marshal_mailbox(context.child("marshal")).await,
                    sync_metadata: StateSyncMetadata::init(&syncing_context, "syncing-test").await,
                    syncer: syncer::Mailbox::new(syncer_sender),
                    held_verify_requests: Vec::new(),
                    database_subscribers: Vec::new(),
                    artifact: Some(SyncResult {
                        databases: test_databases(),
                        anchor,
                    }),
                    resolvers: NoopResolver,
                    sync_completed,
                    retarget_grace: TEST_RETARGET_GRACE,
                    retarget_frontier: None,
                    pending_retarget: None,
                    prune_config: None,
                    metrics: StatefulMetrics::new(&context),
                },
            }
        }
    }

    fn archive_config(page_cache: CacheRef, partition: &str) -> immutable::Config<()> {
        immutable::Config {
            metadata_partition: format!("{partition}-metadata"),
            freezer_table_partition: format!("{partition}-freezer-table"),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 2,
            freezer_key_partition: format!("{partition}-freezer-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition}-freezer-value"),
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
                view_retention: ViewDelta::new(1),
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

    /// Initializes a marshal actor whose finalization archive is pre-seeded with the given
    /// block's finalization, then starts it so `get_finalization` serves the finalization
    /// without any peer fetching. The returned handler and handle must stay alive for the
    /// marshal to keep running.
    async fn start_marshal(
        context: deterministic::Context,
        scheme: TestScheme,
        block: &TestBlock,
        finalization: Option<Finalization<TestScheme, Sha256Digest>>,
    ) -> (
        MarshalMailbox<TestScheme, TestVariant>,
        handler::Handler<Sha256Digest>,
        Handle<()>,
    ) {
        let provider = ConstantProvider::new(scheme);
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
        let mut finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(page_cache.clone(), "syncing-finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        if let Some(finalization) = finalization {
            finalizations_by_height = finalizations_by_height
                .put(block.height().get(), block.digest(), finalization)
                .await
                .expect("failed to seed finalization")
                .sync()
                .await
                .expect("failed to sync finalizations archive");
        }
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), "syncing-blocks"),
        )
        .await
        .expect("failed to initialize blocks archive");

        let (actor, mailbox, _height) = MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
            context.child("marshal_actor"),
            finalizations_by_height,
            finalized_blocks,
            marshal::Config {
                provider,
                epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                start: marshal::Start::Genesis(TestBlock::new(0, 0)),
                partition_prefix: "syncing-harness".to_string(),
                mailbox_size: NZUsize!(8),
                view_retention: ViewDelta::new(1),
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
        let (resolver_receiver, resolver_handler) =
            handler::init(context.child("resolver_handler"), NZUsize!(8));
        let handle = actor.start_unbuffered(NoopReporter, (resolver_receiver, IgnoreResolver));
        (mailbox, resolver_handler, handle)
    }

    #[test]
    fn anchor_height_block_acknowledges_and_transitions_without_handoff() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context.child("harness"), anchor(7, 9)).await;
            let (acknowledgement, mut waiter) = Exact::handle();

            let (syncing, action) = harness
                .syncing
                .process_finalized(Arc::new(TestBlock::new(7, 9)), acknowledgement)
                .await;
            harness.syncing = syncing;

            assert!(poll!(&mut waiter).is_pending());
            assert!(matches!(action, Some(FinalizedHandoff::Reflected(_, _))));
            harness.syncing.transition(action).await;
            assert!(waiter.await.is_ok());
        });
    }

    #[test]
    fn next_height_block_transitions_with_handoff_without_early_ack() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, waiter) = Exact::handle();

            let (_syncing, action) = harness
                .syncing
                .process_finalized(Arc::new(TestBlock::new(8, 10)), acknowledgement)
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
    fn handoff_classification_orders_mixed_terminal_sequence() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(u64::MAX - 2, 9)).await;
            assert!(harness.syncing.prepare_handoffs(VecDeque::new()).is_empty());

            let mut finalized = VecDeque::new();
            for (height, digest) in [
                (u64::MAX - 3, 8),
                (u64::MAX - 2, 9),
                (u64::MAX - 1, 10),
                (u64::MAX, 11),
            ] {
                let (acknowledgement, _waiter) = Exact::handle();
                finalized.push_back((Arc::new(TestBlock::new(height, digest)), acknowledgement));
            }
            let mut handoffs = harness.syncing.prepare_handoffs(finalized);
            assert!(matches!(
                handoffs.pop_front(),
                Some(FinalizedHandoff::Covered(block, _))
                    if block.height() == Height::new(u64::MAX - 3)
            ));
            assert!(matches!(
                handoffs.pop_front(),
                Some(FinalizedHandoff::Reflected(block, _))
                    if block.height() == Height::new(u64::MAX - 2)
            ));
            for height in [u64::MAX - 1, u64::MAX] {
                assert!(matches!(
                    handoffs.pop_front(),
                    Some(FinalizedHandoff::Apply(block, _))
                        if block.height() == Height::new(height)
                ));
            }
            assert!(handoffs.is_empty());
        });
    }

    #[test]
    #[should_panic(expected = "sync anchor digest")]
    fn anchor_height_block_with_conflicting_digest_panics() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, _waiter) = Exact::handle();
            let _ = harness
                .syncing
                .process_finalized(Arc::new(TestBlock::new(7, 10)), acknowledgement)
                .await;
        });
    }

    #[test]
    #[should_panic(expected = "next finalized block")]
    fn non_anchor_non_next_block_panics() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(7, 9)).await;
            let (acknowledgement, _waiter) = Exact::handle();
            let _ = harness
                .syncing
                .process_finalized(Arc::new(TestBlock::new(9, 10)), acknowledgement)
                .await;
        });
    }

    #[test]
    fn transition_waits_for_metadata_and_database_durability_before_acknowledgement() {
        deterministic::Runner::default().start(|context| async move {
            // Gate the sync-complete metadata write and the handoff batch's flush independently.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let mut harness =
                TestHarness::new_on(context.child("harness"), delayed, anchor(7, 9)).await;
            let (flush_entered, flush_entered_rx) = oneshot::channel();
            let (release_flush, flush_released) = oneshot::channel();
            let flush = Handle::from_future(async move {
                let _ = flush_entered.send(());
                flush_released.await.unwrap_or(Err(RuntimeError::Closed))
            });
            harness
                .syncing
                .artifact
                .as_mut()
                .expect("harness must contain a sync artifact")
                .databases = Shared::new("test", TestDb::with_finalize(flush));
            let (acknowledgement, mut waiter) = Exact::handle();

            // Transition's first durability operation is the sync-complete metadata write.
            pending.arm();
            let transition = context.child("transition").spawn(move |_| {
                harness.syncing.transition(Some(FinalizedHandoff::Apply(
                    Arc::new(TestBlock::new(8, 10)),
                    acknowledgement,
                )))
            });
            let gate = next_pending_sync(&pending);
            gate.blocked
                .await
                .expect("transition must reach the sync-complete write");
            assert!(
                poll!(&mut waiter).is_pending(),
                "handoff must not be acknowledged while sync-complete metadata is blocked",
            );

            gate.release
                .send(Ok(()))
                .expect("transition must be waiting on the gate");

            select! {
                entered = flush_entered_rx => {
                    entered.expect("handoff must poll the database flush");
                },
                result = &mut waiter => {
                    panic!("handoff was acknowledged before its database flush: {result:?}");
                },
            }
            assert!(
                poll!(&mut waiter).is_pending(),
                "handoff must remain unacknowledged while its database flush is blocked",
            );
            release_flush
                .send(Ok(()))
                .expect("handoff must be waiting on the database flush");
            transition.await.expect("transition failed");
            waiter
                .await
                .expect("handoff acknowledgement should complete");

            // The completed height is durable: reopen the metadata partition.
            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), Some(Height::new(7)));
        });
    }

    #[test]
    fn current_tip_grace_keeps_actor_responsive_until_sync_completes() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let initial_finalization = finalization(&fixture.schemes, 8, 10);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &block,
                Some(initial_finalization),
            )
            .await;
            let (harness, mut mailbox, mut syncer_receiver, sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            let (retargeted, retargeted_rx) = oneshot::channel();
            let coordinator = context.child("coordinator").spawn(move |_| async move {
                for expected in [8, 8] {
                    let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                        syncer_receiver.recv().await
                    else {
                        panic!("retarget should send a target update to the syncer");
                    };
                    assert!(
                        response.send(None).is_ok(),
                        "response receiver should be alive"
                    );
                    let (anchor, targets) = update.record(|anchor, targets| (anchor, targets));
                    assert_eq!(anchor.height, Height::new(expected));
                    assert_eq!(targets, expected);
                }
                assert!(retargeted.send(()).is_ok());
            });

            let (acknowledgement, mut waiter) = Exact::handle();
            let (syncing, handoff) = harness
                .syncing
                .process_finalized(Arc::new(block.clone()), acknowledgement)
                .await;

            assert!(handoff.is_none());
            assert!(
                syncing.pending_retarget.is_some(),
                "the current tip should receive a sync window",
            );
            assert!(
                poll!(&mut waiter).is_pending(),
                "the current tip must remain unacknowledged during its sync window",
            );

            let actor = context
                .child("syncing_actor")
                .spawn(move |_| syncing.start());
            let proposal = TestBlock::new(9, 11);
            assert!(
                mailbox
                    .propose(
                        (context.child("proposal"), proposal.context()),
                        ancestry::from_iter([]),
                        (),
                    )
                    .await
                    .is_none(),
                "the syncing actor must reject proposals without waiting for the grace timer",
            );

            context.sleep(TEST_RETARGET_GRACE).await;
            assert!(
                waiter.await.is_ok(),
                "the expired target must be acknowledged"
            );

            // Redelivery after the first window receives another sync window.
            let (next_acknowledgement, mut next_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block), next_acknowledgement));
            retargeted_rx
                .await
                .expect("the redelivered target should be observed");
            assert!(
                poll!(&mut next_waiter).is_pending(),
                "the redelivered target must receive another sync window",
            );

            // Finalizations arriving during the window are held in order and handed off
            // together when sync completes. A proposal after each report fences the actor's
            // FIFO mailbox so the artifact cannot race ahead of the queued block.
            let mut queued_waiters = Vec::new();
            for (height, digest) in [(9, 11), (10, 12)] {
                let (acknowledgement, mut waiter) = Exact::handle();
                assert!(matches!(
                    mailbox.report(Update::Block(
                        Arc::new(TestBlock::new(height, digest)),
                        acknowledgement,
                    )),
                    Feedback::Ok
                ));
                let proposal = TestBlock::new(height + 10, digest + 10);
                assert!(
                    mailbox
                        .propose(
                            (context.child("queue_fence"), proposal.context()),
                            ancestry::from_iter([]),
                            (),
                        )
                        .await
                        .is_none()
                );
                assert!(
                    poll!(&mut waiter).is_pending(),
                    "queued finalization must wait for sync handoff",
                );
                queued_waiters.push(waiter);
            }

            assert!(
                sync_complete
                    .send(SyncResult {
                        databases: test_databases(),
                        anchor: anchor(8, 10),
                    })
                    .is_ok(),
                "syncing actor should still await the artifact",
            );
            drop(mailbox);
            actor.await.expect("syncing actor failed");
            assert!(
                next_waiter.await.is_ok(),
                "sync handoff must acknowledge the redelivered finalization",
            );
            for waiter in queued_waiters {
                assert!(
                    waiter.await.is_ok(),
                    "sync handoff must acknowledge each queued finalization",
                );
            }
            coordinator.await.expect("coordinator failed");
        });
    }

    #[test]
    fn retarget_grace_expiry_coalesces_to_newest_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let newest = TestBlock::new(10, 12);
            let newest_finalization = finalization(&fixture.schemes, 10, 12);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &newest,
                Some(newest_finalization.clone()),
            )
            .await;
            let (mut harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            let mut finalized = VecDeque::new();
            let mut waiters = VecDeque::new();
            for (height, digest) in [(8, 10), (9, 11), (10, 12)] {
                let (acknowledgement, waiter) = Exact::handle();
                finalized.push_back((Arc::new(TestBlock::new(height, digest)), acknowledgement));
                waiters.push_back(waiter);
            }
            harness.syncing.arm_retarget_grace(finalized);

            let expire = context
                .child("expire")
                .spawn(move |_| harness.syncing.expire_retarget_grace());
            let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("expiry must forward the newest target");
            };
            assert!(response.send(None).is_ok());

            assert!(waiters.pop_front().unwrap().await.is_ok());
            let mut intermediate_waiter = waiters.pop_front().unwrap();
            let mut newest_waiter = waiters.pop_front().unwrap();
            assert!(
                poll!(&mut intermediate_waiter).is_pending(),
                "an intermediate target must wait until the newest target is observed",
            );
            assert!(
                poll!(&mut newest_waiter).is_pending(),
                "the newest target must wait until it is observed",
            );
            assert!(waiters.is_empty());

            let (recorded, targets) = update.record(|anchor, targets| (anchor, targets));
            assert_eq!(recorded, anchor(10, 12));
            assert_eq!(targets, 10);

            let (syncing, handoffs) = expire.await.expect("grace expiry failed");
            assert!(handoffs.is_none());
            assert!(intermediate_waiter.await.is_ok());
            assert!(
                poll!(&mut newest_waiter).is_pending(),
                "the newest target must remain held for the next sync window",
            );
            let grace = syncing
                .pending_retarget
                .as_ref()
                .expect("the newest target must receive another sync window");
            assert_eq!(grace.finalized.len(), 1);
            assert_eq!(grace.finalized[0].0.height(), Height::new(10));
            assert_eq!(syncing.retarget_frontier, Some(Height::new(10)));
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                Some(&newest_finalization),
            );
        });
    }

    #[test]
    fn target_observation_cancels_cleanly_on_shutdown() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let finalization = finalization(&fixture.schemes, 8, 10);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &block,
                Some(finalization),
            )
            .await;
            let (harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            let (acknowledgement, waiter) = Exact::handle();
            let process = context.child("process_finalized").spawn(move |_| {
                harness
                    .syncing
                    .process_finalized(Arc::new(block), acknowledgement)
            });
            let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("retarget should reach target observation");
            };
            let pending_update = (update, response);

            let stopper = context.child("stopper");
            let stop = context.child("stop").spawn(|_| async move {
                stopper.stop(0, None).await.expect("runtime should stop");
            });

            let (syncing, handoff) = process.await.expect("retarget task should stop cleanly");
            assert!(handoff.is_none());
            assert!(
                waiter.await.is_err(),
                "shutdown must leave marshal to redeliver the unacknowledged block",
            );
            drop(syncing);
            drop(pending_update);
            stop.await.expect("stop task should finish");
        });
    }

    /// Acknowledging a retargeted finalization requires its certified floor to be durably
    /// recoverable.
    #[test]
    fn retarget_persists_floor_before_acknowledgement() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let finalization = finalization(&fixture.schemes, 8, 10);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &block,
                Some(finalization.clone()),
            )
            .await;
            let pending = PendingSyncs::default();
            let syncing_context = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let (harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing_on(context.child("harness"), syncing_context, marshal)
                    .await;

            let (acknowledgement, mut waiter) = Exact::handle();
            pending.arm();
            let process = context.child("retarget").spawn(move |_| {
                harness
                    .syncing
                    .process_finalized(Arc::new(block), acknowledgement)
            });

            let gate = next_pending_sync(&pending);
            gate.blocked.await.expect("retarget must persist its floor");
            assert!(
                syncer_receiver.try_recv().is_err(),
                "the sync engine must not observe a target before its floor is durable",
            );
            assert!(
                poll!(&mut waiter).is_pending(),
                "marshal must not be acknowledged before its floor is durable",
            );
            gate.release
                .send(Ok(()))
                .expect("retarget must be waiting on the metadata flush");

            let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("retarget should send a target update to the syncer");
            };
            assert!(
                response.send(None).is_ok(),
                "response receiver should be alive"
            );
            let (recorded, targets) = update.record(|anchor, targets| (anchor, targets));
            assert_eq!(recorded, anchor(8, 10));
            assert_eq!(targets, 8);

            let (syncing, action) = process.await.expect("retarget failed");

            assert!(action.is_none(), "retarget mid-sync must not hand off");
            assert!(poll!(&mut waiter).is_pending());
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                Some(&finalization),
                "retargeted floor must be persisted before marshal is acknowledged",
            );
            let (syncing, handoffs) = syncing.expire_retarget_grace().await;
            assert!(handoffs.is_none());
            assert!(waiter.await.is_ok(), "marshal must be acknowledged");
            assert_eq!(
                syncing.retarget_grace, TEST_RETARGET_GRACE,
                "timing out a target must not change the configured sync window",
            );
            drop(syncing);

            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.in_progress_floor(), Some(&finalization));
        });
    }

    /// A transitively finalized ancestor persists its certifying descendant before marshal is
    /// acknowledged.
    #[test]
    fn retarget_transitive_ancestor_persists_descendant_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let descendant = TestBlock::new(9, 11);
            let finalization = finalization(&fixture.schemes, 9, 11);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &descendant,
                Some(finalization.clone()),
            )
            .await;
            let pending = PendingSyncs::default();
            let syncing_context = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let (harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing_on(context.child("harness"), syncing_context, marshal)
                    .await;

            let (acknowledgement, mut waiter) = Exact::handle();
            pending.arm();
            let process = context.child("retarget").spawn(move |_| {
                harness
                    .syncing
                    .process_finalized(Arc::new(block), acknowledgement)
            });

            let gate = next_pending_sync(&pending);
            gate.blocked
                .await
                .expect("retarget must persist its descendant floor");
            assert!(
                syncer_receiver.try_recv().is_err(),
                "the sync engine must not observe the ancestor before its floor is durable",
            );
            assert!(
                poll!(&mut waiter).is_pending(),
                "marshal must not be acknowledged before the descendant floor is durable",
            );
            gate.release
                .send(Ok(()))
                .expect("retarget must be waiting on the metadata flush");

            let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("retarget should send a target update to the syncer");
            };
            assert!(
                response.send(None).is_ok(),
                "response receiver should be alive"
            );
            let (recorded, targets) = update.record(|anchor, targets| (anchor, targets));
            assert_eq!(recorded, anchor(8, 10));
            assert_eq!(targets, 8);

            let (syncing, action) = process.await.expect("retarget failed");

            assert!(action.is_none(), "retarget mid-sync must not hand off");
            assert!(waiter.await.is_ok(), "marshal must be acknowledged");
            assert_eq!(
                syncing.retarget_frontier,
                Some(Height::new(9)),
                "the certifying descendant must remain the fixed backlog frontier",
            );
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                Some(&finalization),
                "the descendant floor must cover the transitive target before acknowledgement",
            );
            drop(syncing);

            let plan =
                syncer::SyncPlan::<_, TestScheme, TestVariant>::init(&context, "syncing-test")
                    .await;
            assert_eq!(plan.floor(), Some(&finalization));
            assert!(matches!(
                plan.marshal_start(()),
                marshal::Start::Floor(ref floor) if floor == &finalization
            ));
        });
    }
}
