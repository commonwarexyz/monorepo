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
    Reflected(B),
    Apply(B),
}

pub(super) struct PendingRetarget<B> {
    timeout: BoxFuture<'static, ()>,
    finalized: VecDeque<Arc<B>>,
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

    /// How long state sync remains on a target before considering a newer finalized target.
    pub(super) retarget_delay: Duration,

    /// Highest finalized height covered by durable state-sync recovery metadata.
    pub(super) recovery_frontier: Option<Height>,

    /// Acknowledged finalizations not yet represented by a forwarded sync target.
    pub(super) pending_retarget: Option<PendingRetarget<A::Block>>,

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
                    Some(pending) => Either::Left(pending.timeout.as_mut()),
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
                    .into_iter()
                    .flat_map(|pending| pending.finalized);
                let handoffs = self.prepare_handoffs(finalized);
                self.transition(handoffs).await;
                return;
            },
            _ = retarget_timeout => {
                let handoffs;
                (self, handoffs) = self.handle_retarget_timeout().await;
                if let Some(handoffs) = handoffs {
                    self.transition(handoffs).await;
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
                    let process = info_span!(parent: &span, "stateful.actor.syncing_finalized");
                    let handoffs;
                    (self, handoffs) = self
                        .process_finalized(block, acknowledgement)
                        .instrument(process)
                        .await;
                    if let Some(handoffs) = handoffs {
                        self.transition(handoffs).await;
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
    ) -> (Self, Option<VecDeque<FinalizedHandoff<Arc<A::Block>>>>) {
        assert!(
            self.artifact.is_none(),
            "cached sync artifact must transition immediately",
        );

        let covered;
        (self, covered) = self.ensure_recovery_frontier(block.height()).await;
        if !covered {
            return (self, None);
        }
        acknowledgement.acknowledge();

        if let Some(pending) = self.pending_retarget.as_mut() {
            pending.finalized.push_back(block);
            return (self, None);
        }

        let observed;
        (self, observed) = self.update_target(&block).await;
        if !observed {
            return (self, None);
        }
        if self.artifact.is_none() {
            self.arm_retarget_timer();
            return (self, None);
        }

        let handoffs = self.prepare_handoffs([block]);
        (self, Some(handoffs))
    }

    /// Ensure restart can recover every finalized block through `height`.
    async fn ensure_recovery_frontier(mut self, height: Height) -> (Self, bool) {
        if self
            .recovery_frontier
            .is_some_and(|frontier| frontier >= height)
        {
            return (self, true);
        }

        let (frontier, _) = select! {
            _ = self.context.stopped() => return (self, false),
            latest = self.marshal.get_info(Identifier::Latest) => {
                latest.expect("marshal must retain a certificate for each finalized block")
            },
        };
        assert!(
            frontier >= height,
            "certifying marshal tip cannot precede a finalized block",
        );
        let finalization = select! {
            _ = self.context.stopped() => return (self, false),
            finalization = self.marshal.get_finalization(frontier) => {
                finalization.expect("latest finalized marshal block must have a certificate")
            },
        };
        self.sync_metadata = self.sync_metadata.begin_sync(finalization).await;
        self.recovery_frontier = Some(frontier);
        (self, true)
    }

    /// Record `block` as the live sync target.
    async fn update_target(mut self, block: &Arc<A::Block>) -> (Self, bool) {
        let artifact = select! {
            _ = self.context.stopped() => return (self, false),
            artifact = self.syncer.update_targets(
                Anchor::from(block.as_ref()),
                A::sync_targets(block.as_ref()),
            ) => artifact,
        };
        if let Some(artifact) = artifact {
            self.artifact = Some(artifact);
        }
        (self, true)
    }

    /// Start one uninterrupted sync window without blocking the actor loop.
    fn arm_retarget_timer(&mut self) {
        assert!(self.pending_retarget.is_none());

        self.pending_retarget = Some(PendingRetarget {
            timeout: Box::pin(self.context.sleep(self.retarget_delay)),
            finalized: VecDeque::new(),
        });
    }

    /// Forward the newest target accumulated during an expired sync window.
    async fn handle_retarget_timeout(
        mut self,
    ) -> (Self, Option<VecDeque<FinalizedHandoff<Arc<A::Block>>>>) {
        let pending = self
            .pending_retarget
            .take()
            .expect("retarget timer requires pending state");

        let Some(newest) = pending.finalized.back() else {
            return (self, None);
        };
        let newest = newest.clone();
        let observed;
        (self, observed) = self.update_target(&newest).await;
        if !observed {
            return (self, None);
        }
        if self.artifact.is_some() {
            let handoffs = self.prepare_handoffs(pending.finalized);
            return (self, Some(handoffs));
        }

        self.arm_retarget_timer();
        (self, None)
    }

    /// Classify finalized messages relative to the completed sync artifact.
    fn prepare_handoffs(
        &self,
        finalized: impl IntoIterator<Item = Arc<A::Block>>,
    ) -> VecDeque<FinalizedHandoff<Arc<A::Block>>> {
        let artifact = self
            .artifact
            .as_ref()
            .expect("sync artifact must exist after sync handoff");
        let finalized = finalized.into_iter();
        let mut previous_height = artifact.anchor.height;
        let mut handoffs = VecDeque::with_capacity(finalized.size_hint().0);

        for block in finalized {
            if block.height() == artifact.anchor.height {
                assert_eq!(
                    block.digest(),
                    artifact.anchor.digest,
                    "finalized block at sync anchor height must match sync anchor digest",
                );
                handoffs.push_back(FinalizedHandoff::Reflected(block));
                continue;
            }

            assert_eq!(
                block.height(),
                previous_height.next(),
                "finalized blocks must ascend consecutively from the sync anchor",
            );
            previous_height = block.height();
            handoffs.push_back(FinalizedHandoff::Apply(block));
        }
        handoffs
    }

    /// Transitions to [`Processing`] state once the database set has converged
    /// on the state sync [`Anchor`]. Handoff finalizations are already acknowledged
    /// and remain recoverable from the persisted state-sync floor until completion.
    async fn transition(
        mut self,
        handoffs: impl IntoIterator<Item = FinalizedHandoff<Arc<A::Block>>>,
    ) {
        let artifact = self.artifact.take().expect("transition must have artifact");
        let mut completed_height = artifact.anchor.height;

        let _ = self.metrics.sync_done.try_set(1);
        let mut processor = Processor::new(
            self.application,
            artifact.databases,
            artifact.anchor,
            self.metrics,
            self.prune_config,
        );

        let mut pending_prune = None;

        for handoff in handoffs {
            match handoff {
                FinalizedHandoff::Reflected(block) => {
                    processor
                        .notify_finalized(self.context.as_present(), block.as_ref())
                        .await;
                }
                FinalizedHandoff::Apply(block) => {
                    let Applied { barrier, prune } = processor
                        .finalize(self.context.as_present(), block.as_ref())
                        .await
                        .expect("sync handoff block cannot be a duplicate");

                    // The processing loop's flush pool does not exist yet, so observe the
                    // deferred flush inline. Keep state-sync metadata in progress until every
                    // handoff block is durable.
                    if !barrier.durable().await {
                        // Restart resumes state sync from the durable recovery floor.
                        return;
                    }
                    pending_prune = prune.or(pending_prune);
                    completed_height = block.height();
                    debug!(
                        height = block.height().get(),
                        "persisted finalized database batch during sync handoff"
                    );
                }
            }
        }

        self.sync_metadata = self.sync_metadata.set_complete(completed_height).await;
        if let Some(prune) = pending_prune {
            prune.run(processor.databases_mut(), &self.marshal).await;
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
            skip_finalized_until: Some(completed_height),
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
        tests::{
            fixtures::{self, MarshalFixture},
            mocks::{TestApp, TestBlock, TestDb, TestScheme, TestVariant, anchor, test_databases},
        },
    };
    use commonware_actor::{Feedback, mailbox as actor_mailbox};
    use commonware_consensus::{
        Application as _, CertifiableBlock as _, Heightable, Reporter as _,
        marshal::{self, Update, ancestry, core::Mailbox as MarshalMailbox},
        simplex::mocks::scheme as scheme_mocks,
        types::Height,
    };
    use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Runner as _, Spawner as _,
        Supervisor as _, deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, next_pending_sync},
    };
    use commonware_utils::{Acknowledgement, NZUsize, acknowledgement::Exact, channel::oneshot};
    use futures::poll;
    use std::{collections::VecDeque, sync::Arc, time::Duration};

    const TEST_RETARGET_DELAY: Duration = Duration::from_secs(1);

    #[derive(Clone)]
    struct NoopResolver;

    impl<DB: Send + Sync + 'static> AttachableResolver<DB> for NoopResolver {
        async fn attach_database(&self, _db: Shared<DB>) {}
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
                    retarget_delay: TEST_RETARGET_DELAY,
                    recovery_frontier: None,
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
            let mut marshal_context = context.child("marshal");
            let scheme = scheme_mocks::fixture(&mut marshal_context, b"syncing-harness", 1).schemes
                [0]
            .clone();
            let marshal =
                fixtures::marshal_fixture(marshal_context, "syncing-harness", scheme, None, false)
                    .await
                    .mailbox;
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
                    marshal,
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
                    retarget_delay: TEST_RETARGET_DELAY,
                    recovery_frontier: None,
                    pending_retarget: None,
                    prune_config: None,
                    metrics: StatefulMetrics::new(&context),
                },
            }
        }
    }

    #[test]
    fn handoff_classification_orders_mixed_terminal_sequence() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(u64::MAX - 2, 9)).await;
            assert!(harness.syncing.prepare_handoffs(VecDeque::new()).is_empty());

            let mut finalized = VecDeque::new();
            for (height, digest) in [(u64::MAX - 2, 9), (u64::MAX - 1, 10), (u64::MAX, 11)] {
                finalized.push_back(Arc::new(TestBlock::new(height, digest)));
            }
            let mut handoffs = harness.syncing.prepare_handoffs(finalized);
            assert!(matches!(
                handoffs.pop_front(),
                Some(FinalizedHandoff::Reflected(block))
                    if block.height() == Height::new(u64::MAX - 2)
            ));
            for height in [u64::MAX - 1, u64::MAX] {
                assert!(matches!(
                    handoffs.pop_front(),
                    Some(FinalizedHandoff::Apply(block))
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
            let _ = harness
                .syncing
                .prepare_handoffs([Arc::new(TestBlock::new(7, 10))]);
        });
    }

    #[test]
    #[should_panic(expected = "ascend consecutively from the sync anchor")]
    fn non_anchor_non_next_block_panics() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(7, 9)).await;
            let _ = harness
                .syncing
                .prepare_handoffs([Arc::new(TestBlock::new(9, 10))]);
        });
    }

    #[test]
    #[should_panic(expected = "ascend consecutively from the sync anchor")]
    fn below_anchor_block_panics() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(7, 9)).await;
            let _ = harness
                .syncing
                .prepare_handoffs([Arc::new(TestBlock::new(6, 8))]);
        });
    }

    #[test]
    fn transition_marks_complete_after_handoff_is_durable() {
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

            // Completion metadata must not be written until the handoff batch is durable.
            pending.arm();
            let gate = next_pending_sync(&pending);
            let transition = context.child("transition").spawn(move |_| {
                harness
                    .syncing
                    .transition(Some(FinalizedHandoff::Apply(Arc::new(TestBlock::new(
                        8, 10,
                    )))))
            });
            flush_entered_rx
                .await
                .expect("handoff must poll the database flush");
            assert_eq!(
                pending.calls(),
                0,
                "completion metadata must not be written before the handoff is durable",
            );
            release_flush
                .send(Ok(()))
                .expect("handoff must be waiting on the database flush");

            gate.blocked
                .await
                .expect("transition must persist sync completion after the database flush");
            gate.release
                .send(Ok(()))
                .expect("transition must be waiting on the metadata flush");

            transition.await.expect("transition failed");

            // The completed height is durable: reopen the metadata partition.
            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), Some(Height::new(8)));
        });
    }

    #[test]
    fn target_update_returning_artifact_hands_off_acknowledged_block() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let finalization = fixtures::finalization(&fixture, 8, Sha256::fill(10));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&block, finalization)),
                true,
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
                panic!("finalized block must update the sync target");
            };
            assert!(
                waiter.await.is_ok(),
                "the recoverable block must be acknowledged before target observation",
            );
            assert!(
                response
                    .send(Some(SyncResult {
                        databases: test_databases(),
                        anchor: anchor(7, 9),
                    }))
                    .is_ok(),
                "target update must still await its response",
            );
            drop(update);

            let (_syncing, handoffs) = process.await.expect("target update failed");
            let handoffs = handoffs.expect("returned artifact must hand off the block");
            assert_eq!(handoffs.len(), 1);
            assert!(matches!(
                handoffs.front(),
                Some(FinalizedHandoff::Apply(block)) if block.height() == Height::new(8)
            ));
        });
    }

    #[test]
    fn current_tip_window_keeps_actor_responsive_until_sync_completes() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let newest = TestBlock::new(10, 12);
            let initial_finalization = fixtures::finalization(&fixture, 10, Sha256::fill(12));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&newest, initial_finalization)),
                true,
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

            let (acknowledgement, waiter) = Exact::handle();
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
                waiter.await.is_ok(),
                "the current target must be acknowledged once it is recoverable",
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
                "the syncing actor must reject proposals without waiting for the retarget timer",
            );

            context.sleep(TEST_RETARGET_DELAY).await;

            // Redelivery after the first window receives another sync window.
            let (next_acknowledgement, next_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(block), next_acknowledgement));
            retargeted_rx
                .await
                .expect("the redelivered target should be observed");
            assert!(
                next_waiter.await.is_ok(),
                "the redelivered target must be acknowledged once it is recoverable",
            );

            // Finalizations arriving during the window are acknowledged once their recovery floor
            // is durable, but retained for handoff if sync completes before their coalesced target
            // is forwarded. A proposal after each report fences the actor's FIFO mailbox so the
            // artifact cannot race ahead of the queued block.
            for (height, digest) in [(9, 11), (10, 12)] {
                let (acknowledgement, waiter) = Exact::handle();
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
                    waiter.await.is_ok(),
                    "queued finalization must be acknowledged during the sync window",
                );
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
            coordinator.await.expect("coordinator failed");

            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), Some(Height::new(10)));
        });
    }

    #[test]
    fn retarget_timeout_coalesces_to_newest_target() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let newest = TestBlock::new(10, 12);
            let newest_finalization = fixtures::finalization(&fixture, 10, Sha256::fill(12));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&newest, newest_finalization.clone())),
                true,
            )
            .await;
            let (mut harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            let (acknowledgement, first_waiter) = Exact::handle();
            let first = context.child("first_target").spawn(move |_| {
                harness
                    .syncing
                    .process_finalized(Arc::new(TestBlock::new(8, 10)), acknowledgement)
            });
            let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("first target must be forwarded immediately");
            };
            assert!(
                first_waiter.await.is_ok(),
                "the first target must be acknowledged once its recovery floor is durable",
            );
            assert!(response.send(None).is_ok());
            let (recorded, targets) = update.record(|anchor, targets| (anchor, targets));
            assert_eq!(recorded, anchor(8, 10));
            assert_eq!(targets, 8);

            let (syncing, handoff) = first.await.expect("first target failed");
            assert!(handoff.is_none());
            harness.syncing = syncing;

            for (height, digest) in [(9, 11), (10, 12)] {
                let (acknowledgement, waiter) = Exact::handle();
                let (syncing, handoff) = harness
                    .syncing
                    .process_finalized(Arc::new(TestBlock::new(height, digest)), acknowledgement)
                    .await;
                assert!(handoff.is_none());
                assert!(
                    waiter.await.is_ok(),
                    "queued target must be acknowledged before the window expires",
                );
                harness.syncing = syncing;
            }
            let pending = harness
                .syncing
                .pending_retarget
                .as_ref()
                .expect("the first target must arm a sync window");
            assert_eq!(
                pending
                    .finalized
                    .iter()
                    .map(|block| block.height())
                    .collect::<Vec<_>>(),
                [Height::new(9), Height::new(10)],
            );
            assert!(
                syncer_receiver.try_recv().is_err(),
                "queued targets must not be forwarded before the window expires",
            );

            let expire = context
                .child("expire")
                .spawn(move |_| harness.syncing.handle_retarget_timeout());
            let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("expiry must forward the newest target");
            };
            assert!(response.send(None).is_ok());

            let (recorded, targets) = update.record(|anchor, targets| (anchor, targets));
            assert_eq!(recorded, anchor(10, 12));
            assert_eq!(targets, 10);

            let (syncing, handoffs) = expire.await.expect("retarget timer failed");
            assert!(handoffs.is_none());
            let pending = syncing
                .pending_retarget
                .as_ref()
                .expect("the newest target must receive another sync window");
            assert!(pending.finalized.is_empty());
            assert_eq!(syncing.recovery_frontier, Some(Height::new(10)));
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                Some(&newest_finalization),
            );
        });
    }

    #[test]
    fn target_observation_shutdown_preserves_acknowledged_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let finalization = fixtures::finalization(&fixture, 8, Sha256::fill(10));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&block, finalization.clone())),
                true,
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
            assert!(
                waiter.await.is_ok(),
                "target observation must not delay a recoverable acknowledgement",
            );

            let stopper = context.child("stopper");
            let stop = context.child("stop").spawn(|_| async move {
                stopper.stop(0, None).await.expect("runtime should stop");
            });

            let (syncing, handoff) = process.await.expect("retarget task should stop cleanly");
            assert!(handoff.is_none());
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                Some(&finalization),
                "the acknowledged block must remain covered after observation is canceled",
            );
            drop(syncing);
            drop(pending_update);
            stop.await.expect("stop task should finish");
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
            let finalization = fixtures::finalization(&fixture, 9, Sha256::fill(11));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&descendant, finalization.clone())),
                true,
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
                syncing.recovery_frontier,
                Some(Height::new(9)),
                "the certifying descendant must remain the recovery frontier",
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
