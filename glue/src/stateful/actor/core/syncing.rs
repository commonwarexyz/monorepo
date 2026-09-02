use crate::stateful::{
    Application, Finalized,
    actor::{
        core::{
            mailbox::Message, processing::Processing, verifications::Request as VerificationRequest,
        },
        metrics::Metrics as StatefulMetrics,
        processor::{Applied, PendingSyncTargets, Processor, Pruning},
        syncer::{self, StateSyncMetadata, SyncResult},
    },
    db::{Anchor, AttachableResolverSet, DatabaseSet as _},
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    Epochable, Heightable, Viewable,
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::{select, select_loop};
use commonware_runtime::{ContextCell, Spawner, telemetry::metrics::GaugeExt};
use commonware_storage::Context;
use commonware_utils::{
    Acknowledgement as _,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
};
use rand_core::Rng;
use std::{collections::VecDeque, sync::Arc};
use tracing::{Instrument as _, debug, error, info_span};

/// Finalized work needed to transition from syncing to processing.
enum FinalizedHandoff<B> {
    Covered(B, Exact),
    Reflected(B, Exact),
    Apply(B, Exact),
}

/// A finalized block retained with its marshal acknowledgement while state sync is active.
///
/// The acknowledgement remains paired with the block until either the full window's newest target
/// is recorded or the block is durably handed off after state sync completes.
pub(super) struct PendingFinalization<B> {
    block: B,
    acknowledgement: Exact,
}

/// Serves application requests while coordinating state sync and its handoff.
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

    /// Verification requests deferred until state sync completes.
    pub(super) deferred_verifications: Vec<VerificationRequest<E, A>>,

    /// Open subscriptions to the synced databases.
    pub(super) database_subscribers: Vec<oneshot::Sender<A::Databases>>,

    /// The cached [`SyncResult`], populated when sync completes.
    pub(super) artifact: Option<SyncResult<E, A>>,

    /// The state sync resolvers used for state sync fetching and post-bootstrap
    /// serving.
    pub(super) resolvers: R,

    /// Signals that the syncer has produced a usable artifact.
    pub(super) sync_completed: oneshot::Receiver<SyncResult<E, A>>,

    /// Unacknowledged finalizations retained until the window retargets or sync completes.
    pub(super) pending_finalizations: VecDeque<PendingFinalization<Arc<A::Block>>>,

    /// Periodic pruning state.
    pub(super) pruning: Option<Pruning<PendingSyncTargets<A, E>>>,

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
                self.deferred_verifications
                    .retain(|request| !request.verification.is_cancelled());
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
                let finalized = std::mem::take(&mut self.pending_finalizations);
                let handoffs = self.prepare_handoffs(finalized);
                self.transition(handoffs).await;
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
                    verification,
                } => {
                    let process = info_span!(parent: &span, "stateful.actor.verify.defer");
                    self.deferred_verifications
                        .retain(|request| !request.verification.is_cancelled());
                    self.deferred_verifications.push(VerificationRequest {
                        span,
                        context,
                        ancestry,
                        verification,
                    });
                    process.in_scope(|| {
                        debug!(
                            deferred_verifications = self.deferred_verifications.len(),
                            "verification deferred: state sync in progress"
                        );
                    });
                }
                Message::Finalized {
                    span,
                    block,
                    acknowledgement,
                    ..
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
        self.pending_finalizations.push_back(PendingFinalization {
            block,
            acknowledgement,
        });

        let max_pending_acks = self.marshal.max_pending_acks();
        if self.pending_finalizations.len() < max_pending_acks {
            return (self, None);
        }
        assert_eq!(
            self.pending_finalizations.len(),
            max_pending_acks,
            "marshal exceeded its configured pending acknowledgement window",
        );
        let newest = self
            .pending_finalizations
            .back()
            .expect("full acknowledgement window must contain a block")
            .block
            .clone();
        let observed;
        (self, observed) = self.update_target(&newest).await;
        if !observed {
            return (self, None);
        }
        if self.artifact.is_some() {
            let finalized = std::mem::take(&mut self.pending_finalizations);
            let handoffs = self.prepare_handoffs(finalized);
            return (self, Some(handoffs));
        }

        for pending in self.pending_finalizations.drain(..) {
            pending.acknowledgement.acknowledge();
        }
        (self, None)
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

    /// Classify finalized messages relative to the completed sync artifact.
    ///
    /// Marshal dispatches heights strictly ascending within one actor lifetime (redelivery
    /// happens only after a restart), and the artifact anchors at the newest recorded target,
    /// so handoff blocks reflect the anchor or extend it consecutively.
    fn prepare_handoffs(
        &self,
        finalized: impl IntoIterator<Item = PendingFinalization<Arc<A::Block>>>,
    ) -> VecDeque<FinalizedHandoff<Arc<A::Block>>> {
        let artifact = self
            .artifact
            .as_ref()
            .expect("sync artifact must exist after sync handoff");
        let finalized = finalized.into_iter();
        let mut previous_height = artifact.anchor.height;
        let mut handoffs = VecDeque::with_capacity(finalized.size_hint().0);

        for PendingFinalization {
            block,
            acknowledgement,
        } in finalized
        {
            if block.height() < artifact.anchor.height {
                handoffs.push_back(FinalizedHandoff::Covered(block, acknowledgement));
                continue;
            }
            if block.height() == artifact.anchor.height {
                assert_eq!(
                    block.digest(),
                    artifact.anchor.digest,
                    "finalized block at sync anchor height must match sync anchor digest",
                );
                handoffs.push_back(FinalizedHandoff::Reflected(block, acknowledgement));
                continue;
            }

            assert_eq!(
                block.height(),
                previous_height.next(),
                "finalized blocks must ascend consecutively from the sync anchor",
            );
            previous_height = block.height();
            handoffs.push_back(FinalizedHandoff::Apply(block, acknowledgement));
        }
        handoffs
    }

    /// Transitions to [`Processing`] state once the database set has converged
    /// on the state sync [`Anchor`].
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
            self.pruning,
        );

        let mut pending_prune = None;
        let mut pending_acknowledgements = Vec::new();

        for handoff in handoffs {
            match handoff {
                FinalizedHandoff::Covered(block, acknowledgement)
                | FinalizedHandoff::Reflected(block, acknowledgement) => {
                    processor
                        .notify_finalized(
                            self.context.as_present(),
                            block.as_ref(),
                            Finalized::Synchronized,
                        )
                        .await;
                    acknowledgement.acknowledge();
                }
                FinalizedHandoff::Apply(block, acknowledgement) => {
                    let Applied { prune, .. } = processor
                        .finalize(self.context.as_present(), block.as_ref(), false)
                        .await
                        .expect("sync handoff block cannot be a duplicate");
                    pending_acknowledgements.push(acknowledgement);
                    pending_prune = prune.or(pending_prune);
                    completed_height = block.height();
                }
            }
        }

        // Applied handoffs extend beyond the state-sync artifact. Release their acknowledgements
        // only after one barrier makes the entire suffix durable.
        if !pending_acknowledgements.is_empty() {
            let barrier = processor.databases().finalize().await;
            if !barrier.durable().await {
                return;
            }
            for acknowledgement in pending_acknowledgements {
                acknowledgement.acknowledge();
            }
            debug!(
                height = completed_height.get(),
                "persisted finalized database batches during sync handoff"
            );
        }

        // Completion is an irreversible startup floor. Persist it only after every handoff through
        // `completed_height` is durable and before pruning or exposing the databases.
        self.sync_metadata = self.sync_metadata.set_complete(completed_height).await;
        if let Some(prune) = pending_prune {
            prune.run(processor.databases(), &self.marshal).await;
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

        Processing {
            context: self.context,
            mailbox: self.mailbox,
            provider: self.provider,
            marshal: self.marshal,
            processor,
            deferred_verifications: self.deferred_verifications,
            skip_finalized_until: Some(completed_height),
        }
        .start()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{
        super::Mailbox as StatefulMailbox, FinalizedHandoff, PendingFinalization, Syncing,
    };
    use crate::stateful::{
        PruneConfig,
        actor::{
            metrics::Metrics as StatefulMetrics,
            processor::Pruning,
            syncer::{self, StateSyncMetadata, SyncResult},
        },
        db::{Anchor, AttachableResolver, Shared},
        tests::{
            fixtures::{self, MarshalFixture},
            mocks::{
                FlushControl, TestApp, TestBlock, TestDb, TestScheme, TestVariant, anchor,
                test_databases,
            },
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

    fn pending(block: TestBlock) -> PendingFinalization<Arc<TestBlock>> {
        let (acknowledgement, _waiter) = Exact::handle();
        PendingFinalization {
            block: Arc::new(block),
            acknowledgement,
        }
    }

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

        async fn advance_full_ack_window(
            mut self,
            context: &deterministic::Context,
            syncer_receiver: &mut actor_mailbox::Receiver<
                syncer::mailbox::Message<deterministic::Context, TestApp>,
            >,
        ) -> Self {
            let mut waiters = Vec::new();
            for (height, digest) in [(8, 10), (9, 11)] {
                let (acknowledgement, mut waiter) = Exact::handle();
                let mut process =
                    Box::pin(self.syncing.process_finalized(
                        Arc::new(TestBlock::new(height, digest)),
                        acknowledgement,
                    ));
                let std::task::Poll::Ready((syncing, handoff)) = poll!(process.as_mut()) else {
                    panic!("a partial acknowledgement window must not retarget");
                };
                assert!(handoff.is_none());
                assert!(poll!(&mut waiter).is_pending());
                assert!(syncer_receiver.try_recv().is_err());
                self.syncing = syncing;
                waiters.push(waiter);
            }

            let (acknowledgement, mut newest_waiter) = Exact::handle();
            let process = context.child("full_window").spawn(move |_| {
                self.syncing
                    .process_finalized(Arc::new(TestBlock::new(10, 12)), acknowledgement)
            });
            let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("a full acknowledgement window must retarget");
            };
            for waiter in &mut waiters {
                assert!(poll!(waiter).is_pending());
            }
            assert!(poll!(&mut newest_waiter).is_pending());
            assert!(response.send(None).is_ok());
            for waiter in &mut waiters {
                assert!(poll!(waiter).is_pending());
            }
            assert!(poll!(&mut newest_waiter).is_pending());
            update.record(|recorded, targets| {
                assert_eq!(recorded, anchor(10, 12));
                assert_eq!(targets, 10);
            });

            let (syncing, handoff) = process.await.expect("full acknowledgement window failed");
            assert!(handoff.is_none());
            for waiter in waiters {
                assert!(waiter.await.is_ok());
            }
            assert!(newest_waiter.await.is_ok());
            assert!(syncing.pending_finalizations.is_empty());
            Self { syncing }
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
                    deferred_verifications: Vec::new(),
                    database_subscribers: Vec::new(),
                    artifact: None,
                    resolvers: NoopResolver,
                    sync_completed,
                    pending_finalizations: VecDeque::new(),
                    pruning: None,
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
            let marshal = fixtures::marshal_fixture(
                marshal_context,
                "syncing-harness",
                scheme,
                None,
                NZUsize!(1),
                false,
            )
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
                    deferred_verifications: Vec::new(),
                    database_subscribers: Vec::new(),
                    artifact: Some(SyncResult {
                        databases: test_databases(),
                        anchor,
                    }),
                    resolvers: NoopResolver,
                    sync_completed,
                    pending_finalizations: VecDeque::new(),
                    pruning: None,
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
            for (height, digest) in [
                (u64::MAX - 3, 8),
                (u64::MAX - 2, 9),
                (u64::MAX - 1, 10),
                (u64::MAX, 11),
            ] {
                finalized.push_back(pending(TestBlock::new(height, digest)));
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
            let _ = harness
                .syncing
                .prepare_handoffs([pending(TestBlock::new(7, 10))]);
        });
    }

    #[test]
    #[should_panic(expected = "ascend consecutively from the sync anchor")]
    fn non_anchor_non_next_block_panics() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(7, 9)).await;
            let _ = harness
                .syncing
                .prepare_handoffs([pending(TestBlock::new(9, 10))]);
        });
    }

    #[test]
    fn handoff_classification_retains_block_covered_by_artifact() {
        deterministic::Runner::default().start(|context| async move {
            let harness = TestHarness::new(context, anchor(7, 9)).await;
            let handoffs = harness
                .syncing
                .prepare_handoffs([pending(TestBlock::new(6, 8))]);
            assert!(matches!(
                handoffs.front(),
                Some(FinalizedHandoff::Covered(block, _)) if block.height() == Height::new(6)
            ));
        });
    }

    #[test]
    fn transition_coalesces_handoff_durability_before_completion() {
        deterministic::Runner::default().start(|context| async move {
            // Gate the sync-complete metadata write and the handoff flush independently.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let mut harness =
                TestHarness::new_on(context.child("harness"), delayed, anchor(7, 9)).await;
            harness.syncing.pruning = Some(Pruning::build(
                PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                },
                harness.syncing.marshal.max_pending_acks(),
                0,
            ));
            let control = FlushControl::default();
            harness
                .syncing
                .artifact
                .as_mut()
                .expect("harness must contain a sync artifact")
                .databases = Shared::new("test", TestDb::gated(control.clone()));

            // Completion metadata must not be written until the handoff batch is durable.
            pending.arm();
            let gate = next_pending_sync(&pending);
            let (reflected_acknowledgement, mut reflected_waiter) = Exact::handle();
            let (first_acknowledgement, mut first_waiter) = Exact::handle();
            let (second_acknowledgement, mut second_waiter) = Exact::handle();
            let transition = context.child("transition").spawn(move |_| {
                harness.syncing.transition([
                    FinalizedHandoff::Reflected(
                        Arc::new(TestBlock::new(7, 9)),
                        reflected_acknowledgement,
                    ),
                    FinalizedHandoff::Apply(Arc::new(TestBlock::new(8, 10)), first_acknowledgement),
                    FinalizedHandoff::Apply(
                        Arc::new(TestBlock::new(9, 11)),
                        second_acknowledgement,
                    ),
                ])
            });
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert!(poll!(&mut reflected_waiter).is_ready());
            assert!(
                poll!(&mut first_waiter).is_pending() && poll!(&mut second_waiter).is_pending(),
            );
            assert_eq!(
                pending.calls(),
                0,
                "completion metadata must not be written before the handoff is durable",
            );
            let first_flush = control.flushes.lock().remove(0);
            first_flush
                .send(Ok(()))
                .expect("handoff must be waiting on its database flush");
            while control.flushes.lock().is_empty() && poll!(&mut second_waiter).is_pending() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert!(poll!(&mut first_waiter).is_ready());
            assert!(poll!(&mut second_waiter).is_ready());
            assert!(
                control.flushes.lock().is_empty(),
                "one database flush must cover the complete handoff prefix",
            );

            gate.blocked
                .await
                .expect("transition must persist sync completion after the database flush");
            gate.release
                .send(Ok(()))
                .expect("transition must be waiting on the metadata flush");

            transition.await.expect("transition failed");
            assert!(reflected_waiter.await.is_ok());
            assert!(first_waiter.await.is_ok());
            assert!(second_waiter.await.is_ok());
            assert_eq!(control.pruned.lock().as_slice(), &[8]);

            // The completed height is durable: reopen the metadata partition.
            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), Some(Height::new(9)));
        });
    }

    #[test]
    fn aborted_handoff_flush_cancels_ack_and_keeps_sync_incomplete() {
        deterministic::Runner::default().start(|context| async move {
            let mut harness = TestHarness::new(context.child("harness"), anchor(7, 9)).await;
            let databases = Shared::new(
                "test",
                TestDb::with_sync(Handle::ready(Err(RuntimeError::Aborted))),
            );
            harness
                .syncing
                .artifact
                .as_mut()
                .expect("harness must contain a sync artifact")
                .databases = databases;

            let (acknowledgement, waiter) = Exact::handle();
            harness
                .syncing
                .transition(Some(FinalizedHandoff::Apply(
                    Arc::new(TestBlock::new(8, 10)),
                    acknowledgement,
                )))
                .await;

            assert!(
                waiter.await.is_err(),
                "an aborted handoff must cancel marshal's acknowledgement",
            );
            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), None);
        });
    }

    #[test]
    fn target_update_returning_artifact_hands_off_pending_block() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let finalization = fixtures::finalization(&fixture, 8, Sha256::fill(10));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
                ..
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&block, finalization)),
                NZUsize!(1),
                true,
            )
            .await;
            let (harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            let (acknowledgement, mut waiter) = Exact::handle();
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
            assert!(poll!(&mut waiter).is_pending());
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
            let mut handoffs = handoffs.expect("returned artifact must hand off the block");
            assert_eq!(handoffs.len(), 1);
            let Some(FinalizedHandoff::Apply(block, acknowledgement)) = handoffs.pop_front() else {
                panic!("block above the artifact must be applied during handoff");
            };
            assert_eq!(block.height(), Height::new(8));
            assert!(poll!(&mut waiter).is_pending());
            acknowledgement.acknowledge();
            assert!(waiter.await.is_ok());
        });
    }

    #[test]
    fn partial_ack_window_keeps_actor_responsive_until_sync_completes() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let newest = TestBlock::new(10, 12);
            let initial_finalization = fixtures::finalization(&fixture, 10, Sha256::fill(12));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
                ..
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&newest, initial_finalization)),
                NZUsize!(3),
                true,
            )
            .await;
            let (harness, mut mailbox, mut syncer_receiver, sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            let actor = context
                .child("syncing_actor")
                .spawn(move |_| harness.syncing.start());
            let mut waiters = Vec::new();
            for (height, digest) in [(8, 10), (9, 11)] {
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
                    "a partial window must retain its acknowledgements",
                );
                waiters.push(waiter);
            }
            assert!(syncer_receiver.try_recv().is_err());

            assert!(
                sync_complete
                    .send(SyncResult {
                        databases: test_databases(),
                        anchor: anchor(7, 9),
                    })
                    .is_ok(),
                "syncing actor should still await the artifact",
            );
            drop(mailbox);
            actor.await.expect("syncing actor failed");
            for waiter in waiters {
                assert!(waiter.await.is_ok());
            }

            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), Some(Height::new(9)));
        });
    }

    #[test]
    fn partial_window_acknowledges_before_completion_metadata() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let initial = fixtures::finalization(&fixture, 7, Sha256::fill(9));
            let newest = TestBlock::new(9, 11);
            let newest_finalization = fixtures::finalization(&fixture, 9, Sha256::fill(11));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
                ..
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&newest, newest_finalization)),
                NZUsize!(3),
                true,
            )
            .await;
            let pending = PendingSyncs::default();
            pending.unblock();
            let syncing_context = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let queue_context = DelayedSyncContext {
                inner: context.child("queue_context"),
                pending: pending.clone(),
            };
            let (mut harness, mut mailbox, _syncer_receiver, sync_complete) =
                TestHarness::new_syncing_on(context.child("harness"), syncing_context, marshal)
                    .await;
            harness.syncing.sync_metadata = harness
                .syncing
                .sync_metadata
                .begin_sync(initial.clone())
                .await;
            let actor = context
                .child("syncing_actor")
                .spawn(move |_| harness.syncing.start());

            let mut waiters = Vec::new();
            for (height, digest) in [(8, 10), (9, 11)] {
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
                            (queue_context.child("queue_fence"), proposal.context()),
                            ancestry::from_iter([]),
                            (),
                        )
                        .await
                        .is_none()
                );
                assert!(poll!(&mut waiter).is_pending());
                waiters.push(waiter);
            }

            pending.arm();
            let completion_gate = next_pending_sync(&pending);
            assert!(
                sync_complete
                    .send(SyncResult {
                        databases: test_databases(),
                        anchor: anchor(7, 9),
                    })
                    .is_ok()
            );
            completion_gate
                .blocked
                .await
                .expect("partial handoff must reach completion metadata");
            for waiter in &mut waiters {
                assert!(
                    poll!(waiter).is_ready(),
                    "durable handoff should acknowledge before completion metadata",
                );
            }
            completion_gate
                .release
                .send(Ok(()))
                .expect("completion must be waiting on the metadata flush");

            drop(mailbox);
            actor.await.expect("syncing actor failed");

            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), Some(Height::new(9)));
        });
    }

    #[test]
    fn retarget_waits_for_ack_window_and_releases_batch_after_observation() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let newest = TestBlock::new(10, 12);
            let newest_finalization = fixtures::finalization(&fixture, 10, Sha256::fill(12));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
                ..
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&newest, newest_finalization)),
                NZUsize!(3),
                true,
            )
            .await;
            let (harness, mailbox, mut syncer_receiver, sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            let harness = harness
                .advance_full_ack_window(&context, &mut syncer_receiver)
                .await;
            let actor = context
                .child("syncing_actor")
                .spawn(move |_| harness.syncing.start());
            assert!(
                sync_complete
                    .send(SyncResult {
                        databases: test_databases(),
                        anchor: anchor(10, 12),
                    })
                    .is_ok()
            );
            drop(mailbox);
            actor.await.expect("syncing actor failed");

            let reopened =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncing-test")
                    .await;
            assert_eq!(reopened.sync_height(), Some(Height::new(10)));
        });
    }

    #[test]
    fn shutdown_after_live_retarget_keeps_initial_floor() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let initial = fixtures::finalization(&fixture, 7, Sha256::fill(9));
            let newest = TestBlock::new(10, 12);
            let newest_finalization = fixtures::finalization(&fixture, 10, Sha256::fill(12));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
                ..
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&newest, newest_finalization)),
                NZUsize!(3),
                true,
            )
            .await;
            let (mut harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            harness.syncing.sync_metadata = harness
                .syncing
                .sync_metadata
                .begin_sync(initial.clone())
                .await;
            let harness = harness
                .advance_full_ack_window(&context, &mut syncer_receiver)
                .await;
            assert_eq!(
                harness.syncing.sync_metadata.in_progress_floor(),
                Some(&initial),
            );

            // Drop all volatile retarget state after marshal has acknowledged the window.
            drop(harness);

            let plan =
                syncer::SyncPlan::<_, TestScheme, TestVariant>::init(&context, "syncing-test")
                    .await;
            assert!(
                plan.should_state_sync(false),
                "an interrupted sync must restart peer state sync",
            );
            let floor = plan
                .floor()
                .cloned()
                .expect("the initial state sync floor must survive restart");
            assert_eq!(floor, initial);
            assert!(matches!(
                plan.marshal_start(()),
                marshal::Start::Floor(ref selected) if selected == &floor
            ));
        });
    }

    #[test]
    fn target_observation_shutdown_keeps_floor_and_cancels_ack() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let initial = fixtures::finalization(&fixture, 7, Sha256::fill(9));
            let block = TestBlock::new(8, 10);
            let finalization = fixtures::finalization(&fixture, 8, Sha256::fill(10));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
                ..
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncing-harness",
                fixture.schemes[0].clone(),
                Some((&block, finalization.clone())),
                NZUsize!(1),
                true,
            )
            .await;
            let (mut harness, _mailbox, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            harness.syncing.sync_metadata = harness
                .syncing
                .sync_metadata
                .begin_sync(initial.clone())
                .await;

            let (acknowledgement, mut waiter) = Exact::handle();
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
                poll!(&mut waiter).is_pending(),
                "target observation must precede acknowledgement",
            );

            let stopper = context.child("stopper");
            let stop = context.child("stop").spawn(|_| async move {
                stopper.stop(0, None).await.expect("runtime should stop");
            });

            let (syncing, handoff) = process.await.expect("retarget task should stop cleanly");
            assert!(handoff.is_none());
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                Some(&initial),
                "target observation must not update durable state-sync metadata",
            );
            drop(syncing);
            drop(pending_update);
            assert!(
                waiter.await.is_err(),
                "shutdown must cancel the retained acknowledgement",
            );
            stop.await.expect("stop task should finish");
        });
    }
}
