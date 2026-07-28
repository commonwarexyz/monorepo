use crate::stateful::{
    Application, PruneConfig,
    actor::{
        core::{mailbox::Message, processing::Processing},
        metrics::Metrics as StatefulMetrics,
        processor::{Applied, Processor},
        syncer::{self, StateSyncMetadata, SyncResult},
    },
    db::{Anchor, DatabaseSet, Publisher, SnapshotOf},
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    Block, Epochable, Heightable, Viewable,
    marshal::{
        ancestry::{BlockProvider, BoxedAncestry},
        core::{Mailbox as MarshalMailbox, Variant},
    },
};
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_macros::select_loop;
use commonware_runtime::{ContextCell, Spawner, telemetry::metrics::GaugeExt};
use commonware_storage::Context;
use commonware_utils::{
    Acknowledgement,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot},
};
use rand_core::Rng;
use std::sync::Arc;
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
    Reflected(B, Exact),
    Apply(B, Exact),
}

pub(super) struct Syncing<E, A, S, V>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
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

    /// The cached [`SyncResult`], populated when sync completes.
    pub(super) artifact: Option<SyncResult<E, A>>,

    /// Signals that the syncer has produced a usable artifact.
    pub(super) sync_completed: oneshot::Receiver<SyncResult<E, A>>,

    /// Periodic prune configuration.
    pub(super) prune_config: Option<PruneConfig>,

    /// Metrics shared across syncing and processing.
    pub(super) metrics: StatefulMetrics,

    /// The actor's one publication handle; the synced initial snapshot installs here at
    /// transition, and it moves into [`Processing`] afterward.
    pub(super) publisher: Publisher<SnapshotOf<A::Databases, E>>,
}

impl<E, A, S, V> Syncing<E, A, S, V>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn start(mut self) {
        select_loop! {
            self.context,
            on_start => {
                self.held_verify_requests
                    .retain(|request| !request.response.is_closed());
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
            let anchor = Anchor::from(block.as_ref());
            let targets = A::sync_targets(block.as_ref());

            // Persist the retargeted floor before the live session can record it and before
            // marshal is acknowledged: the sync engine's durable state advances toward the
            // new target, and marshal prunes behind acknowledged blocks, so a crash must
            // resume from a floor at least as new as any target the engine acted on. An
            // ancestor finalized transitively by a descendant's certificate has no
            // finalization of its own; the floor then advances when the certificate-carrying
            // descendant is delivered. A crash inside that window resumes from the lagging
            // floor, which the sync journal may have durably outrun (recovery then requires
            // a newer floor).
            if let Some(finalization) = self.marshal.get_finalization(block.height()).await {
                self.sync_metadata = self.sync_metadata.begin_sync(finalization).await;
            }

            // Do not acknowledge marshal until the live sync session has recorded this
            // block's tip update. If we ack after merely enqueueing it, sync can still
            // complete on the previous anchor and handoff would observe marshal ahead of
            // `artifact.anchor.height.next()`.
            match self.syncer.update_targets(anchor, targets).await {
                Some(syncer::Artifact::Delivered(artifact)) => self.artifact = Some(artifact),
                Some(syncer::Artifact::Announced) => {
                    let artifact = (&mut self.sync_completed)
                        .await
                        .expect("announced sync artifact must arrive on the completion channel");
                    self.artifact = Some(artifact);
                }
                None => {
                    acknowledgement.acknowledge();
                    return (self, None);
                }
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
            return (
                self,
                Some(FinalizedHandoff::Reflected(block, acknowledgement)),
            );
        }

        assert_eq!(
            block.height(),
            artifact.anchor.height.next(),
            "finalized block after sync anchor must be the next finalized block",
        );
        (self, Some(FinalizedHandoff::Apply(block, acknowledgement)))
    }

    /// Transitions to [`Processing`] state once the database set has converged
    /// on the state sync [`Anchor`].
    async fn transition(mut self, handoff: Option<FinalizedHandoff<Arc<A::Block>>>) {
        let artifact = self.artifact.take().expect("transition must have artifact");
        let synced_height = artifact.anchor.height;

        let _ = self.metrics.sync_done.try_set(1);
        // Install the synced committed state as generation zero so serving can begin
        // before the first finalization; synced state is durable by construction.
        let mut publisher = self.publisher;
        let (databases, synced) = artifact.databases.snapshot().await;
        publisher.install_durable(synced);
        let mut processor = Processor::new(
            self.application,
            databases,
            artifact.anchor,
            self.metrics,
            self.prune_config,
        );

        self.sync_metadata = self.sync_metadata.set_complete(synced_height).await;

        if let Some(handoff) = handoff {
            match handoff {
                FinalizedHandoff::Reflected(block, acknowledgement) => {
                    processor
                        .notify_finalized(self.context.as_present(), block.as_ref())
                        .await;
                    acknowledgement.acknowledge();
                }
                FinalizedHandoff::Apply(block, acknowledgement) => {
                    let (returned, applied) = processor
                        .finalize(self.context.as_present(), block.as_ref())
                        .await;
                    processor = returned;
                    let Applied {
                        snapshot,
                        barrier,
                        prune,
                    } = applied.expect("sync handoff block cannot be a duplicate");

                    // The processing loop's flush pool does not exist yet, so
                    // observe the deferred flush inline. Acknowledging only
                    // once durable preserves the startup rewind contract.
                    let staged = publisher.stage(snapshot);
                    if !barrier.durable().await {
                        // Runtime shutdown before the flush completed: marshal
                        // redelivers the block on the next startup.
                        return;
                    }
                    staged.install();
                    debug!(
                        height = block.height().get(),
                        "persisted finalized database batch during sync handoff"
                    );
                    acknowledgement.acknowledge();
                    if let Some(prune) = prune {
                        processor = processor.prune_databases(prune, &self.marshal).await;
                    }
                }
            }
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
            publisher,
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
        db::Anchor,
        tests::mocks::{
            TestApp, TestBlock, TestScheme, TestVariant, anchor, init_marshal_mailbox,
            start_marshal, test_databases,
        },
    };
    use commonware_actor::mailbox as actor_mailbox;
    use commonware_consensus::{
        Heightable,
        marshal::core::Mailbox as MarshalMailbox,
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        ContextCell, Runner as _, Spawner as _, Supervisor as _, deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, next_pending_sync},
    };
    use commonware_utils::{Acknowledgement, NZUsize, acknowledgement::Exact, channel::oneshot};
    use futures::{FutureExt, poll};
    use std::sync::Arc;

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
        syncing: Syncing<E, TestApp, TestScheme, TestVariant>,
    }

    impl TestHarness<deterministic::Context> {
        async fn new(context: deterministic::Context, anchor: Anchor<Sha256Digest>) -> Self {
            Self::new_on(context.child("fixture"), context, anchor).await
        }

        /// Build the harness mid-sync: no artifact yet, the provided marshal mailbox, a
        /// live syncer receiver for a coordinator mock to service, and the completion
        /// sender announced artifacts arrive on.
        async fn new_syncing(
            context: deterministic::Context,
            marshal: MarshalMailbox<TestScheme, TestVariant>,
        ) -> (
            Self,
            actor_mailbox::Receiver<syncer::mailbox::Message<deterministic::Context, TestApp>>,
            oneshot::Sender<SyncResult<deterministic::Context, TestApp>>,
        ) {
            let (_mailbox_sender, mailbox) =
                actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let (syncer_sender, syncer_receiver) =
                actor_mailbox::new(context.child("syncer_mailbox"), NZUsize!(1));
            let (sync_complete, sync_completed) = oneshot::channel();

            let harness = Self {
                syncing: Syncing {
                    context: ContextCell::new(context.child("syncing")),
                    mailbox,
                    application: TestApp,
                    provider: (),
                    marshal,
                    sync_metadata: StateSyncMetadata::init(&context, "syncing-test").await,
                    syncer: syncer::Mailbox::new(syncer_sender),
                    held_verify_requests: Vec::new(),
                    artifact: None,
                    sync_completed,
                    prune_config: None,
                    metrics: StatefulMetrics::new(&context),
                    publisher: crate::stateful::db::Publisher::new(&context).0,
                },
            };
            (harness, syncer_receiver, sync_complete)
        }
    }

    impl<E> TestHarness<E>
    where
        E: rand_core::Rng + commonware_runtime::Spawner + commonware_storage::Context,
    {
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
                    artifact: Some(SyncResult {
                        databases: test_databases(),
                        anchor,
                    }),
                    sync_completed,
                    prune_config: None,
                    metrics: StatefulMetrics::new(&context),
                    publisher: crate::stateful::db::Publisher::new(&context).0,
                },
            }
        }
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
    fn transition_marks_sync_complete_before_handoff_acknowledgement() {
        deterministic::Runner::default().start(|context| async move {
            // Gate the sync-complete metadata write at the storage layer so the
            // acknowledgement ordering is observable.
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context.child("delayed"),
                pending: pending.clone(),
            };
            let harness =
                TestHarness::new_on(context.child("harness"), delayed, anchor(7, 9)).await;
            let (acknowledgement, mut waiter) = Exact::handle();

            // Arm the gate: transition's first durability operation (the sync-complete
            // metadata write) blocks until the test releases it.
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

    /// A retargeted finalization persists its floor before marshal is acknowledged: the sync
    /// engine's durable state advances toward the new target, so a crash after the ack must
    /// resume from the new floor, not the original one.
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
            let (harness, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            // Service the single target update like a live sync coordinator: respond that
            // sync has not completed, then record the tip update.
            let coordinator = context.child("coordinator").spawn(move |_| async move {
                let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                    syncer_receiver.recv().await
                else {
                    panic!("retarget should send a target update to the syncer");
                };
                assert!(
                    response.send(None).is_ok(),
                    "response receiver should be alive"
                );
                let (recorded, targets) = update.record();
                assert_eq!(recorded, anchor(8, 10));
                assert_eq!(targets, 8);
            });

            let (acknowledgement, waiter) = Exact::handle();
            let (syncing, action) = harness
                .syncing
                .process_finalized(Arc::new(block), acknowledgement)
                .await;

            assert!(action.is_none(), "retarget mid-sync must not hand off");
            assert!(waiter.await.is_ok(), "marshal must be acknowledged");
            coordinator.await.expect("coordinator failed");
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                Some(&finalization),
                "retargeted floor must be persisted before marshal is acknowledged",
            );
        });
    }

    /// An ancestor finalized transitively by a descendant's certificate has no finalization
    /// of its own: the retarget still records the tip update and acknowledges marshal, and
    /// the persisted floor is left unchanged.
    #[test]
    fn retarget_without_finalization_acknowledges_without_persisting() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &block,
                None,
            )
            .await;
            let (harness, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            // Service the single target update like a live sync coordinator.
            let coordinator = context.child("coordinator").spawn(move |_| async move {
                let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                    syncer_receiver.recv().await
                else {
                    panic!("retarget should send a target update to the syncer");
                };
                assert!(
                    response.send(None).is_ok(),
                    "response receiver should be alive"
                );
                let _ = update.record();
            });

            let (acknowledgement, waiter) = Exact::handle();
            let (syncing, action) = harness
                .syncing
                .process_finalized(Arc::new(block), acknowledgement)
                .await;

            assert!(action.is_none(), "retarget mid-sync must not hand off");
            assert!(waiter.await.is_ok(), "marshal must be acknowledged");
            coordinator.await.expect("coordinator failed");
            assert_eq!(
                syncing.sync_metadata.in_progress_floor(),
                None,
                "an uncertified ancestor must not move the persisted floor",
            );
        });
    }

    /// A retarget that races sync completion on the syncer's side: the tip-update
    /// channel closed, so the syncer awaited its task and delivered the artifact
    /// with the response. The block at the anchor height must hand off.
    #[test]
    fn retarget_racing_completion_receives_delivered_artifact() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &block,
                None,
            )
            .await;
            let (harness, mut syncer_receiver, _sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            // The syncer converged before recording this update: it drops the
            // update and delivers the artifact on the response.
            let coordinator = context.child("coordinator").spawn(move |_| async move {
                let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                    syncer_receiver.recv().await
                else {
                    panic!("retarget should send a target update to the syncer");
                };
                drop(update);
                let delivered = SyncResult::<deterministic::Context, TestApp> {
                    databases: test_databases(),
                    anchor: anchor(8, 10),
                };
                assert!(
                    response
                        .send(Some(syncer::Artifact::Delivered(delivered)))
                        .is_ok(),
                    "response receiver should be alive"
                );
            });

            let (acknowledgement, waiter) = Exact::handle();
            let (syncing, action) = harness
                .syncing
                .process_finalized(Arc::new(block), acknowledgement)
                .await;

            coordinator.await.expect("coordinator failed");
            assert!(
                matches!(action, Some(FinalizedHandoff::Reflected(_, _))),
                "the anchor-height block must hand off as already reflected",
            );
            assert_eq!(
                syncing.artifact.expect("artifact must be stored").anchor,
                anchor(8, 10),
            );
            assert!(
                waiter.now_or_never().is_none(),
                "the handoff acknowledgement fires at transition, not before",
            );
        });
    }

    /// The other side of the race: sync completed and the artifact already went
    /// out on the completion channel, so the syncer only announces it and the
    /// retarget collects it from that channel.
    #[test]
    fn retarget_racing_completion_collects_announced_artifact() {
        deterministic::Runner::default().start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncing-harness", 1);
            let block = TestBlock::new(8, 10);
            let (marshal, _resolver_handler, _marshal_handle) = start_marshal(
                context.child("marshal"),
                fixture.schemes[0].clone(),
                &block,
                None,
            )
            .await;
            let (harness, mut syncer_receiver, sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            // The artifact already went out on the completion channel; the
            // syncer only announces it.
            let coordinator = context.child("coordinator").spawn(move |_| async move {
                let Some(syncer::mailbox::Message::UpdateTargets { update, response }) =
                    syncer_receiver.recv().await
                else {
                    panic!("retarget should send a target update to the syncer");
                };
                drop(update);
                let completed = SyncResult::<deterministic::Context, TestApp> {
                    databases: test_databases(),
                    anchor: anchor(8, 10),
                };
                assert!(
                    sync_complete.send(completed).is_ok(),
                    "completion receiver should be alive"
                );
                assert!(
                    response.send(Some(syncer::Artifact::Announced)).is_ok(),
                    "response receiver should be alive"
                );
            });

            let (acknowledgement, waiter) = Exact::handle();
            let (syncing, action) = harness
                .syncing
                .process_finalized(Arc::new(block), acknowledgement)
                .await;

            coordinator.await.expect("coordinator failed");
            assert!(
                matches!(action, Some(FinalizedHandoff::Reflected(_, _))),
                "the anchor-height block must hand off as already reflected",
            );
            assert_eq!(
                syncing.artifact.expect("artifact must be stored").anchor,
                anchor(8, 10),
            );
            assert!(
                waiter.now_or_never().is_none(),
                "the handoff acknowledgement fires at transition, not before",
            );
        });
    }
}
