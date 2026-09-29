//! The state-sync phase of the stateful actor.
//!
//! Finalized blocks are retained with their acknowledgements while a sync runs.
//! Each time marshal's ack window fills, the newest retained block becomes the
//! live sync target and the whole window is acknowledged once the sync engines
//! observe that target. When sync completes, retained blocks are classified
//! against the artifact's anchor, applied durably, and the loop hands off to
//! [`Processing`].

use crate::stateful::{
    Application,
    actor::{
        SyncTargets,
        core::{
            mailbox::Message, processing::Processing, verifications::Request as VerificationRequest,
        },
        metrics::Metrics as StatefulMetrics,
        processor::{Processor, Pruning, Publication},
        syncer::{self, Artifact, SyncPlan},
    },
    db::{Anchor, DatabaseSet as _, Publisher, SnapshotsOf},
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    CertifiableBlock, Epochable, Heightable, Viewable,
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
use futures::FutureExt as _;
use rand_core::Rng;
use std::{collections::VecDeque, mem, sync::Arc};
use tracing::{Instrument as _, debug, error, info_span, warn};

/// A retained finalization classified against the converged sync anchor.
///
/// Covered and reflected blocks are already in the synced state and are acknowledged without
/// running application hooks.
enum FinalizedHandoff<B> {
    /// A block below the anchor.
    Covered(B, Exact),
    /// The block at the anchor.
    Reflected(B, Exact),
    /// A block above the anchor, or a duplicate report of one. Each block is applied once, and
    /// every receipt is acknowledged after the handoff barrier completes.
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
    /// Startup plan carrying the durable sync decision and selected floor.
    pub(super) plan: SyncPlan<E, S, V>,
    /// Syncer actor mailbox.
    pub(super) syncer: syncer::Mailbox<E, A>,

    /// Verification requests deferred until state sync completes.
    pub(super) deferred_verifications: Vec<VerificationRequest<E, A>>,

    /// Publishes the latest snapshots.
    pub(super) snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,

    /// Receives the converged [`Artifact`] from the syncer.
    pub(super) completion: oneshot::Receiver<Artifact<E, A>>,

    /// Unacknowledged finalizations retained until the window retargets or sync completes.
    pub(super) pending_finalizations: VecDeque<PendingFinalization<Arc<A::Block>>>,

    /// Periodic pruning state, if enabled.
    pub(super) pruning: Option<Pruning<SyncTargets<A, E>>>,
    /// Metrics shared across syncing and processing.
    pub(super) metrics: StatefulMetrics,
}

impl<E, A, S, V> Syncing<E, A, S, V>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    pub async fn run(mut self) {
        let mut converged = None;
        select_loop! {
            self.context,
            on_start => {
                self.deferred_verifications
                    .retain(|request| !request.verification.is_cancelled());
            },
            on_stopped => {
                debug!("syncing loop received shutdown signal");
            },
            Ok(artifact) = &mut self.completion else {
                error!("syncer stopped before publishing state sync artifact");
                break;
            } => {
                let handoffs =
                    classify(artifact.anchor, mem::take(&mut self.pending_finalizations));
                converged = Some((artifact, handoffs));
                break;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down syncing loop");
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
                } => {
                    let process = info_span!(parent: &span, "stateful.actor.syncing_finalized");
                    let handoff;
                    (self, handoff) = self
                        .finalized(block, acknowledgement)
                        .instrument(process)
                        .await;
                    if handoff.is_some() {
                        converged = handoff;
                        break;
                    }
                }
            },
        }

        // Hand off after the loop, so its stop signal is not held for the node's lifetime.
        if let Some((artifact, handoffs)) = converged {
            self.transition(artifact, handoffs).await;
        }
    }

    /// Retains `block` with its acknowledgement and advances the sync target once marshal's
    /// pending acknowledgement window is full.
    ///
    /// A full window records its newest block as the sync target and then acknowledges every
    /// retained block. Returns the converged [`Artifact`] with the classified handoffs if state
    /// sync finished first, and no handoff otherwise (including when the actor stops while
    /// retargeting). Panics if marshal delivers more blocks than its window.
    async fn finalized(
        mut self,
        block: Arc<A::Block>,
        acknowledgement: Exact,
    ) -> (
        Self,
        Option<(Artifact<E, A>, VecDeque<FinalizedHandoff<Arc<A::Block>>>)>,
    ) {
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

        let outcome = select! {
            _ = self.context.stopped() => return (self, None),
            outcome = self.syncer.retarget(
                Anchor::from(newest.as_ref()),
                A::sync_targets(newest.as_ref()),
            ) => outcome,
        };
        // The syncer exits only on shutdown, which can fire while `retarget` is polled.
        let Some(outcome) = outcome else {
            assert!(
                self.context.stopped().now_or_never().is_some(),
                "syncer stopped unexpectedly"
            );
            return (self, None);
        };
        if outcome == syncer::UpdateOutcome::SyncCompleted {
            // The syncer sent the artifact on the completion channel. Collect it here so the
            // retained finalizations are handed off under the newest recorded target.
            let artifact = select! {
                _ = self.context.stopped() => return (self, None),
                artifact = &mut self.completion => match artifact {
                    Ok(artifact) => artifact,
                    Err(_) => {
                        // The consumed receiver must not be polled again. Leave a dead one so
                        // the loop's completion arm logs and stops.
                        self.completion = oneshot::channel().1;
                        return (self, None);
                    }
                },
            };
            let handoffs = classify(artifact.anchor, mem::take(&mut self.pending_finalizations));
            return (self, Some((artifact, handoffs)));
        }

        for pending in self.pending_finalizations.drain(..) {
            pending.acknowledgement.acknowledge();
        }
        (self, None)
    }

    /// Hands the converged state to [`Processing`].
    ///
    /// Returns without recording completion if shutdown interrupts the handoff or its barrier is
    /// not durable.
    async fn transition(
        self,
        artifact: Artifact<E, A>,
        handoffs: impl IntoIterator<Item = FinalizedHandoff<Arc<A::Block>>>,
    ) {
        let Self {
            context,
            mailbox,
            application,
            provider,
            marshal,
            plan,
            syncer,
            deferred_verifications,
            mut snapshot_publisher,
            completion,
            pending_finalizations,
            pruning,
            metrics,
        } = self;
        // Nothing retargets or awaits the syncer from here on. Dropping its mailbox lets it exit.
        drop((syncer, completion, pending_finalizations));
        let Artifact { databases, anchor } = artifact;
        let mut completed_height = anchor.height;

        let mut processor =
            Processor::new(application, databases, anchor, metrics.clone(), pruning);

        // One signal for the whole handoff. Re-creating it per block would
        // record an extra auditor event on the deterministic runtime each time.
        let mut shutdown = context.stopped();

        // Serving must not wait for the next finalization, so the synced state
        // alone publishes first.
        select! {
            _ = &mut shutdown => {
                warn!(height = completed_height.get(), "exiting mid-handoff on shutdown");
                return;
            },
            driven = processor.publish_snapshot(&mut snapshot_publisher) => {
                processor = driven;
            },
        }

        let mut pending_prune = None;
        let mut pending_acknowledgements = Vec::new();

        for handoff in handoffs {
            match handoff {
                FinalizedHandoff::Covered(_, acknowledgement)
                | FinalizedHandoff::Reflected(_, acknowledgement) => {
                    acknowledgement.acknowledge();
                }
                FinalizedHandoff::Apply(block, acknowledgement) => {
                    if !processor.redelivered(block.as_ref()) {
                        // Exiting on stop leaves the block unacknowledged, and
                        // marshal redelivers it after a restart.
                        let applied;
                        select! {
                            _ = &mut shutdown => {
                                warn!(
                                    height = block.height().get(),
                                    "exiting mid-handoff on shutdown"
                                );
                                return;
                            },
                            driven = processor.finalize(context.as_present(), block.as_ref(), false) => {
                                (processor, applied) = driven;
                            },
                        }

                        // Cheap members serve every replayed block, as in processing.
                        match applied.publication {
                            Publication::Snapshot(snapshots) => {
                                snapshot_publisher.publish(block.height(), snapshots);
                            }
                            Publication::None if A::Databases::ANY_CHEAP_SNAPSHOT => {
                                select! {
                                    _ = &mut shutdown => {
                                        warn!(
                                            height = block.height().get(),
                                            "exiting mid-handoff on shutdown"
                                        );
                                        return;
                                    },
                                    driven = processor.refresh_snapshot(&mut snapshot_publisher) => {
                                        processor = driven;
                                    },
                                }
                            }
                            Publication::None => {}
                            Publication::WithBarrier(..) => {
                                unreachable!("the handoff requests no barrier per block")
                            }
                        }
                        pending_prune = applied.prune.or(pending_prune);
                        completed_height = block.height();
                    }
                    pending_acknowledgements.push(acknowledgement);
                }
            }
        }

        // Acknowledge applied handoffs only after one barrier makes the whole applied suffix
        // durable.
        if !pending_acknowledgements.is_empty() {
            let (snapshots, barrier);
            select! {
                _ = &mut shutdown => {
                    warn!(
                        height = completed_height.get(),
                        "exiting mid-handoff on shutdown"
                    );
                    return;
                },
                driven = processor.sync() => {
                    (processor, snapshots, barrier) = driven;
                },
            }

            // The snapshots serve immediately; peers verify what they fetch
            // against a finalized root, so serving safely runs ahead of disk.
            snapshot_publisher.publish(completed_height, snapshots);
            let durable = select! {
                _ = &mut shutdown => {
                    warn!(height = completed_height.get(), "exiting mid-handoff on shutdown");
                    return;
                },
                durable = barrier.durable() => durable,
            };
            if !durable {
                if shutdown.now_or_never().is_none() {
                    error!(
                        height = completed_height.get(),
                        "database barrier aborted without shutdown, stopping sync handoff"
                    );
                }
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
        // `completed_height` is durable and before processing takes new work.
        select! {
            _ = &mut shutdown => {
                warn!(height = completed_height.get(), "exiting mid-handoff on shutdown");
                return;
            },
            _ = plan.set_completed(completed_height) => {},
        }
        let _ = metrics.sync_done.try_set(1);
        drop(shutdown);

        // A prune that became due during the handoff runs from processing, which prunes only
        // durable state and stops on shutdown.
        Processing {
            context,
            mailbox,
            provider,
            marshal,
            snapshot_publisher,
        }
        .run(processor, deferred_verifications, pending_prune)
        .await
    }
}

/// Classifies retained finalizations against the converged sync anchor, in height order.
///
/// A live floor change can redeliver a suffix, so a block above the anchor may appear more than
/// once. Every copy is classified as [`FinalizedHandoff::Apply`].
///
/// Panics if the block at the anchor height has a different digest, a duplicate differs from its
/// original, or a block above the anchor skips a height.
fn classify<B>(
    anchor: Anchor<<B as Digestible>::Digest>,
    mut finalized: VecDeque<PendingFinalization<Arc<B>>>,
) -> VecDeque<FinalizedHandoff<Arc<B>>>
where
    B: CertifiableBlock,
    B::Context: Epochable + Viewable,
{
    finalized
        .make_contiguous()
        .sort_unstable_by_key(|pending| pending.block.height());
    let mut previous = anchor;
    let mut handoffs = VecDeque::with_capacity(finalized.len());

    for PendingFinalization {
        block,
        acknowledgement,
    } in finalized
    {
        if block.height() < anchor.height {
            handoffs.push_back(FinalizedHandoff::Covered(block, acknowledgement));
            continue;
        }
        if block.height() == anchor.height {
            assert_eq!(
                block.digest(),
                anchor.digest,
                "finalized block at sync anchor height must match sync anchor digest",
            );
            handoffs.push_back(FinalizedHandoff::Reflected(block, acknowledgement));
            continue;
        }

        if block.height() == previous.height {
            assert_eq!(
                block.digest(),
                previous.digest,
                "duplicate finalized block must match its original digest"
            );
        } else {
            assert_eq!(
                block.height(),
                previous.height.next(),
                "finalized block skips unapplied heights",
            );
            previous = Anchor::from(block.as_ref());
        }
        handoffs.push_back(FinalizedHandoff::Apply(block, acknowledgement));
    }
    handoffs
}

#[cfg(test)]
mod tests {
    use super::{
        super::Mailbox as StatefulMailbox, FinalizedHandoff, Message, PendingFinalization, Syncing,
        classify,
    };
    use crate::stateful::{
        PruneConfig,
        actor::{
            metrics::Metrics as StatefulMetrics,
            processor::Pruning,
            syncer::{self, Artifact, SyncPlan},
        },
        db::{Anchor, Publisher, Single, Subscriber},
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
        marshal::{
            self, Update, ancestry,
            core::{Mailbox as MarshalMailbox, Processed},
        },
        simplex::{mocks::scheme as scheme_mocks, types::Activity},
        types::Height,
    };
    use commonware_cryptography::{
        Digestible as _,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_runtime::{
        Clock as _, ContextCell, Error as RuntimeError, Handle, Runner as _, Spawner as _,
        Supervisor as _, deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, next_pending_sync},
        reschedule,
    };
    use commonware_utils::{Acknowledgement, NZUsize, acknowledgement::Exact, channel::oneshot};
    use futures::{FutureExt as _, poll};
    use std::{
        collections::VecDeque,
        sync::{Arc, atomic::Ordering},
        time::Duration,
    };

    fn pending(block: TestBlock) -> PendingFinalization<Arc<TestBlock>> {
        let (acknowledgement, _waiter) = Exact::handle();
        PendingFinalization {
            block: Arc::new(block),
            acknowledgement,
        }
    }

    struct TestHarness<E>
    where
        E: rand_core::Rng + commonware_runtime::Spawner + commonware_storage::Context,
    {
        syncing: Syncing<E, TestApp, TestScheme, TestVariant>,
        subscriber: Subscriber<u64>,
    }

    impl TestHarness<deterministic::Context> {
        async fn new(
            context: deterministic::Context,
            anchor: Anchor<Sha256Digest>,
        ) -> (Self, Artifact<deterministic::Context, TestApp>) {
            let marshal = harness_marshal(context.child("marshal")).await;
            Self::new_on(context.child("harness"), marshal, anchor).await
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
            oneshot::Sender<Artifact<deterministic::Context, TestApp>>,
        ) {
            Self::new_syncing_on(context.child("harness"), marshal).await
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
                let mut process = Box::pin(
                    self.syncing
                        .finalized(Arc::new(TestBlock::new(height, digest)), acknowledgement),
                );
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
            let subscriber = self.subscriber.clone();
            let process = context.child("full_window").spawn(move |_| {
                self.syncing
                    .finalized(Arc::new(TestBlock::new(10, 12)), acknowledgement)
            });
            let Some(syncer::mailbox::Message::Retarget { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("a full acknowledgement window must retarget");
            };
            for waiter in &mut waiters {
                assert!(poll!(waiter).is_pending());
            }
            assert!(poll!(&mut newest_waiter).is_pending());
            assert!(response.send(syncer::UpdateOutcome::Observed).is_ok());
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
            Self {
                syncing,
                subscriber,
            }
        }
    }

    impl<E> TestHarness<E>
    where
        E: rand_core::Rng + commonware_runtime::Spawner + commonware_storage::Context,
    {
        async fn new_syncing_on(
            context: E,
            marshal: MarshalMailbox<TestScheme, TestVariant>,
        ) -> (
            Self,
            StatefulMailbox<E, TestApp>,
            actor_mailbox::Receiver<syncer::mailbox::Message<E, TestApp>>,
            oneshot::Sender<Artifact<E, TestApp>>,
        ) {
            let (mailbox_sender, mailbox) =
                actor_mailbox::new(context.child("mailbox"), NZUsize!(1));
            let (syncer_sender, syncer_receiver) =
                actor_mailbox::new(context.child("syncer"), NZUsize!(1));
            let (sender, completion) = oneshot::channel();
            let publication_context = context.child("publication");
            let (snapshot_publisher, snapshot_subscriber) = Publisher::new(&publication_context);
            let harness = Self {
                syncing: Syncing {
                    context: ContextCell::new(context.child("syncing")),
                    mailbox,
                    application: TestApp::default(),
                    provider: (),
                    marshal,
                    plan: SyncPlan::init(context.child("plan"), "syncing-test").await,
                    syncer: syncer::Mailbox::new(syncer_sender),
                    deferred_verifications: Vec::new(),
                    snapshot_publisher,
                    completion,
                    pending_finalizations: VecDeque::new(),
                    pruning: None,
                    metrics: StatefulMetrics::new(&context),
                },
                subscriber: snapshot_subscriber,
            };
            (
                harness,
                StatefulMailbox::new(mailbox_sender),
                syncer_receiver,
                sender,
            )
        }

        /// Build the harness with `context` owning the syncing actor and its state-sync
        /// metadata, and return a completed sync artifact at `anchor` to transition with.
        async fn new_on(
            context: E,
            marshal: MarshalMailbox<TestScheme, TestVariant>,
            anchor: Anchor<Sha256Digest>,
        ) -> (Self, Artifact<E, TestApp>) {
            let (harness, _mailbox, _syncer_receiver, _completion) =
                Self::new_syncing_on(context, marshal).await;
            let artifact = Artifact {
                databases: test_databases(),
                anchor,
            };
            (harness, artifact)
        }
    }

    /// Start a stopped marshal fixture for the harness and return its mailbox.
    async fn harness_marshal(
        mut context: deterministic::Context,
    ) -> MarshalMailbox<TestScheme, TestVariant> {
        let scheme = scheme_mocks::fixture(&mut context, b"syncing-harness", 1).schemes[0].clone();
        fixtures::marshal_fixture(context, "syncing-harness", scheme, None, NZUsize!(1), false)
            .await
            .mailbox
    }

    #[test]
    fn handoff_classification_orders_mixed_terminal_sequence() {
        assert!(classify::<TestBlock>(anchor(u64::MAX - 2, 9), VecDeque::new()).is_empty());

        let mut finalized = VecDeque::new();
        for (height, digest) in [
            (u64::MAX - 3, 8),
            (u64::MAX - 2, 9),
            (u64::MAX - 1, 10),
            (u64::MAX, 11),
            (u64::MAX - 1, 10),
            (u64::MAX, 11),
        ] {
            finalized.push_back(pending(TestBlock::new(height, digest)));
        }
        let mut handoffs = classify(anchor(u64::MAX - 2, 9), finalized);
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
        for height in [u64::MAX - 1, u64::MAX - 1, u64::MAX, u64::MAX] {
            assert!(matches!(
                handoffs.pop_front(),
                Some(FinalizedHandoff::Apply(block, _))
                    if block.height() == Height::new(height)
            ));
        }
        assert!(handoffs.is_empty());
    }

    #[test]
    #[should_panic(expected = "sync anchor digest")]
    fn anchor_height_block_with_conflicting_digest_panics() {
        let _ = classify(
            anchor(7, 9),
            VecDeque::from([pending(TestBlock::new(7, 10))]),
        );
    }

    #[test]
    #[should_panic(expected = "duplicate finalized block must match its original digest")]
    fn duplicate_handoff_with_conflicting_digest_panics() {
        let _ = classify(
            anchor(7, 9),
            VecDeque::from([
                pending(TestBlock::new(8, 10)),
                pending(TestBlock::new(8, 11)),
            ]),
        );
    }

    #[test]
    #[should_panic(expected = "finalized block skips unapplied heights")]
    fn non_anchor_non_next_block_panics() {
        let _ = classify(
            anchor(7, 9),
            VecDeque::from([pending(TestBlock::new(9, 10))]),
        );
    }

    #[test]
    fn handoff_classification_retains_block_covered_by_artifact() {
        let handoffs = classify(
            anchor(7, 9),
            VecDeque::from([pending(TestBlock::new(6, 8))]),
        );
        assert!(matches!(
            handoffs.front(),
            Some(FinalizedHandoff::Covered(block, _)) if block.height() == Height::new(6)
        ));
    }

    #[test]
    fn transition_skips_hooks_for_reflected_handoffs() {
        deterministic::Runner::default().start(|context| async move {
            let (application, hooks) = TestApp::observe_finalization();
            let (mut harness, artifact) = TestHarness::new(context, anchor(7, 9)).await;
            harness.syncing.application = application;

            let (covered_acknowledgement, covered_waiter) = Exact::handle();
            let (reflected_acknowledgement, reflected_waiter) = Exact::handle();
            harness
                .syncing
                .transition(
                    artifact,
                    [
                        FinalizedHandoff::Covered(
                            Arc::new(TestBlock::new(6, 8)),
                            covered_acknowledgement,
                        ),
                        FinalizedHandoff::Reflected(
                            Arc::new(TestBlock::new(7, 9)),
                            reflected_acknowledgement,
                        ),
                    ],
                )
                .await;

            assert!(covered_waiter.await.is_ok());
            assert!(reflected_waiter.await.is_ok());
            assert_eq!(hooks.load(Ordering::SeqCst), 0);
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
            let marshal = harness_marshal(context.child("marshal")).await;
            let (mut harness, stateful_mailbox, _syncer_receiver, _completion) =
                TestHarness::new_syncing_on(delayed, marshal).await;
            let mut artifact = Artifact {
                databases: test_databases(),
                anchor: anchor(7, 9),
            };
            harness.syncing.pruning = Some(Pruning::new(
                PruneConfig {
                    maintenance_interval: NZUsize!(1),
                    retained_marshal_blocks: 0,
                    retained_qmdb_blocks: 0,
                },
                harness.syncing.marshal.max_pending_acks(),
                0,
            ));
            let control = FlushControl::default();
            artifact.databases = Single::from(TestDb::gated(control.clone()));
            let (application, hooks) = TestApp::observe_finalization();
            harness.syncing.application = application;

            // Completion metadata must not be written until the handoff batch is durable.
            pending.arm();
            let gate = next_pending_sync(&pending);
            let (reflected_acknowledgement, mut reflected_waiter) = Exact::handle();
            let (first_acknowledgement, mut first_waiter) = Exact::handle();
            let (second_acknowledgement, mut second_waiter) = Exact::handle();
            let first = TestBlock::child(&TestBlock::new(7, 9), 10);
            let second = TestBlock::child(&first, 11);
            let sync_done = harness.syncing.metrics.sync_done.clone();
            let subscriber = harness.subscriber.clone();
            let transition = context.child("transition").spawn(move |_| {
                harness.syncing.transition(
                    artifact,
                    [
                        FinalizedHandoff::Reflected(
                            Arc::new(TestBlock::new(7, 9)),
                            reflected_acknowledgement,
                        ),
                        FinalizedHandoff::Apply(Arc::new(first), first_acknowledgement),
                        FinalizedHandoff::Apply(Arc::new(second), second_acknowledgement),
                    ],
                )
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
            assert_eq!(
                subscriber.latest(),
                Some(2),
                "the captured handoff suffix must serve ahead of its flush",
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
            assert_eq!(
                sync_done.get(),
                0,
                "completion must not be reported before it is recorded",
            );
            gate.release
                .send(Ok(()))
                .expect("transition must be waiting on the metadata flush");

            // The prune that became due during the handoff runs once processing takes over.
            while control.pruned.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }
            assert_eq!(control.pruned.lock().as_slice(), &[8]);
            assert_eq!(sync_done.get(), 1);
            drop(stateful_mailbox);
            transition.await.expect("transition failed");
            assert!(reflected_waiter.await.is_ok());
            assert!(first_waiter.await.is_ok());
            assert!(second_waiter.await.is_ok());
            assert_eq!(
                hooks.load(Ordering::SeqCst),
                4,
                "both applied handoff blocks must run capture and finalized",
            );

            // The completed height is durable: reopen the metadata partition.
            let reopened =
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), "syncing-test")
                    .await;
            assert_eq!(reopened.completed(), Some(Height::new(9)));
        });
    }

    #[test]
    fn aborted_handoff_flush_cancels_ack_and_keeps_sync_incomplete() {
        deterministic::Runner::default().start(|context| async move {
            let (harness, mut artifact) =
                TestHarness::new(context.child("harness"), anchor(7, 9)).await;
            artifact.databases =
                Single::from(TestDb::with_sync(Handle::ready(Err(RuntimeError::Aborted))));

            let (acknowledgement, waiter) = Exact::handle();
            let sync_done = harness.syncing.metrics.sync_done.clone();
            harness
                .syncing
                .transition(
                    artifact,
                    Some(FinalizedHandoff::Apply(
                        Arc::new(TestBlock::child(&TestBlock::new(7, 9), 10)),
                        acknowledgement,
                    )),
                )
                .await;

            assert!(
                waiter.await.is_err(),
                "an aborted handoff must cancel marshal's acknowledgement",
            );
            assert!(
                harness.subscriber.latest().is_none(),
                "serving must shut off once the handoff stops",
            );
            assert_eq!(
                sync_done.get(),
                0,
                "an aborted handoff must not report completion",
            );
            let reopened =
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), "syncing-test")
                    .await;
            assert_eq!(reopened.completed(), None);
        });
    }

    /// Losing the syncer without shutdown fails loudly once a full acknowledgement window
    /// retargets. The harness marshal holds one pending acknowledgement.
    #[test]
    #[should_panic(expected = "syncer stopped unexpectedly")]
    fn retarget_panics_when_syncer_stops_without_shutdown() {
        deterministic::Runner::default().start(|context| async move {
            let marshal = harness_marshal(context.child("marshal")).await;
            let (harness, _mailbox, syncer_receiver, _completion) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            drop(syncer_receiver);
            assert_eq!(harness.syncing.marshal.max_pending_acks(), 1);
            let (acknowledgement, _waiter) = Exact::handle();
            let _ = harness
                .syncing
                .finalized(Arc::new(TestBlock::new(8, 10)), acknowledgement)
                .await;
        });
    }

    /// A syncer that exits on shutdown ends the retarget quietly and acknowledges nothing.
    #[test]
    fn retarget_exits_quietly_when_syncer_stops_on_shutdown() {
        deterministic::Runner::default().start(|context| async move {
            let marshal = harness_marshal(context.child("marshal")).await;
            let (harness, _mailbox, syncer_receiver, _completion) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            // Polling `stop` once fires the signal.
            let _ = context.child("stopper").stop(0, None).now_or_never();
            drop(syncer_receiver);
            assert_eq!(harness.syncing.marshal.max_pending_acks(), 1);
            let (acknowledgement, waiter) = Exact::handle();
            let (syncing, handoff) = harness
                .syncing
                .finalized(Arc::new(TestBlock::new(8, 10)), acknowledgement)
                .await;
            assert!(handoff.is_none());
            assert_eq!(syncing.pending_finalizations.len(), 1);
            drop(syncing);
            assert!(waiter.await.is_err());
        });
    }

    /// A stop while the handoff waits on its flush exits within the stop deadline and leaves the
    /// block unacknowledged.
    #[test]
    fn shutdown_interrupts_parked_handoff_flush() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (harness, mut artifact) =
                TestHarness::new(context.child("harness"), anchor(7, 9)).await;
            let control = FlushControl::default();
            artifact.databases = Single::from(TestDb::gated(control.clone()));
            let (acknowledgement, waiter) = Exact::handle();
            let sync_done = harness.syncing.metrics.sync_done.clone();
            let transition = context.child("transition").spawn(move |_| {
                harness.syncing.transition(
                    artifact,
                    [FinalizedHandoff::Apply(
                        Arc::new(TestBlock::child(&TestBlock::new(7, 9), 10)),
                        acknowledgement,
                    )],
                )
            });
            while control.flushes.lock().is_empty() {
                context.sleep(Duration::from_millis(10)).await;
            }

            let stopper = context.child("stopper");
            let stop = context
                .child("stop")
                .spawn(|_| async move { stopper.stop(0, Some(Duration::from_millis(100))).await });
            assert!(
                stop.await.expect("stop task should finish").is_ok(),
                "shutdown must interrupt the parked handoff flush",
            );
            transition.await.expect("transition should exit cleanly");
            assert!(waiter.await.is_err());
            assert_eq!(sync_done.get(), 0);
        });
    }

    /// A stop while the handoff's initial publish or its block replay is parked exits within the
    /// stop deadline, leaves the block unacknowledged, and records no completion.
    #[rstest::rstest]
    #[case::initial_publish(TestDb::gate_next_snapshot as fn() -> _)]
    #[case::finalize(TestDb::gate_next_new_batch as fn() -> _)]
    fn shutdown_interrupts_parked_handoff(
        #[case] gate: fn() -> (oneshot::Receiver<()>, oneshot::Sender<()>),
    ) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (harness, artifact) =
                TestHarness::new(context.child("harness"), anchor(7, 9)).await;
            let (started, _release) = gate();
            let (acknowledgement, waiter) = Exact::handle();
            let sync_done = harness.syncing.metrics.sync_done.clone();
            let transition = context.child("transition").spawn(move |_| {
                harness.syncing.transition(
                    artifact,
                    [FinalizedHandoff::Apply(
                        Arc::new(TestBlock::child(&TestBlock::new(7, 9), 10)),
                        acknowledgement,
                    )],
                )
            });
            started.await.expect("the handoff should reach the gate");

            let stopper = context.child("stopper");
            let stop = context
                .child("stop")
                .spawn(|_| async move { stopper.stop(0, Some(Duration::from_millis(100))).await });
            assert!(
                stop.await.expect("stop task should finish").is_ok(),
                "shutdown must interrupt the parked handoff",
            );
            transition.await.expect("transition should exit cleanly");
            assert!(waiter.await.is_err());
            assert_eq!(sync_done.get(), 0);
            let reopened =
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), "syncing-test")
                    .await;
            assert_eq!(reopened.completed(), None);
        });
    }

    /// A live floor during state sync redelivers receipts. The handoff applies each block once
    /// and releases every receipt only after its flush.
    #[rstest::rstest]
    #[case::success(true)]
    #[case::failure(false)]
    fn live_floor_reports_handoff_once_after_durability(#[case] succeeds: bool) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut signing = context.child("signing");
            let fixture =
                scheme_mocks::fixture(&mut signing, b"_COMMONWARE_GLUE_SYNCING_LIVE_FLOOR", 1);
            let (sender, mut reports) = actor_mailbox::new(context.child("reports"), NZUsize!(8));
            let reporter = StatefulMailbox::<_, TestApp>::new(sender);
            let marshal = fixtures::marshal_fixture_with_reporter(
                context.child("marshal"),
                "syncing-live-floor",
                fixture.schemes[0].clone(),
                NZUsize!(4),
                reporter.clone(),
            )
            .await;

            // Blocks 1 through 3 extend genesis, and block 2 becomes the live floor.
            let mut ingress = marshal.mailbox.clone();
            let genesis = TestBlock::new(0, 0);
            let first = TestBlock::child(&genesis, 1);
            let second = TestBlock::child(&first, 2);
            let third = TestBlock::child(&second, 3);
            let first_finalization = fixtures::finalization(&fixture, 1, first.digest());
            let floor_finalization = fixtures::finalization(&fixture, 2, second.digest());

            // Acknowledge genesis and block 1 so marshal's processed height is 1.
            let Some(Message::Finalized {
                block,
                acknowledgement,
                ..
            }) = reports.recv().await
            else {
                panic!("marshal must report genesis");
            };
            assert_eq!(block.height(), Height::zero());
            acknowledgement.acknowledge();
            assert!(
                ingress
                    .verified(first.context().round, Arc::new(first.clone()))
                    .await
            );
            ingress.report(Activity::Finalization(first_finalization.clone()));
            let Some(Message::Finalized {
                block,
                acknowledgement,
                ..
            }) = reports.recv().await
            else {
                panic!("marshal must report the recoverable anchor");
            };
            assert_eq!(block.height(), Height::new(1));
            acknowledgement.acknowledge();
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(1)))
            );

            // Start syncing from block 1.
            let (mut harness, _mailbox, mut coordinator, complete) =
                TestHarness::new_syncing(context.child("harness"), marshal.mailbox.clone()).await;
            harness.syncing.plan = harness.syncing.plan.set_floor(first_finalization).await;
            assert!(harness.syncing.plan.floor().is_some());

            // The interrupted sync has a recoverable artifact at 1, but has not recorded Complete.
            // Its coordinator can finish before a later target update is recorded.
            let control = FlushControl::default();
            let artifact = Artifact {
                databases: Single::from(TestDb::gated(control.clone())),
                anchor: anchor(1, 1),
            };

            // Report blocks 2 and 3. Stateful retains both receipts because the window is not full.
            for block in [&second, &third] {
                assert!(
                    ingress
                        .verified(block.context().round, Arc::new(block.clone()))
                        .await
                );
                ingress.report(Activity::Finalization(fixtures::finalization(
                    &fixture,
                    block.height().get(),
                    block.digest(),
                )));
                let Some(Message::Finalized {
                    block: reported,
                    acknowledgement,
                    ..
                }) = reports.recv().await
                else {
                    panic!("marshal must report the original suffix");
                };
                assert_eq!(reported.height(), block.height());
                let (syncing, handoff) = harness.syncing.finalized(reported, acknowledgement).await;
                assert!(handoff.is_none());
                harness.syncing = syncing;
            }

            // Installing block 2 keeps processed height 1 and redelivers blocks 2 and 3 with
            // fresh receipts.
            marshal.mailbox.set_floor(floor_finalization);
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(1)))
            );
            let Some(Message::Finalized {
                block,
                acknowledgement,
                ..
            }) = reports.recv().await
            else {
                panic!("floor installation must report its anchor again");
            };
            assert_eq!(block.height(), Height::new(2));
            let (syncing, handoff) = harness.syncing.finalized(block, acknowledgement).await;
            assert!(handoff.is_none());
            harness.syncing = syncing;
            assert!(coordinator.try_recv().is_err());

            // The redelivered block 3 is the fourth retained receipt. It fills the window, and the
            // coordinator answers the retarget with the completed artifact.
            let Some(Message::Finalized {
                block,
                acknowledgement,
                ..
            }) = reports.recv().await
            else {
                panic!("floor installation must report the suffix again");
            };
            assert_eq!(block.height(), Height::new(3));
            harness.syncing.mailbox = reports;
            let process = context
                .child("full_window")
                .spawn(move |_| harness.syncing.finalized(block, acknowledgement));
            let Some(syncer::mailbox::Message::Retarget { update, response }) =
                coordinator.recv().await
            else {
                panic!("four actual receipts must fill the acknowledgement window");
            };
            assert!(complete.send(artifact).is_ok());
            assert!(response.send(syncer::UpdateOutcome::SyncCompleted).is_ok());
            drop(update);
            let (syncing, handoff) = process.await.unwrap();
            let (artifact, handoffs) = handoff.expect("completed artifact must hand off reports");

            // The handoff applies blocks 2 and 3 once and holds all four receipts behind one
            // flush.
            let transition = context
                .child("transition")
                .spawn(move |_| syncing.transition(artifact, handoffs));
            while control.flushes.lock().is_empty() {
                reschedule().await;
            }
            assert_eq!(control.applied.load(Ordering::Relaxed), 2);
            assert_eq!(control.flushes.lock().len(), 1);
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(1)))
            );
            let release = control.flushes.lock().remove(0);
            if !succeeds {
                // A failed flush stops the handoff. After restart, marshal is still at block 1
                // and state sync is still in progress.
                drop(release);
                transition.await.expect("failed durability stops handoff");
                marshal.abort().await;
                let restarted = fixtures::marshal_fixture_with_reporter(
                    context.child("restart"),
                    "syncing-live-floor",
                    fixture.schemes[0].clone(),
                    NZUsize!(4),
                    fixtures::FixtureReporter::new(false),
                )
                .await;
                assert_eq!(
                    restarted.floor.processed(),
                    Some(Processed::Block(Height::new(1)))
                );
                let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                    context.child("plan"),
                    "syncing-test",
                )
                .await;
                assert!(plan.floor().is_some());
                assert_eq!(plan.completed(), None);
                restarted.abort().await;
                return;
            }

            // The flush releases every receipt, advancing marshal to block 3.
            release.send(Ok(())).unwrap();
            while marshal.mailbox.get_processed().await != Some(Processed::Block(Height::new(3))) {
                reschedule().await;
            }
            assert_eq!(
                marshal.mailbox.get_processed().await,
                Some(Processed::Block(Height::new(3)))
            );
            assert_eq!(control.applied.load(Ordering::Relaxed), 2);
            assert!(control.flushes.lock().is_empty());
            transition.abort();
            let _ = transition.await;
            marshal.abort().await;
        });
    }

    #[test]
    fn retarget_returning_artifact_hands_off_pending_block() {
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
            let (harness, _mailbox, mut syncer_receiver, sync_complete) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;

            let (acknowledgement, mut waiter) = Exact::handle();
            let process = context
                .child("finalized")
                .spawn(move |_| harness.syncing.finalized(Arc::new(block), acknowledgement));
            let Some(syncer::mailbox::Message::Retarget { update, response }) =
                syncer_receiver.recv().await
            else {
                panic!("finalized block must update the sync target");
            };
            assert!(poll!(&mut waiter).is_pending());
            assert!(
                sync_complete
                    .send(Artifact {
                        databases: test_databases(),
                        anchor: anchor(7, 9),
                    })
                    .is_ok(),
                "completion receiver must be alive",
            );
            assert!(
                response.send(syncer::UpdateOutcome::SyncCompleted).is_ok(),
                "target update must still await its response",
            );
            drop(update);

            let (_syncing, handoff) = process.await.expect("target update failed");
            let (artifact, mut handoffs) =
                handoff.expect("returned artifact must hand off the block");
            assert_eq!(artifact.anchor, anchor(7, 9));
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
            let (harness, mut mailbox, mut syncer_receiver, completion) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            let actor = context
                .child("syncing_actor")
                .spawn(move |_| harness.syncing.run());
            let mut waiters = Vec::new();
            let mut parent = TestBlock::new(7, 9);
            for (height, digest) in [(8, 10), (9, 11)] {
                let block = TestBlock::child(&parent, digest);
                let (acknowledgement, mut waiter) = Exact::handle();
                assert!(matches!(
                    mailbox.report(Update::Block(Arc::new(block.clone()), acknowledgement)),
                    Feedback::Ok
                ));
                parent = block;
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
                completion
                    .send(Artifact {
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
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), "syncing-test")
                    .await;
            assert_eq!(reopened.completed(), Some(Height::new(9)));
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
            let (mut harness, mut mailbox, _syncer_receiver, completion) =
                TestHarness::new_syncing_on(syncing_context, marshal).await;
            harness.syncing.plan = harness.syncing.plan.set_floor(initial.clone()).await;
            let actor = context
                .child("syncing_actor")
                .spawn(move |_| harness.syncing.run());

            let mut waiters = Vec::new();
            let mut parent = TestBlock::new(7, 9);
            for (height, digest) in [(8, 10), (9, 11)] {
                let block = TestBlock::child(&parent, digest);
                let (acknowledgement, mut waiter) = Exact::handle();
                assert!(matches!(
                    mailbox.report(Update::Block(Arc::new(block.clone()), acknowledgement)),
                    Feedback::Ok
                ));
                parent = block;
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
                completion
                    .send(Artifact {
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
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), "syncing-test")
                    .await;
            assert_eq!(reopened.completed(), Some(Height::new(9)));
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
            let (harness, mailbox, mut syncer_receiver, completion) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            let harness = harness
                .advance_full_ack_window(&context, &mut syncer_receiver)
                .await;
            let actor = context
                .child("syncing_actor")
                .spawn(move |_| harness.syncing.run());
            assert!(
                completion
                    .send(Artifact {
                        databases: test_databases(),
                        anchor: anchor(10, 12),
                    })
                    .is_ok()
            );
            drop(mailbox);
            actor.await.expect("syncing actor failed");

            let reopened =
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), "syncing-test")
                    .await;
            assert_eq!(reopened.completed(), Some(Height::new(10)));
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
            let (mut harness, _mailbox, mut syncer_receiver, _completion) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            harness.syncing.plan = harness.syncing.plan.set_floor(initial.clone()).await;
            let harness = harness
                .advance_full_ack_window(&context, &mut syncer_receiver)
                .await;
            assert_eq!(harness.syncing.plan.floor(), Some(&initial));

            // Drop all volatile retarget state after marshal has acknowledged the window.
            drop(harness);

            let plan = syncer::SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                "syncing-test",
            )
            .await;
            assert!(
                plan.should_sync(false),
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
            let (mut harness, _mailbox, mut syncer_receiver, _completion) =
                TestHarness::new_syncing(context.child("harness"), marshal).await;
            harness.syncing.plan = harness.syncing.plan.set_floor(initial.clone()).await;

            let (acknowledgement, mut waiter) = Exact::handle();
            let process = context
                .child("finalized")
                .spawn(move |_| harness.syncing.finalized(Arc::new(block), acknowledgement));
            let Some(syncer::mailbox::Message::Retarget { update, response }) =
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
                syncing.plan.floor(),
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
