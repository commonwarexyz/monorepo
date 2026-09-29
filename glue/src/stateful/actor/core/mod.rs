//! The [`Stateful`] actor and its two modes.
//!
//! - [`Syncing`] serves requests while state sync runs and hands the converged state to
//!   [`Processing`].
//! - [`Processing`] serves proposals, verifications, and finalizations against the live databases.

use crate::stateful::{
    Application,
    actor::{
        BlockDigest, SyncTargets,
        core::{mailbox::Message, processing::Processing, syncing::Syncing},
        metrics::Metrics as StatefulMetrics,
        processor::{Processor, Pruning},
        syncer::{self, Artifact, SyncPlan},
    },
    db::{DatabaseSet, Publisher, SnapshotsOf, StateSyncSet, SyncEngineConfig},
};
use commonware_actor::mailbox::{self as actor_mailbox};
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Floor, Mailbox as MarshalMailbox, Variant},
    },
    simplex::types::Finalization,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell, telemetry::metrics::GaugeExt};
use commonware_storage::Context;
use commonware_utils::channel::oneshot;
use futures::join;
use rand_core::Rng;
use std::num::NonZeroUsize;
use tracing::debug;

mod mailbox;
pub use mailbox::Mailbox;
pub(super) use mailbox::Verification;

mod processing;
mod syncing;
mod verifications;

/// Periodic pruning configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PruneConfig {
    /// Finalized blocks between database and marshal pruning attempts.
    ///
    /// Stateful selects a random phase within the interval when it starts. This controls only how
    /// often pruning runs, not how much history is retained.
    pub maintenance_interval: NonZeroUsize,

    /// Finalized blocks to retain in marshal beyond its acknowledgement window plus one.
    ///
    /// This should generally be set to a large enough number of blocks to facilitate downtime
    /// on a validator that has completed state sync. If marshal retains too few blocks, a rebooted
    /// node may fail to recover due to peers being unable to serve the blocks it needs to catch up.
    pub retained_marshal_blocks: usize,

    /// Finalized blocks' worth of operations to retain in QMDB beyond marshal's
    /// acknowledgement window plus one.
    ///
    /// This value is generally safe to set to 0, as QMDB operations below the active range are only
    /// needed to serve state sync requests for lagging peers. Some network topologies may benefit from
    /// a non-zero value here to provide a larger buffer for serving state sync requests during periods
    /// of instability.
    pub retained_qmdb_blocks: usize,
}

impl PruneConfig {
    /// Checks that marshal retains at least as many blocks as QMDB.
    ///
    /// # Panics
    ///
    /// Panics if `retained_marshal_blocks` is less than `retained_qmdb_blocks`.
    pub const fn assert_valid(self) {
        assert!(
            self.retained_marshal_blocks >= self.retained_qmdb_blocks,
            "marshal must retain at least as many blocks as QMDB",
        );
    }
}

/// Configuration for constructing a [`Stateful`] application.
pub struct Config<E, A, S, V, R>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// The inner application that drives state transitions.
    pub application: A,

    /// Configuration used to construct the database set.
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Provider cloned into each proposal.
    pub provider: A::Provider,

    /// Marshal mailbox and the durable floor returned with it during initialization.
    pub marshal: (MarshalMailbox<S, V>, Floor),

    /// Capacity of the actor's mailbox.
    pub mailbox_size: NonZeroUsize,

    /// Startup plan from [`SyncPlan::init`] (and [`SyncPlan::set_floor`] when a floor is
    /// selected).
    ///
    /// Marshal must start from [`SyncPlan::marshal_start`] of the same plan.
    pub plan: SyncPlan<E, S, V>,

    /// Resolvers that fetch state sync data from peers.
    pub resolvers: R,

    /// Publishes the latest snapshots for serving peers.
    ///
    /// Create it with [`Publisher::new`] and hand the returned
    /// [`Subscriber`](crate::stateful::db::Subscriber), or a
    /// [view](crate::stateful::db::Subscriber::view) of one database's snapshot, to each
    /// [`p2p::Actor`](crate::stateful::db::p2p::Actor) that serves that database.
    pub snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,

    /// Sync engine tuning knobs.
    pub sync_config: SyncEngineConfig,

    /// Periodic database and marshal pruning configuration (no pruning when `None`).
    ///
    /// When set, [`Stateful`] retains the last `max_pending_acks + 1` finalized blocks (marshal's
    /// pending acknowledgement window plus one) and the configured retained block windows beyond
    /// them. Marshal must retain at least as many blocks as QMDB (see
    /// [`PruneConfig::assert_valid`]).
    pub prune_config: Option<PruneConfig>,
}

/// Actor that maintains speculative and finalized state for an [`Application`].
///
/// Consensus and marshal reach it through its [`Mailbox`]. See the [module docs](crate::stateful)
/// for the protocol.
pub struct Stateful<E, A, S, V, R>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context.
    context: ContextCell<E>,
    /// The receiver for messages.
    mailbox: actor_mailbox::Receiver<Message<E, A>>,
    /// The inner application that drives state transitions.
    application: A,
    /// Provider cloned into each proposal.
    provider: A::Provider,
    /// Marshal mailbox and the durable floor returned during initialization.
    marshal: (MarshalMailbox<S, V>, Floor),
    /// Configuration used to initialize the database set at startup.
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    /// Startup plan carrying the metadata handle and floor decision.
    plan: SyncPlan<E, S, V>,
    /// Resolvers for state sync fetches.
    resolvers: R,
    /// Publishes the latest snapshots.
    snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,
    /// Sync engine settings.
    sync_config: SyncEngineConfig,

    /// Pruning schedule from [`Config::prune_config`], with a random phase.
    pruning: Option<Pruning<SyncTargets<A, E>>>,
}

impl<E, A, S, V, R> Stateful<E, A, S, V, R>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
    R: Send + Sync + 'static,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    /// Creates a [`Stateful`] actor and its [`Mailbox`].
    ///
    /// The actor handles no messages until [`Stateful::start`] is called.
    ///
    /// # Panics
    ///
    /// Panics if [`Config::prune_config`] fails [`PruneConfig::assert_valid`].
    pub fn new(mut context: E, config: Config<E, A, S, V, R>) -> (Self, Mailbox<E, A>) {
        const {
            assert!(
                !A::Databases::CHEAP_SNAPSHOT || A::Databases::ANY_CHEAP_SNAPSHOT,
                "CHEAP_SNAPSHOT requires ANY_CHEAP_SNAPSHOT"
            );
        }
        let pruning = config.prune_config.map(|prune_config| {
            Pruning::random(
                prune_config,
                config.marshal.0.max_pending_acks(),
                &mut context,
            )
        });

        let (sender, mailbox) = actor_mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                application: config.application,
                provider: config.provider,
                marshal: config.marshal,
                db_config: config.db_config,
                plan: config.plan,
                resolvers: config.resolvers,
                snapshot_publisher: config
                    .snapshot_publisher
                    .with_merge(A::Databases::merge_snapshots),
                sync_config: config.sync_config,
                pruning,
            },
            Mailbox::new(sender),
        )
    }

    /// Spawns the actor and returns its handle.
    ///
    /// With a persisted floor, the actor runs state sync first: proposals return `None` and
    /// verifications wait until it completes. Otherwise it recovers from marshal before handling
    /// any message. See [Startup](crate::stateful#startup).
    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) {
        if let Some(finalization) = self.plan.floor().cloned() {
            self.sync(finalization).await;
        } else {
            self.recover().await;
        }
    }

    /// Runs state sync toward `finalization`, then processing.
    async fn sync(self, finalization: Finalization<S, V::Commitment>) {
        let (marshal, floor) = self.marshal;
        let metrics = StatefulMetrics::new(self.context.as_present());
        let (sender, receiver) = oneshot::channel();
        let (syncer, syncer_mailbox) = syncer::Syncer::new(syncer::Config {
            context: self.context.child("syncer"),
            db_config: self.db_config,
            sync_config: self.sync_config,
            resolvers: self.resolvers,
            finalization,
            marshal: (marshal.clone(), floor),
            completion: sender,
        });
        let syncing = Syncing {
            context: self.context,
            mailbox: self.mailbox,
            application: self.application,
            provider: self.provider,
            marshal,
            plan: self.plan,
            syncer: syncer_mailbox,
            deferred_verifications: Vec::new(),
            snapshot_publisher: self.snapshot_publisher,
            completion: receiver,
            pending_finalizations: Default::default(),
            pruning: self.pruning,
            metrics,
        };
        let _ = join!(syncer.start(), syncing.run());
    }

    /// Opens the database set from marshal, records completion, then runs processing.
    async fn recover(self) {
        let (marshal, _) = self.marshal;
        let Artifact { databases, anchor } = syncer::open::<E, A, S, V>(
            self.context.child("databases"),
            &marshal,
            self.db_config,
            self.plan.completed(),
        )
        .await;

        self.plan.set_completed(anchor.height).await;

        let metrics = StatefulMetrics::new(self.context.as_present());
        let _ = metrics.sync_done.try_set(1);
        let processor = Processor::new(self.application, databases, anchor, metrics, self.pruning);

        // The recovered state alone must publish before the loop starts, so
        // serving begins before the next finalization.
        let mut snapshot_publisher = self.snapshot_publisher;
        let processor = select! {
            _ = self.context.stopped() => {
                debug!("shutdown signal received before processing started");
                return;
            },
            processor = processor.publish_snapshot(&mut snapshot_publisher) => processor,
        };
        Processing {
            context: self.context,
            mailbox: self.mailbox,
            provider: self.provider,
            marshal,
            snapshot_publisher,
        }
        .run(processor, Vec::new())
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Mailbox, Stateful};
    use crate::stateful::{
        actor::syncer::SyncPlan,
        db::{Publisher, StateSyncDb, SyncEngineConfig},
        tests::{
            fixtures,
            mocks::{TestApp, TestBlock, TestDb, TestScheme, TestVariant},
        },
    };
    use commonware_consensus::{
        Application as _, CertifiableBlock as _, Reporter as _,
        marshal::{Update, ancestry},
        simplex::mocks::scheme as scheme_mocks,
        types::Height,
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_macros::select;
    use commonware_runtime::{
        Clock as _, Handle, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{
        Acknowledgement as _, NZU64, NZUsize,
        acknowledgement::Exact,
        channel::{mpsc, oneshot},
    };
    use futures::poll;
    use std::{convert::Infallible, sync::Arc, time::Duration};

    #[derive(Clone)]
    struct NoopResolver;

    impl<S: Send> StateSyncDb<deterministic::Context, S> for TestDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: deterministic::Context,
            _config: Self::Config,
            _source: S,
            _target: Self::SyncTarget,
            _tip_updates: mpsc::Receiver<Self::SyncTarget>,
            _finish: Option<mpsc::Receiver<()>>,
            _reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            Ok(Self::default())
        }
    }

    #[test]
    fn startup_serves_recovered_state_before_any_block() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut signing_context = context.child("signing");
            let fixture = scheme_mocks::fixture(&mut signing_context, b"startup-serve", 1);
            let marshal = fixtures::marshal_fixture(
                context.child("marshal_fixture"),
                "startup-serve",
                fixture.schemes[0].clone(),
                None,
                NZUsize!(1),
                true,
            )
            .await;

            let plan =
                SyncPlan::init(context.child("plan"), "startup-serve-stateful".to_string()).await;
            let publication_context = context.child("publication");
            let (snapshot_publisher, snapshot_subscriber) = Publisher::new(&publication_context);
            let (stateful, _mailbox) = Stateful::new(
                context.child("stateful"),
                Config {
                    application: TestApp::default(),
                    db_config: (),
                    provider: (),
                    marshal: (marshal.mailbox, marshal.floor),
                    mailbox_size: NZUsize!(8),
                    plan,
                    resolvers: NoopResolver,
                    snapshot_publisher,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                    prune_config: None,
                },
            );
            let handle = stateful.start();

            // No block is ever reported, so the recovered state alone must
            // publish and begin serving.
            while snapshot_subscriber.latest() != Some(0) {
                context.sleep(Duration::from_millis(1)).await;
            }

            // Recovery records its anchor as completed before serving.
            handle.abort();
            let _ = handle.await;
            let reopened = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("reopened_plan"),
                "startup-serve-stateful".to_string(),
            )
            .await;
            assert_eq!(reopened.completed(), Some(Height::zero()));
        });
    }

    #[test]
    fn mailbox_rejects_propose_while_floor_resolution_waits() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut signing_context = context.child("signing");
            let fixture = scheme_mocks::fixture(&mut signing_context, b"pending-floor", 1);
            let finalization = fixtures::finalization(&fixture, 1, Sha256Digest::from([7; 32]));
            let marshal = fixtures::marshal_fixture(
                context.child("marshal_fixture"),
                "pending-floor",
                fixture.schemes[0].clone(),
                None,
                NZUsize!(1),
                false,
            )
            .await;

            let plan =
                SyncPlan::init(context.child("plan"), "pending-floor-stateful".to_string()).await;
            let publication_context = context.child("publication");
            let (stateful, mut mailbox) = Stateful::new(
                context.child("stateful"),
                Config {
                    application: TestApp::default(),
                    db_config: (),
                    provider: (),
                    marshal: (marshal.mailbox, marshal.floor),
                    mailbox_size: NZUsize!(8),
                    plan: plan.set_floor(finalization).await,
                    resolvers: NoopResolver,
                    snapshot_publisher: Publisher::new(&publication_context).0,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                    prune_config: None,
                },
            );
            let handle = stateful.start();

            select! {
                result = mailbox.propose(
                    (context.child("proposal"), TestBlock::new(1, 1).context()),
                    ancestry::from_iter([]),
                    (),
                ) => {
                    assert!(result.is_none());
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("stateful mailbox stalled while resolving state sync floor");
                },
            }

            handle.abort();
        });
    }

    /// Starts a recovering actor whose startup publish parks on a snapshot gate. Returns the
    /// actor, its mailbox, the marshal fixture, and the gate's release once startup reaches it.
    async fn start_gated_recovery(
        context: &mut deterministic::Context,
        prefix: &str,
    ) -> (
        Handle<()>,
        Mailbox<deterministic::Context, TestApp>,
        fixtures::MarshalFixture,
        oneshot::Sender<()>,
    ) {
        let scheme = scheme_mocks::fixture(context, prefix.as_bytes(), 1);
        let marshal = fixtures::marshal_fixture(
            context.child("marshal"),
            prefix,
            scheme.schemes[0].clone(),
            None,
            NZUsize!(8),
            true,
        )
        .await;

        let (startup_started, startup_release) = TestDb::gate_next_snapshot();
        let plan = SyncPlan::init(context.child("plan"), format!("{prefix}-stateful")).await;
        let publication_context = context.child("publication");
        let (stateful, mailbox) = Stateful::new(
            context.child("stateful"),
            Config {
                application: TestApp::default(),
                db_config: (),
                provider: (),
                marshal: (marshal.mailbox.clone(), marshal.floor),
                mailbox_size: NZUsize!(1),
                plan,
                resolvers: NoopResolver,
                snapshot_publisher: Publisher::new(&publication_context).0,
                sync_config: SyncEngineConfig {
                    fetch_batch_size: NZU64!(1),
                    apply_batch_size: NZU64!(1),
                    max_outstanding_requests: 1,
                    update_channel_size: NZUsize!(1),
                    max_retained_roots: 1,
                },
                prune_config: None,
            },
        );
        let actor = stateful.start();
        startup_started
            .await
            .expect("startup should reach the snapshot publish before processing");
        (actor, mailbox, marshal, startup_release)
    }

    /// A stop while startup's first publish is parked exits before processing starts.
    #[test]
    fn shutdown_interrupts_startup_publish() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|mut context| async move {
            let (actor, _mailbox, marshal, _startup_release) =
                start_gated_recovery(&mut context, "startup-publish-shutdown").await;
            let stopper = context.child("stopper");
            context
                .child("stop")
                .spawn(|_| async move { stopper.stop(0, None).await });
            actor.await.expect("the actor should exit cleanly");
            drop(marshal.guards);
        });
    }

    #[test]
    fn startup_recovery_releases_cancelled_verify_ancestries() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|mut context| async move {
            // Hold startup after database recovery but before processing polls the mailbox.
            let genesis = TestBlock::new(0, 0);
            let finalized = TestBlock::child(&genesis, 1);
            let (actor, mut mailbox, marshal, startup_release) =
                start_gated_recovery(&mut context, "startup-recovery-cancelled-verifications")
                    .await;

            // Fill the single ready slot and reliable overflow with independently owned ancestries.
            let owners = [
                Arc::new(TestBlock::new(2, 2)),
                Arc::new(TestBlock::new(3, 3)),
                Arc::new(TestBlock::new(4, 4)),
            ];
            let weak_owners = owners.iter().map(Arc::downgrade).collect::<Vec<_>>();

            let mut first_mailbox = mailbox.clone();
            let mut first = Box::pin(first_mailbox.verify(
                (context.child("verify_first"), owners[0].context()),
                ancestry::from_iter([Arc::clone(&owners[0])]),
            ));
            assert!(poll!(&mut first).is_pending());

            let mut second_mailbox = mailbox.clone();
            let mut second = Box::pin(second_mailbox.verify(
                (context.child("verify_second"), owners[1].context()),
                ancestry::from_iter([Arc::clone(&owners[1])]),
            ));
            assert!(poll!(&mut second).is_pending());

            let mut third_mailbox = mailbox.clone();
            let mut third = Box::pin(third_mailbox.verify(
                (context.child("verify_third"), owners[2].context()),
                ancestry::from_iter([Arc::clone(&owners[2])]),
            ));
            assert!(poll!(&mut third).is_pending());

            // Queue a finalization behind the verifications, then cancel every caller.
            let (acknowledgement, mut acknowledgement_waiter) = Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(finalized), acknowledgement));

            drop(first);
            drop(second);
            drop(third);
            drop(owners);
            context.sleep(Duration::from_millis(10)).await;

            // Startup remains blocked while cancellation releases every ancestry block.
            assert!(poll!(&mut acknowledgement_waiter).is_pending());
            for (index, owner) in weak_owners.iter().enumerate() {
                assert!(
                    owner.upgrade().is_none(),
                    "cancelled startup verification {index} retained its ancestry owner",
                );
            }

            // Resuming startup drains the queue and acknowledges the later finalization.
            startup_release
                .send(())
                .expect("startup should remain gated");
            select! {
                result = acknowledgement_waiter => {
                    result.expect("finalized block should be acknowledged after startup");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("finalized acknowledgement stalled after startup");
                },
            }

            actor.abort();
            drop(marshal.guards);
        });
    }
}
