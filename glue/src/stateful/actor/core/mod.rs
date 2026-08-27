//! Stateful application that manages the pending-tip DAG of merkleized batches on behalf of an [`Application`].
//!
//! The [`Stateful`] actor is split into two control loops:
//! - [`Syncing`] manages the state sync process.
//! - [`Processing`] manages the pending-tip DAG and drives the inner application.

use crate::stateful::{
    Application,
    actor::{
        core::{mailbox::Message, processing::Processing, syncing::Syncing},
        metrics::Metrics as StatefulMetrics,
        processor::{PendingSyncTargets, Processor, Pruning},
        syncer::{self, SyncPlan, SyncResult},
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
use commonware_cryptography::{Digestible, certificate::Scheme};
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell, telemetry::metrics::GaugeExt};
use commonware_storage::Context;
use commonware_utils::channel::oneshot;
use futures::join;
use rand_core::Rng;
use std::num::NonZeroUsize;

mod mailbox;
pub use mailbox::Mailbox;
pub(super) use mailbox::Request;

mod processing;
mod syncing;

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

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
    /// Ensure marshal is never pruned more aggressively than QMDB.
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

    /// Capacity of the stateful actor mailbox channel.
    pub mailbox_size: NonZeroUsize,

    /// Startup plan loaded via [`SyncPlan::init`], optionally augmented with
    /// a finalized floor via [`SyncPlan::with_floor`]. Carries the durable
    /// metadata handle and the startup decision shared with marshal.
    pub plan: SyncPlan<E, S, V>,

    /// Resolver(s) for state sync fetches.
    pub resolvers: R,

    /// Publishes the latest snapshots.
    pub snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,

    /// Sync engine tuning knobs.
    pub sync_config: SyncEngineConfig,

    /// Periodic database and marshal pruning configuration.
    ///
    /// When enabled, glue retains `max_pending_acks + 1` finalized blocks plus
    /// the configured retained block windows before pruning. Marshal must retain
    /// at least as many blocks as QMDB.
    pub prune_config: Option<PruneConfig>,
}

/// Stateful application that manages the pending-tip DAG of merkleized
/// batches on behalf of an [`Application`], implementing the consensus
/// application and verifying traits.
pub struct Stateful<E, A, S, V, R>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: ContextCell<E>,

    /// The receiver for messages.
    mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// The inner application that drives state transitions.
    application: A,

    /// Provider cloned into each proposal.
    provider: A::Provider,

    /// Marshal mailbox and the durable floor returned with it during initialization.
    marshal: (MarshalMailbox<S, V>, Floor),

    /// Configuration used to initialize the database set at startup.
    db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Startup plan carrying the metadata handle and floor decision.
    plan: SyncPlan<E, S, V>,

    /// Resolver(s) for state sync fetches.
    resolvers: R,

    /// Publishes the latest snapshots.
    snapshot_publisher: Publisher<SnapshotsOf<A::Databases, E>>,

    /// Sync engine tuning knobs.
    sync_config: SyncEngineConfig,

    /// Periodic pruning state.
    pruning: Option<Pruning<PendingSyncTargets<A, E>>>,
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
    /// Construct a [`Stateful`] actor and its [`Mailbox`].
    ///
    /// This only wires dependencies and allocates the mailbox. The actor does
    /// not process messages until [`Stateful::start`] is called.
    pub fn init(mut context: E, config: Config<E, A, S, V, R>) -> (Self, Mailbox<E, A>) {
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
                snapshot_publisher: config.snapshot_publisher,
                sync_config: config.sync_config,
                pruning,
            },
            Mailbox::new(sender),
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(self) {
        if let Some(floor) = self.plan.floor().cloned() {
            self.start_state_sync(floor).await;
        } else if self.plan.requires_state_sync_floor() {
            panic!("interrupted state sync is missing its persisted floor");
        } else {
            self.start_from_marshal().await;
        }
    }

    /// Starts the application in [`Syncing`] mode, kicking off a state sync process
    /// towards the finalized floor specified in the [`SyncPlan`].
    async fn start_state_sync(self, finalization: Finalization<S, V::Commitment>) {
        let (marshal, floor) = self.marshal;
        let metrics = StatefulMetrics::new(self.context.as_present());
        let sync_metadata = self
            .plan
            .into_sync_metadata()
            .begin_sync(finalization.clone())
            .await;
        let (sync_complete, sync_completed) = oneshot::channel();
        let (syncer, syncer_mailbox) = syncer::Syncer::new(syncer::Config {
            context: self.context.child("syncer"),
            db_config: self.db_config,
            sync_config: self.sync_config,
            resolvers: self.resolvers,
            finalization,
            marshal: (marshal.clone(), floor),
            sync_complete,
        });
        let syncing = Syncing {
            context: self.context,
            mailbox: self.mailbox,
            application: self.application,
            provider: self.provider,
            marshal,
            sync_metadata,
            syncer: syncer_mailbox,
            deferred_verifications: Vec::new(),
            artifact: None,
            snapshot_publisher: self.snapshot_publisher,
            sync_completed,
            pending_finalizations: Default::default(),
            pruning: self.pruning,
            metrics,
        };
        let _ = join!(syncer.start(), syncing.start());
    }

    /// Starts the application by initializing the database set at marshal's current floor.
    async fn start_from_marshal(self) {
        let (marshal, _) = self.marshal;
        let syncer::StartupResult {
            sync: SyncResult { databases, anchor },
            skip_finalized_until,
        } = syncer::init_databases_from_marshal::<E, A, S, V>(
            self.context.as_present(),
            &marshal,
            self.db_config,
            self.plan.into_sync_metadata(),
        )
        .await;

        let metrics = StatefulMetrics::new(self.context.as_present());
        let _ = metrics.sync_done.try_set(1);
        let mut processor = Processor::new(
            self.application,
            databases,
            marshal,
            self.snapshot_publisher,
            anchor,
            metrics,
            self.pruning,
        );

        // The recovered state alone must publish before the loop starts, so
        // serving begins before the next finalization.
        processor.publish_snapshot().await;
        Processing {
            context: self.context,
            mailbox: self.mailbox,
            provider: self.provider,
            skip_finalized_until,
        }
        .start(processor, Vec::new())
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Stateful};
    use crate::stateful::{
        actor::syncer::SyncPlan,
        db::{Publisher, StateSyncDb, SyncEngineConfig},
        tests::{
            fixtures,
            mocks::{TestApp, TestBlock, TestDb},
        },
    };
    use commonware_consensus::{
        Application as _, CertifiableBlock as _, Reporter as _,
        marshal::{Update, ancestry},
        simplex::mocks::scheme as scheme_mocks,
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_macros::select;
    use commonware_runtime::{Clock as _, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{
        Acknowledgement as _, NZU64, NZUsize, acknowledgement::Exact, channel::mpsc,
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

            let plan = SyncPlan::init(&context, "startup-serve-stateful".to_string()).await;
            let publication_context = context.child("publication");
            let (snapshot_publisher, snapshot_subscriber) = Publisher::new(&publication_context);
            let (stateful, _mailbox) = Stateful::init(
                context.child("stateful"),
                Config {
                    application: TestApp,
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

            handle.abort();
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

            let plan = SyncPlan::init(&context, "pending-floor-stateful".to_string()).await;
            let publication_context = context.child("publication");
            let (stateful, mut mailbox) = Stateful::init(
                context.child("stateful"),
                Config {
                    application: TestApp,
                    db_config: (),
                    provider: (),
                    marshal: (marshal.mailbox, marshal.floor),
                    mailbox_size: NZUsize!(8),
                    plan: plan.with_floor(finalization),
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

    #[test]
    fn startup_recovery_releases_cancelled_verify_ancestries() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|mut context| async move {
            // Hold startup after database recovery but before processing polls the mailbox.
            let prefix = "startup-recovery-cancelled-verifications";
            let scheme = scheme_mocks::fixture(&mut context, prefix.as_bytes(), 1);
            let genesis = TestBlock::new(0, 0);
            let finalized = TestBlock::child(&genesis, 1);
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
            let plan = SyncPlan::init(&context, format!("{prefix}-stateful")).await;
            let publication_context = context.child("publication");
            let (stateful, mut mailbox) = Stateful::init(
                context.child("stateful"),
                Config {
                    application: TestApp,
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
