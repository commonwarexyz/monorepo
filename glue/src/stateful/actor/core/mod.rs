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
    db::{AttachableResolverSet, DatabaseSet, StateSyncSet, SyncEngineConfig},
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
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell, telemetry::metrics::GaugeExt};
use commonware_storage::Context;
use commonware_utils::channel::oneshot;
use futures::join;
use rand_core::Rng;
use std::num::NonZeroUsize;

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

    /// Resolvers that fetch state sync data from peers and serve the local databases to them.
    pub resolvers: R,

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
    /// Resolvers for state sync fetches and post-bootstrap serving.
    resolvers: R,
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
    R: AttachableResolverSet<A::Databases>,
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
                application: config.application.clone(),
                provider: config.provider,
                marshal: config.marshal,
                db_config: config.db_config,
                plan: config.plan,
                resolvers: config.resolvers,
                sync_config: config.sync_config,
                pruning,
            },
            Mailbox::new(sender, config.application),
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
            resolvers: self.resolvers.clone(),
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
            database_subscribers: Vec::new(),
            resolvers: self.resolvers,
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

        self.resolvers.attach_databases(databases.clone()).await;

        let metrics = StatefulMetrics::new(self.context.as_present());
        let _ = metrics.sync_done.try_set(1);
        let processor = Processor::new(self.application, databases, anchor, metrics, self.pruning);
        Processing {
            context: self.context,
            mailbox: self.mailbox,
            provider: self.provider,
            marshal,
            processor,
            deferred_verifications: Vec::new(),
        }
        .run()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Mailbox, Stateful};
    use crate::stateful::{
        Application,
        actor::syncer::SyncPlan,
        db::{AttachableResolver, Shared, StateSyncDb, SyncEngineConfig},
        tests::{
            fixtures,
            mocks::{TestApp, TestBlock, TestDb},
        },
    };
    use commonware_consensus::{
        Application as _, CertifiableBlock as _, Handoff, Reporter as _,
        marshal::{
            Update,
            ancestry::{self, Ancestry, BoxedAncestry, Parent},
        },
        simplex::mocks::scheme as scheme_mocks,
    };
    use commonware_cryptography::sha256::Digest as Sha256Digest;
    use commonware_macros::select;
    use commonware_runtime::{
        Clock, Handle, Metrics, Runner as _, Spawner, Supervisor as _, deterministic,
    };
    use commonware_utils::{
        Acknowledgement as _, NZU64, NZUsize,
        acknowledgement::Exact,
        channel::{mpsc, oneshot},
        sync::Mutex,
    };
    use futures::poll;
    use rand_core::Rng;
    use std::{
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    /// Blocks startup before the actor begins polling its mailbox.
    struct StartupGate {
        started: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
    }

    /// Resolver that can pause database attachment during startup.
    #[derive(Clone, Default)]
    struct NoopResolver {
        startup_gate: Arc<Mutex<Option<StartupGate>>>,
    }

    impl NoopResolver {
        /// Creates a resolver with handles to observe and release its next database attachment.
        fn gated() -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
            let (started, started_rx) = oneshot::channel();
            let (release, release_rx) = oneshot::channel();
            (
                Self {
                    startup_gate: Arc::new(Mutex::new(Some(StartupGate {
                        started,
                        release: release_rx,
                    }))),
                },
                started_rx,
                release,
            )
        }
    }

    impl AttachableResolver<TestDb> for NoopResolver {
        async fn attach_database(&self, _db: Shared<TestDb>) {
            // Consume the single-use gate before waiting so the wait does not hold the gate lock.
            let Some(StartupGate {
                started,
                mut release,
            }) = self.startup_gate.lock().take()
            else {
                return;
            };
            started
                .send(())
                .expect("test should await the startup gate");
            let _ = (&mut release).await;
        }
    }

    impl StateSyncDb<deterministic::Context, NoopResolver> for TestDb {
        type SyncError = Infallible;

        async fn sync_db(
            _context: deterministic::Context,
            _config: Self::Config,
            _resolver: NoopResolver,
            _target: Self::SyncTarget,
            _tip_updates: mpsc::Receiver<Self::SyncTarget>,
            _finish: Option<mpsc::Receiver<()>>,
            _reached_target: Option<mpsc::Sender<Self::SyncTarget>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<Self, Self::SyncError> {
            Ok(Self::default())
        }
    }

    /// A parent handle that records whether the application asked for its ancestry.
    #[derive(Clone)]
    struct Watched(Arc<AtomicBool>);

    impl Parent<TestBlock> for Watched {
        async fn ancestry(self) -> Option<impl Ancestry<TestBlock>> {
            self.0.store(true, Ordering::SeqCst);
            None::<BoxedAncestry<TestBlock>>
        }
    }

    /// Starts a [`Stateful`] around `application` and returns its mailbox, the actor handle,
    /// and the guards that keep its marshal alive.
    async fn stateful_with(
        context: &deterministic::Context,
        application: TestApp,
    ) -> (
        Mailbox<deterministic::Context, TestApp>,
        Handle<()>,
        Box<dyn std::any::Any>,
    ) {
        let mut signing_context = context.child("signing");
        let fixture = scheme_mocks::fixture(&mut signing_context, b"handoff", 1);
        let marshal = fixtures::marshal_fixture(
            context.child("marshal"),
            "stateful-handoff",
            fixture.schemes[0].clone(),
            None,
            NZUsize!(8),
            true,
        )
        .await;
        let plan = SyncPlan::init(context.child("plan"), "stateful-handoff-stateful").await;
        let (stateful, mailbox) = Stateful::new(
            context.child("stateful"),
            Config {
                application,
                db_config: (),
                provider: (),
                marshal: (marshal.mailbox.clone(), marshal.floor),
                mailbox_size: NZUsize!(8),
                plan,
                resolvers: NoopResolver::default(),
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
        (mailbox, stateful.start(), marshal.guards)
    }

    /// A `Wait` decision answers without asking for the parent.
    #[test]
    fn mailbox_prepare_wait_skips_parent() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, handle, _guards) =
                stateful_with(&context, TestApp::with_handoff(Handoff::Wait)).await;
            let asked = Arc::new(AtomicBool::new(false));
            let block = TestBlock::new(1, 1);
            let prepared = mailbox
                .prepare(
                    (context.child("wait"), block.context()),
                    Watched(asked.clone()),
                    (),
                )
                .await;
            assert!(prepared.is_wait());
            assert!(
                !asked.load(Ordering::SeqCst),
                "a Wait decision must not fetch the parent"
            );
            handle.abort();
            let _ = handle.await;
        });
    }

    /// A decision other than `Wait` fetches the parent and forwards the build to the actor as
    /// an ordinary proposal. An absent ancestry or a build that yields no block declines.
    #[test]
    fn mailbox_prepare_declines_without_block() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (mut mailbox, handle, _guards) =
                stateful_with(&context, TestApp::with_handoff(Handoff::Publish(()))).await;
            let asked = Arc::new(AtomicBool::new(false));
            let block = TestBlock::new(1, 1);
            let prepared = mailbox
                .prepare(
                    (context.child("publish"), block.context()),
                    Watched(asked.clone()),
                    (),
                )
                .await;
            assert!(prepared.is_wait(), "an absent ancestry declines");
            assert!(
                asked.load(Ordering::SeqCst),
                "a Publish decision fetches the parent"
            );

            let genesis = TestBlock::new(0, 0);
            assert_eq!(
                mailbox
                    .prepare(
                        (context.child("publish"), block.context()),
                        ancestry::from_iter([Arc::new(genesis)]),
                        (),
                    )
                    .await
                    .map(|_| ()),
                Handoff::Wait,
                "a build that yields no block declines"
            );
            handle.abort();
            let _ = handle.await;
        });
    }

    /// A built block comes back under the application's decision.
    #[test]
    fn mailbox_prepare_attaches_decision() {
        for decision in [Handoff::Publish(()), Handoff::Stage(())] {
            deterministic::Runner::timed(Duration::from_secs(5)).start(move |context| async move {
                let genesis = TestBlock::new(0, 0);
                let child = TestBlock::child(&genesis, 1);
                let application = TestApp::with_handoff(decision).with_proposal(child.clone());
                let (mut mailbox, handle, _guards) = stateful_with(&context, application).await;
                let prepared = mailbox
                    .prepare(
                        (context.child("build"), child.context()),
                        ancestry::from_iter([Arc::new(genesis)]),
                        (),
                    )
                    .await;
                assert_eq!(
                    prepared,
                    decision.map(|()| child),
                    "a built block must carry the {decision:?} decision"
                );
                handle.abort();
                let _ = handle.await;
            });
        }
    }

    fn is_send<T: Send>(_: T) {}

    /// [`Mailbox::subscribe_databases`] returns a `Send` future even for an application
    /// that is not `Sync`, so callers can await it in spawned tasks.
    #[allow(dead_code)]
    fn assert_mailbox_futures_are_send<E, A>(mailbox: &Mailbox<E, A>)
    where
        E: Rng + Spawner + Metrics + Clock,
        A: Application<E>,
    {
        is_send(mailbox.subscribe_databases());
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
            let (stateful, mut mailbox) = Stateful::new(
                context.child("stateful"),
                Config {
                    application: TestApp::default(),
                    db_config: (),
                    provider: (),
                    marshal: (marshal.mailbox, marshal.floor),
                    mailbox_size: NZUsize!(8),
                    plan: plan.set_floor(finalization).await,
                    resolvers: NoopResolver::default(),
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

            let (resolver, startup_started, startup_release) = NoopResolver::gated();
            let plan = SyncPlan::init(context.child("plan"), format!("{prefix}-stateful")).await;
            let (stateful, mut mailbox) = Stateful::new(
                context.child("stateful"),
                Config {
                    application: TestApp::default(),
                    db_config: (),
                    provider: (),
                    marshal: (marshal.mailbox.clone(), marshal.floor),
                    mailbox_size: NZUsize!(1),
                    plan,
                    resolvers: resolver,
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
                .expect("startup should reach resolver attachment before processing");

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
