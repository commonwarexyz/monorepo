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
        processor::Processor,
        syncer::{self, SyncPlan, SyncResult},
    },
    db::{AttachableResolverSet, DatabaseSet, StateSyncSet, SyncEngineConfig},
};
use commonware_actor::mailbox::{self as actor_mailbox};
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
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
pub(super) use mailbox::Verification;

mod processing;
mod syncing;

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

/// Periodic pruning configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PruneConfig {
    /// Marshal's ack window. Must match the marshal config used to construct the marshal
    /// mailbox: pruning retains at least the last `max_pending_acks + 1` finalized blocks so
    /// that any state a restart may need to rewind to is never pruned.
    pub max_pending_acks: NonZeroUsize,

    /// Prune databases and marshal every `maintenance_interval` finalized blocks.
    ///
    /// This controls only how often pruning runs, not how much history is retained. Each prune
    /// always leaves at least the configured retention windows in place, so a small interval
    /// prunes more frequently but never below those floors.
    pub maintenance_interval: NonZeroUsize,

    /// Finalized blocks to retain in marshal beyond `max_pending_acks + 1`.
    ///
    /// This should generally be set to a large enough number of blocks to facilitate downtime
    /// on a validator that has completed state sync. If marshal retains too few blocks, a rebooted
    /// node may fail to recover due to peers being unable to serve the blocks it needs to catch up.
    pub retained_marshal_blocks: usize,

    /// Finalized blocks' worth of operations to retain in QMDB beyond `max_pending_acks + 1`.
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

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    pub marshal: MarshalMailbox<S, V>,

    /// Capacity of the stateful actor mailbox channel.
    pub mailbox_size: NonZeroUsize,

    /// Startup plan loaded via [`SyncPlan::init`], optionally augmented with
    /// a finalized floor via [`SyncPlan::with_floor`]. Carries the durable
    /// metadata handle and the startup decision shared with marshal.
    pub plan: SyncPlan<E, S, V>,

    /// Resolver(s) for state sync fetches and post-bootstrap serving.
    pub resolvers: R,

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

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    marshal: MarshalMailbox<S, V>,

    /// Configuration used to initialize the database set at startup.
    db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Startup plan carrying the metadata handle and floor decision.
    plan: SyncPlan<E, S, V>,

    /// Resolver(s) for state sync fetches and post-bootstrap serving.
    resolvers: R,

    /// Sync engine tuning knobs.
    sync_config: SyncEngineConfig,

    /// Periodic prune configuration.
    prune_config: Option<PruneConfig>,
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
    /// Construct a [`Stateful`] actor and its [`Mailbox`].
    ///
    /// This only wires dependencies and allocates the mailbox. The actor does
    /// not process messages until [`Stateful::start`] is called.
    pub fn init(context: E, config: Config<E, A, S, V, R>) -> (Self, Mailbox<E, A>) {
        if let Some(prune_config) = config.prune_config {
            prune_config.assert_valid();
        }

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
                sync_config: config.sync_config,
                prune_config: config.prune_config,
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
    async fn start_state_sync(self, floor: Finalization<S, V::Commitment>) {
        let metrics = StatefulMetrics::new(self.context.as_present());
        let sync_metadata = self
            .plan
            .into_sync_metadata()
            .begin_sync(floor.clone())
            .await;
        let (sync_complete, sync_completed) = oneshot::channel();
        let (syncer, syncer_mailbox) = syncer::Syncer::new(syncer::Config {
            context: self.context.child("syncer"),
            db_config: self.db_config,
            sync_config: self.sync_config,
            resolvers: self.resolvers.clone(),
            finalization: floor,
            marshal: self.marshal.clone(),
            sync_complete,
        });
        let syncing = Syncing {
            context: self.context,
            mailbox: self.mailbox,
            application: self.application,
            provider: self.provider,
            marshal: self.marshal,
            sync_metadata,
            syncer: syncer_mailbox,
            held_verify_requests: Vec::new(),
            database_subscribers: Vec::new(),
            artifact: None,
            resolvers: self.resolvers,
            sync_completed,
            prune_config: self.prune_config,
            metrics,
        };
        let _ = join!(syncer.start(), syncing.start());
    }

    /// Starts the application by initializing the database set at marshal's current floor.
    async fn start_from_marshal(self) {
        let syncer::StartupResult {
            sync: SyncResult { databases, anchor },
            skip_finalized_until,
        } = syncer::init_databases_from_marshal::<E, A, S, V>(
            self.context.as_present(),
            &self.marshal,
            self.db_config,
            self.plan.into_sync_metadata(),
        )
        .await;

        // Attach the resolvers to the initialized databases before starting the processor,
        // so that this instance can serve peers database operations and proofs. The
        // resolver handles can be dropped after this: serving runs on the resolver
        // actors' own contexts.
        self.resolvers.attach_databases(databases.clone()).await;

        let metrics = StatefulMetrics::new(self.context.as_present());
        let _ = metrics.sync_done.try_set(1);
        let processor = Processor::new(
            self.application,
            databases,
            anchor,
            metrics,
            self.prune_config,
        );
        Processing {
            context: self.context,
            mailbox: self.mailbox,
            provider: self.provider,
            marshal: self.marshal,
            processor,
            initial_verifications: Vec::new(),
            skip_finalized_until,
        }
        .start()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Mailbox, Stateful, processing::Processing};
    use crate::stateful::{
        Application, Input, Proposed,
        actor::{metrics::Metrics as StatefulMetrics, processor::Processor, syncer::SyncPlan},
        db::{AttachableResolver, Shared, StateSyncDb, SyncEngineConfig},
        tests::mocks::{
            TestApp, TestBlock, TestDatabases, TestDb, TestMerkleized, TestScheme,
            TestUnmerkleized, TestVariant, anchor, test_databases,
        },
    };
    use commonware_actor::{Feedback, mailbox as actor_mailbox};
    use commonware_consensus::{
        Application as _, CertifiableAutomaton as _, CertifiableBlock as _, Heightable as _,
        Reporter,
        marshal::{
            self,
            ancestry::{self, Ancestry},
            core::{Actor as MarshalActor, Mailbox as MarshalMailbox},
            resolver::handler,
            standard::Deferred,
        },
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, FixedEpocher, Round, View, ViewDelta},
    };
    use commonware_cryptography::{
        Digestible as _,
        certificate::{ConstantProvider, mocks::Fixture},
        ed25519,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_resolver::{Fetch, Resolver as MarshalResolver, TargetedResolver};
    use commonware_runtime::{
        Clock as _, ContextCell, Runner as _, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        Acknowledgement as _, NZU16, NZU64, NZUsize,
        acknowledgement::Exact,
        channel::{mpsc, oneshot},
        sync::Mutex,
        vec::NonEmptyVec,
    };
    use futures::StreamExt as _;
    use std::{collections::VecDeque, convert::Infallible, sync::Arc, time::Duration};

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ApplicationCall {
        Verify(Sha256Digest),
        Apply(Sha256Digest),
    }

    struct VerifyGate {
        started: oneshot::Sender<()>,
        release: oneshot::Receiver<()>,
        finished: oneshot::Sender<()>,
    }

    #[derive(Clone)]
    struct GatedApp {
        gates: Arc<Mutex<VecDeque<VerifyGate>>>,
        calls: Arc<Mutex<Vec<ApplicationCall>>>,
    }

    impl GatedApp {
        fn new(
            gates: impl IntoIterator<Item = VerifyGate>,
        ) -> (Self, Arc<Mutex<Vec<ApplicationCall>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    gates: Arc::new(Mutex::new(gates.into_iter().collect())),
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    impl Application<deterministic::Context> for GatedApp {
        type SigningScheme = TestScheme;
        type Context = <TestApp as Application<deterministic::Context>>::Context;
        type Block = TestBlock;
        type Databases = TestDatabases;
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            TestBlock::new(0, 0)
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            None
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Option<TestMerkleized> {
            let mut ancestry = Box::pin(ancestry);
            let block = ancestry.next().await?;
            self.calls
                .lock()
                .push(ApplicationCall::Verify(block.digest()));
            let mut gate = self
                .gates
                .lock()
                .pop_front()
                .expect("unexpected verification");
            gate.started.send(()).expect("test must await execution");
            let _ = (&mut gate.release).await;
            gate.finished.send(()).expect("test must await completion");
            Some(TestMerkleized)
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> TestMerkleized {
            self.calls
                .lock()
                .push(ApplicationCall::Apply(block.digest()));
            TestMerkleized
        }
    }

    fn verify_gate() -> (
        VerifyGate,
        oneshot::Receiver<()>,
        oneshot::Sender<()>,
        oneshot::Receiver<()>,
    ) {
        let (started, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let (finished, finished_rx) = oneshot::channel();
        (
            VerifyGate {
                started,
                release: release_rx,
                finished,
            },
            started_rx,
            release,
            finished_rx,
        )
    }

    #[derive(Clone)]
    struct NoopResolver;

    impl AttachableResolver<TestDb> for NoopResolver {
        async fn attach_database(&self, _db: Shared<TestDb>) {}
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
            Ok(Self)
        }
    }

    #[derive(Clone)]
    struct NoopMarshalReporter;

    impl Reporter for NoopMarshalReporter {
        type Activity = marshal::Update<TestBlock>;

        fn report(&mut self, activity: Self::Activity) -> Feedback {
            if let marshal::Update::Block(_, acknowledgement) = activity {
                acknowledgement.acknowledge();
            }
            Feedback::Ok
        }
    }

    #[derive(Clone)]
    struct NoopMarshalResolver;

    impl MarshalResolver for NoopMarshalResolver {
        type Key = handler::Key<Sha256Digest>;
        type Subscriber = handler::Annotation;

        fn fetch<F>(&mut self, _fetch: F) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _fetches: Vec<F>) -> Feedback
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

    impl TargetedResolver for NoopMarshalResolver {
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
            _fetches: Vec<(F, NonEmptyVec<Self::PublicKey>)>,
        ) -> Feedback
        where
            F: Into<Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            Feedback::Ok
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
    ) -> (
        MarshalMailbox<TestScheme, TestVariant>,
        commonware_runtime::Handle<()>,
        handler::Handler<Sha256Digest>,
    ) {
        let fixture = scheme_mocks::fixture(&mut context, b"retained-verify", 1);
        let provider = ConstantProvider::new(fixture.schemes[0].clone());
        let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(page_cache.clone(), "retained-verify-finalizations"),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), "retained-verify-blocks"),
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
                partition_prefix: "retained-verify-marshal".to_string(),
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
        let actor = actor.start_unbuffered(
            NoopMarshalReporter,
            (resolver_receiver, NoopMarshalResolver),
        );
        (mailbox, actor, resolver_handler)
    }

    fn start_processing(
        context: &deterministic::Context,
        app: GatedApp,
        marshal: MarshalMailbox<TestScheme, TestVariant>,
    ) -> (
        Mailbox<deterministic::Context, GatedApp>,
        commonware_runtime::Handle<()>,
    ) {
        let (sender, receiver) = actor_mailbox::new(context.child("mailbox"), NZUsize!(8));
        let mailbox = Mailbox::new(sender);
        let processing = Processing {
            context: ContextCell::new(context.child("processor")),
            mailbox: receiver,
            provider: (),
            marshal,
            processor: Processor::new(
                app,
                test_databases(),
                anchor(0, 0),
                StatefulMetrics::new(context),
                None,
            ),
            initial_verifications: Vec::new(),
            skip_finalized_until: None,
        };
        let actor = context.child("actor").spawn(move |_| processing.start());
        (mailbox, actor)
    }

    async fn seed_chain(
        marshal: &MarshalMailbox<TestScheme, TestVariant>,
    ) -> (TestBlock, TestBlock) {
        let genesis = TestBlock::new(0, 0);
        let parent = TestBlock::child(&genesis, 1);
        let child = TestBlock::child(&parent, 2);
        assert!(
            marshal
                .verified(parent.context().round, parent.clone())
                .await
        );
        assert!(marshal.verified(child.context().round, child.clone()).await);
        (parent, child)
    }

    fn build_finalization(
        fixture: &Fixture<TestScheme>,
        payload: Sha256Digest,
    ) -> Finalization<TestScheme, Sha256Digest> {
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(1)),
            View::zero(),
            payload,
        );
        let votes: Vec<_> = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect();

        Finalization::from_finalizes(&fixture.verifier, &votes, &Sequential)
            .expect("finalization quorum")
    }

    #[test]
    fn mailbox_rejects_propose_while_floor_resolution_waits() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let mut signing_context = context.child("signing");
            let fixture = scheme_mocks::fixture(&mut signing_context, b"pending-floor", 1);
            let provider = ConstantProvider::new(fixture.schemes[0].clone());
            let finalization = build_finalization(&fixture, Sha256Digest::from([7; 32]));

            let page_cache = CacheRef::from_pooler(&context, NZU16!(1024), NZUsize!(8));
            let finalizations_by_height = immutable::Archive::init(
                context.child("finalizations_by_height"),
                archive_config(page_cache.clone(), "pending-floor-finalizations"),
            )
            .await
            .expect("failed to initialize finalizations archive");
            let finalized_blocks = immutable::Archive::init(
                context.child("finalized_blocks"),
                archive_config(page_cache.clone(), "pending-floor-blocks"),
            )
            .await
            .expect("failed to initialize blocks archive");

            let (_marshal_actor, marshal, _height) =
                MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
                    context.child("marshal"),
                    finalizations_by_height,
                    finalized_blocks,
                    marshal::Config {
                        provider,
                        epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                        start: marshal::Start::Genesis(TestBlock::new(0, 0)),
                        partition_prefix: "pending-floor-marshal".to_string(),
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

            let plan = SyncPlan::init(&context, "pending-floor-stateful".to_string()).await;
            let (stateful, mut mailbox) = Stateful::init(
                context.child("stateful"),
                Config {
                    application: TestApp,
                    db_config: (),
                    provider: (),
                    marshal,
                    mailbox_size: NZUsize!(8),
                    plan: plan.with_floor(finalization),
                    resolvers: NoopResolver,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: 1,
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
    fn dropped_verify_finishes_and_caches_state() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started_rx, mut release_tx, finished_rx) = verify_gate();
            let (app, _calls) = GatedApp::new([gate]);
            let (marshal, marshal_actor, _resolver_handler) =
                init_marshal_mailbox(context.child("marshal")).await;
            let (mut mailbox, actor) = start_processing(&context, app, marshal);

            let block = TestBlock::new(1, 1);
            let genesis = TestBlock::new(0, 0);
            let first_block = block.clone();
            let first_genesis = genesis.clone();
            let mut first_mailbox = mailbox.clone();
            let first = context.child("first_verify").spawn(move |task_context| {
                let consensus_context = first_block.context();
                async move {
                    first_mailbox
                        .verify(
                            (task_context, consensus_context),
                            ancestry::from_iter([Arc::new(first_block), Arc::new(first_genesis)]),
                        )
                        .await
                }
            });

            started_rx.await.expect("verification should start");
            first.abort();
            let _ = first.await;
            select! {
                _ = release_tx.closed() => {
                    panic!("dropped latest verification should keep executing");
                },
                _ = context.sleep(Duration::from_millis(1)) => {},
            }

            release_tx
                .send(())
                .expect("retained verification should still be running");
            finished_rx
                .await
                .expect("retained verification should finish");

            assert!(
                mailbox
                    .verify(
                        (context.child("cached_verify"), block.context()),
                        ancestry::from_iter([Arc::new(block), Arc::new(genesis)]),
                    )
                    .await,
                "completed verification state should be cached",
            );

            actor.abort();
            marshal_actor.abort();
            let _ = actor.await;
            let _ = marshal_actor.await;
        });
    }

    #[test]
    fn finalization_restarts_live_verification_without_dropping_caller() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (gate, started, mut release, finished) = verify_gate();
            let (app, calls) = GatedApp::new([gate]);
            let (marshal, marshal_actor, _resolver_handler) =
                init_marshal_mailbox(context.child("marshal")).await;
            let (mut mailbox, stateful_actor) = start_processing(&context, app, marshal);

            let block = TestBlock::new(1, 1);
            let genesis = TestBlock::new(0, 0);
            let verify_block = block.clone();
            let mut verify_mailbox = mailbox.clone();
            let verification = context.child("verify").spawn(move |task_context| {
                let consensus_context = verify_block.context();
                async move {
                    verify_mailbox
                        .verify(
                            (task_context, consensus_context),
                            ancestry::from_iter([Arc::new(verify_block), Arc::new(genesis)]),
                        )
                        .await
                }
            });
            started.await.expect("verification should start");

            let (acknowledgement, acknowledged) = Exact::handle();
            assert_eq!(
                mailbox.report(marshal::Update::Block(
                    Arc::new(block.clone()),
                    acknowledgement,
                )),
                Feedback::Ok,
            );
            acknowledged
                .await
                .expect("finalization should be acknowledged");
            release.closed().await;
            assert!(
                finished.await.is_err(),
                "the old application attempt should be dropped before finalization",
            );
            assert!(
                verification
                    .await
                    .expect("verification task should complete"),
                "the live request should be retried against finalized state",
            );
            assert_eq!(
                *calls.lock(),
                vec![
                    ApplicationCall::Verify(block.digest()),
                    ApplicationCall::Apply(block.digest()),
                ],
            );

            stateful_actor.abort();
            marshal_actor.abort();
            let _ = stateful_actor.await;
            let _ = marshal_actor.await;
        });
    }

    #[test]
    fn child_certification_rebuilds_parent_before_parent_certification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (child_gate, child_started, child_release, child_finished) = verify_gate();
            let (app, calls) = GatedApp::new([child_gate]);
            let (marshal, marshal_actor, _resolver_handler) =
                init_marshal_mailbox(context.child("marshal")).await;
            let (mailbox, stateful_actor) = start_processing(&context, app, marshal.clone());
            let (parent, child) = seed_chain(&marshal).await;
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mailbox,
                marshal,
                FixedEpocher::new(NZU64!(u64::MAX)),
            );

            let child_certification = marshaled
                .certify(child.context().round, child.digest())
                .await;
            child_started
                .await
                .expect("child verification should start");
            assert_eq!(
                *calls.lock(),
                vec![
                    ApplicationCall::Apply(parent.digest()),
                    ApplicationCall::Verify(child.digest()),
                ],
            );
            child_release
                .send(())
                .expect("child verification should still be running");
            child_finished
                .await
                .expect("child verification should finish");
            assert!(
                child_certification
                    .await
                    .expect("child certification result missing")
            );

            let parent_certification = marshaled
                .certify(parent.context().round, parent.digest())
                .await;
            assert!(
                parent_certification
                    .await
                    .expect("parent certification result missing")
            );
            assert_eq!(
                *calls.lock(),
                vec![
                    ApplicationCall::Apply(parent.digest()),
                    ApplicationCall::Verify(child.digest()),
                ],
                "parent certification should reuse the state rebuilt for its child",
            );

            stateful_actor.abort();
            marshal_actor.abort();
            let _ = stateful_actor.await;
            let _ = marshal_actor.await;
        });
    }

    #[test]
    fn child_certification_supersedes_abandoned_parent_certification() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, mut parent_release, parent_finished) = verify_gate();
            let (child_gate, child_started, child_release, child_finished) = verify_gate();
            let (app, calls) = GatedApp::new([parent_gate, child_gate]);
            let (marshal, marshal_actor, _resolver_handler) =
                init_marshal_mailbox(context.child("marshal")).await;
            let (mailbox, stateful_actor) = start_processing(&context, app, marshal.clone());
            let (parent, child) = seed_chain(&marshal).await;
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mailbox,
                marshal,
                FixedEpocher::new(NZU64!(u64::MAX)),
            );

            let parent_certification = marshaled
                .certify(parent.context().round, parent.digest())
                .await;
            parent_started
                .await
                .expect("parent verification should start");
            drop(parent_certification);

            let child_certification = marshaled
                .certify(child.context().round, child.digest())
                .await;
            parent_release.closed().await;
            assert!(
                parent_finished.await.is_err(),
                "abandoned parent verification should be cancelled"
            );
            child_started
                .await
                .expect("child verification should start after parent cancellation");
            assert_eq!(
                *calls.lock(),
                vec![
                    ApplicationCall::Verify(parent.digest()),
                    ApplicationCall::Apply(parent.digest()),
                    ApplicationCall::Verify(child.digest()),
                ],
            );
            child_release
                .send(())
                .expect("child verification should still be running");
            child_finished
                .await
                .expect("child verification should finish");
            assert!(
                child_certification
                    .await
                    .expect("child certification result missing")
            );

            let parent_certification = marshaled
                .certify(parent.context().round, parent.digest())
                .await;
            assert!(
                parent_certification
                    .await
                    .expect("parent certification result missing")
            );
            assert_eq!(
                *calls.lock(),
                vec![
                    ApplicationCall::Verify(parent.digest()),
                    ApplicationCall::Apply(parent.digest()),
                    ApplicationCall::Verify(child.digest()),
                ],
                "retried parent certification should reuse rebuilt state",
            );

            stateful_actor.abort();
            marshal_actor.abort();
            let _ = stateful_actor.await;
            let _ = marshal_actor.await;
        });
    }

    #[test]
    fn child_certification_completes_while_parent_certification_is_pending() {
        deterministic::Runner::timed(Duration::from_secs(5)).start(|context| async move {
            let (parent_gate, parent_started, parent_release, parent_finished) = verify_gate();
            let (child_gate, child_started, child_release, child_finished) = verify_gate();
            let (app, calls) = GatedApp::new([parent_gate, child_gate]);
            let (marshal, marshal_actor, _resolver_handler) =
                init_marshal_mailbox(context.child("marshal")).await;
            let (mailbox, stateful_actor) = start_processing(&context, app, marshal.clone());
            let (parent, child) = seed_chain(&marshal).await;
            let mut marshaled = Deferred::new(
                context.child("deferred"),
                mailbox,
                marshal,
                FixedEpocher::new(NZU64!(u64::MAX)),
            );

            let mut parent_certification = marshaled
                .certify(parent.context().round, parent.digest())
                .await;
            parent_started
                .await
                .expect("parent verification should start");

            let child_certification = marshaled
                .certify(child.context().round, child.digest())
                .await;
            select! {
                result = child_started => {
                    result.expect("child verification should start while its parent remains pending");
                },
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("pending parent certification blocked child certification");
                },
            }
            assert_eq!(
                *calls.lock(),
                vec![
                    ApplicationCall::Verify(parent.digest()),
                    ApplicationCall::Apply(parent.digest()),
                    ApplicationCall::Verify(child.digest()),
                ],
            );

            child_release
                .send(())
                .expect("child verification should still be running");
            child_finished
                .await
                .expect("child verification should finish");
            assert!(
                child_certification
                    .await
                    .expect("child certification result missing")
            );
            select! {
                result = &mut parent_certification => {
                    panic!("parent certification completed before release: {result:?}");
                },
                _ = context.sleep(Duration::from_millis(1)) => {},
            }

            parent_release
                .send(())
                .expect("parent verification should still be running");
            parent_finished
                .await
                .expect("parent verification should finish");
            assert!(
                parent_certification
                    .await
                    .expect("parent certification result missing")
            );

            stateful_actor.abort();
            marshal_actor.abort();
            let _ = stateful_actor.await;
            let _ = marshal_actor.await;
        });
    }
}
