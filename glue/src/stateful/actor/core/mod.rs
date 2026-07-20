//! Stateful application that manages the pending-tip DAG of merkleized batches on behalf of an [`Application`].
//!
//! The [`Stateful`] actor is split into two control loops:
//! - [`Syncing`] manages the state sync process.
//! - [`Processing`] manages the pending-tip DAG and drives the inner application.

use crate::stateful::{
    actor::{
        core::{mailbox::Message, processing::Processing, syncing::Syncing},
        metrics::Metrics as StatefulMetrics,
        processor::Processor,
        syncer::{self, SyncPlan, SyncResult},
    },
    db::{AttachableResolverSet, DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application,
};
use commonware_actor::mailbox::{self as actor_mailbox};
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    simplex::types::Finalization,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_runtime::{spawn_cell, telemetry::metrics::GaugeExt, ContextCell, Handle, Spawner};
use commonware_storage::Context;
use commonware_utils::{channel::oneshot, sync::AsyncMutex};
use futures::join;
use rand_core::Rng;
use std::{num::NonZeroUsize, sync::Arc};

mod mailbox;
pub use mailbox::Mailbox;

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

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub input_provider: A::InputProvider,

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

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

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
                input_provider: config.input_provider,
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
        let sync_metadata = Arc::new(AsyncMutex::new(self.plan.into_sync_metadata()));
        let (sync_complete, sync_completed) = oneshot::channel();
        let (syncer, syncer_mailbox) = syncer::Syncer::new(syncer::Config {
            context: self.context.child("syncer"),
            db_config: self.db_config,
            sync_config: self.sync_config,
            resolvers: self.resolvers.clone(),
            sync_metadata: sync_metadata.clone(),
            finalization: floor,
            marshal: self.marshal.clone(),
            sync_complete,
        });
        let syncing = Syncing {
            context: self.context,
            mailbox: self.mailbox,
            application: self.application,
            input_provider: self.input_provider,
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
            input_provider: self.input_provider,
            marshal: self.marshal,
            processor,
            skip_finalized_until,
        }
        .start()
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Stateful};
    use crate::stateful::{
        actor::syncer::SyncPlan,
        db::{AttachableResolver, ManagedDb, Shared as SharedDb, StateSyncDb, SyncEngineConfig},
        tests::mocks::{
            TestApp, TestBlock, TestDb, TestMerkleized, TestScheme, TestUnmerkleized, TestVariant,
        },
        Application, Proposed,
    };
    use commonware_consensus::{
        marshal::{self, ancestry, core::Actor as MarshalActor, Update},
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Context as SimplexContext, Finalization, Finalize, Proposal},
        },
        types::{Epoch, FixedEpocher, Round, View, ViewDelta},
        Application as _, CertifiableBlock as _, Heightable as _, Reporter as _,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        ed25519,
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, reschedule, Clock as _, Error as RuntimeError,
        Handle, Runner as _, Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{
        channel::{mpsc, oneshot},
        sync::{Mutex, TracedAsyncRwLock},
        Acknowledgement as _, NZUsize, NZU16, NZU64,
    };
    use futures::Stream;
    use std::{convert::Infallible, sync::Arc, time::Duration};

    #[derive(Clone)]
    struct NoopResolver;

    impl AttachableResolver<TestDb> for NoopResolver {
        async fn attach_database(&self, _db: Arc<TracedAsyncRwLock<TestDb>>) {}
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

            let plan = SyncPlan::init(&context, "pending-floor-stateful".to_string()).await;
            let (stateful, mut mailbox) = Stateful::init(
                context.child("stateful"),
                Config {
                    application: TestApp,
                    db_config: (),
                    input_provider: (),
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
    /// Pending finalize syncs, oldest first: each entry releases (or fails)
    /// one [`GatedFinalizeDb::finalize`] durability handle.
    type FinalizeGate = Arc<Mutex<Vec<oneshot::Sender<Result<(), RuntimeError>>>>>;

    /// A database whose finalize durability handles are released by the test.
    struct GatedFinalizeDb {
        gate: FinalizeGate,
    }

    impl<E: Send> ManagedDb<E> for GatedFinalizeDb {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Error = Infallible;
        type Config = FinalizeGate;
        type SyncTarget = u64;

        fn initial_sync_target() -> Self::SyncTarget {
            0
        }

        async fn init(_context: E, gate: Self::Config) -> Result<Self, Self::Error> {
            Ok(Self { gate })
        }

        async fn new_batch(_db: &SharedDb<Self>) -> Self::Unmerkleized {
            TestUnmerkleized
        }

        fn matches_sync_target(_batch: &Self::Merkleized, _target: &Self::SyncTarget) -> bool {
            true
        }

        async fn finalize(&mut self, _batch: Self::Merkleized) -> Result<Handle<()>, Self::Error> {
            let (sender, receiver) = oneshot::channel();
            self.gate.lock().push(sender);
            Ok(Handle::from_receiver(receiver))
        }

        fn sync_target(&self) -> Self::SyncTarget {
            0
        }

        async fn rewind_to_target(&mut self, _target: Self::SyncTarget) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    impl StateSyncDb<deterministic::Context, NoopResolver> for GatedFinalizeDb {
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
            unreachable!("this test never runs peer state sync")
        }
    }

    impl AttachableResolver<GatedFinalizeDb> for NoopResolver {
        async fn attach_database(&self, _db: SharedDb<GatedFinalizeDb>) {}
    }

    /// An application recording the heights delivered to `finalized`.
    #[derive(Clone)]
    struct GatedApp {
        finalized: Arc<Mutex<Vec<u64>>>,
    }

    impl Application<deterministic::Context> for GatedApp {
        type SigningScheme = TestScheme;
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
        type Block = TestBlock;
        type Databases = SharedDb<GatedFinalizeDb>;
        type InputProvider = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            TestBlock::new(0, 0)
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
            _batches: TestUnmerkleized,
            _input: &mut Self::InputProvider,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            None
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Stream<Item = Arc<Self::Block>> + Send,
            _batches: TestUnmerkleized,
        ) -> Option<TestMerkleized> {
            None
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> TestMerkleized {
            TestMerkleized
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            _databases: &Self::Databases,
        ) {
            self.finalized.lock().push(block.height().get());
        }
    }

    /// Acknowledge-everything reporter for the marshal actor: this harness
    /// bypasses marshal dispatch (updates are reported straight into the
    /// stateful mailbox), so marshal's own reporter sees nothing relevant.
    #[derive(Clone)]
    struct NoopReporter;

    impl commonware_consensus::Reporter for NoopReporter {
        type Activity = Update<TestBlock>;

        fn report(&mut self, activity: Self::Activity) -> commonware_actor::Feedback {
            if let Update::Block(_, ack) = activity {
                ack.acknowledge();
            }
            commonware_actor::Feedback::Ok
        }
    }

    /// A resolver that records nothing and fetches nothing: this harness
    /// never needs marshal to backfill.
    #[derive(Clone)]
    struct NullResolver;

    impl commonware_resolver::Resolver for NullResolver {
        type Key = marshal::resolver::handler::Key<Sha256Digest>;
        type Subscriber = marshal::resolver::handler::Annotation;

        fn fetch<F>(&mut self, _fetch: F) -> commonware_actor::Feedback
        where
            F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            commonware_actor::Feedback::Ok
        }

        fn fetch_all<F>(&mut self, _fetches: Vec<F>) -> commonware_actor::Feedback
        where
            F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            commonware_actor::Feedback::Ok
        }

        fn retain(
            &mut self,
            _predicate: impl Fn(&Self::Key, &Self::Subscriber) -> bool + Send + 'static,
        ) -> commonware_actor::Feedback {
            commonware_actor::Feedback::Ok
        }
    }

    impl commonware_resolver::TargetedResolver for NullResolver {
        type PublicKey = ed25519::PublicKey;

        fn fetch_targeted(
            &mut self,
            _fetch: impl Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
            _targets: commonware_utils::vec::NonEmptyVec<Self::PublicKey>,
        ) -> commonware_actor::Feedback {
            commonware_actor::Feedback::Ok
        }

        fn fetch_all_targeted<F>(
            &mut self,
            _fetches: Vec<(F, commonware_utils::vec::NonEmptyVec<Self::PublicKey>)>,
        ) -> commonware_actor::Feedback
        where
            F: Into<commonware_resolver::Fetch<Self::Key, Self::Subscriber>> + Send,
        {
            commonware_actor::Feedback::Ok
        }
    }

    /// Marshal + Stateful harness over [`GatedApp`], started without a state
    /// sync floor (startup recovers from marshal's genesis).
    async fn start_gated_stateful(
        context: &deterministic::Context,
        prefix: &str,
    ) -> (
        super::Mailbox<deterministic::Context, GatedApp>,
        FinalizeGate,
        Arc<Mutex<Vec<u64>>>,
        Handle<()>,
        marshal::resolver::handler::Handler<Sha256Digest>,
    ) {
        let mut signing_context = context.child("signing");
        let fixture = scheme_mocks::fixture(&mut signing_context, prefix.as_bytes(), 1);
        let provider = ConstantProvider::new(fixture.schemes[0].clone());

        let page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8));
        let finalizations_by_height = immutable::Archive::init(
            context.child("finalizations_by_height"),
            archive_config(page_cache.clone(), &format!("{prefix}-finalizations")),
        )
        .await
        .expect("failed to initialize finalizations archive");
        let finalized_blocks = immutable::Archive::init(
            context.child("finalized_blocks"),
            archive_config(page_cache.clone(), &format!("{prefix}-blocks")),
        )
        .await
        .expect("failed to initialize blocks archive");

        let (marshal_actor, marshal, _height) =
            MarshalActor::<_, TestVariant, _, _, _, _, _>::init(
                context.child("marshal"),
                finalizations_by_height,
                finalized_blocks,
                marshal::Config {
                    provider,
                    epocher: FixedEpocher::new(NZU64!(u64::MAX)),
                    start: marshal::Start::Genesis(TestBlock::new(0, 0)),
                    partition_prefix: format!("{prefix}-marshal"),
                    mailbox_size: NZUsize!(8),
                    view_retention_timeout: ViewDelta::new(1),
                    prunable_items_per_section: NZU64!(4),
                    page_cache,
                    replay_buffer: NZUsize!(64),
                    key_write_buffer: NZUsize!(64),
                    value_write_buffer: NZUsize!(64),
                    block_codec_config: (),
                    max_repair: NZUsize!(1),
                    max_pending_acks: NZUsize!(4),
                    strategy: Sequential,
                },
            )
            .await;
        // The marshal actor must run: startup anchors the databases by
        // querying it for the genesis floor block.
        // The handler half must stay alive for the whole test: the marshal
        // actor shuts down when it closes.
        let (resolver_rx, resolver_handler) =
            marshal::resolver::handler::init(context.child("resolver_handler"), NZUsize!(8));
        let _marshal_handle =
            marshal_actor.start_unbuffered(NoopReporter, (resolver_rx, NullResolver));

        let gate: FinalizeGate = Arc::new(Mutex::new(Vec::new()));
        let finalized = Arc::new(Mutex::new(Vec::new()));
        let plan = SyncPlan::init(context, format!("{prefix}-stateful")).await;
        let (stateful, mailbox) = Stateful::init(
            context.child("stateful"),
            Config {
                application: GatedApp {
                    finalized: finalized.clone(),
                },
                db_config: gate.clone(),
                input_provider: (),
                marshal,
                mailbox_size: NZUsize!(8),
                plan,
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
        (mailbox, gate, finalized, handle, resolver_handler)
    }

    /// Wait until `gate` holds exactly `count` pending finalize syncs.
    async fn wait_for_pending(gate: &FinalizeGate, count: usize) {
        while gate.lock().len() != count {
            reschedule().await;
        }
    }

    /// The external effects of a finalized block — the application's
    /// `finalized` notification and the marshal acknowledgement — gate on
    /// the database sync's durability handle, while the actor keeps serving
    /// the mailbox (and even the NEXT finalized block's execution) during
    /// the in-flight sync. Effects release strictly in block order.
    #[test]
    fn finalized_effects_gate_on_durability() {
        deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
            let (mut mailbox, gate, finalized, handle, _resolver_handler) =
                start_gated_stateful(&context, "ack-order").await;

            // Startup complete once the database set is attached.
            let _ = mailbox.subscribe_databases().await;

            // Deliver block 1: its sync parks on the gate, so neither the
            // acknowledgement nor the finalized notification may fire.
            let (ack1, waiter1) = commonware_utils::acknowledgement::Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(TestBlock::new(1, 1)), ack1));
            wait_for_pending(&gate, 1).await;
            futures::pin_mut!(waiter1);
            assert!(
                futures::poll!(waiter1.as_mut()).is_pending(),
                "acknowledgement must wait for durability"
            );
            assert!(
                finalized.lock().is_empty(),
                "notification must wait for durability"
            );

            // The actor keeps serving the mailbox while the sync is parked.
            let _ = mailbox.subscribe_databases().await;

            // Deliver block 2: the actor executes it and starts its sync
            // (two parked syncs), with block 1's effects still gated.
            let (ack2, waiter2) = commonware_utils::acknowledgement::Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(TestBlock::new(2, 2)), ack2));
            wait_for_pending(&gate, 2).await;
            futures::pin_mut!(waiter2);
            assert!(futures::poll!(waiter1.as_mut()).is_pending());
            assert!(futures::poll!(waiter2.as_mut()).is_pending());
            assert!(finalized.lock().is_empty());

            // Release block 1's sync: exactly its effects fire, in order.
            let release1 = gate.lock().remove(0);
            release1.send(Ok(())).unwrap();
            waiter1.await.expect("block 1 must be acknowledged");
            assert_eq!(*finalized.lock(), vec![1]);
            assert!(
                futures::poll!(waiter2.as_mut()).is_pending(),
                "block 2 must stay gated on its own sync"
            );

            // Release block 2's sync: its effects follow.
            let release2 = gate.lock().remove(0);
            release2.send(Ok(())).unwrap();
            waiter2.await.expect("block 2 must be acknowledged");
            assert_eq!(*finalized.lock(), vec![1, 2]);

            handle.abort();
        });
    }

    /// A finalize sync failure is fatal: the actor panics rather than
    /// acknowledging (or reporting) state that was never made durable.
    #[test]
    #[should_panic(expected = "database finalize sync failed")]
    fn finalized_sync_failure_is_fatal() {
        deterministic::Runner::timed(Duration::from_secs(60)).start(|context| async move {
            let (mut mailbox, gate, _finalized, _handle, _resolver_handler) =
                start_gated_stateful(&context, "ack-fail").await;

            let _ = mailbox.subscribe_databases().await;
            let (ack1, waiter1) = commonware_utils::acknowledgement::Exact::handle();
            let _ = mailbox.report(Update::Block(Arc::new(TestBlock::new(1, 1)), ack1));
            wait_for_pending(&gate, 1).await;

            let release = gate.lock().remove(0);
            release.send(Err(RuntimeError::WriteFailed)).unwrap();
            // The actor's panic unwinds through the runner before this waiter
            // can resolve.
            let _ = waiter1.await;
            unreachable!("the failed sync must abort the actor");
        });
    }
}
