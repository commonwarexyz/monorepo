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
    db::{
        assert_rewind_window_safety, AttachableResolverSet, DatabaseSet, StateSyncSet,
        SyncEngineConfig,
    },
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
use commonware_runtime::{
    spawn_cell, telemetry::metrics::GaugeExt, Clock, ContextCell, Handle, Metrics, Spawner, Storage,
};
use commonware_utils::{channel::oneshot, sync::AsyncMutex};
use futures::join;
use rand::Rng;
use std::{num::NonZeroUsize, sync::Arc};

mod mailbox;
pub use mailbox::Mailbox;

mod processing;
mod syncing;

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

/// Opens the dequeue-side child of a mailbox request's span, separating queue
/// wait from processing time in traces.
fn process_span(parent: &tracing::Span) -> tracing::Span {
    tracing::info_span!(parent: parent, "stateful.actor.process")
}

/// Periodic pruning configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PruneConfig {
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
    E: Rng + Spawner + Metrics + Clock + Storage,
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

    /// Marshal ack window used by the provided marshal mailbox.
    ///
    /// This must match the marshal config used to construct [`Self::marshal`].
    pub max_pending_acks: NonZeroUsize,

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
    E: Rng + Spawner + Metrics + Clock + Storage,
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

    /// Marshal ack window, used to derive automatic prune retention.
    max_pending_acks: NonZeroUsize,

    /// Periodic prune configuration.
    prune_config: Option<PruneConfig>,
}

impl<E, A, S, V, R> Stateful<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
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
        assert_rewind_window_safety::<E, A::Databases>(config.max_pending_acks);
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
                max_pending_acks: config.max_pending_acks,
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
            panic!("interrupted state sync must resume from a newly selected floor");
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
            max_pending_acks: self.max_pending_acks,
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
        // so that this instance can serve peers database operations and proofs.
        self.resolvers.attach_databases(databases.clone()).await;

        keep_resolvers_alive(self.context.as_present(), self.resolvers);

        let metrics = StatefulMetrics::new(self.context.as_present());
        let _ = metrics.sync_done.try_set(1);
        let processor = Processor::new(
            self.application,
            databases,
            anchor,
            metrics,
            self.max_pending_acks,
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

fn keep_resolvers_alive<E, R>(context: &E, resolvers: R)
where
    E: Spawner,
    R: Send + 'static,
{
    context
        .child("resolver_keepalive")
        .spawn(|context| async move {
            let _ = context.stopped().await;
            drop(resolvers);
        });
}

#[cfg(test)]
mod tests {
    use super::{Config, Stateful};
    use crate::stateful::{
        actor::syncer::SyncPlan,
        db::{AttachableResolver, StateSyncDb, SyncEngineConfig},
        tests::mocks::{TestApp, TestBlock, TestDb, TestScheme, TestVariant},
    };
    use commonware_consensus::{
        marshal::{self, ancestry, core::Actor as MarshalActor},
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Finalization, Finalize, Proposal},
        },
        types::{Epoch, FixedEpocher, Round, View, ViewDelta},
        Application as _, CertifiableBlock as _,
    };
    use commonware_cryptography::{
        certificate::{mocks::Fixture, ConstantProvider},
        sha256::Digest as Sha256Digest,
    };
    use commonware_macros::select;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, Clock as _, Runner as _, Supervisor as _,
    };
    use commonware_storage::archive::immutable;
    use commonware_utils::{channel::mpsc, sync::AsyncRwLock, NZUsize, NZU16, NZU64};
    use std::{convert::Infallible, sync::Arc, time::Duration};

    #[derive(Clone)]
    struct NoopResolver;

    impl AttachableResolver<TestDb> for NoopResolver {
        async fn attach_database(&self, _db: Arc<AsyncRwLock<TestDb>>) {}
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
            freezer_table_partition: format!("{partition}-table"),
            freezer_table_initial_size: 4,
            freezer_table_resize_frequency: 2,
            freezer_table_resize_chunk_size: 2,
            freezer_key_partition: format!("{partition}-key"),
            freezer_key_page_cache: page_cache,
            freezer_value_partition: format!("{partition}-value"),
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
                    max_pending_acks: NZUsize!(1),
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
}
