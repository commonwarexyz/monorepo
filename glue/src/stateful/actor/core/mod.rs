//! Stateful application that manages the pending-tip DAG of merkleized batches on behalf of an [`Application`].
//!
//! The [`Stateful`] actor is split into two control loops:
//! - [`Syncing`] manages the state sync process.
//! - [`Processing`] manages the pending-tip DAG and drives the inner application.

use crate::stateful::{
    actor::{
        core::{mailbox::Message, processing::Processing, syncing::Syncing},
        processor::{Processor, ProcessorMetrics},
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
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::channel::oneshot;
use futures::join;
use rand::Rng;
use std::num::NonZeroUsize;

mod mailbox;
pub use mailbox::Mailbox;

mod processing;
mod syncing;

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;

/// Configuration for constructing a [`Stateful`] application.
pub struct Config<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
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
    /// metadata partition prefix and the startup decision shared with marshal.
    pub plan: SyncPlan<S, V>,

    /// Resolver(s) for startup sync fetches and post-bootstrap serving.
    pub resolvers: R,

    /// Sync engine tuning knobs.
    pub sync_config: SyncEngineConfig,
}

/// Stateful application that manages the pending-tip DAG of merkleized
/// batches on behalf of an [`Application`], implementing the consensus
/// application and verifying traits.
pub struct Stateful<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
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

    /// Startup plan carrying the metadata partition prefix and floor decision.
    plan: SyncPlan<S, V>,

    /// Resolver(s) for startup sync fetches and post-bootstrap serving.
    resolvers: R,

    /// Sync engine tuning knobs.
    sync_config: SyncEngineConfig,
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
            panic!("interrupted startup sync must resume from a newly selected floor");
        } else {
            self.start_from_marshal().await;
        }
    }

    /// Starts the application in [`Syncing`] mode, kicking off a state sync process
    /// towards the finalized floor specified in the [`SyncPlan`].
    async fn start_state_sync(self, floor: Finalization<S, V::Commitment>) {
        let resolved_floor =
            syncer::resolve_startup_floor::<E, A, S, V>(&self.marshal, &floor).await;
        syncer::set_sync_in_progress(
            self.context.as_present(),
            self.plan.partition_prefix(),
            resolved_floor.marker,
        )
        .await;

        let (sync_complete, sync_completed) = oneshot::channel();
        let (syncer, syncer_mailbox) = syncer::Syncer::new(syncer::Config {
            context: self.context.child("syncer"),
            db_config: self.db_config,
            sync_config: self.sync_config,
            resolvers: self.resolvers.clone(),
            starting_anchor: resolved_floor.anchor,
            starting_targets: resolved_floor.targets,
            sync_complete,
        });
        let syncing = Syncing {
            context: self.context,
            mailbox: self.mailbox,
            application: self.application,
            input_provider: self.input_provider,
            marshal: self.marshal,
            partition_prefix: self.plan.partition_prefix().to_string(),
            syncer: syncer_mailbox,
            held_verify_requests: Vec::new(),
            database_subscribers: Vec::new(),
            artifact: None,
            resolvers: self.resolvers,
            sync_completed,
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
            self.plan.partition_prefix(),
            self.plan.sync_height(),
        )
        .await;

        // Attach the resolvers to the initialized databases before starting the processor,
        // so that this instance can serve peers database operations and proofs.
        self.resolvers.attach_databases(databases.clone()).await;

        let processor_metrics = ProcessorMetrics::new(self.context.child("processor"));
        let processor = Processor::new(self.application, databases, anchor, processor_metrics);
        Processing {
            context: self.context,
            mailbox: self.mailbox,
            input_provider: self.input_provider,
            marshal: self.marshal,
            resolvers: self.resolvers,
            processor,
            skip_finalized_until,
        }
        .start()
        .await
    }
}
