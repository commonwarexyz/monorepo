//! Consensus-facing stateful application that manages pending state on behalf of
//! an inner application.

use crate::stateful::{
    actor::{
        bootstrap::{bootstrap, BootstrapConfig, Mode as BootstrapMode},
        mailbox::{ErasedAncestorStream, Message},
        metrics::Metrics as ProcessorMetrics,
        processor::{FinalizeStatus, Processor},
        Mailbox,
    },
    db::{Anchor, AttachableResolverSet, DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application,
};
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
    },
    types::Height,
    Heightable,
};
use commonware_cryptography::{certificate::Scheme, Digestible};
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, mpsc, oneshot, ring},
    Acknowledgement,
};
use futures::SinkExt;
use rand::Rng;
use tracing::{debug, info};

type BlockDigest<A, E> = <<A as Application<E>>::Block as Digestible>::Digest;
type AnchoredUpdate<A, E> = (
    Anchor<BlockDigest<A, E>>,
    <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets,
);

/// Buffered verify request while startup sync is in progress.
struct HeldVerify<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    context: (E, A::Context),
    ancestry: ErasedAncestorStream<A::Block>,
    response: oneshot::Sender<bool>,
}

/// Buffered finalization while startup sync is in progress.
struct HeldFinalization<B> {
    block: B,
    acknowledgement: Exact,
}

/// Tracks the attached database set and pending subscribers.
struct DatabaseAttachment<D: Clone> {
    databases: Option<D>,
    subscribers: Vec<oneshot::Sender<D>>,
}

impl<D: Clone> DatabaseAttachment<D> {
    const fn new() -> Self {
        Self {
            databases: None,
            subscribers: Vec::new(),
        }
    }

    fn prune_closed_subscribers(&mut self) {
        self.subscribers
            .retain(|subscriber| !subscriber.is_closed());
    }

    fn subscribe(&mut self, response: oneshot::Sender<D>) {
        let Some(databases) = self.databases.clone() else {
            self.subscribers.push(response);
            return;
        };
        response.send_lossy(databases);
    }

    fn attach(&mut self, databases: D) {
        self.databases = Some(databases.clone());
        for subscriber in self.subscribers.drain(..) {
            subscriber.send_lossy(databases.clone());
        }
    }
}

const STATE_SYNC_METADATA_SUFFIX: &str = "_state_sync_metadata";

/// Startup mode for the [`Stateful`] application.
pub enum StartupMode<B> {
    /// Initialize databases and let marshal backfill.
    MarshalSync,
    /// State sync the databases, starting at the given block's embedded targets.
    ///
    /// It is up to the user to determine whether or not this block is a valid member
    /// of the canonical chain.
    StateSync { block: B },
}

/// Configuration for constructing a [`Stateful`] application.
pub struct Config<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The inner application that drives state transitions.
    pub app: A,

    /// Configuration used to construct the database set.
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Source of input (e.g. transactions) passed to the application on propose.
    pub input_provider: A::InputProvider,

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    pub marshal: P,

    /// Capacity of the stateful actor mailbox channel.
    pub mailbox_size: usize,

    /// Partition prefix used to derive the durable state-sync metadata partition.
    pub partition_prefix: String,

    /// Explicit startup mode.
    pub startup: StartupMode<A::Block>,

    /// Resolver(s) for startup sync fetches and post-bootstrap serving.
    pub resolvers: R,

    /// Sync engine tuning knobs.
    pub sync_config: SyncEngineConfig,
}

/// Actor state while state sync is in progress.
struct SyncingState<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// The inner application that drives state transitions.
    app: A,

    /// Anchored target updates forwarded to the bootstrap sync task.
    tip_sender: ring::Sender<AnchoredUpdate<A, E>>,

    /// Resolver set attached once sync completes.
    sync_resolvers: R,

    /// Verify requests held while syncing.
    ///
    /// The simplex voter keeps at most one in-flight verify request, so this
    /// list is bounded by protocol behavior.
    held_verify_requests: Vec<HeldVerify<E, A>>,

    /// Finalizations held while syncing.
    ///
    /// Marshal bounds in-flight application updates by `max_pending_acks`,
    /// so this list is also bounded by protocol behavior.
    held_finalizations: Vec<HeldFinalization<A::Block>>,
}

impl<E, A, R> SyncingState<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    const fn new(
        app: A,
        tip_sender: ring::Sender<AnchoredUpdate<A, E>>,
        sync_resolvers: R,
    ) -> Self {
        Self {
            app,
            tip_sender,
            sync_resolvers,
            held_verify_requests: Vec::new(),
            held_finalizations: Vec::new(),
        }
    }
}

/// Runtime actor mode.
enum Mode<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Actor is syncing startup state.
    Syncing(SyncingState<E, A, R>),

    /// Actor is processing consensus-driven execution with marshal backfill sync.
    Processing(Processor<E, A>),
}

/// Application dependencies shared across both modes.
struct Shared<E, A, P>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: ContextCell<E>,

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    marshal: P,

    /// Attached database set and pending subscribers.
    database_attachment: DatabaseAttachment<A::Databases>,
}

/// Stateful application that manages the pending-tip DAG of merkleized
/// batches on behalf of an [`Application`], implementing the consensus
/// application and verifying traits.
pub struct Stateful<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Sender half of the actor mailbox channel.
    sender: mpsc::Sender<Message<E, A>>,

    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: ContextCell<E>,

    /// The receiver for messages.
    mailbox: mpsc::Receiver<Message<E, A>>,

    /// The inner application that drives state transitions.
    inner: A,

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    marshal: P,

    /// Configuration used to initialize the database set at startup.
    db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Partition prefix used to derive the durable state-sync metadata partition.
    partition_prefix: String,

    /// Explicit startup mode.
    startup: StartupMode<A::Block>,

    /// Resolver(s) for startup sync fetches and post-bootstrap serving.
    resolvers: R,

    /// Sync engine tuning knobs.
    sync_config: SyncEngineConfig,
}

impl<E, A, P, R> Stateful<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Construct a [`Stateful`] actor and its [`Mailbox`].
    ///
    /// This only wires dependencies and allocates the mailbox. The actor does
    /// not process messages until [`Stateful::start`] is called.
    pub fn init(context: E, config: Config<E, A, P, R>) -> (Self, Mailbox<E, A>) {
        let (sender, mailbox) = mpsc::channel(config.mailbox_size);
        (
            Self {
                sender: sender.clone(),
                context: ContextCell::new(context),
                mailbox,
                inner: config.app,
                input_provider: config.input_provider,
                marshal: config.marshal,
                db_config: config.db_config,
                partition_prefix: config.partition_prefix,
                startup: config.startup,
                resolvers: config.resolvers,
                sync_config: config.sync_config,
            },
            Mailbox::new(sender),
        )
    }

    /// Start the actor and run startup bootstrap in the background.
    ///
    /// This is the single startup entrypoint for both modes:
    /// - [`StartupMode::MarshalSync`]: initialize databases and backfill from marshal.
    /// - [`StartupMode::StateSync`]: run one-time startup state sync.
    pub fn start<S, V>(self) -> Handle<()>
    where
        E: Rng + Spawner + Metrics + Clock + Storage,
        A: Application<E>,
        A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        P: BlockProvider<Block = A::Block> + Into<MarshalMailbox<S, V>>,
        R: AttachableResolverSet<A::Databases>,
    {
        let (tip_sender, target_updates) = ring::channel(self.sync_config.update_channel_size);
        let bootstrap_mode = match self.startup {
            StartupMode::MarshalSync => BootstrapMode::MarshalSync,
            StartupMode::StateSync { block } => BootstrapMode::StateSync {
                block,
                target_updates,
            },
        };
        let bootstrap_resolvers = self.resolvers.clone();
        let bootstrap_context = self.context.as_present().child("state_sync");
        let bootstrap_task_context = self.context.as_present().child("state_sync_bootstrap");
        let mut service = Service {
            mailbox: self.mailbox,
            shared: Shared {
                context: self.context,
                input_provider: self.input_provider,
                marshal: self.marshal,
                database_attachment: DatabaseAttachment::new(),
            },
            mode: Mode::Syncing(SyncingState::new(self.inner, tip_sender, self.resolvers)),
        };
        let bootstrap_config = BootstrapConfig {
            context: bootstrap_context,
            db_config: self.db_config,
            metadata_partition: format!("{}{STATE_SYNC_METADATA_SUFFIX}", self.partition_prefix),
            sync_config: self.sync_config,
            resolvers: bootstrap_resolvers,
            mode: bootstrap_mode,
        };
        let marshal: MarshalMailbox<S, V> = service.shared.marshal.clone().into();
        let mailbox = Mailbox::new(self.sender);
        bootstrap_task_context.spawn(move |_| bootstrap(marshal, mailbox, bootstrap_config));
        spawn_cell!(service.shared.context, service.run())
    }
}

/// Stateful application service.
struct Service<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    mailbox: mpsc::Receiver<Message<E, A>>,
    shared: Shared<E, A, P>,
    mode: Mode<E, A, R>,
}

impl<E, A, P, R> Service<E, A, P, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    async fn run(mut self)
    where
        R: AttachableResolverSet<A::Databases>,
    {
        select_loop! {
            self.shared.context,
            on_start => {
                self.shared.database_attachment.prune_closed_subscribers();
            },
            on_stopped => {
                debug!("context shutdown, stopping stateful application");
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down");
                break;
            } => {
                match (&mut self.mode, message) {
                    // Shared
                    (_, Message::Genesis { response }) => {
                        let genesis = match &mut self.mode {
                            Mode::Syncing(syncing) => syncing.app.genesis().await,
                            Mode::Processing(processor) => processor.genesis().await,
                        };
                        response.send_lossy(genesis);
                    }
                    (_, Message::SubscribeDatabases { response }) => {
                        self.shared.database_attachment.subscribe(response);
                    }

                    // Syncing Mode
                    (Mode::Syncing(_), Message::Propose { response, .. }) => {
                        debug!("proposal rejected: state sync in progress");
                        response.send_lossy(None);
                    }
                    (
                        Mode::Syncing(syncing),
                        Message::Verify {
                            context,
                            ancestry,
                            response,
                        },
                    ) => {
                        syncing
                            .held_verify_requests
                            .retain(|request| !request.response.is_closed());
                        syncing.held_verify_requests.push(HeldVerify {
                            context,
                            ancestry,
                            response,
                        });
                        debug!(
                            held_verify_requests = syncing.held_verify_requests.len(),
                            "verify held: state sync in progress"
                        );
                    }
                    (
                        Mode::Syncing(syncing),
                        Message::Finalized {
                            block,
                            acknowledgement,
                        },
                    ) => {
                        debug!(
                            height = block.height().get(),
                            "finalization held during sync"
                        );
                        syncing.held_finalizations.push(HeldFinalization {
                            block,
                            acknowledgement,
                        });
                    }
                    (Mode::Syncing(syncing), Message::Tip { height, digest }) => {
                        handle_tip(&mut self.shared, syncing, height, digest).await;
                    }
                    (
                        Mode::Syncing(syncing),
                        Message::SyncComplete {
                            databases,
                            last_processed,
                        },
                    ) => {
                        let attached_databases = databases.clone();
                        let processor = handle_sync_complete(
                            self.shared.context.as_present(),
                            self.shared.marshal.clone(),
                            syncing,
                            databases,
                            last_processed,
                        )
                        .await;
                        self.shared.database_attachment.attach(attached_databases);
                        self.mode = Mode::Processing(processor);
                    }

                    // Processing mode
                    (
                        Mode::Processing(processor),
                        Message::Propose {
                            context,
                            ancestry,
                            response,
                        },
                    ) => {
                        processor
                            .propose(
                                self.shared.context.as_present(),
                                self.shared.marshal.clone(),
                                context,
                                ancestry,
                                &mut self.shared.input_provider,
                                response,
                            )
                            .await;
                    }
                    (
                        Mode::Processing(processor),
                        Message::Verify {
                            context,
                            ancestry,
                            response,
                        },
                    ) => {
                        processor
                            .verify(
                                self.shared.context.as_present(),
                                self.shared.marshal.clone(),
                                context,
                                ancestry,
                                response,
                            )
                            .await;
                    }
                    (
                        Mode::Processing(processor),
                        Message::Finalized {
                            block,
                            acknowledgement,
                        },
                    ) => {
                        if let FinalizeStatus::Persisted { height } = processor
                            .finalize(self.shared.context.as_present(), block)
                            .await
                        {
                            debug!(height = height.get(), "persisted finalized database batch");
                        }
                        acknowledgement.acknowledge();
                    }
                    (Mode::Processing(_), Message::Tip { .. }) => {}
                    (Mode::Processing(_), Message::SyncComplete { .. }) => {}
                }
            },
        }
    }
}

/// Handles a [`Message::Tip`].
///
/// In [`Mode::Syncing`], fetches the block from marshal, extracts
/// per-database sync targets via [`Application::sync_targets`], and
/// forwards them to the background sync engines.
async fn handle_tip<E, A, P, R>(
    shared: &mut Shared<E, A, P>,
    syncing: &mut SyncingState<E, A, R>,
    height: Height,
    digest: <A::Block as Digestible>::Digest,
) where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
{
    let Some(block) = shared.marshal.clone().fetch_block(digest).await else {
        debug!(
            height = height.get(),
            "tip block not available from provider, skipping target update"
        );
        return;
    };

    let anchored_update = (Anchor { height, digest }, A::sync_targets(&block));
    if syncing.tip_sender.send(anchored_update).await.is_err() {
        debug!(
            height = height.get(),
            "tip update channel unavailable, skipping target update"
        );
    }
}

/// Handles a [`Message::SyncComplete`].
///
/// Attaches resolvers to the databases and returns a [`Processor`] ready for
/// consensus execution.
async fn handle_sync_complete<E, A, P, R>(
    context: &E,
    marshal: P,
    syncing: &mut SyncingState<E, A, R>,
    databases: A::Databases,
    last_processed: Anchor<<A::Block as Digestible>::Digest>,
) -> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    P: BlockProvider<Block = A::Block>,
    R: AttachableResolverSet<A::Databases>,
{
    let app = syncing.app.clone();
    syncing
        .sync_resolvers
        .attach_databases(databases.clone())
        .await;
    let metrics = ProcessorMetrics::new(context.child("processor_metrics"));
    let mut processor = Processor::new(app, databases, last_processed, metrics);

    // In case any verification requests were delivered after the floor was updated,
    // process them now to ensure we progress consensus.
    for HeldVerify {
        context: request_context,
        ancestry,
        response,
    } in syncing.held_verify_requests.drain(..)
    {
        processor
            .verify(
                context,
                marshal.clone(),
                request_context,
                ancestry,
                response,
            )
            .await;
    }

    // In case any finalizations were delivered after the floor was updated,
    // process them now to ensure we progress marshal.
    for HeldFinalization {
        block,
        acknowledgement,
    } in syncing.held_finalizations.drain(..)
    {
        if block.height() <= last_processed.height {
            // Block is already persisted at or below the reconciled floor.
            // The acknowledgement can be dropped, since marshal cancels
            // pending acks when the floor is updated.
            continue;
        }
        processor.finalize(context, block).await;
        acknowledgement.acknowledge();
    }

    info!("sync complete, database attached to processor");
    processor
}

#[cfg(test)]
mod tests {
    use super::DatabaseAttachment;
    use commonware_utils::channel::oneshot;

    #[test]
    fn database_attachment_notifies_pending_subscribers() {
        let mut attachment = DatabaseAttachment::new();
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();

        attachment.subscribe(tx1);
        attachment.subscribe(tx2);
        attachment.attach(7u64);

        assert_eq!(rx1.blocking_recv(), Ok(7));
        assert_eq!(rx2.blocking_recv(), Ok(7));
    }

    #[test]
    fn database_attachment_replays_to_late_subscribers() {
        let mut attachment = DatabaseAttachment::new();
        attachment.attach(11u64);

        let (tx, rx) = oneshot::channel();
        attachment.subscribe(tx);

        assert_eq!(rx.blocking_recv(), Ok(11));
    }

    #[test]
    fn database_attachment_prunes_closed_subscribers() {
        let mut attachment = DatabaseAttachment::new();
        let (closed_tx, closed_rx) = oneshot::channel::<u64>();
        let (open_tx, open_rx) = oneshot::channel();

        drop(closed_rx);
        attachment.subscribe(closed_tx);
        attachment.subscribe(open_tx);

        assert_eq!(attachment.subscribers.len(), 2);

        attachment.prune_closed_subscribers();

        assert_eq!(attachment.subscribers.len(), 1);

        attachment.attach(13u64);
        assert_eq!(open_rx.blocking_recv(), Ok(13));
    }
}
