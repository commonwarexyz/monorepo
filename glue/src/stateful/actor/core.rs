//! Consensus-facing stateful application that manages pending state on behalf of
//! an inner application.

use crate::stateful::{
    actor::{
        bootstrap::{
            bootstrap, metadata_partition, state_sync_done, BootstrapConfig, Completion,
            Mode as BootstrapMode,
        },
        mailbox::{ErasedAncestorStream, Message},
        metrics::Metrics as ProcessorMetrics,
        processor::{FinalizeStatus, Processor},
        Mailbox,
    },
    db::{Anchor, AttachableResolverSet, DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application,
};
use commonware_actor::mailbox as actor_mailbox;
use commonware_consensus::{
    marshal::{
        ancestry::BlockProvider,
        core::{Mailbox as MarshalMailbox, Variant as MarshalVariant},
        Start as MarshalStart,
    },
    simplex::types::Finalization,
    types::{Height, Round},
    CertifiableBlock, Epochable, Heightable, Viewable,
};
use commonware_cryptography::{certificate::Scheme, Digest, Digestible};
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    acknowledgement::Exact,
    channel::{fallible::OneshotExt, oneshot, ring},
    futures::OptionFuture,
    Acknowledgement,
};
use futures::{
    future::{pending, Either},
    SinkExt,
};
use rand::Rng;
use std::num::NonZeroUsize;
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

/// Startup plan that determines whether state sync is required and, when so,
/// which finalized floor to sync from.
///
/// Construction is two-phase so the caller can avoid fetching a finalized
/// floor from peers when state sync has already completed:
///
/// 1. [`SyncPlan::load`] reads the durable state-sync flag.
/// 2. If [`SyncPlan::needs_state_sync`] returns `true`, the caller fetches a
///    finalized floor and attaches it via [`SyncPlan::with_floor`]. Otherwise
///    the caller skips floor selection entirely.
///
/// The same plan is then passed to marshal (via [`SyncPlan::marshal_start`])
/// and to stateful (via [`Config::plan`]), guaranteeing both actors agree on
/// the startup decision.
pub struct SyncPlan<F> {
    partition_prefix: String,
    state_sync_complete: bool,
    floor: Option<F>,
}

impl<F> SyncPlan<F> {
    /// Load the durable state-sync completion flag for this partition prefix.
    ///
    /// # Panics
    ///
    /// Panics if the metadata store cannot be opened. A node that cannot
    /// determine whether state sync already completed cannot safely choose a
    /// startup path.
    pub async fn load<E>(context: E, partition_prefix: impl Into<String>) -> Self
    where
        E: Clock + Metrics + Storage,
    {
        let partition_prefix = partition_prefix.into();
        let state_sync_complete = state_sync_done(context, &partition_prefix).await;
        Self {
            partition_prefix,
            state_sync_complete,
            floor: None,
        }
    }

    /// Returns whether state sync should still run on this node.
    ///
    /// When `false`, the caller should skip floor selection: any floor passed
    /// to [`SyncPlan::with_floor`] would be ignored.
    pub const fn needs_state_sync(&self) -> bool {
        !self.state_sync_complete
    }

    /// Attach a finalized floor to state sync from.
    ///
    /// Has no effect if state sync has already completed.
    #[must_use]
    pub fn with_floor(mut self, floor: F) -> Self {
        if self.needs_state_sync() {
            self.floor = Some(floor);
        }
        self
    }
}

impl<S, C> SyncPlan<Finalization<S, C>>
where
    S: Scheme,
    C: Digest,
{
    /// Marshal startup anchor matching this plan.
    ///
    /// Callers should pass this into marshal's configuration before
    /// constructing stateful, so both actors are initialized from the same
    /// startup decision.
    pub fn marshal_start<B>(&self, genesis: B) -> MarshalStart<S, C, B> {
        self.floor.as_ref().map_or_else(
            || MarshalStart::Genesis(genesis),
            |finalization| MarshalStart::Floor(finalization.clone()),
        )
    }
}

/// Configuration for constructing a [`Stateful`] application.
pub struct Config<E, A, P, R, F>
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

    /// Startup plan loaded via [`SyncPlan::load`], optionally augmented with
    /// a finalized floor via [`SyncPlan::with_floor`]. Carries the durable
    /// metadata partition prefix and the startup decision shared with marshal.
    pub plan: SyncPlan<F>,

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
    target_sender: ring::Sender<AnchoredUpdate<A, E>>,

    /// Resolver set attached once sync completes.
    sync_resolvers: R,

    /// Verify requests held while syncing.
    ///
    /// The simplex voter keeps at most one in-flight verify request, so this
    /// list is bounded by protocol behavior.
    held_verify_requests: Vec<HeldVerify<E, A>>,

    /// Bootstrap completion, once database state sync has converged.
    completion: Option<Completion<E, A>>,

    /// Last finalized block acknowledged while syncing.
    last_acknowledged: Height,
}

impl<E, A, R> SyncingState<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    const fn new(
        app: A,
        target_sender: ring::Sender<AnchoredUpdate<A, E>>,
        sync_resolvers: R,
    ) -> Self {
        Self {
            app,
            target_sender,
            sync_resolvers,
            held_verify_requests: Vec::new(),
            completion: None,
            last_acknowledged: Height::zero(),
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
struct Shared<E, A, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
{
    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: ContextCell<E>,

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

    /// Marshal mailbox used for lazy block lookup.
    marshal: MarshalMailbox<S, V>,

    /// Attached database set and pending subscribers.
    database_attachment: DatabaseAttachment<A::Databases>,
}

/// Stateful application that manages the pending-tip DAG of merkleized
/// batches on behalf of an [`Application`], implementing the consensus
/// application and verifying traits.
pub struct Stateful<E, A, P, R, F>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Runtime context providing RNG, task spawning, metrics, and clock.
    context: ContextCell<E>,

    /// The receiver for messages.
    mailbox: actor_mailbox::Receiver<Message<E, A>>,

    /// The inner application that drives state transitions.
    inner: A,

    /// Source of input (e.g. transactions) passed to the application on propose.
    input_provider: A::InputProvider,

    /// Marshal mailbox used for startup anchoring and lazy recovery.
    marshal: P,

    /// Configuration used to initialize the database set at startup.
    db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Startup plan carrying the metadata partition prefix and floor decision.
    plan: SyncPlan<F>,

    /// Resolver(s) for startup sync fetches and post-bootstrap serving.
    resolvers: R,

    /// Sync engine tuning knobs.
    sync_config: SyncEngineConfig,
}

impl<E, A, P, R, F> Stateful<E, A, P, R, F>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    /// Construct a [`Stateful`] actor and its [`Mailbox`].
    ///
    /// This only wires dependencies and allocates the mailbox. The actor does
    /// not process messages until [`Stateful::start`] is called.
    pub fn init(context: E, config: Config<E, A, P, R, F>) -> (Self, Mailbox<E, A>) {
        let mailbox_size =
            NonZeroUsize::new(config.mailbox_size).expect("mailbox_size must be non-zero");
        let (sender, mailbox) = actor_mailbox::new(context.child("mailbox"), mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                inner: config.app,
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

    /// Start the actor and run startup bootstrap in the background.
    ///
    /// This is the single startup entrypoint for both modes:
    /// - No floor attached to the plan: initialize databases and backfill from marshal.
    /// - Floor attached to the plan: run one-time startup state sync.
    pub fn start<S, V>(self) -> Handle<()>
    where
        E: Rng + Spawner + Metrics + Clock + Storage,
        A: Application<E>,
        A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
        S: Scheme,
        V: MarshalVariant<ApplicationBlock = A::Block>,
        P: BlockProvider<Block = A::Block> + Clone + Into<MarshalMailbox<S, V>>,
        F: Into<Finalization<S, V::Commitment>>,
        MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
        R: AttachableResolverSet<A::Databases>,
    {
        let (target_sender, target_updates) = ring::channel(self.sync_config.update_channel_size);
        let (completion, bootstrap_completion) = oneshot::channel();
        let SyncPlan {
            partition_prefix,
            floor,
            state_sync_complete: _,
        } = self.plan;
        let (bootstrap_mode, pending_state_sync_floor_height) = floor.map_or_else(
            || (BootstrapMode::MarshalSync, None),
            |finalization| {
                let (floor_height_sender, floor_height_receiver) = oneshot::channel();
                let mode = BootstrapMode::StateSync {
                    finalization: finalization.into(),
                    target_updates,
                    state_sync_floor_height: floor_height_sender,
                };
                (mode, Some(floor_height_receiver))
            },
        );
        let bootstrap_app = self.inner.clone();
        let bootstrap_resolvers = self.resolvers.clone();
        let bootstrap_context = self.context.as_present().child("state_sync");
        let bootstrap_task_context = self.context.as_present().child("state_sync_bootstrap");
        let marshal: MarshalMailbox<S, V> = self.marshal.clone().into();
        let mut service = Service {
            mailbox: self.mailbox,
            marshal_sync: matches!(bootstrap_mode, BootstrapMode::MarshalSync),
            pending_state_sync_floor_height,
            shared: Shared {
                context: self.context,
                input_provider: self.input_provider,
                marshal: marshal.clone(),
                database_attachment: DatabaseAttachment::new(),
            },
            bootstrap_completion: Some(bootstrap_completion),
            mode: Mode::Syncing(SyncingState::new(self.inner, target_sender, self.resolvers)),
        };
        let bootstrap_config = BootstrapConfig {
            context: bootstrap_context,
            db_config: self.db_config,
            app: bootstrap_app,
            metadata_partition: metadata_partition(&partition_prefix),
            sync_config: self.sync_config,
            resolvers: bootstrap_resolvers,
            mode: bootstrap_mode,
            completion,
        };
        bootstrap_task_context.spawn(move |_| bootstrap(marshal, bootstrap_config));
        spawn_cell!(service.shared.context, service.run())
    }
}

/// Stateful application service.
struct Service<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    mailbox: actor_mailbox::Receiver<Message<E, A>>,
    marshal_sync: bool,
    pending_state_sync_floor_height: Option<oneshot::Receiver<Height>>,
    bootstrap_completion: Option<oneshot::Receiver<Completion<E, A>>>,
    shared: Shared<E, A, S, V>,
    mode: Mode<E, A, R>,
}

impl<E, A, S, V, R> Service<E, A, S, V, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
{
    const fn should_read_mailbox(&self) -> bool {
        // State sync starts from marshal's configured floor. Wait until
        // bootstrap tells us that floor height so finalized blocks are
        // interpreted relative to the state-sync floor, not Height::zero.
        if self.pending_state_sync_floor_height.is_some() {
            return false;
        }

        // Keep reading finalized blocks while bootstrap syncs databases if
        // state syncing. Those blocks drive target updates, and proposals/
        // verifies are still rejected or held by Syncing mode.
        if !self.marshal_sync {
            return true;
        }

        // Marshal sync does not need mailbox traffic to complete bootstrap.
        // Wait for database initialization/reconciliation before handling
        // proposals, verifies, or finalized blocks.
        self.bootstrap_completion.is_none()
    }

    async fn try_enter_processing(&mut self)
    where
        R: AttachableResolverSet<A::Databases>,
    {
        let transition = {
            let Mode::Syncing(syncing) = &mut self.mode else {
                return;
            };
            let Some(completion) = syncing.completion.as_ref() else {
                return;
            };
            if syncing.last_acknowledged < completion.last_processed.height {
                return;
            }

            let Completion {
                databases,
                last_processed,
            } = syncing
                .completion
                .take()
                .expect("completion must be present");
            let attached_databases = databases.clone();
            let processor = handle_sync_complete(
                self.shared.context.as_present(),
                self.shared.marshal.clone(),
                syncing,
                databases,
                last_processed,
            )
            .await;
            (attached_databases, processor)
        };

        let (databases, processor) = transition;
        self.shared.database_attachment.attach(databases);
        self.mode = Mode::Processing(processor);
    }

    async fn run(mut self)
    where
        R: AttachableResolverSet<A::Databases>,
    {
        select_loop! {
            self.shared.context,
            on_start => {
                self.shared.database_attachment.prune_closed_subscribers();
                let read_mailbox = self.should_read_mailbox();
                let state_sync_floor_height =
                    OptionFuture::from(self.pending_state_sync_floor_height.as_mut());
                let bootstrap_completion = OptionFuture::from(self.bootstrap_completion.as_mut());
                let mailbox_message = if read_mailbox {
                    Either::Left(self.mailbox.recv())
                } else {
                    Either::Right(pending())
                };
            },
            on_stopped => {
                debug!("context shutdown, stopping stateful application");
            },
            height = state_sync_floor_height => {
                self.pending_state_sync_floor_height = None;
                let height = height.expect("state-sync floor height channel closed");
                let Mode::Syncing(syncing) = &mut self.mode else {
                    panic!("received state-sync floor height while not syncing");
                };
                syncing.last_acknowledged = height;
                self.try_enter_processing().await;
            },
            result = bootstrap_completion => {
                self.bootstrap_completion = None;
                let completion = result.expect("bootstrap completion channel closed");
                let Mode::Syncing(syncing) = &mut self.mode else {
                    panic!("received bootstrap completion while not syncing");
                };
                if self.marshal_sync {
                    syncing.last_acknowledged = completion.last_processed.height;
                }
                syncing.completion = Some(completion);
                self.try_enter_processing().await;
            },
            Some(message) = mailbox_message else {
                debug!("mailbox closed, shutting down");
                break;
            } => {
                match (&mut self.mode, message) {
                    // Shared
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
                        handle_syncing_finalized(syncing, block, acknowledgement).await;
                        self.try_enter_processing().await;
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
                }
            },
        }
    }
}

async fn handle_syncing_finalized<E, A, R>(
    syncing: &mut SyncingState<E, A, R>,
    block: A::Block,
    acknowledgement: Exact,
) where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
{
    let height = block.height();
    if height <= syncing.last_acknowledged {
        acknowledgement.acknowledge();
        return;
    }

    assert_eq!(
        height,
        syncing.last_acknowledged.next(),
        "marshal must deliver contiguous finalized blocks while syncing",
    );

    let block_context = block.context();
    let update = (
        Anchor {
            height,
            round: Round::new(block_context.epoch(), block_context.view()),
            digest: block.digest(),
        },
        A::sync_targets(&block),
    );

    if syncing.target_sender.send(update).await.is_err() {
        debug!(
            height = height.get(),
            "sync target update ignored: bootstrap receiver closed"
        );
    }

    syncing.last_acknowledged = height;
    acknowledgement.acknowledge();
}

/// Handles bootstrap completion.
///
/// Attaches resolvers to the databases and returns a [`Processor`] ready for
/// consensus execution.
async fn handle_sync_complete<E, A, S, V, R>(
    context: &E,
    marshal: MarshalMailbox<S, V>,
    syncing: &mut SyncingState<E, A, R>,
    databases: A::Databases,
    last_processed: Anchor<<A::Block as Digestible>::Digest>,
) -> Processor<E, A>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    S: Scheme,
    V: MarshalVariant<ApplicationBlock = A::Block>,
    MarshalMailbox<S, V>: BlockProvider<Block = A::Block>,
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
