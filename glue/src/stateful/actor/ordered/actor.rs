//! The ordered mode's actor.

use super::mailbox::{Mailbox, Merkleized, Message};
use crate::{
    executor::Update,
    stateful::{
        PruneConfig,
        actor::{
            durability::Durability,
            processor::{Prune, Pruning},
        },
        db::{AttachableResolverSet, DatabaseSet, StateSyncSet, SyncEngineConfig, TipUpdate},
        ordered::Application,
    },
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver};
use commonware_consensus::{
    Heightable as _,
    marshal::{Finalized, Ledger, Linear},
    types::{Height, OutputIndex},
};
use commonware_cryptography::Digestible;
use commonware_macros::{select, select_loop};
use commonware_runtime::{
    ContextCell, Handle, Spawner, spawn_cell,
    telemetry::metrics::{
        Gauge, GaugeExt as _, MetricsExt as _,
        histogram::{self, Buckets, Timed},
    },
};
use commonware_storage::Context;
use commonware_utils::{
    NZUsize,
    acknowledgement::Exact,
    channel::{fallible::OneshotExt as _, oneshot, ring},
};
use futures::{FutureExt as _, future::BoxFuture};
use rand_core::Rng;
use std::{collections::VecDeque, future, num::NonZeroUsize, pin::pin, sync::Arc};
use tracing::{debug, warn};

type SyncTargets<A, E> = <<A as Application<E>>::Databases as DatabaseSet<E>>::SyncTargets;

/// Configuration of an ordered [`Stateful`] actor.
pub struct Config<E, A, R>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
{
    /// The application that executes inputs and observes applied blocks.
    pub application: A,

    /// Configuration used to open the database set.
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Resolvers that fetch database operations from peers during a state sync, and serve this
    /// node's operations to peers once its databases are open.
    pub resolvers: R,

    /// Tuning of the state sync engines.
    pub sync_config: SyncEngineConfig,

    /// Capacity of the actor's mailbox.
    pub mailbox_size: NonZeroUsize,

    /// Periodic pruning of the databases and the executed chain.
    ///
    /// When enabled, stateful retains the executor's acknowledgement window plus one blocks, plus
    /// the configured retained windows, behind the applied tip. The databases also keep every
    /// operation a peer needs to sync to the newest certified checkpoint, and nothing is pruned
    /// before a checkpoint is certified.
    pub prune_config: Option<PruneConfig>,
}

/// An executed block that is not applied yet.
struct Pending<E, A>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
{
    height: Height,
    digest: <A::Block as Digestible>::Digest,
    /// The sync targets the block commits to.
    targets: SyncTargets<A, E>,
    /// The batches the block commits to, or `None` if it left state unchanged.
    merkleized: Option<Merkleized<A, E>>,
}

/// A block whose batches are being captured, applied, and observed.
struct Applying {
    /// Released once a database barrier covers the block.
    acknowledgement: Exact,
    future: BoxFuture<'static, ()>,
    timer: histogram::Timer,
}

/// Manages the databases of an [`Application`] whose inputs an executor runs.
///
/// See the [ordered mode documentation](crate::stateful::ordered).
pub struct Stateful<E, A, R>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
{
    context: ContextCell<E>,
    mailbox: Receiver<Message<E, A>>,
    application: A,
    /// Consumed when the databases are opened or synced.
    db_config: Option<<A::Databases as DatabaseSet<E>>::Config>,
    resolvers: R,
    sync_config: SyncEngineConfig,
    prune_config: Option<PruneConfig>,
}

impl<E, A, R> Stateful<E, A, R>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, Arc<A::Block>>,
    R: AttachableResolverSet<A::Databases>,
{
    /// Creates the actor and the [`Mailbox`] the executor uses as its application and consumer.
    ///
    /// The actor does nothing until [`start`](Self::start)ed.
    pub fn init(context: E, config: Config<E, A, R>) -> (Self, Mailbox<E, A>) {
        let (sender, mailbox) = actor_mailbox::new(context.child("mailbox"), config.mailbox_size);
        (
            Self {
                context: ContextCell::new(context),
                mailbox,
                application: config.application.clone(),
                db_config: Some(config.db_config),
                resolvers: config.resolvers,
                sync_config: config.sync_config,
                prune_config: config.prune_config,
            },
            Mailbox::new(sender, config.application),
        )
    }

    /// Starts the actor on `chain`, the [`Mailbox`](crate::executor::Mailbox) of the executor it
    /// serves.
    pub fn start<L>(mut self, chain: L) -> Handle<()>
    where
        L: Ledger<Block = A::Block> + Linear,
    {
        spawn_cell!(self.context, self.run(chain))
    }

    async fn run<L>(mut self, chain: L)
    where
        L: Ledger<Block = A::Block> + Linear,
    {
        let mut subscribers = Vec::new();
        let Some((databases, tip)) = self.open(&mut subscribers).await else {
            return;
        };
        self.resolvers.attach_databases(databases.clone()).await;
        for response in subscribers {
            response.send_lossy(databases.clone());
        }

        let pruning = self.prune_config.map(|config| {
            Pruning::random(
                config,
                chain.ack_window().get(),
                self.context.as_present_mut(),
            )
        });
        let pending_blocks = self.context.gauge(
            "pending_blocks",
            "Number of executed blocks awaiting application",
        );
        let finalize_duration = Timed::new(self.context.histogram(
            "finalize_duration",
            "Histogram of time taken to capture, apply, and observe a block's batches, in seconds",
            Buckets::LOCAL,
        ));
        Processing {
            context: self.context,
            mailbox: self.mailbox,
            application: self.application,
            databases,
            chain,
            applied: (tip.height(), A::sync_targets(&tip)),
            checkpoint: None,
            pending: VecDeque::new(),
            delivered: VecDeque::new(),
            applying: None,
            durability: Durability::new(tip.height()),
            pruning,
            prune: None,
            pending_blocks,
            finalize_duration,
        }
        .run()
        .await;
    }

    /// Opens the databases where the executor resumes: at the sync targets of the block it
    /// reports, or, for a chain without a base, by state-syncing them to the checkpointed blocks
    /// it offers. Returns the databases and the block they hold the state after, or `None` if the
    /// actor stopped first.
    async fn open(
        &mut self,
        subscribers: &mut Vec<oneshot::Sender<A::Databases>>,
    ) -> Option<(A::Databases, Arc<A::Block>)> {
        let mut synced = None;
        loop {
            let message = select! {
                _ = self.context.stopped() => return None,
                message = self.mailbox.recv() => message?,
            };
            match message {
                Message::Resume(tip) => {
                    let databases = match synced.take() {
                        Some((databases, base)) => {
                            assert_eq!(
                                tip.digest(),
                                Digestible::digest(&base),
                                "the executor resumes from a block other than the synced one"
                            );
                            databases
                        }
                        // Opening at the tip's targets discards any state a crash left beyond
                        // it, which the executor executes and delivers again.
                        None => {
                            A::Databases::init(
                                self.context.child("databases"),
                                self.db_config.take().expect("databases open once"),
                                Some(A::sync_targets(&tip)),
                            )
                            .await
                        }
                    };
                    return Some((databases, tip));
                }
                Message::Sync {
                    target,
                    updates,
                    response,
                } => {
                    let (databases, base) = self.sync(target, updates, subscribers).await?;
                    response.send_lossy(Arc::clone(&base));
                    synced = Some((databases, base));
                }
                Message::Databases { response } => subscribers.push(response),
                _ => panic!("the executor resumes before it executes"),
            }
        }
    }

    /// State-syncs the databases to `target`, following the newer targets `updates` offers, and
    /// returns them with the block they reached, or `None` if the actor stopped first.
    ///
    /// An update is recorded once the sync engines record it as their target, from which point
    /// they only converge on it or on a later target.
    async fn sync(
        &mut self,
        target: Arc<A::Block>,
        updates: ring::Receiver<Update<A::Block>>,
        subscribers: &mut Vec<oneshot::Sender<A::Databases>>,
    ) -> Option<(A::Databases, Arc<A::Block>)> {
        let (tips, tip_updates) = ring::channel(NZUsize!(1));
        let targets = A::sync_targets(&target);
        let mut sync = pin!(A::Databases::sync(
            self.context.child("sync"),
            self.db_config.take().expect("databases open once"),
            self.resolvers.clone(),
            target,
            targets,
            tip_updates,
            self.sync_config,
        ));
        let mut updates = Some(updates);
        loop {
            select! {
                _ = self.context.stopped() => return None,
                result = &mut sync => {
                    return Some(result.unwrap_or_else(|error| {
                        panic!("state sync failed: {error:?}")
                    }));
                },
                update = next_update(&mut updates) => match update {
                    Some(Update { block, recorded }) => {
                        let targets = A::sync_targets(&block);
                        tips.send_lossy(TipUpdate::observed_by(block, targets, recorded));
                    }
                    None => updates = None,
                },
                message = self.mailbox.recv() => match message? {
                    Message::Databases { response } => subscribers.push(response),
                    _ => panic!("the executor executes nothing while its state syncs"),
                },
            }
        }
    }
}

/// Waits for the next target the executor offers, if it still offers any.
async fn next_update<B: Send + Sync>(
    updates: &mut Option<ring::Receiver<Update<B>>>,
) -> Option<Update<B>> {
    match updates {
        Some(updates) => updates.recv().await,
        None => future::pending().await,
    }
}

/// The actor once its databases are open.
struct Processing<E, A, L>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    L: Ledger<Block = A::Block> + Linear,
{
    context: ContextCell<E>,
    mailbox: Receiver<Message<E, A>>,
    application: A,
    databases: A::Databases,
    chain: L,

    /// Height and sync targets of the newest applied block.
    applied: (Height, SyncTargets<A, E>),
    /// Executed blocks above the applied one, oldest first.
    pending: VecDeque<Pending<E, A>>,
    /// Blocks the executor delivered that are not applied yet, oldest first.
    delivered: VecDeque<Finalized<A::Block>>,
    /// The application in flight, always of the oldest pending block.
    applying: Option<Applying>,
    durability: Durability,
    pruning: Option<Pruning<SyncTargets<A, E>>>,
    /// The newest prune selected by the schedule and not run yet.
    prune: Option<Prune<SyncTargets<A, E>>>,
    /// Height and sync targets of the newest block a checkpoint certified, which peers sync to.
    checkpoint: Option<(Height, SyncTargets<A, E>)>,

    pending_blocks: Gauge,
    finalize_duration: Timed,
}

impl<E, A, L> Processing<E, A, L>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    L: Ledger<Block = A::Block> + Linear,
{
    async fn run(mut self) {
        select_loop! {
            self.context,
            on_start => {
                if self.applying.is_none() {
                    self.maintain().await;
                    self.start_application();
                }
            },
            on_stopped => {
                debug!("stateful stopped");
            },
            Some(message) = self.mailbox.recv() else break => {
                self.handle(message).await;
            },
            () = next_application(&mut self.applying) => {
                let Applying {
                    acknowledgement,
                    timer,
                    ..
                } = self.applying.take().expect("an application was in flight");
                timer.observe(self.context.as_ref());
                self.applied(acknowledgement, true);
            },
            completion = self.durability.completion() => {
                if !self.durability.complete(completion) {
                    debug!("runtime stopped before a database sync completed");
                    break;
                }
            },
        }
    }

    async fn handle(&mut self, message: Message<E, A>) {
        match message {
            Message::Resume(_) | Message::Sync { .. } => panic!("the executor resumes once"),
            Message::Certified(block) => {
                self.checkpoint = Some((block.height(), A::sync_targets(&block)));
            }
            Message::Fork { height, response } => {
                assert_eq!(
                    height,
                    self.tip().0.next(),
                    "the executor executes each height once, in order"
                );
                // Only a changed block's application locks the databases, and it keeps that block
                // pending until it completes, so reading the databases here never waits on it.
                let batches = match self
                    .pending
                    .iter()
                    .rev()
                    .find_map(|pending| pending.merkleized.as_ref())
                {
                    Some(parent) => A::Databases::fork_batches(parent),
                    None => self.databases.new_batches().await,
                };
                response.send_lossy((batches, self.tip().1.clone()));
            }
            Message::Executed {
                height,
                digest,
                targets,
                merkleized,
            } => {
                assert_eq!(
                    height,
                    self.tip().0.next(),
                    "executed block does not extend the tip"
                );
                self.pending.push_back(Pending {
                    height,
                    digest,
                    targets,
                    merkleized,
                });
                let _ = self.pending_blocks.try_set(self.pending.len());
            }
            Message::Finalized(block) => self.delivered.push_back(block),
            Message::Databases { response } => {
                response.send_lossy(self.databases.clone());
            }
        }
    }

    /// Returns the height and sync targets of the newest executed block.
    fn tip(&self) -> (Height, &SyncTargets<A, E>) {
        self.pending.back().map_or_else(
            || (self.applied.0, &self.applied.1),
            |pending| (pending.height, &pending.targets),
        )
    }

    /// Prunes once the selected prune target is durable, then starts a barrier over applied
    /// state. Neither overlaps another database mutation.
    async fn maintain(&mut self) {
        if self.durability.has_barrier() {
            return;
        }
        if let Some(prune) = self
            .prune
            .take_if(|prune| self.durability.covers(prune.barrier_height))
        {
            // Peers sync to the newest certified checkpoint, so the databases keep its operations,
            // and are not pruned before one is certified.
            if let Some((height, targets)) = &self.checkpoint {
                let target = if *height < prune.barrier_height {
                    targets
                } else {
                    &prune.qmdb_target
                };
                self.databases.prune(target).await;
            }
            if let Err(error) = self
                .chain
                .prune(OutputIndex::new(prune.marshal_height.get()))
                .await
            {
                warn!(%error, "executed chain did not prune");
            }
        }
        if self.durability.needs_barrier() {
            let height = self.durability.applied();
            let barrier = self.databases.finalize().await;
            self.durability.set_barrier(height, barrier);
        }
    }

    /// Starts applying the oldest delivered block once stateful has seen it executed, completing
    /// at once every block that left state unchanged.
    fn start_application(&mut self) {
        while self.applying.is_none() {
            let (Some(delivered), Some(pending)) = (self.delivered.front(), self.pending.front())
            else {
                return;
            };
            assert_eq!(
                pending.height,
                delivered.block.height(),
                "the executor delivers blocks in order"
            );
            assert_eq!(
                pending.digest,
                delivered.block.digest(),
                "the executor delivers the block stateful executed"
            );
            let batches = pending.merkleized.clone();
            let Finalized {
                block,
                acknowledgement,
                ..
            } = self.delivered.pop_front().expect("a block was delivered");
            let Some(batches) = batches else {
                self.applied(acknowledgement, false);
                continue;
            };

            let mut application = self.application.clone();
            let databases = self.databases.clone();
            let capture = self.context.child("capture");
            let finalized = self.context.child("finalized");
            let future = async move {
                let captured = application
                    .capture(capture, &block, &batches, databases.readers())
                    .await;
                databases.apply(batches).await;
                application
                    .finalized(finalized, &block, captured, databases.readers())
                    .await;
            }
            .boxed();
            self.applying = Some(Applying {
                acknowledgement,
                future,
                timer: self.finalize_duration.timer(self.context.as_ref()),
            });
        }
    }

    /// Records that the oldest pending block is applied, holding its acknowledgement until a
    /// barrier covers it. A block that left state `changed` false needs no barrier of its own.
    fn applied(&mut self, acknowledgement: Exact, changed: bool) {
        let Pending {
            height, targets, ..
        } = self
            .pending
            .pop_front()
            .expect("the applied block was pending");
        let _ = self.pending_blocks.try_set(self.pending.len());
        if changed {
            self.durability.record(height, acknowledgement);
        } else {
            self.durability.record_unchanged(height, acknowledgement);
        }
        if let Some(prune) = self
            .pruning
            .as_mut()
            .and_then(|pruning| pruning.observe(height, targets.clone()))
        {
            self.prune = Some(prune);
        }
        self.applied = (height, targets);
    }
}

/// Waits for the application in flight, if any.
async fn next_application(applying: &mut Option<Applying>) {
    match applying {
        Some(applying) => (&mut applying.future).await,
        None => future::pending().await,
    }
}
