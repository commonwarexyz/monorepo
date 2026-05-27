use super::{
    mailbox::{Mailbox, Message},
    BlockDigest, SyncResult,
};
use crate::stateful::{
    db::{Anchor, DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application,
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver};
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot, ring},
    futures::OptionFuture,
    NZUsize,
};
use futures::SinkExt;
use rand::Rng;
use tracing::{debug, error};

/// Configuration for [`Syncer`].
pub struct Config<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
{
    /// Runtime context used for metadata and database initialization.
    pub context: E,

    /// Database configuration for the managed set.
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Per-database sync engine parameters.
    pub sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    pub resolvers: R,

    /// Anchor where startup state sync begins.
    pub starting_anchor: Anchor<BlockDigest<A, E>>,

    /// Initial targets derived from the resolved startup floor block.
    pub starting_targets: <A::Databases as DatabaseSet<E>>::SyncTargets,

    /// Notifies the stateful actor when state sync has produced an artifact.
    pub sync_complete: oneshot::Sender<SyncResult<E, A>>,
}

pub struct Syncer<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
{
    /// Runtime context.
    context: ContextCell<E>,

    /// The mailbox.
    mailbox: Receiver<Message<E, A>>,

    /// The produced state sync artifact, if complete.
    artifact: Option<SyncResult<E, A>>,

    /// Database configuration for the managed set.
    db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Per-database sync engine parameters.
    sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    resolvers: R,

    /// Anchor where startup state sync begins.
    starting_anchor: Anchor<BlockDigest<A, E>>,

    /// Initial targets derived from the resolved startup floor block.
    starting_targets: <A::Databases as DatabaseSet<E>>::SyncTargets,

    /// Notifies the stateful actor when state sync has produced an artifact.
    sync_complete: Option<oneshot::Sender<SyncResult<E, A>>>,
}

impl<E, A, R> Syncer<E, A, R>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    R: Send + Sync + 'static,
{
    pub fn new(config: Config<E, A, R>) -> (Self, Mailbox<E, A>) {
        let (sender, receiver) = actor_mailbox::new(config.context.child("mailbox"), NZUsize!(1));
        let mailbox = Mailbox::new(sender);
        (
            Self {
                context: ContextCell::new(config.context),
                mailbox: receiver,
                artifact: None,
                db_config: config.db_config,
                sync_config: config.sync_config,
                resolvers: config.resolvers,
                starting_anchor: config.starting_anchor,
                starting_targets: config.starting_targets,
                sync_complete: Some(config.sync_complete),
            },
            mailbox,
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    pub async fn run(mut self) {
        let (mut tip_updates_tx, tip_updates_rx) = ring::channel(NZUsize!(1));
        let mut state_sync_task = OptionFuture::from(Some(Box::pin(A::Databases::sync(
            self.context.child("state_sync"),
            self.db_config,
            self.resolvers,
            self.starting_anchor,
            self.starting_targets,
            tip_updates_rx,
            self.sync_config,
        ))));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("syncer received stop signal, shutting down");
            },
            Ok((databases, anchor)) = &mut state_sync_task else {
                error!("critical: state sync task failed");
                panic!("state sync task failed");
            } => {
                Self::publish_artifact(
                    &mut self.artifact,
                    &mut self.sync_complete,
                    databases,
                    anchor,
                );
                state_sync_task = None.into();
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down syncer");
                break;
            } => match message {
                Message::UpdateTargets { update, response } => {
                    if let Some(artifact) = self.artifact.clone() {
                        response.send_lossy(Some(artifact));
                        continue;
                    }

                    // If sync had already completed, the state-sync branch above would
                    // have published `self.artifact` before this mailbox branch ran.
                    if tip_updates_tx.send(update).await.is_err() {
                        // Tuple sync closes the live tip-update receiver as soon as the
                        // coordinator converges, before the database tasks have necessarily
                        // finished. Treat that close as "wait for the in-flight sync task to
                        // publish its artifact", not as a hard failure.
                        match (&mut state_sync_task).await {
                            Ok((databases, anchor)) => {
                                Self::publish_artifact(
                                    &mut self.artifact,
                                    &mut self.sync_complete,
                                    databases,
                                    anchor,
                                );
                                state_sync_task = None.into();
                            }
                            Err(_) => {
                                error!("critical: state sync task failed");
                                panic!("state sync task failed");
                            }
                        }
                        response.send_lossy(self.artifact.clone());
                        continue;
                    }
                    response.send_lossy(None);
                }
            },
        }
    }

    fn publish_artifact(
        artifact: &mut Option<SyncResult<E, A>>,
        sync_complete: &mut Option<oneshot::Sender<SyncResult<E, A>>>,
        databases: A::Databases,
        anchor: Anchor<BlockDigest<A, E>>,
    ) {
        let sync_result = SyncResult { databases, anchor };
        *artifact = Some(sync_result.clone());
        if let Some(sync_complete) = sync_complete.take() {
            sync_complete.send_lossy(sync_result);
        }
    }
}
