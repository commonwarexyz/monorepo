use super::{
    mailbox::{Mailbox, Message},
    resolve_state_sync_floor, BlockDigest, StateSyncMetadata, SyncResult,
};
use crate::stateful::{
    db::{Anchor, DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application,
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::types::Finalization,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    channel::{fallible::OneshotExt, oneshot, ring},
    futures::OptionFuture,
    sync::AsyncMutex,
    NZUsize,
};
use futures::SinkExt;
use rand::Rng;
use std::sync::Arc;
use tracing::{debug, error};

/// Configuration for [`Syncer`].
pub struct Config<E, A, R, S, V>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context used for metadata and database initialization.
    pub context: E,

    /// Database configuration for the managed set.
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Per-database sync engine parameters.
    pub sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    pub resolvers: R,

    /// Durable state-sync metadata.
    pub sync_metadata: Arc<AsyncMutex<StateSyncMetadata<E, V::Commitment>>>,

    /// Finalized floor marshal should resolve before sync starts.
    pub finalization: Finalization<S, V::Commitment>,

    /// Marshal mailbox used to query the finalized floor.
    pub marshal: MarshalMailbox<S, V>,

    /// Notifies the stateful actor when state sync has produced an artifact.
    pub sync_complete: oneshot::Sender<SyncResult<E, A>>,
}

pub struct Syncer<E, A, R, S, V>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
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

    /// Durable state-sync metadata.
    sync_metadata: Arc<AsyncMutex<StateSyncMetadata<E, V::Commitment>>>,

    /// Finalized floor marshal should resolve before sync starts.
    finalization: Finalization<S, V::Commitment>,

    /// Marshal mailbox used to query the finalized floor.
    marshal: MarshalMailbox<S, V>,

    /// Notifies the stateful actor when state sync has produced an artifact.
    sync_complete: Option<oneshot::Sender<SyncResult<E, A>>>,
}

impl<E, A, R, S, V> Syncer<E, A, R, S, V>
where
    E: Rng + Spawner + Metrics + Clock + Storage,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    R: Send + Sync + 'static,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    pub fn new(config: Config<E, A, R, S, V>) -> (Self, Mailbox<E, A>) {
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
                sync_metadata: config.sync_metadata,
                finalization: config.finalization,
                marshal: config.marshal,
                sync_complete: Some(config.sync_complete),
            },
            mailbox,
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    pub async fn run(mut self) {
        let resolved_floor =
            resolve_state_sync_floor::<E, A, S, V>(&self.marshal, &self.finalization).await;
        let sync_mode = {
            let mut sync_metadata = self.sync_metadata.lock().await;
            sync_metadata.begin_sync(resolved_floor.marker).await
        };

        let (mut tip_updates_tx, tip_updates_rx) = ring::channel(NZUsize!(1));
        let mut state_sync_task = OptionFuture::from(Some(Box::pin(A::Databases::sync(
            self.context.child("state_sync"),
            self.db_config,
            self.resolvers,
            resolved_floor.anchor,
            resolved_floor.targets,
            tip_updates_rx,
            self.sync_config,
            sync_mode,
        ))));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("syncer received stop signal, shutting down");
            },
            result = &mut state_sync_task => {
                match result {
                    Ok((databases, anchor)) => {
                        Self::publish_artifact(
                            &mut self.artifact,
                            &mut self.sync_complete,
                            databases,
                            anchor,
                        );
                        state_sync_task = None.into();
                    }
                    Err(err) => {
                        error!(?err, "critical: state sync task failed");
                        panic!("state sync task failed: {err:?}");
                    }
                }
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
                            Err(err) => {
                                error!(?err, "critical: state sync task failed");
                                panic!("state sync task failed: {err:?}");
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
