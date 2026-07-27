use super::{
    BlockDigest, SyncResult,
    mailbox::{Artifact, Mailbox, Message},
    resolve_state_sync_floor,
};
use crate::stateful::{
    Application,
    db::{DatabaseSet, StateSyncSet, SyncEngineConfig},
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver};
use commonware_consensus::{
    marshal::core::{Mailbox as MarshalMailbox, Variant},
    simplex::types::Finalization,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select_loop;
use commonware_runtime::{ContextCell, Handle, Spawner, spawn_cell};
use commonware_storage::Context;
use commonware_utils::{
    NZUsize,
    channel::{fallible::OneshotExt, oneshot, ring},
    futures::OptionFuture,
};
use futures::SinkExt;
use rand_core::Rng;
use tracing::debug;

/// Configuration for [`Syncer`].
pub struct Config<E, A, R, S, V>
where
    E: Rng + Spawner + Context,
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

    /// Finalized floor marshal should resolve before sync starts.
    pub finalization: Finalization<S, V::Commitment>,

    /// Marshal mailbox used to query the finalized floor.
    pub marshal: MarshalMailbox<S, V>,

    /// Notifies the stateful actor when state sync has produced an artifact.
    pub sync_complete: oneshot::Sender<SyncResult<E, A>>,
}

pub struct Syncer<E, A, R, S, V>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context.
    context: ContextCell<E>,

    /// The mailbox.
    mailbox: Receiver<Message<E, A>>,

    /// Whether the completed artifact already went out on the completion channel.
    delivered: bool,

    /// Database configuration for the managed set.
    db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Per-database sync engine parameters.
    sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    resolvers: R,

    /// Finalized floor marshal should resolve before sync starts.
    finalization: Finalization<S, V::Commitment>,

    /// Marshal mailbox used to query the finalized floor.
    marshal: MarshalMailbox<S, V>,

    /// Notifies the stateful actor when state sync has produced an artifact.
    sync_complete: Option<oneshot::Sender<SyncResult<E, A>>>,
}

impl<E, A, R, S, V> Syncer<E, A, R, S, V>
where
    E: Rng + Spawner + Context,
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
                delivered: false,
                db_config: config.db_config,
                sync_config: config.sync_config,
                resolvers: config.resolvers,
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

        let (mut tip_updates_tx, tip_updates_rx) = ring::channel(NZUsize!(1));
        let mut state_sync_task = OptionFuture::from(Some(Box::pin(A::Databases::sync(
            self.context.child("state_sync"),
            self.db_config,
            self.resolvers,
            resolved_floor.anchor,
            resolved_floor.targets,
            tip_updates_rx,
            self.sync_config,
        ))));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("syncer received stop signal, shutting down");
            },
            result = &mut state_sync_task => match result {
                Ok((databases, anchor)) => {
                    self.delivered = true;
                    if let Some(sync_complete) = self.sync_complete.take() {
                        sync_complete.send_lossy(SyncResult { databases, anchor });
                    }
                    state_sync_task = None.into();
                }
                Err(err) => {
                    panic!("state sync task failed: {err:?}");
                }
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down syncer");
                break;
            } => match message {
                Message::UpdateTargets { update, response } => {
                    if self.delivered {
                        // The artifact already went out on the completion channel, so
                        // the caller collects it from there.
                        response.send_lossy(Some(Artifact::Announced));
                        continue;
                    }

                    // If sync had already completed, the state-sync branch above would
                    // have marked delivery before this mailbox branch ran.
                    if tip_updates_tx.send(update).await.is_err() {
                        // Tuple sync closes the live tip-update receiver as soon as the
                        // coordinator converges, before the database tasks have necessarily
                        // finished. Treat that close as "wait for the in-flight sync task to
                        // produce its artifact", not as a hard failure. The artifact travels
                        // with this response, so the completion channel stays unused.
                        match (&mut state_sync_task).await {
                            Ok((databases, anchor)) => {
                                self.delivered = true;
                                state_sync_task = None.into();
                                response.send_lossy(Some(Artifact::Delivered(SyncResult {
                                    databases,
                                    anchor,
                                })));
                            }
                            Err(err) => {
                                panic!("state sync task failed: {err:?}");
                            }
                        }
                        continue;
                    }
                    response.send_lossy(None);
                }
            },
        }
    }

}
