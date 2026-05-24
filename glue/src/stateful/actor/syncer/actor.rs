use super::{
    mailbox::{Mailbox, Message},
    BlockDigest, SyncResult,
};
use crate::stateful::{
    db::{Anchor, DatabaseSet, StateSyncSet, SyncEngineConfig},
    Application,
};
use commonware_actor::mailbox::{self as actor_mailbox, Receiver};
use commonware_consensus::{
    marshal::core::{CommitmentFallback, Mailbox as MarshalMailbox, Variant},
    simplex::types::Finalization,
};
use commonware_cryptography::certificate::Scheme;
use commonware_macros::select_loop;
use commonware_runtime::{spawn_cell, Clock, ContextCell, Handle, Metrics, Spawner, Storage};
use commonware_utils::{
    channel::{fallible::OneshotExt, ring},
    futures::OptionFuture,
    NZUsize,
};
use futures::SinkExt;
use rand::Rng;
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

    /// The partition prefix used for sync metadata storage.
    pub partition_prefix: String,

    /// Per-database sync engine parameters.
    pub sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    pub resolvers: R,

    /// Finalized floor marshal should resolve before sync starts.
    pub finalization: Finalization<S, V::Commitment>,

    /// Marshal mailbox used to query the finalized floor.
    pub marshal: MarshalMailbox<S, V>,
}

pub struct Syncer<E, A, R, S, V>
where
    E: Rng + Spawner + Metrics + Clock,
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

    /// The partition prefix used for sync metadata storage.
    partition_prefix: String,

    /// Per-database sync engine parameters.
    sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    resolvers: R,

    /// Finalized floor marshal should resolve before sync starts.
    finalization: Finalization<S, V::Commitment>,

    /// Marshal mailbox used to query the finalized floor.
    marshal: MarshalMailbox<S, V>,
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
                partition_prefix: config.partition_prefix,
                sync_config: config.sync_config,
                resolvers: config.resolvers,
                finalization: config.finalization,
                marshal: config.marshal,
            },
            mailbox,
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    pub async fn run(mut self) {
        let (starting_anchor, starting_targets) =
            Self::resolve_floor(self.marshal.clone(), self.finalization.clone()).await;
        let (mut tip_updates_tx, tip_updates_rx) = ring::channel(NZUsize!(1));
        let mut state_sync_task = OptionFuture::from(Some(Box::pin(A::Databases::sync(
            self.context.child("state_sync"),
            self.db_config,
            self.resolvers,
            starting_anchor,
            starting_targets,
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
                self.artifact = Some(SyncResult { databases, anchor });
                state_sync_task = None.into();
                super::set_sync_complete(self.context.as_present(), &self.partition_prefix).await;
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down syncer");
                break;
            } => match message {
                Message::TakeDatabases { response } => {
                    response.send_lossy(self.artifact.take());
                }
                Message::UpdateTargets { update, response } => {
                    if let Some(artifact) = self.artifact.take() {
                        response.send_lossy(Some(artifact));
                        continue;
                    }

                    // If sync had already completed, the state-sync branch above would
                    // have published `self.artifact` before this mailbox branch ran.
                    tip_updates_tx
                        .send(update)
                        .await
                        .expect("tip update receiver must remain alive while sync is in progress");
                    response.send_lossy(None);
                }
            },
        }
    }

    /// Resolves the initial [`Anchor`] and sync targets for the state sync process, based
    /// on the direct [`Finalization`] provided in the configuration.
    async fn resolve_floor(
        marshal: MarshalMailbox<S, V>,
        finalization: Finalization<S, V::Commitment>,
    ) -> (
        Anchor<BlockDigest<A, E>>,
        <A::Databases as DatabaseSet<E>>::SyncTargets,
    ) {
        // Wait to retrieve the floor block from marshal. We use `Wait` here,
        // since marshal triggers a fetch for the floor block if it is not
        // already available already.
        let floor = {
            let block = marshal
                .subscribe_by_commitment(finalization.proposal.payload, CommitmentFallback::Wait)
                .await
                .expect("marshal must yield floor block");
            V::into_inner(block)
        };
        let targets = A::sync_targets(&floor);

        (Anchor::from(&floor), targets)
    }
}
