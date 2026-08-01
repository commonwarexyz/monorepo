use super::{
    BlockDigest, SyncResult,
    mailbox::{Mailbox, Message},
    resolve_state_sync_floor,
};
use crate::stateful::{
    Application,
    db::{Anchor, DatabaseSet, StateSyncSet, SyncEngineConfig},
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

    /// The produced state sync artifact, if complete.
    artifact: Option<SyncResult<E, A>>,

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
                artifact: None,
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

        let (tip_updates_tx, tip_updates_rx) = ring::channel(NZUsize!(1));
        let mut tip_updates_tx = Some(tip_updates_tx);
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
                    Self::publish_artifact(
                        &mut self.artifact,
                        &mut self.sync_complete,
                        databases,
                        anchor,
                    );
                    state_sync_task = None.into();

                    // A tip update enqueued after the coordinator's final drain has no
                    // receiver left to record it or release its observation barrier.
                    // Dropping the sender frees the ring buffer, so the observer of any
                    // queued update retries and receives the artifact.
                    tip_updates_tx = None;
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
                    if let Some(artifact) = self.artifact.clone() {
                        response.send_lossy(Some(artifact));
                        continue;
                    }

                    // If sync had already completed, the state-sync branch above would
                    // have published `self.artifact` before this mailbox branch ran.
                    let tip_updates = tip_updates_tx
                        .as_mut()
                        .expect("ring sender lives until the artifact is published");
                    if tip_updates.send(update).await.is_err() {
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
                                panic!("state sync task failed: {err:?}");
                            }
                        }
                        tip_updates_tx = None;
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

#[cfg(test)]
mod tests {
    use super::{Config, Syncer};
    use crate::stateful::{
        Application, Input, Proposed,
        db::{Anchor, Barrier, DatabaseSet, StateSyncSet, SyncEngineConfig, TipUpdate},
        tests::{
            fixtures::{self, MarshalFixture},
            mocks::{TestBlock, TestMerkleized, TestScheme, TestUnmerkleized, TestVariant, anchor},
        },
    };
    use commonware_consensus::{
        marshal::ancestry::Ancestry,
        simplex::{mocks::scheme as scheme_mocks, types::Context as SimplexContext},
        types::Height,
    };
    use commonware_cryptography::{
        ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_runtime::{
        Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{
        NZU64, NZUsize,
        channel::{oneshot, ring},
    };
    use std::{convert::Infallible, time::Duration};

    /// Database set whose sync holds the tip-update ring receiver without draining it, then
    /// completes once the actor has parked a forwarded update in the ring buffer.
    #[derive(Clone)]
    struct WedgeSet;

    impl DatabaseSet<deterministic::Context> for WedgeSet {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Config = ();
        type SyncTargets = u64;

        async fn init(_context: deterministic::Context, _config: Self::Config) -> Self {
            unreachable!("WedgeSet is constructed by sync")
        }

        fn initial_sync_targets() -> Self::SyncTargets {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn new_batches(&self) -> Self::Unmerkleized {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        fn fork_batches(_parent: &Self::Merkleized) -> Self::Unmerkleized {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        fn matches_sync_targets(_batches: &Self::Merkleized, _targets: &Self::SyncTargets) -> bool {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn finalize(&self, _batches: Self::Merkleized) -> Barrier {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn prune(&self, _targets: &Self::SyncTargets) {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn committed_targets(&self) -> Self::SyncTargets {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn rewind_to_targets(&self, _targets: Self::SyncTargets) {
            unreachable!("WedgeSet only serves the syncer harness")
        }
    }

    impl StateSyncSet<deterministic::Context, (), Sha256Digest> for WedgeSet {
        type Error = Infallible;

        async fn sync(
            context: deterministic::Context,
            _config: Self::Config,
            _resolvers: (),
            anchor: Anchor<Sha256Digest>,
            _targets: Self::SyncTargets,
            tip_updates: ring::Receiver<TipUpdate<Sha256Digest, Self::SyncTargets>>,
            _sync_config: SyncEngineConfig,
        ) -> Result<(Self, Anchor<Sha256Digest>), Self::Error> {
            // Hold the ring receiver without draining it. The deterministic clock advances
            // only at quiescence, so the sleep fires only once every other task has parked,
            // which includes the actor forwarding a tip update into the ring buffer.
            // Completing then drops the receiver with the update still queued.
            context.sleep(Duration::from_secs(1)).await;
            drop(tip_updates);
            Ok((Self, anchor))
        }
    }

    #[derive(Clone)]
    struct WedgeApp;

    impl Application<deterministic::Context> for WedgeApp {
        type SigningScheme = TestScheme;
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
        type Block = TestBlock;
        type Databases = WedgeSet;
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            use commonware_consensus::Heightable as _;
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            unreachable!("WedgeApp only serves the syncer harness")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            unreachable!("WedgeApp only serves the syncer harness")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Option<TestMerkleized> {
            unreachable!("WedgeApp only serves the syncer harness")
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> TestMerkleized {
            unreachable!("WedgeApp only serves the syncer harness")
        }
    }

    /// A tip update stranded in the ring buffer by sync completion must resolve through the
    /// caller's retry with the completed artifact, not wedge its observation forever.
    #[test]
    fn stranded_tip_update_resolves_to_artifact() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncer-wedge", 1);
            let block = TestBlock::new(0, 0);
            let finalization = fixtures::finalization(&fixture, 0, Sha256::fill(0));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncer-wedge",
                fixture.schemes[0].clone(),
                Some((&block, finalization.clone())),
                NZUsize!(1),
                true,
            )
            .await;

            let (sync_complete, sync_completed) = oneshot::channel();
            let (syncer, mailbox) =
                Syncer::<_, WedgeApp, (), TestScheme, TestVariant>::new(Config {
                    context: context.child("syncer"),
                    db_config: (),
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                    resolvers: (),
                    finalization,
                    marshal,
                    sync_complete,
                });
            let actor = syncer.start();

            // The update is forwarded into the ring buffer and its observation parks before
            // the sync task completes (the task's clock only advances at quiescence). The
            // stranded observation must resolve through a retry that returns the artifact.
            let update = context
                .child("update")
                .spawn(move |_| async move { mailbox.update_targets(anchor(1, 1), 1).await });
            let result = update.await.expect("update task failed");
            assert!(
                matches!(&result, Some(artifact) if artifact.anchor.height == Height::zero()),
                "stranded update must resolve to the completed artifact",
            );

            let artifact = sync_completed.await.expect("artifact must publish");
            assert_eq!(artifact.anchor.height, Height::zero());
            actor.await.expect("syncer actor failed");
        });
    }
}
