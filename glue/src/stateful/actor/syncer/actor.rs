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
    marshal::core::{Floor, Mailbox as MarshalMailbox, Variant},
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

    /// Marshal mailbox and the durable floor returned with it during initialization.
    pub marshal: (MarshalMailbox<S, V>, Floor),

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

    /// Marshal mailbox and the durable floor returned with it during initialization.
    marshal: (MarshalMailbox<S, V>, Floor),

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
        let (marshal, floor) = &self.marshal;
        let resolved_floor =
            resolve_state_sync_floor::<E, A, S, V>(marshal, *floor, &self.finalization).await;

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
    use super::{Config, Syncer, resolve_state_sync_floor};
    use crate::stateful::{
        Application, Input, Proposed,
        actor::syncer::{
            StateSyncMetadata, recover_databases_from_marshal, replay_databases_from_base,
        },
        db::{Anchor, Barrier, DatabaseSet, StateSyncSet, SyncEngineConfig, TipUpdate},
        tests::{
            fixtures::{self, MarshalFixture},
            mocks::{TestBlock, TestMerkleized, TestScheme, TestUnmerkleized, TestVariant, anchor},
        },
    };
    use commonware_consensus::{
        Heightable as _, Reporter as _,
        marshal::ancestry::Ancestry,
        simplex::{
            mocks::scheme as scheme_mocks,
            types::{Activity, Context as SimplexContext},
        },
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digestible as _, ed25519,
        sha256::{Digest as Sha256Digest, Sha256},
    };
    use commonware_runtime::{
        Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic,
    };
    use commonware_utils::{
        NZU64, NZUsize,
        channel::{oneshot, ring},
        sync::Mutex,
    };
    use std::{convert::Infallible, sync::Arc, time::Duration};

    /// Database set whose sync holds the tip-update ring receiver without draining it, then
    /// completes once the actor has parked a forwarded update in the ring buffer.
    #[derive(Clone, Default)]
    struct WedgeSet(u64);

    impl DatabaseSet<deterministic::Context> for WedgeSet {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Readers = ();
        type Config = u64;
        type SyncTargets = u64;

        async fn init(_context: deterministic::Context, config: Self::Config) -> Self {
            Self(config)
        }

        fn initial_sync_targets() -> Self::SyncTargets {
            0
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

        fn readers(&self) -> Self::Readers {}

        async fn apply(&self, _batches: Self::Merkleized) {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn finalize(&self) -> Barrier {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn prune(&self, _targets: &Self::SyncTargets) {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn committed_targets(&self) -> Self::SyncTargets {
            self.0
        }

        async fn rewind_to_targets(&self, targets: Self::SyncTargets) {
            assert_eq!(targets, self.0, "test database cannot rewind");
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
            Ok((Self::default(), anchor))
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

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum ReplayEvent {
        Rewind(u64),
        ApplicationApply(u64),
        DatabaseApply(u64),
        Finalized(u64),
    }

    #[derive(Clone)]
    struct ReplayConfig {
        opened_at: u64,
        events: Arc<Mutex<Vec<ReplayEvent>>>,
    }

    #[derive(Clone, Copy)]
    struct ReplayUnmerkleized(u64);

    #[derive(Clone, Copy)]
    struct ReplayMerkleized(u64);

    #[derive(Clone)]
    struct ReplaySet {
        height: Arc<Mutex<u64>>,
        events: Arc<Mutex<Vec<ReplayEvent>>>,
    }

    impl DatabaseSet<deterministic::Context> for ReplaySet {
        type Unmerkleized = ReplayUnmerkleized;
        type Merkleized = ReplayMerkleized;
        type Readers = u64;
        type Config = ReplayConfig;
        type SyncTargets = u64;

        async fn init(_context: deterministic::Context, config: Self::Config) -> Self {
            Self {
                height: Arc::new(Mutex::new(config.opened_at)),
                events: config.events,
            }
        }

        fn initial_sync_targets() -> Self::SyncTargets {
            0
        }

        async fn new_batches(&self) -> Self::Unmerkleized {
            ReplayUnmerkleized(*self.height.lock())
        }

        fn fork_batches(parent: &Self::Merkleized) -> Self::Unmerkleized {
            ReplayUnmerkleized(parent.0)
        }

        fn matches_sync_targets(batches: &Self::Merkleized, targets: &Self::SyncTargets) -> bool {
            batches.0 == *targets
        }

        fn readers(&self) -> Self::Readers {
            *self.height.lock()
        }

        async fn apply(&self, batches: Self::Merkleized) {
            let mut height = self.height.lock();
            assert_eq!(
                batches.0,
                height.checked_add(1).expect("test height overflow"),
                "replay database applies must be contiguous",
            );
            *height = batches.0;
            self.events
                .lock()
                .push(ReplayEvent::DatabaseApply(batches.0));
        }

        async fn finalize(&self) -> Barrier {
            unreachable!("startup replay must not finalize per block")
        }

        async fn prune(&self, _targets: &Self::SyncTargets) {
            unreachable!("ReplaySet only serves the startup recovery harness")
        }

        async fn committed_targets(&self) -> Self::SyncTargets {
            *self.height.lock()
        }

        async fn rewind_to_targets(&self, targets: Self::SyncTargets) {
            let mut height = self.height.lock();
            assert!(
                targets <= *height,
                "test database cannot advance through rewind",
            );
            *height = targets;
            self.events.lock().push(ReplayEvent::Rewind(targets));
        }
    }

    #[derive(Clone)]
    struct ReplayApp {
        events: Arc<Mutex<Vec<ReplayEvent>>>,
        mismatch_at: Option<Height>,
    }

    impl Application<deterministic::Context> for ReplayApp {
        type SigningScheme = TestScheme;
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
        type Block = TestBlock;
        type Databases = ReplaySet;
        type Provider = ();
        type Input = ();

        fn sync_targets(block: &Self::Block) -> u64 {
            block.height().get()
        }

        async fn genesis(&mut self) -> Self::Block {
            unreachable!("ReplayApp only serves the startup recovery harness")
        }

        async fn propose(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: ReplayUnmerkleized,
            _input: Input<Self::Input, Self::Provider>,
        ) -> Option<Proposed<Self, deterministic::Context>> {
            unreachable!("ReplayApp only serves the startup recovery harness")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: ReplayUnmerkleized,
        ) -> Option<ReplayMerkleized> {
            unreachable!("ReplayApp only serves the startup recovery harness")
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            batches: ReplayUnmerkleized,
        ) -> ReplayMerkleized {
            let height = block.height();
            assert_eq!(
                height.get(),
                batches.0.checked_add(1).expect("test height overflow"),
                "application replay must be contiguous",
            );
            self.events
                .lock()
                .push(ReplayEvent::ApplicationApply(height.get()));
            ReplayMerkleized(if self.mismatch_at == Some(height) {
                height.next().get()
            } else {
                height.get()
            })
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            block: &Self::Block,
            applied_height: u64,
        ) {
            assert_eq!(applied_height, block.height().get());
            self.events
                .lock()
                .push(ReplayEvent::Finalized(applied_height));
        }
    }

    async fn marshal_with_chain(
        mut context: deterministic::Context,
        prefix: &str,
        tip: u64,
    ) -> (MarshalFixture, Vec<TestBlock>) {
        let fixture = scheme_mocks::fixture(&mut context, prefix.as_bytes(), 1);
        let marshal_fixture = fixtures::marshal_fixture(
            context.child("marshal"),
            prefix,
            fixture.schemes[0].clone(),
            None,
            NZUsize!(1),
            true,
        )
        .await;
        let mut marshal = marshal_fixture.mailbox.clone();
        let mut blocks = vec![TestBlock::new(0, 0)];
        for height in 1..=tip {
            let block = TestBlock::child(
                blocks.last().expect("genesis block must exist"),
                height as u8,
            );
            let finalization = fixtures::finalization(&fixture, height, block.digest());
            assert!(
                marshal
                    .verified(finalization.proposal.round, block.clone())
                    .await
            );
            let _ = marshal.report(Activity::Finalization(finalization));
            while marshal.get_processed_height().await != Some(block.height()) {
                context.sleep(Duration::from_millis(1)).await;
            }
            blocks.push(block);
        }
        (marshal_fixture, blocks)
    }

    #[test]
    fn startup_replays_processed_suffix_from_durable_base() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let base = Height::new(2);
            let (fixture, blocks) =
                marshal_with_chain(context.child("fixture"), "syncer-replay", 5).await;
            let metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, "syncer-replay")
                    .await
                    .set_complete(base)
                    .await;
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut application = ReplayApp {
                events: events.clone(),
                mismatch_at: None,
            };

            let startup = recover_databases_from_marshal::<
                deterministic::Context,
                ReplayApp,
                TestScheme,
                TestVariant,
            >(
                &context,
                &fixture.mailbox,
                ReplayConfig {
                    opened_at: base.get(),
                    events: events.clone(),
                },
                metadata,
                &mut application,
            )
            .await;

            assert_eq!(startup.sync.anchor.height, Height::new(5));
            assert_eq!(startup.sync.anchor.digest, blocks[5].digest());
            assert_eq!(startup.sync.databases.committed_targets().await, 5);
            assert_eq!(startup.skip_finalized_until, None);
            assert_eq!(startup.replayed_finalized_after, None);
            assert_eq!(startup.sync_metadata.sync_height(), Some(base));
            assert_eq!(
                *events.lock(),
                vec![
                    ReplayEvent::Rewind(2),
                    ReplayEvent::ApplicationApply(3),
                    ReplayEvent::DatabaseApply(3),
                    ReplayEvent::Finalized(3),
                    ReplayEvent::ApplicationApply(4),
                    ReplayEvent::DatabaseApply(4),
                    ReplayEvent::Finalized(4),
                    ReplayEvent::ApplicationApply(5),
                    ReplayEvent::DatabaseApply(5),
                    ReplayEvent::Finalized(5),
                ],
            );
        });
    }

    #[test]
    fn startup_replays_durable_finalizations_before_acknowledgement() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let prefix = "syncer-replay-unacknowledged";
            let scheme = scheme_mocks::fixture(&mut context, prefix.as_bytes(), 1);
            let genesis = TestBlock::new(0, 0);
            let block = TestBlock::child(&genesis, 1);
            let finalization = fixtures::finalization(&scheme, 1, block.digest());
            let fixture = fixtures::marshal_fixture_with_held_finalization(
                context.child("marshal"),
                prefix,
                scheme.schemes[0].clone(),
                &block,
                finalization,
                NZUsize!(8),
            )
            .await;

            assert_eq!(
                fixture.mailbox.get_startup_replay_tip().await,
                Some(Height::new(1)),
            );
            assert_eq!(fixture.mailbox.get_processed_height().await, None);

            let events = Arc::new(Mutex::new(Vec::new()));
            let metadata =
                StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(&context, prefix).await;
            let mut application = ReplayApp {
                events: events.clone(),
                mismatch_at: None,
            };
            let startup = recover_databases_from_marshal::<
                deterministic::Context,
                ReplayApp,
                TestScheme,
                TestVariant,
            >(
                &context,
                &fixture.mailbox,
                ReplayConfig {
                    opened_at: 0,
                    events: events.clone(),
                },
                metadata,
                &mut application,
            )
            .await;

            assert_eq!(startup.sync.anchor.height, Height::new(1));
            assert_eq!(startup.sync.anchor.digest, block.digest());
            assert_eq!(startup.sync.databases.committed_targets().await, 1);
            assert_eq!(startup.skip_finalized_until, Some(Height::new(1)));
            assert_eq!(startup.replayed_finalized_after, Some(Height::zero()),);
            assert_eq!(startup.sync_metadata.sync_height(), Some(Height::zero()));
            assert_eq!(
                *events.lock(),
                vec![
                    ReplayEvent::Rewind(0),
                    ReplayEvent::ApplicationApply(1),
                    ReplayEvent::DatabaseApply(1),
                    ReplayEvent::Finalized(1),
                ],
            );
        });
    }

    #[test]
    #[should_panic(expected = "marshal must retain every finalized block after the replay base")]
    fn startup_replay_rejects_archived_gap() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let base = TestBlock::new(2, 2);
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut application = ReplayApp {
                events: events.clone(),
                mismatch_at: None,
            };
            let _ = replay_databases_from_base::<deterministic::Context, ReplayApp, _, _>(
                &context,
                ReplayConfig {
                    opened_at: 2,
                    events,
                },
                &mut application,
                base,
                Height::new(4),
                |_| async { None },
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "marshal must retain the durable replay base block")]
    fn startup_replay_rejects_missing_base() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let (fixture, _) =
                marshal_with_chain(context.child("fixture"), "syncer-replay-missing-base", 0).await;
            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                "syncer-replay-missing-base",
            )
            .await
            .set_complete(Height::new(2))
            .await;
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut application = ReplayApp {
                events: events.clone(),
                mismatch_at: None,
            };

            let _ = recover_databases_from_marshal::<
                deterministic::Context,
                ReplayApp,
                TestScheme,
                TestVariant,
            >(
                &context,
                &fixture.mailbox,
                ReplayConfig {
                    opened_at: 2,
                    events,
                },
                metadata,
                &mut application,
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "archived replay blocks must have contiguous parents")]
    fn startup_replay_rejects_parent_mismatch() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut application = ReplayApp {
                events: events.clone(),
                mismatch_at: None,
            };
            let wrong_child = TestBlock::new(3, 3);
            let _ = replay_databases_from_base::<deterministic::Context, ReplayApp, _, _>(
                &context,
                ReplayConfig {
                    opened_at: 2,
                    events,
                },
                &mut application,
                TestBlock::new(2, 2),
                Height::new(3),
                move |_| {
                    let wrong_child = wrong_child.clone();
                    async move { Some(wrong_child) }
                },
            )
            .await;
        });
    }

    #[test]
    #[should_panic(expected = "replayed database batches must match block sync targets")]
    fn startup_replay_rejects_target_mismatch_before_database_apply() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let base = Height::new(1);
            let (fixture, _) =
                marshal_with_chain(context.child("fixture"), "syncer-replay-mismatch", 3).await;
            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                "syncer-replay-mismatch",
            )
            .await
            .set_complete(base)
            .await;
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut application = ReplayApp {
                events: events.clone(),
                mismatch_at: Some(Height::new(2)),
            };

            let _ = recover_databases_from_marshal::<
                deterministic::Context,
                ReplayApp,
                TestScheme,
                TestVariant,
            >(
                &context,
                &fixture.mailbox,
                ReplayConfig {
                    opened_at: base.get(),
                    events,
                },
                metadata,
                &mut application,
            )
            .await;
        });
    }

    #[test]
    fn resolved_floor_covers_durable_marshal_progress() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncer-floor", 1);
            let selected = fixtures::finalization(&fixture, 0, Sha256::fill(0));
            let processed_block = TestBlock::new(1, 1);
            let MarshalFixture {
                mailbox: marshal,
                floor,
                guards: _guards,
            } = fixtures::marshal_fixture_with_finalized_block(
                context.child("marshal"),
                "syncer-floor",
                fixture.schemes[0].clone(),
                &processed_block,
                NZUsize!(1),
                true,
            )
            .await;

            while marshal.get_processed_height().await != Some(Height::new(1)) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(marshal.get_finalization(Height::new(1)).await.is_none());

            let resolved = resolve_state_sync_floor::<
                deterministic::Context,
                WedgeApp,
                TestScheme,
                TestVariant,
            >(&marshal, floor, &selected)
            .await;
            assert_eq!(resolved.anchor.height, Height::new(1));
            assert_eq!(resolved.targets, 1);
        });
    }

    #[test]
    fn startup_uses_floor_anchor_when_processed_predecessor_is_pruned() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncer-floor-install", 1);
            let floor = TestBlock::new(2, 2);
            let finalization = fixtures::finalization(&fixture, 2, Sha256::fill(2));
            let MarshalFixture {
                mailbox: marshal,
                guards: _guards,
                ..
            } = fixtures::marshal_fixture_with_floor(
                context.child("marshal"),
                "syncer-floor-install",
                fixture.schemes[0].clone(),
                &floor,
                finalization,
                NZUsize!(1),
            )
            .await;

            while marshal.get_processed_height().await != Some(Height::new(1)) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(marshal.get_block(Height::new(1)).await.is_none());
            assert!(marshal.get_block(Height::new(2)).await.is_some());

            let metadata = StateSyncMetadata::<_, TestScheme, Sha256Digest>::init(
                &context,
                "syncer-floor-install",
            )
            .await
            .set_complete(Height::new(2))
            .await;
            let mut application = WedgeApp;
            let startup = recover_databases_from_marshal::<
                deterministic::Context,
                WedgeApp,
                TestScheme,
                TestVariant,
            >(&context, &marshal, 2, metadata, &mut application)
            .await;

            assert_eq!(startup.sync.anchor.height, Height::new(2));
            assert_eq!(startup.sync.databases.committed_targets().await, 2);
            assert_eq!(startup.skip_finalized_until, Some(Height::new(2)));
            assert_eq!(startup.replayed_finalized_after, None);
            assert_eq!(startup.sync_metadata.sync_height(), Some(Height::new(2)));
        });
    }

    #[test]
    fn resolved_floor_uses_anchor_when_processed_predecessor_is_pruned() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncer-floor-resolve", 1);
            let selected = TestBlock::new(1, 1);
            let selected_finalization = fixtures::finalization(&fixture, 1, Sha256::fill(1));
            let floor_block = TestBlock::new(3, 3);
            let floor_finalization = fixtures::finalization(&fixture, 3, Sha256::fill(3));
            let MarshalFixture {
                mailbox: marshal,
                floor,
                guards: _guards,
            } = fixtures::marshal_fixture_with_floor(
                context.child("marshal"),
                "syncer-floor-resolve",
                fixture.schemes[0].clone(),
                &floor_block,
                floor_finalization,
                NZUsize!(1),
            )
            .await;

            while marshal.get_processed_height().await != Some(Height::new(2)) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(marshal.get_block(Height::new(2)).await.is_none());
            assert!(marshal.get_block(Height::new(3)).await.is_some());

            let resolver = context.child("resolve").spawn({
                let marshal = marshal.clone();
                move |_| async move {
                    resolve_state_sync_floor::<
                        deterministic::Context,
                        WedgeApp,
                        TestScheme,
                        TestVariant,
                    >(&marshal, floor, &selected_finalization)
                    .await
                }
            });
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                marshal
                    .verified(Round::new(Epoch::zero(), View::new(1)), selected)
                    .await
            );

            let resolved = resolver.await.expect("floor resolution failed");
            assert_eq!(resolved.anchor.height, Height::new(3));
            assert_eq!(resolved.targets, 3);
        });
    }

    #[test]
    fn resolved_floor_skips_selected_block_pruned_by_newer_floor() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncer-pruned-floor", 1);
            let selected_finalization = fixtures::finalization(&fixture, 1, Sha256::fill(1));
            let first = fixtures::prunable_marshal_fixture(
                context.child("marshal"),
                "syncer-pruned-floor",
                fixture.schemes[0].clone(),
                None,
                None,
                NZUsize!(1),
                true,
            )
            .await;
            let mut marshal = first.mailbox.clone();

            for height in 1..=9 {
                let block = TestBlock::new(height, height as u8);
                let finalization =
                    fixtures::finalization(&fixture, height, Sha256::fill(height as u8));
                let height = block.height();
                assert!(marshal.verified(finalization.proposal.round, block).await);
                let _ = marshal.report(Activity::Finalization(finalization));
                for _ in 0..100 {
                    if marshal.get_processed_height().await == Some(height) {
                        break;
                    }
                    context.sleep(Duration::from_millis(1)).await;
                }
                assert_eq!(marshal.get_processed_height().await, Some(height));
            }

            let newer_floor = TestBlock::new(10, 10);
            let newer_finalization = fixtures::finalization(&fixture, 10, Sha256::fill(10));
            assert!(
                marshal
                    .verified(newer_finalization.proposal.round, newer_floor)
                    .await
            );
            marshal.set_floor(newer_finalization);
            for _ in 0..100 {
                if marshal.get_block(Height::new(1)).await.is_none() {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(marshal.get_block(Height::new(1)).await.is_none());
            for _ in 0..100 {
                if marshal.get_processed_height().await == Some(Height::new(10)) {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(marshal.get_processed_height().await, Some(Height::new(10)));

            first.abort();
            drop(marshal);
            context.sleep(Duration::from_millis(1)).await;

            let MarshalFixture {
                mailbox: marshal,
                floor,
                guards: _guards,
            } = fixtures::prunable_marshal_fixture(
                context.child("marshal_restart"),
                "syncer-pruned-floor",
                fixture.schemes[0].clone(),
                None,
                Some(selected_finalization.clone()),
                NZUsize!(1),
                true,
            )
            .await;
            assert_eq!(floor.height(), Some(Height::new(10)));
            assert!(floor.round() > selected_finalization.proposal.round);
            assert!(
                marshal
                    .get_block(&selected_finalization.proposal.payload)
                    .await
                    .is_none(),
                "stale selected block must remain unavailable after restart",
            );

            let resolved = commonware_macros::select! {
                resolved = resolve_state_sync_floor::<
                    deterministic::Context,
                    WedgeApp,
                    TestScheme,
                    TestVariant,
                >(&marshal, floor, &selected_finalization) => resolved,
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("a superseded floor must not wait for its pruned block");
                },
            };
            assert_eq!(resolved.anchor.height, Height::new(10));
            assert_eq!(resolved.targets, 10);
        });
    }

    #[test]
    fn resolved_floor_recovers_round_after_boundary_prune() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncer-boundary-floor", 1);
            let selected_block = TestBlock::new(1, 1);
            let selected_finalization = fixtures::finalization(&fixture, 1, Sha256::fill(1));
            let first = fixtures::prunable_marshal_fixture(
                context.child("marshal_first"),
                "syncer-boundary-floor",
                fixture.schemes[0].clone(),
                None,
                None,
                NZUsize!(1),
                true,
            )
            .await;
            let mut marshal = first.mailbox.clone();
            for height in 1..=5 {
                let block = if height == 1 {
                    selected_block.clone()
                } else {
                    TestBlock::new(height, height as u8)
                };
                let finalization = if height == 1 {
                    selected_finalization.clone()
                } else {
                    fixtures::finalization(&fixture, height, Sha256::fill(height as u8))
                };
                let height = block.height();
                assert!(marshal.verified(finalization.proposal.round, block).await);
                let _ = marshal.report(Activity::Finalization(finalization));
                while marshal.get_processed_height().await != Some(height) {
                    context.sleep(Duration::from_millis(1)).await;
                }
            }
            first.abort();
            drop(marshal);
            context.sleep(Duration::from_millis(1)).await;

            let newer_block = TestBlock::new(8, 8);
            let newer_finalization = fixtures::finalization(&fixture, 8, Sha256::fill(8));
            let second = fixtures::prunable_marshal_fixture(
                context.child("marshal_second"),
                "syncer-boundary-floor",
                fixture.schemes[0].clone(),
                Some(&newer_block),
                Some(newer_finalization.clone()),
                NZUsize!(1),
                false,
            )
            .await;
            let marshal = second.mailbox.clone();
            while marshal.get_processed_height().await != Some(Height::new(7)) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(
                marshal
                    .get_block(&selected_finalization.proposal.payload)
                    .await
                    .is_none(),
                "stale selected block must be unavailable before restart",
            );
            assert!(marshal.get_block(Height::new(8)).await.is_some());
            second.abort();
            drop(marshal);
            context.sleep(Duration::from_millis(1)).await;

            let MarshalFixture {
                mailbox: marshal,
                floor,
                guards: _guards,
            } = fixtures::prunable_marshal_fixture(
                context.child("marshal_third"),
                "syncer-boundary-floor",
                fixture.schemes[0].clone(),
                None,
                Some(selected_finalization.clone()),
                NZUsize!(1),
                true,
            )
            .await;
            assert_eq!(floor.height(), Some(Height::new(7)));
            assert_eq!(floor.round(), newer_finalization.proposal.round);
            assert!(
                marshal
                    .get_block(&selected_finalization.proposal.payload)
                    .await
                    .is_none(),
                "stale selected block must remain unavailable after restart",
            );

            let resolved = commonware_macros::select! {
                resolved = resolve_state_sync_floor::<
                    deterministic::Context,
                    WedgeApp,
                    TestScheme,
                    TestVariant,
                >(&marshal, floor, &selected_finalization) => resolved,
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("a superseded floor must not wait for its pruned block");
                },
            };
            assert_eq!(resolved.anchor.height, Height::new(8));
            assert_eq!(resolved.targets, 8);
        });
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
                floor,
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
                    db_config: 0,
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                    resolvers: (),
                    finalization,
                    marshal: (marshal, floor),
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
