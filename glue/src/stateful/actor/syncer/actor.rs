use super::{
    Artifact,
    mailbox::{Mailbox, Message},
    resolve,
};
use crate::stateful::{
    Application,
    actor::{BlockDigest, SyncTargets},
    db::{Anchor, DatabaseSet, StateSyncSet, SyncEngineConfig, TipUpdate},
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
};
use futures::{SinkExt, future::pending};
use rand_core::Rng;
use std::{future::Future, mem, pin::Pin};
use tracing::debug;

/// State sync resources live until convergence, then only the artifact is retained for retries.
enum Phase<E, A, F>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
{
    Syncing {
        task: Pin<Box<F>>,
        updates: ring::Sender<TipUpdate<BlockDigest<A, E>, SyncTargets<A, E>>>,
        completion: oneshot::Sender<Artifact<E, A>>,
    },
    Complete(Artifact<E, A>),
}

impl<E, A, F> Phase<E, A, F>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    F: Future<Output = Artifact<E, A>>,
{
    /// Waits for convergence, staying pending after the artifact is published.
    async fn completion(&mut self) -> Artifact<E, A> {
        match self {
            Self::Syncing { task, .. } => task.await,
            Self::Complete(_) => pending().await,
        }
    }

    /// Publishes once and drops the sync resources, including any unobserved target update.
    fn publish(&mut self, artifact: Artifact<E, A>) {
        let Self::Syncing { completion, .. } = mem::replace(self, Self::Complete(artifact.clone()))
        else {
            panic!("state sync artifact already published");
        };
        completion.send_lossy(artifact);
    }

    /// Forwards a target, or publishes and returns the artifact if convergence won the race.
    async fn retarget(
        &mut self,
        update: TipUpdate<BlockDigest<A, E>, SyncTargets<A, E>>,
    ) -> Option<Artifact<E, A>> {
        match self {
            Self::Complete(artifact) => return Some(artifact.clone()),
            Self::Syncing { updates, .. } => {
                if updates.send(update).await.is_ok() {
                    return None;
                }
            }
        }

        // A closed target channel accepts no more targets. Wait for convergence.
        let artifact = self.completion().await;
        self.publish(artifact.clone());
        Some(artifact)
    }
}

/// Configuration for [`Syncer`].
pub struct Config<E, A, R, S, V>
where
    E: Rng + Spawner + Context,
    A: Application<E>,
    A::Databases: StateSyncSet<E, R, BlockDigest<A, E>>,
    S: Scheme,
    V: Variant<ApplicationBlock = A::Block>,
{
    /// Runtime context.
    pub context: E,

    /// Database configuration for the managed set.
    pub db_config: <A::Databases as DatabaseSet<E>>::Config,

    /// Per-database sync engine parameters.
    pub sync_config: SyncEngineConfig,

    /// Per-database resolvers used to fetch state from peers.
    pub resolvers: R,

    /// Selected state sync floor.
    pub finalization: Finalization<S, V::Commitment>,

    /// Marshal mailbox and the durable floor returned with it during initialization.
    pub marshal: (MarshalMailbox<S, V>, Floor),

    /// Delivers the converged [`Artifact`] to [`Stateful`](crate::stateful::Stateful).
    pub completion: oneshot::Sender<Artifact<E, A>>,
}

/// Runs state sync from the block returned by [`resolve`], accepts target updates, and publishes
/// the converged [`Artifact`] to [`Stateful`](crate::stateful::Stateful).
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
    /// Database configuration for the managed set.
    db_config: <A::Databases as DatabaseSet<E>>::Config,
    /// Per-database sync engine parameters.
    sync_config: SyncEngineConfig,
    /// Per-database resolvers used to fetch state from peers.
    resolvers: R,
    /// Requested state sync floor used to select the starting block.
    finalization: Finalization<S, V::Commitment>,
    /// Marshal mailbox and the durable floor returned during initialization.
    marshal: (MarshalMailbox<S, V>, Floor),
    completion: oneshot::Sender<Artifact<E, A>>,
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
                db_config: config.db_config,
                sync_config: config.sync_config,
                resolvers: config.resolvers,
                finalization: config.finalization,
                marshal: config.marshal,
                completion: config.completion,
            },
            mailbox,
        )
    }

    pub fn start(mut self) -> Handle<()> {
        spawn_cell!(self.context, self.run())
    }

    async fn run(mut self) {
        let (marshal, floor) = &self.marshal;
        let block = resolve(marshal, *floor, &self.finalization).await;

        let (updates, tip_updates_rx) = ring::channel(NZUsize!(1));
        let task = A::Databases::sync(
            self.context.child("state_sync"),
            self.db_config,
            self.resolvers,
            Anchor::from(block.as_ref()),
            A::sync_targets(block.as_ref()),
            tip_updates_rx,
            self.sync_config,
        );
        let mut phase = Phase::Syncing {
            task: Box::pin(async move {
                let (databases, anchor) = task
                    .await
                    .unwrap_or_else(|err| panic!("state sync task failed: {err:?}"));
                Artifact { databases, anchor }
            }),
            updates,
            completion: self.completion,
        };

        select_loop! {
            self.context,
            on_stopped => {
                debug!("syncer received stop signal, shutting down");
            },
            artifact = phase.completion() => {
                phase.publish(artifact);
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down syncer");
                break;
            } => match message {
                Message::Retarget { update, response } => {
                    response.send_lossy(phase.retarget(update).await);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Artifact, Config, Phase, Syncer, resolve};
    use crate::stateful::{
        Application, Config as StatefulConfig, Input, Proposed, Stateful,
        actor::syncer::{SyncPlan, open},
        db::{
            Anchor, AttachableResolverSet, Barrier, DatabaseSet, StateSyncSet, SyncEngineConfig,
            TipUpdate,
        },
        tests::{
            fixtures::{self, MarshalFixture},
            mocks::{TestBlock, TestMerkleized, TestScheme, TestUnmerkleized, TestVariant, anchor},
        },
    };
    use commonware_consensus::{
        Heightable as _, Reporter as _,
        marshal::{ancestry::Ancestry, core::Processed},
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
        Clock as _, Runner as _, Spawner as _, Supervisor as _, deterministic, reschedule,
    };
    use commonware_utils::{
        NZU64, NZUsize,
        channel::{oneshot, ring},
    };
    use futures::poll;
    use std::{convert::Infallible, time::Duration};

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

        async fn init(
            _context: deterministic::Context,
            config: Self::Config,
            expected: Option<Self::SyncTargets>,
        ) -> Self {
            assert_eq!(
                expected,
                Some(config),
                "startup must pass the configured target"
            );
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

    impl AttachableResolverSet<WedgeSet> for () {
        async fn attach_databases(&self, _databases: WedgeSet) {}
    }

    #[derive(Clone)]
    struct WedgeApp;

    impl Application<deterministic::Context> for WedgeApp {
        type SigningScheme = TestScheme;
        type Context = SimplexContext<Sha256Digest, ed25519::PublicKey>;
        type Block = TestBlock;
        type Databases = WedgeSet;
        type Captured = ();
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
        ) -> Option<TestMerkleized> {
            unreachable!("WedgeApp only serves the syncer harness")
        }

        async fn capture(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: &TestMerkleized,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
            unreachable!("WedgeApp only serves the syncer harness")
        }

        async fn finalized(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _captured: Self::Captured,
            _readers: <Self::Databases as DatabaseSet<deterministic::Context>>::Readers,
        ) {
            unreachable!("WedgeApp only serves the syncer harness")
        }
    }

    #[test]
    fn resolve_covers_durable_marshal_progress() {
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

            while marshal.get_processed().await.map(Processed::height) != Some(Height::new(1)) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(marshal.get_finalization(Height::new(1)).await.is_none());

            let resolved = resolve(&marshal, floor, &selected).await;
            assert_eq!(
                Anchor::from(resolved.as_ref()),
                Anchor::from(&processed_block)
            );
        });
    }

    /// Resuming state sync after a floor install resolves to the retained floor block only when
    /// it is the selected finalization.
    #[rstest::rstest]
    #[case::selected_successor_within_section(3, 3, 3)]
    #[case::selected_successor_at_section_boundary(4, 4, 4)]
    #[case::selected_predecessor(4, 3, 3)]
    #[case::selected_older(4, 2, 3)]
    fn resolve_selects_only_matching_retained_successor(
        #[case] height: u64,
        #[case] selected_height: u64,
        #[case] expected_height: u64,
    ) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut signing = context.child("signing");
            let fixture =
                scheme_mocks::fixture(&mut signing, b"_COMMONWARE_GLUE_RETAINED_FLOOR_ANCHOR", 1);
            let mut blocks = vec![TestBlock::new(0, 0)];
            for height in 1..=height {
                blocks.push(TestBlock::child(
                    blocks.last().unwrap(),
                    height.try_into().unwrap(),
                ));
            }

            // Acknowledge blocks 1 through F-1 in prunable archives.
            let first = fixtures::prunable_marshal_fixture(
                context.child("first"),
                "retained-floor-anchor",
                fixture.schemes[0].clone(),
                None,
                None,
                NZUsize!(1),
                true,
            )
            .await;
            let mut marshal = first.mailbox.clone();
            for block in &blocks[1..blocks.len() - 1] {
                let finalization =
                    fixtures::finalization(&fixture, block.height().get(), block.digest());
                assert!(marshal.verified(finalization.round(), block.clone()).await);
                marshal.report(Activity::Finalization(finalization));
                assert_eq!(
                    marshal.get_processed().await,
                    Some(Processed::Block(block.height()))
                );
            }
            first.abort().await;
            drop(marshal);

            // Restart with F as the floor. Marshal records F-1 as processed and prunes below it.
            let block = blocks.last().unwrap();
            let installed = fixtures::finalization(&fixture, height, block.digest());
            let predecessor = Height::new(height - 1);
            let second = fixtures::prunable_marshal_fixture(
                context.child("second"),
                "retained-floor-anchor",
                fixture.schemes[0].clone(),
                Some(block),
                Some(installed.clone()),
                NZUsize!(1),
                false,
            )
            .await;
            assert_eq!(
                second.mailbox.get_processed().await,
                Some(Processed::Block(predecessor))
            );
            second.abort().await;

            // Restart again and confirm F-1, its finalization, and F are all retained.
            let third = fixtures::prunable_marshal_fixture(
                context.child("third"),
                "retained-floor-anchor",
                fixture.schemes[0].clone(),
                None,
                Some(installed.clone()),
                NZUsize!(1),
                false,
            )
            .await;
            assert_eq!(third.floor.processed(), Some(Processed::Block(predecessor)));
            assert_eq!(third.floor.round(), installed.round());
            assert!(third.mailbox.get_block(predecessor).await.is_some());
            assert!(third.mailbox.get_finalization(predecessor).await.is_some());
            assert!(third.mailbox.get_block(block.height()).await.is_some());

            // A selection at F is read back from persisted metadata, as a resumed sync reads it.
            let selected_block = &blocks[selected_height as usize];
            let selected =
                fixtures::finalization(&fixture, selected_height, selected_block.digest());
            let selected = if selected_height == height {
                let partition = format!("retained-floor-plan-{height}");
                let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                    context.child("select"),
                    &partition,
                )
                .await
                .set_floor(selected)
                .await;
                drop(plan);

                let plan =
                    SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), &partition)
                        .await;
                assert!(plan.floor().is_some());
                plan.floor().expect("persisted selected floor").clone()
            } else {
                selected
            };

            // Only a selection of F resolves to F. Older selections resolve to F-1.
            let resolved = resolve(&third.mailbox, third.floor, &selected).await;
            assert_eq!(
                Anchor::from(resolved.as_ref()),
                Anchor::from(&blocks[expected_height as usize]),
            );
            third.abort().await;
        });
    }

    /// A live floor installed after marshal's startup snapshot can prune the snapshot's anchor or
    /// move the processed height past the selected block. Resolution follows the live position.
    #[rstest::rstest]
    #[case::pruned_snapshot_anchor(2, 4, 5, 2, 4)]
    #[case::selected_below_live_floor(4, 6, 7, 5, 6)]
    fn resolve_follows_live_floor_after_startup(
        #[case] acknowledged: u64,
        #[case] stored: u64,
        #[case] live_floor: u64,
        #[case] selected_height: u64,
        #[case] expected_height: u64,
    ) {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|context| async move {
            let mut signing = context.child("signing");
            let fixture =
                scheme_mocks::fixture(&mut signing, b"_COMMONWARE_GLUE_LIVE_FLOOR_RESOLVE", 1);
            let mut blocks = vec![TestBlock::new(0, 0)];
            for height in 1..=live_floor {
                blocks.push(TestBlock::child(
                    blocks.last().unwrap(),
                    height.try_into().unwrap(),
                ));
            }
            let finalized = |height: u64| {
                fixtures::finalization(&fixture, height, blocks[height as usize].digest())
            };

            // Acknowledge blocks through the snapshot height.
            let first = fixtures::prunable_marshal_fixture(
                context.child("first"),
                "live-floor-resolve",
                fixture.schemes[0].clone(),
                None,
                None,
                NZUsize!(1),
                true,
            )
            .await;
            let mut marshal = first.mailbox.clone();
            for height in 1..=acknowledged {
                let finalization = finalized(height);
                let block = blocks[height as usize].clone();
                assert!(marshal.verified(finalization.round(), block).await);
                marshal.report(Activity::Finalization(finalization));
                assert_eq!(
                    marshal.get_processed().await,
                    Some(Processed::Block(Height::new(height)))
                );
            }
            first.abort().await;
            drop(marshal);

            // Store later blocks without acknowledging them.
            let second = fixtures::prunable_marshal_fixture(
                context.child("second"),
                "live-floor-resolve",
                fixture.schemes[0].clone(),
                None,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            let mut marshal = second.mailbox.clone();
            for height in acknowledged + 1..=stored {
                let finalization = finalized(height);
                let block = blocks[height as usize].clone();
                assert!(marshal.verified(finalization.round(), block).await);
                marshal.report(Activity::Finalization(finalization));
                while marshal.get_block(Height::new(height)).await.is_none() {
                    context.sleep(Duration::from_millis(1)).await;
                }
            }
            second.abort().await;
            drop(marshal);

            // Restart, then install a live floor before resolving from the startup snapshot.
            let third = fixtures::prunable_marshal_fixture(
                context.child("third"),
                "live-floor-resolve",
                fixture.schemes[0].clone(),
                None,
                None,
                NZUsize!(1),
                false,
            )
            .await;
            assert_eq!(
                third.floor.processed(),
                Some(Processed::Block(Height::new(acknowledged)))
            );
            let marshal = third.mailbox.clone();
            let floor = finalized(live_floor);
            let block = blocks[live_floor as usize].clone();
            assert!(marshal.verified(floor.round(), block).await);
            marshal.set_floor(floor);
            let live = Some(Processed::Block(Height::new(live_floor - 1)));
            while marshal.get_processed().await != live {
                context.sleep(Duration::from_millis(1)).await;
            }

            let resolved = resolve(&marshal, third.floor, &finalized(selected_height)).await;
            assert_eq!(
                Anchor::from(resolved.as_ref()),
                Anchor::from(&blocks[expected_height as usize]),
            );
            third.abort().await;
        });
    }

    #[test]
    fn startup_uses_floor_anchor_when_processed_predecessor_is_missing() {
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

            while marshal.get_processed().await.map(Processed::height) != Some(Height::new(1)) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(
                marshal.get_processed().await,
                Some(Processed::Absent(Height::new(1)))
            );
            assert!(marshal.get_block(Height::new(1)).await.is_none());
            assert!(marshal.get_block(Height::new(2)).await.is_some());

            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(
                context.child("plan"),
                "syncer-floor-install",
            )
            .await;
            let startup = open::<deterministic::Context, WedgeApp, TestScheme, TestVariant>(
                context.child("databases"),
                &marshal,
                2,
                plan.completed(),
            )
            .await;

            assert_eq!(startup.anchor.height, Height::new(2));
            assert_eq!(startup.databases.committed_targets().await, 2);
        });
    }

    /// A floor selected before a stop resumes state sync on a restart without a request, even
    /// when marshal installed it before Stateful started.
    #[test]
    fn restart_resumes_floor_installed_before_stateful() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let prefix = "syncer-selected-floor";
            let fixture = scheme_mocks::fixture(&mut context, prefix.as_bytes(), 1);
            let block = TestBlock::new(2, 2);
            let selected = fixtures::finalization(&fixture, 2, block.digest());

            // Select the floor, let marshal durably install it, and stop before Stateful starts.
            let plan = SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), prefix)
                .await
                .set_floor(selected)
                .await;
            let marshal = fixtures::prunable_marshal_fixture(
                context.child("marshal"),
                prefix,
                fixture.schemes[0].clone(),
                Some(&block),
                plan.floor().cloned(),
                NZUsize!(1),
                false,
            )
            .await;
            while marshal.mailbox.get_processed().await != Some(Processed::Absent(Height::new(1))) {
                reschedule().await;
            }
            marshal.abort().await;
            drop(plan);

            // Restart without a request. The empty database matches only the genesis target, so
            // recovering from marshal's installed floor would fail startup.
            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), prefix).await;
            let marshal = fixtures::prunable_marshal_fixture(
                context.child("marshal"),
                prefix,
                fixture.schemes[0].clone(),
                None,
                plan.floor().cloned(),
                NZUsize!(1),
                false,
            )
            .await;
            let (stateful, mailbox) = Stateful::new(
                context.child("stateful"),
                StatefulConfig {
                    application: WedgeApp,
                    db_config: 0,
                    provider: (),
                    marshal: (marshal.mailbox.clone(), marshal.floor),
                    mailbox_size: NZUsize!(1),
                    plan,
                    resolvers: (),
                    sync_config: SyncEngineConfig {
                        fetch_batch_size: NZU64!(1),
                        apply_batch_size: NZU64!(1),
                        max_outstanding_requests: 1,
                        update_channel_size: NZUsize!(1),
                        max_retained_roots: 1,
                    },
                    prune_config: None,
                },
            );
            let actor = stateful.start();

            // State sync resumes and completes at the installed floor.
            mailbox.subscribe_databases().await;
            actor.abort();
            let _ = actor.await;
            let plan =
                SyncPlan::<_, TestScheme, TestVariant>::init(context.child("plan"), prefix).await;
            assert_eq!(plan.completed(), Some(block.height()));
            marshal.abort().await;
        });
    }

    #[test]
    fn resolve_uses_anchor_when_processed_predecessor_is_missing() {
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

            while marshal.get_processed().await.map(Processed::height) != Some(Height::new(2)) {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(
                marshal.get_processed().await,
                Some(Processed::Absent(Height::new(2)))
            );
            assert!(marshal.get_block(Height::new(2)).await.is_none());
            assert!(marshal.get_block(Height::new(3)).await.is_some());

            let resolver = context.child("resolve").spawn({
                let marshal = marshal.clone();
                move |_| async move { resolve(&marshal, floor, &selected_finalization).await }
            });
            context.sleep(Duration::from_millis(1)).await;
            assert!(
                marshal
                    .verified(Round::new(Epoch::zero(), View::new(1)), selected)
                    .await
            );

            let resolved = resolver.await.expect("floor resolution failed");
            assert_eq!(Anchor::from(resolved.as_ref()), Anchor::from(&floor_block));
        });
    }

    #[test]
    fn resolve_skips_selected_block_pruned_by_newer_floor() {
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
                    if marshal.get_processed().await.map(Processed::height) == Some(height) {
                        break;
                    }
                    context.sleep(Duration::from_millis(1)).await;
                }
                assert_eq!(
                    marshal.get_processed().await,
                    Some(Processed::Block(height))
                );
            }

            let newer_floor = TestBlock::new(10, 10);
            let expected = Anchor::from(&newer_floor);
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
                if marshal.get_processed().await.map(Processed::height) == Some(Height::new(10)) {
                    break;
                }
                context.sleep(Duration::from_millis(1)).await;
            }
            assert_eq!(
                marshal.get_processed().await,
                Some(Processed::Block(Height::new(10)))
            );

            first.abort().await;
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
            assert_eq!(floor.processed(), Some(Processed::Block(Height::new(10))));
            assert!(floor.round() > selected_finalization.proposal.round);
            assert!(
                marshal
                    .get_block(&selected_finalization.proposal.payload)
                    .await
                    .is_none(),
                "stale selected block must remain unavailable after restart",
            );

            let resolved = commonware_macros::select! {
                resolved = resolve(&marshal, floor, &selected_finalization) => resolved,
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("a superseded floor must not wait for its pruned block");
                },
            };
            assert_eq!(Anchor::from(resolved.as_ref()), expected);
        });
    }

    #[test]
    fn resolve_recovers_round_after_boundary_prune() {
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
                while marshal.get_processed().await.map(Processed::height) != Some(height) {
                    context.sleep(Duration::from_millis(1)).await;
                }
            }
            first.abort().await;
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
            while marshal.get_processed().await.map(Processed::height) != Some(Height::new(7)) {
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
            second.abort().await;
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
            assert_eq!(floor.processed(), Some(Processed::Absent(Height::new(7))));
            assert_eq!(floor.round(), newer_finalization.proposal.round);
            assert!(
                marshal
                    .get_block(&selected_finalization.proposal.payload)
                    .await
                    .is_none(),
                "stale selected block must remain unavailable after restart",
            );

            let resolved = commonware_macros::select! {
                resolved = resolve(&marshal, floor, &selected_finalization) => resolved,
                _ = context.sleep(Duration::from_millis(100)) => {
                    panic!("a superseded floor must not wait for its pruned block");
                },
            };
            assert_eq!(Anchor::from(resolved.as_ref()), Anchor::from(&newer_block));
        });
    }

    /// A closed update channel must wait for the artifact, publish it, and serve later retries.
    #[test]
    fn closed_tip_channel_waits_for_artifact() {
        deterministic::Runner::default().start(|_| async move {
            let (updates, receiver) = ring::channel(NZUsize!(1));
            drop(receiver);
            let (completion, mut published) = oneshot::channel();
            let (release, ready) = oneshot::channel();
            let mut phase = Phase::<deterministic::Context, WedgeApp, _>::Syncing {
                task: Box::pin(async move { ready.await.expect("sync must finish") }),
                updates,
                completion,
            };
            let (update, observed) = TipUpdate::with_observation(anchor(1, 1), 1);
            let mut retarget = Box::pin(phase.retarget(update));
            assert!(poll!(&mut retarget).is_pending());
            assert!(observed.await.is_err());
            assert!(poll!(&mut published).is_pending());

            assert!(
                release
                    .send(Artifact {
                        databases: WedgeSet::default(),
                        anchor: anchor(0, 0),
                    })
                    .is_ok(),
            );
            let artifact = retarget.await.expect("retarget must return the artifact");
            assert_eq!(artifact.anchor, anchor(0, 0));
            assert_eq!(
                published.await.expect("artifact must publish").anchor,
                artifact.anchor
            );

            let (update, observed) = TipUpdate::with_observation(anchor(2, 2), 2);
            let retry = phase
                .retarget(update)
                .await
                .expect("retry must return the artifact");
            assert_eq!(retry.anchor, artifact.anchor);
            assert!(observed.await.is_err());
            assert!(poll!(Box::pin(phase.completion())).is_pending());
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

            let (sender, receiver) = oneshot::channel();
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
                    completion: sender,
                });
            let actor = syncer.start();

            // The update is forwarded into the ring buffer and its observation parks before
            // the sync task completes (the task's clock only advances at quiescence). The
            // stranded observation must resolve through a retry that returns the artifact.
            let update = context
                .child("update")
                .spawn(move |_| async move { mailbox.retarget(anchor(1, 1), 1).await });
            let result = update.await.expect("update task failed");
            assert!(
                matches!(&result, Some(artifact) if artifact.anchor.height == Height::zero()),
                "stranded update must resolve to the completed artifact",
            );

            let artifact = receiver.await.expect("artifact must publish");
            assert_eq!(artifact.anchor.height, Height::zero());
            actor.await.expect("syncer actor failed");
        });
    }
}
