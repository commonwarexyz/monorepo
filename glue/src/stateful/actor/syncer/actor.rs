use super::{
    Artifact,
    mailbox::{Mailbox, Message, UpdateOutcome},
    resolve,
};
use crate::stateful::{
    Application,
    actor::BlockDigest,
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
    completion: Option<oneshot::Sender<Artifact<E, A>>>,
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
                completion: Some(config.completion),
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

        let (tip_updates_tx, tip_updates_rx) = ring::channel(NZUsize!(1));
        let mut tip_updates_tx = Some(tip_updates_tx);
        let mut task = OptionFuture::from(Some(Box::pin(A::Databases::sync(
            self.context.child("state_sync"),
            self.db_config,
            self.resolvers,
            Anchor::from(block.as_ref()),
            A::sync_targets(block.as_ref()),
            tip_updates_rx,
            self.sync_config,
        ))));

        select_loop! {
            self.context,
            on_stopped => {
                debug!("syncer received stop signal, shutting down");
            },
            result = &mut task => match result {
                Ok((databases, anchor)) => {
                    let completion = self
                        .completion
                        .take()
                        .expect("completion sender present until sync completes");
                    completion.send_lossy(Artifact { databases, anchor });
                    task = None.into();

                    // No coordinator remains to record a queued update. Dropping the sender
                    // drops that update, so its caller retries and learns sync completed.
                    tip_updates_tx = None;
                }
                Err(err) => {
                    // Unreachable from adversarial input, since the target root comes
                    // from a finalized block and fetched operations are
                    // proof-verified, so bad peer data surfaces as resolver
                    // feedback and retries, never as an engine error.
                    panic!("state sync task failed: {err:?}");
                }
            },
            Some(message) = self.mailbox.recv() else {
                debug!("mailbox closed, shutting down syncer");
                break;
            } => match message {
                Message::Retarget { update, response } => {
                    if self.completion.is_none() {
                        response.send_lossy(UpdateOutcome::SyncCompleted);
                        continue;
                    }

                    // If sync had already completed, the state-sync branch above would
                    // have consumed the completion sender before this mailbox branch ran.
                    let tip_updates = tip_updates_tx
                        .as_mut()
                        .expect("ring sender lives until the artifact is published");
                    if tip_updates.send(update).await.is_err() {
                        // A closed target channel means state sync accepts no more targets. Wait
                        // for its result instead of failing.
                        match (&mut task).await {
                            Ok((databases, anchor)) => {
                                task = None.into();
                                let completion = self
                                    .completion
                                    .take()
                                    .expect("completion sender present until sync completes");
                                completion.send_lossy(Artifact { databases, anchor });
                                response.send_lossy(UpdateOutcome::SyncCompleted);
                            }
                            Err(err) => {
                                panic!("state sync task failed: {err:?}");
                            }
                        }
                        tip_updates_tx = None;
                        continue;
                    }
                    response.send_lossy(UpdateOutcome::Observed);
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, Syncer, resolve};
    use crate::stateful::{
        Application, Config as StatefulConfig, ExecutionError, Input, Proposed, Stateful,
        actor::syncer::{SyncPlan, UpdateOutcome, open},
        db::{Anchor, Barrier, DatabaseSet, Publisher, StateSyncSet, SyncEngineConfig, TipUpdate},
        tests::{
            fixtures::{self, MarshalFixture},
            mocks::{TestBlock, TestMerkleized, TestScheme, TestUnmerkleized, TestVariant, anchor},
        },
    };
    use commonware_consensus::{
        Application as _, CertifiableBlock as _, Heightable as _, Reporter as _,
        marshal::{
            ancestry::{self, Ancestry},
            core::Processed,
        },
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
    use std::{convert::Infallible, sync::Arc, time::Duration};

    /// Database set whose sync holds the tip-update ring receiver without draining it, then
    /// completes once the actor has parked a forwarded update in the ring buffer.
    #[derive(Clone, Default)]
    struct WedgeSet(u64);

    impl DatabaseSet<deterministic::Context> for WedgeSet {
        type Unmerkleized = TestUnmerkleized;
        type Merkleized = TestMerkleized;
        type Readers = ();
        type Snapshots = ();
        type Config = u64;
        type SyncTargets = u64;

        const CHEAP_SNAPSHOT: bool = false;
        const ANY_CHEAP_SNAPSHOT: bool = false;

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

        fn readers(&self) -> Self::Readers {}

        async fn new_batches(_readers: &Self::Readers) -> Self::Unmerkleized {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        fn fork_batches(_parent: &Self::Merkleized) -> Self::Unmerkleized {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        fn matches_sync_targets(_batches: &Self::Merkleized, _targets: &Self::SyncTargets) -> bool {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn apply(self, _batches: Self::Merkleized) -> Self {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn finalize(self) -> (Self, Self::Snapshots, Barrier) {
            unreachable!("WedgeSet only serves the syncer harness")
        }

        async fn snapshot(self) -> (Self, Self::Snapshots) {
            (self, ())
        }

        async fn refresh_cheap(self, _served: &Self::Snapshots) -> (Self, Self::Snapshots) {
            (self, ())
        }

        fn merge_snapshots(_served: &Self::Snapshots, _fresh: Self::Snapshots) -> Self::Snapshots {}

        async fn prune(self, _targets: &Self::SyncTargets) -> Self {
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
            // Hold the ring receiver without draining it. The 1 s sleep spans many scheduling
            // rounds of the deterministic clock, so the actor forwards a tip update into the
            // ring buffer first. Completing then drops the receiver with the update still
            // queued.
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
        ) -> Result<Option<Proposed<Self, deterministic::Context>>, ExecutionError> {
            unreachable!("WedgeApp only serves the syncer harness")
        }

        async fn verify(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _ancestry: impl Ancestry<Self::Block>,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
            unreachable!("WedgeApp only serves the syncer harness")
        }

        async fn apply(
            &mut self,
            _context: (deterministic::Context, Self::Context),
            _block: &Self::Block,
            _batches: TestUnmerkleized,
        ) -> Result<Option<TestMerkleized>, ExecutionError> {
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
            let publication_context = context.child("publication");
            let (snapshot_publisher, snapshot_subscriber) = Publisher::new(&publication_context);
            let (stateful, mut mailbox) = Stateful::new(
                context.child("stateful"),
                StatefulConfig {
                    application: WedgeApp,
                    db_config: 0,
                    provider: (),
                    marshal: (marshal.mailbox.clone(), marshal.floor),
                    mailbox_size: NZUsize!(1),
                    plan,
                    resolvers: (),
                    snapshot_publisher,
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

            // State sync resumes and converges at the installed floor, whose snapshot the handoff
            // publishes before it records completion.
            while snapshot_subscriber.latest().is_none() {
                context.sleep(Duration::from_millis(1)).await;
            }

            // The handoff no longer reads the mailbox, so processing answers this empty proposal
            // only after completion is recorded.
            assert!(
                mailbox
                    .propose(
                        (context.child("fence"), block.context()),
                        ancestry::from_iter(std::iter::empty::<Arc<TestBlock>>()),
                        (),
                    )
                    .await
                    .is_none()
            );
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

    /// A tip update stranded in the ring buffer by sync completion resolves
    /// through the caller's retry with the completed artifact instead of
    /// parking its observation forever.
    #[test]
    fn stranded_tip_update_resolves_to_artifact() {
        deterministic::Runner::timed(Duration::from_secs(10)).start(|mut context| async move {
            let fixture = scheme_mocks::fixture(&mut context, b"syncer-stranded-update", 1);
            let block = TestBlock::new(0, 0);
            let finalization = fixtures::finalization(&fixture, 0, Sha256::fill(0));
            let MarshalFixture {
                mailbox: marshal,
                floor,
                guards: _guards,
            } = fixtures::marshal_fixture(
                context.child("marshal"),
                "syncer-stranded-update",
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
            // the sync task's 1 s sleep ends. The
            // stranded observation must resolve through a retry that reports completion,
            // with the artifact arriving on the completion channel.
            let update = context
                .child("update")
                .spawn(move |_| async move { mailbox.retarget(anchor(1, 1), 1).await });
            let outcome = update.await.expect("update task failed");
            assert_eq!(
                outcome,
                Some(UpdateOutcome::SyncCompleted),
                "stranded update must report the completed sync"
            );

            let artifact = receiver.await.expect("artifact must publish");
            assert_eq!(artifact.anchor.height, Height::zero());
            actor.await.expect("syncer actor failed");
        });
    }
}
