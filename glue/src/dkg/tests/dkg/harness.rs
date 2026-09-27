use super::properties::{DkgOutcome, ExpectedOutcome};
use crate::{
    dkg::{
        bootstrap,
        tests::{
            max_supported_mode,
            mocks::{FailingManager, FilteredReceiver, MemorySecretStore},
        },
        types::EpochInfo,
    },
    simulate::{
        action::{Crash, Schedule},
        engine::{EngineDefinition, InitContext},
        exit::{ExitCondition as _, ProcessedHeightAtLeast},
        plan::PlanBuilder,
        processed::ProcessedHeight,
        tracker::ProgressTracker,
    },
};
use commonware_consensus::types::Epoch;
use commonware_cryptography::{
    Signer as _,
    bls12381::{
        dkg::feldman_desmedt::Reveal,
        primitives::{
            group::{Private, Share},
            sharing::Mode,
            variant::MinPk,
        },
    },
    ed25519,
};
use commonware_macros::select;
use commonware_math::algebra::Random;
use commonware_p2p::{
    Manager as _, Provider as _,
    simulated::{self, Link, Network},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Quota, Runner as _, Spawner as _, Supervisor as _, deterministic,
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{
    NZU32, NZU64, NZUsize, Participant, channel::oneshot, ordered::Set, probability,
    sequence::Unit, sync::Mutex, test_rng,
};
use std::{
    collections::{BTreeMap, HashSet},
    num::NonZeroU64,
    sync::Arc,
    time::Duration,
};
use tracing::info;

const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_INITIAL_E2E";
const EPOCH_LENGTH: NonZeroU64 = NZU64!(32);
const TEST_QUOTA: Quota = Quota::per_second(NZU32!(1_000_000));

const VOTES: u64 = 0;
const CERTIFICATES: u64 = 1;
const RESOLVER: u64 = 2;
const BACKFILL: u64 = 3;
const BROADCAST: u64 = 4;
const DKG: u64 = 5;

#[derive(Default)]
struct NodeStateInner {
    completed: bool,
    info: Option<EpochInfo<MinPk, ed25519::PublicKey>>,
}

#[derive(Clone)]
pub(super) struct NodeState {
    store: MemorySecretStore,
    inner: Arc<Mutex<NodeStateInner>>,
}

impl NodeState {
    pub(super) fn completed(&self) -> bool {
        self.inner.lock().completed
    }

    pub(super) fn info(&self) -> Option<EpochInfo<MinPk, ed25519::PublicKey>> {
        self.inner.lock().info.clone()
    }

    pub(super) fn has_share(&self, epoch: Epoch) -> bool {
        self.store.has_share(epoch)
    }
}

impl ProcessedHeight for NodeState {
    async fn processed_height(&self) -> u64 {
        self.inner.lock().completed as u64
    }
}

pub(super) struct StartedNode {
    context: deterministic::Context,
    handle: Handle<()>,
    completion: oneshot::Receiver<bootstrap::Completion<MinPk>>,
    state: NodeState,
}

#[derive(Clone)]
pub(super) struct DkgEngine {
    signers: Vec<ed25519::PrivateKey>,
    filtered_dkg: Arc<HashSet<ed25519::PublicKey>>,
    deaf: Arc<HashSet<ed25519::PublicKey>>,
    stores: Arc<Mutex<BTreeMap<ed25519::PublicKey, MemorySecretStore>>>,
    inits: Arc<Mutex<BTreeMap<ed25519::PublicKey, Vec<bool>>>>,
}

impl DkgEngine {
    pub(super) fn new(total: u64) -> Self {
        let mut signers = (0..total)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        signers.sort_by_key(|signer| signer.public_key());
        Self {
            signers,
            filtered_dkg: Arc::default(),
            deaf: Arc::default(),
            stores: Arc::default(),
            inits: Arc::default(),
        }
    }

    /// Returns whether each incarnation of `public_key` started with its
    /// epoch-zero share.
    pub(super) fn inits(&self, public_key: &ed25519::PublicKey) -> Vec<bool> {
        self.inits
            .lock()
            .get(public_key)
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn with_filtered_dkg(mut self) -> Self {
        self.filtered_dkg = Arc::new(
            self.signers
                .iter()
                .map(|signer| signer.public_key())
                .collect(),
        );
        self
    }

    /// Drops every consensus message `participant` receives, so it can learn
    /// the chain only through marshal.
    pub(super) fn with_deaf(mut self, participant: usize) -> Self {
        self.deaf = Arc::new(HashSet::from([self.participant(participant)]));
        self
    }

    pub(super) fn participant(&self, index: usize) -> ed25519::PublicKey {
        self.signers[index].public_key()
    }

    fn signer(&self, public_key: &ed25519::PublicKey) -> ed25519::PrivateKey {
        self.signers
            .iter()
            .find(|signer| signer.public_key() == *public_key)
            .expect("participant signer exists")
            .clone()
    }

    fn participants_set(&self) -> Set<ed25519::PublicKey> {
        Set::from_iter_dedup(self.signers.iter().map(|signer| signer.public_key()))
    }

    fn store(&self, public_key: &ed25519::PublicKey) -> MemorySecretStore {
        self.stores
            .lock()
            .entry(public_key.clone())
            .or_default()
            .clone()
    }
}

impl EngineDefinition for DkgEngine {
    type PublicKey = ed25519::PublicKey;
    type Engine = StartedNode;
    type State = NodeState;

    fn participants(&self) -> Vec<Self::PublicKey> {
        self.signers
            .iter()
            .map(|signer| signer.public_key())
            .collect()
    }

    fn channels(&self) -> Vec<(u64, Quota)> {
        vec![
            (VOTES, TEST_QUOTA),
            (CERTIFICATES, TEST_QUOTA),
            (RESOLVER, TEST_QUOTA),
            (BACKFILL, TEST_QUOTA),
            (BROADCAST, TEST_QUOTA),
            (DKG, TEST_QUOTA),
        ]
    }

    async fn init(&self, ctx: InitContext<'_, Self::PublicKey>) -> (Self::Engine, Self::State) {
        let InitContext {
            context,
            index,
            public_key,
            oracle,
            mut channels,
            ..
        } = ctx;
        assert_eq!(channels.len(), 6);

        let store = self.store(public_key);
        self.inits
            .lock()
            .entry(public_key.clone())
            .or_default()
            .push(store.has_share(Epoch::zero()));
        let state = NodeState {
            store: store.clone(),
            inner: Arc::default(),
        };
        let engine = bootstrap::Engine::<_, MinPk, _, _, _, _, _>::new(
            context.child("dkg"),
            bootstrap::Config {
                signer: self.signer(public_key),
                manager: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                secret_store: store,
                strategy: Sequential,
                namespace: NAMESPACE,
                sharing_mode: Mode::NonZeroCounter,
                reveal: Reveal::V1,
                max_supported_mode: max_supported_mode(),
                partition_prefix: format!("dkg-{index}"),
                participants: self.participants_set(),
                directory: Unit,
                blocks_per_epoch: EPOCH_LENGTH,
            },
        );
        let deaf = self.deaf.contains(public_key);
        let (handle, completion) = engine.start(
            filter(channels.remove(0), deaf),
            filter(channels.remove(0), deaf),
            filter(channels.remove(0), deaf),
            channels.remove(0),
            channels.remove(0),
            filter(channels.remove(0), self.filtered_dkg.contains(public_key)),
        );

        (
            StartedNode {
                context,
                handle,
                completion,
                state: state.clone(),
            },
            state,
        )
    }

    fn start(engine: Self::Engine) -> Handle<()> {
        let StartedNode {
            context,
            handle,
            completion,
            state,
        } = engine;
        context.spawn(move |_| async move {
            let mut handle = AbortOnDrop(Some(handle));
            select! {
                completion = completion => {
                    let completion = completion.expect("completion channel closed");
                    {
                        let mut inner = state.inner.lock();
                        inner.completed = true;
                        inner.info = completion.info;
                    }

                    // A completed engine keeps serving peers until the plan exits.
                    let result = handle.0.as_mut().expect("handle present").await;
                    panic!("DKG engine stopped after completion: {result:?}");
                },
                result = &mut handle.0.as_mut().expect("handle present") => {
                    result.expect("DKG engine stopped");
                },
            }
        })
    }
}

/// Wraps the receiver of `channel` to drop every message when `drop` is set.
fn filter<S, R>((sender, receiver): (S, R), drop: bool) -> (S, FilteredReceiver<R>) {
    if drop {
        (sender, FilteredReceiver::drop_all(receiver))
    } else {
        (sender, FilteredReceiver::pass(receiver))
    }
}

struct AbortOnDrop(Option<Handle<()>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

pub(super) fn run_plan(
    engine: DkgEngine,
    link: Link,
    crashes: Vec<Crash<ed25519::PublicKey>>,
    expected: ExpectedOutcome,
    seeds: impl IntoIterator<Item = u64>,
) {
    let participants = engine.participants();
    for seed in seeds {
        info!(seed, "running DKG plan");

        // Secret stores survive restarts within a run, so each seed starts
        // with empty stores.
        let engine = DkgEngine {
            stores: Arc::default(),
            inits: Arc::default(),
            ..engine.clone()
        };
        let property = DkgOutcome::new(participants.clone(), expected);
        let mut builder = PlanBuilder::new(engine)
            .link(link.clone())
            .required_finalizations(0)
            .exit_condition(ProcessedHeightAtLeast::new(1))
            .property(property)
            .timeout(Duration::from_secs(300))
            .seed(seed);
        for crash in crashes.iter().cloned() {
            builder = builder.crash(crash);
        }
        builder.run().expect("DKG simulation");
    }
}

/// Runs `schedule` on `engine` for one seed, keeping its secret stores and
/// init records so the caller can inspect them afterward.
pub(super) fn run_schedule(engine: &DkgEngine, schedule: Schedule<ed25519::PublicKey>) {
    let property = DkgOutcome::new(engine.participants(), ExpectedOutcome::Success);
    PlanBuilder::new(engine.clone())
        .link(good_link())
        .required_finalizations(0)
        .exit_condition(ProcessedHeightAtLeast::new(1))
        .property(property)
        .timeout(Duration::from_secs(300))
        .crash(Crash::Schedule(schedule))
        .run()
        .expect("DKG simulation");
}

pub(super) fn run_restart_completion_state_is_fresh() {
    let engine = DkgEngine::new(1);
    let public_key = engine.participant(0);
    let old_state = NodeState {
        store: engine.store(&public_key),
        inner: Arc::default(),
    };
    let replacement_state = NodeState {
        store: engine.store(&public_key),
        inner: Arc::default(),
    };

    let share = Share::new(Participant::new(0), Private::random(test_rng()));
    old_state.store.seed_share(Epoch::zero(), share);
    assert!(
        replacement_state.has_share(Epoch::zero()),
        "restart must retain the persistent secret store"
    );

    old_state.inner.lock().completed = true;
    assert!(
        !replacement_state.completed(),
        "stale completion changed replacement state"
    );

    let runner = deterministic::Runner::timed(Duration::from_secs(1));
    runner.start(|_| async move {
        let tracker = ProgressTracker::<ed25519::PublicKey>::default();
        let states = [&replacement_state];
        let reached = ProcessedHeightAtLeast::new(1)
            .reached(&tracker, &states, 1)
            .await
            .expect("exit condition should evaluate");
        assert!(
            !reached,
            "exit condition should wait for the current incarnation"
        );
    });
}

pub(super) fn good_link() -> Link {
    Link {
        latency: Duration::from_millis(20),
        jitter: Duration::from_millis(5),
        success_rate: probability!(1.0),
    }
}

pub(super) fn run_closed_network_receiver() {
    let runner = deterministic::Runner::timed(Duration::from_secs(5));
    runner.start(|context| async move {
        let engine = DkgEngine::new(1);
        let participants = engine.participants_set();
        let (network, oracle) = Network::<_, ed25519::PublicKey>::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(participants.len()),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();

        let public_key = engine.participant(0);
        oracle.manager().track(0, participants.clone());

        let control = oracle.control(public_key.clone());
        let mut channels = Vec::new();
        for (channel, quota) in engine.channels() {
            channels.push(
                control
                    .register(channel, quota)
                    .await
                    .expect("channel registration failed"),
            );
        }

        let _replacement_broadcast = control
            .register(BROADCAST, TEST_QUOTA)
            .await
            .expect("replacement channel registration failed");

        let store = engine.store(&public_key);
        let bootstrap = bootstrap::Engine::<_, MinPk, _, _, _, _, _>::new(
            context.child("dkg"),
            bootstrap::Config {
                signer: engine.signer(&public_key),
                manager: oracle.manager(),
                blocker: oracle.control(public_key),
                secret_store: store,
                strategy: Sequential,
                namespace: NAMESPACE,
                sharing_mode: Mode::NonZeroCounter,
                reveal: Reveal::V1,
                max_supported_mode: max_supported_mode(),
                partition_prefix: "dkg-closed-receiver".into(),
                participants,
                directory: Unit,
                blocks_per_epoch: EPOCH_LENGTH,
            },
        );
        let (mut handle, completion) = bootstrap.start(
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
        );

        select! {
            result = &mut handle => result.expect("bootstrap should stop cleanly"),
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("bootstrap did not stop after a supplied receiver closed");
            },
        }

        assert!(
            completion.await.is_err(),
            "closed receiver should not produce DKG completion"
        );
        context.sleep(Duration::from_millis(10)).await;
        assert_eq!(
            count_running_tasks(&context, "dkg"),
            0,
            "bootstrap child actors should be canceled"
        );
    });
}

pub(super) fn run_activation_failure_completes_empty() {
    let runner = deterministic::Runner::timed(Duration::from_secs(5));
    runner.start(|context| async move {
        let (network, oracle) = Network::<_, ed25519::PublicKey>::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                max_peers_per_set: NZUsize!(1),
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();

        let engine = DkgEngine::new(1);
        let public_key = engine.participant(0);
        let control = oracle.control(public_key.clone());
        let mut channels = Vec::new();
        for (channel, quota) in engine.channels() {
            channels.push(
                control
                    .register(channel, quota)
                    .await
                    .expect("channel registration failed"),
            );
        }

        let bootstrap = bootstrap::Engine::<_, MinPk, _, _, _, _, _>::new(
            context.child("dkg"),
            bootstrap::Config {
                signer: engine.signer(&public_key),
                manager: FailingManager(oracle.manager()),
                blocker: oracle.control(public_key),
                secret_store: engine.store(&engine.participant(0)),
                strategy: Sequential,
                namespace: NAMESPACE,
                sharing_mode: Mode::NonZeroCounter,
                reveal: Reveal::V1,
                max_supported_mode: max_supported_mode(),
                partition_prefix: "dkg-activation-failure".into(),
                participants: engine.participants_set(),
                directory: Unit,
                blocks_per_epoch: EPOCH_LENGTH,
            },
        );
        let (handle, completion) = bootstrap.start(
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
        );

        let completion = select! {
            result = completion => {
                result.expect("activation failure should report DKG completion")
            },
            _ = context.sleep(Duration::from_secs(1)) => {
                panic!("activation failure did not report DKG completion");
            },
        };
        assert!(completion.info.is_none());
        context.sleep(Duration::from_millis(10)).await;
        handle.abort();
    });
}

type Info = EpochInfo<MinPk, ed25519::PublicKey>;

/// Runs a single-participant ceremony to completion, then lets the runtime
/// idle for `idle` before an unclean shutdown.
fn complete<M>(
    engine: &DkgEngine,
    manager: impl FnOnce(&simulated::Oracle<ed25519::PublicKey, deterministic::Context>) -> M
    + Send
    + 'static,
    idle: Duration,
) -> (Option<Info>, deterministic::Checkpoint)
where
    M: crate::dkg::network::Manager<PublicKey = ed25519::PublicKey, Directory = Unit> + Clone,
{
    let runner = deterministic::Runner::timed(Duration::from_secs(120));
    runner.start_and_recover({
        let engine = engine.clone();
        move |context| async move {
            let oracle = network(&context);
            let (_handle, completion) = boot(&context, &oracle, &engine, manager(&oracle)).await;
            let info = completion.await.expect("DKG should report completion").info;
            context.sleep(idle).await;
            info
        }
    })
}

/// Restarts the single participant from `checkpoint` on a fresh network and
/// returns its report and whether it activated peer set zero. Fails if the
/// engine stops after reporting.
fn restart<M>(
    engine: &DkgEngine,
    checkpoint: deterministic::Checkpoint,
    manager: impl FnOnce(&simulated::Oracle<ed25519::PublicKey, deterministic::Context>) -> M
    + Send
    + 'static,
) -> (Option<Info>, bool)
where
    M: crate::dkg::network::Manager<PublicKey = ed25519::PublicKey, Directory = Unit> + Clone,
{
    let runner = deterministic::Runner::from(checkpoint);
    let engine = engine.clone();
    runner.start(|context| async move {
        let oracle = network(&context);
        let (mut handle, completion) = boot(&context, &oracle, &engine, manager(&oracle)).await;
        let restarted = select! {
            restarted = completion => restarted.expect("restart should report completion"),
            _ = context.sleep(Duration::from_secs(30)) => panic!("restart did not report completion"),
        };
        select! {
            result = &mut handle => panic!("engine stopped after reporting: {result:?}"),
            _ = context.sleep(Duration::from_secs(1)) => {},
        }
        let tracked = oracle.manager().peer_set(0).await.is_some();
        handle.abort();
        (restarted.info, tracked)
    })
}

pub(super) fn run_restart_after_completion() {
    let engine = DkgEngine::new(1);

    // The ceremony completes and persists the share, then the runtime stops
    // uncleanly without idling.
    let (info, checkpoint) = complete(&engine, |oracle| oracle.manager(), Duration::ZERO);
    let info = info.expect("DKG should succeed");
    assert!(
        engine
            .store(&engine.participant(0))
            .has_share(Epoch::zero())
    );

    // Running the ceremony again could not activate its peer set and would
    // report no artifact. The restart reports the finalized artifact instead
    // and keeps running.
    let (restarted, _) = restart(&engine, checkpoint, |oracle| {
        FailingManager(oracle.manager())
    });
    assert_eq!(restarted, Some(info));
}

pub(super) fn run_restart_without_share() {
    let engine = DkgEngine::new(1);

    // The ceremony completes and marshal records the final block as processed.
    let (info, checkpoint) = complete(&engine, |oracle| oracle.manager(), Duration::from_secs(5));
    let info = info.expect("DKG should succeed");

    // Model a participant that completed without a share.
    engine
        .stores
        .lock()
        .insert(engine.participant(0), MemorySecretStore::default());

    // The restart reports the finalized artifact and re-activates peer set
    // zero on a network that has never seen it.
    let (restarted, tracked) = restart(&engine, checkpoint, |oracle| oracle.manager());
    assert_eq!(restarted, Some(info));
    assert!(tracked, "restart should activate peer set zero");
}

pub(super) fn run_restart_after_failure() {
    let engine = DkgEngine::new(1);

    // Activation fails, so the ceremony reports no artifact, and the chain
    // finalizes a final block without one while the actor idles.
    let (info, checkpoint) = complete(
        &engine,
        |oracle| FailingManager(oracle.manager()),
        Duration::from_secs(60),
    );
    assert!(info.is_none());

    // The restart reports the failed outcome from the final block.
    let (restarted, tracked) = restart(&engine, checkpoint, |oracle| oracle.manager());
    assert!(restarted.is_none());
    assert!(tracked, "restart should activate peer set zero");
}

pub(super) fn run_share_without_final_block() {
    // The secret store holds a share before any bootstrap storage exists.
    let engine = DkgEngine::new(1);
    let share = Share::new(Participant::new(0), Private::random(test_rng()));
    engine
        .store(&engine.participant(0))
        .seed_share(Epoch::zero(), share);

    let runner = deterministic::Runner::timed(Duration::from_secs(5));
    runner.start(|context| async move {
        let oracle = network(&context);
        let (handle, _) = boot(&context, &oracle, &engine, oracle.manager()).await;
        let _ = handle.await;
    });
}

/// Starts a simulated network with room for one participant.
fn network(
    context: &deterministic::Context,
) -> simulated::Oracle<ed25519::PublicKey, deterministic::Context> {
    let (network, oracle) = Network::<_, ed25519::PublicKey>::new(
        context.child("network"),
        simulated::Config {
            max_size: 1024 * 1024,
            max_peers_per_set: NZUsize!(1),
            disconnect_on_block: true,
            tracked_peer_sets: NZUsize!(1),
        },
    );
    network.start();
    oracle
}

/// Starts the first participant's bootstrap engine on freshly registered
/// channels, reusing its storage partitions and secret store.
async fn boot<M>(
    context: &deterministic::Context,
    oracle: &simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    engine: &DkgEngine,
    manager: M,
) -> (Handle<()>, oneshot::Receiver<bootstrap::Completion<MinPk>>)
where
    M: crate::dkg::network::Manager<PublicKey = ed25519::PublicKey, Directory = Unit> + Clone,
{
    let public_key = engine.participant(0);
    let control = oracle.control(public_key.clone());
    let mut channels = Vec::new();
    for (channel, quota) in engine.channels() {
        channels.push(
            control
                .register(channel, quota)
                .await
                .expect("channel registration failed"),
        );
    }

    let bootstrap = bootstrap::Engine::<_, MinPk, _, _, _, _, _>::new(
        context.child("dkg"),
        bootstrap::Config {
            signer: engine.signer(&public_key),
            manager,
            blocker: control,
            secret_store: engine.store(&public_key),
            strategy: Sequential,
            namespace: NAMESPACE,
            sharing_mode: Mode::NonZeroCounter,
            reveal: Reveal::V1,
            max_supported_mode: max_supported_mode(),
            partition_prefix: "dkg-single".into(),
            participants: engine.participants_set(),
            directory: Unit,
            blocks_per_epoch: EPOCH_LENGTH,
        },
    );
    bootstrap.start(
        channels.remove(0),
        channels.remove(0),
        channels.remove(0),
        channels.remove(0),
        channels.remove(0),
        channels.remove(0),
    )
}
