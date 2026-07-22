use super::properties::{DkgOutcome, ExpectedOutcome};
use crate::{
    dkg::{
        bootstrap,
        tests::{
            max_supported_mode,
            mocks::{FilteredReceiver, MemorySecretStore},
        },
        types::EpochInfo,
    },
    simulate::{
        action::Crash,
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
    bls12381::primitives::{
        group::{Private, Share},
        sharing::Mode,
        variant::MinPk,
    },
    ed25519,
};
use commonware_macros::select;
use commonware_math::algebra::Random;
use commonware_p2p::{
    Manager as _,
    simulated::{self, Link, Network},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Quota, Runner as _, Spawner as _, Supervisor as _, deterministic,
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{
    NZU32, NZU64, NZUsize, Participant, channel::oneshot, ordered::Set, sync::Mutex, test_rng,
};
use futures::future::pending;
use std::{
    collections::{BTreeMap, HashSet},
    num::NonZeroU64,
    sync::Arc,
    time::Duration,
};

const NAMESPACE: &[u8] = b"_COMMONWARE_GLUE_DKG_INITIAL_E2E";
const EPOCH_LENGTH: NonZeroU64 = NZU64!(16);
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
    stores: Arc<Mutex<BTreeMap<ed25519::PublicKey, MemorySecretStore>>>,
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
            stores: Arc::default(),
        }
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
        let state = NodeState {
            store: store.clone(),
            inner: Arc::default(),
        };
        let engine = bootstrap::Engine::<_, MinPk, _, _, _, _>::new(
            context.child("dkg"),
            bootstrap::Config {
                signer: self.signer(public_key),
                manager: oracle.manager(),
                blocker: oracle.control(public_key.clone()),
                secret_store: store,
                strategy: Sequential,
                namespace: NAMESPACE,
                sharing_mode: Mode::NonZeroCounter,
                max_supported_mode: max_supported_mode(),
                partition_prefix: format!("dkg-{index}"),
                participants: self.participants_set(),
                blocks_per_epoch: EPOCH_LENGTH,
            },
        );
        let (handle, completion) = engine.start(
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            channels.remove(0),
            {
                let (sender, receiver) = channels.remove(0);
                (
                    sender,
                    if self.filtered_dkg.contains(public_key) {
                        FilteredReceiver::drop_all(receiver)
                    } else {
                        FilteredReceiver::pass(receiver)
                    },
                )
            },
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
                    pending::<()>().await;
                },
                result = &mut handle.0.as_mut().expect("handle present") => {
                    result.expect("DKG engine stopped");
                },
            }
        })
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
) {
    let participants = engine.participants();
    let property = DkgOutcome::new(participants, expected);
    let mut builder = PlanBuilder::new(engine)
        .link(link)
        .required_finalizations(0)
        .exit_condition(ProcessedHeightAtLeast::new(1))
        .property(property)
        .timeout(Duration::from_secs(60));
    for crash in crashes {
        builder = builder.crash(crash);
    }
    builder.run().expect("DKG simulation");
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
        success_rate: 1.0,
    }
}

pub(super) fn run_closed_network_receiver() {
    let runner = deterministic::Runner::timed(Duration::from_secs(5));
    runner.start(|context| async move {
        let (network, oracle) = Network::<_, ed25519::PublicKey>::new(
            context.child("network"),
            simulated::Config {
                max_size: 1024 * 1024,
                disconnect_on_block: true,
                tracked_peer_sets: NZUsize!(1),
            },
        );
        network.start();

        let engine = DkgEngine::new(1);
        let public_key = engine.participant(0);
        oracle
            .manager()
            .track(0, Set::from_iter_dedup(engine.participants()));

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
        let bootstrap = bootstrap::Engine::<_, MinPk, _, _, _, _>::new(
            context.child("dkg"),
            bootstrap::Config {
                signer: engine.signer(&public_key),
                manager: oracle.manager(),
                blocker: oracle.control(public_key),
                secret_store: store,
                strategy: Sequential,
                namespace: NAMESPACE,
                sharing_mode: Mode::NonZeroCounter,
                max_supported_mode: max_supported_mode(),
                partition_prefix: "dkg-closed-receiver".into(),
                participants: engine.participants_set(),
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
