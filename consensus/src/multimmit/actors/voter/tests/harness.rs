//! Shared voter test harness: participant zero's actors wired as the engine wires them, observed
//! by test hooks, on a simulated network whose other participants are test-driven peers.

use crate::multimmit::{
    actors::{
        resolver::Server,
        voter::{Actor, Inspector, Planes, actor::TestHooks},
    },
    config::Tuning,
    engine::{
        ActorLimits, CHECKPOINT_INTERVAL, Config as EngineConfig, derive_profile, wire_actors,
    },
    machine::Inspection,
    mocks::{
        Committee, MockApplication, RecordingBlocker, RecordingRelay, RecordingReporter,
        cluster::{
            CERTIFICATE_CHANNEL, CONSENSUS_CHANNEL, DATA_CHANNEL, QUOTA, RESOLVER_CHANNEL,
            start_network,
        },
    },
    storage::{RecoveryConfig, recover},
    testing::decode_frame,
    types::{CodecConfig, SignedTransactionBlock},
    wire::DataMessage,
};
use commonware_codec::Read;
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519, sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    Receiver as _,
    simulated::{Link, Oracle, Receiver, Sender},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic::Context,
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{NZUsize, channel::oneshot, probability};
use std::{num::NonZeroUsize, time::Duration};

pub(super) type Hooks = TestHooks<MinPk, Sha256Digest>;

/// Storage partition prefix of the node under test.
const PREFIX: &str = "voter";

/// A 5 s timer ceiling.
pub(super) fn tuning() -> Tuning {
    Tuning {
        timer_ceiling: Duration::from_secs(5),
        ..Tuning::new()
    }
}

/// The doubles one node runs with. Clones share their recordings, so a restarted node can run
/// with the same attachments.
#[derive(Clone, Default)]
pub(super) struct Attachments {
    pub(super) application: MockApplication,
    pub(super) relay: RecordingRelay<Sha256Digest, ed25519::PublicKey>,
    pub(super) reporter: RecordingReporter<MinPk, Sha256Digest>,
    pub(super) blocker: RecordingBlocker,
    pub(super) hooks: Hooks,
}

impl Attachments {
    /// Returns attachments whose application builds nothing until a test permits it.
    pub(super) fn paused() -> Self {
        let attachments = Self::default();
        attachments.application.pause_building();
        attachments
    }
}

/// A six-participant committee on a simulated network. Participant zero runs the voter under
/// test; every other participant is a peer the test drives directly.
pub(super) struct Network {
    pub(super) committee: Committee<MinPk>,
    oracle: Oracle<ed25519::PublicKey, Context>,
}

impl Network {
    pub(super) async fn new(context: &Context, seed: u64) -> Self {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
        let oracle = start_network(context, committee.identities.clone(), 4 * 1024 * 1024).await;
        Self { committee, oracle }
    }

    /// Registers participant `peer` on `channel`, without linking it to the node.
    pub(super) async fn register(
        &self,
        peer: usize,
        channel: u64,
    ) -> (
        Sender<ed25519::PublicKey, Context>,
        Receiver<ed25519::PublicKey>,
    ) {
        self.oracle
            .control(self.committee.identities[peer].clone())
            .register(channel, QUOTA)
            .await
            .unwrap()
    }

    /// Links participant `peer` and the node in both directions.
    pub(super) async fn link(&self, peer: usize) {
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::ZERO,
            success_rate: probability!(1.0),
        };
        let node = self.committee.identities[0].clone();
        let peer = self.committee.identities[peer].clone();
        let _ = self
            .oracle
            .add_link(peer.clone(), node.clone(), link.clone())
            .await;
        let _ = self.oracle.add_link(node, peer, link).await;
    }

    /// Registers participant `peer` on `channel` and links it with the node.
    pub(super) async fn peer(
        &self,
        peer: usize,
        channel: u64,
    ) -> (
        Sender<ed25519::PublicKey, Context>,
        Receiver<ed25519::PublicKey>,
    ) {
        let endpoints = self.register(peer, channel).await;
        self.link(peer).await;
        endpoints
    }

    /// Receives frames on `receiver` until `select` maps one to a value, failing after
    /// `timeout`.
    pub(super) async fn receive<M: Read<Cfg = CodecConfig>, T>(
        &self,
        context: &Context,
        receiver: &mut Receiver<ed25519::PublicKey>,
        timeout: Duration,
        mut select: impl FnMut(M) -> Option<T>,
    ) -> T {
        let deadline = context.current() + timeout;
        loop {
            select! {
                result = receiver.recv() => {
                    let (_, bytes) = result.expect("the network stays up");
                    if let Some(value) = select(decode_frame(&self.committee, bytes)) {
                        return value;
                    }
                },
                () = context.sleep_until(deadline) => panic!("no matching frame within {timeout:?}"),
            }
        }
    }

    /// Receives the next signed header the node sends on the data plane.
    pub(super) async fn next_block(
        &self,
        context: &Context,
        receiver: &mut Receiver<ed25519::PublicKey>,
    ) -> SignedTransactionBlock<MinPk, Sha256Digest> {
        self.receive(
            context,
            receiver,
            Duration::from_secs(5),
            |DataMessage::<MinPk, Sha256Digest>::Block(block)| Some(block),
        )
        .await
    }

    /// Asserts that `receiver` gets no frame for `duration`.
    pub(super) async fn silent(
        context: &Context,
        receiver: &mut Receiver<ed25519::PublicKey>,
        duration: Duration,
    ) {
        select! {
            result = receiver.recv() => panic!("unexpected frame: {result:?}"),
            () = context.sleep(duration) => {},
        }
    }

    /// Starts participant zero under `label` over its stored state and returns it with the
    /// receiver that resolves once its voter is ready.
    pub(super) async fn launch(
        &self,
        context: &Context,
        label: &'static str,
        attachments: &Attachments,
    ) -> (Node, oneshot::Receiver<()>) {
        let me = self.committee.identities[0].clone();
        let context = context.child(label);
        let task_prefix = context.name().label;
        let control = self.oracle.control(me);
        let data = control.register(DATA_CHANNEL, QUOTA).await.unwrap();
        let consensus = control.register(CONSENSUS_CHANNEL, QUOTA).await.unwrap();
        let certificates = control.register(CERTIFICATE_CHANNEL, QUOTA).await.unwrap();
        let resolver = control.register(RESOLVER_CHANNEL, QUOTA).await.unwrap();

        let Attachments {
            application,
            relay,
            reporter,
            blocker,
            hooks,
        } = attachments.clone();
        let config = EngineConfig {
            scheme: self.committee.signers[0].clone(),
            genesis: self.committee.config.genesis().clone(),
            tuning: tuning(),
            automaton: application,
            relay,
            reporter,
            strategy: Sequential,
            critical_strategy: Sequential,
            blocker,
            partition_prefix: PREFIX.into(),
            page_cache: CacheRef::from_pooler(&context, paged::page_size(4_096), NZUsize!(8)),
            mailbox_size: NonZeroUsize::new(64).unwrap(),
        };
        let profile = derive_profile(&config).expect("the test configuration is valid");
        let limits = ActorLimits::from_profile::<MinPk, _>(&profile, CHECKPOINT_INTERVAL);
        let mut stores = context.child("stores");
        let recovered = Box::pin(recover::<_, Sha256, _, _, _>(
            &mut stores,
            RecoveryConfig {
                profile: profile.clone(),
                partition_prefix: PREFIX,
                scheme: &config.scheme,
                strategy: &Sequential,
                page_cache: config.page_cache.clone(),
                checkpoint_interval: CHECKPOINT_INTERVAL,
            },
        ))
        .await
        .expect("durable state recovers");
        let actors = wire_actors(
            &context,
            config,
            &profile,
            recovered,
            limits,
            |context, queues, config| Actor::new_with_hooks(context, queues, config, hooks),
        );
        let artifacts = actors.resolver_mailbox.server();
        let endpoints = actors.voter_mailbox;
        let ingress = actors.ingress.start(
            actors.verifier,
            endpoints.completions,
            endpoints.observations,
            data.1,
            consensus.1,
            certificates.1,
        );
        let resolver = actors.resolver.start(endpoints.resolutions, resolver);
        let (ready, readiness) = oneshot::channel();
        let voter = actors.voter.start(
            ready,
            Planes {
                data: data.0,
                consensus: consensus.0,
                certificates: certificates.0,
            },
            actors.ingress_mailbox,
            actors.verifier_mailbox,
            actors.resolver_mailbox,
        );
        (
            Node {
                artifacts,
                inspector: endpoints.inspector,
                task_prefix,
                tasks: vec![ingress, resolver, voter],
            },
            readiness,
        )
    }

    /// Starts participant zero under `label` and waits until its voter is ready.
    pub(super) async fn start(
        &self,
        context: &Context,
        label: &'static str,
        attachments: &Attachments,
    ) -> Node {
        let (node, ready) = self.launch(context, label, attachments).await;
        ready.await.expect("the voter becomes ready");
        node
    }
}

/// Participant zero's running actors.
pub(super) struct Node {
    /// Reads the artifacts the node's resolver serves to peers.
    pub(super) artifacts: Server<MinPk, Sha256Digest>,
    inspector: Inspector<Sha256Digest>,
    task_prefix: String,
    tasks: Vec<Handle<()>>,
}

impl Node {
    /// Reads the machine's diagnostic projection.
    pub(super) async fn inspect(&self) -> Inspection<Sha256Digest> {
        self.inspector.inspect().await.expect("the voter responds")
    }

    /// Polls the machine until `done` holds, failing after `timeout`.
    pub(super) async fn wait_until(
        &self,
        context: &Context,
        timeout: Duration,
        mut done: impl FnMut(&Inspection<Sha256Digest>) -> bool,
    ) -> Inspection<Sha256Digest> {
        let deadline = context.current() + timeout;
        loop {
            let inspection = self.inspect().await;
            if done(&inspection) {
                return inspection;
            }
            assert!(
                context.current() < deadline,
                "condition unmet: {inspection:?}"
            );
            context.sleep(Duration::from_millis(10)).await;
        }
    }

    /// Stops every task of the node at once, leaving its storage as the crash found it.
    pub(super) async fn crash(self, context: &Context) {
        assert!(count_running_tasks(context, &self.task_prefix) > 0);
        for task in &self.tasks {
            task.abort();
        }
        for task in self.tasks {
            let _ = task.await;
        }
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(
            count_running_tasks(context, &self.task_prefix),
            0,
            "node tasks survived the crash"
        );
    }
}
