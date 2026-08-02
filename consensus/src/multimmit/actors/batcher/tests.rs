//! Deterministic batcher tests over the simulated network.

use super::{Actor, Completed, Config, IngressLimits, Message, Observed};
use crate::{
    multimmit::{
        actors::wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope},
        config::Limits,
        machine::{
            Artifact, BarrierAck, Capability, CoreState, CoreTurn, DurabilityCapability, Profile,
            Role, StepStatus, Tuning, VerificationCapability, VerifyJob,
        },
        mocks::{
            Committee, RecordingBlocker,
            cluster::{QUOTA, start_network},
        },
        types::SignedTransactionBlock,
    },
    types::{Attributable as _, Epoch, Round, View},
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::{Encode as _, EncodeSize as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    ed25519::PublicKey as Ed25519PublicKey, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_traced};
use commonware_p2p::{
    Receiver, Recipients, Sender as P2pSender,
    simulated::{Link, Oracle},
};
use commonware_parallel::{Manual, Sequential, Strategy};
use commonware_runtime::{
    Clock as _, IoBuf, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt,
    future::{Future, pending},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime},
};
use tracing::Span;

type TestActor =
    Actor<DeterministicContext, Sha256, Ed25519PublicKey, MinPk, RecordingBlocker, Sequential>;

#[derive(Clone, Debug)]
struct StallingStrategy {
    calls: Arc<AtomicUsize>,
    stall_at: usize,
}

impl StallingStrategy {
    fn new(stall_at: usize) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            stall_at,
        }
    }
}

impl Strategy for StallingStrategy {
    fn manual(&self) -> Manual<Self> {
        Manual::new(self.clone(), NonZeroUsize::MIN)
    }

    fn spawn<F, T>(&self, operation: F) -> impl Future<Output = T> + Send + 'static
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static,
    {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let stall_at = self.stall_at;
        let strategy = self.clone();
        async move {
            if call == stall_at {
                pending::<()>().await;
            }
            operation(strategy)
        }
    }

    fn fold_init<I, INIT, T, R, ID, F, RD>(
        &self,
        iter: I,
        init: INIT,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> R
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        INIT: Fn() -> T + Send + Sync,
        T: Send,
        R: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, &mut T, I::Item) -> R + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        Sequential.fold_init(iter, init, identity, fold_op, reduce_op)
    }

    fn try_fold<I, R, E, ID, F, RD>(
        &self,
        iter: I,
        identity: ID,
        fold_op: F,
        reduce_op: RD,
    ) -> Result<R, E>
    where
        I: IntoIterator<IntoIter: Send, Item: Send> + Send,
        R: Send,
        E: Send,
        ID: Fn() -> R + Send + Sync,
        F: Fn(R, I::Item) -> Result<R, E> + Send + Sync,
        RD: Fn(R, R) -> R + Send + Sync,
    {
        Sequential.try_fold(iter, identity, fold_op, reduce_op)
    }

    fn run<R, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> R
    where
        R: Send,
        SEQ: FnOnce() -> R + Send,
        PAR: FnOnce() -> R + Send,
    {
        Sequential.run(len, serial, parallel)
    }

    fn try_run<R, E, SEQ, PAR>(&self, len: usize, serial: SEQ, parallel: PAR) -> Result<R, E>
    where
        R: Send,
        E: Send,
        SEQ: FnOnce() -> Result<R, E> + Send,
        PAR: FnOnce() -> Result<R, E> + Send,
    {
        Sequential.try_run(len, serial, parallel)
    }

    fn join<A, B, RA, RB>(&self, a: A, b: B) -> (RA, RB)
    where
        A: FnOnce() -> RA + Send,
        B: FnOnce() -> RB + Send,
        RA: Send,
        RB: Send,
    {
        Sequential.join(a, b)
    }

    fn sort_by<T, C>(&self, items: &mut [T], compare: C)
    where
        T: Send,
        C: Fn(&T, &T) -> std::cmp::Ordering + Send + Sync,
    {
        Sequential.sort_by(items, compare);
    }
}

struct ReadyReceiver {
    messages: VecDeque<(Ed25519PublicKey, IoBuf)>,
    immediate: usize,
    context: Option<DeterministicContext>,
    ready_after: Option<Duration>,
    ready_at: Option<SystemTime>,
}

impl fmt::Debug for ReadyReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadyReceiver")
            .field("messages", &self.messages.len())
            .field("immediate", &self.immediate)
            .field("ready_after", &self.ready_after)
            .field("ready_at", &self.ready_at)
            .finish()
    }
}

impl ReadyReceiver {
    fn new(messages: Vec<(Ed25519PublicKey, Bytes)>) -> Self {
        let immediate = messages.len();
        Self {
            messages: messages
                .into_iter()
                .map(|(peer, message)| (peer, message.into()))
                .collect(),
            immediate,
            context: None,
            ready_after: None,
            ready_at: None,
        }
    }

    fn staged(
        context: DeterministicContext,
        ready_after: Duration,
        immediate: Vec<(Ed25519PublicKey, Bytes)>,
        delayed: Vec<(Ed25519PublicKey, Bytes)>,
    ) -> Self {
        let immediate_len = immediate.len();
        Self {
            messages: immediate
                .into_iter()
                .chain(delayed)
                .map(|(peer, message)| (peer, message.into()))
                .collect(),
            immediate: immediate_len,
            context: Some(context),
            ready_after: Some(ready_after),
            ready_at: None,
        }
    }
}

impl Receiver for ReadyReceiver {
    type Error = Infallible;
    type PublicKey = Ed25519PublicKey;

    async fn recv(&mut self) -> Result<(Self::PublicKey, IoBuf), Self::Error> {
        if self.immediate > 0 {
            self.immediate -= 1;
            return Ok(self.messages.pop_front().expect("immediate message exists"));
        }
        if let Some(ready_after) = self.ready_after {
            let context = self.context.as_ref().expect("staged receiver has a clock");
            let ready_at = *self
                .ready_at
                .get_or_insert_with(|| context.current() + ready_after);
            context.sleep_until(ready_at).await;
            self.ready_after = None;
            self.ready_at = None;
        }
        match self.messages.pop_front() {
            Some(message) => Ok(message),
            None => pending().await,
        }
    }
}

struct ReadyHarness {
    mailbox: mailbox::Sender<Message<Ed25519PublicKey, MinPk, Sha256Digest>>,
    observations: mailbox::UnreliableReceiver<Observed<Ed25519PublicKey, MinPk, Sha256Digest>>,
    _completions: mailbox::Receiver<Completed<Sha256Digest>>,
}

impl ReadyHarness {
    fn start(
        context: &DeterministicContext,
        committee: &Committee<MinPk>,
        limits: IngressLimits,
        data: ReadyReceiver,
        consensus: ReadyReceiver,
        certificates: ReadyReceiver,
    ) -> Self {
        Self::start_with_observation_capacity(
            context,
            committee,
            limits,
            data,
            consensus,
            certificates,
            NonZeroUsize::new(8).unwrap(),
        )
    }

    fn start_with_observation_capacity(
        context: &DeterministicContext,
        committee: &Committee<MinPk>,
        limits: IngressLimits,
        data: ReadyReceiver,
        consensus: ReadyReceiver,
        certificates: ReadyReceiver,
        observation_capacity: NonZeroUsize,
    ) -> Self {
        let (actor, mailbox): (TestActor, _) = Actor::new(
            context.child("batcher"),
            Config {
                scheme: committee.verifier.clone(),
                blocker: RecordingBlocker::default(),
                strategy: Sequential,
                codec: committee.codec(),
                limits,
                mailbox_size: NonZeroUsize::new(16).unwrap(),
                observation_capacity,
            },
        );
        let (observation_sender, observations) =
            mailbox::new_unreliable(context.child("observations"), observation_capacity);
        let (completion_sender, completions) =
            mailbox::new(context.child("completions"), NonZeroUsize::new(8).unwrap());
        actor.start(
            observation_sender,
            completion_sender,
            data,
            consensus,
            certificates,
        );

        Self {
            mailbox,
            observations,
            _completions: completions,
        }
    }
}

#[test_traced]
fn stalled_decode_and_identification_workers_do_not_block_control() {
    for stall_at in [0, 1] {
        let executor = DeterministicRunner::timed(Duration::from_secs(1));
        executor.start(move |context| async move {
            let committee =
                Committee::<MinPk>::new(84 + stall_at as u64, 6, Limits::new(2, 1).unwrap());
            let epoch = committee.config.epoch();
            let strategy = StallingStrategy::new(stall_at);
            let calls = Arc::clone(&strategy.calls);
            let (actor, mailbox): (
                Actor<
                    DeterministicContext,
                    Sha256,
                    Ed25519PublicKey,
                    MinPk,
                    RecordingBlocker,
                    StallingStrategy,
                >,
                _,
            ) = Actor::new(
                context.child("batcher"),
                Config {
                    scheme: committee.verifier.clone(),
                    blocker: RecordingBlocker::default(),
                    strategy,
                    codec: committee.codec(),
                    limits: limits(),
                    mailbox_size: NonZeroUsize::new(4).unwrap(),
                    observation_capacity: NonZeroUsize::MIN,
                },
            );
            let (observation_sender, _observations) =
                mailbox::new_unreliable(context.child("observations"), NonZeroUsize::MIN);
            let (completion_sender, _completions) =
                mailbox::new(context.child("completions"), NonZeroUsize::MIN);
            let consensus = ReadyReceiver::new(vec![(
                committee.identities[1].clone(),
                Envelope::new(
                    epoch,
                    ConsensusMessage::<MinPk, Sha256Digest>::NoVote(committee.novote(1, 1)),
                )
                .encode(),
            )]);
            let mut task = actor.start(
                observation_sender,
                completion_sender,
                ReadyReceiver::new(Vec::new()),
                consensus,
                ReadyReceiver::new(Vec::new()),
            );

            while calls.load(Ordering::SeqCst) <= stall_at {
                context.sleep(Duration::from_millis(1)).await;
            }
            assert!(mailbox.enqueue(Message::ObservationConsumed).accepted());
            select! {
                result = &mut task => result.expect("batcher exits after servicing control"),
                _ = context.sleep(Duration::from_millis(10)) => {
                    panic!("stalled worker blocked the batcher control mailbox")
                },
            }
        });
    }
}

#[test_traced]
fn saturated_observation_handoff_preserves_admitted_certificate() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = limits();
        ingress_limits.cohort_items = NonZeroUsize::new(1).unwrap();
        let committee = Committee::<MinPk>::new(41, 6, Limits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let filler = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(committee.novote(1, 1));
        let certificate = committee.vqc(2);
        let consensus = ReadyReceiver::new(vec![(
            committee.identities[1].clone(),
            Envelope::new(epoch, filler).encode(),
        )]);
        let certificates = ReadyReceiver::staged(
            context.child("staged_certificates"),
            Duration::from_millis(1),
            Vec::new(),
            vec![(
                committee.identities[2].clone(),
                Envelope::new(epoch, CertificateMessage::Vqc(certificate.clone())).encode(),
            )],
        );
        let mut harness = ReadyHarness::start_with_observation_capacity(
            &context,
            &committee,
            ingress_limits,
            ReadyReceiver::new(Vec::new()),
            consensus,
            certificates,
            NonZeroUsize::new(1).unwrap(),
        );

        context.sleep(Duration::from_millis(5)).await;
        let metrics = context.encode();
        assert!(
            metrics
                .lines()
                .any(|line| line == "batcher_decoded_total{plane=\"Certificate\"} 1"),
            "certificate did not enter a bounded lane before credit returned: {metrics}"
        );
        let filler = harness
            .observations
            .recv()
            .await
            .expect("filler cohort was forwarded");
        assert!(matches!(&filler.artifacts[0].1.1, Artifact::NoVote(_)));
        assert!(
            harness
                .mailbox
                .enqueue(Message::ObservationConsumed)
                .accepted()
        );

        context.sleep(Duration::from_millis(5)).await;
        let preserved = harness
            .observations
            .try_recv()
            .expect("admitted certificate was preserved while the handoff was saturated");
        assert!(matches!(
            &preserved.artifacts[0].1.1,
            Artifact::Vqc(actual) if actual == &certificate
        ));
    });
}

#[test_traced]
fn byzantine_replay_saturation_preserves_correct_peer_service() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = limits();
        ingress_limits.cohort_items = NonZeroUsize::MIN;
        ingress_limits.lane_items = NonZeroUsize::new(4).unwrap();
        let committee = Committee::<MinPk>::new(86, 6, Limits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let replay = Envelope::new(
            epoch,
            ConsensusMessage::<MinPk, Sha256Digest>::NoVote(committee.novote(1, 1)),
        )
        .encode();
        let correct = Envelope::new(
            epoch,
            ConsensusMessage::<MinPk, Sha256Digest>::NoVote(committee.novote(2, 1)),
        )
        .encode();
        let consensus = (0..8)
            .map(|_| (committee.identities[1].clone(), replay.clone()))
            .chain([(committee.identities[2].clone(), correct)])
            .collect();
        let mut harness = ReadyHarness::start_with_observation_capacity(
            &context,
            &committee,
            ingress_limits,
            ReadyReceiver::new(Vec::new()),
            ReadyReceiver::new(consensus),
            ReadyReceiver::new(Vec::new()),
            NonZeroUsize::MIN,
        );

        context.sleep(Duration::from_millis(10)).await;
        let first = harness
            .observations
            .recv()
            .await
            .expect("the initial replay reached the bounded handoff");
        assert_eq!(first.artifacts[0].0, committee.identities[1]);
        assert!(
            harness
                .mailbox
                .enqueue(Message::ObservationConsumed)
                .accepted()
        );

        let mut served_correct = false;
        for _ in 0..2 {
            let cohort = harness
                .observations
                .recv()
                .await
                .expect("admitted peers remain serviceable");
            served_correct |= cohort.artifacts[0].0 == committee.identities[2];
            assert!(
                harness
                    .mailbox
                    .enqueue(Message::ObservationConsumed)
                    .accepted()
            );
        }
        assert!(
            served_correct,
            "one Byzantine identity delayed the correct peer beyond one f+1 rotation",
        );
    });
}

fn limits() -> IngressLimits {
    IngressLimits {
        cohort_items: NonZeroUsize::new(8).unwrap(),
        lane_items: NonZeroUsize::new(16).unwrap(),
        lane_bytes: NonZeroUsize::new(64 * 1024).unwrap(),
        inflight_jobs: NonZeroUsize::new(2).unwrap(),
        coalesce: Duration::ZERO,
    }
}

fn observer_profile(committee: &Committee<MinPk>) -> Profile<Sha256, MinPk> {
    Profile::new(
        committee.config.clone(),
        Role::Observer,
        Tuning {
            view_timeout: Duration::from_secs(1),
            production_interval: Duration::from_millis(100),
            ..Tuning::default()
        },
    )
    .unwrap()
}

struct Harness {
    committee: Committee<MinPk>,
    blocker: RecordingBlocker,
    mailbox: mailbox::Sender<Message<Ed25519PublicKey, MinPk, Sha256Digest>>,
    observations: mailbox::UnreliableReceiver<Observed<Ed25519PublicKey, MinPk, Sha256Digest>>,
    completions: mailbox::Receiver<Completed<Sha256Digest>>,
    peers: Vec<Ed25519PublicKey>,
    oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
    me: Ed25519PublicKey,
}

impl Harness {
    /// Starts a batcher for participant zero with every other participant linked to it.
    async fn new(context: &DeterministicContext, seed: u64) -> Self {
        Self::with_limits(context, seed, limits()).await
    }

    async fn with_limits(context: &DeterministicContext, seed: u64, limits: IngressLimits) -> Self {
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let me = committee.identities[0].clone();
        let peers = committee.identities.clone();
        let oracle = start_network(context, peers.clone(), 1024 * 1024).await;

        let mut receivers = Vec::new();
        for channel in 0..3u64 {
            let (_, receiver) = oracle
                .control(me.clone())
                .register(channel, QUOTA)
                .await
                .unwrap();
            receivers.push(receiver);
        }
        let mut receivers = receivers.into_iter();

        let blocker = RecordingBlocker::default();
        let (actor, mailbox): (TestActor, _) = Actor::new(
            context.child("batcher"),
            Config {
                scheme: committee.verifier.clone(),
                blocker: blocker.clone(),
                strategy: Sequential,
                codec: committee.codec(),
                limits,
                mailbox_size: NonZeroUsize::new(16).unwrap(),
                observation_capacity: NonZeroUsize::new(8).unwrap(),
            },
        );
        let (observation_sender, observations) =
            mailbox::new_unreliable(context.child("observations"), NonZeroUsize::new(8).unwrap());
        let (completion_sender, completions) =
            mailbox::new(context.child("completions"), NonZeroUsize::new(8).unwrap());
        actor.start(
            observation_sender,
            completion_sender,
            receivers.next().unwrap(),
            receivers.next().unwrap(),
            receivers.next().unwrap(),
        );

        Self {
            committee,
            blocker,
            mailbox,
            observations,
            completions,
            peers,
            oracle,
            me,
        }
    }

    /// Registers `peer` on `channel` and links it toward the batcher.
    async fn sender(
        &self,
        peer: usize,
        channel: u64,
    ) -> impl P2pSender<PublicKey = Ed25519PublicKey> + use<> {
        let peer = self.peers[peer].clone();
        let (sender, _) = self
            .oracle
            .control(peer.clone())
            .register(channel, QUOTA)
            .await
            .unwrap();
        self.oracle
            .add_link(
                peer,
                self.me.clone(),
                Link {
                    latency: Duration::from_millis(1),
                    jitter: Duration::ZERO,
                    success_rate: 1.0,
                },
            )
            .await
            .unwrap();
        sender
    }

    fn envelope<M>(&self, payload: M) -> Envelope<M> {
        Envelope::new(self.committee.config.epoch(), payload)
    }

    /// Collects forwarded artifacts until `count` have arrived.
    async fn observed(&mut self, count: usize) -> Vec<Artifact<MinPk, Sha256Digest>> {
        let mut artifacts = Vec::new();
        while artifacts.len() < count {
            let cohort = self
                .observations
                .recv()
                .await
                .expect("batcher stays running");
            for (_, (id, artifact)) in cohort.artifacts {
                assert_eq!(
                    id,
                    artifact.id::<Sha256>(),
                    "forwarded identifier matches its artifact"
                );
                artifacts.push(artifact);
            }
        }
        artifacts
    }
}

#[test_traced]
fn forwards_fair_cohorts_and_transaction_headers() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 31).await;
        let commitment = Sha256::hash(&[b"transaction"]);
        let block = harness.committee.signed_block(1, commitment);

        let mut data = harness.sender(1, 0).await;
        let mut consensus = harness.sender(2, 1).await;
        data.send(
            Recipients::One(harness.me.clone()),
            harness.envelope(DataMessage::Block(block.clone())).encode(),
            false,
        );
        consensus.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    harness.committee.novote(2, 1),
                ))
                .encode(),
            false,
        );

        let artifacts = harness.observed(2).await;
        assert!(
            artifacts
                .iter()
                .any(|artifact| matches!(artifact, Artifact::TransactionBlock(b) if b == &block))
        );
        assert!(
            artifacts
                .iter()
                .any(|artifact| matches!(artifact, Artifact::NoVote(_)))
        );

        let metrics = context.encode();
        assert!(
            metrics.lines().any(
                |line| line.contains("batcher_decoded_total{plane=\"Data\"}")
                    && line.ends_with(" 1")
            ),
            "data ingress was not counted by plane: {metrics}"
        );
        assert!(
            metrics.lines().any(
                |line| line.contains("batcher_decoded_total{plane=\"Consensus\"}")
                    && line.ends_with(" 1")
            ),
            "consensus ingress was not counted by plane: {metrics}"
        );

        assert!(harness.blocker.blocked().is_empty());
    });
}

#[test_traced]
fn continuously_ready_consensus_does_not_starve_other_planes() {
    const CONSENSUS_BACKLOG: u64 = 32;
    const SERVICE_BOUND: usize = 3;

    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = limits();
        ingress_limits.cohort_items = NonZeroUsize::new(1).unwrap();
        let committee = Committee::<MinPk>::new(39, 6, Limits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let consensus = (1..=CONSENSUS_BACKLOG)
            .map(|view| {
                let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    committee.novote(1, view),
                );
                (
                    committee.identities[1].clone(),
                    Envelope::new(epoch, message).encode(),
                )
            })
            .collect();
        let certificate = committee.vqc(1);
        let certificates = vec![(
            committee.identities[2].clone(),
            Envelope::new(epoch, CertificateMessage::Vqc(certificate.clone())).encode(),
        )];
        let block = committee.signed_block(3, Sha256::hash(&[b"data"]));
        let data = vec![(
            committee.identities[3].clone(),
            Envelope::new(epoch, DataMessage::Block(block.clone())).encode(),
        )];
        let mut harness = ReadyHarness::start(
            &context,
            &committee,
            ingress_limits,
            ReadyReceiver::new(data),
            ReadyReceiver::new(consensus),
            ReadyReceiver::new(certificates),
        );

        let mut artifacts = Vec::new();
        while artifacts.len() < SERVICE_BOUND {
            let cohort = harness
                .observations
                .recv()
                .await
                .expect("batcher stays running");
            artifacts.extend(
                cohort
                    .artifacts
                    .into_iter()
                    .map(|(_, (_, artifact))| artifact),
            );
        }
        assert!(
            artifacts
                .iter()
                .any(|artifact| matches!(artifact, Artifact::Vqc(actual) if actual == &certificate)),
            "certificate ingress exceeded the {SERVICE_BOUND}-selection service bound: {artifacts:?}",
        );
        assert!(
            artifacts.iter().any(
                |artifact| matches!(artifact, Artifact::TransactionBlock(actual) if actual == &block)
            ),
            "data ingress exceeded the {SERVICE_BOUND}-selection service bound: {artifacts:?}",
        );
    });
}

#[test_traced]
fn due_partial_cohort_flushes_during_continuous_ingress() {
    const CONSENSUS_BACKLOG: u64 = 32;
    const MAX_ITEMS_BEFORE_FLUSH: usize = 1;

    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = limits();
        ingress_limits.cohort_items = NonZeroUsize::new(64).unwrap();
        ingress_limits.lane_items = NonZeroUsize::new(64).unwrap();
        ingress_limits.coalesce = Duration::from_millis(5);
        let committee = Committee::<MinPk>::new(40, 6, Limits::new(2, 1).unwrap());
        let epoch = committee.config.epoch();
        let consensus = (1..=CONSENSUS_BACKLOG)
            .map(|view| {
                let message =
                    ConsensusMessage::<MinPk, Sha256Digest>::NoVote(committee.novote(1, view));
                (
                    committee.identities[1].clone(),
                    Envelope::new(epoch, message).encode(),
                )
            })
            .collect::<Vec<_>>();
        let consensus = ReadyReceiver::staged(
            context.child("staged_consensus"),
            ingress_limits.coalesce,
            consensus[..1].to_vec(),
            consensus[1..].to_vec(),
        );
        let mut harness = ReadyHarness::start(
            &context,
            &committee,
            ingress_limits,
            ReadyReceiver::new(Vec::new()),
            consensus,
            ReadyReceiver::new(Vec::new()),
        );

        let cohort = harness
            .observations
            .recv()
            .await
            .expect("batcher stays running");
        assert!(
            cohort.artifacts.len() <= MAX_ITEMS_BEFORE_FLUSH,
            "an actually due partial cohort admitted {} items while consensus remained ready",
            cohort.artifacts.len(),
        );
    });
}

#[test_traced]
fn blocks_peers_for_malformed_and_wrong_epoch_traffic() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 32).await;

        let mut malformed = harness.sender(1, 1).await;
        malformed.send(
            Recipients::One(harness.me.clone()),
            Bytes::from_static(b"garbage"),
            false,
        );

        let mut wrong_epoch = harness.sender(2, 1).await;
        let novote = harness.committee.novote(2, 1);
        wrong_epoch.send(
            Recipients::One(harness.me.clone()),
            Envelope::new(
                harness.committee.config.epoch().next(),
                ConsensusMessage::<MinPk, Sha256Digest>::NoVote(novote),
            )
            .encode(),
            false,
        );

        // Valid traffic from a third peer still flows after both rejections.
        let mut valid = harness.sender(3, 1).await;
        valid.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    harness.committee.novote(3, 1),
                ))
                .encode(),
            false,
        );

        let artifacts = harness.observed(1).await;
        assert!(matches!(&artifacts[0], Artifact::NoVote(vote) if vote.signer().get() == 3));

        let blocked = harness.blocker.blocked();
        assert_eq!(blocked.len(), 2);
        assert!(blocked.contains(&harness.peers[1]));
        assert!(blocked.contains(&harness.peers[2]));
    });
}

#[test_traced]
fn omitted_non_genesis_parent_forwards_the_leader_block() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 36).await;
        let mut consensus = harness.sender(1, 1).await;
        let parent = harness.committee.vqc(1);
        let block = harness.committee.leader_block_with_parent(2, &parent);

        consensus.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(ConsensusMessage::Proposal {
                    block: Box::new(block.clone()),
                    parent: None,
                })
                .encode(),
            false,
        );
        let artifacts = harness.observed(1).await;
        assert!(matches!(&artifacts[0], Artifact::LeaderBlock(actual) if actual == &block));
        assert!(harness.blocker.blocked().is_empty());
    });
}

#[test_traced]
fn mismatched_exact_parent_forwards_no_artifacts() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 37).await;
        let mut consensus = harness.sender(1, 1).await;
        let attached = harness.committee.vqc(1);
        let referenced = harness.committee.vqc(2);
        let block = harness.committee.leader_block_with_parent(3, &referenced);

        consensus.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(ConsensusMessage::Proposal {
                    block: Box::new(block),
                    parent: Some(Box::new(attached)),
                })
                .encode(),
            false,
        );
        context.sleep(Duration::from_millis(10)).await;

        let mut artifacts = Vec::new();
        while let Ok(cohort) = harness.observations.try_recv() {
            artifacts.extend(
                cohort
                    .artifacts
                    .into_iter()
                    .map(|(_, (_, artifact))| artifact),
            );
        }
        assert!(
            artifacts.is_empty(),
            "a proposal with the wrong exact parent forwarded artifacts: {artifacts:?}",
        );
        assert_eq!(harness.blocker.blocked(), vec![harness.peers[1].clone()]);
    });
}

#[test_traced]
fn exact_proposal_capacity_rejection_forwards_neither_artifact() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = limits();
        ingress_limits.lane_items = NonZeroUsize::new(1).unwrap();
        let mut harness = Harness::with_limits(&context, 38, ingress_limits).await;
        let mut consensus = harness.sender(1, 1).await;
        let parent = harness.committee.vqc(1);
        let block = harness.committee.leader_block_with_parent(2, &parent);

        consensus.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(ConsensusMessage::Proposal {
                    block: Box::new(block),
                    parent: Some(Box::new(parent)),
                })
                .encode(),
            false,
        );
        context.sleep(Duration::from_millis(10)).await;

        let mut artifacts = Vec::new();
        while let Ok(cohort) = harness.observations.try_recv() {
            artifacts.extend(
                cohort
                    .artifacts
                    .into_iter()
                    .map(|(_, (_, artifact))| artifact),
            );
        }
        assert!(
            artifacts.is_empty(),
            "a partially admitted exact proposal forwarded artifacts: {artifacts:?}",
        );
        assert!(harness.blocker.blocked().is_empty());
    });
}

#[test_traced]
fn executes_machine_issued_jobs_with_exact_tickets() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 33).await;
        let committee = &harness.committee;

        let good_block = committee.signed_block(0, Sha256::hash(&[b"good"]));
        let header = good_block.header().clone();
        let forged = SignedTransactionBlock::new(
            committee.transaction_header(0, Sha256::hash(&[b"forged"])),
            good_block.attestation().clone(),
        );
        let artifacts = vec![
            Artifact::TransactionBlock(good_block),
            Artifact::DaVote(committee.da_vote(1, header)),
            Artifact::NoVote(committee.novote(2, 1)),
            Artifact::TransactionBlock(forged),
        ];
        let identified = artifacts
            .into_iter()
            .map(|artifact| {
                let id = artifact.id::<Sha256>();
                (id, artifact)
            })
            .collect::<Vec<_>>();
        let resident_bytes = identified
            .iter()
            .map(|(id, artifact)| id.encode_size() + artifact.encode_size())
            .sum();

        // Drive the production Core boundary until it issues the exact verification job.
        let mut core = CoreState::fresh(observer_profile(committee), NonZeroUsize::MIN).unwrap();
        core.start_fresh().unwrap();
        let mut observed = Some((identified, resident_bytes));
        let mut jobs: Vec<VerifyJob<MinPk, Sha256Digest>> = Vec::new();
        loop {
            let capabilities = match core.next_action(NonZeroUsize::MIN).unwrap() {
                CoreTurn::Input(serviced) => serviced.transition.into_parts().0,
                CoreTurn::Work(work) => work.into_parts().0,
                CoreTurn::YieldRequired => {
                    core.resume_after_yield().unwrap();
                    continue;
                }
                CoreTurn::Idle if !jobs.is_empty() => break,
                CoreTurn::Idle => panic!("Core idled before issuing verification"),
            };
            for effect in capabilities {
                match effect {
                    Capability::Durability(DurabilityCapability::Persist(job)) => {
                        core.persistence_completed(BarrierAck::new(
                            job.id(),
                            job.generation(),
                            job.last_cursor(),
                        ))
                        .unwrap();
                    }
                    Capability::Verification(VerificationCapability::Verify(job)) => {
                        jobs.push(job);
                    }
                    _ => {}
                }
            }
            if core.inspection().is_live()
                && let Some((identified, resident_bytes)) = observed.take()
            {
                core.observe(identified, resident_bytes).unwrap();
            }
        }
        assert!(!jobs.is_empty(), "observation schedules verification");

        let expected = jobs.iter().map(|job| job.items().len()).sum::<usize>();
        for job in jobs {
            let sources = vec![None; job.items().len()];
            assert!(
                harness
                    .mailbox
                    .enqueue(Message::Verify {
                        span: Span::none(),
                        round: Round::new(Epoch::new(33), View::new(1)),
                        job,
                        sources,
                    })
                    .accepted()
            );
        }

        let mut valid = 0;
        let mut invalid = 0;
        let mut items = 0;
        while items < expected {
            let Completed { completion, .. } =
                harness.completions.recv().await.expect("batcher running");
            items += completion.verdicts().len();
            core.verification_completed(completion).unwrap();
            let status = loop {
                match core.next_action(NonZeroUsize::MIN).unwrap() {
                    CoreTurn::Input(serviced) => break serviced.transition.status().clone(),
                    CoreTurn::Work(_) => {}
                    CoreTurn::YieldRequired => core.resume_after_yield().unwrap(),
                    CoreTurn::Idle => panic!("Core idled before accepting verification"),
                }
            };
            let StepStatus::Verified {
                valid: step_valid,
                invalid: step_invalid,
            } = status
            else {
                panic!("verification completion was not accepted: {status:?}");
            };
            valid += step_valid;
            invalid += step_invalid;
        }
        assert_eq!(valid, 3);
        assert_eq!(invalid, 1);
        assert!(
            harness.blocker.blocked().is_empty(),
            "a source-free verification job blocked a network peer"
        );
        let signer = &committee.identities[2];
        let expected = format!("batcher_latest_verified_vote{{peer=\"{signer}\"}} 1");
        assert!(
            context.encode().lines().any(|line| line == expected),
            "a valid novote did not advance its embedded signer's verified view"
        );
    });
}

#[test_traced]
fn saturated_observation_handoff_preserves_bounded_ingress() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 35).await;
        let mut consensus = harness.sender(1, 1).await;

        // Without consumption credits, the batcher keeps bounded ingress in its lanes instead of
        // destructively flushing more cohorts into a saturated handoff.
        for view in 1..=200u64 {
            consensus.send(
                Recipients::One(harness.me.clone()),
                harness
                    .envelope(ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                        harness.committee.novote(1, view),
                    ))
                    .encode(),
                false,
            );
        }
        context.sleep(Duration::from_millis(100)).await;
        let metrics = context.encode();
        assert!(
            metrics
                .lines()
                .any(|line| line == "batcher_dropped_voter_cohorts_total 0"),
            "handoff saturation dropped an admitted cohort: {metrics}"
        );
        assert!(
            metrics
                .lines()
                .any(|line| line == "batcher_decoded_total{plane=\"Consensus\"} 200"),
            "bounded lane admission stopped with the observation handoff: {metrics}"
        );

        let first = harness
            .observations
            .recv()
            .await
            .expect("the observation mailbox was filled");
        assert!(!first.artifacts.is_empty());
        assert!(
            harness
                .mailbox
                .enqueue(Message::ObservationConsumed)
                .accepted()
        );
        let next = harness
            .observations
            .recv()
            .await
            .expect("a consumption credit resumed cohort delivery");
        assert!(!next.artifacts.is_empty());
    });
}

#[test_traced]
fn stops_cleanly_with_the_runtime() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 34).await;
        let mut consensus = harness.sender(1, 1).await;
        consensus.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    harness.committee.novote(1, 1),
                ))
                .encode(),
            false,
        );
        let _ = harness.observed(1).await;
        context.stop(0, None).await.unwrap();
    });
}
