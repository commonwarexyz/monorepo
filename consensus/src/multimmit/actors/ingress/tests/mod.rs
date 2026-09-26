//! Deterministic ingress tests over the simulated network.

use super::{Actor, Config, IngressLimits, Mailbox};
use crate::{
    Epochable as _,
    multimmit::{
        actors::{
            verifier,
            voter::{self, Endpoints, Inbox, Observed},
        },
        mocks::{
            Committee,
            cluster::{QUOTA, start_network},
        },
        testing::expect_within,
        types::{Artifact, ChainId, DaVote},
        wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, Plane},
    },
    types::{Attributable as _, Participant, View},
};
use bytes::Bytes;
use commonware_actor::mailbox;
use commonware_codec::Encode as _;
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    ed25519::PublicKey as Ed25519PublicKey, sha256::Digest as Sha256Digest,
};
use commonware_macros::test_traced;
use commonware_p2p::{
    Receiver, Recipients, Sender as P2pSender,
    simulated::{Link, Oracle},
};
use commonware_parallel::{Rayon, Sequential, Strategy, mocks};
use commonware_runtime::{
    Clock as _, IoBuf, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
    deterministic::{Context as DeterministicContext, Runner as DeterministicRunner},
    telemetry::metrics::metric_sum,
};
use commonware_utils::probability;
use futures::FutureExt as _;
use std::{
    collections::VecDeque,
    convert::Infallible,
    fmt,
    future::pending,
    num::NonZeroUsize,
    sync::Arc,
    time::{Duration, SystemTime},
};

mod unit;

type TestActor<T, C> = Actor<DeterministicContext, Sha256, Ed25519PublicKey, MinPk, T, C>;

/// Builds an ingress configuration for `committee`'s epoch.
fn config<T, C>(
    committee: &Committee<MinPk>,
    limits: IngressLimits,
    strategy: T,
    critical_strategy: C,
    mailbox_size: NonZeroUsize,
    observation_capacity: NonZeroUsize,
) -> Config<Ed25519PublicKey, T, C> {
    Config {
        epoch: committee.config.epoch(),
        participants: Arc::new(committee.verifier.participants().clone()),
        strategy,
        critical_strategy,
        codec: committee.codec(),
        bounds: committee
            .codec()
            .encoded_bounds::<MinPk, Sha256Digest>()
            .unwrap(),
        limits,
        mailbox_size,
        observation_capacity,
    }
}

type TestVerifier<T, C> =
    verifier::Verifier<DeterministicContext, Sha256, Ed25519PublicKey, MinPk, T, C>;

/// Builds the verifier that shares the ingress task.
///
/// The task stops when the verifier's mailbox closes, so callers keep the mailbox.
fn verifier<T: Strategy, C: Strategy>(
    context: &DeterministicContext,
    committee: &Committee<MinPk>,
    strategy: T,
    critical_strategy: C,
) -> (TestVerifier<T, C>, verifier::Mailbox<MinPk, Sha256Digest>) {
    verifier::Verifier::new(
        context.child("batcher"),
        verifier::Config {
            scheme: committee.verifier.clone(),
            strategy,
            critical_strategy,
            inflight_jobs: NonZeroUsize::new(4).unwrap(),
            mailbox_size: NonZeroUsize::new(4).unwrap(),
        },
    )
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
    mailbox: Mailbox,
    observations: mailbox::UnreliableReceiver<Observed<Ed25519PublicKey, MinPk, Sha256Digest>>,
    _verifier: verifier::Mailbox<MinPk, Sha256Digest>,
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
        let (actor, mailbox): (TestActor<Sequential, Sequential>, _) = Actor::new(
            context.child("batcher"),
            config(
                committee,
                limits,
                Sequential,
                Sequential,
                NonZeroUsize::new(16).unwrap(),
                observation_capacity,
            ),
        );
        let voter_context = context.child("voter");
        let (voter, Inbox { observations, .. }) =
            voter::Mailbox::new(&voter_context, context, observation_capacity);
        let (verifier, verifier_mailbox) = verifier(context, committee, Sequential, Sequential);
        let endpoints = voter.into_endpoints();
        actor.start(
            verifier,
            endpoints.completions,
            endpoints.observations,
            data,
            consensus,
            certificates,
        );

        Self {
            mailbox,
            observations,
            _verifier: verifier_mailbox,
        }
    }
}

#[test_traced]
fn stalled_ingress_worker_does_not_block_control() {
    let executor = DeterministicRunner::timed(Duration::from_secs(1));
    executor.start(move |context| async move {
        let committee = Committee::<MinPk>::builder(84, 6).build();
        let epoch = committee.config.epoch();
        // The pool's workers never start, so the frame's decode job never returns.
        let strategy = mocks::pending(NonZeroUsize::new(2).unwrap());
        let (actor, mailbox): (TestActor<Rayon, Rayon>, _) = Actor::new(
            context.child("batcher"),
            config(
                &committee,
                IngressLimits::TEST,
                strategy.clone(),
                strategy.clone(),
                NonZeroUsize::new(4).unwrap(),
                NonZeroUsize::MIN,
            ),
        );
        let voter_context = context.child("voter");
        let (voter, _inbox) = voter::Mailbox::new(&voter_context, &context, NonZeroUsize::MIN);
        let Endpoints {
            observations,
            completions,
            ..
        } = voter.into_endpoints();
        let (verifier, _verifier_mailbox) =
            verifier(&context, &committee, strategy.clone(), strategy);
        let consensus = ReadyReceiver::new(vec![(
            committee.identities[1].clone(),
            Envelope::new(
                epoch,
                ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    committee.novote(Participant::new(1), View::new(1)),
                ),
            )
            .encode(),
        )]);
        let mut task = actor.start(
            verifier,
            completions,
            observations,
            ReadyReceiver::new(Vec::new()),
            consensus,
            ReadyReceiver::new(Vec::new()),
        );

        // Let the actor take the frame and hand its decode to the stalled pool.
        context.sleep(Duration::from_millis(1)).await;
        // One credit more than the cohorts in flight is fatal, so servicing it stops the actor.
        assert!(mailbox.consumed(1).accepted());
        expect_within(
            &context,
            Duration::from_millis(10),
            &mut task,
            "stalled worker blocked the ingress control mailbox",
        )
        .await
        .expect("ingress exits after servicing control");
    });
}

#[test_traced]
fn saturated_observation_handoff_preserves_admitted_certificate() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = IngressLimits::TEST;
        ingress_limits.cohort_items = NonZeroUsize::new(1).unwrap();
        let committee = Committee::<MinPk>::builder(41, 6).build();
        let epoch = committee.config.epoch();
        let filler = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
            committee.novote(Participant::new(1), View::new(1)),
        );
        let certificate = committee.vqc(View::new(2));
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
        assert!(matches!(
            &filler.artifacts[0].1.artifact,
            Artifact::NoVote(_)
        ));
        assert!(harness.mailbox.consumed(1).accepted());

        context.sleep(Duration::from_millis(5)).await;
        let preserved = harness
            .observations
            .try_recv()
            .expect("admitted certificate was preserved while the handoff was saturated");
        assert!(matches!(
            &preserved.artifacts[0].1.artifact,
            Artifact::Vqc(actual) if actual == &certificate
        ));
    });
}

#[test_traced]
fn byzantine_replay_saturation_preserves_correct_peer_service() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = IngressLimits::TEST;
        ingress_limits.cohort_items = NonZeroUsize::MIN;
        ingress_limits.lane_items = NonZeroUsize::new(4).unwrap();
        let committee = Committee::<MinPk>::builder(86, 6).build();
        let epoch = committee.config.epoch();
        let replay = Envelope::new(
            epoch,
            ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                committee.novote(Participant::new(1), View::new(1)),
            ),
        )
        .encode();
        let correct = Envelope::new(
            epoch,
            ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                committee.novote(Participant::new(2), View::new(1)),
            ),
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
        assert!(harness.mailbox.consumed(1).accepted());

        let mut served_correct = false;
        for _ in 0..2 {
            let cohort = harness
                .observations
                .recv()
                .await
                .expect("admitted peers remain serviceable");
            served_correct |= cohort.artifacts[0].0 == committee.identities[2];
            assert!(harness.mailbox.consumed(1).accepted());
        }
        assert!(
            served_correct,
            "one Byzantine identity delayed the correct peer beyond one f+1 rotation",
        );
    });
}

struct Harness {
    committee: Committee<MinPk>,
    mailbox: Mailbox,
    observations: mailbox::UnreliableReceiver<Observed<Ed25519PublicKey, MinPk, Sha256Digest>>,
    peers: Vec<Ed25519PublicKey>,
    oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
    me: Ed25519PublicKey,
    _verifier: verifier::Mailbox<MinPk, Sha256Digest>,
}

impl Harness {
    /// Starts an ingress actor for participant zero with every other participant linked to it.
    async fn new(context: &DeterministicContext, seed: u64) -> Self {
        Self::with_limits(context, seed, IngressLimits::TEST).await
    }

    async fn with_limits(context: &DeterministicContext, seed: u64, limits: IngressLimits) -> Self {
        let committee = Committee::<MinPk>::builder(seed, 6).build();
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

        let (actor, mailbox): (TestActor<Sequential, Sequential>, _) = Actor::new(
            context.child("batcher"),
            config(
                &committee,
                limits,
                Sequential,
                Sequential,
                NonZeroUsize::new(16).unwrap(),
                NonZeroUsize::new(8).unwrap(),
            ),
        );
        let voter_context = context.child("voter");
        let (voter, Inbox { observations, .. }) =
            voter::Mailbox::new(&voter_context, context, NonZeroUsize::new(8).unwrap());
        let (verifier, verifier_mailbox) = verifier(context, &committee, Sequential, Sequential);
        let endpoints = voter.into_endpoints();
        actor.start(
            verifier,
            endpoints.completions,
            endpoints.observations,
            receivers.next().unwrap(),
            receivers.next().unwrap(),
            receivers.next().unwrap(),
        );

        Self {
            committee,
            mailbox,
            observations,
            peers,
            oracle,
            me,
            _verifier: verifier_mailbox,
        }
    }

    /// Registers `peer` on `channel` and links it toward the ingress actor.
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
                    success_rate: probability!(1.0),
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
                .expect("ingress stays running");
            for (_, identified) in cohort.artifacts {
                let artifact = identified.artifact;
                let id = identified.id;
                assert_eq!(
                    identified.provisions.as_slice(),
                    artifact.provisions::<Sha256>()
                );
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
fn a_da_vote_is_dropped_unless_its_sender_is_its_signer() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let committee = Committee::<MinPk>::builder(87, 6).build();
        let epoch = committee.config.epoch();
        let signer = 3usize;
        let header =
            committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"da vote header"]));
        let vote = committee.da_vote(Participant::from_usize(signer), header.clone());
        // Another peer first sends a vote naming the signer, carrying share bytes signed over a
        // different header, then the signer sends its own vote.
        let elsewhere =
            committee.transaction_header(ChainId::new(0), Sha256::hash(&[b"another header"]));
        let misattributed = DaVote::new(
            header,
            committee
                .da_vote(Participant::from_usize(signer), elsewhere)
                .share()
                .clone(),
        );
        let data = vec![
            (
                committee.identities[1].clone(),
                Envelope::new(epoch, DataMessage::DaVote(misattributed)).encode(),
            ),
            (
                committee.identities[signer].clone(),
                Envelope::new(epoch, DataMessage::DaVote(vote.clone())).encode(),
            ),
        ];
        let mut harness = ReadyHarness::start(
            &context,
            &committee,
            IngressLimits::TEST,
            ReadyReceiver::new(data),
            ReadyReceiver::new(Vec::new()),
            ReadyReceiver::new(Vec::new()),
        );

        let cohort = harness
            .observations
            .recv()
            .await
            .expect("the signer's own share is admitted");
        assert!(harness.mailbox.consumed(1).accepted());
        assert_eq!(
            cohort.artifacts.len(),
            1,
            "the misattributed share was dropped"
        );
        let (peer, identified) = &cohort.artifacts[0];
        assert_eq!(*peer, committee.identities[signer]);
        assert!(
            matches!(&identified.artifact, Artifact::DaVote(admitted) if admitted == &vote),
            "the admitted artifact is the signer's own share",
        );

        let metrics = context.encode();
        assert_eq!(
            metric_sum(&metrics, "batcher_dropped_misattributed_total", &[]),
            1.0,
            "the misattributed share was not counted: {metrics}"
        );
    });
}

#[test_traced]
fn forwards_fair_cohorts_and_transaction_headers() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 31).await;
        let commitment = Sha256::hash(&[b"transaction"]);
        let block = harness.committee.signed_block(ChainId::new(1), commitment);

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
                    harness.committee.novote(Participant::new(2), View::new(1)),
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
        assert_eq!(
            metric_sum(&metrics, "batcher_decoded_total", &[("plane", "Data")]),
            1.0,
            "data ingress was not counted by plane: {metrics}"
        );
        assert_eq!(
            metric_sum(&metrics, "batcher_decoded_total", &[("plane", "Consensus")]),
            1.0,
            "consensus ingress was not counted by plane: {metrics}"
        );
    });
}

#[test_traced]
fn continuously_ready_consensus_does_not_starve_other_planes() {
    const CONSENSUS_BACKLOG: u64 = 32;
    const SERVICE_BOUND: usize = 3;

    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = IngressLimits::TEST;
        ingress_limits.cohort_items = NonZeroUsize::new(1).unwrap();
        let committee = Committee::<MinPk>::builder(39, 6).build();
        let epoch = committee.config.epoch();
        let consensus = (1..=CONSENSUS_BACKLOG)
            .map(|view| {
                let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    committee.novote(Participant::new(1), View::new(view)),
                );
                (
                    committee.identities[1].clone(),
                    Envelope::new(epoch, message).encode(),
                )
            })
            .collect();
        let certificate = committee.vqc(View::new(1));
        let certificates = vec![(
            committee.identities[2].clone(),
            Envelope::new(epoch, CertificateMessage::Vqc(certificate.clone())).encode(),
        )];
        let block = committee.signed_block(ChainId::new(3), Sha256::hash(&[b"data"]));
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
                .expect("ingress stays running");
            artifacts.extend(
                cohort
                    .artifacts
                    .into_iter()
                    .map(|(_, identified)| identified.artifact),
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
fn partial_cohorts_flush_as_soon_as_credit_allows() {
    const CONSENSUS_BACKLOG: u64 = 32;
    const MAX_ITEMS_BEFORE_FLUSH: usize = 1;

    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = IngressLimits::TEST;
        ingress_limits.cohort_items = NonZeroUsize::new(64).unwrap();
        ingress_limits.lane_items = NonZeroUsize::new(64).unwrap();
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let epoch = committee.config.epoch();
        let consensus = (1..=CONSENSUS_BACKLOG)
            .map(|view| {
                let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    committee.novote(Participant::new(1), View::new(view)),
                );
                (
                    committee.identities[1].clone(),
                    Envelope::new(epoch, message).encode(),
                )
            })
            .collect::<Vec<_>>();
        let consensus = ReadyReceiver::staged(
            context.child("staged_consensus"),
            Duration::from_millis(5),
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
            .expect("ingress stays running");
        assert!(
            cohort.artifacts.len() <= MAX_ITEMS_BEFORE_FLUSH,
            "a partial cohort waited for later ingress and admitted {} items",
            cohort.artifacts.len(),
        );
    });
}

#[test_traced]
fn a_lone_data_artifact_is_forwarded_without_further_ingress() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = IngressLimits::TEST;
        ingress_limits.cohort_items = NonZeroUsize::new(64).unwrap();
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let epoch = committee.config.epoch();
        let block = committee.signed_block(ChainId::new(3), Sha256::hash(&[b"lone data"]));
        let data = vec![(
            committee.identities[3].clone(),
            Envelope::new(epoch, DataMessage::Block(block)).encode(),
        )];
        let mut harness = ReadyHarness::start(
            &context,
            &committee,
            ingress_limits,
            ReadyReceiver::new(data),
            ReadyReceiver::new(Vec::new()),
            ReadyReceiver::new(Vec::new()),
        );

        // Nothing else ever arrives, so the runtime would deadlock if the lone artifact waited
        // for the cohort budget or a timer.
        let cohort = harness
            .observations
            .recv()
            .await
            .expect("ingress stays running");
        assert_eq!(cohort.artifacts.len(), 1);
    });
}

#[test_traced]
fn ingress_batches_into_full_cohorts_while_credit_is_held() {
    const CONSENSUS_BACKLOG: u64 = 32;

    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = IngressLimits::TEST;
        ingress_limits.cohort_items = NonZeroUsize::new(64).unwrap();
        ingress_limits.lane_items = NonZeroUsize::new(64).unwrap();
        let committee = Committee::<MinPk>::builder(40, 6).build();
        let epoch = committee.config.epoch();
        let consensus = (1..=CONSENSUS_BACKLOG)
            .map(|view| {
                let message = ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                    committee.novote(Participant::new(1), View::new(view)),
                );
                (
                    committee.identities[1].clone(),
                    Envelope::new(epoch, message).encode(),
                )
            })
            .collect::<Vec<_>>();
        let mut harness = ReadyHarness::start_with_observation_capacity(
            &context,
            &committee,
            ingress_limits,
            ReadyReceiver::new(Vec::new()),
            ReadyReceiver::new(consensus),
            ReadyReceiver::new(Vec::new()),
            NonZeroUsize::new(1).unwrap(),
        );

        let first = harness
            .observations
            .recv()
            .await
            .expect("ingress stays running");
        assert_eq!(first.artifacts.len(), 1, "the first arrival flushed alone");

        // Every later arrival lands while the single credit is held, so it batches in the lanes.
        context.sleep(Duration::from_secs(1)).await;
        assert!(
            harness.observations.try_recv().is_err(),
            "a cohort was forwarded without credit"
        );
        assert!(harness.mailbox.consumed(1).accepted());
        let batched = harness
            .observations
            .recv()
            .await
            .expect("ingress stays running");
        assert_eq!(
            batched.artifacts.len(),
            ingress_limits.view_cohort_items.get(),
            "the held backlog did not leave as a full view cohort",
        );
        assert_eq!(batched.plane, Plane::Consensus);
    });
}

#[test_traced]
fn rejects_malformed_and_wrong_epoch_traffic_without_blocking() {
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
        let novote = harness.committee.novote(Participant::new(2), View::new(1));
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
                    harness.committee.novote(Participant::new(3), View::new(1)),
                ))
                .encode(),
            false,
        );

        let artifacts = harness.observed(1).await;
        assert!(matches!(&artifacts[0], Artifact::NoVote(vote) if vote.signer().get() == 3));
    });
}

#[test_traced]
fn omitted_non_genesis_parent_forwards_the_leader_block() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 36).await;
        let mut consensus = harness.sender(1, 1).await;
        let parent = harness.committee.vqc(View::new(1));
        let block = harness
            .committee
            .leader_block_with_parent(View::new(2), &parent);

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
    });
}

#[test_traced]
fn mismatched_exact_parent_forwards_no_artifacts() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 37).await;
        let mut consensus = harness.sender(1, 1).await;
        let attached = harness.committee.vqc(View::new(1));
        let referenced = harness.committee.vqc(View::new(2));
        let block = harness
            .committee
            .leader_block_with_parent(View::new(3), &referenced);

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
                    .map(|(_, identified)| identified.artifact),
            );
        }
        assert!(
            artifacts.is_empty(),
            "a proposal with the wrong exact parent forwarded artifacts: {artifacts:?}",
        );
    });
}

#[test_traced]
fn exact_proposal_capacity_rejection_forwards_neither_artifact() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress_limits = IngressLimits::TEST;
        ingress_limits.lane_items = NonZeroUsize::new(1).unwrap();
        let mut harness = Harness::with_limits(&context, 38, ingress_limits).await;
        let mut consensus = harness.sender(1, 1).await;
        let parent = harness.committee.vqc(View::new(1));
        let block = harness
            .committee
            .leader_block_with_parent(View::new(2), &parent);

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
                    .map(|(_, identified)| identified.artifact),
            );
        }
        assert!(
            artifacts.is_empty(),
            "a partially admitted exact proposal forwarded artifacts: {artifacts:?}",
        );
    });
}

#[test_traced]
fn a_relayed_da_vote_is_dropped_without_blocking_its_sender() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 51).await;
        let header = harness
            .committee
            .transaction_header(ChainId::new(0), Sha256::hash(&[b"relayed share"]));

        // Peer two relays a share participant three signed. Honest votes are sent only by their
        // signer, so the relayed share is dropped rather than admitted.
        let mut relay = harness.sender(2, 0).await;
        relay.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(DataMessage::DaVote(
                    harness
                        .committee
                        .da_vote(Participant::new(3), header.clone()),
                ))
                .encode(),
            false,
        );

        // The relaying peer is not blocked: its own share is still admitted.
        relay.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(DataMessage::DaVote(
                    harness.committee.da_vote(Participant::new(2), header.clone()),
                ))
                .encode(),
            false,
        );

        // The signer's own copy is admitted.
        let mut owner = harness.sender(3, 0).await;
        owner.send(
            Recipients::One(harness.me.clone()),
            harness
                .envelope(DataMessage::DaVote(
                    harness.committee.da_vote(Participant::new(3), header),
                ))
                .encode(),
            false,
        );

        let artifacts = harness.observed(2).await;
        assert_eq!(
            artifacts
                .iter()
                .filter(|artifact| matches!(artifact, Artifact::DaVote(vote) if vote.signer().get() == 3))
                .count(),
            1,
            "only the signer's own share is admitted",
        );
        assert!(
            artifacts
                .iter()
                .any(|artifact| matches!(artifact, Artifact::DaVote(vote) if vote.signer().get() == 2)),
            "the relaying peer's own share is still serviced",
        );

        let metrics = context.encode();
        assert_eq!(
            metric_sum(&metrics, "batcher_dropped_misattributed_total", &[]),
            1.0,
            "the relayed share was not counted as misattributed: {metrics}"
        );
    });
}

#[test_traced]
fn saturated_observation_handoff_preserves_bounded_ingress() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut harness = Harness::new(&context, 35).await;
        let mut consensus = harness.sender(1, 1).await;

        // Without consumption credits, ingress keeps bounded traffic in its lanes instead of
        // destructively flushing more cohorts into a saturated handoff.
        for view in 1..=200u64 {
            consensus.send(
                Recipients::One(harness.me.clone()),
                harness
                    .envelope(ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                        harness
                            .committee
                            .novote(Participant::new(1), View::new(view)),
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

        let first = harness.observations.recv().await.unwrap();
        assert!(!first.artifacts.is_empty());
        assert!(harness.mailbox.consumed(1).accepted());
        let next = harness.observations.recv().await.unwrap();
        assert!(!next.artifacts.is_empty());
    });
}

#[test_traced]
fn consumption_credit_releases_multiple_cohorts() {
    DeterministicRunner::default().start(|context| async move {
        let mut harness = Harness::new(&context, 36).await;
        let mut consensus = harness.sender(1, 1).await;
        for round in 0..2 {
            for offset in 1..=8 {
                consensus.send(
                    Recipients::One(harness.me.clone()),
                    harness
                        .envelope(ConsensusMessage::<MinPk, Sha256Digest>::NoVote(
                            harness
                                .committee
                                .novote(Participant::new(1), View::new(round * 8 + offset)),
                        ))
                        .encode(),
                    false,
                );
                let cohort = harness.observations.recv().await.unwrap();
                assert_eq!(cohort.artifacts.len(), 1);
            }
            assert!(harness.observations.recv().now_or_never().is_none());
            assert!(harness.mailbox.consumed(8).accepted());
        }
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
                    harness.committee.novote(Participant::new(1), View::new(1)),
                ))
                .encode(),
            false,
        );
        let _ = harness.observed(1).await;
        context.stop(0, None).await.unwrap();
    });
}
