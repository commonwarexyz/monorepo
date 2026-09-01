//! Shared voter test harness: engine and network setup, trace capture, and publication waits.

use crate::{
    Epochable as _,
    multimmit::{
        Config as EngineConfig,
        actors::{
            ingress::IngressLimits,
            resolver::{self, Message as ResolverControl, ResolveRequest},
            util::reliable_policy,
            voter::{
                Actor, Flusher, Inspector, Mailbox, Planes, Resolutions, VoterLimits,
                actor::{TestDurableAttempt, TestHooks},
            },
        },
        config::{Profile, Role, Tuning},
        engine::{ActorLimits, Overrides, derive_profile, wire_actors},
        machine::{DurableEffect, EffectId, Inspection, testing::EffectExt},
        mocks::{
            Committee, MockApplication, RecordingBlocker, RecordingRelay, RecordingReporter,
            cluster::{QUOTA, start_network},
        },
        storage::{RecoveryConfig, recover},
        testing::SpanRecorder,
        types::{
            Artifact, ChainId, DaCertificate, DaVote, SignedTransactionBlock,
            TransactionBlockHeader,
        },
        wire::{DataMessage, Envelope, EnvelopeConfig},
    },
    types::{Attributable as _, Height, Participant},
};
use commonware_actor::mailbox;
use commonware_codec::Decode as _;
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, ed25519::PublicKey as Ed25519PublicKey,
    sha256::Digest as Sha256Digest,
};
use commonware_macros::select;
use commonware_p2p::{
    Receiver as P2pReceiver, Sender as P2pSender,
    simulated::{Link, Oracle},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Spawner as _, Supervisor as _,
    buffer::paged::{self, CacheRef},
    deterministic::Context as DeterministicContext,
    mocks::{DelayedSyncContext, PendingSyncs},
    telemetry::metrics::count_running_tasks,
};
use commonware_utils::{NZU64, NZUsize, channel::oneshot, probability};
use std::{collections::BTreeMap, num::NonZeroUsize, time::Duration};

pub(super) type TestRelay = RecordingRelay<Sha256Digest, Ed25519PublicKey>;

pub(super) type TestReporter = RecordingReporter<MinPk, Sha256Digest>;

/// A resolve request the scripted resolver forwarded to the test.
pub(super) struct Requested(pub(super) ResolveRequest);

reliable_policy!(impl for Requested);

/// Asserts that every event carrying a `test_root` field was emitted under that exact root span.
pub(super) fn assert_test_roots(recorder: &SpanRecorder) {
    for event in recorder.events() {
        let Some((_, root)) = event
            .fields
            .fields
            .iter()
            .find(|(name, _)| name == "test_root")
        else {
            continue;
        };
        let root: u64 = root.parse().unwrap();
        assert_ne!(root, 0, "the input retains an enabled terminal-error root");
        assert_eq!(
            event.root,
            Some(root),
            "terminal errors and work share the exact root identity"
        );
    }
}

/// The application doubles, voter hooks, and storage syncs one test node runs with.
pub(super) struct Attachments {
    /// The automaton the voter builds and verifies with.
    pub(super) application: MockApplication,
    /// The relay the voter announces staged blocks to.
    pub(super) relay: TestRelay,
    /// The reporter the voter sends activity to.
    pub(super) reporter: TestReporter,
    /// Hooks that observe the voter's typed boundaries and gate its journal.
    pub(super) hooks: TestHooks<MinPk, Sha256Digest>,
    /// Durability syncs of the node's storage; released at once unless a test holds them.
    pub(super) checkpoint_syncs: PendingSyncs,
}

impl Default for Attachments {
    fn default() -> Self {
        let checkpoint_syncs = PendingSyncs::default();
        checkpoint_syncs.unblock();
        Self {
            application: MockApplication::default(),
            relay: TestRelay::default(),
            reporter: TestReporter::default(),
            hooks: TestHooks::default(),
            checkpoint_syncs,
        }
    }
}

pub(super) fn da_certificate(
    committee: &Committee<MinPk>,
    header: &TransactionBlockHeader<Sha256Digest>,
) -> DaCertificate<MinPk, Sha256Digest> {
    let votes = (0..committee.codec().da_quorum())
        .map(|signer| committee.da_vote(Participant::from_usize(signer), header.clone()))
        .collect::<Vec<_>>();
    committee
        .verifier
        .assemble_da_certificate(&votes, &Sequential)
        .expect("a quorum of shares recovers the supplied header certificate")
}

pub(super) fn tuning() -> Tuning {
    Tuning {
        production_interval: Duration::from_millis(100),
        ..Tuning::new(Duration::from_millis(500))
    }
}

pub(super) fn profile(committee: &Committee<MinPk>, role: Role) -> Profile<Sha256Digest> {
    Profile::new::<MinPk>(committee.config.clone(), role, tuning()).unwrap()
}

/// The voter policy test nodes run with: fast publication retries, no heartbeat or early
/// timeouts, and no checkpoints unless a test asks for them.
pub(super) fn voter_limits() -> VoterLimits {
    VoterLimits {
        retry_initial: Duration::from_millis(100),
        retry_ceiling: Duration::from_millis(400),
        heartbeat: Duration::from_secs(3600),
        checkpoint_interval: NZU64!(1_000_000),
        skip_timeout: None,
        view_cohort_items: IngressLimits::VIEW_COHORT_ITEMS,
    }
}

/// The committee, network, and identity a node joins.
struct Network {
    committee: Committee<MinPk>,
    oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
    index: usize,
}

/// A limit override applied on top of the engine's derived actor limits.
type LimitsOverride = Box<dyn FnOnce(&mut ActorLimits)>;

/// Builds one attached test node: recovered storage, then the engine's actor wiring over it.
///
/// A node runs the ingress, verifier, and voter actors of an engine with the test's hooks. Its
/// resolver is scripted unless [`Self::production_resolver`] is set: the scripted resolver
/// forwards every resolve request to [`Node::resolver`] and serves nothing.
pub(super) struct NodeBuilder {
    seed: u64,
    role: Role,
    instance: &'static str,
    attachments: Attachments,
    network: Option<Network>,
    production_resolver: bool,
    limits: Vec<LimitsOverride>,
}

impl NodeBuilder {
    /// Builds a node that runs as `role` with participant zero's identity in a fresh six-node
    /// committee derived from `seed`, storing under `node_{seed}` and labelled `instance`.
    pub(super) fn new(seed: u64, role: Role, instance: &'static str) -> Self {
        Self {
            seed,
            role,
            instance,
            attachments: Attachments::default(),
            network: None,
            production_resolver: false,
            limits: Vec::new(),
        }
    }

    /// Runs the node with `attachments`.
    pub(super) fn attachments(mut self, attachments: Attachments) -> Self {
        self.attachments = attachments;
        self
    }

    /// Overrides actor limits after the test defaults: the engine's derived limits with the
    /// [`voter_limits`] voter policy.
    pub(super) fn limits(mut self, limits: impl FnOnce(&mut ActorLimits) + 'static) -> Self {
        self.limits.push(Box::new(limits));
        self
    }

    /// Joins `committee`'s existing network as the participant at `index`.
    pub(super) fn network(
        mut self,
        committee: Committee<MinPk>,
        oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
        index: usize,
    ) -> Self {
        self.network = Some(Network {
            committee,
            oracle,
            index,
        });
        self
    }

    /// Runs the production resolver over the fourth plane instead of the scripted one.
    pub(super) const fn production_resolver(mut self) -> Self {
        self.production_resolver = true;
        self
    }

    /// Starts the node and waits until its voter is ready.
    pub(super) async fn start(self, context: &DeterministicContext) -> Node {
        let (node, ready) = self.start_pending(context).await;
        ready.await.expect("voter becomes ready");
        node
    }

    /// Starts the node and returns it with the receiver that resolves once its voter is ready.
    pub(super) async fn start_pending(
        self,
        context: &DeterministicContext,
    ) -> (Node, oneshot::Receiver<()>) {
        Box::pin(self.launch(context)).await
    }

    async fn launch(self, context: &DeterministicContext) -> (Node, oneshot::Receiver<()>) {
        let Self {
            seed,
            role,
            instance,
            attachments,
            network,
            production_resolver,
            limits: overrides,
        } = self;
        let Network {
            committee,
            oracle,
            index,
        } = match network {
            Some(network) => network,
            None => {
                let committee = Committee::<MinPk>::builder(seed, 6).build();
                let oracle =
                    start_network(context, committee.identities.clone(), 1024 * 1024).await;
                Network {
                    committee,
                    oracle,
                    index: 0,
                }
            }
        };
        let me = committee.identities[index].clone();
        let Attachments {
            application,
            relay,
            reporter,
            hooks,
            checkpoint_syncs,
        } = attachments;
        let context = context.child(instance);
        let task_prefix = context.name().label;
        let mut planes = Vec::new();
        for channel in 0..3u64 {
            planes.push(
                oracle
                    .control(me.clone())
                    .register(channel, QUOTA)
                    .await
                    .unwrap(),
            );
        }
        let [data, consensus, certificates] =
            <[_; 3]>::try_from(planes).unwrap_or_else(|_| panic!("three planes"));
        let resolver_controls_context = context.child("resolver_controls");
        let resolver_requests_context = context.child("resolver_requests");
        let scripted_resolver_context = context.child("scripted_resolver");
        let unused_resolver_context = context.child("unused_resolver");
        let root = DelayedSyncContext {
            inner: context,
            pending: checkpoint_syncs,
        };

        let blocker = RecordingBlocker::default();
        let config = EngineConfig {
            scheme: match role {
                Role::Validator(participant) => {
                    committee.signers[participant.get() as usize].clone()
                }
                Role::Observer => committee.verifier.clone(),
            },
            genesis: committee.config.genesis().clone(),
            tuning: tuning(),
            automaton: application,
            relay,
            reporter,
            strategy: Sequential,
            critical_strategy: Sequential,
            blocker: blocker.clone(),
            partition_prefix: format!("node_{seed}"),
            page_cache: CacheRef::from_pooler(&root, paged::page_size(4_096), NZUsize!(8)),
            mailbox_size: NonZeroUsize::new(64).unwrap(),
        };
        let profile: Profile<Sha256Digest> =
            derive_profile(&config).expect("test configuration is valid");
        let mut limits = ActorLimits::from_profile::<MinPk, _>(&profile, Overrides::default());
        limits.voter = voter_limits();
        for override_limits in overrides {
            override_limits(&mut limits);
        }

        // Durable recovery, application custody, and any due compaction all complete before an
        // actor exists or can accept ingress.
        let mut store_context = root.child("stores");
        let recovered = Box::pin(recover::<_, Sha256, _, _, _, _>(
            &mut store_context,
            RecoveryConfig {
                profile: profile.clone(),
                partition_prefix: &config.partition_prefix,
                scheme: &config.scheme,
                strategy: &Sequential,
                page_cache: config.page_cache.clone(),
                checkpoint_interval: limits.voter.checkpoint_interval,
                inflight_application: NZUsize!(4),
            },
            &config.automaton,
        ))
        .await
        .expect("durable state recovers");

        let actors = wire_actors(
            &root,
            config,
            &profile,
            recovered,
            limits,
            |context, queues, config| Actor::new_with_hooks(context, queues, config, hooks),
        );
        let voter_mailbox = actors.voter_mailbox.clone();
        let flusher = actors.voter.flusher();
        let endpoints = actors.voter_mailbox.into_endpoints();
        let ingress_task = actors.ingress.start(
            actors.verifier,
            endpoints.completions,
            endpoints.observations,
            data.1,
            consensus.1,
            certificates.1,
        );
        let (resolver_mailbox, resolver_receiver, resolver_task) = if production_resolver {
            let network = oracle.control(me.clone()).register(3, QUOTA).await.unwrap();
            let resolver_task = actors.resolver.start(endpoints.resolutions, network);
            let (_, unused) =
                mailbox::new::<Requested>(unused_resolver_context, NonZeroUsize::new(4).unwrap());
            (actors.resolver_mailbox, unused, resolver_task)
        } else {
            // The scripted resolver serves nothing, so its query queue has no receiver.
            let (queries, _) = mailbox::new_unreliable(
                resolver_controls_context.child("queries"),
                NonZeroUsize::MIN,
            );
            let (resolver_sender, mut controls) =
                mailbox::new(resolver_controls_context, NonZeroUsize::new(64).unwrap());
            let (requests, resolver_receiver) =
                mailbox::new(resolver_requests_context, NonZeroUsize::new(64).unwrap());
            let resolver_task = scripted_resolver_context.spawn(move |_| async move {
                while let Some(message) = controls.recv().await {
                    match message {
                        ResolverControl::Resolve(request) => {
                            if !requests.enqueue(Requested(request)).accepted() {
                                break;
                            }
                        }
                        ResolverControl::Cancel { .. }
                        | ResolverControl::Reject { .. }
                        | ResolverControl::Retain { .. }
                        | ResolverControl::Prune { .. } => {}
                    }
                }
            });
            (
                resolver::Mailbox::new(resolver_sender, queries),
                resolver_receiver,
                resolver_task,
            )
        };
        let (ready_sender, ready_receiver) = oneshot::channel();
        let voter_task = actors.voter.start(
            ready_sender,
            Planes {
                data: data.0,
                consensus: consensus.0,
                certificates: certificates.0,
            },
            actors.ingress_mailbox,
            actors.verifier_mailbox,
            resolver_mailbox,
        );
        (
            Node {
                committee,
                blocker,
                voter: voter_mailbox,
                flusher,
                resolver: resolver_receiver,
                oracle,
                me,
                task_prefix,
                tasks: vec![ingress_task, voter_task, resolver_task],
            },
            ready_receiver,
        )
    }
}

/// One attached node: its committee, network identity, and running actors.
pub(super) struct Node {
    pub(super) committee: Committee<MinPk>,
    pub(super) blocker: RecordingBlocker,
    voter: Mailbox<Ed25519PublicKey, MinPk, Sha256Digest>,
    /// Demands durability for every append the voter's persistence actor admitted.
    pub(super) flusher: Flusher,
    /// Resolve requests the scripted resolver forwarded; never receives with the production
    /// resolver.
    pub(super) resolver: mailbox::Receiver<Requested>,
    oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
    pub(super) me: Ed25519PublicKey,
    task_prefix: String,
    pub(super) tasks: Vec<Handle<()>>,
}

impl Node {
    /// Registers `peer` on `channel`, linked in both directions with the node.
    pub(super) async fn peer(
        &self,
        peer: usize,
        channel: u64,
    ) -> (
        impl P2pSender<PublicKey = Ed25519PublicKey> + use<>,
        impl P2pReceiver<PublicKey = Ed25519PublicKey> + use<>,
    ) {
        let peer = self.committee.identities[peer].clone();
        let (sender, receiver) = self
            .oracle
            .control(peer.clone())
            .register(channel, QUOTA)
            .await
            .unwrap();
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::ZERO,
            success_rate: probability!(1.0),
        };
        let _ = self
            .oracle
            .add_link(peer.clone(), self.me.clone(), link.clone())
            .await;
        let _ = self.oracle.add_link(self.me.clone(), peer, link).await;
        (sender, receiver)
    }

    pub(super) fn envelope<M>(&self, payload: M) -> Envelope<M> {
        Envelope::new(self.committee.config.epoch(), payload)
    }

    pub(super) fn envelope_cfg<C>(&self, payload: C) -> EnvelopeConfig<C> {
        EnvelopeConfig {
            max_frame_bytes: usize::MAX,
            epoch: self.committee.config.epoch(),
            payload,
        }
    }

    /// Reads the machine's current normalized projection.
    pub(super) async fn inspect(&mut self) -> Inspection<Sha256Digest> {
        self.inspector().inspect().await.expect("voter responds")
    }

    /// Returns a handle that reads the voter's diagnostic projection.
    pub(super) fn inspector(&self) -> Inspector<Sha256Digest> {
        self.voter.clone().into_endpoints().inspector
    }

    /// Returns the endpoint that delivers resolution completions to the voter.
    pub(super) fn resolutions(&self) -> Resolutions<MinPk, Sha256Digest> {
        self.voter.clone().into_endpoints().resolutions
    }

    pub(super) async fn crash(self, context: &DeterministicContext) {
        assert!(
            count_running_tasks(context, &self.task_prefix) > 0,
            "node has no running tasks before its crash cut"
        );
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
            "node tasks remained after the crash cut"
        );
    }
}

/// Receives data-plane messages until one decodes to a transaction block.
pub(super) async fn next_block(
    node: &Node,
    receiver: &mut impl P2pReceiver<PublicKey = Ed25519PublicKey>,
) -> TransactionBlockHeader<Sha256Digest> {
    loop {
        let (_, bytes) = receiver.recv().await.expect("network stays up");
        let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
            bytes,
            &node.envelope_cfg(node.committee.codec()),
        )
        .expect("node emits canonical envelopes");
        if let DataMessage::Block(header) = envelope.into_payload() {
            return header.header().clone();
        }
    }
}

pub(super) type DurableLedger = BTreeMap<EffectId, Vec<TestDurableAttempt<MinPk, Sha256Digest>>>;

#[derive(Default)]
pub(super) struct ExposureLedger {
    pub(super) blocks:
        BTreeMap<(ChainId, Height, Participant), SignedTransactionBlock<MinPk, Sha256Digest>>,
    votes: BTreeMap<(ChainId, Height, Participant), DaVote<MinPk, Sha256Digest>>,
}

impl ExposureLedger {
    pub(super) fn record(&mut self, node: &Node, message: DataMessage<MinPk, Sha256Digest>) {
        match message {
            DataMessage::Block(block) => {
                assert!(node.committee.verifier.verify_transaction_block(&block));
                let key = (
                    block.header().chain(),
                    block.header().height(),
                    block.signer(),
                );
                if let Some(previous) = self.blocks.insert(key, block.clone()) {
                    assert_eq!(previous, block, "one signing slot exposed two blocks");
                }
            }
            DataMessage::DaVote(vote) => {
                assert!(node.committee.verifier.verify_da_vote(&vote));
                let key = (vote.header().chain(), vote.header().height(), vote.signer());
                if let Some(previous) = self.votes.insert(key, vote.clone()) {
                    assert_eq!(previous, vote, "one signing slot exposed two DA votes");
                }
            }
            DataMessage::DaCertificate(certificate) => {
                assert!(node.committee.verifier.verify_da_certificate(&certificate));
            }
        }
    }

    pub(super) fn block(
        &self,
        chain: ChainId,
        height: Height,
        signer: Participant,
    ) -> Option<&SignedTransactionBlock<MinPk, Sha256Digest>> {
        self.blocks.get(&(chain, height, signer))
    }
}

pub(super) async fn wait_for_slot_block(
    context: &DeterministicContext,
    node: &Node,
    receiver: &mut impl P2pReceiver<PublicKey = Ed25519PublicKey>,
    exposure: &mut ExposureLedger,
    chain: ChainId,
    height: Height,
    signer: Participant,
) -> SignedTransactionBlock<MinPk, Sha256Digest> {
    let deadline = context.current() + Duration::from_secs(1);
    loop {
        select! {
            result = receiver.recv() => {
                let (_, bytes) = result.expect("network stays up");
                let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                    bytes,
                    &node.envelope_cfg(node.committee.codec()),
                )
                .expect("canonical envelope");
                exposure.record(node, envelope.into_payload());
                if let Some(block) = exposure.block(chain, height, signer) {
                    return block.clone();
                }
            },
            () = context.sleep_until(deadline) => {
                panic!("the signed block was not exposed on the data plane");
            },
        }
    }
}

pub(super) fn slot_publications(
    ledger: &DurableLedger,
    chain: ChainId,
    height: Height,
) -> DurableLedger {
    ledger
        .iter()
        .filter(|(_, attempts)| {
            attempts.iter().any(|attempt| {
                matches!(
                    &attempt.effect.broadcast_one(),
                    Some(artifact)
                        if matches!(artifact.as_ref(), Artifact::TransactionBlock(block)
                            if block.header().chain() == chain && block.header().height() == height)
                )
            })
        })
        .map(|(id, attempts)| (*id, attempts.clone()))
        .collect()
}

pub(super) fn da_certificate_publications(ledger: &DurableLedger) -> DurableLedger {
    ledger
        .iter()
        .filter(|(_, attempts)| {
            attempts.iter().any(|attempt| {
                matches!(
                    &attempt.effect.broadcast_one(),
                    Some(artifact)
                        if matches!(artifact.as_ref(), Artifact::DaCertificate(_))
                )
            })
        })
        .map(|(id, attempts)| (*id, attempts.clone()))
        .collect()
}

pub(super) async fn wait_for_da_certificate(
    context: &DeterministicContext,
    node: &Node,
    receiver: &mut impl P2pReceiver<PublicKey = Ed25519PublicKey>,
    expected: &TransactionBlockHeader<Sha256Digest>,
) {
    let deadline = context.current() + Duration::from_secs(1);
    loop {
        select! {
            result = receiver.recv() => {
                let (_, bytes) = result.expect("network stays up");
                let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                    bytes,
                    &node.envelope_cfg(node.committee.codec()),
                )
                .expect("canonical data envelope");
                let DataMessage::DaCertificate(certificate) = envelope.into_payload() else {
                    continue;
                };
                assert!(
                    node.committee.verifier.verify_da_certificate(&certificate),
                    "the observed DA successor is cryptographically invalid"
                );
                if certificate.header() == expected {
                    return;
                }
            },
            () = context.sleep_until(deadline) => {
                panic!("the exact DA successor was not exposed on the data plane");
            },
        }
    }
}

pub(super) async fn wait_for_live_publication(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    mut matches: impl FnMut(&DurableEffect<MinPk, Sha256Digest>) -> bool,
) -> (EffectId, TestDurableAttempt<MinPk, Sha256Digest>) {
    let deadline = context.current() + Duration::from_secs(2);
    loop {
        let live = hooks.live_publications();
        for (id, attempts) in hooks.durable_effects() {
            let Some(attempt) = attempts.last() else {
                continue;
            };
            if live.contains(&id) && matches(&attempt.effect) {
                return (id, attempt.clone());
            }
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(deadline) => {
                panic!("the expected publication was not installed: {:?}", hooks.events());
            },
        }
    }
}
