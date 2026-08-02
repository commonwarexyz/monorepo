//! Deterministic voter tests over the simulated network with real cryptography.

use super::{
    Actor, Config, Message, Query, Startup, VoterLimits,
    actor::{
        POLL_BUDGET, RetentionBoundary, TestDurableAttempt, TestEvent, TestHooks, round_span,
        round_timeout_span,
    },
    journal::{JournalPoint, TestGates},
};
use crate::{
    Viewable as _,
    multimmit::{
        actors::{
            batcher::{self, Actor as Batcher, IngressLimits},
            resolver::{self, Actor as Resolver, Message as ResolverControl, ResolveRequest},
            wire::{CertificateMessage, ConsensusMessage, DataMessage, Envelope, EnvelopeConfig},
        },
        config::Limits,
        engine::{
            Config as EngineConfig, Engine, compact_recovery_suffix, open_stores,
            verify_recovered_payloads,
        },
        machine::{
            Artifact, BarrierAck, Capability, CoreState, CoreTurn, Cursor, DaVoteRequest,
            DurabilityCapability, DurableEffect, EffectId, Inspection, LeaderCapability,
            LqcAggregateCompletion, Profile, ResolutionCompletion, ResolutionJob, Role,
            SendRequest, SignRequest, Tuning, VerificationCapability, ViewProof,
            VqcAggregateCompletion, contracts::Lane,
        },
        mocks::{
            Committee, MockApplication, MockBuildGate, NoopBlocker, RecordingBlocker,
            RecordingRelay, RecordingReporter,
            cluster::{QUOTA, start_network},
        },
        types::{
            Activity, ChainId, Context, DaVote, SignedTransactionBlock, TransactionBlockHeader,
            ViewMessage,
        },
    },
    types::{Attributable as _, Epoch, Height, Participant, Round, View},
};
use commonware_actor::{Feedback, mailbox};
use commonware_codec::{Decode as _, Encode as _, EncodeSize as _};
use commonware_cryptography::{
    Hasher as _, Sha256, bls12381::primitives::variant::MinPk,
    ed25519::PublicKey as Ed25519PublicKey, sha256::Digest as Sha256Digest,
};
use commonware_macros::{select, test_collect_traces, test_traced};
use commonware_p2p::{
    Receiver as P2pReceiver, Recipients, Sender as P2pSender,
    simulated::{Link, Oracle},
};
use commonware_parallel::Sequential;
use commonware_runtime::{
    Clock as _, Handle, Metrics as _, Runner as _, Spawner as _, Storage as _, Supervisor as _,
    deterministic::{Context as DeterministicContext, FaultConfig, Runner as DeterministicRunner},
    mocks::{DeferredSync, DelayedSyncContext, PendingSyncs, next_pending_sync},
    telemetry::{metrics::count_running_tasks, traces::collector::TraceStorage},
    utils::reschedule,
};
use commonware_utils::{NZU64, channel::oneshot, sync::Mutex};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    num::NonZeroUsize,
    sync::Arc,
    time::Duration,
};
use tracing::Level;
use tracing_subscriber::layer::SubscriberExt as _;

type TestBatcher =
    Batcher<DeterministicContext, Sha256, Ed25519PublicKey, MinPk, RecordingBlocker, Sequential>;
type TestRelay = RecordingRelay<Sha256Digest, Ed25519PublicKey>;
type TestReporter = RecordingReporter<MinPk, Sha256Digest>;

#[test_traced]
fn inspection_overflow_does_not_retain_queries() {
    DeterministicRunner::default().start(|context| async move {
        let (sender, _queries): (mailbox::UnreliableSender<Query<Sha256Digest>>, _) =
            mailbox::new_unreliable(context.child("inspection_queries"), NonZeroUsize::MIN);
        let (first, _first_response) = oneshot::channel();
        assert!(
            sender
                .enqueue(Query::Inspect { responder: first })
                .accepted()
        );

        let (overflow, overflow_response) = oneshot::channel();
        assert!(
            sender
                .enqueue(Query::Inspect {
                    responder: overflow,
                })
                .is_rejected()
        );
        assert!(overflow_response.await.is_err());
    });
}

impl commonware_actor::mailbox::Policy for ResolveRequest {
    type Overflow = VecDeque<Self>;

    fn handle(overflow: &mut Self::Overflow, message: Self) {
        overflow.push_back(message);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TraceFieldKind {
    I64,
    Other,
}

struct TraceFieldVisitor<'a> {
    fields: &'a mut BTreeMap<String, TraceFieldKind>,
}

impl tracing::field::Visit for TraceFieldVisitor<'_> {
    fn record_i64(&mut self, field: &tracing::field::Field, _: i64) {
        self.fields
            .insert(field.name().to_string(), TraceFieldKind::I64);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, _: u64) {
        self.fields
            .insert(field.name().to_string(), TraceFieldKind::Other);
    }

    fn record_str(&mut self, field: &tracing::field::Field, _: &str) {
        self.fields
            .insert(field.name().to_string(), TraceFieldKind::Other);
    }

    fn record_debug(&mut self, field: &tracing::field::Field, _: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), TraceFieldKind::Other);
    }
}

struct TraceFieldLayer {
    spans: Arc<Mutex<BTreeMap<String, BTreeMap<String, TraceFieldKind>>>>,
}

impl<S> tracing_subscriber::Layer<S> for TraceFieldLayer
where
    S: tracing::Subscriber,
{
    fn on_new_span(
        &self,
        attributes: &tracing::span::Attributes<'_>,
        _: &tracing::span::Id,
        _: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let name = attributes.metadata().name();
        if !matches!(
            name,
            "multimmit.voter.round" | "multimmit.voter.round.timeout"
        ) {
            return;
        }
        let mut fields = BTreeMap::new();
        attributes.record(&mut TraceFieldVisitor {
            fields: &mut fields,
        });
        self.spans.lock().insert(name.to_string(), fields);
    }
}

struct Attachments {
    application: MockApplication,
    relay: TestRelay,
    reporter: TestReporter,
    ingress: Option<IngressLimits>,
    journal_gates: Option<TestGates>,
    test_hooks: Option<TestHooks<MinPk, Sha256Digest>>,
    production_resolver: bool,
    checkpoint_syncs: PendingSyncs,
}

impl Default for Attachments {
    fn default() -> Self {
        let checkpoint_syncs = PendingSyncs::default();
        checkpoint_syncs.unblock();
        Self {
            application: MockApplication::default(),
            relay: TestRelay::default(),
            reporter: TestReporter::default(),
            ingress: None,
            journal_gates: None,
            test_hooks: None,
            production_resolver: false,
            checkpoint_syncs,
        }
    }
}

fn profile(committee: &Committee<MinPk>, role: Role) -> Profile<Sha256, MinPk> {
    Profile::new(
        committee.config.clone(),
        role,
        Tuning {
            view_timeout: Duration::from_millis(500),
            production_interval: Duration::from_millis(100),
            ..Tuning::default()
        },
    )
    .unwrap()
}

fn ingress_limits() -> IngressLimits {
    IngressLimits {
        cohort_items: NonZeroUsize::new(8).unwrap(),
        lane_items: NonZeroUsize::new(32).unwrap(),
        lane_bytes: NonZeroUsize::new(256 * 1024).unwrap(),
        inflight_jobs: NonZeroUsize::new(4).unwrap(),
        coalesce: Duration::ZERO,
    }
}

fn voter_limits() -> VoterLimits {
    VoterLimits {
        inflight_application: NonZeroUsize::new(4).unwrap(),
        retry_initial: Duration::from_millis(100),
        retry_ceiling: Duration::from_millis(400),
        heartbeat: Duration::from_secs(3600),
        checkpoint_interval: NZU64!(1_000_000),
    }
}

fn metric_sample(encoded: &str, name: &str) -> f64 {
    encoded
        .lines()
        .find_map(|line| {
            let (sample, value) = line.rsplit_once(' ')?;
            (sample == name).then(|| value.parse().unwrap())
        })
        .unwrap_or_else(|| panic!("missing metric sample {name}: {encoded}"))
}

fn histogram_percentile_bound(encoded: &str, name: &str, percent: f64) -> f64 {
    let count_name = name.replace("_bucket", "_count");
    let rank = (metric_sample(encoded, &count_name) * percent / 100.0).ceil();
    encoded
        .lines()
        .filter_map(|line| {
            let (sample, value) = line.rsplit_once(' ')?;
            if !sample.starts_with(name) || value.parse::<f64>().ok()? < rank {
                return None;
            }
            let upper_bound = sample.split("le=\"").nth(1)?.split('"').next()?;
            (upper_bound != "+Inf").then(|| upper_bound.parse().expect("finite histogram bound"))
        })
        .next()
        .unwrap_or(f64::INFINITY)
}

struct Node {
    committee: Committee<MinPk>,
    blocker: RecordingBlocker,
    _voter_control: mailbox::Sender<Message<MinPk, Sha256Digest>>,
    voter: mailbox::UnreliableSender<Query<Sha256Digest>>,
    resolver: mailbox::Receiver<ResolveRequest>,
    oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
    me: Ed25519PublicKey,
    task_prefix: String,
    tasks: Vec<Handle<()>>,
}

impl Node {
    /// Starts one attached node (batcher + voter) as `role` for participant zero's identity.
    async fn start(
        context: &DeterministicContext,
        seed: u64,
        role: Role,
        instance: &'static str,
    ) -> Self {
        Self::start_with_attachments(context, seed, role, instance, Attachments::default()).await
    }

    /// Starts one attached node with configurable test attachments.
    async fn start_with_attachments(
        context: &DeterministicContext,
        seed: u64,
        role: Role,
        instance: &'static str,
        attachments: Attachments,
    ) -> Self {
        Self::start_with_limits(context, seed, role, instance, attachments, voter_limits()).await
    }

    async fn start_with_limits(
        context: &DeterministicContext,
        seed: u64,
        role: Role,
        instance: &'static str,
        attachments: Attachments,
        limits: VoterLimits,
    ) -> Self {
        let production_resolver = attachments.production_resolver;
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let profile = profile(&committee, role);
        let me = committee.identities[0].clone();
        let oracle = start_network(context, committee.identities.clone(), 1024 * 1024).await;

        Box::pin(Self::attach(
            context,
            committee,
            profile,
            role,
            oracle,
            me,
            seed,
            instance,
            production_resolver,
            attachments,
            limits,
        ))
        .await
    }

    async fn start_pending_with_limits(
        context: &DeterministicContext,
        seed: u64,
        role: Role,
        instance: &'static str,
        attachments: Attachments,
        limits: VoterLimits,
    ) -> (Self, oneshot::Receiver<()>) {
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let profile = profile(&committee, role);
        let me = committee.identities[0].clone();
        let oracle = start_network(context, committee.identities.clone(), 1024 * 1024).await;

        Box::pin(Self::attach_pending(
            context,
            committee,
            profile,
            role,
            oracle,
            me,
            seed,
            instance,
            false,
            attachments,
            limits,
        ))
        .await
    }
    /// Starts one validator whose first application build is held by a one-shot gate.
    async fn start_gated_build(
        context: &DeterministicContext,
        seed: u64,
        instance: &'static str,
    ) -> (Self, MockBuildGate) {
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let role = Role::Validator(Participant::new(0));
        let profile = profile(&committee, role);
        let (application, gate) = MockApplication::with_gated_build();
        let me = committee.identities[0].clone();
        let oracle = start_network(context, committee.identities.clone(), 1024 * 1024).await;
        let node = Box::pin(Self::attach(
            context,
            committee,
            profile,
            role,
            oracle,
            me,
            seed,
            instance,
            false,
            Attachments {
                application,
                ..Attachments::default()
            },
            voter_limits(),
        ))
        .await;
        (node, gate)
    }

    /// Starts one validator whose first remote verification is held by a one-shot gate.
    async fn start_gated_verification(
        context: &DeterministicContext,
        seed: u64,
        instance: &'static str,
    ) -> (Self, MockBuildGate) {
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let role = Role::Validator(Participant::new(0));
        let profile = profile(&committee, role);
        let (application, gate) = MockApplication::with_gated_verify();
        let me = committee.identities[0].clone();
        let oracle = start_network(context, committee.identities.clone(), 1024 * 1024).await;
        let limits = VoterLimits {
            inflight_application: NonZeroUsize::new(1).unwrap(),
            ..voter_limits()
        };
        let node = Box::pin(Self::attach(
            context,
            committee,
            profile,
            role,
            oracle,
            me,
            seed,
            instance,
            false,
            Attachments {
                application,
                ..Attachments::default()
            },
            limits,
        ))
        .await;
        (node, gate)
    }

    /// Starts one attached node that attempts a checkpoint after every acknowledged event.
    async fn start_checkpointing(
        context: &DeterministicContext,
        seed: u64,
        instance: &'static str,
    ) -> Self {
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let role = Role::Validator(Participant::new(0));
        let profile = profile(&committee, role);
        let me = committee.identities[0].clone();
        let oracle = start_network(context, committee.identities.clone(), 1024 * 1024).await;
        let limits = VoterLimits {
            checkpoint_interval: NZU64!(1),
            ..voter_limits()
        };
        Box::pin(Self::attach(
            context,
            committee,
            profile,
            role,
            oracle,
            me,
            seed,
            instance,
            false,
            Attachments::default(),
            limits,
        ))
        .await
    }

    /// Starts one attached node with the production resolver on a shared network.
    #[allow(clippy::too_many_arguments)]
    async fn start_full(
        context: &DeterministicContext,
        committee: Committee<MinPk>,
        oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
        index: usize,
        role: Role,
        instance: &'static str,
        prefix: u64,
    ) -> Self {
        let profile = profile(&committee, role);
        let me = committee.identities[index].clone();
        Box::pin(Self::attach(
            context,
            committee,
            profile,
            role,
            oracle,
            me,
            prefix,
            instance,
            true,
            Attachments::default(),
            voter_limits(),
        ))
        .await
    }

    /// Attaches batcher and voter over an existing network and storage prefix.
    #[allow(clippy::too_many_arguments)]
    async fn attach(
        context: &DeterministicContext,
        committee: Committee<MinPk>,
        profile: Profile<Sha256, MinPk>,
        role: Role,
        oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
        me: Ed25519PublicKey,
        seed: u64,
        instance: &'static str,
        production_resolver: bool,
        attachments: Attachments,
        limits: VoterLimits,
    ) -> Self {
        let (node, ready) = Box::pin(Self::attach_pending(
            context,
            committee,
            profile,
            role,
            oracle,
            me,
            seed,
            instance,
            production_resolver,
            attachments,
            limits,
        ))
        .await;
        ready.await.expect("voter becomes ready");
        node
    }

    #[allow(clippy::too_many_arguments)]
    async fn attach_pending(
        context: &DeterministicContext,
        committee: Committee<MinPk>,
        profile: Profile<Sha256, MinPk>,
        role: Role,
        oracle: Oracle<Ed25519PublicKey, DeterministicContext>,
        me: Ed25519PublicKey,
        seed: u64,
        instance: &'static str,
        production_resolver: bool,
        attachments: Attachments,
        limits: VoterLimits,
    ) -> (Self, oneshot::Receiver<()>) {
        let Attachments {
            application,
            relay,
            reporter,
            ingress,
            journal_gates,
            test_hooks,
            production_resolver: _,
            checkpoint_syncs,
        } = attachments;
        let context = context.child(instance);
        let task_prefix = context.name().label;
        let mut plane_senders = Vec::new();
        let mut plane_receivers = Vec::new();
        for channel in 0..3u64 {
            let (sender, receiver) = oracle
                .control(me.clone())
                .register(channel, QUOTA)
                .await
                .unwrap();
            plane_senders.push(sender);
            plane_receivers.push(receiver);
        }
        let mut plane_receivers = plane_receivers.into_iter();
        let mut plane_senders = plane_senders.into_iter();
        let batcher_context = context.child("batcher");
        let observations_context = context.child("observations");
        let completions_context = context.child("completions");
        let production_resolver_context = context.child("prod_resolver");
        let unused_resolver_context = context.child("unused_resolver");
        let resolver_controls_context = context.child("resolver_controls");
        let resolver_requests_context = context.child("resolver_requests");
        let scripted_resolver_context = context.child("scripted_resolver");

        // Match Engine::start: durable recovery, application custody, and any due compaction all
        // complete before an actor exists or can accept ingress.
        let scheme = match role {
            Role::Validator(participant) => committee.signers[participant.get() as usize].clone(),
            Role::Observer => committee.verifier.clone(),
        };
        let storage_context = DelayedSyncContext {
            inner: context,
            pending: checkpoint_syncs,
        };
        let mut store_context = storage_context.child("stores");
        let stores = Box::pin(open_stores(
            &mut store_context,
            profile,
            &format!("node-{seed}"),
            &scheme,
            &Sequential,
            limits.inflight_application,
        ))
        .await
        .expect("stores open");
        if let Startup::Recovered(recovered) = &stores.startup {
            verify_recovered_payloads(
                &application,
                recovered.core.recovered_payloads(),
                limits.inflight_application,
            )
            .await
            .expect("recovered application payloads remain available");
        }
        let stores = compact_recovery_suffix(stores, limits.checkpoint_interval)
            .await
            .expect("due recovery suffix compacts");

        let blocker = RecordingBlocker::default();
        let (batcher, batcher_mailbox): (TestBatcher, _) = Batcher::new(
            batcher_context,
            batcher::Config {
                scheme: committee.verifier.clone(),
                blocker: blocker.clone(),
                strategy: Sequential,
                codec: committee.codec(),
                limits: ingress.unwrap_or_else(ingress_limits),
                mailbox_size: NonZeroUsize::new(64).unwrap(),
                observation_capacity: NonZeroUsize::new(64).unwrap(),
            },
        );
        let (observation_sender, observation_receiver) =
            mailbox::new_unreliable(observations_context, NonZeroUsize::new(64).unwrap());
        let (completion_sender, completion_receiver) =
            mailbox::new(completions_context, NonZeroUsize::new(64).unwrap());
        let batcher_task = batcher.start(
            observation_sender,
            completion_sender,
            plane_receivers.next().unwrap(),
            plane_receivers.next().unwrap(),
            plane_receivers.next().unwrap(),
        );
        let config = Config {
            scheme,
            strategy: Sequential,
            automaton: application.clone(),
            relay: relay.clone(),
            reporter: reporter.clone(),
            startup: stores.startup,
            checkpoints: stores.checkpoints,
            limits,
            mailbox_size: NonZeroUsize::new(64).unwrap(),
        };
        let (voter, voter_mailbox) = match (journal_gates, test_hooks) {
            (Some(gates), Some(hooks)) => {
                Actor::new_with_test_hooks(storage_context.child("voter"), config, gates, hooks)
            }
            (Some(gates), None) => Actor::new_with_test_hooks(
                storage_context.child("voter"),
                config,
                gates,
                TestHooks::default(),
            ),
            (None, Some(hooks)) => Actor::new_with_test_hooks(
                storage_context.child("voter"),
                config,
                TestGates::default(),
                hooks,
            ),
            (None, None) => Actor::new(storage_context.child("voter"), config),
        };
        let super::Mailbox {
            control: voter_mailbox,
            queries: voter_queries,
        } = voter_mailbox;
        let voter_mailbox_for_resolver = voter_mailbox.clone();
        let (resolver_sender, resolver_receiver, resolver_task) = if production_resolver {
            let (network_sender, network_receiver) =
                oracle.control(me.clone()).register(3, QUOTA).await.unwrap();
            let resolver_config = resolver::Config {
                peers: committee.identities.clone(),
                me: Some(me.clone()),
                blocker: NoopBlocker,
                epoch: committee.config.epoch(),
                codec: committee.codec(),
                strategy: Sequential,
                fetch_timeout: Duration::from_millis(250),
                mailbox_size: NonZeroUsize::new(64).unwrap(),
            };
            let (resolver, resolver_mailbox): (
                Resolver<
                    DeterministicContext,
                    Sha256,
                    Ed25519PublicKey,
                    MinPk,
                    NoopBlocker,
                    Sequential,
                >,
                _,
            ) = Resolver::new(production_resolver_context, resolver_config);
            let resolver::Mailbox {
                control: resolver_mailbox,
                queries: _resolver_queries,
            } = resolver_mailbox;
            let resolver_task = resolver.start(
                voter_mailbox_for_resolver.clone(),
                (network_sender, network_receiver),
            );
            let (_, unused) = mailbox::new::<ResolveRequest>(
                unused_resolver_context,
                NonZeroUsize::new(4).unwrap(),
            );
            (resolver_mailbox, unused, resolver_task)
        } else {
            let (resolver_sender, mut controls) =
                mailbox::new(resolver_controls_context, NonZeroUsize::new(64).unwrap());
            let (requests, resolver_receiver) =
                mailbox::new(resolver_requests_context, NonZeroUsize::new(64).unwrap());
            let resolver_task = scripted_resolver_context.spawn(move |_| async move {
                while let Some(message) = controls.recv().await {
                    match message {
                        ResolverControl::Resolve(request) => {
                            if !requests.enqueue(request).accepted() {
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
            (resolver_sender, resolver_receiver, resolver_task)
        };
        let (ready_sender, ready_receiver) = oneshot::channel();
        let voter_task = voter.start(
            ready_sender,
            batcher_mailbox,
            observation_receiver,
            completion_receiver,
            resolver_sender,
            plane_senders.next().unwrap(),
            plane_senders.next().unwrap(),
            plane_senders.next().unwrap(),
        );
        (
            Self {
                committee,
                blocker,
                _voter_control: voter_mailbox,
                voter: voter_queries,
                resolver: resolver_receiver,
                oracle,
                me,
                task_prefix,
                tasks: vec![batcher_task, voter_task, resolver_task],
            },
            ready_receiver,
        )
    }

    /// Registers `peer` on `channel`, linked in both directions with the node.
    async fn peer(
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
            success_rate: 1.0,
        };
        let _ = self
            .oracle
            .add_link(peer.clone(), self.me.clone(), link.clone())
            .await;
        let _ = self.oracle.add_link(self.me.clone(), peer, link).await;
        (sender, receiver)
    }

    fn envelope<M>(&self, payload: M) -> Envelope<M> {
        Envelope::new(self.committee.config.epoch(), payload)
    }

    fn envelope_cfg<C>(&self, payload: C) -> EnvelopeConfig<C> {
        EnvelopeConfig {
            max_frame_bytes: usize::MAX,
            epoch: self.committee.config.epoch(),
            payload,
        }
    }

    /// Reads the machine's current normalized projection.
    async fn inspect(&mut self) -> Inspection<Sha256Digest> {
        let (responder, receiver) = oneshot::channel();
        assert!(self.voter.enqueue(Query::Inspect { responder }).accepted());
        receiver.await.expect("voter responds")
    }

    async fn crash(self, context: &DeterministicContext) {
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
async fn next_block(
    node: &Node,
    receiver: &mut impl P2pReceiver<PublicKey = Ed25519PublicKey>,
) -> TransactionBlockHeader<Sha256Digest> {
    loop {
        let (_, bytes) = receiver.recv().await.expect("network stays up");
        let envelope =
            Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(bytes, &node.envelope_cfg(()))
                .expect("node emits canonical envelopes");
        if let DataMessage::Block(header) = envelope.into_payload() {
            return header.header().clone();
        }
    }
}

#[test_traced]
fn fresh_validator_requests_a_block_without_work_update() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let (application, mut build) = MockApplication::with_gated_build();
        let log = application.log();
        let _node = Node::start_with_attachments(
            &context,
            61,
            Role::Validator(Participant::new(0)),
            "primary",
            Attachments {
                application,
                ..Attachments::default()
            },
        )
        .await;

        select! {
            () = build.wait_started() => {},
            () = context.sleep(Duration::from_millis(250)) => {
                panic!("fresh validator did not autonomously request a block");
            },
        }
        assert_eq!(log.lock().proposed, 1);
        build.release();
    });
}

#[test_traced]
fn declined_build_is_retried_without_another_work_update() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let application = MockApplication::with_declined_builds(1);
        let node = Node::start_with_attachments(
            &context,
            62,
            Role::Validator(Participant::new(0)),
            "primary",
            Attachments {
                application,
                ..Attachments::default()
            },
        )
        .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        let header = select! {
            header = next_block(&node, &mut data_rx) => header,
            () = context.sleep(Duration::from_millis(500)) => {
                panic!("declined application build was not retried after the production interval");
            },
        };
        assert_eq!(
            header.commitment(),
            MockApplication::block_digest(Context::from(&header), b"mock payload 1")
        );
    });
}

#[test_traced]
fn checkpoints_interleave_with_pipelined_barriers() {
    // Barriers pipeline behind staged application, so a checkpoint must never observe a batch
    // the machine emitted but the journal has not appended. A one-event interval forces a
    // checkpoint attempt at every acknowledgement, exactly where that window would open.
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut node = Node::start_checkpointing(&context, 53, "primary").await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        // Two blocks exhaust the solo producer's pipeline depth; every event in between forces
        // a checkpoint attempt against the live barrier pipeline.
        for _ in 0..2 {
            next_block(&node, &mut data_rx).await;
        }
        let inspection = node.inspect().await;
        assert!(inspection.produced_blocks() >= 2);
    });
}

#[test_traced]
fn checkpoint_io_keeps_control_live_and_bounds_authority_suffix() {
    const SEED: u64 = 89;
    const CHECKPOINT_INTERVAL: u64 = 32;

    DeterministicRunner::timed(Duration::from_secs(20)).start(|context| async move {
        let application = MockApplication::new();
        let application_log = application.log();
        let gates = TestGates::default();
        let checkpoint_syncs = PendingSyncs::default();
        checkpoint_syncs.unblock();
        let mut roll = gates.arm_next_roll();
        let mut before_prune = gates.arm_next_before_prune();
        let mut after_prune = gates.arm_next_after_prune();
        let limits = VoterLimits {
            checkpoint_interval: NZU64!(CHECKPOINT_INTERVAL),
            ..voter_limits()
        };
        let mut node = Node::start_with_limits(
            &context,
            SEED,
            Role::Validator(Participant::new(0)),
            "checkpoint_fence",
            Attachments {
                application,
                journal_gates: Some(gates.clone()),
                checkpoint_syncs: checkpoint_syncs.clone(),
                ..Attachments::default()
            },
            limits,
        )
        .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        // Certify every produced block through the real peer/batcher path. Each certificate
        // reopens the bounded producer window, so authority-producing work remains continuously
        // available until the checkpoint fence deliberately pauses its admission.
        let feeder_committee = Committee::<MinPk>::new(SEED, 6, Limits::new(2, 1).unwrap());
        let feeder_me = node.me.clone();
        let feeder = context
            .child("checkpoint_feeder")
            .spawn(move |_| async move {
                while let Ok((_, bytes)) = data_rx.recv().await {
                    let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                        bytes,
                        &EnvelopeConfig {
                            max_frame_bytes: usize::MAX,
                            epoch: feeder_committee.config.epoch(),
                            payload: (),
                        },
                    )
                    .expect("node emits canonical data envelopes");
                    let DataMessage::Block(block) = envelope.into_payload() else {
                        continue;
                    };
                    let header = block.header().clone();
                    let votes = (0..feeder_committee.codec().da_quorum())
                        .map(|signer| feeder_committee.da_vote(signer, header.clone()))
                        .collect::<Vec<_>>();
                    let certificate = feeder_committee
                        .verifier
                        .assemble_da_certificate(&votes, &Sequential)
                        .expect("a quorum of shares recovers the certificate");
                    data_tx.send(
                        Recipients::One(feeder_me.clone()),
                        Envelope::new(
                            feeder_committee.config.epoch(),
                            DataMessage::<MinPk, Sha256Digest>::DaCertificate(certificate),
                        )
                        .encode(),
                        false,
                    );
                }
            });

        select! {
            () = roll.wait_entered() => {},
            () = context.sleep(Duration::from_secs(5)) => {
                panic!("continuous authority load starved the journal roll");
            },
        }
        assert!(
            application_log.lock().built >= 3,
            "the checkpoint must follow sustained certificate-driven production"
        );
        checkpoint_syncs.arm();
        let DeferredSync {
            release: checkpoint_store,
            blocked: checkpoint_store_blocked,
        } = next_pending_sync(&checkpoint_syncs);
        roll.release();

        select! {
            result = checkpoint_store_blocked => {
                result.expect("the checkpoint metadata sync reaches its real storage gate");
            },
            () = context.sleep(Duration::from_secs(5)) => {
                panic!("the checkpoint store did not start after the journal roll");
            },
        }
        let store_builds = application_log.lock().built;
        let store_appends = gates.appends().len();
        context.sleep(Duration::from_secs(1)).await;
        assert!(
            application_log.lock().built > store_builds,
            "checkpoint storage blocked application construction"
        );
        assert!(
            gates.appends().len() > store_appends,
            "checkpoint storage blocked the post-cut journal suffix"
        );
        assert!(
            gates.appends().len() - store_appends <= CHECKPOINT_INTERVAL as usize,
            "a stalled checkpoint exceeded one bounded post-cut interval"
        );
        let bounded_appends = gates.appends().len();
        context.sleep(Duration::from_secs(1)).await;
        assert_eq!(
            gates.appends().len(),
            bounded_appends,
            "a stalled checkpoint did not fence post-cut journal growth"
        );
        let inspection = select! {
            inspection = node.inspect() => inspection,
            () = context.sleep(Duration::from_secs(1)) => {
                panic!("the checkpoint fence blocked read-only inspection");
            },
        };
        assert!(inspection.produced_blocks() >= 3);
        checkpoint_store
            .send(Ok(()))
            .expect("the checkpoint metadata sync remains blocked");

        select! {
            () = before_prune.wait_entered() => {},
            () = context.sleep(Duration::from_secs(5)) => {
                panic!("continuous authority load starved checkpoint pruning");
            },
        }
        let prune_appends = gates.appends().len();
        context.sleep(Duration::from_secs(1)).await;
        assert_eq!(
            gates.appends().len(),
            prune_appends,
            "a stalled prune reopened post-cut journal growth"
        );
        select! {
            _ = node.inspect() => {},
            () = context.sleep(Duration::from_secs(1)) => {
                panic!("the prune fence blocked read-only inspection");
            },
        }
        let checkpoint_partition = format!("node-{SEED}-multimmit-machine-checkpoints");
        assert!(
            !context
                .scan(&checkpoint_partition)
                .await
                .unwrap()
                .is_empty(),
            "pruning must follow a durable checkpoint"
        );
        before_prune.release();

        select! {
            () = after_prune.wait_entered() => {},
            () = context.sleep(Duration::from_secs(5)) => {
                panic!("the admitted prune did not complete");
            },
        }
        let journal_partition = format!("node-{SEED}-multimmit-machine-journal");
        let sections = context
            .scan(&journal_partition)
            .await
            .expect("journal partition remains readable");
        assert!(
            sections
                .iter()
                .all(|name| name.as_slice() != 0u64.to_be_bytes()),
            "pruning retained the checkpoint-covered journal section"
        );
        after_prune.release();

        feeder.abort();
        let _ = feeder.await;
    });
}

#[test_traced]
fn fresh_validator_builds_signs_and_publishes_a_block() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut node = Node::start(
            &context,
            41,
            Role::Validator(Participant::new(0)),
            "primary",
        )
        .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        let header = next_block(&node, &mut data_rx).await;
        assert_eq!(header.chain().get(), 0);
        assert!(
            [b"mock payload 1".as_slice(), b"mock payload 2".as_slice()]
                .into_iter()
                .map(|payload| MockApplication::block_digest(Context::from(&header), payload))
                .any(|commitment| commitment == header.commitment())
        );

        // The producer keeps building while its certificate window remains open.
        let inspection = node.inspect().await;
        assert!(inspection.produced_blocks() >= 1);

        let metrics = context.encode();
        assert!(
            !metrics.contains("primary_voter_view_advances_total"),
            "current_view is the single source of leader-view progress: {metrics}"
        );
        for metric in ["transmissions_total", "transmitted_bytes_total"] {
            assert!(
                metrics.lines().any(|line| {
                    line.contains(metric)
                        && line.contains("plane=\"Data\"")
                        && !line.ends_with(" 0")
                }),
                "published data traffic was not counted in {metric}: {metrics}"
            );
        }
        for name in [
            "primary_voter_current_view",
            "primary_voter_proposal_anchor_view",
            "primary_voter_produced_blocks",
            "primary_voter_producer_vote_shares",
            "primary_voter_producer_pipeline_blocked",
            "primary_voter_producer_recovery_active",
            "primary_voter_active_validations",
            "primary_voter_pending_validations",
            "primary_voter_build_active",
            "primary_voter_build_latency",
            "primary_voter_vqc_latency",
            "primary_voter_lqc_latency",
            "primary_voter_ready_to_sign_latency",
            "primary_voter_sign_ready_to_wire_latency",
            "primary_voter_propose_to_sign_ready_latency",
            "primary_voter_verify_to_sign_ready_latency",
            "primary_voter_startup_drain_latency",
            "primary_voter_chains_known{chain=\"0\"}",
            "primary_voter_chains_finalized{chain=\"0\"}",
            "primary_voter_chains_certified{chain=\"0\"}",
        ] {
            assert!(metrics.contains(name), "missing metric {name}: {metrics}");
        }
    });
}

struct SigningLatencySample {
    covered_tail: f64,
    samples: f64,
    p95: f64,
    p99: f64,
}

async fn signing_latency_sample(
    context: &DeterministicContext,
    seed: u64,
    instance: &'static str,
    storage_delay: Duration,
) -> SigningLatencySample {
    let (application, mut build) = MockApplication::with_gated_build();
    application.permit_builds(1);
    let gates = TestGates::default();
    let node = Node::start_with_attachments(
        context,
        seed,
        Role::Validator(Participant::new(0)),
        instance,
        Attachments {
            application,
            journal_gates: Some(gates.clone()),
            ..Attachments::default()
        },
    )
    .await;
    let (_, mut data_rx) = node.peer(1, 0).await;
    build.wait_started().await;

    // Hold the authorization append after it reaches the journal. Private signing can finish
    // while the owner is suspended, but the owner cannot consume the signed completion yet.
    let mut authorization_append = gates.arm_after_append();
    build.release();
    authorization_append.wait_entered().await;

    // Catch the signed completion after it appends, then arm the one sync that covers both the
    // non-exposing authorization and the ready signature.
    let mut signature_append = gates.arm_after_append();
    authorization_append.release();
    signature_append.wait_entered().await;
    let mut publication_sync = gates.arm_next_start_sync();
    signature_append.release();
    publication_sync.wait_entered().await;

    // One sync is necessary and sufficient for this causally ready authorization/signature wave.
    // It gates the first wire exposure, giving the injected-storage sample an exact pre-ack cut.
    let prefix = format!("{instance}_voter_");
    let release_count = format!("{prefix}sign_ready_to_wire_latency_count");
    let release_sum = format!("{prefix}sign_ready_to_wire_latency_sum");
    let histogram = format!("{prefix}sign_ready_to_wire_latency_bucket");
    let before = context.encode();
    let initial_count = metric_sample(&before, &release_count);
    assert_eq!(
        initial_count, 0.0,
        "no signed publication may precede the coalesced barrier acknowledgement"
    );
    let initial_sum = metric_sample(&before, &release_sum);
    context.sleep(storage_delay).await;
    publication_sync.release();
    let _initial = next_block(&node, &mut data_rx).await;

    for _ in 0..128 {
        if metric_sample(&context.encode(), &release_count) >= 1.0 {
            break;
        }
        reschedule().await;
    }

    let metrics = context.encode();
    assert!(
        metric_sample(&metrics, &format!("{prefix}ready_to_sign_latency_count")) >= 1.0,
        "the signed block never reached private signing"
    );
    assert_eq!(
        metric_sample(
            &metrics,
            &format!("{prefix}propose_to_sign_ready_latency_count")
        ),
        1.0
    );
    assert!(
        metric_sample(
            &metrics,
            &format!("{prefix}sign_ready_to_wire_latency_count")
        ) >= 1.0,
        "the durable signed wave never reached the wire"
    );
    let final_count = metric_sample(&metrics, &release_count);
    let final_sum = metric_sample(&metrics, &release_sum);
    SigningLatencySample {
        covered_tail: final_sum - initial_sum,
        samples: final_count - initial_count,
        p95: histogram_percentile_bound(&metrics, &histogram, 95.0),
        p99: histogram_percentile_bound(&metrics, &histogram, 99.0),
    }
}

#[test_traced]
fn signing_timing_includes_the_exact_storage_release_delay() {
    const STORAGE_DELAY: Duration = Duration::from_millis(250);

    let baseline =
        DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
            signing_latency_sample(&context, 81, "timing_baseline", Duration::ZERO).await
        });
    let delayed = DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        signing_latency_sample(&context, 81, "timing_delayed", STORAGE_DELAY).await
    });

    assert!(baseline.covered_tail <= 0.5 * baseline.samples);
    assert!(
        delayed.covered_tail >= STORAGE_DELAY.as_secs_f64(),
        "the behind-sync sample must contain the injected storage delay"
    );
    assert!(delayed.covered_tail <= 0.5 * delayed.samples);
    // Logical-time scheduling and the injected storage delay must keep both tails within the
    // 500ms service-latency ceiling.
    assert!(baseline.p95 <= 0.5 && baseline.p99 <= 0.5);
    assert!(delayed.p95 <= 0.5 && delayed.p99 <= 0.5);
}

#[test_traced]
fn verified_block_signing_reaches_wire_without_application_correlation() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let (application, mut verification) = MockApplication::with_gated_verify();
        application.pause_building();
        let node = Node::start_with_attachments(
            &context,
            82,
            Role::Validator(Participant::new(0)),
            "verify_timing",
            Attachments {
                application,
                ..Attachments::default()
            },
        )
        .await;
        let (mut peer_tx, mut peer_data_rx) = node.peer(1, 0).await;
        let commitment = Sha256::hash(&[b"timed remote payload"]);
        let block = node.committee.signed_block(1, commitment);
        peer_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(block)).encode(),
            false,
        );
        verification.wait_started().await;
        verification.release();

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = select! {
                result = peer_data_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => panic!("DA vote was not published"),
            };
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(()),
            )
            .expect("canonical envelope");
            if let DataMessage::DaVote(vote) = envelope.into_payload()
                && vote.header().commitment() == commitment
            {
                break;
            }
        }

        let metrics = context.encode();
        assert_eq!(
            metric_sample(
                &metrics,
                "verify_timing_voter_verify_to_sign_ready_latency_count"
            ),
            1.0
        );
        assert_eq!(
            metric_sample(
                &metrics,
                "verify_timing_voter_sign_ready_to_wire_latency_count"
            ),
            1.0
        );
    });
}

#[test]
fn round_compare_fields_are_numeric() {
    let spans = Arc::new(Mutex::new(BTreeMap::new()));
    let subscriber = tracing_subscriber::registry().with(TraceFieldLayer {
        spans: Arc::clone(&spans),
    });
    tracing::subscriber::with_default(subscriber, || {
        let round = Round::new(Epoch::new(42), View::new(1_964));
        let root = round_span(round.epoch(), round.view());
        let _timeout = round_timeout_span(&root, round);
    });

    let spans = spans.lock();
    for name in ["multimmit.voter.round", "multimmit.voter.round.timeout"] {
        let fields = spans.get(name).expect("the span was recorded");
        assert_eq!(fields.get("epoch"), Some(&TraceFieldKind::I64));
        assert_eq!(fields.get("view"), Some(&TraceFieldKind::I64));
    }
}

#[test_collect_traces]
fn round_spans_track_ingress_and_publication_boundaries(traces: TraceStorage) {
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    executor.start(|context| async move {
        let seed = 76;
        let node = Node::start_with_attachments(
            &context,
            seed,
            Role::Validator(Participant::new(0)),
            "primary",
            Attachments::default(),
        )
        .await;
        let (mut peer_tx, mut peer_data_rx) = node.peer(1, 0).await;

        select! {
            _ = next_block(&node, &mut peer_data_rx) => {},
            () = context.sleep(Duration::from_secs(1)) => {
                panic!("local block was not published");
            },
        }

        let commitment = Sha256::hash(&[b"traced remote payload"]);
        let block = node.committee.signed_block(1, commitment);
        peer_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(block)).encode(),
            false,
        );

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = select! {
                result = peer_data_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => {
                    panic!("remote block was not observed and verified");
                },
            };
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(()),
            )
            .expect("canonical envelope");
            if let DataMessage::DaVote(vote) = envelope.into_payload()
                && vote.header().commitment() == commitment
            {
                break;
            }
        }

        let events = traces.get_by_level(Level::DEBUG);
        events
            .expect_event(|event| {
                event.metadata.content == "test reporter received activity"
                    && event
                        .expect_span_at_index(0, |span| {
                            if span.content == "multimmit.voter.verify.complete"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("verified span is missing its round fields"
                                    .to_string()
                                    .into())
                            }
                        })
                        .is_ok()
                    && event
                        .expect_span_at_index(1, |span| {
                            if span.content == "multimmit.voter.verify"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("verify span is missing its round fields".to_string().into())
                            }
                        })
                        .is_ok()
                    && event
                        .expect_span_at_index(2, |span| {
                            if span.content == "multimmit.voter.observe"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("observe span is missing its round fields"
                                    .to_string()
                                    .into())
                            }
                        })
                        .is_ok()
                    && event
                        .expect_span(|span| {
                            span.content == "multimmit.voter.round"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                        })
                        .is_ok()
            })
            .unwrap();
        events
            .expect_event(|event| {
                event.metadata.content == "durable publication installed"
                    && event
                        .expect_span_at_index(0, |span| {
                            if span.content == "multimmit.voter.publish.install"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("install span is missing its origin fields"
                                    .to_string()
                                    .into())
                            }
                        })
                        .is_ok()
                    && event
                        .expect_span(|span| {
                            span.content == "multimmit.voter.round"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                        })
                        .is_ok()
            })
            .unwrap();
        events
            .expect_event(|event| {
                event.metadata.content == "test relay received payload"
                    && event
                        .expect_span_at_index(0, |span| {
                            if span.content == "multimmit.voter.publish"
                                && span.expect_field_exact("epoch", "76").is_ok()
                                && span.expect_field_exact("view", "1").is_ok()
                            {
                                Ok(())
                            } else {
                                Err("publish span is missing its round fields"
                                    .to_string()
                                    .into())
                            }
                        })
                        .is_ok()
            })
            .unwrap();
    });
}

#[test_traced]
fn ready_application_work_precedes_later_mailbox_traffic() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let (node, mut build) = Node::start_gated_build(&context, 49, "primary").await;

        build.wait_started().await;
        // Quiesce the voter before staging the race. Every completion pool self-wakes once on
        // its first poll, and an outstanding wake would let the voter run between the mailbox
        // enqueue and the build task's completion, leaving no ready application work to outrank.
        context.sleep(Duration::from_millis(1)).await;
        let (responder, inspection) = oneshot::channel();
        assert!(node.voter.enqueue(Query::Inspect { responder }).accepted());
        build.release();

        let inspection = inspection.await.expect("voter responds");
        assert!(inspection.produced_blocks() >= 1);
    });
}

#[test_traced]
fn live_admission_preserves_core_local_priority_under_peer_flood() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let hooks = TestHooks::default();
        let mut ingress = ingress_limits();
        ingress.inflight_jobs = NonZeroUsize::new(16).unwrap();
        let node = Node::start_with_attachments(
            &context,
            86,
            Role::Observer,
            "live_scheduler",
            Attachments {
                ingress: Some(ingress),
                test_hooks: Some(hooks.clone()),
                ..Attachments::default()
            },
        )
        .await;
        let (mut peer, _) = node.peer(1, 0).await;

        for ordinal in 0..64_u64 {
            let commitment = Sha256::hash(&[
                b"live scheduler flood".as_slice(),
                ordinal.to_be_bytes().as_slice(),
            ]);
            let block = node.committee.signed_block(1, commitment);
            peer.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::Block(block)).encode(),
                false,
            );
        }

        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let services = hooks.services();
            let mut cycles = BTreeMap::<u64, (usize, usize)>::new();
            for (cycle, lane) in services {
                let counts = cycles.entry(cycle).or_default();
                match lane {
                    Lane::LocalCompletion => counts.0 += 1,
                    Lane::PeerObservation => counts.1 += 1,
                    _ => {}
                }
            }
            let prioritized_cycles = cycles
                .values()
                .filter(|&&(local, peer)| local >= 4 && peer == 2)
                .count();
            if prioritized_cycles >= 3 {
                return;
            }
            select! {
                () = context.sleep(Duration::from_millis(10)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("live admission never exposed Core's local priority: {cycles:?}");
                },
            }
        }
    });
}

#[test_traced]
fn invalid_verification_blocks_only_its_authenticated_source() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut ingress = ingress_limits();
        ingress.coalesce = Duration::from_millis(5);
        let node = Node::start_with_attachments(
            &context,
            76,
            Role::Observer,
            "primary",
            Attachments {
                ingress: Some(ingress),
                ..Attachments::default()
            },
        )
        .await;
        let (mut peer_a, _) = node.peer(1, 0).await;
        let (mut peer_b, _) = node.peer(2, 0).await;

        let original_a0 = node
            .committee
            .signed_block(0, Sha256::hash(&[b"original a0"]));
        let forged_a0 = SignedTransactionBlock::new(
            node.committee
                .transaction_header(0, Sha256::hash(&[b"forged a0"])),
            original_a0.attestation().clone(),
        );
        let valid_b = node.committee.signed_block(1, Sha256::hash(&[b"valid b"]));
        let original_a2 = node
            .committee
            .signed_block(2, Sha256::hash(&[b"original a2"]));
        let forged_a2 = SignedTransactionBlock::new(
            node.committee
                .transaction_header(2, Sha256::hash(&[b"forged a2"])),
            original_a2.attestation().clone(),
        );

        peer_a.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(forged_a0)).encode(),
            false,
        );
        peer_b.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(valid_b)).encode(),
            false,
        );
        peer_a.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(forged_a2)).encode(),
            false,
        );

        context.sleep(Duration::from_millis(50)).await;
        assert_eq!(
            node.blocker.blocked(),
            vec![node.committee.identities[1].clone()]
        );
    });
}

#[test_traced]
fn accepted_inspection_loses_to_at_most_one_ready_event() {
    DeterministicRunner::default().start(|context| async move {
        let mut node = Node::start(&context, 79, Role::Observer, "control_order").await;
        let baseline = metric_sample(&context.encode(), "control_order_voter_stale_total");
        let view = View::new(1);
        for id in 0..8 {
            let job = ResolutionJob::fabricate(id, 0, view);
            let completion = ResolutionCompletion::new(
                job.id(),
                job.generation(),
                job.view(),
                ViewProof::Nullification(Box::new(node.committee.nullification(view.get()))),
            );
            assert!(
                node._voter_control
                    .enqueue(Message::Resolution {
                        span: tracing::Span::none(),
                        round: Round::new(node.committee.config.epoch(), view),
                        completion,
                    })
                    .accepted()
            );
        }

        let _ = node.inspect().await;
        let serviced =
            metric_sample(&context.encode(), "control_order_voter_stale_total") - baseline;
        assert!(
            (1.0..=2.0).contains(&serviced),
            "accepted inspection lost to {serviced} ready control events",
        );
    });
}

#[test_traced]
fn application_eventual_validity_restores_correct_chain_liveness() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let (mut node, mut validation) =
            Node::start_gated_verification(&context, 50, "primary").await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;
        let (_, mut consensus_rx) = node.peer(1, 1).await;

        let remote_commitment = Sha256::hash(&[b"unavailable remote payload"]);
        let remote = node.committee.signed_block(1, remote_commitment);
        let remote_header = remote.header().clone();
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(remote)).encode(),
            false,
        );
        validation.wait_started().await;

        let (responder, inspection) = oneshot::channel();
        assert!(node.voter.enqueue(Query::Inspect { responder }).accepted());

        let _ = select! {
            result = inspection => result.expect("voter responds while validation is pending"),
            () = context.sleep(Duration::from_millis(100)) => {
                panic!("remote validation blocked voter control");
            },
        };

        let local = select! {
            header = next_block(&node, &mut data_rx) => header,
            () = context.sleep(Duration::from_millis(250)) => {
                panic!("remote validation blocked the eligible local build");
            },
        };
        assert_eq!(local.chain().get(), 0);

        let deadline = context.current() + Duration::from_secs(1);
        let mut saw_novote = false;
        let mut saw_nullify = false;
        while !(saw_novote && saw_nullify) {
            select! {
                result = consensus_rx.recv() => {
                    let (_, bytes) = result.expect("network stays up");
                    let envelope =
                        Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                            bytes,
                            &node.envelope_cfg(node.committee.codec()),
                        )
                        .expect("canonical envelope");
                    match envelope.into_payload() {
                        ConsensusMessage::NoVote(vote) => {
                            assert!(node.committee.verifier.verify_novote(&vote));
                            saw_novote = true;
                        }
                        ConsensusMessage::Nullify(nullify) => {
                            assert!(
                                node.committee
                                    .verifier
                                    .verify_nullify(&nullify)
                            );
                            saw_nullify = true;
                        }
                        _ => {}
                    }
                },
                () = context.sleep_until(deadline) => {
                    panic!("remote validation blocked the view timer");
                },
            }
        }

        validation.release();

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = select! {
                result = data_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => {
                    panic!("eventually valid remote block did not receive a local DA vote");
                },
            };
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(()),
            )
            .expect("canonical data envelope");
            let DataMessage::DaVote(vote) = envelope.into_payload() else {
                continue;
            };
            if vote.header() == &remote_header {
                assert_eq!(vote.signer(), Participant::new(0));
                break;
            }
        }

        let votes = (0..node.committee.codec().da_quorum())
            .map(|signer| node.committee.da_vote(signer, remote_header.clone()))
            .collect::<Vec<_>>();
        let certificate = node
            .committee
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .expect("a quorum of shares recovers the remote certificate");
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::DaCertificate(certificate))
                .encode(),
            false,
        );
        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let inspection = node.inspect().await;
            let remote_chain = inspection
                .chain_progress()
                .iter()
                .find(|progress| progress.chain().get() == 1)
                .expect("remote chain is tracked");
            if remote_chain.certified() >= Height::new(1) {
                assert!(remote_chain.known() >= remote_chain.certified());
                break;
            }
            assert!(
                context.current() < deadline,
                "eventually valid remote chain did not certify"
            );
            context.sleep(Duration::from_millis(10)).await;
        }
    });
}

#[test_traced]
fn da_certificate_releases_obsolete_remote_validation() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let (application, mut validation) = MockApplication::with_gated_verify();
        application.pause_building();
        let node = Node::start_with_attachments(
            &context,
            83,
            Role::Validator(Participant::new(0)),
            "retire_validation",
            Attachments {
                application,
                ..Attachments::default()
            },
        )
        .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        let first_commitment = Sha256::hash(&[b"unavailable certified payload"]);
        let first = node.committee.signed_block(1, first_commitment);
        let first_header = first.header().clone();
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(first)).encode(),
            false,
        );
        validation.wait_started().await;

        let votes = (0..node.committee.codec().da_quorum())
            .map(|signer| node.committee.da_vote(signer, first_header.clone()))
            .collect::<Vec<_>>();
        let certificate = node
            .committee
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .expect("a quorum of shares recovers the first certificate");
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::DaCertificate(certificate))
                .encode(),
            false,
        );

        let second_header = TransactionBlockHeader::new(
            node.committee.config.epoch(),
            first_header.chain(),
            first_header.height().next(),
            first_header.block_ref::<Sha256>().digest(),
            Sha256::hash(&[b"payload after certified frontier"]),
        )
        .expect("height two extends the certified frontier");
        let second = node.committee.signers[1]
            .sign_transaction_block(second_header.clone())
            .expect("the configured producer signs its successor");
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(second)).encode(),
            false,
        );

        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = select! {
                result = data_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => {
                    panic!("the certified frontier did not release its obsolete validation");
                },
            };
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(()),
            )
            .expect("canonical data envelope");
            if let DataMessage::DaVote(vote) = envelope.into_payload()
                && vote.header() == &second_header
            {
                break;
            }
        }
    });
}

#[derive(Copy, Clone)]
enum JournalStall {
    Append,
    StartSync,
}

async fn assert_journal_stall_does_not_block_voter(
    context: &DeterministicContext,
    seed: u64,
    instance: &'static str,
    stall: JournalStall,
) {
    let application = MockApplication::default();
    application.pause_building();
    let gates = TestGates::default();
    let mut node = Node::start_with_attachments(
        context,
        seed,
        Role::Validator(Participant::new(0)),
        instance,
        Attachments {
            application,
            journal_gates: Some(gates.clone()),
            ..Attachments::default()
        },
    )
    .await;
    let mut gate = match stall {
        JournalStall::Append => gates.arm_next_append(),
        JournalStall::StartSync => gates.arm_next_start_sync(),
    };
    let (mut data_tx, _) = node.peer(1, 0).await;
    let (mut consensus_tx, _) = node.peer(2, 1).await;

    let remote = node
        .committee
        .signed_block(1, Sha256::hash(&[b"journal stall remote payload"]));
    data_tx.send(
        Recipients::One(node.me.clone()),
        node.envelope(DataMessage::Block(remote)).encode(),
        false,
    );
    select! {
        () = gate.wait_entered() => {},
        () = context.sleep(Duration::from_secs(1)) => {
            panic!("voter did not reach the armed journal storage call");
        },
    }

    let baseline = select! {
        inspection = node.inspect() => inspection.waiting_artifacts(),
        () = context.sleep(Duration::from_millis(100)) => {
            panic!("pending journal storage blocked voter control");
        },
    };
    let leader = node.committee.leader_block(1);
    let vote = node.committee.vote(2, &leader);
    consensus_tx.send(
        Recipients::One(node.me.clone()),
        node.envelope(ConsensusMessage::Vote(vote)).encode(),
        true,
    );

    let peer_deadline = context.current() + Duration::from_secs(1);
    loop {
        let inspection = select! {
            inspection = node.inspect() => inspection,
            () = context.sleep(Duration::from_millis(100)) => {
                panic!("pending journal storage blocked voter control");
            },
        };
        if inspection.waiting_artifacts() > baseline {
            break;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(peer_deadline) => {
                panic!("pending journal storage blocked peer verification or machine service");
            },
        }
    }

    let metric = format!("{instance}_voter_view_timeouts_total 1");
    let timer_deadline = context.current() + Duration::from_secs(1);
    loop {
        let metrics = context.encode();
        if metrics.lines().any(|line| line == metric) {
            break;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(timer_deadline) => {
                panic!("pending journal storage blocked the view timer: {metrics}");
            },
        }
    }
    select! {
        _ = node.inspect() => {},
        () = context.sleep(Duration::from_millis(100)) => {
            panic!("voter control stopped after servicing the timer");
        },
    }

    gate.release();
}

#[test_traced]
fn pending_journal_append_does_not_starve_voter_progress() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        assert_journal_stall_does_not_block_voter(
            &context,
            77,
            "append_stall",
            JournalStall::Append,
        )
        .await;
    });
}

#[test_traced]
fn pending_journal_start_sync_does_not_starve_voter_progress() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        assert_journal_stall_does_not_block_voter(
            &context,
            78,
            "start_sync_stall",
            JournalStall::StartSync,
        )
        .await;
    });
}

#[test_traced]
fn stalled_journal_sync_bounds_staged_persistence() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let gates = TestGates::default();
        let mut node = Node::start_with_attachments(
            &context,
            79,
            Role::Observer,
            "staged_bound",
            Attachments {
                journal_gates: Some(gates.clone()),
                ..Attachments::default()
            },
        )
        .await;
        let mut sync = gates.arm_next_start_sync();
        let (mut certificates_tx, _) = node.peer(2, 2).await;
        certificates_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::Lqc(node.committee.lqc(1))).encode(),
            true,
        );
        select! {
            () = sync.wait_entered() => {},
            () = context.sleep(Duration::from_secs(1)) => {
                panic!("voter did not reach the armed journal sync");
            },
        }

        let metric = "staged_bound_voter_staged_batches";
        let ceiling = CoreState::<Sha256, MinPk>::MAX_STAGED_BARRIERS as f64;
        let mut parent = node.committee.vqc(1);
        let mut ceiling_view = None;
        let mut last_submitted_view = 0;
        for view in 2..=128 {
            let block = node.committee.leader_block_with_parent(view, &parent);
            let votes = (0..node.committee.codec().view_quorum())
                .map(|signer| node.committee.vote(signer, &block))
                .collect::<Vec<_>>();
            let messages = votes
                .iter()
                .cloned()
                .map(ViewMessage::Vote)
                .collect::<Vec<_>>();
            let lqc = node
                .committee
                .verifier
                .assemble_lqc::<Sha256, _>(block.block().clone(), &votes, &Sequential)
                .expect("quorum of chained votes aggregates");
            parent = node
                .committee
                .verifier
                .assemble_vqc::<Sha256, _>(block.block().clone(), &messages, &Sequential)
                .expect("quorum of chained view messages aggregates");
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::Lqc(lqc)).encode(),
                true,
            );

            if let Some(first_fenced_view) = ceiling_view {
                last_submitted_view = view;
                context.sleep(Duration::from_millis(1)).await;
                let encoded = context.encode();
                assert_eq!(metric_sample(&encoded, metric), ceiling, "{encoded}");
                if view == first_fenced_view + 2 {
                    break;
                }
                continue;
            }

            let deadline = context.current() + Duration::from_secs(1);
            loop {
                let encoded = context.encode();
                if metric_sample(&encoded, metric) == ceiling {
                    ceiling_view = Some(view);
                    last_submitted_view = view;
                    break;
                }
                if metric_sample(&encoded, "staged_bound_voter_current_view") > view as f64 {
                    break;
                }
                select! {
                    () = context.sleep(Duration::from_millis(1)) => {},
                    () = context.sleep_until(deadline) => {
                        let inspection = node.inspect().await;
                        panic!("chained L-QC did not advance view {view}: {inspection:?}");
                    },
                }
            }
        }

        let ceiling_view = ceiling_view.expect("staged persistence reached its ceiling");
        assert_eq!(last_submitted_view, ceiling_view + 2);
        let encoded = context.encode();
        assert_eq!(metric_sample(&encoded, metric), ceiling, "{encoded}");
        let fenced_view = metric_sample(&encoded, "staged_bound_voter_current_view");

        context.sleep(Duration::from_secs(2)).await;
        let encoded = context.encode();
        assert_eq!(metric_sample(&encoded, metric), ceiling, "{encoded}");
        assert_eq!(
            metric_sample(&encoded, "staged_bound_voter_current_view"),
            fenced_view,
            "{encoded}"
        );
        select! {
            _ = node.inspect() => {},
            () = context.sleep(Duration::from_millis(100)) => {
                panic!("the persistence fence blocked voter control");
            },
        }

        sync.release();
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let encoded = context.encode();
            if metric_sample(&encoded, metric) == 0.0
                && metric_sample(&encoded, "staged_bound_voter_current_view") > fenced_view
            {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(10)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("persistence did not fully drain and resume after sync completed: {encoded}");
                },
            }
        }
    });
}

#[derive(Clone, Copy, Debug)]
enum DurabilityCut {
    BeforeAppend,
    AppendBeforeSync,
    SyncBeforeAck,
    BeforeCheckpoint,
    CheckpointBeforePrune,
    AfterSuccessfulPrune,
}

impl DurabilityCut {
    const fn checkpointing(self) -> bool {
        matches!(
            self,
            Self::BeforeCheckpoint | Self::CheckpointBeforePrune | Self::AfterSuccessfulPrune
        )
    }

    const fn durable_subject(self) -> bool {
        matches!(
            self,
            Self::SyncBeforeAck
                | Self::BeforeCheckpoint
                | Self::CheckpointBeforePrune
                | Self::AfterSuccessfulPrune
        )
    }
}

type DurableLedger = BTreeMap<EffectId, Vec<TestDurableAttempt<MinPk, Sha256Digest>>>;

#[derive(Clone)]
struct DurableScenario {
    publication: EffectId,
    generation: u64,
    block: SignedTransactionBlock<MinPk, Sha256Digest>,
    before_publication: DurableLedger,
}

#[derive(Default)]
struct ExposureLedger {
    blocks: BTreeMap<(ChainId, Height, Participant), SignedTransactionBlock<MinPk, Sha256Digest>>,
    votes: BTreeMap<(ChainId, Height, Participant), DaVote<MinPk, Sha256Digest>>,
}

impl ExposureLedger {
    fn record(&mut self, node: &Node, message: DataMessage<MinPk, Sha256Digest>) {
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

    fn block(
        &self,
        chain: ChainId,
        height: Height,
        signer: Participant,
    ) -> Option<&SignedTransactionBlock<MinPk, Sha256Digest>> {
        self.blocks.get(&(chain, height, signer))
    }
}

async fn collect_data_exposure(
    context: &DeterministicContext,
    node: &Node,
    receiver: &mut impl P2pReceiver<PublicKey = Ed25519PublicKey>,
    exposure: &mut ExposureLedger,
    duration: Duration,
) {
    let deadline = context.current() + duration;
    loop {
        select! {
            result = receiver.recv() => {
                let (_, bytes) = result.expect("network stays up");
                let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                    bytes,
                    &node.envelope_cfg(()),
                )
                .expect("canonical envelope");
                exposure.record(node, envelope.into_payload());
            },
            () = context.sleep_until(deadline) => return,
        }
    }
}

async fn wait_for_slot_block(
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
                    &node.envelope_cfg(()),
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

fn slot_publications(ledger: &DurableLedger, chain: ChainId, height: Height) -> DurableLedger {
    ledger
        .iter()
        .filter(|(_, attempts)| {
            attempts.iter().any(|attempt| {
                matches!(
                    &attempt.effect,
                    DurableEffect::Broadcast(artifact)
                        if matches!(artifact.as_ref(), Artifact::TransactionBlock(block)
                            if block.header().chain() == chain && block.header().height() == height)
                )
            })
        })
        .map(|(id, attempts)| (*id, attempts.clone()))
        .collect()
}

fn exact_block_publication(
    id: EffectId,
    generation: u64,
    block: SignedTransactionBlock<MinPk, Sha256Digest>,
) -> DurableLedger {
    BTreeMap::from([(
        id,
        vec![TestDurableAttempt {
            generation,
            effect: DurableEffect::Broadcast(Arc::new(Artifact::TransactionBlock(block))),
        }],
    )])
}

fn exact_durable_ledger(
    committee: &Committee<MinPk>,
    block: &SignedTransactionBlock<MinPk, Sha256Digest>,
    generation: u64,
) -> DurableLedger {
    let attempt = |effect| vec![TestDurableAttempt { generation, effect }];
    let block = Arc::new(block.clone());
    let vote = committee.da_vote(0, block.header().clone());
    BTreeMap::from([
        (
            EffectId::from_cursor(Cursor::new(2)),
            attempt(DurableEffect::Sign(SignRequest::TransactionBlock(
                block.header().clone(),
            ))),
        ),
        (
            EffectId::from_cursor(Cursor::new(3)),
            attempt(DurableEffect::Broadcast(Arc::new(
                Artifact::TransactionBlock(block.as_ref().clone()),
            ))),
        ),
        (
            EffectId::from_cursor(Cursor::new(4)),
            attempt(DurableEffect::Sign(SignRequest::DaVote(
                DaVoteRequest::new(block),
            ))),
        ),
        (
            EffectId::from_cursor(Cursor::new(5)),
            attempt(DurableEffect::Send(SendRequest::new(
                Participant::new(0),
                Arc::new(Artifact::DaVote(vote)),
            ))),
        ),
    ])
}

fn exact_private_ledger(
    committee: &Committee<MinPk>,
    block: &SignedTransactionBlock<MinPk, Sha256Digest>,
    generation: u64,
) -> DurableLedger {
    exact_durable_ledger(committee, block, generation)
        .into_iter()
        .filter(|(_, attempts)| {
            attempts
                .iter()
                .all(|attempt| !attempt.effect.is_network_publication())
        })
        .collect()
}

fn calibrate_durable_scenario(seed: u64) -> DurableScenario {
    let role = Role::Validator(Participant::new(0));
    let application = MockApplication::new();
    application.pause_building();
    let gates = TestGates::default();
    let hooks = TestHooks::default();
    let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
    let context = Context::from(&committee.transaction_header(0, Sha256::hash(&[b"context"])));
    let expected_block =
        committee.signed_block(0, MockApplication::block_digest(context, b"mock payload 1"));
    let generation = 1;
    let publication = EffectId::from_cursor(Cursor::new(3));
    let expected_ledger = exact_durable_ledger(&committee, &expected_block, generation);
    let before_publication = exact_private_ledger(&committee, &expected_block, generation);
    let runner = DeterministicRunner::timed(Duration::from_secs(10));
    runner.start(move |context| async move {
        let node = Node::start_with_attachments(
            &context,
            seed,
            role,
            "durability_node",
            Attachments {
                application: application.clone(),
                journal_gates: Some(gates.clone()),
                test_hooks: Some(hooks.clone()),
                ..Attachments::default()
            },
        )
        .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        application.permit_builds(1);
        let mut exposure = ExposureLedger::default();
        let block = wait_for_slot_block(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            expected_block.header().chain(),
            expected_block.header().height(),
            expected_block.signer(),
        )
        .await;
        assert_eq!(block, expected_block);
        wait_for_live_publication(&context, &hooks, |effect| {
            matches!(effect, DurableEffect::Send(request)
                if matches!(request.artifact().as_ref(), Artifact::DaVote(vote)
                    if vote.header() == block.header()))
        })
        .await;

        let ledger = hooks.durable_effects();
        assert_eq!(ledger, expected_ledger, "the fixture ledger changed");
        DurableScenario {
            publication,
            generation,
            block,
            before_publication,
        }
    })
}

fn exercise_durability_cut(cut: DurabilityCut, scenario: DurableScenario, seed: u64) {
    let role = Role::Validator(Participant::new(0));
    let application = MockApplication::new();
    application.pause_building();
    let recovered_application = application.clone();
    let first_gates = TestGates::default();
    let first_hooks = TestHooks::default();
    let expected = scenario.block.clone();
    let first_expected = expected.clone();
    let first_scenario = scenario.clone();
    let runner = DeterministicRunner::timed(Duration::from_secs(10));
    let (mut exposure, checkpoint) = runner.start_and_recover(move |context| async move {
        let limits = VoterLimits {
            checkpoint_interval: if cut.checkpointing() {
                NZU64!(1)
            } else {
                voter_limits().checkpoint_interval
            },
            ..voter_limits()
        };
        let node = Node::start_with_limits(
            &context,
            seed,
            role,
            "durability_node",
            Attachments {
                application: application.clone(),
                journal_gates: Some(first_gates.clone()),
                test_hooks: Some(first_hooks.clone()),
                production_resolver: true,
                ..Attachments::default()
            },
            limits,
        )
        .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        let mut exposure = ExposureLedger::default();

        let mut gate = if cut.checkpointing() {
            application.permit_builds(1);
            let block = wait_for_slot_block(
                &context,
                &node,
                &mut data_rx,
                &mut exposure,
                first_expected.header().chain(),
                first_expected.header().height(),
                first_expected.signer(),
            )
            .await;
            assert_eq!(
                block, first_expected,
                "checkpoint setup changed the durable subject"
            );
            assert_eq!(
                slot_publications(
                    &first_hooks.durable_effects(),
                    first_expected.header().chain(),
                    first_expected.header().height(),
                ),
                exact_block_publication(
                    first_scenario.publication,
                    first_scenario.generation,
                    first_expected.clone(),
                )
            );
            match cut {
                DurabilityCut::BeforeCheckpoint => first_gates.arm_next_roll(),
                DurabilityCut::CheckpointBeforePrune => first_gates.arm_next_before_prune(),
                DurabilityCut::AfterSuccessfulPrune => first_gates.arm_next_after_prune(),
                _ => unreachable!("checkpoint cuts were filtered"),
            }
        } else {
            let gate = match cut {
                DurabilityCut::BeforeAppend => first_gates.arm_append_covering(
                    first_scenario.generation,
                    Cursor::new(first_scenario.publication.get()),
                ),
                DurabilityCut::AppendBeforeSync => first_gates.arm_start_sync_covering(
                    first_scenario.generation,
                    Cursor::new(first_scenario.publication.get()),
                ),
                DurabilityCut::SyncBeforeAck => first_gates.arm_after_sync_covering(
                    first_scenario.generation,
                    Cursor::new(first_scenario.publication.get()),
                ),
                _ => unreachable!("journal cuts were filtered"),
            };
            application.permit_builds(1);
            gate
        };
        select! {
            () = gate.wait_entered() => {},
            () = context.sleep(Duration::from_secs(2)) => {
                panic!("{cut:?} did not reach its exact storage coordinate");
            },
        }

        collect_data_exposure(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            Duration::from_millis(50),
        )
        .await;
        if !cut.checkpointing() {
            assert!(
                exposure
                    .block(
                        first_expected.header().chain(),
                        first_expected.header().height(),
                        first_expected.signer(),
                    )
                    .is_none(),
                "{cut:?} exposed a signed block before its barrier acknowledgement"
            );
            assert_eq!(
                first_hooks.durable_effects(),
                first_scenario.before_publication,
                "{cut:?} executed a durable effect outside the calibrated pre-release map"
            );
            assert!(
                slot_publications(
                    &first_hooks.durable_effects(),
                    first_expected.header().chain(),
                    first_expected.header().height(),
                )
                .is_empty(),
                "{cut:?} executed its publication before acknowledgement"
            );
        }
        node.crash(&context).await;
        drop(gate);
        exposure
    });

    recovered_application.permit_builds(1);
    let recovered_hooks = TestHooks::default();
    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let node = Node::start_with_attachments(
            &context,
            seed,
            role,
            "durability_node",
            Attachments {
                application: recovered_application,
                test_hooks: Some(recovered_hooks.clone()),
                production_resolver: true,
                ..Attachments::default()
            },
        )
        .await;
        if matches!(cut, DurabilityCut::CheckpointBeforePrune) {
            let partition = format!("node-{seed}-multimmit-machine-journal");
            let sections = context
                .scan(&partition)
                .await
                .expect("recovered journal partition remains readable");
            assert!(
                sections
                    .iter()
                    .all(|name| name.as_slice() != 0u64.to_be_bytes()),
                "startup did not complete checkpoint-covered pruning"
            );
        }
        let (_, mut data_rx) = node.peer(1, 0).await;
        let block = wait_for_slot_block(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            expected.header().chain(),
            expected.header().height(),
            expected.signer(),
        )
        .await;
        collect_data_exposure(
            &context,
            &node,
            &mut data_rx,
            &mut exposure,
            Duration::from_millis(50),
        )
        .await;

        let alternate = node.committee.signed_block(
            0,
            MockApplication::block_digest(Context::from(expected.header()), b"mock payload 2"),
        );
        if cut.durable_subject() {
            assert_eq!(
                block, expected,
                "{cut:?} forgot its durable signing subject"
            );
        } else {
            assert!(
                block == expected || block == alternate,
                "{cut:?} exposed a block outside the two independently constructed subjects"
            );
        }
        assert_eq!(
            exposure
                .blocks
                .iter()
                .filter(|((chain, height, signer), _)| {
                    *chain == expected.header().chain()
                        && *height == expected.header().height()
                        && *signer == expected.signer()
                })
                .count(),
            1,
            "{cut:?} exposed more than one artifact for the signing slot"
        );

        let publications = slot_publications(
            &recovered_hooks.durable_effects(),
            block.header().chain(),
            block.header().height(),
        );
        if cut.durable_subject() {
            assert_eq!(
                publications,
                exact_block_publication(scenario.publication, scenario.generation + 1, expected,),
                "{cut:?} did not reissue the exact durable obligation"
            );
        } else {
            let publication_entries = publications.iter().collect::<Vec<_>>();
            let [(id, attempts)] = publication_entries.as_slice() else {
                panic!(
                    "{cut:?} did not issue exactly one recovered slot obligation: {publications:?}"
                );
            };
            assert_eq!(attempts.len(), 1);
            assert_eq!(attempts[0].generation, scenario.generation + 1);
            assert_eq!(
                attempts[0].effect,
                DurableEffect::Broadcast(Arc::new(Artifact::TransactionBlock(block)))
            );
            assert!(id.get() >= scenario.publication.get());
        }
    });
}

#[test_traced]
fn durability_cut_matrix_reissues_and_retires_exact_obligations() {
    let seed = 80;
    let scenario = calibrate_durable_scenario(seed);
    for cut in [
        DurabilityCut::BeforeAppend,
        DurabilityCut::AppendBeforeSync,
        DurabilityCut::SyncBeforeAck,
        DurabilityCut::BeforeCheckpoint,
        DurabilityCut::CheckpointBeforePrune,
        DurabilityCut::AfterSuccessfulPrune,
    ] {
        exercise_durability_cut(cut, scenario.clone(), seed);
    }
}

fn da_certificate_publications(ledger: &DurableLedger) -> DurableLedger {
    ledger
        .iter()
        .filter(|(_, attempts)| {
            attempts.iter().any(|attempt| {
                matches!(
                    &attempt.effect,
                    DurableEffect::Broadcast(artifact)
                        if matches!(artifact.as_ref(), Artifact::DaCertificate(_))
                )
            })
        })
        .map(|(id, attempts)| (*id, attempts.clone()))
        .collect()
}

async fn wait_for_da_certificate(
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
                    &node.envelope_cfg(()),
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

#[test_traced]
fn successor_barrier_retains_installs_then_retires() {
    let seed = 81;
    let application = MockApplication::new();
    application.pause_building();
    let recovered_application = application.clone();
    let first_hooks = TestHooks::default();
    let recovered_hooks = TestHooks::default();
    let runner = DeterministicRunner::timed(Duration::from_secs(10));
    let ((predecessor, successor, generation, header), checkpoint) =
        runner.start_and_recover(move |context| async move {
            let node = Node::start_with_attachments(
                &context,
                seed,
                Role::Validator(Participant::new(0)),
                "successor_node",
                Attachments {
                    application: application.clone(),
                    test_hooks: Some(first_hooks.clone()),
                    production_resolver: true,
                    ..Attachments::default()
                },
            )
            .await;
            let (mut data_tx, mut data_rx) = node.peer(2, 0).await;
            application.permit_builds(1);
            let mut exposure = ExposureLedger::default();
            let block = wait_for_slot_block(
                &context,
                &node,
                &mut data_rx,
                &mut exposure,
                ChainId::new(0),
                Height::new(1),
                Participant::new(0),
            )
            .await;
            let header = block.header().clone();
            let first = slot_publications(
                &first_hooks.durable_effects(),
                header.chain(),
                header.height(),
            );
            let first_entries = first.iter().collect::<Vec<_>>();
            let [(predecessor, attempts)] = first_entries.as_slice() else {
                panic!("the signed block did not create one exact obligation: {first:?}");
            };
            let [attempt] = attempts.as_slice() else {
                panic!("the signed-block obligation executed more than once: {attempts:?}");
            };
            assert_eq!(
                attempt.effect,
                DurableEffect::Broadcast(Arc::new(Artifact::TransactionBlock(block.clone())))
            );
            let generation = attempt.generation;
            let predecessor = **predecessor;
            let votes = (0..node.committee.codec().da_quorum())
                .map(|signer| node.committee.da_vote(signer, header.clone()))
                .collect::<Vec<_>>();
            let certificate = node
                .committee
                .verifier
                .assemble_da_certificate(&votes, &Sequential)
                .expect("a quorum of shares recovers the DA successor");
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                    certificate,
                ))
                .encode(),
                false,
            );
            let (successor, successor_attempt) =
                wait_for_live_publication(&context, &first_hooks, |effect| {
                    matches!(effect,
                    DurableEffect::Broadcast(artifact)
                        if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                            if certificate.header() == &header))
                })
                .await;
            assert!(matches!(
                &successor_attempt.effect,
                DurableEffect::Broadcast(artifact)
                    if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                        if certificate.header() == &header)
            ));
            wait_for_retirement_ack(&context, &first_hooks, predecessor).await;

            let events = first_hooks.events();
            let installed = events
                .iter()
                .position(
                    |event| matches!(event, TestEvent::Installed { id, .. } if *id == successor),
                )
                .expect("the DA successor was installed during acknowledgement service");
            let retired = events
                .iter()
                .position(
                    |event| matches!(event, TestEvent::Retired(ids) if ids.contains(&predecessor)),
                )
                .expect("the acknowledged predecessor was retired");
            assert!(
                installed < retired,
                "the predecessor retired before its successor was installed"
            );

            node.crash(&context).await;
            (predecessor, successor, generation, header)
        });

    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let node = Node::start_with_attachments(
            &context,
            seed,
            Role::Validator(Participant::new(0)),
            "successor_node",
            Attachments {
                application: recovered_application,
                test_hooks: Some(recovered_hooks.clone()),
                production_resolver: true,
                ..Attachments::default()
            },
        )
        .await;
        let (_, mut data_rx) = node.peer(2, 0).await;
        wait_for_da_certificate(&context, &node, &mut data_rx, &header).await;
        let recovered = da_certificate_publications(&recovered_hooks.durable_effects());
        let recovered_entries = recovered.iter().collect::<Vec<_>>();
        let [(recovered_id, attempts)] = recovered_entries.as_slice() else {
            panic!("recovery did not reissue one exact DA successor: {recovered:?}");
        };
        assert_eq!(**recovered_id, successor);
        let [attempt] = attempts.as_slice() else {
            panic!("recovery executed the DA successor more than once");
        };
        assert_eq!(attempt.generation, generation + 1);
        assert!(matches!(
            &attempt.effect,
            DurableEffect::Broadcast(artifact)
                if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                    if certificate.header() == &header)
        ));
        assert!(
            !recovered_hooks.durable_effects().contains_key(&predecessor),
            "recovery reissued the retired predecessor"
        );
    });
}

#[derive(Clone, Copy, Debug)]
enum ActorDischargeFamily {
    BlockCertifiedAtLeast,
    VoteCertifiedAtLeast,
    CertificateSupersededAbove,
    ExitReplacedAfter,
    ViewRetired,
}

impl ActorDischargeFamily {
    const ALL: [Self; 5] = [
        Self::BlockCertifiedAtLeast,
        Self::VoteCertifiedAtLeast,
        Self::CertificateSupersededAbove,
        Self::ExitReplacedAfter,
        Self::ViewRetired,
    ];

    const fn role(self) -> Role {
        match self {
            Self::ExitReplacedAfter => Role::Observer,
            Self::BlockCertifiedAtLeast
            | Self::VoteCertifiedAtLeast
            | Self::CertificateSupersededAbove
            | Self::ViewRetired => Role::Validator(Participant::new(0)),
        }
    }
}

#[derive(Clone)]
enum ActorDischargeSuccessor {
    DaCertificate(TransactionBlockHeader<Sha256Digest>),
    Nullification(View),
    FinalityFloor(View),
}

#[derive(Clone)]
struct PreparedActorDischarge {
    predecessor: EffectId,
    generation: u64,
    successor: ActorDischargeSuccessor,
}

async fn wait_for_live_publication(
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

async fn wait_for_publication_ack(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    publication: EffectId,
) -> BarrierAck {
    let deadline = context.current() + Duration::from_secs(2);
    loop {
        if let Some(ack) = hooks.events().iter().find_map(|event| match event {
            TestEvent::Acknowledged { ack, .. } if ack.cursor().get() >= publication.get() => {
                Some(*ack)
            }
            _ => None,
        }) {
            return ack;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(deadline) => {
                panic!("publication {publication:?} was not acknowledged");
            },
        }
    }
}

async fn wait_for_later_ack(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    cursor: Cursor,
) {
    let deadline = context.current() + Duration::from_secs(2);
    loop {
        if hooks.events().iter().any(
            |event| matches!(event, TestEvent::Acknowledged { ack, .. } if ack.cursor() > cursor),
        ) {
            return;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(deadline) => {
                panic!("no acknowledgement advanced beyond {cursor:?}");
            },
        }
    }
}

async fn wait_for_retirement_ack(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    predecessor: EffectId,
) -> BarrierAck {
    let deadline = context.current() + Duration::from_secs(2);
    loop {
        let events = hooks.events();
        let acknowledgement = events.iter().position(|event| {
            matches!(event, TestEvent::Acknowledged { retired, .. }
                if retired.contains(&predecessor))
        });
        let retirement = events.iter().position(
            |event| matches!(event, TestEvent::Retired(retired) if retired.contains(&predecessor)),
        );
        if let (Some(acknowledgement), Some(retirement)) = (acknowledgement, retirement) {
            assert!(
                acknowledgement < retirement,
                "publication retired before its exact acknowledgement: {events:?}"
            );
            let TestEvent::Acknowledged { ack, .. } = events[acknowledgement] else {
                unreachable!("the position was selected from acknowledgement events");
            };
            return ack;
        }
        select! {
            () = context.sleep(Duration::from_millis(10)) => {},
            () = context.sleep_until(deadline) => {
                panic!("publication {predecessor:?} was not retired: {events:?}");
            },
        }
    }
}

fn assert_exact_journal_ack(gates: &TestGates, ack: BarrierAck) -> JournalPoint {
    let point = gates
        .appends()
        .into_iter()
        .find(|point| {
            point.barrier == ack.barrier()
                && point.generation == ack.generation()
                && point.result == ack.cursor()
        })
        .unwrap_or_else(|| panic!("acknowledgement did not name an exact append: {ack:?}"));
    assert!(point.previous.get() < point.result.get());
    point
}

async fn prepare_actor_discharge(
    context: &DeterministicContext,
    node: &Node,
    application: &MockApplication,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    family: ActorDischargeFamily,
) -> PreparedActorDischarge {
    match family {
        ActorDischargeFamily::BlockCertifiedAtLeast
        | ActorDischargeFamily::VoteCertifiedAtLeast
        | ActorDischargeFamily::CertificateSupersededAbove => {
            let (mut data_tx, mut data_rx) = node.peer(1, 0).await;
            application.permit_builds(1);
            let mut exposure = ExposureLedger::default();
            let block = wait_for_slot_block(
                context,
                node,
                &mut data_rx,
                &mut exposure,
                ChainId::new(0),
                Height::new(1),
                Participant::new(0),
            )
            .await;
            let header = block.header().clone();
            let (block_id, block_attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect, DurableEffect::Broadcast(artifact)
                    if matches!(artifact.as_ref(), Artifact::TransactionBlock(actual)
                        if actual.header() == &header))
            })
            .await;
            let (vote_id, vote_attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect, DurableEffect::Send(request)
                    if matches!(request.artifact().as_ref(), Artifact::DaVote(vote)
                        if vote.header() == &header))
            })
            .await;
            assert_eq!(block_attempt.generation, vote_attempt.generation);

            if !matches!(family, ActorDischargeFamily::CertificateSupersededAbove) {
                let predecessor = if matches!(family, ActorDischargeFamily::BlockCertifiedAtLeast) {
                    block_id
                } else {
                    vote_id
                };
                return PreparedActorDischarge {
                    predecessor,
                    generation: block_attempt.generation,
                    successor: ActorDischargeSuccessor::DaCertificate(header),
                };
            }

            let votes = (0..node.committee.codec().da_quorum())
                .map(|signer| node.committee.da_vote(signer, header.clone()))
                .collect::<Vec<_>>();
            let certificate = node
                .committee
                .verifier
                .assemble_da_certificate(&votes, &Sequential)
                .expect("a quorum recovers the same-height certificate predecessor");
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                    certificate,
                ))
                .encode(),
                false,
            );
            let (certificate_id, certificate_attempt) =
                wait_for_live_publication(context, hooks, |effect| {
                    matches!(effect, DurableEffect::Broadcast(artifact)
                        if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                            if certificate.header() == &header))
                })
                .await;
            wait_for_publication_ack(context, hooks, certificate_id).await;
            assert!(
                hooks.live_publications().contains(&certificate_id),
                "a certificate retired at its own height"
            );
            assert!(
                !hooks.live_publications().contains(&block_id)
                    && !hooks.live_publications().contains(&vote_id),
                "the same-height certificate did not replace the block and vote"
            );

            let parent = header.block_ref::<Sha256>();
            let next_header = TransactionBlockHeader::new(
                node.committee.config.epoch(),
                header.chain(),
                Height::new(2),
                parent.digest(),
                Sha256::hash(&[b"strictly higher certificate payload"]),
            )
            .expect("height two extends the certified predecessor");
            let next_block = node.committee.signers[0]
                .sign_transaction_block(next_header.clone())
                .expect("the producer signs its height-two block");
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::Block(next_block))
                    .encode(),
                false,
            );
            wait_for_live_publication(context, hooks, |effect| {
                matches!(effect, DurableEffect::Send(request)
                    if matches!(request.artifact().as_ref(), Artifact::DaVote(vote)
                        if vote.header() == &next_header))
            })
            .await;

            PreparedActorDischarge {
                predecessor: certificate_id,
                generation: certificate_attempt.generation,
                successor: ActorDischargeSuccessor::DaCertificate(next_header),
            }
        }
        ActorDischargeFamily::ExitReplacedAfter => {
            let (mut certificates_tx, _) = node.peer(1, 2).await;
            let view = View::new(1);
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    node.committee.nullification(view.get()),
                ))
                .encode(),
                true,
            );
            let (predecessor, attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect, DurableEffect::Broadcast(artifact)
                    if matches!(artifact.as_ref(), Artifact::Nullification(certificate)
                        if certificate.view() == view))
            })
            .await;
            wait_for_publication_ack(context, hooks, predecessor).await;
            wait_for_later_ack(context, hooks, Cursor::new(predecessor.get())).await;
            PreparedActorDischarge {
                predecessor,
                generation: attempt.generation,
                successor: ActorDischargeSuccessor::Nullification(View::new(2)),
            }
        }
        ActorDischargeFamily::ViewRetired => {
            let (_, mut consensus_rx) = node.peer(1, 1).await;
            let deadline = context.current() + Duration::from_secs(2);
            let view = loop {
                let (_, bytes) = select! {
                    result = consensus_rx.recv() => result.expect("network stays up"),
                    () = context.sleep_until(deadline) => {
                        panic!("the timeout did not publish an own-message batch");
                    },
                };
                let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                    bytes,
                    &node.envelope_cfg(node.committee.codec()),
                )
                .expect("canonical consensus envelope");
                match envelope.into_payload() {
                    ConsensusMessage::NoVote(message) => break message.view(),
                    ConsensusMessage::Nullify(message) => break message.view(),
                    _ => {}
                }
            };
            let (predecessor, attempt) = wait_for_live_publication(context, hooks, |effect| {
                matches!(effect, DurableEffect::BroadcastBatch(artifacts)
                if artifacts.iter().all(|artifact| match artifact.as_ref() {
                    Artifact::NoVote(message) => message.view() == view,
                    Artifact::Nullify(message) => message.view() == view,
                    _ => false,
                }))
            })
            .await;
            PreparedActorDischarge {
                predecessor,
                generation: attempt.generation,
                successor: ActorDischargeSuccessor::FinalityFloor(View::new(view.get() + 1)),
            }
        }
    }
}

async fn submit_actor_discharge_successor(node: &Node, successor: &ActorDischargeSuccessor) {
    match successor {
        ActorDischargeSuccessor::DaCertificate(header) => {
            let (mut data_tx, _) = node.peer(2, 0).await;
            let votes = (0..node.committee.codec().da_quorum())
                .map(|signer| node.committee.da_vote(signer, header.clone()))
                .collect::<Vec<_>>();
            let certificate = node
                .committee
                .verifier
                .assemble_da_certificate(&votes, &Sequential)
                .expect("a quorum recovers the DA discharge successor");
            data_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                    certificate,
                ))
                .encode(),
                false,
            );
        }
        ActorDischargeSuccessor::Nullification(view) => {
            let (mut certificates_tx, _) = node.peer(2, 2).await;
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    node.committee.nullification(view.get()),
                ))
                .encode(),
                true,
            );
        }
        ActorDischargeSuccessor::FinalityFloor(view) => {
            let (mut certificates_tx, _) = node.peer(2, 2).await;
            certificates_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(CertificateMessage::Lqc(node.committee.lqc(view.get())))
                    .encode(),
                true,
            );
        }
    }
}

async fn wait_for_successor_publication(
    context: &DeterministicContext,
    hooks: &TestHooks<MinPk, Sha256Digest>,
    successor: &ActorDischargeSuccessor,
) -> Option<EffectId> {
    match successor {
        ActorDischargeSuccessor::DaCertificate(header) => Some(
            wait_for_live_publication(context, hooks, |effect| {
                matches!(effect, DurableEffect::Broadcast(artifact)
                    if matches!(artifact.as_ref(), Artifact::DaCertificate(certificate)
                        if certificate.header() == header))
            })
            .await
            .0,
        ),
        ActorDischargeSuccessor::Nullification(view) => Some(
            wait_for_live_publication(context, hooks, |effect| {
                matches!(effect, DurableEffect::Broadcast(artifact)
                    if matches!(artifact.as_ref(), Artifact::Nullification(certificate)
                        if certificate.view() == *view))
            })
            .await
            .0,
        ),
        ActorDischargeSuccessor::FinalityFloor(_) => None,
    }
}

fn assert_pre_ack_publications(
    hooks: &TestHooks<MinPk, Sha256Digest>,
    predecessor: EffectId,
    successor: Option<EffectId>,
) {
    let live = hooks.live_publications();
    assert!(
        live.contains(&predecessor),
        "predecessor retired before its covering BarrierAck: {:?}",
        hooks.events()
    );
    if let Some(successor) = successor {
        assert!(
            live.contains(&successor),
            "replayable successor was not installed before its BarrierAck"
        );
    }
    assert!(
        !hooks.events().iter().any(|event| {
            matches!(event, TestEvent::Acknowledged { retired, .. }
                if retired.contains(&predecessor))
        }),
        "the exact retiring acknowledgement crossed the sync gate"
    );
}

#[test_traced]
fn all_publication_discharge_families_wait_for_their_exact_barrier_ack() {
    for (index, family) in ActorDischargeFamily::ALL.into_iter().enumerate() {
        let seed = 90 + index as u64;
        DeterministicRunner::timed(Duration::from_secs(15)).start(move |context| async move {
            let application = MockApplication::new();
            application.pause_building();
            let gates = TestGates::default();
            let hooks = TestHooks::default();
            let node = Node::start_with_attachments(
                &context,
                seed,
                family.role(),
                "publication_ack_node",
                Attachments {
                    application: application.clone(),
                    journal_gates: Some(gates.clone()),
                    test_hooks: Some(hooks.clone()),
                    production_resolver: true,
                    ..Attachments::default()
                },
            )
            .await;
            let prepared =
                prepare_actor_discharge(&context, &node, &application, &hooks, family).await;

            let mut gate = gates.arm_next_after_sync();
            submit_actor_discharge_successor(&node, &prepared.successor).await;
            select! {
                () = gate.wait_entered() => {},
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("{family:?} did not reach its successor sync cut");
                },
            }
            let successor =
                wait_for_successor_publication(&context, &hooks, &prepared.successor).await;
            assert_pre_ack_publications(&hooks, prepared.predecessor, successor);

            gate.release();
            let ack = wait_for_retirement_ack(&context, &hooks, prepared.predecessor).await;
            let point = assert_exact_journal_ack(&gates, ack);
            if let Some(successor) = successor {
                assert!(
                    point.previous.get() < successor.get() && successor.get() <= point.result.get(),
                    "{family:?} retired on a barrier that did not cover its successor"
                );
                assert!(hooks.live_publications().contains(&successor));
            }
            assert!(!hooks.live_publications().contains(&prepared.predecessor));
        });
    }
}

#[test_traced]
fn resolver_retention_obeys_its_exact_durability_boundary() {
    let seed = 110;
    DeterministicRunner::timed(Duration::from_secs(10)).start(move |context| async move {
        let application = MockApplication::new();
        application.pause_building();
        let gates = TestGates::default();
        let hooks = TestHooks::default();
        let node = Node::start_with_attachments(
            &context,
            seed,
            Role::Observer,
            "resolver_retention_node",
            Attachments {
                application,
                journal_gates: Some(gates.clone()),
                test_hooks: Some(hooks.clone()),
                production_resolver: true,
                ..Attachments::default()
            },
        )
        .await;
        let (mut certificates_tx, _) = node.peer(1, 2).await;

        let first_view = View::new(1);
        let mut first_sync = gates.arm_next_after_sync();
        certificates_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                node.committee.nullification(first_view.get()),
            ))
            .encode(),
            true,
        );
        select! {
            () = first_sync.wait_entered() => {},
            () = context.sleep(Duration::from_secs(2)) => {
                panic!("the first nullification did not reach its post-sync cut");
            },
        }
        let staged_barrier = hooks.events().iter().find_map(|event| match event {
            TestEvent::Retained {
                object: resolver::Served::Nullification(certificate),
                boundary: RetentionBoundary::Staged(barrier),
            } if certificate.view() == first_view => Some(*barrier),
            _ => None,
        });
        let staged_barrier = staged_barrier
            .expect("a forwarded proof enters serving custody while its barrier is staged");
        assert!(
            !hooks.events().iter().any(|event| {
                matches!(event, TestEvent::Retained {
                    object: resolver::Served::Nullification(certificate),
                    boundary: RetentionBoundary::Acknowledged(_),
                } if certificate.view() == first_view)
            }),
            "acknowledgement-gated retention crossed the post-sync response gate"
        );
        first_sync.release();

        let (predecessor, _) = wait_for_live_publication(&context, &hooks, |effect| {
            matches!(effect, DurableEffect::Broadcast(artifact)
                if matches!(artifact.as_ref(), Artifact::Nullification(certificate)
                    if certificate.view() == first_view))
        })
        .await;
        let publication_ack = wait_for_publication_ack(&context, &hooks, predecessor).await;
        assert_eq!(publication_ack.barrier(), staged_barrier);

        let lqc_view = View::new(3);
        let mut lqc_sync = gates.arm_after_sync_retiring(predecessor);
        certificates_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::Lqc(node.committee.lqc(lqc_view.get())))
                .encode(),
            true,
        );
        select! {
            () = lqc_sync.wait_entered() => {},
            () = context.sleep(Duration::from_secs(2)) => {
                panic!("the L-QC did not reach its post-sync cut");
            },
        }
        assert!(
            !hooks.events().iter().any(|event| {
                matches!(event, TestEvent::Retained {
                    object: resolver::Served::Lqc(certificate),
                    ..
                } if certificate.view() == lqc_view)
            }),
            "an L-QC entered serving custody before its durable acknowledgement"
        );
        let lqc_point = *gates
            .appends()
            .last()
            .expect("the post-sync gate covers one appended L-QC transition");
        lqc_sync.release();

        let deadline = context.current() + Duration::from_secs(2);
        let retention_ack = loop {
            if let Some(ack) = hooks.events().iter().find_map(|event| match event {
                TestEvent::Retained {
                    object: resolver::Served::Lqc(certificate),
                    boundary: RetentionBoundary::Acknowledged(ack),
                } if certificate.view() == lqc_view => Some(*ack),
                _ => None,
            }) {
                break ack;
            }
            select! {
                () = context.sleep(Duration::from_millis(10)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("the acknowledged L-QC never entered serving custody");
                },
            }
        };
        assert_eq!(retention_ack.barrier(), lqc_point.barrier);
        assert_eq!(retention_ack.cursor(), lqc_point.result);
    });
}

#[test_traced]
fn crash_after_successor_append_releases_only_recovered_successors() {
    for (index, family) in ActorDischargeFamily::ALL.into_iter().enumerate() {
        let seed = 100 + index as u64;
        let application = MockApplication::new();
        application.pause_building();
        let recovered_application = application.clone();
        let first_gates = TestGates::default();
        let first_hooks = TestHooks::default();
        let runner = DeterministicRunner::timed(Duration::from_secs(15));
        let ((prepared, successor), checkpoint) =
            runner.start_and_recover(move |context| async move {
                let node = Node::start_with_attachments(
                    &context,
                    seed,
                    family.role(),
                    "publication_recovery_node",
                    Attachments {
                        application: application.clone(),
                        journal_gates: Some(first_gates.clone()),
                        test_hooks: Some(first_hooks.clone()),
                        production_resolver: true,
                        ..Attachments::default()
                    },
                )
                .await;
                let prepared =
                    prepare_actor_discharge(&context, &node, &application, &first_hooks, family)
                        .await;
                let mut gate = first_gates.arm_after_sync_retiring(prepared.predecessor);
                submit_actor_discharge_successor(&node, &prepared.successor).await;
                let successor = if matches!(
                    &prepared.successor,
                    ActorDischargeSuccessor::FinalityFloor(_)
                ) {
                    None
                } else {
                    wait_for_successor_publication(&context, &first_hooks, &prepared.successor)
                        .await
                };
                select! {
                    () = gate.wait_entered() => {},
                    () = context.sleep(Duration::from_secs(2)) => {
                        panic!("{family:?} did not reach its exact crash-after-sync cut");
                    },
                }
                assert_pre_ack_publications(&first_hooks, prepared.predecessor, successor);
                node.crash(&context).await;
                drop(gate);
                (prepared, successor)
            });

        let recovered_gates = TestGates::default();
        let recovered_hooks = TestHooks::default();
        let mut generation_gate = recovered_gates.arm_next_after_sync();
        DeterministicRunner::from(checkpoint).start(move |context| async move {
            let mut start = Box::pin(Node::start_with_attachments(
                &context,
                seed,
                family.role(),
                "publication_recovery_node",
                Attachments {
                    application: recovered_application,
                    journal_gates: Some(recovered_gates.clone()),
                    test_hooks: Some(recovered_hooks.clone()),
                    production_resolver: true,
                    ..Attachments::default()
                },
            ));
            select! {
                () = generation_gate.wait_entered() => {},
                _node = &mut start => {
                    panic!("{family:?} became ready before recovery generation ack");
                },
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("{family:?} did not stage its recovery generation");
                },
            }
            assert!(
                recovered_hooks.live_publications().is_empty(),
                "recovery exposed a publication before its generation ack"
            );
            assert!(
                !recovered_hooks.events().iter().any(|event| {
                    matches!(event, TestEvent::Retired(retired)
                        if retired.contains(&prepared.predecessor))
                }),
                "recovery retired a volatile predecessor before its generation ack"
            );
            let generation_point = recovered_gates
                .appends()
                .into_iter()
                .last()
                .expect("recovery appended its generation advance");
            assert_eq!(generation_point.generation, prepared.generation);
            generation_gate.release();
            let _node = start.await;

            let generation_ack = recovered_hooks
                .events()
                .iter()
                .find_map(|event| match event {
                    TestEvent::Acknowledged { ack, .. }
                        if ack.barrier() == generation_point.barrier =>
                    {
                        Some(*ack)
                    }
                    _ => None,
                })
                .expect("startup waited for the recovery generation ack");
            assert_eq!(
                generation_ack,
                BarrierAck::new(
                    generation_point.barrier,
                    generation_point.generation,
                    generation_point.result,
                )
            );
            assert!(
                !recovered_hooks
                    .live_publications()
                    .contains(&prepared.predecessor)
            );
            if let Some(successor) = successor {
                let recovered =
                    wait_for_successor_publication(&context, &recovered_hooks, &prepared.successor)
                        .await;
                assert_eq!(recovered, Some(successor));
                let attempts = recovered_hooks.durable_effects();
                assert_eq!(attempts[&successor].len(), 1);
                assert_eq!(attempts[&successor][0].generation, prepared.generation + 1);
            }
        });
    }
}

#[test_traced]
fn mutable_journal_sync_failure_stops_production_engine() {
    let seed = 82;
    DeterministicRunner::timed(Duration::from_secs(10)).start(move |context| async move {
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let me = committee.identities[0].clone();
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;
        let mut planes = Vec::new();
        for channel in 0..4u64 {
            planes.push(
                oracle
                    .control(me.clone())
                    .register(channel, QUOTA)
                    .await
                    .unwrap(),
            );
        }
        let mut planes = planes.into_iter();
        let application = MockApplication::new();
        application.pause_building();
        let role = Role::Validator(Participant::new(0));
        let engine_context = context.child("storage_failure_engine");
        let task_prefix = engine_context.name().label;
        let engine = Engine::new(
            engine_context,
            EngineConfig {
                profile: profile(&committee, role),
                scheme: committee.signers[0].clone(),
                automaton: application.clone(),
                relay: application.clone(),
                reporter: TestReporter::default(),
                strategy: Sequential,
                blocker: NoopBlocker,
                partition_prefix: "storage-failure-engine".to_owned(),
                mailbox_size: NonZeroUsize::new(64).unwrap(),
            },
        );
        let mut running = Box::pin(engine.start(
            planes.next().unwrap(),
            planes.next().unwrap(),
            planes.next().unwrap(),
            planes.next().unwrap(),
        ))
        .await
        .expect("the production engine starts");
        assert!(running.ready().await, "the production engine becomes ready");
        assert!(
            count_running_tasks(&context, &task_prefix) > 0,
            "the production engine has no supervised tasks before fault injection"
        );
        let inspector = running.inspector();

        *context.storage_fault_config().write() = FaultConfig {
            sync_rate: Some(1.0),
            ..FaultConfig::default()
        };
        application.permit_builds(1);

        let mut joined = Box::pin(running.join());
        select! {
            () = &mut joined => {},
            () = context.sleep(Duration::from_secs(2)) => {
                panic!("the engine root did not stop after the mutable journal failure");
            },
        }
        assert!(
            inspector.inspect().await.is_none(),
            "the failed engine left its diagnostic mailbox open"
        );
        context.sleep(Duration::from_millis(1)).await;
        assert_eq!(
            count_running_tasks(&context, &task_prefix),
            0,
            "the joined engine left supervised descendants running"
        );
    });
}

#[test_traced]
fn dependency_blocked_artifact_is_not_reported_before_admission() {
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    executor.start(|context| async move {
        let reporter = TestReporter::with_feedback(Feedback::Ok);
        let mut node = Node::start_with_attachments(
            &context,
            51,
            Role::Observer,
            "primary",
            Attachments {
                reporter: reporter.clone(),
                ..Attachments::default()
            },
        )
        .await;
        let (mut consensus_tx, _) = node.peer(1, 1).await;

        let leader = node.committee.leader_block(1);
        let vote = node.committee.vote(1, &leader);
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Vote(vote)).encode(),
            true,
        );

        let deadline = context.current() + Duration::from_secs(2);
        loop {
            if node.inspect().await.waiting_artifacts() == 1 {
                break;
            }
            select! {
                () = context.sleep(Duration::from_millis(10)) => {},
                () = context.sleep_until(deadline) => {
                    panic!("vote never entered the dependency index");
                },
            }
        }

        let activities = reporter.activities();
        assert!(
            activities.is_empty(),
            "dependency-blocked activity was reported before admission: {activities:?}"
        );
    });
}

#[test_traced]
fn closed_relay_retries_exact_commitment_without_publishing_header() {
    let executor = DeterministicRunner::timed(Duration::from_secs(10));
    executor.start(|context| async move {
        let relay = TestRelay::with_feedback(Feedback::Closed);
        let node = Node::start_with_attachments(
            &context,
            52,
            Role::Validator(Participant::new(0)),
            "primary",
            Attachments {
                relay: relay.clone(),
                ..Attachments::default()
            },
        )
        .await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        select! {
            header = next_block(&node, &mut data_rx) => {
                panic!("closed relay allowed transaction header publication: {header:?}");
            },
            () = context.sleep(Duration::from_secs(1)) => {},
        }

        let broadcasts = relay.broadcasts();
        assert!(
            broadcasts.len() >= 2,
            "closed relay was not retried: {broadcasts:?}"
        );
        assert!(
            broadcasts
                .iter()
                .all(|(_, feedback)| *feedback == Feedback::Closed),
            "relay returned unexpected feedback: {broadcasts:?}"
        );
        let commitments = broadcasts
            .iter()
            .map(|(commitment, _)| *commitment)
            .collect::<BTreeSet<_>>();
        assert!(
            commitments.iter().all(|commitment| {
                broadcasts
                    .iter()
                    .filter(|(attempted, _)| attempted == commitment)
                    .count()
                    >= 2
            }),
            "a durable Relay obligation was not retried exactly: {broadcasts:?}"
        );
    });
}

#[test_traced]
fn accepted_relay_attempt_precedes_exact_header_publication() {
    for (seed, feedback) in [(53, Feedback::Ok), (54, Feedback::Backoff)] {
        let executor = DeterministicRunner::timed(Duration::from_secs(10));
        executor.start(move |context| async move {
            let relay = TestRelay::with_feedback(feedback);
            let node = Node::start_with_attachments(
                &context,
                seed,
                Role::Validator(Participant::new(0)),
                "primary",
                Attachments {
                    relay: relay.clone(),
                    ..Attachments::default()
                },
            )
            .await;
            let (_, mut data_rx) = node.peer(1, 0).await;

            let header = select! {
                header = next_block(&node, &mut data_rx) => header,
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("accepted relay attempt did not publish a header");
                },
            };

            let broadcasts = relay.broadcasts();
            let Some((_, returned)) = broadcasts
                .iter()
                .find(|(commitment, _)| *commitment == header.commitment())
            else {
                panic!("header was published before its exact relay attempt");
            };
            assert_eq!(*returned, feedback);
        });
    }
}

#[test_traced]
fn publication_retries_until_semantic_supersession() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = Node::start(
            &context,
            42,
            Role::Validator(Participant::new(0)),
            "primary",
        )
        .await;
        let (mut data_tx, mut data_rx) = node.peer(1, 0).await;

        // The exact block is retried across the backoff schedule. The producer keeps building
        // within its window while work is pending, so later frames may carry newer blocks; the
        // retry is the frame that repeats this exact header.
        let header = next_block(&node, &mut data_rx).await;
        let mut retried = false;
        for _ in 0..8 {
            let again = next_block(&node, &mut data_rx).await;
            if again == header {
                retried = true;
                break;
            }
        }
        assert!(retried, "the exact block is retried until it is superseded");

        // An admitted DA certificate for the exact header supersedes the block publication.
        let votes = (0..node.committee.codec().da_quorum())
            .map(|signer| node.committee.da_vote(signer, header.clone()))
            .collect::<Vec<_>>();
        let certificate = node
            .committee
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .expect("quorum of shares recovers");
        data_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::<MinPk, Sha256Digest>::DaCertificate(
                certificate,
            ))
            .encode(),
            false,
        );

        // Let the certificate be admitted and the in-flight frames settle. The producer keeps
        // building newer blocks, so supersession is about this exact header, not about the outbox
        // emptying.
        context.sleep(Duration::from_secs(2)).await;
        let (_, mut settled_rx) = node.peer(2, 0).await;
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            select! {
                result = settled_rx.recv() => {
                    let (_, bytes) = result.expect("network stays up");
                    let envelope =
                        Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                            bytes,
                            &node.envelope_cfg(()),
                        )
                        .expect("canonical envelope");
                    if let DataMessage::Block(sent) = envelope.into_payload() {
                        assert_ne!(
                            sent.header(),
                            &header,
                            "superseded block kept publishing"
                        );
                    }
                },
                () = context.sleep_until(deadline) => break,
            }
        }
    });
}

#[test_traced]
fn reporter_feedback_does_not_block_remote_block_admission() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let reporter = TestReporter::with_feedback(Feedback::Closed);
        let application = MockApplication::new();
        application.pause_building();
        let node = Node::start_with_attachments(
            &context,
            43,
            Role::Validator(Participant::new(0)),
            "primary",
            Attachments {
                application,
                reporter: reporter.clone(),
                ..Attachments::default()
            },
        )
        .await;
        // The producer of chain one sends its block; the DA share must come back to it alone.
        let (mut peer_tx, mut peer_data_rx) = node.peer(1, 0).await;
        let (_, mut other_rx) = node.peer(2, 0).await;

        let commitment = Sha256::hash(&[b"remote payload"]);
        let block = node.committee.signed_block(1, commitment);
        peer_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(DataMessage::Block(block.clone())).encode(),
            false,
        );

        // The producer receives an attributed DA share from participant zero.
        loop {
            let (_, bytes) = peer_data_rx.recv().await.expect("network stays up");
            let envelope = Envelope::<DataMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(()),
            )
            .expect("canonical envelope");
            if let DataMessage::DaVote(vote) = envelope.into_payload() {
                assert_eq!(vote.signer().get(), 0);
                assert_eq!(vote.header().commitment(), commitment);
                assert!(node.committee.verifier.verify_da_vote(&vote));
                break;
            }
        }
        let artifact = Artifact::TransactionBlock(block);
        let accepted = Activity::ProtocolAccepted {
            artifact_id: artifact.id::<Sha256>(),
            artifact: Arc::new(artifact),
        };
        let activities = reporter.activities();
        assert!(
            activities.contains(&accepted),
            "admitted block was not reported: {activities:?}"
        );

        // The share is a point-to-point send: another peer never sees it.
        select! {
            result = other_rx.recv() => {
                panic!("targeted send leaked to another peer: {result:?}");
            },
            () = context.sleep(Duration::from_millis(500)) => {},
        }
    });
}

#[test_traced]
fn timeout_signs_and_broadcasts_an_atomic_novote_nullify_batch() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let node = Node::start(
            &context,
            44,
            Role::Validator(Participant::new(0)),
            "primary",
        )
        .await;
        let (mut consensus_tx, mut consensus_rx) = node.peer(1, 1).await;
        let (_, mut certificate_rx) = node.peer(1, 2).await;

        // No leader traffic arrives, so the view timer fires and the batch publishes.
        let mut saw_novote = false;
        let mut saw_nullify = false;
        let mut nullified_view = None;
        let deadline = context.current() + Duration::from_secs(1);
        while !(saw_novote && saw_nullify) {
            let (_, bytes) = select! {
                result = consensus_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => {
                    panic!("timeout did not emit the atomic NoVote/Nullify batch");
                },
            };
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            match envelope.into_payload() {
                ConsensusMessage::NoVote(vote) => {
                    assert!(node.committee.verifier.verify_novote(&vote));
                    saw_novote = true;
                }
                ConsensusMessage::Nullify(nullify) => {
                    assert!(node.committee.verifier.verify_nullify(&nullify));
                    nullified_view = Some(nullify.view().get());
                    saw_nullify = true;
                }
                _ => {}
            }
        }

        // The remaining threshold shares recover and durably forward one certificate.
        let view = nullified_view.expect("the timeout emitted a nullify share");
        for signer in 1..node.committee.codec().nullification_quorum() {
            consensus_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(ConsensusMessage::<MinPk, Sha256Digest>::Nullify(
                    node.committee.nullify(signer, view),
                ))
                .encode(),
                true,
            );
        }
        let deadline = context.current() + Duration::from_secs(1);
        loop {
            let (_, bytes) = select! {
                result = certificate_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => {
                    panic!("nullification shares did not produce a certificate");
                },
            };
            let envelope = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical envelope");
            if matches!(
                envelope.into_payload(),
                CertificateMessage::Nullification(_)
            ) {
                break;
            }
        }
        // The certificate leaves the process when its forwarding stages, so the durable
        // counter lands on the barrier acknowledgement that follows the wire message.
        let deadline = context.current() + Duration::from_secs(1);
        let metrics = loop {
            let metrics = context.encode();
            if metrics
                .lines()
                .any(|line| line == "primary_voter_nullifications_total 1")
            {
                break metrics;
            }
            assert!(
                context.current() < deadline,
                "durable nullification forwarding was not counted: {metrics}"
            );
            context.sleep(Duration::from_millis(10)).await;
        };
        assert!(
            metrics.lines().any(|line| {
                line.starts_with("primary_voter_nullification_recovery_latency_count ")
                    && line.ends_with(" 1")
            }),
            "nullification recovery latency was not observed: {metrics}"
        );
    });
}

/// Drives Core to quiescence, mirroring the voter's inline executors.
///
/// The voter services one bounded Core turn per loop iteration and routes every completion back
/// through Core's named transition API.
fn drive_core(
    committee: &Committee<MinPk>,
    core: &mut CoreState<Sha256, MinPk>,
) -> Option<BarrierAck> {
    let mut last_ack = None;
    loop {
        let capabilities = match core.next_action(POLL_BUDGET).expect("Core advances") {
            CoreTurn::Input(serviced) => serviced.transition.into_parts().0,
            CoreTurn::Work(work) => work.into_parts().0,
            CoreTurn::YieldRequired => {
                core.resume_after_yield().expect("Core resumes after yield");
                continue;
            }
            CoreTurn::Idle => return last_ack,
        };
        for capability in capabilities {
            match capability {
                Capability::Durability(DurabilityCapability::Persist(job)) => {
                    let ack = BarrierAck::new(job.id(), job.generation(), job.last_cursor());
                    last_ack = Some(ack);
                    core.persistence_completed(ack).expect("Core accepts ack");
                }
                Capability::Verification(VerificationCapability::Verify(job)) => {
                    let completion = job.verify::<_, Ed25519PublicKey, Sha256>(
                        &mut commonware_utils::test_rng(),
                        &committee.verifier,
                        &Sequential,
                    );
                    core.verification_completed(completion)
                        .expect("Core accepts verification");
                }
                Capability::Leader(LeaderCapability::AggregateVqc(job)) => {
                    let messages = job.messages().collect::<Vec<_>>();
                    let certificate = committee
                        .verifier
                        .assemble_vqc::<Sha256, _>(job.leader().clone(), &messages, &Sequential)
                        .expect("aggregation succeeds");
                    core.leader_vqc_aggregated(Box::new(VqcAggregateCompletion::new(
                        job.id(),
                        job.generation(),
                        certificate,
                    )))
                    .expect("Core accepts V-QC aggregation");
                }
                Capability::Leader(LeaderCapability::AggregateLqc(job)) => {
                    let votes = job.votes().cloned().collect::<Vec<_>>();
                    let certificate = committee
                        .verifier
                        .assemble_lqc::<Sha256, _>(job.leader().clone(), &votes, &Sequential)
                        .expect("aggregation succeeds");
                    core.leader_lqc_aggregated(Box::new(LqcAggregateCompletion::new(
                        job.id(),
                        job.generation(),
                        certificate,
                    )))
                    .expect("Core accepts L-QC aggregation");
                }
                // Publications, timers, resolution, and application work change machine state
                // only through completions; none arrive in these schedules.
                _ => {}
            }
        }
    }
}

#[test_traced]
fn attached_observer_matches_the_synchronous_core() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut node = Node::start(&context, 45, Role::Observer, "primary").await;
        let (mut consensus_tx, _) = node.peer(1, 1).await;

        // One leader block and a finalizing vote quorum, in one deterministic arrival order.
        let block = node.committee.leader_block(1);
        let votes = (0..node.committee.codec().view_quorum())
            .map(|signer| node.committee.vote(signer, &block))
            .collect::<Vec<_>>();
        let mut artifacts = vec![Artifact::LeaderBlock(block.clone())];
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(block),
                parent: None,
            })
            .encode(),
            true,
        );
        for vote in &votes {
            artifacts.push(Artifact::Vote(vote.clone()));
            consensus_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(ConsensusMessage::Vote(vote.clone())).encode(),
                true,
            );
        }

        // Drive the synchronous Core over the identical cohort.
        let committee = Committee::<MinPk>::new(45, 6, Limits::new(2, 1).unwrap());
        let mut core =
            CoreState::fresh(profile(&committee, Role::Observer), NonZeroUsize::MIN).unwrap();
        core.start_fresh().unwrap();
        let _ = drive_core(&committee, &mut core);
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
        core.observe(identified, resident_bytes).unwrap();
        let _ = drive_core(&committee, &mut core);
        let expected = core.inspection();

        // The attached machine converges to the same normalized projection.
        let mut attached = node.inspect().await;
        for _ in 0..200 {
            if matches_modulo_outbox_ids(&attached, &expected) {
                break;
            }
            context.sleep(Duration::from_millis(25)).await;
            attached = node.inspect().await;
        }
        assert!(
            matches_modulo_outbox_ids(&attached, &expected),
            "attached {attached:?} does not match pure {expected:?}"
        );
    });
}

#[test_traced]
fn updated_broadcast_parent_is_attached_to_a_live_proposal() {
    DeterministicRunner::timed(Duration::from_secs(10)).start(|context| async move {
        let seed = 79;
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;
        let role = Role::Validator(Participant::new(3));
        let application = MockApplication::new();
        application.pause_building();
        let ingress = IngressLimits {
            coalesce: Duration::from_millis(20),
            ..ingress_limits()
        };
        let mut node = Node::attach(
            &context,
            Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap()),
            profile(&committee, role),
            role,
            oracle,
            committee.identities[3].clone(),
            seed,
            "updated_parent",
            false,
            Attachments {
                application,
                ingress: Some(ingress),
                ..Attachments::default()
            },
            voter_limits(),
        )
        .await;
        let (mut consensus_tx, mut consensus_rx) = node.peer(1, 1).await;
        let (mut certificate_tx, mut certificate_rx) = node.peer(1, 2).await;
        let block = committee.leader_block(1);
        let unsigned = block.block().clone();
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(block.clone()),
                parent: None,
            })
            .encode(),
            true,
        );

        let messages = (0..6)
            .map(|signer| ViewMessage::Vote(committee.vote(signer, &block)))
            .collect::<Vec<_>>();
        for message in &messages {
            let ViewMessage::Vote(vote) = message else {
                unreachable!("the test uses only votes");
            };
            consensus_tx.send(
                Recipients::One(node.me.clone()),
                node.envelope(ConsensusMessage::Vote(vote.clone())).encode(),
                true,
            );
        }
        let first = committee
            .verifier
            .assemble_vqc::<Sha256, _>(unsigned.clone(), &messages[..5], &Sequential)
            .expect("the first quorum aggregates");
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let (_, bytes) = select! {
                result = certificate_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => panic!("the first V-QC was not published"),
            };
            let envelope = Envelope::<CertificateMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical certificate envelope");
            if let CertificateMessage::Vqc(certificate) = envelope.into_payload() {
                assert_eq!(certificate.id::<Sha256>(), first.id::<Sha256>());
                break;
            }
        }

        let improved = committee
            .verifier
            .assemble_vqc::<Sha256, _>(unsigned, &messages, &Sequential)
            .expect("the full sticky transcript aggregates");
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(node.inspect().await.view(), View::new(2));

        certificate_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                committee.nullification(2),
            ))
            .encode(),
            true,
        );
        let deadline = context.current() + Duration::from_secs(2);
        loop {
            let (_, bytes) = select! {
                result = consensus_rx.recv() => result.expect("network stays up"),
                () = context.sleep_until(deadline) => panic!("view-three proposal was not published"),
            };
            let envelope = Envelope::<ConsensusMessage<MinPk, Sha256Digest>>::decode_cfg(
                bytes,
                &node.envelope_cfg(node.committee.codec()),
            )
            .expect("canonical consensus envelope");
            let ConsensusMessage::Proposal {
                block,
                parent: Some(parent),
            } = envelope.into_payload()
            else {
                continue;
            };
            if block.view() != View::new(3) {
                continue;
            }
            assert_eq!(block.block().parent(), improved.id::<Sha256>());
            assert_eq!(*parent, improved);
            break;
        }
    });
}

/// Compares two inspections, ignoring outbox effect-id numbering.
///
/// Assemblies complete on the compute pool, so effect-id interleaving is scheduling-dependent:
/// the machine's semantics are order-tolerant, and everything but the id numbering must still
/// match, including the number of durable unacknowledged effects.
fn matches_modulo_outbox_ids(
    left: &Inspection<Sha256Digest>,
    right: &Inspection<Sha256Digest>,
) -> bool {
    left.outbox().len() == right.outbox().len()
        && left.epoch() == right.epoch()
        && left.view() == right.view()
        && left.generation() == right.generation()
        && left.cursor() == right.cursor()
        && left.is_live() == right.is_live()
        && left.is_recovering() == right.is_recovering()
        && left.cached_artifacts() == right.cached_artifacts()
        && left.pending_artifacts() == right.pending_artifacts()
        && left.waiting_artifacts() == right.waiting_artifacts()
        && left.ready_artifacts() == right.ready_artifacts()
        && left.dropped_artifacts() == right.dropped_artifacts()
        && left.future_artifacts() == right.future_artifacts()
        && left.verification_jobs() == right.verification_jobs()
        && left.pending_barrier() == right.pending_barrier()
        && left.local_artifacts() == right.local_artifacts()
        && left.finality_floor() == right.finality_floor()
        && left.produced_blocks() == right.produced_blocks()
        && left.resolution_jobs() == right.resolution_jobs()
        && left.chain_progress() == right.chain_progress()
        && left.pools() == right.pools()
        && left.finality() == right.finality()
        && left.retained_artifact_references() == right.retained_artifact_references()
        && left.nullification_suffix() == right.nullification_suffix()
        && left.retired_view() == right.retired_view()
        && left.finality_floor() == right.finality_floor()
}

#[test_traced]
fn recovery_reissues_unsuperseded_publications() {
    // Run one validator until it has two distinct durable publications, then crash the whole
    // runtime uncleanly and recover only its synced storage.
    let seed = 46;
    let role = Role::Validator(Participant::new(0));
    let initial_relay = TestRelay::default();
    let first_relay = initial_relay.clone();
    let runner = DeterministicRunner::timed(Duration::from_secs(60));
    let (obligations, checkpoint) = runner.start_and_recover(move |context| async move {
        let node = Node::start_with_attachments(
            &context,
            seed,
            role,
            "first",
            Attachments {
                relay: first_relay,
                ..Attachments::default()
            },
        )
        .await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        let mut obligations = Vec::new();
        while obligations.len() < 2 {
            let header = next_block(&node, &mut data_rx).await;
            if !obligations.contains(&header) {
                obligations.push(header);
            }
        }
        obligations
    });
    for header in &obligations {
        assert!(
            initial_relay
                .broadcasts()
                .iter()
                .any(|(commitment, _)| *commitment == header.commitment()),
            "initial publication was not relayed: {header:?}"
        );
    }

    // Close the first recovered attempt for both obligations. Each must remain installed, retry
    // Relay, and publish its original signed header only after Relay accepts it.
    let relay = TestRelay::scripted([Feedback::Closed, Feedback::Closed], Feedback::Ok);
    let runner = DeterministicRunner::from(checkpoint);
    runner.start(move |context| async move {
        let mut node = Node::start_with_attachments(
            &context,
            seed,
            role,
            "second",
            Attachments {
                relay: relay.clone(),
                ..Attachments::default()
            },
        )
        .await;
        let inspection = node.inspect().await;
        assert!(inspection.produced_blocks() > 0);
        let expected = format!(
            "second_voter_produced_blocks {}",
            inspection.produced_blocks()
        );
        assert!(
            context.encode().lines().any(|line| line == expected),
            "recovered production gauge did not reflect machine state"
        );
        let (_, mut data_rx) = node.peer(1, 0).await;
        let deadline = context.current() + Duration::from_secs(2);
        let mut recovered = Vec::new();
        while recovered.len() < obligations.len() {
            let header = select! {
                header = next_block(&node, &mut data_rx) => header,
                () = context.sleep_until(deadline) => {
                    panic!("recovery did not republish every exact obligation: {recovered:?}");
                },
            };
            let Some(expected) = obligations
                .iter()
                .find(|expected| expected.commitment() == header.commitment())
            else {
                continue;
            };
            assert_eq!(
                &header, expected,
                "recovery reconstructed a different header"
            );
            if !recovered.contains(&header) {
                recovered.push(header);
            }
        }

        for expected in &obligations {
            let attempts = relay
                .broadcasts()
                .into_iter()
                .filter_map(|(commitment, feedback)| {
                    (commitment == expected.commitment()).then_some(feedback)
                })
                .collect::<Vec<_>>();
            assert_eq!(attempts.first(), Some(&Feedback::Closed));
            assert!(
                attempts.contains(&Feedback::Ok),
                "recovered obligation was not retried after Relay closed: {expected:?}"
            );
        }
    });
}

#[test_traced]
fn recovery_ready_waits_for_the_exact_drain_acknowledgement() {
    const RECOVERY_DELAY: Duration = Duration::from_millis(250);

    let seed = 83;
    let role = Role::Validator(Participant::new(0));
    let runner = DeterministicRunner::timed(Duration::from_secs(30));
    let (expected, checkpoint) = runner.start_and_recover(move |context| async move {
        let node = Node::start(&context, seed, role, "recovery_source").await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        next_block(&node, &mut data_rx).await
    });

    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let gates = TestGates::default();
        let mut drain = gates.arm_next_start_sync();
        let (node, ready) = Node::start_pending_with_limits(
            &context,
            seed,
            role,
            "recovery_target",
            Attachments {
                journal_gates: Some(gates),
                ..Attachments::default()
            },
            voter_limits(),
        )
        .await;
        let mut ready = Box::pin(ready);
        drain.wait_entered().await;
        let (_, mut data_rx) = node.peer(1, 0).await;

        select! {
            result = &mut ready => panic!("ready resolved before recovery drain: {result:?}"),
            result = data_rx.recv() => panic!("recovered publication escaped before ready: {result:?}"),
            () = context.sleep(RECOVERY_DELAY) => {},
        }
        let metrics = context.encode();
        assert_eq!(
            metric_sample(
                &metrics,
                "recovery_target_voter_startup_drain_latency_count"
            ),
            0.0
        );

        drain.release();
        ready.await.expect("recovered voter becomes ready");
        let recovered = select! {
            header = next_block(&node, &mut data_rx) => header,
            () = context.sleep(Duration::from_secs(1)) => {
                panic!("pre-ack recovery publication was not preserved");
            },
        };
        assert_eq!(recovered, expected);

        let metrics = context.encode();
        assert_eq!(
            metric_sample(
                &metrics,
                "recovery_target_voter_startup_drain_latency_count"
            ),
            1.0
        );
        let drain_latency = metric_sample(
            &metrics,
            "recovery_target_voter_startup_drain_latency_sum",
        );
        assert!(drain_latency >= RECOVERY_DELAY.as_secs_f64());
        assert!(drain_latency <= 0.5);
        let histogram = "recovery_target_voter_startup_drain_latency_bucket";
        assert!(histogram_percentile_bound(&metrics, histogram, 95.0) <= 0.5);
        assert!(histogram_percentile_bound(&metrics, histogram, 99.0) <= 0.5);
    });
}

#[test_traced]
fn repeated_pre_ack_recovery_crashes_keep_the_suffix_bounded() {
    const SEED: u64 = 108;
    const RESTARTS: usize = 5;

    let role = Role::Validator(Participant::new(0));
    let runner = DeterministicRunner::timed(Duration::from_secs(30));
    let (_, mut checkpoint) = runner.start_and_recover(move |context| async move {
        let mut node = Node::start(&context, SEED, role, "bounded_recovery").await;
        let (_, mut data_rx) = node.peer(1, 0).await;
        let _ = next_block(&node, &mut data_rx).await;
        for _ in 0..100 {
            if node.inspect().await.pending_barrier().is_none() {
                node.crash(&context).await;
                return;
            }
            context.sleep(Duration::from_millis(10)).await;
        }
        panic!("the source generation did not become durable");
    });

    for _ in 0..RESTARTS {
        let gates = TestGates::default();
        let mut synced_generation = gates.arm_next_after_sync();
        let checkpoint_syncs = PendingSyncs::default();
        checkpoint_syncs.arm();
        let DeferredSync {
            release: release_startup_sync,
            blocked: startup_sync_blocked,
        } = next_pending_sync(&checkpoint_syncs);
        let runner = DeterministicRunner::from(checkpoint);
        let (_, next_checkpoint) = runner.start_and_recover(move |context| async move {
            let limits = VoterLimits {
                checkpoint_interval: NZU64!(1),
                ..voter_limits()
            };
            let mut starting = Box::pin(Node::start_pending_with_limits(
                &context,
                SEED,
                role,
                "bounded_recovery",
                Attachments {
                    journal_gates: Some(gates),
                    checkpoint_syncs: checkpoint_syncs.clone(),
                    ..Attachments::default()
                },
                limits,
            ));
            select! {
                result = startup_sync_blocked => {
                    result.expect("recovery compaction reaches the storage fence");
                },
                _ = &mut starting => {
                    panic!("recovery constructed actors before its compacted base was durable");
                },
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("recovery did not reach its actor-free storage fence");
                },
            }
            assert_eq!(
                count_running_tasks(&context, "bounded_recovery"),
                0,
                "an actor existed while recovery storage was fenced"
            );
            release_startup_sync
                .send(Ok(()))
                .expect("startup storage fence remains pending");
            checkpoint_syncs.unblock();
            let (node, ready) = starting.await;
            let mut ready = Box::pin(ready);
            select! {
                () = synced_generation.wait_entered() => {},
                result = &mut ready => {
                    panic!("recovery became ready before its generation acknowledgement: {result:?}");
                },
                () = context.sleep(Duration::from_secs(2)) => {
                    panic!("recovery generation did not reach the post-sync crash cut");
                },
            }
            node.crash(&context).await;
        });
        checkpoint = next_checkpoint;
    }

    DeterministicRunner::from(checkpoint).start(move |context| async move {
        let committee = Committee::<MinPk>::new(SEED, 6, Limits::new(2, 1).unwrap());
        let mut store_context = context.child("bounded_recovery_stores");
        let stores = Box::pin(open_stores(
            &mut store_context,
            profile(&committee, role),
            &format!("node-{SEED}"),
            &committee.signers[0],
            &Sequential,
            voter_limits().inflight_application,
        ))
        .await
        .expect("stores recover after repeated pre-ack crashes");
        let Startup::Recovered(recovered) = &stores.startup else {
            panic!("durable generations must select recovery startup");
        };
        assert_eq!(
            recovered.events_since_checkpoint, 1,
            "each restart must replace, rather than extend, the replay suffix"
        );

        let sections = context
            .scan(&format!("node-{SEED}-multimmit-machine-journal"))
            .await
            .expect("journal partition remains readable");
        assert!(
            sections.len() <= 2,
            "repeated recovery retained obsolete journal sections: {sections:?}"
        );
    });
}

#[test_traced]
fn resolver_port_receives_machine_issued_requests() {
    let executor = DeterministicRunner::default();
    executor.start(|context| async move {
        let mut node = Node::start(&context, 47, Role::Observer, "primary").await;
        let (mut consensus_tx, _) = node.peer(1, 1).await;

        // A vote for an unknown leader parks as a dependency; ordering does not request
        // resolution for it, but a V-QC naming an unknown parent does.
        let vqc = node.committee.vqc(2);
        consensus_tx.send(
            Recipients::One(node.me.clone()),
            node.envelope(ConsensusMessage::Proposal {
                block: Box::new(node.committee.leader_block(3)),
                parent: Some(Box::new(vqc)),
            })
            .encode(),
            true,
        );

        // The machine may or may not need external resolution for this schedule; the port must
        // simply stay wired if a request is emitted.
        select! {
            request = node.resolver.recv() => {
                let ResolveRequest { job, .. } = request.expect("voter stays running");
                assert!(job.view() >= View::new(1));
            },
            () = context.sleep(Duration::from_secs(2)) => {},
        }
        let _ = node.inspect().await;
    });
}

#[test_traced]
fn skipped_view_nullification_resolves_from_a_peer_node() {
    let executor = DeterministicRunner::timed(Duration::from_secs(60));
    executor.start(|context| async move {
        let seed = 48;
        let committee = Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap());
        let oracle = start_network(&context, committee.identities.clone(), 1024 * 1024).await;

        // Two full observers: node A misses the gap proof that node B durably forwarded.
        let mut node_a = Box::pin(Node::start_full(
            &context,
            Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap()),
            oracle.clone(),
            0,
            Role::Observer,
            "node_a",
            seed,
        ))
        .await;
        let node_b = Box::pin(Node::start_full(
            &context,
            Committee::<MinPk>::new(seed, 6, Limits::new(2, 1).unwrap()),
            oracle.clone(),
            1,
            Role::Observer,
            "node_b",
            seed + 1,
        ))
        .await;

        // Link both nodes on every plane so certificates and resolver traffic flow.
        let link = Link {
            latency: Duration::from_millis(1),
            jitter: Duration::ZERO,
            success_rate: 1.0,
        };
        let _ = oracle
            .add_link(node_a.me.clone(), node_b.me.clone(), link.clone())
            .await;
        let _ = oracle
            .add_link(node_b.me.clone(), node_a.me.clone(), link.clone())
            .await;

        // A third identity injects protocol traffic into both nodes.
        let (mut certs_tx, _) = node_b.peer(2, 2).await;
        let _ = oracle
            .add_link(
                committee.identities[2].clone(),
                node_a.me.clone(),
                link.clone(),
            )
            .await;
        let (mut consensus_tx_a, _) = node_a.peer(2, 1).await;

        // Node B durably forwards the skipped-view nullification, making it servable.
        let nullification = committee.nullification(2);
        certs_tx.send(
            Recipients::One(node_b.me.clone()),
            node_b
                .envelope(CertificateMessage::<MinPk, Sha256Digest>::Nullification(
                    nullification,
                ))
                .encode(),
            true,
        );
        context.sleep(Duration::from_millis(200)).await;

        // Node A receives an exact-Q proposal that skips view two. It has the parent certificate
        // in the proposal bundle but must retrieve the durable proof for the skipped view.
        let vqc = committee.vqc(1);
        let block = committee.leader_block_with_parent(3, &vqc);
        consensus_tx_a.send(
            Recipients::One(node_a.me.clone()),
            node_a
                .envelope(ConsensusMessage::Proposal {
                    block: Box::new(block),
                    parent: Some(Box::new(vqc)),
                })
                .encode(),
            true,
        );

        // The proposal leaves the dependency index once the resolver retrieves the gap proof.
        let mut settled = false;
        for _ in 0..400 {
            context.sleep(Duration::from_millis(25)).await;
            let inspection = node_a.inspect().await;
            if inspection.waiting_artifacts() == 0 && inspection.cached_artifacts() >= 2 {
                settled = true;
                break;
            }
        }
        assert!(settled, "the skipped-view nullification was never resolved");
    });
}
