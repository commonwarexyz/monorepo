//! Full-system deterministic harness and end-to-end scenarios.

use crate::{
    Automaton as _, Epochable as _, Heightable as _, Reporter, Viewable as _,
    marshal::{Floors, Ledger},
    multimmit::{
        config::max_outbox_effects,
        marshal::{
            ArchiveConfig, ArchiveMode, Config, Error as MailboxError, Floor, Inline, LqcVerifier,
            Mailbox, MarshalProgress, Relay, Retention, ServiceHandle, Start, Update,
            actors::catalog, open, storage::catalog::StoredRef,
        },
        mocks::{
            Committee,
            cluster::{Cluster, ClusterOptions, LaunchSpec, QUOTA, link_all, start_network},
        },
        scheme::bls12381_threshold::Scheme,
        testing::{SpanRecorder, TestBody, metric_total},
        types::{
            Activity, Anchor, Artifact, ArtifactId, BlockRef, Body, CertificateId, ChainId,
            ChainProposal, Context, DigestedLeader, Extension, FinalityFact, FinalityId,
            LeaderBlock, Lqc, PathLimits, Position, TipRecord, TransactionBlock,
            TransactionBlockHeader, VoteBody, genesis_history as protocol_genesis_history,
        },
    },
    types::{Height, OutputIndex, Participant, Round, View},
};
use bytes::BufMut;
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::{Recipients, simulated};
use commonware_parallel::Sequential;
use commonware_resolver::p2p;
use commonware_runtime::{
    Clock as _, Handle, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::CacheRef, deterministic, telemetry::metrics::count_running_tasks,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{
    Acknowledgement as _, NZU16, NZU64, NZUsize, channel::oneshot, sync::Mutex,
};
use futures::{StreamExt as _, stream::FuturesUnordered};
use std::{
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
use tracing_subscriber::prelude::*;

const CHAINS: usize = 2;
const PARTICIPANTS: u32 = 6;
/// Channels of the harness nodes' marshals.
const CHANNELS: Channels = Channels {
    resolver: 0,
    broadcast: 1,
};
/// Channels of a marshal attached to a cluster engine, clear of the engine's own planes.
const ENGINE_CHANNELS: Channels = Channels {
    resolver: 4,
    broadcast: 5,
};
const WAIT_STEPS: usize = 2_000;
/// Resolver mailbox capacity, which also bounds backfill concurrency.
const RESOLVER_MAILBOX_SIZE: NonZeroUsize = NZUsize!(64);
const WAIT_STEP: Duration = Duration::from_millis(5);
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MARSHAL_E2E";
const NODE_LABELS: [[&str; 3]; 2] = [
    [
        "node_0_generation_0",
        "node_0_generation_1",
        "node_0_generation_2",
    ],
    [
        "node_1_generation_0",
        "node_1_generation_1",
        "node_1_generation_2",
    ],
];
type TestBlock = TransactionBlock<Sha256, TestBody>;
type TestScheme = Scheme<ed25519::PublicKey, MinPk>;
type TestMailbox = Mailbox<Sha256, MinPk, TestBody>;
type TestBuffer = buffered::Mailbox<ed25519::PublicKey, TestBlock>;
type TestRelay = Relay<Sha256, TestBody, ed25519::PublicKey>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct DigestBody(Sha256Digest);

impl Write for DigestBody {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl EncodeSize for DigestBody {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Read for DigestBody {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(Sha256Digest::read(buf)?))
    }
}

impl Digestible for DigestBody {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        self.0
    }
}

type DigestBlock = TransactionBlock<Sha256, DigestBody>;

/// The network channels one marshal registers.
#[derive(Clone, Copy)]
struct Channels {
    resolver: u64,
    broadcast: u64,
}

/// How to wire one node's marshal.
struct Wiring<'a, B: Body<Sha256>> {
    oracle: &'a simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    identity: ed25519::PublicKey,
    channels: Channels,
    config: Config<TwoCap, MinPk, B>,
    /// Whether the node exposes a staged-block relay.
    relay: bool,
}

/// One node's running marshal, with the broadcast and resolver engines it runs over.
struct Node<B: Body<Sha256>> {
    mailbox: Mailbox<Sha256, MinPk, B>,
    buffer: buffered::Mailbox<ed25519::PublicKey, TransactionBlock<Sha256, B>>,
    relay: Option<Relay<Sha256, B, ed25519::PublicKey>>,
    catalog: catalog::Mailbox<Sha256, MinPk, B>,
    marshal: ServiceHandle,
    resolver: Handle<()>,
    broadcast: Handle<()>,
    task_prefix: String,
}

impl<B: Body<Sha256>> Node<B> {
    fn abort(&mut self) {
        self.marshal.abort();
    }

    async fn join(self) {
        self.marshal
            .join()
            .await
            .expect("requested marshal shutdown succeeds");
        self.resolver.abort();
        self.broadcast.abort();
        let _ = self.resolver.await;
        let _ = self.broadcast.await;
    }

    async fn shutdown(mut self) {
        self.abort();
        self.join().await;
    }
}

/// Starts the broadcast engine, marshal, and network resolver `wiring` describes under
/// `context`.
async fn wire_marshal<B, F>(
    context: deterministic::Context,
    wiring: Wiring<'_, B>,
    verifier: CommitteeVerifier,
    reporter: F,
) -> Node<B>
where
    B: Body<Sha256, Cfg = ()> + Clone + Send + Sync + 'static,
    F: Reporter<Activity = Update<TransactionBlock<Sha256, B>>>,
{
    let Wiring {
        oracle,
        identity,
        channels,
        config,
        relay,
    } = wiring;
    let task_prefix = context.name().label;
    let control = oracle.control(identity.clone());
    let resolver_network = control.register(channels.resolver, QUOTA).await.unwrap();
    let broadcast_network = control.register(channels.broadcast, QUOTA).await.unwrap();
    let (broadcast_engine, buffer) = buffered::Engine::new(
        context.child("broadcast"),
        buffered::Config {
            public_key: identity.clone(),
            mailbox_size: NZUsize!(64),
            ingress_size: NZUsize!(64),
            deque_size: 16,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
            blocker: control.clone(),
            strategy: Sequential,
        },
    );
    let broadcast = broadcast_engine.start(broadcast_network);
    let (mut service, bridge) = open::<_, TwoCap, Sha256, MinPk, B, ed25519::PublicKey>(
        context.child("marshal"),
        config,
        buffer.clone(),
    )
    .await
    .unwrap();
    let relay = relay.then(|| service.relay(None));
    let catalog = service.catalog();
    let (resolver_engine, resolver) = p2p::Engine::new(
        context.child("resolver"),
        p2p::Config {
            peer_provider: oracle.manager(),
            blocker: control,
            consumer: bridge.clone(),
            producer: bridge,
            mailbox_size: NZUsize!(64),
            me: Some(identity),
            timeout: Duration::from_millis(100),
            fetch_retry_timeout: Duration::from_millis(20),
            priority_requests: false,
            priority_responses: false,
        },
    );
    let resolver_handle = resolver_engine.start(resolver_network);
    let (mailbox, marshal) = service.start(resolver, verifier, reporter);
    Node {
        mailbox,
        buffer,
        relay,
        catalog,
        marshal,
        resolver: resolver_handle,
        broadcast,
        task_prefix,
    }
}

/// Starts a marshal that `launch` of a cluster engine reports to, over committee member zero's
/// identity.
async fn start_attached_marshal(
    context: &deterministic::Context,
    oracle: &simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    committee: &Committee<MinPk>,
    reporter: ApplicationReporter<DigestBody>,
    launch: u64,
) -> Node<DigestBody> {
    let node_context = context.child(if launch == 0 {
        "engine_marshal_first"
    } else {
        "engine_marshal_second"
    });
    let archive = ArchiveConfig::new(
        TwoCap,
        CacheRef::from_pooler(&node_context, NZU16!(1024), NZUsize!(8)),
    );
    let mut config = Config::new(
        Start::Genesis(committee.config.genesis().clone()),
        "multimmit_engine_marshal_e2e".into(),
        committee.codec(),
        (),
        archive,
    );
    config.capacities.catalog_mailbox_size = NZUsize!(64);
    config.capacities.admission_cut_capacity = NZUsize!(64);
    config.capacities.pending_segment_items = NZU64!(64);
    config.capacities.resolver_mailbox_size = NZUsize!(64);
    config.capacities.backfill_concurrency = config.capacities.resolver_mailbox_size;
    wire_marshal(
        node_context,
        Wiring {
            oracle,
            identity: committee.identities[0].clone(),
            channels: ENGINE_CHANNELS,
            config,
            relay: false,
        },
        CommitteeVerifier::new(committee.verifier.clone()),
        reporter,
    )
    .await
}

#[derive(Clone)]
struct VerificationGate {
    started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

#[derive(Clone)]
struct CommitteeVerifier {
    scheme: TestScheme,
    gate: Option<VerificationGate>,
}

impl CommitteeVerifier {
    const fn new(scheme: TestScheme) -> Self {
        Self { scheme, gate: None }
    }
}

/// The test committee rejected an L-QC, or its verification gate closed.
#[derive(Debug, thiserror::Error)]
enum VerifyError {
    #[error("committee rejected LQC")]
    Rejected,
    #[error("verification gate closed")]
    GateClosed,
}

impl LqcVerifier<Sha256, MinPk> for CommitteeVerifier {
    type Error = VerifyError;

    fn verify(
        &mut self,
        proof: &Lqc<MinPk, Sha256Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let valid = self
            .scheme
            .verify_lqc::<_, Sha256, _>(&mut commonware_utils::test_rng(), proof, &Sequential)
            .is_some();
        let gate = self.gate.take().map(|gate| {
            (
                gate.started
                    .lock()
                    .take()
                    .expect("verification gate starts once"),
                gate.release
                    .lock()
                    .take()
                    .expect("verification gate releases once"),
            )
        });
        async move {
            if !valid {
                return Err(VerifyError::Rejected);
            }
            if let Some((started, release)) = gate {
                let _ = started.send(());
                release.await.map_err(|_| VerifyError::GateClosed)?;
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
struct Delivered<B: Body<Sha256>> {
    index: OutputIndex,
    block: Arc<TransactionBlock<Sha256, B>>,
}

struct ReporterState<B: Body<Sha256>> {
    delivered: Vec<Delivered<B>>,
    /// Final blocks reported before they are ordered, with the ordered deliveries before each.
    finals: Vec<(BlockRef<Sha256Digest>, usize)>,
    pending: std::collections::VecDeque<(OutputIndex, commonware_utils::acknowledgement::Exact)>,
}

/// Records every delivered update and acknowledges it at once or when the test says so.
struct ApplicationReporter<B: Body<Sha256>> {
    state: Arc<Mutex<ReporterState<B>>>,
    auto_acknowledge: bool,
}

impl<B: Body<Sha256>> Clone for ApplicationReporter<B> {
    fn clone(&self) -> Self {
        Self {
            state: Arc::clone(&self.state),
            auto_acknowledge: self.auto_acknowledge,
        }
    }
}

impl<B: Body<Sha256> + Clone> ApplicationReporter<B> {
    fn new(auto_acknowledge: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(ReporterState {
                delivered: Vec::new(),
                finals: Vec::new(),
                pending: std::collections::VecDeque::new(),
            })),
            auto_acknowledge,
        }
    }

    fn delivered(&self) -> Vec<Delivered<B>> {
        self.state.lock().delivered.clone()
    }

    /// Returns every final block reported before it was ordered, with the number of ordered
    /// deliveries that preceded its report.
    fn finals(&self) -> Vec<(BlockRef<Sha256Digest>, usize)> {
        self.state.lock().finals.clone()
    }

    fn pending(&self) -> Vec<OutputIndex> {
        self.state
            .lock()
            .pending
            .iter()
            .map(|(index, _)| *index)
            .collect()
    }

    fn acknowledge_next(&self) -> Option<OutputIndex> {
        let (index, acknowledgement) = self.state.lock().pending.pop_front()?;
        acknowledgement.acknowledge();
        Some(index)
    }

    fn acknowledge(&self, index: OutputIndex) -> bool {
        let mut state = self.state.lock();
        let Some(position) = state
            .pending
            .iter()
            .position(|(pending, _)| *pending == index)
        else {
            return false;
        };
        let (_, acknowledgement) = state
            .pending
            .remove(position)
            .expect("the located acknowledgement exists");
        drop(state);
        acknowledgement.acknowledge();
        true
    }

    fn discard_pending(&self) {
        self.state.lock().pending.clear();
    }
}

impl<B: Body<Sha256> + Send + Sync + 'static> Reporter for ApplicationReporter<B> {
    type Activity = Update<TransactionBlock<Sha256, B>>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let (index, block, acknowledgement) = match activity {
            Update::Block {
                index,
                block,
                acknowledgement,
            } => (index, block, acknowledgement),
            Update::Final(block) => {
                let mut state = self.state.lock();
                let delivered = state.delivered.len();
                state.finals.push((block.reference(), delivered));
                return Feedback::Ok;
            }
        };
        let mut state = self.state.lock();
        state.delivered.push(Delivered { index, block });
        if self.auto_acknowledge {
            drop(state);
            acknowledgement.acknowledge();
        } else {
            state.pending.push_back((index, acknowledgement));
        }
        Feedback::Ok
    }
}

/// Waits until `reporter` has recorded at least `count` updates and returns them.
async fn wait_delivered<B: Body<Sha256> + Clone>(
    context: &deterministic::Context,
    reporter: &ApplicationReporter<B>,
    count: usize,
) -> Vec<Delivered<B>> {
    for _ in 0..WAIT_STEPS {
        let delivered = reporter.delivered();
        if delivered.len() >= count {
            return delivered;
        }
        context.sleep(WAIT_STEP).await;
    }
    panic!("the marshal did not deliver {count} updates");
}

/// Waits for buffered ingress of the block named by `reference`.
fn subscribe_buffered(
    buffer: &TestBuffer,
    reference: BlockRef<Sha256Digest>,
) -> impl std::future::Future<Output = Option<Arc<TestBlock>>> + Send + 'static {
    let receiver = buffer.subscribe(reference.digest());
    async move {
        receiver
            .await
            .ok()
            .filter(|block| block.reference() == reference)
    }
}

/// Returns the block named by `reference` if buffered ingress holds it.
async fn get_buffered(
    buffer: &TestBuffer,
    reference: BlockRef<Sha256Digest>,
) -> Option<Arc<TestBlock>> {
    buffer
        .get(reference.digest())
        .await
        .filter(|block| block.reference() == reference)
}

struct Harness {
    context: deterministic::Context,
    oracle: simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    committee: Committee<MinPk>,
    reporters: [ApplicationReporter<TestBody>; 2],
    nodes: [Option<Node<TestBody>>; 2],
    launches: [u64; 2],
    seed: u64,
    archive_modes: [ArchiveMode; 3],
    catalog_mailbox_size: NonZeroUsize,
    max_commit_outputs: NonZeroUsize,
    max_hot_block_bytes: NonZeroUsize,
    max_pending_acks: NonZeroUsize,
    final_lookahead: NonZeroUsize,
    backfill_concurrency: NonZeroUsize,
    verification_gate: Option<VerificationGate>,
    relay: bool,
}

impl Harness {
    async fn new(context: deterministic::Context, seed: u64, auto_acknowledge: [bool; 2]) -> Self {
        Self::new_with_archives(context, seed, auto_acknowledge, [ArchiveMode::Prunable; 3]).await
    }

    async fn new_with_archives(
        context: deterministic::Context,
        seed: u64,
        auto_acknowledge: [bool; 2],
        archive_modes: [ArchiveMode; 3],
    ) -> Self {
        let committee = Committee::builder(seed, PARTICIPANTS)
            .namespace(NAMESPACE)
            .producers((0..CHAINS as u32).map(Participant::new).collect())
            .limits(PathLimits::new(4, 1).unwrap())
            .build();
        let identities = committee.identities[..2].to_vec();
        let oracle = start_network(&context, identities.clone(), 4 * 1024 * 1024).await;
        link_all(&oracle, &identities).await;
        Self {
            context,
            oracle,
            committee,
            reporters: auto_acknowledge.map(ApplicationReporter::new),
            nodes: [None, None],
            launches: [0, 0],
            seed,
            archive_modes,
            catalog_mailbox_size: NZUsize!(64),
            max_commit_outputs: NZUsize!(8),
            max_hot_block_bytes: NZUsize!(512 * 1024 * 1024),
            max_pending_acks: NZUsize!(128),
            final_lookahead: NZUsize!(512),
            backfill_concurrency: RESOLVER_MAILBOX_SIZE,
            verification_gate: None,
            relay: false,
        }
    }

    fn config(
        &self,
        context: &deterministic::Context,
        index: usize,
    ) -> Config<TwoCap, MinPk, TestBody> {
        let mut archive = ArchiveConfig::new(
            TwoCap,
            CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8)),
        );
        archive.items_per_section = NZU64!(2);
        Config::new(
            Start::Genesis(self.committee.config.genesis().clone()),
            format!("multimmit_marshal_e2e_{}_{}", self.seed, index),
            self.committee.codec(),
            (),
            archive,
        )
        .with_catalog_mailbox_size(self.catalog_mailbox_size)
        .with_admission_cut_capacity(self.catalog_mailbox_size)
        .with_pending_segment_items(
            NonZeroU64::new(self.catalog_mailbox_size.get() as u64).unwrap(),
        )
        .with_resolver_mailbox_size(RESOLVER_MAILBOX_SIZE)
        // Backfill must not exceed the resolver mailbox.
        .with_backfill_concurrency(self.backfill_concurrency)
        .with_max_commit_outputs(self.max_commit_outputs)
        .with_max_hot_block_bytes(self.max_hot_block_bytes)
        .with_max_pending_acks(self.max_pending_acks)
        .with_final_lookahead(self.final_lookahead)
        .with_retention(Retention {
            lqc: self.archive_modes[0],
            history: self.archive_modes[1],
            blocks: self.archive_modes[2],
        })
    }

    async fn start(&mut self, index: usize) {
        assert!(self.nodes[index].is_none(), "node is already running");
        let floor_generation = self.launches[index];
        self.launches[index] += 1;
        let node_context = self.context.child(
            NODE_LABELS[index]
                .get(floor_generation as usize)
                .copied()
                .expect("test restart bound is sufficient"),
        );
        let config = self.config(&node_context, index);
        let verifier = CommitteeVerifier {
            scheme: self.committee.verifier.clone(),
            gate: self.verification_gate.take(),
        };
        let node = wire_marshal(
            node_context,
            Wiring {
                oracle: &self.oracle,
                identity: self.committee.identities[index].clone(),
                channels: CHANNELS,
                config,
                relay: self.relay,
            },
            verifier,
            self.reporters[index].clone(),
        )
        .await;
        self.nodes[index] = Some(node);
    }

    fn mailbox(&self, index: usize) -> TestMailbox {
        self.nodes[index]
            .as_ref()
            .expect("node is running")
            .mailbox
            .clone()
    }

    fn buffer(&self, index: usize) -> TestBuffer {
        self.nodes[index]
            .as_ref()
            .expect("node is running")
            .buffer
            .clone()
    }

    fn relay(&self, index: usize) -> TestRelay {
        self.nodes[index]
            .as_ref()
            .expect("node is running")
            .relay
            .clone()
            .expect("node was started with a relay")
    }

    fn reporter(&self, index: usize) -> ApplicationReporter<TestBody> {
        self.reporters[index].clone()
    }

    fn catalog(&self, index: usize) -> catalog::Mailbox<Sha256, MinPk, TestBody> {
        self.nodes[index]
            .as_ref()
            .expect("node is running")
            .catalog
            .clone()
    }

    async fn crash(&mut self, index: usize) {
        let mut node = self.nodes[index].take().expect("node is running");
        assert!(
            count_running_tasks(&self.context, &node.task_prefix) > 0,
            "node owns running actors before abort"
        );
        let task_prefix = node.task_prefix.clone();
        node.abort();
        node.join().await;
        self.reporters[index].discard_pending();
        for _ in 0..10 {
            if count_running_tasks(&self.context, &task_prefix) == 0 {
                break;
            }
            self.context.sleep(Duration::from_millis(1)).await;
        }
        let tasks = self
            .context
            .encode()
            .lines()
            .filter(|line| {
                line.starts_with("runtime_tasks_running{")
                    && line.contains("kind=\"Task\"")
                    && line.contains(&format!("name=\"{task_prefix}"))
                    && !line.ends_with(" 0")
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(
            count_running_tasks(&self.context, &task_prefix),
            0,
            "node actors stop after joining every lifecycle owner:\n{tasks}"
        );
    }

    async fn shutdown(&mut self) {
        for index in 0..self.nodes.len() {
            if self.nodes[index].is_some() {
                self.crash(index).await;
            }
        }
    }

    async fn wait_updates(&self, index: usize, count: usize) -> Vec<Delivered<TestBody>> {
        wait_delivered(&self.context, &self.reporters[index], count).await
    }

    async fn wait_progress(
        &self,
        index: usize,
        predicate: impl Fn(&MarshalProgress<Sha256Digest>) -> bool,
    ) -> MarshalProgress<Sha256Digest> {
        for _ in 0..WAIT_STEPS {
            if let Ok(progress) = self.mailbox(index).progress().await
                && predicate(&progress)
            {
                return progress;
            }
            self.context.sleep(WAIT_STEP).await;
        }
        panic!("node {index} did not reach expected progress");
    }
}

struct Certified {
    proof: Arc<Lqc<MinPk, Sha256Digest>>,
    history: Arc<TipRecord<Sha256Digest>>,
    blocks: Vec<Vec<Arc<TestBlock>>>,
}

impl Certified {
    fn id(&self) -> CertificateId<Sha256Digest> {
        self.proof.id::<Sha256>()
    }

    fn tips(&self) -> Vec<BlockRef<Sha256Digest>> {
        self.blocks
            .iter()
            .map(|blocks| blocks.last().unwrap().reference())
            .collect()
    }

    fn offset_major(&self) -> Vec<Arc<TestBlock>> {
        let depth = self.blocks.iter().map(Vec::len).max().unwrap_or(0);
        (0..depth)
            .flat_map(|offset| {
                self.blocks
                    .iter()
                    .filter_map(move |chain| chain.get(offset).map(Arc::clone))
            })
            .collect()
    }

    /// Reports that the engine durably recorded a certificate for each chain's tip and no longer
    /// verifies any block at or below it.
    fn release(&self, mailbox: &TestMailbox) {
        let mut reporter = mailbox.clone();
        for certified in self.tips() {
            let feedback = reporter.report(Activity::CertificateRecorded {
                certified,
                released: certified.height(),
            });
            assert!(feedback.accepted());
        }
    }

    async fn submit(&self, mailbox: &TestMailbox) {
        for block in self.blocks.iter().flatten() {
            mailbox.put_block(Arc::clone(block)).await.unwrap();
        }
    }

    fn accept_history(&self, mailbox: &TestMailbox) {
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(Activity::HistoryAccepted {
                view: self.proof.view(),
                commitment: self.history.commitment::<Sha256>(),
                record: Arc::clone(&self.history),
            }),
            Feedback::Ok
        );
    }

    fn finalize(&self, mailbox: &TestMailbox) {
        self.accept_history(mailbox);
        let mut reporter = mailbox.clone();
        let artifact = Arc::new(Artifact::Lqc(self.proof.as_ref().clone()));
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );
    }

    /// Returns a settled direct-pool fact for the batch's leader naming `tips`.
    fn fact(
        &self,
        label: &[u8],
        committee: &Committee<MinPk>,
        tips: Vec<BlockRef<Sha256Digest>>,
    ) -> FinalityFact<Sha256Digest> {
        let positions = self
            .blocks
            .iter()
            .map(|chain| Position::new(chain.len() as u32))
            .collect();
        direct_fact(
            self.proof.leader(),
            label,
            committee.codec().view_quorum(),
            tips,
            positions,
            vec![true; CHAINS],
        )
    }
}

fn digest(label: &[u8], marker: u64) -> Sha256Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

fn body(marker: u64) -> TestBody {
    TestBody::new(
        digest(b"application parent", marker),
        Height::new(marker + 1),
        marker,
    )
}

fn initial_history(committee: &Committee<MinPk>) -> Arc<TipRecord<Sha256Digest>> {
    let genesis = committee.config.genesis();
    Arc::new(
        TipRecord::at_tips(
            protocol_genesis_history::<Sha256>(genesis),
            genesis.tips().to_vec(),
        )
        .unwrap(),
    )
}

fn certify(
    committee: &Committee<MinPk>,
    view: u64,
    history: Arc<TipRecord<Sha256Digest>>,
    bases: &[BlockRef<Sha256Digest>],
    bodies: Vec<Vec<TestBody>>,
) -> Certified {
    assert_eq!(bases.len(), CHAINS);
    assert_eq!(bodies.len(), CHAINS);
    let epoch = committee.config.epoch();
    let mut blocks = Vec::with_capacity(CHAINS);
    let mut proposals = Vec::with_capacity(CHAINS);
    for (chain, (base, bodies)) in bases.iter().zip(bodies).enumerate() {
        let chain = ChainId::new(chain as u32);
        let mut parent = base.digest();
        let mut chain_blocks = Vec::with_capacity(bodies.len());
        let mut payloads = Vec::with_capacity(bodies.len());
        for (offset, body) in bodies.into_iter().enumerate() {
            payloads.push(body.digest());
            let header = TransactionBlockHeader::new(
                epoch,
                chain,
                Height::new(base.height().get() + offset as u64 + 1),
                parent,
                body.digest(),
            )
            .unwrap();
            let block = Arc::new(TransactionBlock::new(header, body).unwrap());
            parent = block.reference().digest();
            chain_blocks.push(block);
        }
        proposals.push(
            ChainProposal::new(
                chain,
                Anchor::Tip(*base),
                payloads,
                committee.codec().pipeline_depth(),
            )
            .unwrap(),
        );
        blocks.push(chain_blocks);
    }
    let leader = LeaderBlock::new(
        Round::new(epoch, View::new(view)),
        committee.config.genesis().vqc(),
        history.commitment::<Sha256>(),
        proposals,
        committee.codec(),
    )
    .unwrap();
    let positions = blocks
        .iter()
        .map(|chain| Position::new(chain.len() as u32))
        .collect();
    let vote = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&leader),
        positions,
        vec![Extension::empty(); CHAINS],
        committee.codec(),
    )
    .unwrap();
    let votes = (0..committee.codec().view_quorum())
        .map(|signer| committee.signers[signer].sign_vote(vote.clone()).unwrap())
        .collect::<Vec<_>>();
    let proof = committee
        .verifier
        .assemble_lqc::<Sha256, _>(leader, &votes, &Sequential)
        .unwrap();
    assert!(
        committee
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut commonware_utils::test_rng(), &proof, &Sequential)
            .is_some(),
        "fixture LQC verifies with the real committee"
    );
    Certified {
        proof: Arc::new(proof),
        history,
        blocks,
    }
}

fn runner(seed: u64) -> deterministic::Runner {
    deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(60))),
    )
}

#[test]
fn marshal_trace_levels_preserve_publication() {
    for level in [tracing::Level::DEBUG, tracing::Level::INFO] {
        let recorder = SpanRecorder::default();
        let subscriber = tracing_subscriber::registry()
            .with(recorder.clone())
            .with(tracing_subscriber::filter::LevelFilter::from_level(level));
        tracing::subscriber::with_default(
            subscriber,
            local_two_chain_delivery_is_offset_major_and_header_exact,
        );
        let spans = recorder
            .spans()
            .into_iter()
            .map(|span| (span.name, span.parent_name))
            .collect::<Vec<_>>();
        let publish = "multimmit.marshal.synchronizer.publish";
        let commit = "multimmit.marshal.catalog.commit";
        assert!(
            spans.iter().any(|(name, _)| *name == publish),
            "{level}: missing publish"
        );
        let commits = spans
            .iter()
            .filter(|(name, _)| *name == commit)
            .collect::<Vec<_>>();
        assert!(!commits.is_empty(), "{level}: missing commit");
        assert!(
            commits.iter().all(|(_, parent)| *parent == Some(publish)),
            "{level}: {commits:?}"
        );
        let routine = [
            "multimmit.marshal.router.drain",
            "multimmit.marshal.synchronizer.stage_ancestry",
            "multimmit.marshal.synchronizer.walk_producers",
            "multimmit.marshal.catalog.process",
            "multimmit.marshal.catalog.admission_cut",
        ];
        let observed = routine.map(|expected| spans.iter().any(|(name, _)| *name == expected));
        assert_eq!(
            observed,
            [level == tracing::Level::DEBUG; 5],
            "{level}: {routine:?}"
        );
        for durable in [
            "multimmit.marshal.catalog.sync_finalized_archives",
            "multimmit.marshal.catalog.publish_checkpoint",
        ] {
            let parents = spans
                .iter()
                .filter(|(name, _)| *name == durable)
                .map(|(_, parent)| *parent)
                .collect::<Vec<_>>();
            assert!(!parents.is_empty(), "{level}: missing {durable}");
            if level == tracing::Level::INFO {
                assert!(
                    parents.iter().all(|parent| *parent == Some(commit)),
                    "{durable}: {parents:?}"
                );
            }
        }
    }
}

#[test]
fn local_two_chain_delivery_is_offset_major_and_header_exact() {
    runner(101).start(|context| async move {
        let mut harness = Harness::new(context, 101, [true, true]).await;
        harness.start(0).await;
        let history = initial_history(&harness.committee);
        let shared = body(10);
        let batch = certify(
            &harness.committee,
            1,
            history,
            harness.committee.config.genesis().tips(),
            vec![
                vec![shared.clone(), body(11)],
                vec![shared.clone(), body(12)],
            ],
        );
        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);

        let delivered = harness.wait_updates(0, 4).await;
        let expected = batch.offset_major();
        for (offset, (actual, block)) in delivered.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(offset as u64 + 1));
            assert_eq!(actual.block.as_ref(), block.as_ref());
        }
        assert_ne!(
            delivered[0].block.reference(),
            delivered[1].block.reference()
        );
        assert_ne!(delivered[0].block.header(), delivered[1].block.header());
        assert_eq!(delivered[0].block.body(), delivered[1].block.body());
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(4))
            .await;
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            4,
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            0,
            "{metrics}"
        );
        harness.shutdown().await;
    });
}

/// A view-1 batch whose leader proposes one block on each chain, while every quorum vote also
/// extends chain 1 with its second block and one vote extends chain 0 with a block nobody holds.
///
/// A fact that leaves chain 0 unsettled emits both proposed blocks and defers chain 1's
/// extension, which a later fact that settles every chain emits.
struct Unsettled {
    batch: Certified,
    leader: LeaderBlock<MinPk, Sha256Digest>,
    positions: Vec<Position>,
}

impl Unsettled {
    fn new(harness: &Harness, marker: u64) -> Self {
        let mut batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(marker)], vec![body(marker + 1), body(marker + 2)]],
        );
        let certified = batch.proof.leader();
        let mut proposals = certified.proposals().to_vec();
        proposals[1] = ChainProposal::new(
            ChainId::new(1),
            Anchor::Tip(harness.committee.config.genesis().tips()[1]),
            vec![batch.blocks[1][0].header().body_digest()],
            harness.committee.codec().pipeline_depth(),
        )
        .unwrap();
        let leader = LeaderBlock::new(
            certified.round(),
            certified.parent(),
            certified.history(),
            proposals,
            harness.committee.codec(),
        )
        .unwrap();
        let positions = vec![Position::new(1), Position::new(1)];
        let votes = (0..harness.committee.codec().view_quorum())
            .map(|signer| {
                let mut extensions = vec![Extension::empty(); CHAINS];
                extensions[1] = Extension::new(
                    vec![batch.blocks[1][1].header().body_digest()],
                    harness.committee.codec().extension_bound(),
                )
                .unwrap();
                if signer == 0 {
                    extensions[0] = Extension::new(
                        vec![digest(b"unsettled chain extension", marker)],
                        harness.committee.codec().extension_bound(),
                    )
                    .unwrap();
                }
                let vote = VoteBody::for_leader(
                    DigestedLeader::new::<Sha256>(&leader),
                    positions.clone(),
                    extensions,
                    harness.committee.codec(),
                )
                .unwrap();
                harness.committee.signers[signer].sign_vote(vote).unwrap()
            })
            .collect::<Vec<_>>();
        batch.proof = Arc::new(
            harness
                .committee
                .verifier
                .assemble_lqc::<Sha256, _>(leader.clone(), &votes, &Sequential)
                .unwrap(),
        );
        Self {
            batch,
            leader,
            positions,
        }
    }

    /// Returns a direct fact for the leader naming `tips`.
    fn fact(
        &self,
        label: &[u8],
        votes: usize,
        tips: Vec<BlockRef<Sha256Digest>>,
        settled: Vec<bool>,
    ) -> FinalityFact<Sha256Digest> {
        direct_fact(
            &self.leader,
            label,
            votes,
            tips,
            self.positions.clone(),
            settled,
        )
    }
}

/// Returns a direct-pool fact for `leader` naming `tips` as the final blocks.
fn direct_fact(
    leader: &LeaderBlock<MinPk, Sha256Digest>,
    label: &[u8],
    votes: usize,
    tips: Vec<BlockRef<Sha256Digest>>,
    positions: Vec<Position>,
    settled: Vec<bool>,
) -> FinalityFact<Sha256Digest> {
    FinalityFact::new(
        FinalityId::Direct(digest(label, 0)),
        leader.round(),
        leader.digest::<Sha256>(),
        leader.parent(),
        votes,
        tips,
        leader.proposed_heights(),
        positions,
        settled,
    )
}

/// Reports a leader finality fact to `mailbox` as consensus would.
fn report_finality(mailbox: &TestMailbox, fact: FinalityFact<Sha256Digest>) {
    let mut reporter = mailbox.clone();
    assert_eq!(
        reporter.report(Activity::LeaderFinalized { fact }),
        Feedback::Ok
    );
}

/// Waits until `reporter` has recorded at least `count` final blocks and returns them.
async fn wait_finals(
    context: &deterministic::Context,
    reporter: &ApplicationReporter<TestBody>,
    count: usize,
) -> Vec<(BlockRef<Sha256Digest>, usize)> {
    for _ in 0..WAIT_STEPS {
        let finals = reporter.finals();
        if finals.len() >= count {
            return finals;
        }
        context.sleep(WAIT_STEP).await;
    }
    panic!("the marshal did not report {count} final blocks");
}

/// Asserts that `finals` names exactly `expected`, oldest first on each chain.
fn assert_finals(
    finals: &[(BlockRef<Sha256Digest>, usize)],
    expected: &[Vec<BlockRef<Sha256Digest>>],
) {
    assert_eq!(
        finals.len(),
        expected.iter().map(Vec::len).sum::<usize>(),
        "{finals:?}"
    );
    for (chain, expected) in expected.iter().enumerate() {
        let reported = finals
            .iter()
            .map(|(reference, _)| *reference)
            .filter(|reference| reference.chain() == ChainId::new(chain as u32))
            .collect::<Vec<_>>();
        assert_eq!(&reported, expected, "chain {chain}");
    }
}

/// Returns a block on `parent`'s chain that extends it.
fn child(parent: &TestBlock, marker: u64) -> Arc<TestBlock> {
    let body = body(marker);
    let header = TransactionBlockHeader::new(
        parent.header().epoch(),
        parent.header().chain(),
        Height::new(parent.header().height().get() + 1),
        parent.reference().digest(),
        body.digest(),
    )
    .unwrap();
    Arc::new(TransactionBlock::new(header, body).unwrap())
}

#[test]
fn pool_finality_update_emits_suffix_truncated_by_first_lqc() {
    runner(132).start(|context| async move {
        let mut harness = Harness::new(context, 132, [true, true]).await;
        harness.start(0).await;
        let unsettled = Unsettled::new(&harness, 1_320);
        let Unsettled {
            batch,
            leader,
            positions,
        } = &unsettled;
        let quorum = harness.committee.codec().view_quorum();

        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        let initial_fact = unsettled.fact(
            b"initial direct pool",
            quorum,
            batch.tips(),
            vec![false, true],
        );
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(Activity::LeaderFinalized { fact: initial_fact }),
            Feedback::Ok
        );
        harness.context.sleep(WAIT_STEP).await;
        assert!(harness.reporters[0].delivered().is_empty());
        batch.finalize(&mailbox);
        let initial = harness.wait_updates(0, 2).await;
        let initial_progress = harness
            .wait_progress(0, |progress| {
                progress.committed == OutputIndex::new(2)
                    && progress.acknowledged == OutputIndex::new(2)
            })
            .await;
        assert_eq!(initial.len(), 2);
        assert_eq!(harness.reporters[0].delivered().len(), 2);
        assert_eq!(initial_progress.floor, batch.id());
        let expected = batch.offset_major();
        for (index, (actual, expected)) in initial.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(index as u64 + 1));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }

        let future = FinalityFact::new(
            FinalityId::Direct(digest(b"future direct pool", 0)),
            Round::new(leader.round().epoch(), View::new(2)),
            digest(b"future leader", 0),
            leader.parent(),
            harness.committee.codec().view_quorum(),
            batch.tips(),
            leader.proposed_heights(),
            positions.clone(),
            vec![true; CHAINS],
        );
        assert_eq!(
            reporter.report(Activity::LeaderFinalized { fact: future }),
            Feedback::Ok
        );
        harness.context.sleep(WAIT_STEP).await;

        let fact = unsettled.fact(
            b"grown direct pool",
            PARTICIPANTS as usize,
            batch.tips(),
            vec![true; CHAINS],
        );
        assert_eq!(
            reporter.report(Activity::LeaderFinalityUpdated { fact }),
            Feedback::Ok
        );

        let delivered = harness.wait_updates(0, 3).await;
        for (index, (actual, expected)) in delivered.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(index as u64 + 1));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }
        let progress = harness
            .wait_progress(0, |progress| {
                progress.committed == OutputIndex::new(3)
                    && progress.acknowledged == OutputIndex::new(3)
            })
            .await;
        assert_eq!(progress.floor, batch.id());
        assert!(mailbox.get_certificate(batch.id()).await.unwrap().is_some());
        harness.shutdown().await;
    });
}

#[test]
fn final_blocks_held_back_by_an_unsettled_sweep_are_reported_before_ordering() {
    runner(150).start(|context| async move {
        let mut harness = Harness::new(context, 150, [true, true]).await;
        harness.start(0).await;
        let unsettled = Unsettled::new(&harness, 1_500);
        let batch = &unsettled.batch;
        let quorum = harness.committee.codec().view_quorum();
        let mailbox = harness.mailbox(0);
        let reporter = harness.reporter(0);
        batch.submit(&mailbox).await;

        // Every block below the fact's tips is final before any L-QC orders it, including chain
        // 1's extension, which the unsettled chain 0 holds back from the sweep.
        report_finality(
            &mailbox,
            unsettled.fact(b"unsettled pool", quorum, batch.tips(), vec![false, true]),
        );
        let finals = wait_finals(&harness.context, &reporter, 3).await;
        let expected = batch
            .blocks
            .iter()
            .map(|chain| chain.iter().map(|block| block.reference()).collect())
            .collect::<Vec<_>>();
        assert_finals(&finals, &expected);
        assert!(finals.iter().all(|(_, delivered)| *delivered == 0));

        batch.finalize(&mailbox);
        harness.wait_updates(0, 2).await;
        report_finality(
            &mailbox,
            unsettled.fact(
                b"repeated pool",
                quorum + 1,
                batch.tips(),
                vec![false, true],
            ),
        );
        report_finality(
            &mailbox,
            unsettled.fact(
                b"settled pool",
                PARTICIPANTS as usize,
                batch.tips(),
                vec![true; CHAINS],
            ),
        );
        let delivered = harness.wait_updates(0, 3).await;
        assert_eq!(
            delivered[2].block.reference(),
            batch.blocks[1][1].reference()
        );

        // Repeated facts and ordered delivery report nothing again.
        harness.context.sleep(WAIT_STEP * 10).await;
        assert_eq!(reporter.finals(), finals);
        harness.shutdown().await;
    });
}

#[test]
fn blocks_above_the_final_tips_are_never_reported() {
    runner(151).start(|context| async move {
        let mut harness = Harness::new(context, 151, [true, true]).await;
        harness.start(0).await;
        let unsettled = Unsettled::new(&harness, 1_510);
        let batch = &unsettled.batch;
        let mailbox = harness.mailbox(0);
        let reporter = harness.reporter(0);
        batch.submit(&mailbox).await;
        // A proposal above chain 0's final block that the engine recorded as certified.
        let certified = child(&batch.blocks[0][0], 1_513);
        mailbox.put_block(Arc::clone(&certified)).await.unwrap();
        record(&mailbox, certified.reference(), 0);

        // The fact finalizes only each chain's first block.
        let tips = vec![
            batch.blocks[0][0].reference(),
            batch.blocks[1][0].reference(),
        ];
        report_finality(
            &mailbox,
            unsettled.fact(
                b"low tips",
                harness.committee.codec().view_quorum(),
                tips.clone(),
                vec![true; CHAINS],
            ),
        );
        let finals = wait_finals(&harness.context, &reporter, 2).await;
        harness.context.sleep(WAIT_STEP * 10).await;
        assert_eq!(reporter.finals(), finals);
        assert_finals(&finals, &[vec![tips[0]], vec![tips[1]]]);
        harness.shutdown().await;
    });
}

#[test]
fn undelivered_blocks_are_reported_as_final_again_after_a_restart() {
    runner(152).start(|context| async move {
        let mut harness = Harness::new(context, 152, [false, true]).await;
        // Only the first output fits the acknowledgement window.
        harness.max_pending_acks = NZUsize!(1);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let reporter = harness.reporter(0);
        let first = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(1_520)], vec![body(1_521)]],
        );
        first.submit(&mailbox).await;
        first.finalize(&mailbox);
        harness.wait_updates(0, 1).await;
        harness
            .wait_progress(0, |progress| progress.committed == OutputIndex::new(2))
            .await;

        // Chain 0's block is delivered; chain 1's is committed behind the full window, so it is
        // still undelivered and final.
        report_finality(
            &mailbox,
            first.fact(b"delivered", &harness.committee, first.tips()),
        );
        let finals = wait_finals(&harness.context, &reporter, 1).await;
        assert_eq!(finals, vec![(first.blocks[1][0].reference(), 1)]);
        harness.context.sleep(WAIT_STEP * 10).await;
        assert_eq!(reporter.finals(), finals);

        // After a restart, chain 1's committed block is still undelivered, so it is reported
        // again without another fact. Chain 0's block is redelivered from the acknowledgement
        // cursor and is never reported after that redelivery.
        harness.crash(0).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        harness.wait_updates(0, 2).await;
        wait_finals(&harness.context, &reporter, 2).await;
        harness.context.sleep(WAIT_STEP * 10).await;
        let finals = reporter.finals();
        let restarted = &finals[1..];
        assert_eq!(
            restarted
                .iter()
                .filter(|(reference, _)| *reference == first.blocks[1][0].reference())
                .count(),
            1,
            "{finals:?}"
        );
        assert!(
            restarted
                .iter()
                .filter(|(reference, _)| *reference == first.blocks[0][0].reference())
                .all(|(_, delivered)| *delivered == 1),
            "{finals:?}"
        );

        // Blocks finalized above the delivered ones are reported.
        let next = certify(
            &harness.committee,
            2,
            initial_history(&harness.committee),
            &first.tips(),
            vec![vec![body(1_522)], vec![body(1_523)]],
        );
        next.submit(&mailbox).await;
        report_finality(
            &mailbox,
            next.fact(b"next", &harness.committee, next.tips()),
        );
        let reported = finals.len();
        let finals = wait_finals(&harness.context, &reporter, reported + 2).await;
        let expected = next
            .blocks
            .iter()
            .map(|chain| chain.iter().map(|block| block.reference()).collect())
            .collect::<Vec<_>>();
        assert_finals(&finals[reported..], &expected);
        harness.shutdown().await;
    });
}

#[test]
fn final_reports_survive_more_chains_than_header_requests() {
    runner(155).start(|context| async move {
        let mut harness = Harness::new(context, 155, [true, true]).await;
        // The catalog serves one header segment per read, fewer than the chains.
        harness.backfill_concurrency = NZUsize!(1);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let reporter = harness.reporter(0);
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(1_550)], vec![body(1_551), body(1_552)]],
        );
        batch.submit(&mailbox).await;
        report_finality(
            &mailbox,
            batch.fact(b"two chains", &harness.committee, batch.tips()),
        );
        let finals = wait_finals(&harness.context, &reporter, 3).await;
        let expected = batch
            .blocks
            .iter()
            .map(|chain| chain.iter().map(|block| block.reference()).collect())
            .collect::<Vec<_>>();
        assert_finals(&finals, &expected);

        // Marshal keeps running and delivers every block.
        batch.finalize(&mailbox);
        harness.wait_updates(0, 3).await;
        harness.shutdown().await;
    });
}

#[test]
fn final_blocks_missing_from_custody_are_reported_once_admitted() {
    runner(156).start(|context| async move {
        let mut harness = Harness::new(context, 156, [true, true]).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let reporter = harness.reporter(0);
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(1_560)], vec![body(1_561), body(1_562)]],
        );
        // Custody holds only chain 1's tip: chain 0 lacks its final tip's header, and chain 1
        // lacks the header below its tip.
        mailbox
            .put_block(Arc::clone(&batch.blocks[1][1]))
            .await
            .unwrap();
        report_finality(
            &mailbox,
            batch.fact(b"missing", &harness.committee, batch.tips()),
        );
        harness.context.sleep(WAIT_STEP * 10).await;
        assert!(reporter.finals().is_empty());

        // Admitting the missing blocks reports them without another fact or commit.
        mailbox
            .put_block(Arc::clone(&batch.blocks[0][0]))
            .await
            .unwrap();
        mailbox
            .put_block(Arc::clone(&batch.blocks[1][0]))
            .await
            .unwrap();
        let finals = wait_finals(&harness.context, &reporter, 3).await;
        let expected = batch
            .blocks
            .iter()
            .map(|chain| chain.iter().map(|block| block.reference()).collect())
            .collect::<Vec<_>>();
        assert_finals(&finals, &expected);
        harness.shutdown().await;
    });
}

#[test]
fn final_blocks_resume_above_an_installed_floor() {
    runner(153).start(|context| async move {
        let mut harness = Harness::new(context, 153, [false, true]).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let reporter = harness.reporter(0);
        let first = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(1_530)], vec![body(1_531)]],
        );
        first.submit(&mailbox).await;
        first.finalize(&mailbox);
        harness.wait_updates(0, 2).await;

        let floor_history = Arc::new(
            TipRecord::at_tips(first.history.commitment::<Sha256>(), first.tips()).unwrap(),
        );
        let floor = certify(
            &harness.committee,
            2,
            floor_history,
            &first.tips(),
            vec![vec![body(1_532)], vec![body(1_533)]],
        );
        floor.submit(&mailbox).await;
        mailbox
            .install_floor(Floor::new(
                Arc::clone(&floor.proof),
                Arc::clone(&floor.history),
                floor.tips(),
            ))
            .await
            .unwrap();
        harness
            .wait_progress(0, |progress| {
                progress.floor_generation == 1 && progress.acknowledged == OutputIndex::new(4)
            })
            .await;
        harness.reporter(0).discard_pending();

        // Blocks at or below the installed floor are not reported, even with their bodies held.
        report_finality(
            &mailbox,
            floor.fact(b"floor", &harness.committee, floor.tips()),
        );
        harness.context.sleep(WAIT_STEP * 10).await;
        assert!(reporter.finals().is_empty());

        let continuation_history = Arc::new(
            TipRecord::at_tips(floor.history.commitment::<Sha256>(), floor.tips()).unwrap(),
        );
        let continuation = certify(
            &harness.committee,
            3,
            continuation_history,
            &floor.tips(),
            vec![vec![body(1_534)], vec![body(1_535)]],
        );
        continuation.submit(&mailbox).await;
        report_finality(
            &mailbox,
            continuation.fact(b"continuation", &harness.committee, continuation.tips()),
        );
        let finals = wait_finals(&harness.context, &reporter, 2).await;
        assert_finals(
            &finals,
            &[
                vec![continuation.blocks[0][0].reference()],
                vec![continuation.blocks[1][0].reference()],
            ],
        );
        assert!(finals.iter().all(|(_, delivered)| *delivered == 2));
        continuation.finalize(&mailbox);
        harness.wait_updates(0, 4).await;
        harness.context.sleep(WAIT_STEP * 10).await;
        assert_eq!(reporter.finals(), finals);
        harness.shutdown().await;
    });
}

#[test]
fn a_large_finality_jump_reports_the_oldest_window_first_and_slides_to_the_tip() {
    runner(154).start(|context| async move {
        let mut harness = Harness::new(context, 154, [true, true]).await;
        // Each chain reads at most two final blocks ahead at a time.
        harness.final_lookahead = NZUsize!(2);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let reporter = harness.reporter(0);
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![
                vec![body(1_540)],
                vec![body(1_541), body(1_542), body(1_543), body(1_544)],
            ],
        );
        batch.submit(&mailbox).await;
        report_finality(
            &mailbox,
            batch.fact(b"jump", &harness.committee, batch.tips()),
        );
        // Chain 1's four final blocks span two windows: the oldest pair is reported first, then
        // the window slides to the tip, all before any block is ordered.
        let finals = wait_finals(&harness.context, &reporter, 5).await;
        let expected = batch
            .blocks
            .iter()
            .map(|chain| chain.iter().map(|block| block.reference()).collect())
            .collect::<Vec<_>>();
        assert_finals(&finals, &expected);
        assert!(finals.iter().all(|(_, delivered)| *delivered == 0));

        // Ordered delivery delivers every block and reports nothing again.
        batch.finalize(&mailbox);
        harness.wait_updates(0, 5).await;
        harness.context.sleep(WAIT_STEP * 10).await;
        assert_eq!(reporter.finals(), finals);
        harness.shutdown().await;
    });
}

#[test]
fn buffered_ingress_subscription_establishes_durable_custody() {
    runner(114).start(|context| async move {
        let mut harness = Harness::new(context, 114, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let target = harness.mailbox(1);
        let body = body(1_140);
        let header = harness.committee.transaction_header(ChainId::new(0), body.digest());
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        let reference = block.reference();

        let mut subscribed = Box::pin(target.subscribe_block(reference));
        commonware_macros::select! {
            result = &mut subscribed => panic!("missing block subscription completed early: {result:?}"),
            _ = harness.context.sleep(WAIT_STEP) => {},
        }
        assert_eq!(
            harness.buffer(0).broadcast_shared(
                Recipients::One(harness.committee.identities[1].clone()),
                Arc::clone(&block),
            ),
            Feedback::Ok
        );
        let received = commonware_macros::select! {
            received = &mut subscribed => received,
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("buffered ingress did not satisfy the block subscription")
            },
        }
        .unwrap();
        assert_eq!(received.as_ref(), block.as_ref());
        assert_eq!(
            target.get_block(reference).await.unwrap().as_deref(),
            Some(block.as_ref())
        );

        harness.crash(1).await;
        harness.start(1).await;
        assert_eq!(
            harness
                .mailbox(1)
                .get_block(reference)
                .await
                .unwrap()
                .as_deref(),
            Some(block.as_ref())
        );
        harness.shutdown().await;
    });
}

#[test]
fn buffered_ingress_cannot_outlive_durable_admission() {
    runner(121).start(|context| async move {
        let mut harness = Harness::new(context, 121, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let target = harness.mailbox(1);
        let body = body(1_210);
        let header = harness
            .committee
            .transaction_header(ChainId::new(0), body.digest());
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        let reference = block.reference();

        harness.nodes[1]
            .as_mut()
            .expect("target is running")
            .marshal
            .abort();
        harness.context.sleep(WAIT_STEP).await;
        let subscribed = target.subscribe_block(reference);
        assert_eq!(
            harness.buffer(0).broadcast_shared(
                Recipients::One(harness.committee.identities[1].clone()),
                Arc::clone(&block),
            ),
            Feedback::Ok
        );
        assert!(subscribed.await.is_err());

        harness.shutdown().await;
    });
}

#[test]
fn accepted_da_certificate_backfills_an_existing_block_subscription() {
    runner(115).start(|context| async move {
        let mut harness = Harness::new(context, 115, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let source = harness.mailbox(0);
        let target = harness.mailbox(1);
        let body = body(1_150);
        let header = harness.committee.transaction_header(ChainId::new(0), body.digest());
        let block = Arc::new(TransactionBlock::new(header.clone(), body).unwrap());
        let reference = block.reference();
        source.put_block(Arc::clone(&block)).await.unwrap();

        let mut subscribed = Box::pin(target.subscribe_block(reference));
        commonware_macros::select! {
            result = &mut subscribed => panic!("missing block subscription completed early: {result:?}"),
            _ = harness.context.sleep(WAIT_STEP) => {},
        }

        let votes = (0..harness.committee.codec().da_quorum())
            .map(Participant::from_usize)
            .map(|signer| harness.committee.da_vote(signer, header.clone()))
            .collect::<Vec<_>>();
        let certificate = harness
            .committee
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .unwrap();
        let artifact = Arc::new(Artifact::DaCertificate(certificate));
        let mut reporter = target.clone();
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );

        let received = commonware_macros::select! {
            received = &mut subscribed => received,
            _ = harness.context.sleep(Duration::from_secs(2)) => {
                panic!("DA certificate did not backfill the missing block")
            },
        }
        .unwrap();
        assert_eq!(received.as_ref(), block.as_ref());
        assert_eq!(
            target
                .get_block(reference)
                .await
                .unwrap()
                .expect("backfilled block is retained")
                .as_ref(),
            block.as_ref()
        );
        harness.crash(1).await;
        harness.start(1).await;
        assert_eq!(
            harness
                .mailbox(1)
                .get_block(reference)
                .await
                .unwrap()
                .as_deref(),
            Some(block.as_ref())
        );
        harness.shutdown().await;
    });
}

#[test]
fn unresolved_block_subscriptions_do_not_stall_router_intake() {
    runner(125).start(|context| async move {
        let mut harness = Harness::new(context, 125, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let target = harness.mailbox(1);
        let mut subscriptions = Vec::new();

        for marker in 0..harness
            .config(&harness.context, 1)
            .capacities
            .resolver_mailbox_size
            .get()
        {
            let missing = body(1_250 + marker as u64);
            let reference = harness
                .committee
                .transaction_header(ChainId::new(0), missing.digest())
                .block_ref::<Sha256>();
            let mailbox = target.clone();
            subscriptions.push(
                harness
                    .context
                    .child("subscription")
                    .shared(false)
                    .spawn(move |_| async move { mailbox.subscribe_block(reference).await }),
            );
        }

        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "resolver_pending_requests")
                >= subscriptions.len() as u64
            {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "resolver_pending_requests"),
            subscriptions.len() as u64,
            "every subscription is registered before testing router progress"
        );

        let progress = commonware_macros::select! {
            progress = target.progress() => progress,
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("unresolved subscriptions stalled unrelated router intake")
            },
        };
        assert!(progress.is_ok());

        for subscription in subscriptions {
            subscription.abort();
        }
        harness.shutdown().await;
    });
}

#[test]
fn saturated_router_backpressures_requests_until_capacity_returns() {
    runner(127).start(|context| async move {
        let mut harness = Harness::new(context, 127, [true, true]).await;
        let (started, _started) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        harness.verification_gate = Some(VerificationGate {
            started: Arc::new(Mutex::new(Some(started))),
            release: Arc::new(Mutex::new(Some(release_rx))),
        });
        harness.start(0).await;
        let target = harness.mailbox(0);
        let floor = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(1_270)], vec![body(1_271)]],
        );
        let install = |mailbox: TestMailbox| {
            let floor = Floor::new(
                Arc::clone(&floor.proof),
                Arc::clone(&floor.history),
                floor.tips(),
            );
            async move { mailbox.install_floor(floor).await }
        };

        // The first installation pauses in verification; the rest queue behind it, so every
        // router job stays occupied.
        let capacity = harness
            .config(&harness.context, 0)
            .capacities
            .resolver_mailbox_size
            .get();
        let mut installs = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            installs.push(
                harness
                    .context
                    .child("install")
                    .shared(false)
                    .spawn({
                        let install = install(target.clone());
                        move |_| install
                    }),
            );
        }
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "pending_jobs") >= capacity as u64 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "pending_jobs"),
            capacity as u64,
            "every router job is occupied before testing intake backpressure"
        );

        let mailbox_capacity = harness.catalog_mailbox_size.get();
        let mut queued = FuturesUnordered::new();
        for _ in 0..=mailbox_capacity {
            queued.push(
                harness
                    .context
                    .child("queued")
                    .shared(false)
                    .spawn({
                        let install = install(target.clone());
                        move |_| install
                    }),
            );
        }
        let rejected = commonware_macros::select! {
            result = queued.next() => result,
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("router did not reject work beyond its ingress capacity")
            },
        }
        .expect("one queued task remains")
        .expect("queued task remains alive");
        assert!(matches!(rejected, Err(MailboxError::Busy)));
        commonware_macros::select! {
            result = queued.next() => {
                panic!("router completed an accepted request while its execution pool remained full: {result:?}")
            },
            _ = harness.context.sleep(WAIT_STEP) => {},
        }

        release.send(()).unwrap();
        for install in installs {
            assert!(!matches!(install.await.unwrap(), Err(MailboxError::Busy)));
        }
        while !queued.is_empty() {
            let result = commonware_macros::select! {
                result = queued.next() => result,
                _ = harness.context.sleep(Duration::from_secs(1)) => {
                    panic!("router did not resume intake after execution capacity returned")
                },
            };
            assert!(!matches!(
                result
                    .expect("one queued task remains")
                    .expect("queued task remains alive"),
                Err(MailboxError::Busy)
            ));
        }
        assert_eq!(target.progress().await.unwrap().floor, floor.id());
        harness.shutdown().await;
    });
}

#[test]
fn relay_broadcasts_staged_blocks_by_digest() {
    runner(129).start(|context| async move {
        let mut harness = Harness::new(context, 129, [true, true]).await;
        harness.relay = true;
        harness.start(0).await;
        harness.start(1).await;
        let source = harness.mailbox(0);
        let mut relay = harness.relay(0);
        let peer = harness.buffer(1);
        let body = body(1_300);
        let header = harness
            .committee
            .transaction_header(ChainId::new(0), body.digest());
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        let reference = block.reference();

        // A digest that was never staged is not broadcast.
        assert_eq!(
            crate::Relay::broadcast(&mut relay, reference.digest(), ()),
            Feedback::Ok
        );
        harness.context.sleep(WAIT_STEP).await;
        assert!(get_buffered(&peer, reference).await.is_none());

        // Once staged, the relay broadcasts the block to every peer.
        let received = subscribe_buffered(&peer, reference);
        source.put_block(Arc::clone(&block)).await.unwrap();
        assert_eq!(
            crate::Relay::broadcast(&mut relay, reference.digest(), ()),
            Feedback::Ok
        );
        let received = commonware_macros::select! {
            received = received => received,
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("the relay did not broadcast the staged block")
            },
        };
        assert_eq!(received.as_deref(), Some(block.as_ref()));
        harness.shutdown().await;
    });
}

#[test]
fn relay_retains_every_block_the_engine_may_republish() {
    runner(133).start(|context| async move {
        let mut harness = Harness::new(context, 133, [true, true]).await;
        harness.relay = true;
        harness.start(0).await;
        harness.start(1).await;
        let source = harness.mailbox(0);
        let mut relay = harness.relay(0);
        let peer = harness.buffer(1);
        let retention = max_outbox_effects(PARTICIPANTS as usize).get();
        let blocks = (0..=retention as u64)
            .map(|marker| {
                let body = body(1_330 + marker);
                let header = harness
                    .committee
                    .transaction_header(ChainId::new(0), body.digest());
                Arc::new(TransactionBlock::new(header, body).unwrap())
            })
            .collect::<Vec<_>>();
        for block in &blocks {
            source.put_block(Arc::clone(block)).await.unwrap();
        }

        // One block past the engine's outbox bound evicts the oldest, and only the oldest.
        let [oldest, next] = [&blocks[0], &blocks[1]].map(|block| block.reference());
        assert_eq!(
            crate::Relay::broadcast(&mut relay, oldest.digest(), ()),
            Feedback::Ok
        );
        harness.context.sleep(WAIT_STEP).await;
        assert!(get_buffered(&peer, oldest).await.is_none());
        let received = subscribe_buffered(&peer, next);
        assert_eq!(
            crate::Relay::broadcast(&mut relay, next.digest(), ()),
            Feedback::Ok
        );
        let received = commonware_macros::select! {
            received = received => received,
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("the relay dropped a block within its retention")
            },
        };
        assert_eq!(received.as_deref(), Some(blocks[1].as_ref()));
        harness.shutdown().await;
    });
}

#[test]
fn saturated_router_queues_block_subscriptions_until_capacity_returns() {
    runner(128).start(|context| async move {
        let mut harness = Harness::new(context, 128, [true, true]).await;
        let (started, _started) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        harness.verification_gate = Some(VerificationGate {
            started: Arc::new(Mutex::new(Some(started))),
            release: Arc::new(Mutex::new(Some(release_rx))),
        });
        harness.start(0).await;
        let target = harness.mailbox(0);
        let floor = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(1_280)], vec![body(1_281)]],
        );
        let install = |mailbox: TestMailbox| {
            let floor = Floor::new(
                Arc::clone(&floor.proof),
                Arc::clone(&floor.history),
                floor.tips(),
            );
            async move { mailbox.install_floor(floor).await }
        };
        let spawn_install = |label| {
            harness.context.child(label).shared(false).spawn({
                let install = install(target.clone());
                move |_| install
            })
        };

        // The first installation pauses in verification and the rest occupy every router job,
        // then a full request queue of installations waits behind them.
        let capacity = harness
            .config(&harness.context, 0)
            .capacities
            .resolver_mailbox_size
            .get();
        let installs = (0..capacity)
            .map(|_| spawn_install("install"))
            .collect::<Vec<_>>();
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "pending_jobs") >= capacity as u64 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "pending_jobs"),
            capacity as u64,
            "every router job is occupied before filling the request queue"
        );
        let queued = (0..harness.catalog_mailbox_size.get())
            .map(|_| spawn_install("queued"))
            .collect::<Vec<_>>();
        // Let every queued installation reach the router's request queue.
        harness.context.sleep(WAIT_STEP).await;

        // Subscriptions past the full queue are retained rather than answered with busy, while
        // further staging-style work is still rejected.
        const SUBSCRIPTIONS: usize = 8;
        let mut subscriptions = FuturesUnordered::new();
        for marker in 0..SUBSCRIPTIONS {
            let missing = body(1_290 + marker as u64);
            let reference = harness
                .committee
                .transaction_header(ChainId::new(0), missing.digest())
                .block_ref::<Sha256>();
            let mailbox = target.clone();
            subscriptions.push(
                harness
                    .context
                    .child("subscription")
                    .shared(false)
                    .spawn(move |_| async move { mailbox.subscribe_block(reference).await }),
            );
        }
        harness.context.sleep(WAIT_STEP).await;
        let rejected = spawn_install("rejected");
        assert!(matches!(
            rejected.await.expect("rejected task remains alive"),
            Err(MailboxError::Busy)
        ));
        commonware_macros::select! {
            result = subscriptions.next() => {
                panic!("a subscription finished while the router was saturated: {result:?}")
            },
            _ = harness.context.sleep(Duration::from_secs(1)) => {},
        }

        // Once capacity returns, the router takes every retained subscription.
        release.send(()).unwrap();
        for install in installs.into_iter().chain(queued) {
            assert!(!matches!(install.await.unwrap(), Err(MailboxError::Busy)));
        }
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "block_subscription_callers")
                >= SUBSCRIPTIONS as u64
            {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "block_subscription_callers"),
            SUBSCRIPTIONS as u64,
            "every retained subscription reached the router"
        );
        commonware_macros::select! {
            result = subscriptions.next() => {
                panic!("a subscription for a missing block finished: {result:?}")
            },
            _ = harness.context.sleep(WAIT_STEP) => {},
        }
        for subscription in subscriptions {
            subscription.abort();
        }
        harness.shutdown().await;
    });
}

#[test]
fn subscriptions_past_the_slot_bound_wait_for_a_free_slot() {
    runner(134).start(|context| async move {
        let mut harness = Harness::new(context, 134, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let target = harness.mailbox(1);
        let capacity = harness
            .config(&harness.context, 1)
            .capacities
            .resolver_mailbox_size
            .get();
        let block = |marker: u64| {
            let body = body(marker);
            let header = harness.committee.transaction_header(ChainId::new(0), body.digest());
            Arc::new(TransactionBlock::new(header, body).unwrap())
        };
        let subscribe = |block: &Arc<TransactionBlock<Sha256, TestBody>>| {
            let mailbox = target.clone();
            let reference = block.reference();
            harness
                .context
                .child("subscription")
                .shared(false)
                .spawn(move |_| async move { mailbox.subscribe_block(reference).await })
        };
        let deliver = |block: &Arc<TransactionBlock<Sha256, TestBody>>| {
            assert_eq!(
                harness.buffer(0).broadcast_shared(
                    Recipients::One(harness.committee.identities[1].clone()),
                    Arc::clone(block),
                ),
                Feedback::Ok
            );
        };

        // Every slot is held by a subscription for a missing block.
        let held = (0..capacity as u64)
            .map(|marker| block(1_300 + marker))
            .collect::<Vec<_>>();
        let mut subscriptions = held.iter().map(subscribe).collect::<Vec<_>>();
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "block_subscription_callers")
                >= capacity as u64
            {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "block_subscription_callers"),
            capacity as u64
        );

        // One more subscription waits for a slot instead of registering or failing.
        let extra = block(1_399);
        let mut waiting = subscribe(&extra);
        commonware_macros::select! {
            result = &mut waiting => panic!("a subscription past the slot bound finished: {result:?}"),
            _ = harness.context.sleep(Duration::from_secs(1)) => {},
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "block_subscription_callers"),
            capacity as u64
        );

        // Answering one held subscription frees its slot, and the waiting one then completes.
        deliver(&held[0]);
        let first = subscriptions.remove(0).await.unwrap().unwrap();
        assert_eq!(first.as_ref(), held[0].as_ref());
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "block_subscription_callers")
                >= capacity as u64
            {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        deliver(&extra);
        let received = commonware_macros::select! {
            received = &mut waiting => received.unwrap().unwrap(),
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("the waiting subscription did not complete after a slot freed")
            },
        };
        assert_eq!(received.as_ref(), extra.as_ref());

        for subscription in subscriptions {
            subscription.abort();
        }
        harness.shutdown().await;
    });
}

#[test]
fn canceled_certified_subscription_stops_resolver_retries() {
    runner(126).start(|context| async move {
        let mut harness = Harness::new(context, 126, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let target = harness.mailbox(1);
        let missing = body(1_260);
        let header = harness.committee.transaction_header(ChainId::new(0), missing.digest());
        let reference = header.block_ref::<Sha256>();

        let mut subscribed = Box::pin(target.subscribe_block(reference));
        commonware_macros::select! {
            result = &mut subscribed => panic!("missing block subscription completed early: {result:?}"),
            _ = harness.context.sleep(WAIT_STEP) => {},
        }
        let votes = (0..harness.committee.codec().da_quorum())
            .map(Participant::from_usize)
            .map(|signer| harness.committee.da_vote(signer, header.clone()))
            .collect::<Vec<_>>();
        let certificate = harness
            .committee
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .unwrap();
        let artifact = Arc::new(Artifact::DaCertificate(certificate));
        let mut reporter = target.clone();
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );

        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "requests_sent_total") > 0 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert!(
            metric_total(&harness.context.encode(), "requests_sent_total") > 0,
            "accepted DA did not authorize an outbound resolver request"
        );

        drop(subscribed);
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "resolver_pending_requests") == 0 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "resolver_pending_requests"),
            0,
            "dropping the final subscriber did not retire its resolver request"
        );
        let requests = metric_total(&harness.context.encode(), "requests_sent_total");
        harness.context.sleep(Duration::from_millis(250)).await;
        assert_eq!(
            metric_total(&harness.context.encode(), "requests_sent_total"),
            requests,
            "a canceled subscription continued retrying"
        );

        harness.shutdown().await;
    });
}

#[test]
fn remote_resolver_backfills_exact_lqc_history_and_blocks() {
    runner(102).start(|context| async move {
        let mut harness = Harness::new(context, 102, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let first = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(20), body(21)], vec![body(22), body(23)]],
        );
        let second_history = Arc::new(
            TipRecord::at_tips(first.history.commitment::<Sha256>(), first.tips()).unwrap(),
        );
        let second = certify(
            &harness.committee,
            2,
            second_history,
            &first.tips(),
            vec![vec![body(24), body(25)], vec![body(26), body(27)]],
        );
        let source = harness.mailbox(0);
        let target = harness.mailbox(1);
        let ingress_block = &first.blocks[0][0];
        let ingress_reference = ingress_block.reference();
        let received = subscribe_buffered(&harness.buffer(1), ingress_reference);
        assert_eq!(
            harness.buffer(0).broadcast_shared(
                Recipients::One(harness.committee.identities[1].clone()),
                Arc::clone(ingress_block),
            ),
            Feedback::Ok
        );
        let received = commonware_macros::select! {
            received = received => received,
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("buffered broadcast did not deliver the exact block")
            },
        }
        .expect("buffered broadcast remains open");
        assert_eq!(received.as_ref(), ingress_block.as_ref());
        assert_eq!(received.reference(), ingress_reference);
        assert_eq!(
            get_buffered(&harness.buffer(1), ingress_reference)
                .await
                .expect("broadcast block remains buffered")
                .as_ref(),
            ingress_block.as_ref()
        );
        target.put_block(Arc::clone(ingress_block)).await.unwrap();

        let producer = harness
            .committee
            .config
            .producer(ChainId::new(0))
            .expect("chain has a configured producer");
        let signed = harness.committee.signers[producer.get() as usize]
            .sign_transaction_block(ingress_block.header().clone())
            .unwrap();
        let artifact = Arc::new(Artifact::TransactionBlock(signed));
        let mut ingress = target.clone();
        assert_eq!(
            ingress.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );

        first.submit(&source).await;
        first.finalize(&source);
        second.submit(&source).await;
        second.finalize(&source);
        harness.wait_updates(0, 8).await;

        let fetched = target.fetch_certificate(second.id()).await.unwrap();
        assert_eq!(fetched.as_ref(), second.proof.as_ref());
        for block in first.offset_major() {
            let reference = block.reference();
            assert_eq!(
                target.get_block(reference).await.unwrap().is_some(),
                reference == ingress_reference
            );
        }
        for block in second.offset_major() {
            let reference = block.reference();
            assert!(target.get_block(reference).await.unwrap().is_none());
        }
        harness.crash(1).await;
        harness.start(1).await;

        let delivered = harness.wait_updates(1, 8).await;
        let expected = first
            .offset_major()
            .into_iter()
            .chain(second.offset_major())
            .collect::<Vec<_>>();
        for (actual, block) in delivered.iter().zip(expected) {
            let reference = block.reference();
            assert_eq!(actual.block.as_ref(), block.as_ref());
            let stored = harness
                .mailbox(1)
                .get_block(reference)
                .await
                .unwrap()
                .expect("resolved block is admitted");
            assert_eq!(stored.as_ref(), block.as_ref());
        }
        assert_eq!(
            harness
                .mailbox(1)
                .get_certificate(second.id())
                .await
                .unwrap()
                .unwrap()
                .as_ref(),
            second.proof.as_ref()
        );
        harness.shutdown().await;
    });
}

#[test]
fn finality_activity_resolves_a_missing_history_opening() {
    runner(110).start(|context| async move {
        let mut harness = Harness::new(context, 110, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(30)], Vec::new()],
        );
        let source = harness.mailbox(0);
        batch.submit(&source).await;
        batch.finalize(&source);
        harness.wait_updates(0, 1).await;

        let target = harness.mailbox(1);
        let mut reporter = target.clone();
        let artifact = Arc::new(Artifact::Lqc(batch.proof.as_ref().clone()));
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );

        let delivered = harness.wait_updates(1, 1).await;
        let expected = &batch.blocks[0][0];
        let reference = expected.reference();
        assert_eq!(delivered[0].block.as_ref(), expected.as_ref());
        assert_eq!(
            target
                .get_block(reference)
                .await
                .unwrap()
                .expect("resolved block is retained")
                .as_ref(),
            expected.as_ref()
        );
        harness.shutdown().await;
    });
}

#[test]
fn late_local_history_completes_active_finality_resolution() {
    runner(118).start(|context| async move {
        let mut harness = Harness::new(context, 118, [true, true]).await;
        harness.start(0).await;
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(1_180)], Vec::new()],
        );
        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        let id = batch.id();
        let artifact = Arc::new(Artifact::Lqc(batch.proof.as_ref().clone()));
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );

        for _ in 0..WAIT_STEPS {
            if harness.catalog(0).lqc(id).await.unwrap().is_some()
                && metric_total(&harness.context.encode(), "resolver_pending_requests") > 0
            {
                assert_eq!(
                    reporter.report(Activity::HistoryAccepted {
                        view: batch.proof.view(),
                        commitment: batch.history.commitment::<Sha256>(),
                        record: Arc::clone(&batch.history),
                    }),
                    Feedback::Ok
                );
                let delivered = harness.wait_updates(0, 1).await;
                assert_eq!(delivered[0].block, batch.blocks[0][0]);
                harness.shutdown().await;
                return;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        panic!("finality resolution did not wait for the missing history");
    });
}

#[test]
fn malformed_reports_do_not_stop_the_service() {
    runner(105).start(|context| async move {
        let mut harness = Harness::new(context, 105, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let mailbox = harness.mailbox(0);
        let history = initial_history(&harness.committee);

        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(Activity::HistoryAccepted {
                view: View::new(1),
                commitment: digest(b"wrong history commitment", 0),
                record: Arc::clone(&history),
            }),
            Feedback::Ok
        );
        harness.context.sleep(Duration::from_millis(10)).await;
        mailbox
            .progress()
            .await
            .expect("an invalid history hint is request-local");
        let batch = certify(
            &harness.committee,
            1,
            history,
            harness.committee.config.genesis().tips(),
            vec![vec![body(25)], Vec::new()],
        );
        let artifact = Arc::new(Artifact::Lqc(batch.proof.as_ref().clone()));
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: ArtifactId::new(digest(b"wrong finality id", 0,)),
                artifact,
            }),
            Feedback::Ok
        );
        mailbox
            .progress()
            .await
            .expect("an invalid finality activity is request-local");

        let other_committee = Committee::builder(106, PARTICIPANTS)
            .namespace(NAMESPACE)
            .producers((0..CHAINS as u32).map(Participant::new).collect())
            .limits(PathLimits::new(4, 1).unwrap())
            .build();
        let other_epoch = certify(
            &other_committee,
            1,
            initial_history(&other_committee),
            other_committee.config.genesis().tips(),
            vec![vec![body(26)], Vec::new()],
        );
        let artifact = Arc::new(Artifact::Lqc(other_epoch.proof.as_ref().clone()));
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );
        mailbox
            .progress()
            .await
            .expect("a wrong-epoch finality activity is request-local");

        let wrong_epoch_block = &other_epoch.blocks[0][0];
        let wrong_epoch_reference = wrong_epoch_block.reference();
        let received = subscribe_buffered(&harness.buffer(0), wrong_epoch_reference);
        assert_eq!(
            harness.buffer(1).broadcast_shared(
                Recipients::One(harness.committee.identities[0].clone()),
                Arc::clone(wrong_epoch_block),
            ),
            Feedback::Ok
        );
        let received = commonware_macros::select! {
            result = received => result.expect("wrong-epoch block is buffered"),
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("wrong-epoch block was not buffered")
            },
        };
        assert_eq!(received.as_ref(), wrong_epoch_block.as_ref());
        let producer = other_committee
            .config
            .producer(ChainId::new(0))
            .expect("chain has a configured producer");
        let signed = other_committee.signers[producer.get() as usize]
            .sign_transaction_block(wrong_epoch_block.header().clone())
            .unwrap();
        let artifact = Arc::new(Artifact::TransactionBlock(signed));
        let mut ingress = mailbox.clone();
        assert_eq!(
            ingress.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );
        harness.context.sleep(Duration::from_millis(10)).await;
        mailbox
            .progress()
            .await
            .expect("a body-ready wrong-epoch header is request-local");
        assert!(
            mailbox
                .get_block(wrong_epoch_reference)
                .await
                .unwrap()
                .is_none()
        );

        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);
        let delivered = harness.wait_updates(0, 1).await;
        assert_eq!(delivered[0].block.as_ref(), batch.blocks[0][0].as_ref());
        harness.shutdown().await;
    });
}

#[test]
fn production_engine_reporter_survives_engine_and_marshal_restart() {
    deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(108)
            .with_timeout(Some(Duration::from_secs(180))),
    )
    .start(|context| async move {
        let mut cluster =
            Cluster::<MinPk>::new(&context, ClusterOptions::new(108, PARTICIPANTS)).await;
        let committee = cluster.fixture();
        let reporter = ApplicationReporter::<DigestBody>::new(true);
        let mut attached =
            start_attached_marshal(&context, cluster.oracle(), &committee, reporter.clone(), 0)
                .await;
        cluster
            .launch(LaunchSpec::new(0).reporter(attached.mailbox.clone()))
            .await;
        for index in 1..PARTICIPANTS as usize {
            cluster.start_one(index).await;
        }
        let nodes = cluster.all_nodes();
        cluster.await_ready(&nodes).await;

        cluster.produce_once();
        cluster
            .wait_produced(&nodes, 1, Duration::from_secs(240))
            .await;
        for &index in &nodes {
            let builds = cluster.app(index).log().lock().builds.clone();
            assert_eq!(builds.len(), 1);
            for (context, commitment) in builds {
                attached
                    .mailbox
                    .put_block(DigestBlock::from_context(context, DigestBody(commitment)))
                    .await
                    .unwrap();
            }
        }
        cluster
            .wait_finalized_all(1, Duration::from_secs(240))
            .await;
        let delivered = wait_delivered(&context, &reporter, PARTICIPANTS as usize).await;
        assert_eq!(delivered.len(), PARTICIPANTS as usize);
        for (index, delivered) in delivered.iter().enumerate() {
            assert_eq!(delivered.index, OutputIndex::new(index as u64 + 1));
            assert_eq!(
                delivered.block.reference(),
                delivered.block.header().block_ref::<Sha256>()
            );
        }
        let first_progress = attached.mailbox.progress().await.unwrap();
        assert_eq!(
            first_progress.acknowledged,
            OutputIndex::new(PARTICIPANTS as u64)
        );

        cluster.crash(0).await;
        attached.shutdown().await;
        let committee = cluster.fixture();
        attached =
            start_attached_marshal(&context, cluster.oracle(), &committee, reporter.clone(), 1)
                .await;
        cluster
            .launch(LaunchSpec::new(0).reporter(attached.mailbox.clone()))
            .await;
        cluster.await_ready(&[0]).await;
        let reopened = attached.mailbox.progress().await.unwrap();
        assert_eq!(reopened.floor_generation, first_progress.floor_generation);
        assert_eq!(reopened.committed, first_progress.committed);
        assert_eq!(reopened.acknowledged, first_progress.acknowledged);
        assert!(
            attached
                .mailbox
                .get_certificate(first_progress.floor)
                .await
                .unwrap()
                .is_some(),
            "marshal's finalized archive survives both restarts"
        );
        context.sleep(Duration::from_millis(100)).await;
        assert_eq!(reporter.delivered().len(), PARTICIPANTS as usize);
        assert!(cluster.inspect(0).await.is_some());

        for &index in &nodes {
            cluster.crash(index).await;
        }
        attached.shutdown().await;
    });
}

#[test]
fn missing_block_pressure_retires_old_subscriptions() {
    runner(109).start(|context| async move {
        let mut harness = Harness::new(context, 109, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let target = harness.mailbox(1);
        let mut reporter = target.clone();

        for marker in 0..64 {
            let missing = body(1_000 + marker);
            let artifact = Arc::new(Artifact::TransactionBlock(
                harness
                    .committee
                    .signed_block(ChainId::new(0), missing.digest()),
            ));
            loop {
                match reporter.report(Activity::ProtocolAccepted {
                    artifact_id: artifact.id::<Sha256>(),
                    artifact: Arc::clone(&artifact),
                }) {
                    Feedback::Ok => break,
                    Feedback::Backoff => harness.context.sleep(WAIT_STEP).await,
                    Feedback::Closed => panic!("marshal closed while filling block waiters"),
                }
            }
            harness.context.sleep(WAIT_STEP).await;
        }

        let body = body(2_000);
        let commitment = body.digest();
        let header = harness
            .committee
            .transaction_header(ChainId::new(0), commitment);
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        let reference = block.reference();
        let received = subscribe_buffered(&harness.buffer(1), reference);
        assert_eq!(
            harness.buffer(0).broadcast_shared(
                Recipients::One(harness.committee.identities[1].clone()),
                Arc::clone(&block),
            ),
            Feedback::Ok
        );
        let received = commonware_macros::select! {
            received = received => received,
            _ = harness.context.sleep(Duration::from_secs(1)) => None,
        }
        .expect("complete block reaches buffered ingress");
        assert_eq!(received.as_ref(), block.as_ref());

        let artifact = Arc::new(Artifact::TransactionBlock(
            harness.committee.signed_block(ChainId::new(0), commitment),
        ));
        let admitted = target.subscribe_block(reference);
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );
        let admitted = commonware_macros::select! {
            admitted = admitted => admitted,
            _ = harness.context.sleep(Duration::from_secs(1)) => {
                panic!("new body-ready hint remained blocked behind missing bodies")
            },
        }
        .unwrap();
        assert_eq!(admitted.as_ref(), block.as_ref());
        harness.shutdown().await;
    });
}

#[test]
fn crash_redelivers_only_until_acknowledgement_is_durable() {
    runner(103).start(|context| async move {
        let mut harness = Harness::new(context, 103, [false, true]).await;
        harness.start(0).await;
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(30)], vec![body(31)]],
        );
        let expected = batch.offset_major();
        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);
        let first = harness.wait_updates(0, 2).await;
        assert_eq!(first[0].block.as_ref(), expected[0].as_ref());
        assert_eq!(first[1].block.as_ref(), expected[1].as_ref());
        assert_eq!(
            harness.reporter(0).pending(),
            vec![OutputIndex::new(1), OutputIndex::new(2)]
        );
        let progress = harness
            .wait_progress(0, |progress| progress.committed == OutputIndex::new(2))
            .await;
        assert_eq!(progress.acknowledged, OutputIndex::zero());
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            2,
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            0,
            "{metrics}"
        );

        assert_eq!(
            harness.reporter(0).acknowledge_next(),
            Some(OutputIndex::new(1))
        );
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(1))
            .await;
        harness.crash(0).await;
        harness.start(0).await;
        let redelivered = harness.wait_updates(0, 3).await;
        assert_eq!(redelivered[2].index, OutputIndex::new(2));
        assert_eq!(redelivered[2].block.as_ref(), expected[1].as_ref());
        assert_eq!(harness.reporter(0).pending(), vec![OutputIndex::new(2)]);
        assert_eq!(
            harness.reporter(0).acknowledge_next(),
            Some(OutputIndex::new(2))
        );
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(2))
            .await;
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            0,
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            1,
            "{metrics}"
        );

        harness.crash(0).await;
        harness.start(0).await;
        harness
            .wait_progress(0, |progress| {
                progress.committed == OutputIndex::new(2)
                    && progress.acknowledged == OutputIndex::new(2)
            })
            .await;
        harness.context.sleep(Duration::from_millis(100)).await;
        assert_eq!(harness.reporter(0).delivered().len(), 3);
        harness.shutdown().await;
    });
}

#[test]
fn delivery_pipelines_exact_acknowledgements_up_to_the_configured_bound() {
    runner(111).start(|context| async move {
        let mut harness = Harness::new(context, 111, [false, true]).await;
        harness.max_pending_acks = NZUsize!(3);
        harness.start(0).await;
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(60), body(61)], vec![body(62), body(63)]],
        );
        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);

        let delivered = harness.wait_updates(0, 3).await;
        assert_eq!(
            delivered.iter().map(|item| item.index).collect::<Vec<_>>(),
            vec![
                OutputIndex::new(1),
                OutputIndex::new(2),
                OutputIndex::new(3)
            ]
        );
        harness.context.sleep(Duration::from_millis(100)).await;
        assert_eq!(harness.reporter(0).delivered().len(), 3);

        let reporter = harness.reporter(0);
        assert!(reporter.acknowledge(OutputIndex::new(2)));
        assert!(reporter.acknowledge(OutputIndex::new(3)));
        harness.context.sleep(Duration::from_millis(100)).await;
        assert_eq!(
            harness.mailbox(0).progress().await.unwrap().acknowledged,
            OutputIndex::zero()
        );
        assert_eq!(reporter.pending(), vec![OutputIndex::new(1)]);

        assert!(reporter.acknowledge(OutputIndex::new(1)));
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(3))
            .await;
        let delivered = harness.wait_updates(0, 4).await;
        assert_eq!(delivered[3].index, OutputIndex::new(4));
        assert_eq!(reporter.pending(), vec![OutputIndex::new(4)]);

        assert!(reporter.acknowledge(OutputIndex::new(4)));
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(4))
            .await;
        harness.shutdown().await;
    });
}

#[test]
fn sustained_one_output_commits_remain_dense_and_memory_only() {
    runner(120).start(|context| async move {
        const OPENINGS: u64 = 4;
        const BLOCKS_PER_CHAIN: u64 = 4;

        let mut harness = Harness::new(context, 120, [true, true]).await;
        harness.max_commit_outputs = NZUsize!(1);
        harness.max_pending_acks = NZUsize!(8);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let mut history = initial_history(&harness.committee);
        let mut bases = harness.committee.config.genesis().tips().to_vec();
        let mut expected = Vec::new();
        for view in 1..=OPENINGS {
            let batch = certify(
                &harness.committee,
                view,
                Arc::clone(&history),
                &bases,
                vec![
                    (0..BLOCKS_PER_CHAIN)
                        .map(|offset| body(3_000 + view * 100 + offset))
                        .collect(),
                    (0..BLOCKS_PER_CHAIN)
                        .map(|offset| body(4_000 + view * 100 + offset))
                        .collect(),
                ],
            );
            batch.submit(&mailbox).await;
            batch.finalize(&mailbox);
            expected.extend(batch.offset_major());
            bases = batch.tips();
            history = Arc::new(
                TipRecord::at_tips(batch.history.commitment::<Sha256>(), bases.clone()).unwrap(),
            );
        }

        let delivered = harness.wait_updates(0, expected.len()).await;
        for (offset, (actual, expected)) in delivered.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(offset as u64 + 1));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }
        let last = OutputIndex::new(u64::try_from(expected.len()).unwrap());
        harness
            .wait_progress(0, |progress| progress.acknowledged == last)
            .await;
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            expected.len() as u64,
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            0,
            "{metrics}"
        );
        harness.shutdown().await;
    });
}

#[test]
fn sustained_history_catchup_remains_dense_and_memory_only() {
    runner(121).start(|context| async move {
        const OPENINGS: u64 = 20;
        const BLOCKS_PER_CHAIN: u64 = 4;
        const OUTPUTS: usize = OPENINGS as usize * BLOCKS_PER_CHAIN as usize * CHAINS;

        let mut harness = Harness::new(context, 121, [true, true]).await;
        harness.catalog_mailbox_size = NZUsize!(256);
        harness.max_commit_outputs = NZUsize!(128);
        harness.max_pending_acks = NZUsize!(256);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let mut reporter = mailbox.clone();
        let mut history = initial_history(&harness.committee);
        let mut bases = harness.committee.config.genesis().tips().to_vec();
        let mut expected = Vec::with_capacity(OUTPUTS);
        let mut final_proof = None;
        for view in 1..=OPENINGS {
            let batch = certify(
                &harness.committee,
                view,
                Arc::clone(&history),
                &bases,
                vec![
                    (0..BLOCKS_PER_CHAIN)
                        .map(|offset| body(5_000 + view * 100 + offset))
                        .collect(),
                    (0..BLOCKS_PER_CHAIN)
                        .map(|offset| body(6_000 + view * 100 + offset))
                        .collect(),
                ],
            );
            batch.submit(&mailbox).await;
            assert_eq!(
                reporter.report(Activity::HistoryAccepted {
                    view: batch.proof.view(),
                    commitment: batch.history.commitment::<Sha256>(),
                    record: Arc::clone(&batch.history),
                }),
                Feedback::Ok
            );
            expected.extend(batch.offset_major());
            bases = batch.tips();
            history = Arc::new(
                TipRecord::at_tips(batch.history.commitment::<Sha256>(), bases.clone()).unwrap(),
            );
            final_proof = Some(batch.proof);
        }
        let artifact = Arc::new(Artifact::Lqc(
            final_proof.expect("at least one opening").as_ref().clone(),
        ));
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );

        let delivered = harness.wait_updates(0, OUTPUTS).await;
        for (offset, (actual, expected)) in delivered.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(offset as u64 + 1));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }
        let last = OutputIndex::new(u64::try_from(OUTPUTS).unwrap());
        harness
            .wait_progress(0, |progress| progress.acknowledged == last)
            .await;

        let metrics = harness.context.encode();
        let expected_outputs = OUTPUTS as u64;
        for (metric, expected) in [
            ("custody_planned_outputs_total", expected_outputs),
            ("custody_local_outputs_total", expected_outputs),
            ("custody_fetched_outputs_total", 0),
            ("delivery_hot_outputs_total", expected_outputs),
            ("delivery_stored_outputs_total", 0),
            ("runtime_storage_reads_total", 0),
        ] {
            assert_eq!(metric_total(&metrics, metric), expected, "{metrics}");
        }
        harness.shutdown().await;
    });
}

#[test]
fn delivery_pressure_materializes_evicted_hot_blocks_from_custody() {
    runner(119).start(|context| async move {
        let mut harness = Harness::new(context, 119, [false, true]).await;
        harness.catalog_mailbox_size = NZUsize!(4);
        harness.max_commit_outputs = NZUsize!(1);
        harness.max_hot_block_bytes = NZUsize!(1);
        harness.max_pending_acks = NZUsize!(1);
        harness.start(0).await;
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![
                vec![body(80), body(81), body(82), body(83)],
                vec![body(84), body(85), body(86), body(87)],
            ],
        );
        let expected = batch.offset_major();
        let committed = OutputIndex::new(u64::try_from(expected.len()).unwrap());
        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);

        harness.wait_updates(0, 1).await;
        harness
            .wait_progress(0, |progress| progress.committed == committed)
            .await;
        for (offset, block) in expected.iter().enumerate() {
            let index = OutputIndex::new(u64::try_from(offset + 1).unwrap());
            let delivered = harness.wait_updates(0, offset + 1).await;
            assert_eq!(delivered[offset].index, index);
            assert_eq!(delivered[offset].block.as_ref(), block.as_ref());
            assert_eq!(harness.reporter(0).acknowledge_next(), Some(index));
            harness
                .wait_progress(0, |progress| progress.acknowledged == index)
                .await;
        }
        let metrics = harness.context.encode();
        assert!(
            metric_total(&metrics, "delivery_stored_outputs_total") > 0,
            "{metrics}"
        );
        assert!(
            metrics.contains("requests_started_total{reason=\"FinalizedBody\"} 0"),
            "{metrics}"
        );
        assert_eq!(harness.reporter(0).delivered().len(), expected.len());
        harness.shutdown().await;
    });
}

#[test]
fn durable_output_descriptors_avoid_finalized_metadata_rereads() {
    runner(131).start(|context| async move {
        let mut harness = Harness::new(context, 131, [true, true]).await;
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![
                vec![body(90), body(91), body(92), body(93)],
                vec![body(94), body(95), body(96), body(97)],
            ],
        );
        let expected = batch.offset_major();
        let descriptor_bytes = std::mem::size_of::<StoredRef<Sha256Digest>>();
        let cache_bytes = descriptor_bytes
            .checked_mul(expected.len())
            .expect("delivery descriptor cache size fits usize");
        assert!(
            cache_bytes
                < expected
                    .iter()
                    .map(|block| block.encode_size())
                    .sum::<usize>()
        );
        harness.max_hot_block_bytes = NonZeroUsize::new(cache_bytes).unwrap();
        harness.max_pending_acks = NonZeroUsize::new(expected.len()).unwrap();
        harness.start(0).await;

        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);

        let delivered = harness.wait_updates(0, expected.len()).await;
        for (offset, (actual, expected)) in delivered.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(offset as u64 + 1));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }
        let last = OutputIndex::new(u64::try_from(expected.len()).unwrap());
        harness
            .wait_progress(0, |progress| progress.acknowledged == last)
            .await;

        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "marshal_storage_final_blocks_gets_total"),
            expected.len() as u64,
            "{metrics}"
        );
        harness.shutdown().await;
    });
}

#[test]
fn delivery_materializes_only_the_cold_prefix_before_a_retained_hot_output() {
    runner(130).start(|context| async move {
        let mut harness = Harness::new(context, 130, [true, true]).await;
        let batch = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(88)], vec![body(89)]],
        );
        let expected = batch.offset_major();
        let block_bytes = expected[0].encode_size();
        assert_eq!(expected[1].encode_size(), block_bytes);
        let descriptor_bytes = std::mem::size_of::<StoredRef<Sha256Digest>>();
        harness.max_hot_block_bytes = NonZeroUsize::new(block_bytes + descriptor_bytes).unwrap();
        harness.max_pending_acks = NZUsize!(2);
        harness.start(0).await;

        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);

        let delivered = harness.wait_updates(0, 2).await;
        for (offset, (actual, expected)) in delivered.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(offset as u64 + 1));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(2))
            .await;

        let metrics = harness.context.encode();
        for (metric, expected) in [
            ("custody_local_outputs_total", 2),
            ("custody_fetched_outputs_total", 0),
            ("delivery_stored_outputs_total", 1),
            ("delivery_hot_outputs_total", 1),
        ] {
            assert_eq!(metric_total(&metrics, metric), expected, "{metrics}");
        }
        harness.shutdown().await;
    });
}

#[test]
fn canceled_floor_install_still_retires_certified_requests() {
    runner(133).start(|context| async move {
        let mut harness = Harness::new(context, 133, [true, true]).await;
        let (started, mut started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        harness.verification_gate = Some(VerificationGate {
            started: Arc::new(Mutex::new(Some(started))),
            release: Arc::new(Mutex::new(Some(release_rx))),
        });
        harness.start(0).await;

        let floor = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(133)], vec![body(134)]],
        );
        let header = floor.blocks[0][0].header().clone();
        let votes = (0..harness.committee.codec().da_quorum())
            .map(Participant::from_usize)
            .map(|signer| harness.committee.da_vote(signer, header.clone()))
            .collect::<Vec<_>>();
        let certificate = harness
            .committee
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .unwrap();
        let artifact = Arc::new(Artifact::DaCertificate(certificate));
        let mailbox = harness.mailbox(0);
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "resolver_pending_requests") == 1 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "resolver_pending_requests"),
            1
        );

        let floor_id = floor.id();
        let mut installation = Box::pin(mailbox.install_floor(Floor::new(
            Arc::clone(&floor.proof),
            Arc::clone(&floor.history),
            floor.tips(),
        )));
        commonware_macros::select! {
            result = &mut started_rx => result.unwrap(),
            result = &mut installation => panic!("floor installation completed before verification paused: {result:?}"),
        }
        drop(installation);
        harness.context.sleep(WAIT_STEP).await;
        release.send(()).unwrap();
        harness
            .wait_progress(0, |progress| {
                progress.floor_generation == 1 && progress.floor == floor_id
            })
            .await;

        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "resolver_pending_requests") == 0 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "resolver_pending_requests"),
            0,
            "installed floor left its certified resolver request active"
        );
        harness.shutdown().await;
    });
}

#[test]
fn floor_installation_retires_the_pending_delivery_window() {
    runner(112).start(|context| async move {
        let mut harness = Harness::new(context, 112, [false, true]).await;
        harness.max_pending_acks = NZUsize!(2);
        harness.start(0).await;
        let first = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(70)], vec![body(71)]],
        );
        let mailbox = harness.mailbox(0);
        first.submit(&mailbox).await;
        first.finalize(&mailbox);
        harness.wait_updates(0, 2).await;
        harness
            .wait_progress(0, |progress| {
                progress.committed == OutputIndex::new(2) && progress.acknowledged.is_zero()
            })
            .await;

        let floor_history = Arc::new(
            TipRecord::at_tips(first.history.commitment::<Sha256>(), first.tips()).unwrap(),
        );
        let floor = certify(
            &harness.committee,
            2,
            floor_history,
            &first.tips(),
            vec![vec![body(72)], vec![body(73)]],
        );
        mailbox
            .install_floor(Floor::new(
                Arc::clone(&floor.proof),
                Arc::clone(&floor.history),
                floor.tips(),
            ))
            .await
            .unwrap();
        // The floor's frontier is at height two on both chains, so its index is four.
        harness
            .wait_progress(0, |progress| {
                progress.floor_generation == 1
                    && progress.committed == OutputIndex::new(4)
                    && progress.acknowledged == OutputIndex::new(4)
            })
            .await;
        harness.reporter(0).discard_pending();

        let continuation_history = Arc::new(
            TipRecord::at_tips(floor.history.commitment::<Sha256>(), floor.tips()).unwrap(),
        );
        let continuation = certify(
            &harness.committee,
            3,
            continuation_history,
            &floor.tips(),
            vec![vec![body(74)], vec![body(75)]],
        );
        continuation.submit(&mailbox).await;
        continuation.finalize(&mailbox);
        let delivered = harness.wait_updates(0, 4).await;
        assert_eq!(delivered[2].index, OutputIndex::new(5));
        assert_eq!(delivered[3].index, OutputIndex::new(6));

        // Once the engine releases every block, pruning at the floor reclaims both generations'
        // rows below it and their bodies, except each chain's newest, which its next block builds
        // on.
        let reporter = harness.reporter(0);
        assert!(reporter.acknowledge(OutputIndex::new(5)));
        assert!(reporter.acknowledge(OutputIndex::new(6)));
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(6))
            .await;
        continuation.release(&mailbox);
        mailbox.prune(OutputIndex::new(6)).await.unwrap();
        for block in first.blocks.iter().flatten() {
            assert!(
                mailbox
                    .get_block(block.reference())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        for chain in &continuation.blocks {
            for (offset, block) in chain.iter().enumerate() {
                let retained = mailbox.get_block(block.reference()).await.unwrap();
                assert_eq!(retained.is_some(), offset + 1 == chain.len());
            }
        }

        harness.crash(0).await;
        harness.start(0).await;
        let reopened = harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(6))
            .await;
        assert_eq!(reopened.committed, OutputIndex::new(6));
        harness.shutdown().await;
    });
}

#[test]
fn a_read_below_the_floor_index_resumes_at_each_later_generation() {
    runner(114).start(|context| async move {
        let mut harness = Harness::new(context, 114, [false, true]).await;
        harness.max_pending_acks = NZUsize!(2);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let first = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(80)], vec![body(81)]],
        );
        first.submit(&mailbox).await;
        first.finalize(&mailbox);
        harness.wait_updates(0, 2).await;

        // Each floor's frontier is two heights above the previous generation's rows, so the
        // first generation holds rows one and two, the second floor index four and rows five and
        // six, and the third floor index eight.
        let mut tips = first.tips();
        let mut history = first.history.commitment::<Sha256>();
        for (view, generation, index) in [(2, 1, 4), (4, 2, 8)] {
            let record = Arc::new(TipRecord::at_tips(history, tips.clone()).unwrap());
            let floor = certify(
                &harness.committee,
                view,
                record,
                &tips,
                vec![vec![body(80 + view)], vec![body(90 + view)]],
            );
            mailbox
                .install_floor(Floor::new(
                    Arc::clone(&floor.proof),
                    Arc::clone(&floor.history),
                    floor.tips(),
                ))
                .await
                .unwrap();
            harness
                .wait_progress(0, |progress| {
                    progress.floor_generation == generation
                        && progress.committed == OutputIndex::new(index)
                })
                .await;
            harness.reporter(0).discard_pending();
            if generation == 2 {
                break;
            }
            let record = Arc::new(
                TipRecord::at_tips(floor.history.commitment::<Sha256>(), floor.tips()).unwrap(),
            );
            let continuation = certify(
                &harness.committee,
                view + 1,
                record,
                &floor.tips(),
                vec![vec![body(100 + view)], vec![body(110 + view)]],
            );
            continuation.submit(&mailbox).await;
            continuation.finalize(&mailbox);
            harness.wait_updates(0, 4).await;
            tips = continuation.tips();
            history = continuation.history.commitment::<Sha256>();
        }

        // A read that begins in a gap below the floor index resumes at the next generation's
        // rows, and one past them finds none below the newest floor.
        let catalog = harness.catalog(0);
        let mut reads = Vec::new();
        for start in [1, 3, 7] {
            let refs = catalog
                .output_refs(OutputIndex::new(start), NZUsize!(4), NZUsize!(1024 * 1024))
                .await
                .unwrap();
            reads.push(
                refs.iter()
                    .map(|output| output.index.get())
                    .collect::<Vec<_>>(),
            );
        }
        assert_eq!(reads, vec![vec![1, 2], vec![5, 6], vec![]]);
        harness.shutdown().await;
    });
}

#[test]
fn a_served_floor_resumes_a_fresh_node_at_the_same_indices() {
    runner(113).start(|context| async move {
        let mut harness = Harness::new(context, 113, [true, true]).await;
        harness.start(0).await;
        let source = harness.mailbox(0);

        // Three views each certify one block per chain, so their floors end at indices 2, 4, 6.
        let mut history = initial_history(&harness.committee);
        let mut tips = harness.committee.config.genesis().tips().to_vec();
        let mut views = Vec::new();
        for view in 1..=3u64 {
            let bodies = vec![vec![body(90 + 2 * view)], vec![body(91 + 2 * view)]];
            let certified = certify(&harness.committee, view, history, &tips, bodies);
            certified.submit(&source).await;
            certified.finalize(&source);
            let id = certified.id();
            harness
                .wait_progress(0, |progress| progress.floor == id)
                .await;
            history = Arc::new(
                TipRecord::at_tips(certified.history.commitment::<Sha256>(), certified.tips())
                    .unwrap(),
            );
            tips = certified.tips();
            views.push(certified);
        }
        let delivered = harness.wait_updates(0, 6).await;

        let floor_at = |at| {
            let source = source.clone();
            async move { source.floor_at(OutputIndex::new(at)).await.unwrap() }
        };
        assert!(floor_at(1).await.is_none());
        for (at, index, view) in [(2, 2, 0), (3, 2, 0), (5, 4, 1), (100, 6, 2)] {
            let (found, floor) = floor_at(at).await.unwrap();
            assert_eq!(found, OutputIndex::new(index));
            assert_eq!(floor.anchor().id::<Sha256>(), views[view].id());
            assert_eq!(floor.emitted(), views[view].tips().as_slice());
        }

        // With every block released, pruning at index five keeps the floor at or below it, every
        // output after that floor, and each chain's newest block at the floor, which its next
        // block builds on.
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(6))
            .await;
        views[2].release(&source);
        source.prune(OutputIndex::new(5)).await.unwrap();
        assert!(floor_at(3).await.is_none());
        let (found, _) = floor_at(5).await.unwrap();
        assert_eq!(found, OutputIndex::new(4));
        for (position, view) in views.iter().enumerate() {
            for chain in &view.blocks {
                for (offset, block) in chain.iter().enumerate() {
                    let local = source.get_block(block.reference()).await.unwrap();
                    let retained = position == 2 || (position == 1 && offset + 1 == chain.len());
                    assert_eq!(local.is_some(), retained);
                }
            }
        }

        // A fresh node installs the floor at index four and receives the outputs after it at the
        // indices the source assigned.
        harness.start(1).await;
        let target = harness.mailbox(1);
        let (_, floor) = floor_at(4).await.unwrap();
        target.install_floor(floor).await.unwrap();
        harness
            .wait_progress(1, |progress| progress.committed == OutputIndex::new(4))
            .await;
        views[2].submit(&target).await;
        views[2].finalize(&target);
        let resumed = harness.wait_updates(1, 2).await;
        for (resumed, delivered) in resumed.iter().zip(&delivered[4..]) {
            assert_eq!(resumed.index, delivered.index);
            assert_eq!(resumed.block.as_ref(), delivered.block.as_ref());
        }
        harness.shutdown().await;
    });
}

/// Returns, per chain, whether each view's block is still held.
async fn held(mailbox: &TestMailbox, views: &[Certified]) -> Vec<Vec<bool>> {
    let mut held = vec![Vec::new(); CHAINS];
    for view in views {
        for (chain, blocks) in view.blocks.iter().enumerate() {
            for block in blocks {
                let local = mailbox.get_block(block.reference()).await.unwrap();
                held[chain].push(local.is_some());
            }
        }
    }
    held
}

/// Reports that the engine durably recorded `certified` and no longer verifies its chain's
/// blocks at or below `released`.
fn record(mailbox: &TestMailbox, certified: BlockRef<Sha256Digest>, released: u64) {
    let mut reporter = mailbox.clone();
    let feedback = reporter.report(Activity::CertificateRecorded {
        certified,
        released: Height::new(released),
    });
    assert!(feedback.accepted());
}

#[test]
fn pruning_keeps_every_block_the_engine_may_still_verify() {
    runner(135).start(|context| async move {
        let mut harness = Harness::new(context, 135, [true, true]).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);

        // Four views each certify one block per chain, at heights one through four.
        let mut history = initial_history(&harness.committee);
        let mut tips = harness.committee.config.genesis().tips().to_vec();
        let mut views = Vec::new();
        for view in 1..=4u64 {
            let bodies = vec![vec![body(120 + 2 * view)], vec![body(121 + 2 * view)]];
            let certified = certify(&harness.committee, view, history, &tips, bodies);
            history = Arc::new(
                TipRecord::at_tips(certified.history.commitment::<Sha256>(), certified.tips())
                    .unwrap(),
            );
            tips = certified.tips();
            views.push(certified);
        }
        for view in &views[..3] {
            view.submit(&mailbox).await;
            view.finalize(&mailbox);
        }
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(6))
            .await;

        // Without a release, pruning at the floor at index six keeps every block, and the output
        // at that index stays readable.
        mailbox.prune(OutputIndex::new(6)).await.unwrap();
        assert_eq!(held(&mailbox, &views[..3]).await, [[true; 3]; 2]);
        let refs = harness
            .catalog(0)
            .output_refs(OutputIndex::new(6), NZUsize!(1), NZUsize!(1024 * 1024))
            .await
            .unwrap();
        assert_eq!(refs[0].index, OutputIndex::new(6));

        // Chain zero's engine may still verify height two and above.
        let tips = views[2].tips();
        record(&mailbox, tips[0], 1);
        mailbox.prune(OutputIndex::new(6)).await.unwrap();
        assert_eq!(
            held(&mailbox, &views[..3]).await,
            [[false, true, true], [true; 3]]
        );

        // A stale release never lowers the bound, and each chain keeps its newest pruned block,
        // which its next block builds on, even once the engine releases it.
        record(&mailbox, tips[0], 3);
        record(&mailbox, tips[0], 0);
        record(&mailbox, tips[1], 3);
        mailbox.prune(OutputIndex::new(6)).await.unwrap();
        assert_eq!(
            held(&mailbox, &views[..3]).await,
            [[false, false, true], [false, false, true]]
        );

        // Releases are not durable: after a restart, nothing more is pruned until the engine
        // reports them again.
        harness.crash(0).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        views[3].submit(&mailbox).await;
        views[3].finalize(&mailbox);
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(8))
            .await;
        mailbox.prune(OutputIndex::new(8)).await.unwrap();
        assert_eq!(held(&mailbox, &views[2..]).await, [[true; 2]; 2]);
        views[3].release(&mailbox);
        mailbox.prune(OutputIndex::new(8)).await.unwrap();
        assert_eq!(held(&mailbox, &views[2..]).await, [[false, true]; 2]);
        harness.shutdown().await;
    });
}

#[test]
fn ledger_prunes_to_the_floors_it_serves() {
    runner(114).start(|context| async move {
        let mut harness = Harness::new(context, 114, [true, true]).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        assert_eq!(
            Ledger::ack_window(&mailbox),
            harness
                .config(&harness.context, 0)
                .capacities
                .max_pending_acks
        );

        // Two views each certify one block per chain, so their floors end at indices 2 and 4.
        let first = certify(
            &harness.committee,
            1,
            initial_history(&harness.committee),
            harness.committee.config.genesis().tips(),
            vec![vec![body(120)], vec![body(121)]],
        );
        first.submit(&mailbox).await;
        first.finalize(&mailbox);
        let history = Arc::new(
            TipRecord::at_tips(first.history.commitment::<Sha256>(), first.tips()).unwrap(),
        );
        let second = certify(
            &harness.committee,
            2,
            history,
            &first.tips(),
            vec![vec![body(122)], vec![body(123)]],
        );
        second.submit(&mailbox).await;
        second.finalize(&mailbox);
        let delivered = harness.wait_updates(0, 4).await;
        harness
            .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(4))
            .await;

        // Pruning below index three keeps the floor at index two and every output after it.
        Ledger::prune(&mailbox, OutputIndex::new(3)).await.unwrap();
        let (index, floor) = Floors::floor_at(&mailbox, OutputIndex::new(3))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(index, OutputIndex::new(2));
        assert_eq!(floor.anchor().id::<Sha256>(), first.id());
        for update in delivered.iter().filter(|update| update.index > index) {
            let block = mailbox.get_block(update.block.reference()).await.unwrap();
            assert_eq!(block.as_deref(), Some(update.block.as_ref()));
        }

        // A fresh node installs the served floor and resumes after the same index, then rejects
        // it once installed, as stale.
        harness.start(1).await;
        assert_eq!(
            Floors::install(&harness.mailbox(1), floor.clone())
                .await
                .unwrap(),
            Some(index)
        );
        harness
            .wait_progress(1, |progress| progress.committed == index)
            .await;
        assert_eq!(
            Floors::install(&harness.mailbox(1), floor).await.unwrap(),
            None
        );
        harness.shutdown().await;
    });
}

/// A producer application that numbers its bodies by height and records the ancestry each call
/// saw, as heights newest first.
#[derive(Clone)]
struct ProducerApplication {
    ancestries: Arc<Mutex<Vec<Vec<u64>>>>,
    /// Builds each block one height above the requested position.
    misplace: bool,
    /// The verdict `verify` returns.
    admit: bool,
}

impl ProducerApplication {
    fn new() -> Self {
        Self {
            ancestries: Arc::default(),
            misplace: false,
            admit: true,
        }
    }

    async fn record(&self, ancestry: impl crate::ancestry::Ancestry<TestBlock>) {
        let heights = ancestry
            .map(|block| block.header().height().get())
            .collect()
            .await;
        self.ancestries.lock().push(heights);
    }

    fn last_ancestry(&self) -> Vec<u64> {
        self.ancestries.lock().last().cloned().unwrap()
    }
}

impl crate::Application<deterministic::Context> for ProducerApplication {
    type Context = Context<Sha256Digest>;
    type Block = TestBlock;
    type Input = ();

    async fn propose(
        &mut self,
        (_, context): (deterministic::Context, Self::Context),
        ancestry: impl crate::ancestry::Ancestry<Self::Block>,
        _: Self::Input,
    ) -> Option<Self::Block> {
        self.record(ancestry).await;
        let context = if self.misplace {
            Context::new(
                context.epoch(),
                context.chain(),
                context.height().next(),
                context.parent(),
            )
            .unwrap()
        } else {
            context
        };
        Some(TransactionBlock::from_context(
            context,
            body(context.height().get()),
        ))
    }

    async fn verify(
        &mut self,
        _: (deterministic::Context, Self::Context),
        ancestry: impl crate::ancestry::Ancestry<Self::Block>,
    ) -> bool {
        self.record(ancestry).await;
        self.admit
    }
}

#[test]
fn inline_producer_stages_its_chain_and_admits_held_blocks() {
    runner(115).start(|context| async move {
        let mut harness = Harness::new(context, 115, [true, true]).await;
        harness.start(0).await;
        let marshal = harness.mailbox(0);
        let application = ProducerApplication::new();
        let mut producer = Inline::new(
            harness.context.child("producer"),
            application.clone(),
            marshal.clone(),
        );
        let genesis = harness.committee.config.genesis().tips()[0];
        let epoch = harness.committee.config.epoch();
        let position = |height: u64, parent| {
            Context::new(epoch, genesis.chain(), Height::new(height), parent).unwrap()
        };

        // The chain's first block builds on the genesis tip, so its ancestry is empty.
        let first = position(1, genesis.digest());
        let body = producer.propose(first).await.await.unwrap();
        let first = first.header(body);
        assert!(application.last_ancestry().is_empty());
        let staged = marshal
            .get_block(first.block_ref::<Sha256>())
            .await
            .unwrap();
        assert_eq!(staged.unwrap().header(), &first);

        // The next block builds on the first, and verifying it sees both.
        let second = position(2, first.digest::<Sha256>());
        let body = producer.propose(second).await.await.unwrap();
        assert_eq!(application.last_ancestry(), vec![1]);
        assert!(producer.verify(second, body).await.await.unwrap());
        assert_eq!(application.last_ancestry(), vec![2, 1]);

        // The application's verdict decides admission of a held block.
        let mut rejecting = Inline::new(
            harness.context.child("rejecting"),
            ProducerApplication {
                admit: false,
                ..ProducerApplication::new()
            },
            marshal.clone(),
        );
        assert!(!rejecting.verify(second, body).await.await.unwrap());

        // A block built for another position is never staged or answered.
        let mut misplacing = Inline::new(
            harness.context.child("misplacing"),
            ProducerApplication {
                misplace: true,
                ..ProducerApplication::new()
            },
            marshal,
        );
        let third = position(3, second.header(body).digest::<Sha256>());
        assert!(misplacing.propose(third).await.await.is_err());
        harness.shutdown().await;
    });
}

async fn run_floor_case(
    context: deterministic::Context,
    seed: u64,
    archive_modes: [ArchiveMode; 3],
) {
    let mut harness = Harness::new_with_archives(context, seed, [true, true], archive_modes).await;
    harness.start(0).await;
    let history = initial_history(&harness.committee);
    let floor = certify(
        &harness.committee,
        1,
        Arc::clone(&history),
        harness.committee.config.genesis().tips(),
        vec![vec![body(40)], vec![body(41)]],
    );
    let old_history = floor.history.commitment::<Sha256>();
    let floor_id = floor.id();
    harness
        .mailbox(0)
        .install_floor(Floor::new(
            Arc::clone(&floor.proof),
            Arc::clone(&floor.history),
            floor.tips(),
        ))
        .await
        .unwrap();
    let progress = harness
        .wait_progress(0, |progress| {
            progress.floor_generation == 1 && progress.floor == floor_id
        })
        .await;
    // The floor's frontier is at height one on both chains, so its index is two.
    assert_eq!(progress.committed, OutputIndex::new(2));
    assert_eq!(progress.acknowledged, OutputIndex::new(2));
    assert!(harness.reporter(0).delivered().is_empty());

    let mailbox = harness.mailbox(0);
    let intermediate_history = Arc::new(TipRecord::at_tips(old_history, floor.tips()).unwrap());
    let intermediate_commitment = intermediate_history.commitment::<Sha256>();
    let mut reporter = mailbox.clone();
    assert_eq!(
        reporter.report(Activity::HistoryAccepted {
            view: View::new(2),
            commitment: intermediate_commitment,
            record: intermediate_history,
        }),
        Feedback::Ok
    );
    let continuation_history =
        Arc::new(TipRecord::at_tips(intermediate_commitment, floor.tips()).unwrap());
    let continuation = certify(
        &harness.committee,
        2,
        continuation_history,
        &floor.tips(),
        vec![vec![body(42), body(44)], vec![body(43), body(45)]],
    );
    let continuation_id = continuation.id();
    continuation.submit(&mailbox).await;
    continuation.finalize(&mailbox);
    let delivered = harness.wait_updates(0, 4).await;
    for (offset, (actual, block)) in delivered
        .iter()
        .zip(continuation.offset_major())
        .enumerate()
    {
        assert_eq!(actual.index, OutputIndex::new(offset as u64 + 3));
        assert_eq!(actual.block.as_ref(), block.as_ref());
    }
    harness
        .wait_progress(0, |progress| {
            progress.floor_generation == 1
                && progress.floor == continuation_id
                && progress.acknowledged == OutputIndex::new(6)
        })
        .await;
    continuation.release(&mailbox);
    mailbox.prune(OutputIndex::new(6)).await.unwrap();

    harness.crash(0).await;
    harness.start(0).await;
    let reopened = harness
        .wait_progress(0, |progress| {
            progress.floor_generation == 1
                && progress.floor == continuation_id
                && progress.acknowledged == OutputIndex::new(6)
        })
        .await;
    assert_eq!(reopened.committed, OutputIndex::new(6));
    // A delayed request below the current floor prunes nothing it still needs.
    harness.mailbox(0).prune(OutputIndex::new(2)).await.unwrap();
    assert_eq!(
        harness
            .mailbox(0)
            .get_certificate(floor_id)
            .await
            .unwrap()
            .is_some(),
        archive_modes[0] == ArchiveMode::Immutable,
        "LQC retention follows its independently selected backend"
    );
    assert_eq!(
        harness
            .catalog(0)
            .history(old_history)
            .await
            .unwrap()
            .is_some(),
        archive_modes[1] == ArchiveMode::Immutable,
        "history retention follows its independently selected backend"
    );
    assert_eq!(
        harness
            .mailbox(0)
            .get_block(continuation.blocks[0][0].reference())
            .await
            .unwrap()
            .is_some(),
        archive_modes[2] == ArchiveMode::Immutable,
        "block retention follows its independently selected backend"
    );
    for chain in &continuation.blocks {
        let newest = chain.last().unwrap().reference();
        assert!(
            harness
                .mailbox(0)
                .get_block(newest)
                .await
                .unwrap()
                .is_some(),
            "the block each chain builds on next survives pruning"
        );
    }
    assert!(
        harness
            .mailbox(0)
            .get_certificate(continuation_id)
            .await
            .unwrap()
            .is_some(),
        "current floor survives pruning and reopen"
    );
    harness.shutdown().await;
}

/// Finalizes three views in which view two's chain-0 anchor jumps to a certified rival of the
/// ordered tip, which an equivocating producer allows. The order reads the new blocks off the
/// rival path, later views extend it, and a reopened node continues from it.
///
/// Without view two's L-QC, view three's opens both history records in one pass.
async fn run_anchor_jump_case(
    context: deterministic::Context,
    seed: u64,
    archive_modes: [ArchiveMode; 3],
    finalize_jump: bool,
) {
    let mut harness = Harness::new_with_archives(context, seed, [true, true], archive_modes).await;
    harness.start(0).await;
    let mailbox = harness.mailbox(0);
    let genesis = harness.committee.config.genesis().tips().to_vec();
    let first = certify(
        &harness.committee,
        1,
        initial_history(&harness.committee),
        &genesis,
        vec![vec![body(90)], vec![body(91)]],
    );
    first.submit(&mailbox).await;
    first.finalize(&mailbox);
    harness.wait_updates(0, 2).await;

    // The equivocator's rival branch, certified up to height 2. Only the anchored block is
    // ordered, so only it is submitted.
    let rival = certify(
        &harness.committee,
        1,
        initial_history(&harness.committee),
        &genesis,
        vec![vec![body(92), body(93)], vec![body(91)]],
    );
    let anchor = &rival.blocks[0][1];
    mailbox.put_block(Arc::clone(anchor)).await.unwrap();

    // The tip anchor stands in for the rival's DA certificate: marshal reads only final tips.
    let second_history =
        Arc::new(TipRecord::at_tips(first.history.commitment::<Sha256>(), first.tips()).unwrap());
    let second = certify(
        &harness.committee,
        2,
        second_history,
        &[anchor.reference(), first.tips()[1]],
        vec![vec![body(94)], vec![body(95)]],
    );
    second.submit(&mailbox).await;
    if finalize_jump {
        second.finalize(&mailbox);
    } else {
        second.accept_history(&mailbox);
    }

    let third_history =
        Arc::new(TipRecord::at_tips(second.history.commitment::<Sha256>(), second.tips()).unwrap());
    let third = certify(
        &harness.committee,
        3,
        third_history,
        &second.tips(),
        vec![vec![body(96)], vec![body(97)]],
    );
    third.submit(&mailbox).await;
    third.finalize(&mailbox);

    let expected = [
        &first.blocks[0][0],
        &first.blocks[1][0],
        anchor,
        &second.blocks[1][0],
        &second.blocks[0][0],
        &third.blocks[0][0],
        &third.blocks[1][0],
    ];
    let delivered = harness.wait_updates(0, expected.len()).await;
    for (offset, (actual, block)) in delivered.iter().zip(expected).enumerate() {
        assert_eq!(actual.index, OutputIndex::new(offset as u64 + 1));
        assert_eq!(actual.block.as_ref(), block.as_ref());
    }
    assert_ne!(
        anchor.header().parent(),
        first.blocks[0][0].reference().digest()
    );
    harness
        .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(7))
        .await;

    harness.crash(0).await;
    harness.start(0).await;
    let mailbox = harness.mailbox(0);
    let fourth_history =
        Arc::new(TipRecord::at_tips(third.history.commitment::<Sha256>(), third.tips()).unwrap());
    let fourth = certify(
        &harness.committee,
        4,
        fourth_history,
        &third.tips(),
        vec![vec![body(98)], vec![body(99)]],
    );
    fourth.submit(&mailbox).await;
    fourth.finalize(&mailbox);
    harness
        .wait_progress(0, |progress| progress.acknowledged == OutputIndex::new(9))
        .await;
    assert_eq!(
        harness
            .mailbox(0)
            .get_block(anchor.reference())
            .await
            .unwrap()
            .as_deref(),
        Some(anchor.as_ref())
    );
    harness.shutdown().await;
}

#[test]
fn anchor_jump_to_a_rival_branch_extends_the_order() {
    for (seed, archive_modes, finalize_jump) in [
        (112, [ArchiveMode::Prunable; 3], true),
        (113, [ArchiveMode::Immutable; 3], true),
        (114, [ArchiveMode::Prunable; 3], false),
        (115, [ArchiveMode::Immutable; 3], false),
    ] {
        runner(seed).start(move |context| {
            run_anchor_jump_case(context, seed, archive_modes, finalize_jump)
        });
    }
}

#[test]
fn verified_floor_continues_and_current_generation_prunes_across_reopen() {
    for (seed, archive_modes) in [
        (104, [ArchiveMode::Prunable; 3]),
        (106, [ArchiveMode::Immutable; 3]),
        (
            107,
            [
                ArchiveMode::Prunable,
                ArchiveMode::Immutable,
                ArchiveMode::Immutable,
            ],
        ),
        (
            110,
            [
                ArchiveMode::Immutable,
                ArchiveMode::Prunable,
                ArchiveMode::Immutable,
            ],
        ),
        (
            111,
            [
                ArchiveMode::Immutable,
                ArchiveMode::Immutable,
                ArchiveMode::Prunable,
            ],
        ),
    ] {
        runner(seed).start(move |context| run_floor_case(context, seed, archive_modes));
    }
}
