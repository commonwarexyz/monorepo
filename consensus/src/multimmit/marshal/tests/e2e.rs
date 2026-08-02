//! Full-system deterministic harness and end-to-end scenarios.

use crate::{
    Reporter, Viewable as _,
    marshal::mocks::block::EmptyBlock,
    multimmit::{
        config::Limits,
        machine::Artifact,
        marshal::{
            ArchiveConfig, ArchiveMode, Config, FloorCheckpoint, LqcVerifier, Mailbox, OutputIndex,
            Progress, Prune, Running, Start, Update, actors::catalog::CatalogClient, open,
        },
        mocks::{
            Committee,
            cluster::{Cluster, ClusterOptions, QUOTA, link_all, start_network},
            sign_vote,
        },
        scheme::bls12381_threshold::Scheme,
        types::{
            Activity, Anchor, BlockRef, ChainId, ChainProposal, Extension, LeaderBlock, Lqc,
            Position, TipRecord, TransactionBlock, TransactionBlockHeader, VoteBody,
            genesis_history as protocol_genesis_history,
        },
    },
    types::{Height, Participant, Round, View},
};
use bytes::{Buf, BufMut};
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt as _, Write};
use commonware_cryptography::{
    Digestible, Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::Recipients;
use commonware_parallel::Sequential;
use commonware_resolver::p2p;
use commonware_runtime::{
    Clock as _, Handle, Metrics as _, Runner as _, Spawner as _, Supervisor as _,
    buffer::paged::CacheRef, deterministic, telemetry::metrics::count_running_tasks,
};
use commonware_storage::translator::TwoCap;
use commonware_utils::{Acknowledgement as _, NZU16, NZU64, NZUsize, sync::Mutex};
use futures::{StreamExt as _, stream::FuturesUnordered};
use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

const CHAINS: usize = 2;
const PARTICIPANTS: u32 = 6;
const NETWORK_CHANNEL_RESOLVER: u64 = 0;
const NETWORK_CHANNEL_BROADCAST: u64 = 1;
const ENGINE_NETWORK_CHANNEL_RESOLVER: u64 = 4;
const ENGINE_NETWORK_CHANNEL_BROADCAST: u64 = 5;
const WAIT_STEPS: usize = 2_000;
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

type TestBody = EmptyBlock<Sha256>;
type TestBlock = TransactionBlock<Sha256, TestBody>;
type TestScheme = Scheme<ed25519::PublicKey, MinPk>;
type TestMailbox = Mailbox<Sha256, MinPk, TestBody, ed25519::PublicKey>;

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

type DigestMailbox = Mailbox<Sha256, MinPk, DigestBody, ed25519::PublicKey>;
type DigestBlock = TransactionBlock<Sha256, DigestBody>;
type DigestDelivery = (OutputIndex, Arc<DigestBlock>);

#[derive(Clone, Default)]
struct DigestReporter {
    delivered: Arc<Mutex<Vec<DigestDelivery>>>,
}

impl DigestReporter {
    fn delivered(&self) -> Vec<DigestDelivery> {
        self.delivered.lock().clone()
    }
}

async fn wait_digest_updates(
    context: &deterministic::Context,
    reporter: &DigestReporter,
    count: usize,
) -> Vec<DigestDelivery> {
    for _ in 0..WAIT_STEPS {
        let delivered = reporter.delivered();
        if delivered.len() >= count {
            return delivered;
        }
        context.sleep(WAIT_STEP).await;
    }
    panic!("attached marshal did not deliver {count} updates");
}

impl Reporter for DigestReporter {
    type Activity = Update<DigestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block {
            index,
            block,
            acknowledgement,
        } = activity;
        self.delivered.lock().push((index, block));
        acknowledgement.acknowledge();
        Feedback::Ok
    }
}

struct AttachedMarshal {
    mailbox: DigestMailbox,
    marshal: Running,
    resolver: Handle<()>,
    broadcast: Handle<()>,
}

impl AttachedMarshal {
    async fn shutdown(self) {
        self.marshal.abort();
        self.marshal.join().await.unwrap();
        self.resolver.abort();
        self.broadcast.abort();
        let _ = self.resolver.await;
        let _ = self.broadcast.await;
    }
}

async fn start_attached_marshal(
    context: &deterministic::Context,
    oracle: &commonware_p2p::simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    committee: &Committee<MinPk>,
    reporter: DigestReporter,
    launch: u64,
) -> AttachedMarshal {
    let node_context = context.child(if launch == 0 {
        "engine_marshal_first"
    } else {
        "engine_marshal_second"
    });
    let identity = committee.identities[0].clone();
    let control = oracle.control(identity.clone());
    let resolver_network = control
        .register(ENGINE_NETWORK_CHANNEL_RESOLVER, QUOTA)
        .await
        .unwrap();
    let broadcast_network = control
        .register(ENGINE_NETWORK_CHANNEL_BROADCAST, QUOTA)
        .await
        .unwrap();
    let (broadcast_engine, buffer) = buffered::Engine::new(
        node_context.child("broadcast"),
        buffered::Config {
            public_key: identity.clone(),
            mailbox_size: NZUsize!(64),
            deque_size: 16,
            priority: false,
            codec_config: (),
            peer_provider: oracle.manager(),
        },
    );
    let broadcast = broadcast_engine.start(broadcast_network);
    let archive = ArchiveConfig::new(
        TwoCap,
        CacheRef::from_pooler(&node_context, NZU16!(1024), NZUsize!(8)),
    );
    let mut config = Config::new(
        committee.config.epoch(),
        NonZeroU32::new(committee.codec().chains() as u32).unwrap(),
        Start::Genesis(committee.config.genesis().clone()),
        "multimmit_engine_marshal_e2e".into(),
        committee.codec(),
        (),
        archive,
    )
    .unwrap();
    config.catalog_mailbox_size = NZUsize!(64);
    config.admission_cut_capacity = NZUsize!(64);
    config.pending_segment_items = NZU64!(64);
    config.resolver_mailbox_size = NZUsize!(64);
    config.backfill_concurrency = config.resolver_mailbox_size;
    let (service, bridge) = open::<_, TwoCap, Sha256, MinPk, DigestBody, ed25519::PublicKey>(
        node_context.child("marshal"),
        config,
        buffer,
    )
    .await
    .unwrap();
    let (resolver_engine, resolver) = p2p::Engine::new(
        node_context.child("resolver"),
        p2p::Config {
            peer_provider: oracle.manager(),
            blocker: control,
            consumer: bridge.clone(),
            producer: bridge,
            mailbox_size: NZUsize!(64),
            me: Some(identity),
            initial: Duration::from_millis(20),
            timeout: Duration::from_millis(100),
            fetch_retry_timeout: Duration::from_millis(20),
            priority_requests: false,
            priority_responses: false,
        },
    );
    let resolver_handle = resolver_engine.start(resolver_network);
    let (mailbox, marshal) = service.start(
        resolver,
        CommitteeVerifier(committee.verifier.clone()),
        reporter,
    );
    AttachedMarshal {
        mailbox,
        marshal,
        resolver: resolver_handle,
        broadcast,
    }
}

#[derive(Clone)]
struct CommitteeVerifier(TestScheme);

impl LqcVerifier<Sha256, MinPk> for CommitteeVerifier {
    type Error = &'static str;

    fn verify(
        &mut self,
        proof: &Lqc<MinPk, Sha256Digest>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let valid = self
            .0
            .verify_lqc::<_, Sha256, _>(&mut commonware_utils::test_rng(), proof, &Sequential)
            .is_some();
        async move {
            if valid {
                Ok(())
            } else {
                Err("committee rejected LQC")
            }
        }
    }
}

#[derive(Clone, Debug)]
struct Delivered {
    index: OutputIndex,
    block: Arc<TestBlock>,
}

#[derive(Default)]
struct ReporterState {
    delivered: Vec<Delivered>,
    pending: std::collections::VecDeque<(OutputIndex, commonware_utils::acknowledgement::Exact)>,
}

#[derive(Clone)]
struct ApplicationReporter {
    state: Arc<Mutex<ReporterState>>,
    auto_acknowledge: bool,
}

impl ApplicationReporter {
    fn new(auto_acknowledge: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(ReporterState::default())),
            auto_acknowledge,
        }
    }

    fn delivered(&self) -> Vec<Delivered> {
        self.state.lock().delivered.clone()
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

impl Reporter for ApplicationReporter {
    type Activity = Update<TestBlock>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        let Update::Block {
            index,
            block,
            acknowledgement,
        } = activity;
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

struct Node {
    mailbox: TestMailbox,
    catalog: CatalogClient<Sha256, MinPk, TestBody>,
    marshal: Running,
    resolver: Handle<()>,
    broadcast: Handle<()>,
    task_prefix: String,
}

impl Node {
    fn abort(&self) {
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
}

struct Harness {
    context: deterministic::Context,
    oracle: commonware_p2p::simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    committee: Committee<MinPk>,
    reporters: [ApplicationReporter; 2],
    nodes: [Option<Node>; 2],
    launches: [u64; 2],
    seed: u64,
    archive_modes: [ArchiveMode; 3],
    catalog_mailbox_size: NonZeroUsize,
    max_commit_outputs: NonZeroUsize,
    max_hot_block_bytes: NonZeroUsize,
    max_pending_acks: NonZeroUsize,
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
        let committee = Committee::new_with_namespace_and_producers(
            seed,
            NAMESPACE,
            PARTICIPANTS,
            (0..CHAINS as u32).map(Participant::new).collect(),
            Limits::new(4, 1).unwrap(),
        );
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
        let mut config = Config::new(
            self.committee.config.epoch(),
            NonZeroU32::new(CHAINS as u32).unwrap(),
            Start::Genesis(self.committee.config.genesis().clone()),
            format!("multimmit_marshal_e2e_{}_{}", self.seed, index),
            self.committee.codec(),
            (),
            archive,
        )
        .unwrap();
        config.catalog_mailbox_size = self.catalog_mailbox_size;
        config.admission_cut_capacity = self.catalog_mailbox_size;
        config.pending_segment_items =
            NonZeroU64::new(self.catalog_mailbox_size.get() as u64).unwrap();
        config.resolver_mailbox_size = NZUsize!(64);
        config.backfill_concurrency = config.resolver_mailbox_size;
        config.max_commit_outputs = self.max_commit_outputs;
        config.max_hot_block_bytes = self.max_hot_block_bytes;
        config.max_pending_acks = self.max_pending_acks;
        config.finalized_lqc = self.archive_modes[0];
        config.finalized_history = self.archive_modes[1];
        config.finalized_blocks = self.archive_modes[2];
        config
    }

    async fn start(&mut self, index: usize) {
        assert!(self.nodes[index].is_none(), "node is already running");
        let generation = self.launches[index];
        self.launches[index] += 1;
        let node_context = self.context.child(
            NODE_LABELS[index]
                .get(generation as usize)
                .copied()
                .expect("test restart bound is sufficient"),
        );
        let task_prefix = node_context.name().label;
        let identity = self.committee.identities[index].clone();
        let control = self.oracle.control(identity.clone());
        let resolver_network = control
            .register(NETWORK_CHANNEL_RESOLVER, QUOTA)
            .await
            .unwrap();
        let broadcast_network = control
            .register(NETWORK_CHANNEL_BROADCAST, QUOTA)
            .await
            .unwrap();

        let (broadcast_engine, buffer) = buffered::Engine::new(
            node_context.child("broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(64),
                deque_size: 16,
                priority: false,
                codec_config: (),
                peer_provider: self.oracle.manager(),
            },
        );
        let broadcast = broadcast_engine.start(broadcast_network);
        let config = self.config(&node_context, index);
        let (service, bridge) = open::<_, TwoCap, Sha256, MinPk, TestBody, ed25519::PublicKey>(
            node_context.child("marshal"),
            config,
            buffer,
        )
        .await
        .unwrap();
        let catalog = service.catalog();
        let (resolver_engine, resolver) = p2p::Engine::new(
            node_context.child("resolver"),
            p2p::Config {
                peer_provider: self.oracle.manager(),
                blocker: control,
                consumer: bridge.clone(),
                producer: bridge,
                mailbox_size: NZUsize!(64),
                me: Some(identity),
                initial: Duration::from_millis(20),
                timeout: Duration::from_millis(100),
                fetch_retry_timeout: Duration::from_millis(20),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let resolver_handle = resolver_engine.start(resolver_network);
        let (mailbox, marshal) = service.start(
            resolver,
            CommitteeVerifier(self.committee.verifier.clone()),
            self.reporters[index].clone(),
        );
        self.nodes[index] = Some(Node {
            mailbox,
            catalog,
            marshal,
            resolver: resolver_handle,
            broadcast,
            task_prefix,
        });
    }

    fn mailbox(&self, index: usize) -> TestMailbox {
        self.nodes[index]
            .as_ref()
            .expect("node is running")
            .mailbox
            .clone()
    }

    fn reporter(&self, index: usize) -> ApplicationReporter {
        self.reporters[index].clone()
    }

    fn catalog(&self, index: usize) -> CatalogClient<Sha256, MinPk, TestBody> {
        self.nodes[index]
            .as_ref()
            .expect("node is running")
            .catalog
            .clone()
    }

    async fn crash(&mut self, index: usize) {
        let node = self.nodes[index].take().expect("node is running");
        assert!(
            count_running_tasks(&self.context, &node.task_prefix) > 0,
            "node owns running actors before abort"
        );
        let task_prefix = node.task_prefix.clone();
        node.abort();
        node.join().await;
        self.reporters[index].discard_pending();
        self.context.sleep(Duration::from_millis(1)).await;
        assert_eq!(
            count_running_tasks(&self.context, &task_prefix),
            0,
            "node actors stop after joining every lifecycle owner"
        );
    }

    async fn shutdown(&mut self) {
        for index in 0..self.nodes.len() {
            if self.nodes[index].is_some() {
                self.crash(index).await;
            }
        }
    }

    async fn wait_updates(&self, index: usize, count: usize) -> Vec<Delivered> {
        for _ in 0..WAIT_STEPS {
            let delivered = self.reporters[index].delivered();
            if delivered.len() >= count {
                return delivered;
            }
            self.context.sleep(WAIT_STEP).await;
        }
        panic!("node {index} did not deliver {count} updates");
    }

    async fn wait_progress(
        &self,
        index: usize,
        predicate: impl Fn(&Progress<Sha256Digest>) -> bool,
    ) -> Progress<Sha256Digest> {
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
    fn id(&self) -> crate::multimmit::types::CertificateId<Sha256Digest> {
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

    async fn submit(&self, mailbox: &TestMailbox) {
        for block in self.blocks.iter().flatten() {
            mailbox.put_block(Arc::clone(block)).await.unwrap();
        }
    }

    fn finalize(&self, mailbox: &TestMailbox) {
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(Activity::HistoryAccepted {
                view: self.proof.view(),
                commitment: self.history.commitment::<Sha256>(),
                record: Arc::clone(&self.history),
            }),
            Feedback::Ok
        );
        let artifact = Arc::new(Artifact::Lqc(self.proof.as_ref().clone()));
        assert_eq!(
            reporter.report(Activity::ProtocolAccepted {
                artifact_id: artifact.id::<Sha256>(),
                artifact,
            }),
            Feedback::Ok
        );
    }
}

fn digest(label: &[u8], marker: u64) -> Sha256Digest {
    Sha256::hash(&[label, &marker.to_be_bytes()])
}

fn metric_total(encoded: &str, suffix: &str) -> f64 {
    encoded
        .lines()
        .filter_map(|line| {
            if line.starts_with('#') {
                return None;
            }
            let (sample, value) = line.rsplit_once(' ')?;
            let name = sample.split_once('{').map_or(sample, |(name, _)| name);
            name.ends_with(suffix)
                .then(|| value.parse::<f64>().expect("counter is numeric"))
        })
        .sum()
}

fn body(marker: u64) -> TestBody {
    EmptyBlock::new(
        digest(b"application parent", marker),
        Height::new(marker + 1),
        marker,
    )
}

fn initial_history(committee: &Committee<MinPk>) -> Arc<TipRecord<Sha256Digest>> {
    let genesis = committee.config.genesis();
    Arc::new(
        TipRecord::new(
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
    let vote = VoteBody::for_leader::<Sha256, MinPk>(
        &leader,
        positions,
        vec![Extension::empty(); CHAINS],
        committee.codec(),
    )
    .unwrap();
    let votes = (0..committee.codec().view_quorum())
        .map(|signer| sign_vote(&committee.signers[signer], vote.clone()).unwrap())
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
            assert_eq!(actual.index, OutputIndex::new(offset as u64));
            assert_eq!(actual.block.as_ref(), block.as_ref());
        }
        assert_ne!(
            delivered[0].block.reference(),
            delivered[1].block.reference()
        );
        assert_ne!(delivered[0].block.header(), delivered[1].block.header());
        assert_eq!(delivered[0].block.body(), delivered[1].block.body());
        harness
            .wait_progress(0, |progress| {
                progress.acknowledged == Some(OutputIndex::new(3))
            })
            .await;
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            4.0,
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            0.0,
            "{metrics}"
        );
        harness.shutdown().await;
    });
}

#[test]
fn buffered_ingress_subscription_establishes_durable_custody() {
    runner(114).start(|context| async move {
        let mut harness = Harness::new(context, 114, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let source = harness.mailbox(0);
        let target = harness.mailbox(1);
        let body = body(1_140);
        let header = harness.committee.transaction_header(0, body.digest());
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        let reference = block.reference();

        let mut subscribed = Box::pin(target.subscribe_block(reference));
        commonware_macros::select! {
            result = &mut subscribed => panic!("missing block subscription completed early: {result:?}"),
            _ = harness.context.sleep(WAIT_STEP) => {},
        }
        assert_eq!(
            source.broadcast_block(
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
        let source = harness.mailbox(0);
        let target = harness.mailbox(1);
        let body = body(1_210);
        let header = harness.committee.transaction_header(0, body.digest());
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        let reference = block.reference();

        harness.nodes[1]
            .as_ref()
            .expect("target is running")
            .marshal
            .abort();
        harness.context.sleep(WAIT_STEP).await;
        let subscribed = target.subscribe_block(reference);
        assert_eq!(
            source.broadcast_block(
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
        let header = harness.committee.transaction_header(0, body.digest());
        let block = Arc::new(TransactionBlock::new(header.clone(), body).unwrap());
        let reference = block.reference();
        source.put_block(Arc::clone(&block)).await.unwrap();

        let mut subscribed = Box::pin(target.subscribe_block(reference));
        commonware_macros::select! {
            result = &mut subscribed => panic!("missing block subscription completed early: {result:?}"),
            _ = harness.context.sleep(WAIT_STEP) => {},
        }

        let votes = (0..harness.committee.codec().da_quorum())
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
            .resolver_mailbox_size
            .get()
        {
            let missing = body(1_250 + marker as u64);
            let reference = harness
                .committee
                .transaction_header(0, missing.digest())
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
                >= subscriptions.len() as f64
            {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "resolver_pending_requests"),
            subscriptions.len() as f64,
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
        harness.start(0).await;
        harness.start(1).await;
        let target = harness.mailbox(1);
        let capacity = harness
            .config(&harness.context, 1)
            .resolver_mailbox_size
            .get();
        let mut fetches = Vec::with_capacity(capacity);

        for marker in 0..capacity {
            let missing = body(1_270 + marker as u64);
            let reference = harness
                .committee
                .transaction_header(0, missing.digest())
                .block_ref::<Sha256>();
            let mailbox = target.clone();
            fetches.push(
                harness
                    .context
                    .child("fetch")
                    .shared(false)
                    .spawn(move |_| async move { mailbox.fetch_block(reference).await }),
            );
        }

        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "pending_jobs") >= capacity as f64 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "pending_jobs"),
            capacity as f64,
            "every router job is occupied before testing intake backpressure"
        );

        let mailbox_capacity = harness.catalog_mailbox_size.get();
        let mut progress = FuturesUnordered::new();
        for _ in 0..=mailbox_capacity {
            let mailbox = target.clone();
            progress.push(
                harness
                    .context
                    .child("progress")
                    .shared(false)
                    .spawn(move |_| async move { mailbox.progress().await }),
            );
        }
        for _ in 0..WAIT_STEPS {
            if metric_total(
                &harness.context.encode(),
                "router_mailbox_backoff_total",
            ) > 0.0
            {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert!(
            metric_total(
                &harness.context.encode(),
                "router_mailbox_backoff_total",
            ) > 0.0,
            "one request reaches overflow after the bounded mailbox fills"
        );
        commonware_macros::select! {
            result = progress.next() => {
                panic!("router completed a request while its execution pool remained full: {result:?}")
            },
            _ = harness.context.sleep(WAIT_STEP) => {},
        }

        for fetch in fetches {
            fetch.abort();
        }
        while !progress.is_empty() {
            let result = commonware_macros::select! {
                result = progress.next() => result,
                _ = harness.context.sleep(Duration::from_secs(1)) => {
                    panic!("router did not resume intake after execution capacity returned")
                },
            };
            assert!(
                result
                    .expect("one progress task remains")
                    .expect("progress task remains alive")
                    .is_ok()
            );
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
        let header = harness.committee.transaction_header(0, missing.digest());
        let reference = header.block_ref::<Sha256>();

        let mut subscribed = Box::pin(target.subscribe_block(reference));
        commonware_macros::select! {
            result = &mut subscribed => panic!("missing block subscription completed early: {result:?}"),
            _ = harness.context.sleep(WAIT_STEP) => {},
        }
        let votes = (0..harness.committee.codec().da_quorum())
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
            if metric_total(&harness.context.encode(), "requests_sent_total") > 0.0 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert!(
            metric_total(&harness.context.encode(), "requests_sent_total") > 0.0,
            "accepted DA did not authorize an outbound resolver request"
        );

        drop(subscribed);
        for _ in 0..WAIT_STEPS {
            if metric_total(&harness.context.encode(), "resolver_pending_requests") == 0.0 {
                break;
            }
            harness.context.sleep(WAIT_STEP).await;
        }
        assert_eq!(
            metric_total(&harness.context.encode(), "resolver_pending_requests"),
            0.0,
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
        let second_history =
            Arc::new(TipRecord::new(first.history.commitment::<Sha256>(), first.tips()).unwrap());
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
        let received = target.subscribe_buffered_block(ingress_reference);
        assert_eq!(
            source.broadcast_block(
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
            target
                .get_buffered_block(ingress_reference)
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
                && metric_total(&harness.context.encode(), "resolver_pending_requests") > 0.0
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
                artifact_id: crate::multimmit::machine::ArtifactId::new(digest(
                    b"wrong finality id",
                    0,
                )),
                artifact,
            }),
            Feedback::Ok
        );
        mailbox
            .progress()
            .await
            .expect("an invalid finality activity is request-local");

        let other_committee = Committee::new_with_namespace_and_producers(
            106,
            NAMESPACE,
            PARTICIPANTS,
            (0..CHAINS as u32).map(Participant::new).collect(),
            Limits::new(4, 1).unwrap(),
        );
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
        let received = mailbox.subscribe_buffered_block(wrong_epoch_reference);
        assert_eq!(
            harness.mailbox(1).broadcast_block(
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
        let mut cluster = Cluster::<MinPk>::new(
            &context,
            ClusterOptions {
                n: PARTICIPANTS,
                seed: 108,
                extras: 0,
                leaders: None,
                quota: None,
                latency: None,
                jitter: None,
                production: None,
                view_retention: None,
            },
        )
        .await;
        let committee = cluster.fixture();
        let reporter = DigestReporter::default();
        let mut attached =
            start_attached_marshal(&context, cluster.oracle(), &committee, reporter.clone(), 0)
                .await;
        cluster
            .launch_with_reporter(0, attached.mailbox.clone())
            .await;
        for index in 1..PARTICIPANTS as usize {
            cluster.start_one(index).await;
        }
        let nodes = [0usize, 1, 2, 3, 4, 5];
        let chains = [0u32, 1, 2, 3, 4, 5];
        cluster.await_ready(&nodes).await;

        cluster.produce_once();
        cluster.wait_produced(&nodes, 1, 2_400).await;
        for index in nodes {
            let builds = cluster.app(index).log().lock().builds.clone();
            assert_eq!(builds.len(), 1);
            for (context, commitment) in builds {
                attached
                    .mailbox
                    .submit(context, DigestBody(commitment))
                    .await
                    .unwrap();
            }
        }
        cluster.wait_finalized(&nodes, &chains, 1, 2_400).await;
        let delivered = wait_digest_updates(&context, &reporter, PARTICIPANTS as usize).await;
        assert_eq!(delivered.len(), PARTICIPANTS as usize);
        for (index, (actual, block)) in delivered.iter().enumerate() {
            assert_eq!(*actual, OutputIndex::new(index as u64));
            assert_eq!(block.reference(), block.header().block_ref::<Sha256>());
        }
        let first_progress = attached.mailbox.progress().await.unwrap();
        assert_eq!(
            first_progress.acknowledged,
            Some(OutputIndex::new(PARTICIPANTS as u64 - 1))
        );

        cluster.crash(0).await;
        attached.shutdown().await;
        let committee = cluster.fixture();
        attached =
            start_attached_marshal(&context, cluster.oracle(), &committee, reporter.clone(), 1)
                .await;
        cluster
            .launch_with_reporter(0, attached.mailbox.clone())
            .await;
        cluster.await_ready(&[0]).await;
        let reopened = attached.mailbox.progress().await.unwrap();
        assert_eq!(reopened.generation, first_progress.generation);
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

        for index in nodes {
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
        let source = harness.mailbox(0);
        let target = harness.mailbox(1);
        let mut reporter = target.clone();

        for marker in 0..64 {
            let missing = body(1_000 + marker);
            let artifact = Arc::new(Artifact::TransactionBlock(
                harness.committee.signed_block(0, missing.digest()),
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
        let header = harness.committee.transaction_header(0, commitment);
        let block = Arc::new(TransactionBlock::new(header, body).unwrap());
        let reference = block.reference();
        let received = target.subscribe_buffered_block(reference);
        assert_eq!(
            source.broadcast_block(
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
            harness.committee.signed_block(0, commitment),
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
            vec![OutputIndex::ZERO, OutputIndex::new(1)]
        );
        let progress = harness
            .wait_progress(0, |progress| {
                progress.committed == Some(OutputIndex::new(1))
            })
            .await;
        assert_eq!(progress.acknowledged, None);
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            2.0,
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            0.0,
            "{metrics}"
        );

        assert_eq!(
            harness.reporter(0).acknowledge_next(),
            Some(OutputIndex::ZERO)
        );
        harness
            .wait_progress(0, |progress| {
                progress.acknowledged == Some(OutputIndex::ZERO)
            })
            .await;
        harness.crash(0).await;
        harness.start(0).await;
        let redelivered = harness.wait_updates(0, 3).await;
        assert_eq!(redelivered[2].index, OutputIndex::new(1));
        assert_eq!(redelivered[2].block.as_ref(), expected[1].as_ref());
        assert_eq!(harness.reporter(0).pending(), vec![OutputIndex::new(1)]);
        assert_eq!(
            harness.reporter(0).acknowledge_next(),
            Some(OutputIndex::new(1))
        );
        harness
            .wait_progress(0, |progress| {
                progress.acknowledged == Some(OutputIndex::new(1))
            })
            .await;
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            0.0,
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            1.0,
            "{metrics}"
        );

        harness.crash(0).await;
        harness.start(0).await;
        harness
            .wait_progress(0, |progress| {
                progress.committed == Some(OutputIndex::new(1))
                    && progress.acknowledged == Some(OutputIndex::new(1))
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
            vec![OutputIndex::ZERO, OutputIndex::new(1), OutputIndex::new(2)]
        );
        harness.context.sleep(Duration::from_millis(100)).await;
        assert_eq!(harness.reporter(0).delivered().len(), 3);

        let reporter = harness.reporter(0);
        assert!(reporter.acknowledge(OutputIndex::new(1)));
        assert!(reporter.acknowledge(OutputIndex::new(2)));
        harness.context.sleep(Duration::from_millis(100)).await;
        assert_eq!(
            harness.mailbox(0).progress().await.unwrap().acknowledged,
            None
        );
        assert_eq!(reporter.pending(), vec![OutputIndex::ZERO]);

        assert!(reporter.acknowledge(OutputIndex::ZERO));
        harness
            .wait_progress(0, |progress| {
                progress.acknowledged == Some(OutputIndex::new(2))
            })
            .await;
        let delivered = harness.wait_updates(0, 4).await;
        assert_eq!(delivered[3].index, OutputIndex::new(3));
        assert_eq!(reporter.pending(), vec![OutputIndex::new(3)]);

        assert!(reporter.acknowledge(OutputIndex::new(3)));
        harness
            .wait_progress(0, |progress| {
                progress.acknowledged == Some(OutputIndex::new(3))
            })
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
                TipRecord::new(batch.history.commitment::<Sha256>(), bases.clone()).unwrap(),
            );
        }

        let delivered = harness.wait_updates(0, expected.len()).await;
        for (offset, (actual, expected)) in delivered.iter().zip(&expected).enumerate() {
            assert_eq!(actual.index, OutputIndex::new(offset as u64));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }
        let last = OutputIndex::new(u64::try_from(expected.len() - 1).unwrap());
        harness
            .wait_progress(0, |progress| progress.acknowledged == Some(last))
            .await;
        let metrics = harness.context.encode();
        assert_eq!(
            metric_total(&metrics, "delivery_hot_outputs_total"),
            f64::from(u32::try_from(expected.len()).unwrap()),
            "{metrics}"
        );
        assert_eq!(
            metric_total(&metrics, "delivery_stored_outputs_total"),
            0.0,
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
                TipRecord::new(batch.history.commitment::<Sha256>(), bases.clone()).unwrap(),
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
            assert_eq!(actual.index, OutputIndex::new(offset as u64));
            assert_eq!(actual.block.as_ref(), expected.as_ref());
        }
        let last = OutputIndex::new(u64::try_from(OUTPUTS - 1).unwrap());
        harness
            .wait_progress(0, |progress| progress.acknowledged == Some(last))
            .await;

        let metrics = harness.context.encode();
        let expected_outputs = f64::from(u32::try_from(OUTPUTS).unwrap());
        for (metric, expected) in [
            ("custody_planned_outputs_total", expected_outputs),
            ("custody_local_outputs_total", expected_outputs),
            ("custody_fetched_outputs_total", 0.0),
            ("delivery_hot_outputs_total", expected_outputs),
            ("delivery_stored_outputs_total", 0.0),
            ("runtime_storage_reads_total", 0.0),
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
        let committed = OutputIndex::new(u64::try_from(expected.len() - 1).unwrap());
        let mailbox = harness.mailbox(0);
        batch.submit(&mailbox).await;
        batch.finalize(&mailbox);

        harness.wait_updates(0, 1).await;
        harness
            .wait_progress(0, |progress| progress.committed == Some(committed))
            .await;
        for (offset, block) in expected.iter().enumerate() {
            let index = OutputIndex::new(u64::try_from(offset).unwrap());
            let delivered = harness.wait_updates(0, offset + 1).await;
            assert_eq!(delivered[offset].index, index);
            assert_eq!(delivered[offset].block.as_ref(), block.as_ref());
            assert_eq!(harness.reporter(0).acknowledge_next(), Some(index));
            harness
                .wait_progress(0, |progress| progress.acknowledged == Some(index))
                .await;
        }
        let metrics = harness.context.encode();
        assert!(
            metric_total(&metrics, "delivery_stored_outputs_total") > 0.0,
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
                progress.committed == Some(OutputIndex::new(1)) && progress.acknowledged.is_none()
            })
            .await;

        let floor_history =
            Arc::new(TipRecord::new(first.history.commitment::<Sha256>(), first.tips()).unwrap());
        let floor = certify(
            &harness.committee,
            2,
            floor_history,
            &first.tips(),
            vec![vec![body(72)], vec![body(73)]],
        );
        mailbox
            .install_floor(FloorCheckpoint::new(
                floor.id(),
                Arc::clone(&floor.proof),
                Arc::clone(&floor.history),
                floor.tips(),
            ))
            .await
            .unwrap();
        harness
            .wait_progress(0, |progress| {
                progress.generation == 1
                    && progress.committed == Some(OutputIndex::new(1))
                    && progress.acknowledged == Some(OutputIndex::new(1))
            })
            .await;
        harness.reporter(0).discard_pending();

        let continuation_history =
            Arc::new(TipRecord::new(floor.history.commitment::<Sha256>(), floor.tips()).unwrap());
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
        assert_eq!(delivered[2].index, OutputIndex::new(2));
        assert_eq!(delivered[3].index, OutputIndex::new(3));
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
        .install_floor(FloorCheckpoint::new(
            floor_id,
            Arc::clone(&floor.proof),
            Arc::clone(&floor.history),
            floor.tips(),
        ))
        .await
        .unwrap();
    let progress = harness
        .wait_progress(0, |progress| {
            progress.generation == 1 && progress.floor == floor_id
        })
        .await;
    assert_eq!(progress.committed, None);
    assert!(harness.reporter(0).delivered().is_empty());

    let mailbox = harness.mailbox(0);
    let intermediate_history = Arc::new(TipRecord::new(old_history, floor.tips()).unwrap());
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
        Arc::new(TipRecord::new(intermediate_commitment, floor.tips()).unwrap());
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
    for (actual, block) in delivered.iter().zip(continuation.offset_major()) {
        assert_eq!(actual.block.as_ref(), block.as_ref());
    }
    harness
        .wait_progress(0, |progress| {
            progress.generation == 1
                && progress.floor == continuation_id
                && progress.acknowledged == Some(OutputIndex::new(3))
        })
        .await;
    mailbox.prune(Prune::new(1)).await.unwrap();

    harness.crash(0).await;
    harness.start(0).await;
    let reopened = harness
        .wait_progress(0, |progress| {
            progress.generation == 1
                && progress.floor == continuation_id
                && progress.acknowledged == Some(OutputIndex::new(3))
        })
        .await;
    assert_eq!(reopened.committed, Some(OutputIndex::new(3)));
    assert!(harness.mailbox(0).prune(Prune::new(0)).await.is_err());
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
