//! Full-system deterministic harness and end-to-end scenarios.
//!
//! Facts are built by hand rather than by a consensus engine: each resolved view is reported as
//! [`Activity::ViewResolved`], consecutive views extend the previous view's tips, and the L-QC of
//! view `v + 1`, which commits to view `v`'s tips-history commitment, finalizes view `v`.

use crate::{
    Reporter,
    multimmit::{
        config::max_outbox_effects,
        marshal::{
            ArchiveConfig, ArchiveMode, Config, Error as MailboxError, Floor, LqcVerifier, Mailbox,
            MarshalProgress, OutputIndex, Relay, Retention, ServiceHandle, Start, Update,
            actors::catalog, open, storage::catalog::StoredRef,
        },
        mocks::{
            Committee,
            cluster::{QUOTA, link_all, start_network},
        },
        scheme::bls12381::Scheme,
        testing::{SpanRecorder, TestBody, metric_total},
        types::{
            Activity, BlockRef, CertificateId, ChainId, ChainSet, HistoryRecord, Lqc, Resolution,
            TransactionBlock,
        },
    },
    types::{Height, Participant, View},
};
use commonware_actor::Feedback;
use commonware_broadcast::{Broadcaster as _, buffered};
use commonware_codec::EncodeSize as _;
use commonware_cryptography::{
    Digested, Digestible as _, Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
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
    collections::VecDeque,
    num::{NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};
use tracing_subscriber::prelude::*;

const CHAINS: usize = 2;
const PARTICIPANTS: u32 = 6;
const RESOLVER_CHANNEL: u64 = 0;
const BROADCAST_CHANNEL: u64 = 1;
const WAIT_STEPS: usize = 2_000;
/// Resolver mailbox capacity, which also bounds backfill concurrency.
const RESOLVER_MAILBOX_SIZE: NonZeroUsize = NZUsize!(64);
const WAIT_STEP: Duration = Duration::from_millis(5);
/// How long a test waits to observe that something does not happen.
const QUIET: Duration = Duration::from_millis(100);
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
type TestActivity = Activity<MinPk, Sha256Digest>;
type TestLqc = Lqc<MinPk, Sha256Digest>;
type TestFloor = Floor<MinPk, Sha256Digest>;

/// One node's running marshal, with the broadcast and resolver engines it runs over.
struct Node {
    mailbox: TestMailbox,
    buffer: TestBuffer,
    relay: Option<TestRelay>,
    catalog: catalog::Mailbox<Sha256, MinPk, TestBody>,
    marshal: ServiceHandle,
    resolver: Handle<()>,
    broadcast: Handle<()>,
    task_prefix: String,
}

impl Node {
    async fn shutdown(mut self) {
        self.marshal.abort();
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

/// Holds the first L-QC verification until the test releases it.
#[derive(Clone)]
struct VerificationGate {
    started: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

impl VerificationGate {
    /// Returns the gate, a receiver for the first verification's start, and its release.
    fn new() -> (Self, oneshot::Receiver<()>, oneshot::Sender<()>) {
        let (started, started_rx) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        let gate = Self {
            started: Arc::new(Mutex::new(Some(started))),
            release: Arc::new(Mutex::new(Some(release_rx))),
        };
        (gate, started_rx, release)
    }
}

/// Verifies L-QCs against the test committee, optionally holding the first verification.
#[derive(Clone)]
struct CommitteeVerifier {
    scheme: TestScheme,
    gate: Option<VerificationGate>,
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

    fn verify(&mut self, proof: &TestLqc) -> impl Future<Output = Result<(), Self::Error>> + Send {
        let valid = self.scheme.verify_lqc::<_, Sha256, _>(
            &mut commonware_utils::test_rng(),
            proof,
            &Sequential,
        );
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
struct Delivered {
    index: OutputIndex,
    block: Arc<TestBlock>,
}

#[derive(Default)]
struct ReporterState {
    delivered: Vec<Delivered>,
    pending: VecDeque<(OutputIndex, commonware_utils::acknowledgement::Exact)>,
}

/// Records every delivered update and acknowledges it at once or when the test says so.
#[derive(Clone)]
struct ApplicationReporter {
    state: Arc<Mutex<ReporterState>>,
    auto_acknowledge: bool,
}

impl ApplicationReporter {
    fn new(auto_acknowledge: bool) -> Self {
        Self {
            state: Arc::default(),
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
        let Update {
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

/// Asserts that `delivered` holds exactly `expected`, at consecutive indices from `first`.
fn assert_delivered(delivered: &[Delivered], first: u64, expected: &[Arc<TestBlock>]) {
    assert_eq!(delivered.len(), expected.len(), "{delivered:?}");
    for (offset, (actual, block)) in delivered.iter().zip(expected).enumerate() {
        assert_eq!(actual.index, OutputIndex::new(first + offset as u64));
        assert_eq!(actual.block.as_ref(), block.as_ref());
    }
}

/// Waits for buffered ingress of the block named by `reference`.
fn subscribe_buffered(
    buffer: &TestBuffer,
    reference: BlockRef<Sha256Digest>,
) -> impl Future<Output = Option<Arc<TestBlock>>> + Send + 'static {
    let receiver = buffer.subscribe(reference.digest());
    async move {
        receiver
            .await
            .ok()
            .map(Arc::<TestBlock>::from)
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
        .map(Arc::<TestBlock>::from)
        .filter(|block| block.reference() == reference)
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

/// Returns the block carrying `body` directly above `parent`.
fn block_above(
    committee: &Committee<MinPk>,
    parent: &BlockRef<Sha256Digest>,
    body: TestBody,
) -> Arc<TestBlock> {
    Arc::new(TransactionBlock::new(committee.header(parent, body.digest()), body).unwrap())
}

/// Returns the block carrying `body(marker)` at height one on chain zero.
fn first_block(committee: &Committee<MinPk>, marker: u64) -> Arc<TestBlock> {
    block_above(committee, &committee.genesis().tips()[0], body(marker))
}

fn committee(seed: u64) -> Committee<MinPk> {
    Committee::builder(seed, PARTICIPANTS)
        .namespace(NAMESPACE)
        .producers((0..CHAINS as u32).map(Participant::new).collect())
        .build()
}

/// A resolved view: its tips-history opening and the blocks it adds above its base.
struct Resolved {
    view: View,
    base: Vec<BlockRef<Sha256Digest>>,
    record: Arc<HistoryRecord<Sha256Digest>>,
    blocks: Vec<Vec<Arc<TestBlock>>>,
}

impl Resolved {
    fn commitment(&self) -> Sha256Digest {
        self.record.commitment::<Sha256>()
    }

    fn tips(&self) -> &[BlockRef<Sha256Digest>] {
        self.record.tips()
    }

    /// Returns the output index after the view: the sum of its tips' heights.
    fn index(&self) -> OutputIndex {
        OutputIndex::new(self.record.output_index().unwrap())
    }

    /// Returns the view's blocks in delivery order: offset-major across chains.
    fn horizontal(&self) -> Vec<Arc<TestBlock>> {
        let depth = self.blocks.iter().map(Vec::len).max().unwrap_or(0);
        (0..depth)
            .flat_map(|offset| {
                self.blocks
                    .iter()
                    .filter_map(move |chain| chain.get(offset).map(Arc::clone))
            })
            .collect()
    }

    fn all_blocks(&self) -> impl Iterator<Item = &Arc<TestBlock>> {
        self.blocks.iter().flatten()
    }

    async fn submit(&self, mailbox: &TestMailbox) {
        for block in self.all_blocks() {
            mailbox.put_block(Arc::clone(block)).await.unwrap();
        }
    }

    /// Returns local consensus's report that the view resolved.
    fn resolution(&self) -> TestActivity {
        Activity::ViewResolved {
            view: self.view,
            base: self.base.clone().into(),
            tips: self.tips().into(),
            commitment: self.commitment(),
            parent_commitment: self.record.parent(),
            by: Resolution::Determined,
        }
    }

    /// Returns the L-QC of the next view's leader block, which commits to this view's history.
    fn lqc(&self, committee: &Committee<MinPk>) -> Arc<TestLqc> {
        Arc::new(committee.lqc_with(
            self.view.next(),
            committee.genesis().vqc(),
            self.commitment(),
        ))
    }

    fn lqc_id(&self, committee: &Committee<MinPk>) -> CertificateId<Sha256Digest> {
        self.lqc(committee).id::<Sha256>()
    }

    /// Returns local consensus's report of the L-QC that finalizes this view.
    fn finalization(&self, committee: &Committee<MinPk>) -> TestActivity {
        Activity::LeaderFinalized {
            lqc: self.lqc(committee),
            opening: Arc::clone(&self.record),
        }
    }

    fn floor(&self, committee: &Committee<MinPk>) -> TestFloor {
        Floor::new(self.lqc(committee), Arc::clone(&self.record))
    }
}

/// Builds consecutive resolved views from genesis, each extending the previous view's tips.
struct Views {
    view: View,
    tips: Vec<BlockRef<Sha256Digest>>,
    commitment: Sha256Digest,
}

impl Views {
    fn new(committee: &Committee<MinPk>) -> Self {
        let genesis = committee.genesis();
        Self {
            view: View::new(0),
            tips: genesis.tips().to_vec(),
            commitment: genesis.history(),
        }
    }

    /// Resolves the next view, adding `bodies[chain]` above each chain's tip.
    fn next(&mut self, committee: &Committee<MinPk>, bodies: Vec<Vec<TestBody>>) -> Resolved {
        assert_eq!(bodies.len(), CHAINS);
        let base = self.tips.clone();
        let blocks = base
            .iter()
            .zip(bodies)
            .map(|(base, bodies)| {
                let mut parent = *base;
                bodies
                    .into_iter()
                    .map(|body| {
                        let block = block_above(committee, &parent, body);
                        parent = block.reference();
                        block
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let tips = blocks
            .iter()
            .zip(&base)
            .map(|(blocks, base)| blocks.last().map_or(*base, |block| block.reference()))
            .collect();
        let record = Arc::new(HistoryRecord::new(self.commitment, tips).unwrap());
        self.view = self.view.next();
        self.tips = record.tips().to_vec();
        self.commitment = record.commitment::<Sha256>();
        Resolved {
            view: self.view,
            base,
            record,
            blocks,
        }
    }

    /// Resolves the next view with one block per chain, carrying `body(first + chain)`.
    fn one_each(&mut self, committee: &Committee<MinPk>, first: u64) -> Resolved {
        self.next(
            committee,
            (0..CHAINS as u64)
                .map(|chain| vec![body(first + chain)])
                .collect(),
        )
    }
}

/// Two marshal nodes over a simulated network, each with its own application reporter.
struct Harness {
    context: deterministic::Context,
    oracle: simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
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
    verification_gate: Option<VerificationGate>,
    relay: bool,
}

impl Harness {
    async fn new(context: deterministic::Context, seed: u64, auto_acknowledge: [bool; 2]) -> Self {
        let committee = committee(seed);
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
            archive_modes: [ArchiveMode::Prunable; 3],
            catalog_mailbox_size: NZUsize!(64),
            max_commit_outputs: NZUsize!(8),
            max_hot_block_bytes: NZUsize!(512 * 1024 * 1024),
            max_pending_acks: NZUsize!(128),
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
            Start::Genesis(self.committee.genesis().clone()),
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
        .with_backfill_concurrency(RESOLVER_MAILBOX_SIZE)
        .with_max_commit_outputs(self.max_commit_outputs)
        .with_max_hot_block_bytes(self.max_hot_block_bytes)
        .with_max_pending_acks(self.max_pending_acks)
        .with_retention(Retention {
            lqc: self.archive_modes[0],
            history: self.archive_modes[1],
            blocks: self.archive_modes[2],
        })
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
        let config = self.config(&node_context, index);
        let identity = self.committee.identities[index].clone();
        let control = self.oracle.control(identity.clone());
        let resolver_network = control.register(RESOLVER_CHANNEL, QUOTA).await.unwrap();
        let broadcast_network = control.register(BROADCAST_CHANNEL, QUOTA).await.unwrap();
        let (broadcast_engine, buffer) = buffered::Engine::new(
            node_context.child("broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(64),
                ingress_size: NZUsize!(64),
                deque_size: 16,
                priority: false,
                codec_config: (),
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                strategy: Sequential,
            },
        );
        let broadcast = broadcast_engine.start(broadcast_network);
        let (mut service, bridge) = open::<_, TwoCap, Sha256, MinPk, TestBody, ed25519::PublicKey>(
            node_context.child("marshal"),
            config,
            buffer.clone(),
        )
        .await
        .unwrap();
        let relay = self.relay.then(|| service.relay(None));
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
                timeout: Duration::from_millis(100),
                fetch_retry_timeout: Duration::from_millis(20),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let resolver_handle = resolver_engine.start(resolver_network);
        let verifier = CommitteeVerifier {
            scheme: self.committee.verifier.clone(),
            gate: self.verification_gate.take(),
        };
        let (mailbox, marshal) = service.start(resolver, verifier, self.reporters[index].clone());
        self.nodes[index] = Some(Node {
            mailbox,
            buffer,
            relay,
            catalog,
            marshal,
            resolver: resolver_handle,
            broadcast,
            task_prefix,
        });
    }

    fn node(&self, index: usize) -> &Node {
        self.nodes[index].as_ref().expect("node is running")
    }

    fn mailbox(&self, index: usize) -> TestMailbox {
        self.node(index).mailbox.clone()
    }

    fn buffer(&self, index: usize) -> TestBuffer {
        self.node(index).buffer.clone()
    }

    fn relay(&self, index: usize) -> TestRelay {
        self.node(index)
            .relay
            .clone()
            .expect("node was started with a relay")
    }

    fn reporter(&self, index: usize) -> ApplicationReporter {
        self.reporters[index].clone()
    }

    fn catalog(&self, index: usize) -> catalog::Mailbox<Sha256, MinPk, TestBody> {
        self.node(index).catalog.clone()
    }

    /// Reports `activity` to node `index` as local consensus would.
    fn report(&self, index: usize, activity: TestActivity) {
        assert_eq!(self.mailbox(index).report(activity), Feedback::Ok);
    }

    /// Reports that view `view` resolved to node `index`.
    fn resolve(&self, index: usize, view: &Resolved) {
        self.report(index, view.resolution());
    }

    /// Reports that view `view` resolved and that the next leader block finalized it.
    fn finalize(&self, index: usize, view: &Resolved) {
        self.resolve(index, view);
        self.report(index, view.finalization(&self.committee));
    }

    /// Reports to node `index` that consensus accepted `block`'s header; an adopted one is
    /// fetched without a grace.
    fn accept_header(&self, index: usize, block: &TestBlock, adopted: bool) {
        let header = block.header().clone();
        let adopted = adopted.then_some(Duration::ZERO);
        self.report(index, Activity::HeaderAccepted { header, adopted });
    }

    /// Broadcasts `block` from node `from`'s buffer to node `to`.
    fn broadcast(&self, from: usize, to: usize, block: &Arc<TestBlock>) {
        assert_eq!(
            self.buffer(from).broadcast(
                Recipients::One(self.committee.identities[to].clone()),
                Digested::precomputed(Arc::clone(block), block.digest()),
            ),
            Feedback::Ok
        );
    }

    fn metric(&self, name: &str) -> u64 {
        metric_total(&self.context.encode(), name)
    }

    /// Waits until `predicate` holds for the metric `name` and returns its value.
    async fn wait_metric(&self, name: &str, predicate: impl Fn(u64) -> bool) -> u64 {
        for _ in 0..WAIT_STEPS {
            let value = self.metric(name);
            if predicate(value) {
                return value;
            }
            self.context.sleep(WAIT_STEP).await;
        }
        panic!(
            "metric {name} did not reach the expected value: {}",
            self.metric(name)
        );
    }

    async fn crash(&mut self, index: usize) {
        let node = self.nodes[index].take().expect("node is running");
        let task_prefix = node.task_prefix.clone();
        assert!(
            count_running_tasks(&self.context, &task_prefix) > 0,
            "node owns running actors before abort"
        );
        node.shutdown().await;
        self.reporters[index].discard_pending();
        for _ in 0..10 {
            if count_running_tasks(&self.context, &task_prefix) == 0 {
                break;
            }
            self.context.sleep(Duration::from_millis(1)).await;
        }
        assert_eq!(
            count_running_tasks(&self.context, &task_prefix),
            0,
            "node actors stop after joining every lifecycle owner"
        );
    }

    async fn restart(&mut self, index: usize) {
        self.crash(index).await;
        self.start(index).await;
    }

    async fn shutdown(&mut self) {
        for index in 0..self.nodes.len() {
            if self.nodes[index].is_some() {
                self.crash(index).await;
            }
        }
    }

    /// Waits until node `index`'s application has recorded at least `count` updates.
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
        panic!(
            "node {index} did not reach expected progress: {:?}",
            self.mailbox(index).progress().await
        );
    }

    /// Waits until node `index` has committed and acknowledged every output through `index`.
    async fn wait_acknowledged(&self, index: usize, through: OutputIndex) {
        self.wait_progress(index, |progress| progress.acknowledged == through)
            .await;
    }

    /// Waits until node `index` holds the block named by `reference`.
    async fn wait_block(&self, index: usize, reference: BlockRef<Sha256Digest>) -> Arc<TestBlock> {
        for _ in 0..WAIT_STEPS {
            if let Some(block) = self.mailbox(index).get_block(reference).await.unwrap() {
                return block;
            }
            self.context.sleep(WAIT_STEP).await;
        }
        panic!("node {index} did not obtain block {reference:?}");
    }
}

fn runner(seed: u64) -> deterministic::Runner {
    deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(60))),
    )
}

/// Runs `future` to completion within one second, or panics with `message`.
async fn within<T>(
    context: &deterministic::Context,
    message: &str,
    future: impl Future<Output = T>,
) -> T {
    commonware_macros::select! {
        output = future => output,
        _ = context.sleep(Duration::from_secs(1)) => panic!("{message}"),
    }
}

/// Asserts that `future` does not complete within `QUIET`.
async fn stays_pending<T: std::fmt::Debug>(
    context: &deterministic::Context,
    message: &str,
    future: impl Future<Output = T> + Unpin,
) {
    commonware_macros::select! {
        output = future => panic!("{message}: {output:?}"),
        _ = context.sleep(QUIET) => {},
    }
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
            "multimmit.marshal.synchronizer.walk_producers",
            "multimmit.marshal.catalog.process",
            "multimmit.marshal.catalog.admission_cut",
        ];
        let observed = routine.map(|expected| spans.iter().any(|(name, _)| *name == expected));
        assert_eq!(
            observed,
            [level == tracing::Level::DEBUG; 4],
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
fn a_burst_of_resolutions_survives_router_pressure_without_peers() {
    runner(131).start(|context| async move {
        let mut harness = Harness::new(context, 131, [true, true]).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let mut views = Views::new(&harness.committee);
        let first = views.one_each(&harness.committee, 1_310);
        first.submit(&mailbox).await;
        let mut burst = vec![first.resolution()];
        for _ in 0..3 * harness.catalog_mailbox_size.get() {
            burst.push(
                views
                    .next(&harness.committee, vec![Vec::new(); CHAINS])
                    .resolution(),
            );
        }
        let last = views.one_each(&harness.committee, 1_320);
        last.submit(&mailbox).await;
        burst.push(last.resolution());

        // The whole burst is reported before the router runs, so most of it overflows the
        // router's mailbox. No peer runs: every opening must come from local reports.
        let mut reporter = harness.mailbox(0);
        for activity in burst {
            assert_ne!(reporter.report(activity), Feedback::Closed);
        }

        let delivered = harness.wait_updates(0, 4).await;
        let mut expected = first.horizontal();
        expected.extend(last.horizontal());
        assert_delivered(&delivered, 1, &expected);
        harness.shutdown().await;
    });
}

#[test]
fn local_two_chain_delivery_is_offset_major_and_header_exact() {
    runner(101).start(|context| async move {
        let mut harness = Harness::new(context, 101, [true, true]).await;
        harness.start(0).await;
        let shared = body(10);
        let view = Views::new(&harness.committee).next(
            &harness.committee,
            vec![
                vec![shared.clone(), body(11)],
                vec![shared.clone(), body(12)],
            ],
        );
        view.submit(&harness.mailbox(0)).await;
        harness.resolve(0, &view);

        let delivered = harness.wait_updates(0, 4).await;
        assert_delivered(&delivered, 1, &view.horizontal());
        assert_eq!(view.index(), OutputIndex::new(4));
        assert_ne!(
            delivered[0].block.reference(),
            delivered[1].block.reference()
        );
        assert_ne!(delivered[0].block.header(), delivered[1].block.header());
        assert_eq!(delivered[0].block.body(), delivered[1].block.body());
        harness.wait_acknowledged(0, view.index()).await;
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

#[test]
fn open_view_sweep_emits_a_prefix_that_resolution_completes() {
    runner(132).start(|context| async move {
        let mut harness = Harness::new(context, 132, [true, true]).await;
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let mut views = Views::new(&harness.committee);
        let first = views.next(
            &harness.committee,
            vec![vec![body(1_320)], vec![body(1_321), body(1_322)]],
        );
        let second = views.next(
            &harness.committee,
            vec![vec![body(1_323), body(1_324)], vec![body(1_325)]],
        );
        first.submit(&mailbox).await;
        second.submit(&mailbox).await;
        let [a1, b1, b2] = [
            &first.blocks[0][0],
            &first.blocks[1][0],
            &first.blocks[1][1],
        ];
        let [a2, a3, b3] = [
            &second.blocks[0][0],
            &second.blocks[0][1],
            &second.blocks[1][0],
        ];
        let sweep = |view: &Resolved, finals: [&Arc<TestBlock>; CHAINS], settled: &[u32]| {
            Activity::ViewSweep {
                view: view.view,
                finals: finals.map(|block| block.reference()).to_vec().into(),
                settled: ChainSet::from_chains(CHAINS, settled.iter().copied().map(ChainId::new))
                    .unwrap(),
            }
        };

        // Every chain is final through its tip, but chain zero is unsettled above its height-one
        // final, so the sweep halts there and leaves chain one's second block for later.
        harness.report(0, sweep(&first, [a1, b2], &[]));
        let delivered = harness.wait_updates(0, 2).await;
        harness.context.sleep(QUIET).await;
        assert_delivered(
            &harness.reporter(0).delivered(),
            1,
            &[a1, b1].map(Arc::clone),
        );
        assert_eq!(delivered.len(), 2);

        // Once chain zero settles, the sweep skips it and continues on chain one. The view's
        // resolution then adds nothing.
        harness.report(0, sweep(&first, [a1, b2], &[0]));
        harness.wait_updates(0, 3).await;
        harness.resolve(0, &first);
        harness.wait_acknowledged(0, first.index()).await;

        // The next view's sweep emits its first offset and halts on chain zero; the resolution
        // emits the rest of the view's order without repeating the swept blocks.
        harness.report(0, sweep(&second, [a2, b3], &[]));
        harness.wait_updates(0, 5).await;
        harness.context.sleep(QUIET).await;
        assert_eq!(harness.reporter(0).delivered().len(), 5);
        harness.resolve(0, &second);
        harness.wait_acknowledged(0, second.index()).await;
        harness.context.sleep(QUIET).await;
        let expected = first
            .horizontal()
            .into_iter()
            .chain(second.horizontal())
            .collect::<Vec<_>>();
        assert_eq!(
            expected[3..].to_vec(),
            [a2, b3, a3].map(Arc::clone).to_vec()
        );
        assert_delivered(&harness.reporter(0).delivered(), 1, &expected);
        assert_eq!(second.index(), OutputIndex::new(6));
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
        let block = first_block(&harness.committee, 1_140);
        let reference = block.reference();

        let mut subscribed = Box::pin(target.subscribe_block(reference));
        stays_pending(
            &harness.context,
            "missing block subscription completed early",
            &mut subscribed,
        )
        .await;
        harness.broadcast(0, 1, &block);
        let received = within(
            &harness.context,
            "buffered ingress did not satisfy the block subscription",
            subscribed,
        )
        .await
        .unwrap();
        assert_eq!(received.as_ref(), block.as_ref());
        assert_eq!(
            target.get_block(reference).await.unwrap().as_deref(),
            Some(block.as_ref())
        );

        harness.restart(1).await;
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
        let block = first_block(&harness.committee, 1_210);

        harness.nodes[1]
            .as_mut()
            .expect("target is running")
            .marshal
            .abort();
        harness.context.sleep(WAIT_STEP).await;
        let subscribed = target.subscribe_block(block.reference());
        harness.broadcast(0, 1, &block);
        assert!(subscribed.await.is_err());

        harness.shutdown().await;
    });
}

#[test]
fn adopted_headers_fetch_their_bodies_from_peers() {
    runner(115).start(|context| async move {
        let mut harness = Harness::new(context, 115, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let source = harness.mailbox(0);
        let target = harness.mailbox(1);
        let [background, subscribed_block] = [1_150, 1_151].map(|marker| {
            let block = first_block(&harness.committee, marker);
            (block.reference(), block)
        });
        for (_, block) in [&background, &subscribed_block] {
            source.put_block(Arc::clone(block)).await.unwrap();
        }

        // An adopted header's body is fetched in the background, without any subscriber.
        harness.accept_header(1, &background.1, true);
        let fetched = harness.wait_block(1, background.0).await;
        assert_eq!(fetched.as_ref(), background.1.as_ref());

        // An adopted header also completes a subscription that buffered ingress cannot answer.
        let (reference, block) = subscribed_block;
        let mut subscribed = Box::pin(target.subscribe_block(reference));
        stays_pending(
            &harness.context,
            "missing block subscription completed early",
            &mut subscribed,
        )
        .await;
        harness.accept_header(1, &block, true);
        let received = within(
            &harness.context,
            "adopted header did not backfill the missing block",
            subscribed,
        )
        .await
        .unwrap();
        assert_eq!(received.as_ref(), block.as_ref());

        harness.restart(1).await;
        for (reference, block) in [background, (reference, block)] {
            assert_eq!(
                harness
                    .mailbox(1)
                    .get_block(reference)
                    .await
                    .unwrap()
                    .as_deref(),
                Some(block.as_ref())
            );
        }
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
        let subscriptions = (0..RESOLVER_MAILBOX_SIZE.get() as u64)
            .map(|marker| {
                let reference = first_block(&harness.committee, 1_250 + marker).reference();
                let mailbox = target.clone();
                harness
                    .context
                    .child("subscription")
                    .shared(false)
                    .spawn(move |_| async move { mailbox.subscribe_block(reference).await })
            })
            .collect::<Vec<_>>();
        let count = subscriptions.len() as u64;
        harness
            .wait_metric("resolver_pending_requests", |pending| pending >= count)
            .await;
        assert_eq!(
            harness.metric("resolver_pending_requests"),
            count,
            "every subscription is registered before testing router progress"
        );

        let progress = within(
            &harness.context,
            "unresolved subscriptions stalled unrelated router intake",
            target.progress(),
        )
        .await;
        assert!(progress.is_ok());

        for subscription in subscriptions {
            subscription.abort();
        }
        harness.shutdown().await;
    });
}

/// Starts node zero with its first L-QC verification held, and returns a receiver for the
/// verification's start and its release.
async fn start_gated(harness: &mut Harness) -> (oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (gate, started, release) = VerificationGate::new();
    harness.verification_gate = Some(gate);
    harness.start(0).await;
    (started, release)
}

/// Returns the L-QC of view one's floor and a spawner of its installations on node zero.
fn floor_installer(
    harness: &Harness,
) -> (
    CertificateId<Sha256Digest>,
    impl Fn(&'static str) -> Handle<Result<(), MailboxError>> + use<>,
) {
    let view = Views::new(&harness.committee).one_each(&harness.committee, 1_270);
    let floor = view.floor(&harness.committee);
    let target = harness.mailbox(0);
    let context = harness.context.child("floor_installer");
    let spawn = move |label: &'static str| {
        let mailbox = target.clone();
        let floor = floor.clone();
        context
            .child(label)
            .shared(false)
            .spawn(move |_| async move { mailbox.install_floor(floor).await })
    };
    (view.lqc_id(&harness.committee), spawn)
}

/// Spawns one floor installation per router job and waits until every job is occupied, the first
/// paused in verification.
async fn occupy_router_jobs(
    harness: &Harness,
    spawn: &impl Fn(&'static str) -> Handle<Result<(), MailboxError>>,
) -> Vec<Handle<Result<(), MailboxError>>> {
    let capacity = RESOLVER_MAILBOX_SIZE.get();
    let installs = (0..capacity).map(|_| spawn("install")).collect::<Vec<_>>();
    harness
        .wait_metric("pending_jobs", |jobs| jobs >= capacity as u64)
        .await;
    assert_eq!(
        harness.metric("pending_jobs"),
        capacity as u64,
        "every router job is occupied"
    );
    installs
}

#[test]
fn saturated_router_backpressures_requests_until_capacity_returns() {
    runner(127).start(|context| async move {
        let mut harness = Harness::new(context, 127, [true, true]).await;
        let (_started, release) = start_gated(&mut harness).await;
        let (floor, spawn) = floor_installer(&harness);
        let installs = occupy_router_jobs(&harness, &spawn).await;

        let mut queued = (0..=harness.catalog_mailbox_size.get())
            .map(|_| spawn("queued"))
            .collect::<FuturesUnordered<_>>();
        let rejected = within(
            &harness.context,
            "router did not reject work beyond its ingress capacity",
            queued.next(),
        )
        .await
        .expect("one queued task remains")
        .expect("queued task remains alive");
        assert!(matches!(rejected, Err(MailboxError::Busy)));
        stays_pending(
            &harness.context,
            "router completed an accepted request while its execution pool remained full",
            queued.next(),
        )
        .await;

        release.send(()).unwrap();
        for install in installs {
            assert!(!matches!(install.await.unwrap(), Err(MailboxError::Busy)));
        }
        while !queued.is_empty() {
            let result = within(
                &harness.context,
                "router did not resume intake after execution capacity returned",
                queued.next(),
            )
            .await;
            assert!(!matches!(
                result
                    .expect("one queued task remains")
                    .expect("queued task remains alive"),
                Err(MailboxError::Busy)
            ));
        }
        assert_eq!(harness.mailbox(0).progress().await.unwrap().floor, floor);
        harness.shutdown().await;
    });
}

#[test]
fn saturated_router_queues_block_subscriptions_until_capacity_returns() {
    runner(128).start(|context| async move {
        let mut harness = Harness::new(context, 128, [true, true]).await;
        let (_started, release) = start_gated(&mut harness).await;
        let (_, spawn) = floor_installer(&harness);
        let target = harness.mailbox(0);

        // The first installation pauses in verification and the rest occupy every router job,
        // then a full request queue of installations waits behind them.
        let installs = occupy_router_jobs(&harness, &spawn).await;
        let queued = (0..harness.catalog_mailbox_size.get())
            .map(|_| spawn("queued"))
            .collect::<Vec<_>>();
        // Let every queued installation reach the router's request queue.
        harness.context.sleep(WAIT_STEP).await;

        // Subscriptions past the full queue are retained rather than answered with busy, while
        // further staging-style work is still rejected.
        const SUBSCRIPTIONS: u64 = 8;
        let mut subscriptions = (0..SUBSCRIPTIONS)
            .map(|marker| {
                let reference = first_block(&harness.committee, 1_290 + marker).reference();
                let mailbox = target.clone();
                harness
                    .context
                    .child("subscription")
                    .shared(false)
                    .spawn(move |_| async move { mailbox.subscribe_block(reference).await })
            })
            .collect::<FuturesUnordered<_>>();
        harness.context.sleep(WAIT_STEP).await;
        assert!(matches!(
            spawn("rejected")
                .await
                .expect("rejected task remains alive"),
            Err(MailboxError::Busy)
        ));
        stays_pending(
            &harness.context,
            "a subscription finished while the router was saturated",
            subscriptions.next(),
        )
        .await;

        // Once capacity returns, the router takes every retained subscription.
        release.send(()).unwrap();
        for install in installs.into_iter().chain(queued) {
            assert!(!matches!(install.await.unwrap(), Err(MailboxError::Busy)));
        }
        harness
            .wait_metric("block_subscription_callers", |callers| {
                callers >= SUBSCRIPTIONS
            })
            .await;
        assert_eq!(
            harness.metric("block_subscription_callers"),
            SUBSCRIPTIONS,
            "every retained subscription reached the router"
        );
        stays_pending(
            &harness.context,
            "a subscription for a missing block finished",
            subscriptions.next(),
        )
        .await;
        for subscription in subscriptions {
            subscription.abort();
        }
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
        let mut relay = harness.relay(0);
        let peer = harness.buffer(1);
        let block = first_block(&harness.committee, 1_300);
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
        harness
            .mailbox(0)
            .put_block(Arc::clone(&block))
            .await
            .unwrap();
        assert_eq!(
            crate::Relay::broadcast(&mut relay, reference.digest(), ()),
            Feedback::Ok
        );
        let received = within(
            &harness.context,
            "the relay did not broadcast the staged block",
            received,
        )
        .await;
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
            .map(|marker| first_block(&harness.committee, 1_330 + marker))
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
        let received = within(
            &harness.context,
            "the relay dropped a block within its retention",
            received,
        )
        .await;
        assert_eq!(received.as_deref(), Some(blocks[1].as_ref()));
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
        let capacity = RESOLVER_MAILBOX_SIZE.get() as u64;
        let subscribe = |block: &Arc<TestBlock>| {
            let mailbox = target.clone();
            let reference = block.reference();
            harness
                .context
                .child("subscription")
                .shared(false)
                .spawn(move |_| async move { mailbox.subscribe_block(reference).await })
        };

        // Every slot is held by a subscription for a missing block.
        let held = (0..capacity)
            .map(|marker| first_block(&harness.committee, 1_300 + marker))
            .collect::<Vec<_>>();
        let mut subscriptions = held.iter().map(subscribe).collect::<Vec<_>>();
        harness
            .wait_metric("block_subscription_callers", |callers| callers >= capacity)
            .await;
        assert_eq!(harness.metric("block_subscription_callers"), capacity);

        // One more subscription waits for a slot instead of registering or failing.
        let extra = first_block(&harness.committee, 1_399);
        let mut waiting = subscribe(&extra);
        stays_pending(
            &harness.context,
            "a subscription past the slot bound finished",
            &mut waiting,
        )
        .await;
        assert_eq!(harness.metric("block_subscription_callers"), capacity);

        // Answering one held subscription frees its slot, and the waiting one then completes.
        harness.broadcast(0, 1, &held[0]);
        let first = subscriptions.remove(0).await.unwrap().unwrap();
        assert_eq!(first.as_ref(), held[0].as_ref());
        harness
            .wait_metric("block_subscription_callers", |callers| callers >= capacity)
            .await;
        harness.broadcast(0, 1, &extra);
        let received = within(
            &harness.context,
            "the waiting subscription did not complete after a slot freed",
            waiting,
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received.as_ref(), extra.as_ref());

        for subscription in subscriptions {
            subscription.abort();
        }
        harness.shutdown().await;
    });
}

#[test]
fn adopted_body_fetch_outlives_a_canceled_subscription() {
    runner(126).start(|context| async move {
        let mut harness = Harness::new(context, 126, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let block = first_block(&harness.committee, 1_260);
        let reference = block.reference();

        let target = harness.mailbox(1);
        let mut subscribed = Box::pin(target.subscribe_block(reference));
        stays_pending(
            &harness.context,
            "missing block subscription completed early",
            &mut subscribed,
        )
        .await;
        harness.accept_header(1, &block, true);
        harness
            .wait_metric("requests_sent_total", |sent| sent > 0)
            .await;

        // The adoption, not the subscriber, owns the fetch: it keeps retrying after the only
        // subscriber leaves and completes once a peer holds the body.
        drop(subscribed);
        harness.context.sleep(QUIET).await;
        assert!(harness.metric("resolver_pending_requests") > 0);
        let sent = harness.metric("requests_sent_total");
        harness.context.sleep(Duration::from_millis(250)).await;
        assert!(harness.metric("requests_sent_total") > sent);
        harness
            .mailbox(0)
            .put_block(Arc::clone(&block))
            .await
            .unwrap();
        let fetched = harness.wait_block(1, reference).await;
        assert_eq!(fetched.as_ref(), block.as_ref());
        harness
            .wait_metric("resolver_pending_requests", |pending| pending == 0)
            .await;

        harness.shutdown().await;
    });
}

/// Finalizes two views with two blocks per chain on node zero and returns them.
async fn finalize_two_views(harness: &Harness, first: u64) -> [Resolved; 2] {
    let mut views = Views::new(&harness.committee);
    let views = [first, first + 4].map(|marker| {
        views.next(
            &harness.committee,
            vec![
                vec![body(marker), body(marker + 1)],
                vec![body(marker + 2), body(marker + 3)],
            ],
        )
    });
    let source = harness.mailbox(0);
    for view in &views {
        view.submit(&source).await;
        harness.finalize(0, view);
    }
    harness.wait_updates(0, 8).await;
    views
}

/// Returns the delivery order of `views`, oldest first.
fn horizontal(views: &[Resolved]) -> Vec<Arc<TestBlock>> {
    views.iter().flat_map(Resolved::horizontal).collect()
}

#[test]
fn remote_resolver_backfills_exact_lqc_history_and_blocks() {
    runner(102).start(|context| async move {
        let mut harness = Harness::new(context, 102, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let views = finalize_two_views(&harness, 20).await;
        let target = harness.mailbox(1);

        // The target holds one block from buffered ingress, whose header consensus accepted.
        let ingress = &views[0].blocks[0][0];
        let received = subscribe_buffered(&harness.buffer(1), ingress.reference());
        harness.broadcast(0, 1, ingress);
        let received = within(
            &harness.context,
            "buffered broadcast did not deliver the exact block",
            received,
        )
        .await
        .expect("buffered broadcast remains open");
        assert_eq!(received.as_ref(), ingress.as_ref());
        target.put_block(Arc::clone(ingress)).await.unwrap();
        harness.accept_header(1, ingress, false);

        // The target fetches the exact L-QC that finalizes view two, and nothing else.
        let lqc = views[1].lqc(&harness.committee);
        let fetched = target.fetch_certificate(lqc.id::<Sha256>()).await.unwrap();
        assert_eq!(fetched, lqc);
        for block in views.iter().flat_map(Resolved::all_blocks) {
            let reference = block.reference();
            assert_eq!(
                target.get_block(reference).await.unwrap().is_some(),
                reference == ingress.reference()
            );
        }

        // On restart, the target synchronizes to its retained L-QC: peers serve both history
        // openings and every block it lacks.
        harness.restart(1).await;
        let delivered = harness.wait_updates(1, 8).await;
        assert_delivered(&delivered, 1, &horizontal(&views));
        for block in views.iter().flat_map(Resolved::all_blocks) {
            let stored = harness
                .mailbox(1)
                .get_block(block.reference())
                .await
                .unwrap()
                .expect("resolved block is admitted");
            assert_eq!(stored.as_ref(), block.as_ref());
        }
        assert_eq!(
            harness
                .mailbox(1)
                .get_certificate(lqc.id::<Sha256>())
                .await
                .unwrap(),
            Some(lqc)
        );
        harness.shutdown().await;
    });
}

#[test]
fn leader_finalized_backfills_missing_openings_and_blocks_from_a_peer() {
    runner(110).start(|context| async move {
        let mut harness = Harness::new(context, 110, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let views = finalize_two_views(&harness, 30).await;

        // The target only learns view two's finalization; view one's opening and every block
        // come from the peer.
        harness.report(1, views[1].finalization(&harness.committee));
        let delivered = harness.wait_updates(1, 8).await;
        assert_delivered(&delivered, 1, &horizontal(&views));
        let progress = harness
            .wait_progress(1, |progress| progress.acknowledged == views[1].index())
            .await;
        assert_eq!(progress.floor, views[1].lqc_id(&harness.committee));
        harness.shutdown().await;
    });
}

#[test]
fn an_anchoring_finalization_above_a_delivered_view_backfills_the_skipped_views() {
    runner(112).start(|context| async move {
        let mut harness = Harness::new(context, 112, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let mut views = Views::new(&harness.committee);
        let views = [1_120, 1_122, 1_124].map(|marker| views.one_each(&harness.committee, marker));
        for view in &views {
            view.submit(&harness.mailbox(0)).await;
            harness.finalize(0, view);
        }
        harness.wait_updates(0, 6).await;

        // The target delivered view one, then anchored at view three's finalization: consensus
        // reports nothing about view two, whose opening and blocks only the peer holds.
        views[0].submit(&harness.mailbox(1)).await;
        harness.resolve(1, &views[0]);
        harness.wait_updates(1, 2).await;
        harness.report(1, views[2].finalization(&harness.committee));
        let delivered = harness.wait_updates(1, 6).await;
        assert_delivered(&delivered, 1, &horizontal(&views));
        let progress = harness
            .wait_progress(1, |progress| progress.acknowledged == views[2].index())
            .await;
        assert_eq!(progress.floor, views[2].lqc_id(&harness.committee));
        harness.shutdown().await;
    });
}

#[test]
fn view_gap_repair_fetches_missing_openings_from_peers() {
    runner(116).start(|context| async move {
        let mut harness = Harness::new(context, 116, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let mut views = Views::new(&harness.committee);
        let views = [160, 162, 164].map(|marker| views.one_each(&harness.committee, marker));
        let target = harness.mailbox(1);
        for view in &views {
            view.submit(&harness.mailbox(0)).await;
            harness.resolve(0, view);
            view.submit(&target).await;
        }
        harness.wait_updates(0, 6).await;

        // The target missed view two's resolution: view three's names its parent commitment,
        // whose opening only the peer holds.
        harness.resolve(1, &views[0]);
        harness.wait_updates(1, 2).await;
        harness.resolve(1, &views[2]);
        let delivered = harness.wait_updates(1, 6).await;
        assert_delivered(&delivered, 1, &horizontal(&views));
        harness.wait_acknowledged(1, views[2].index()).await;
        harness.shutdown().await;
    });
}

#[test]
fn late_local_resolution_completes_an_active_gap_repair() {
    runner(118).start(|context| async move {
        let mut harness = Harness::new(context, 118, [true, true]).await;
        harness.start(0).await;
        let mut views = Views::new(&harness.committee);
        let views = [1_180, 1_182].map(|marker| views.one_each(&harness.committee, marker));
        for view in &views {
            view.submit(&harness.mailbox(0)).await;
        }

        // View two resolves first; without view one's opening the node asks its (absent) peers.
        harness.resolve(0, &views[1]);
        harness
            .wait_metric("resolver_pending_requests", |pending| pending > 0)
            .await;
        assert!(harness.reporter(0).delivered().is_empty());

        // View one's late resolution stages the missing opening locally.
        harness.resolve(0, &views[0]);
        let delivered = harness.wait_updates(0, 4).await;
        assert_delivered(&delivered, 1, &horizontal(&views));
        harness.wait_acknowledged(0, views[1].index()).await;
        harness.shutdown().await;
    });
}

#[test]
fn malformed_reports_do_not_stop_the_service() {
    runner(105).start(|context| async move {
        let mut harness = Harness::new(context, 105, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let mailbox = harness.mailbox(0);
        let view = Views::new(&harness.committee)
            .next(&harness.committee, vec![vec![body(25)], Vec::new()]);
        let request_local = |what: &'static str| {
            let mailbox = mailbox.clone();
            let context = harness.context.child("request_local");
            async move {
                context.sleep(Duration::from_millis(10)).await;
                mailbox
                    .progress()
                    .await
                    .unwrap_or_else(|error| panic!("{what} stopped marshal: {error:?}"));
            }
        };

        // A resolution whose commitment does not hash its opening.
        let Activity::ViewResolved {
            view: resolved,
            base,
            tips,
            parent_commitment,
            by,
            ..
        } = view.resolution()
        else {
            unreachable!("a resolution is reported as ViewResolved");
        };
        harness.report(
            0,
            Activity::ViewResolved {
                view: resolved,
                base,
                tips,
                commitment: digest(b"wrong history commitment", 0),
                parent_commitment,
                by,
            },
        );
        request_local("a resolution with a wrong commitment").await;

        // A finalization whose opening does not open the leader block's history commitment.
        let wrong_opening =
            Arc::new(HistoryRecord::new(digest(b"wrong parent", 0), view.tips().to_vec()).unwrap());
        harness.report(
            0,
            Activity::LeaderFinalized {
                lqc: view.lqc(&harness.committee),
                opening: wrong_opening,
            },
        );
        request_local("a finalization with a wrong opening").await;

        // A finalization of another committee's epoch.
        let other_committee = committee(106);
        let other =
            Views::new(&other_committee).next(&other_committee, vec![vec![body(26)], Vec::new()]);
        harness.report(0, other.finalization(&other_committee));
        request_local("a wrong-epoch finalization").await;

        // An adopted header of another epoch, whose block buffered ingress holds.
        let wrong_epoch_block = &other.blocks[0][0];
        let received = subscribe_buffered(&harness.buffer(0), wrong_epoch_block.reference());
        harness.broadcast(1, 0, wrong_epoch_block);
        let received = within(
            &harness.context,
            "wrong-epoch block was not buffered",
            received,
        )
        .await
        .expect("wrong-epoch block is buffered");
        assert_eq!(received.as_ref(), wrong_epoch_block.as_ref());
        harness.report(
            0,
            Activity::HeaderAccepted {
                header: wrong_epoch_block.header().clone(),
                adopted: Some(Duration::ZERO),
            },
        );
        request_local("a wrong-epoch adopted header").await;
        assert!(
            mailbox
                .get_block(wrong_epoch_block.reference())
                .await
                .unwrap()
                .is_none()
        );

        view.submit(&mailbox).await;
        harness.finalize(0, &view);
        let delivered = harness.wait_updates(0, 1).await;
        assert_delivered(&delivered, 1, &view.horizontal());
        harness.shutdown().await;
    });
}

#[test]
fn missing_block_pressure_retires_old_subscriptions() {
    runner(109).start(|context| async move {
        let mut harness = Harness::new(context, 109, [true, true]).await;
        harness.start(0).await;
        harness.start(1).await;
        let mut reporter = harness.mailbox(1);

        // Adopted headers whose bodies no peer holds fill backfill's waiters.
        for marker in 0..64 {
            let missing = first_block(&harness.committee, 1_000 + marker);
            let header = missing.header().clone();
            loop {
                match reporter.report(Activity::HeaderAccepted {
                    header: header.clone(),
                    adopted: Some(Duration::ZERO),
                }) {
                    Feedback::Ok => break,
                    Feedback::Backoff => harness.context.sleep(WAIT_STEP).await,
                    Feedback::Closed => panic!("marshal closed while filling block waiters"),
                }
            }
            harness.context.sleep(WAIT_STEP).await;
        }

        // A newly adopted block that a peer serves is still fetched.
        let block = first_block(&harness.committee, 2_000);
        harness
            .mailbox(0)
            .put_block(Arc::clone(&block))
            .await
            .unwrap();
        harness.accept_header(1, &block, true);
        let admitted = within(
            &harness.context,
            "new adopted header remained blocked behind missing bodies",
            harness.wait_block(1, block.reference()),
        )
        .await;
        assert_eq!(admitted.as_ref(), block.as_ref());
        harness.shutdown().await;
    });
}

#[test]
fn crash_redelivers_only_until_acknowledgement_is_durable() {
    runner(103).start(|context| async move {
        let mut harness = Harness::new(context, 103, [false, true]).await;
        harness.start(0).await;
        let view = Views::new(&harness.committee).one_each(&harness.committee, 30);
        let expected = view.horizontal();
        view.submit(&harness.mailbox(0)).await;
        harness.resolve(0, &view);
        let first = harness.wait_updates(0, 2).await;
        assert_delivered(&first, 1, &expected);
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
        harness.wait_acknowledged(0, OutputIndex::new(1)).await;
        harness.restart(0).await;
        let redelivered = harness.wait_updates(0, 3).await;
        assert_delivered(&redelivered[2..], 2, &expected[1..]);
        assert_eq!(harness.reporter(0).pending(), vec![OutputIndex::new(2)]);
        assert_eq!(
            harness.reporter(0).acknowledge_next(),
            Some(OutputIndex::new(2))
        );
        harness.wait_acknowledged(0, OutputIndex::new(2)).await;
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

        harness.restart(0).await;
        harness
            .wait_progress(0, |progress| {
                progress.committed == OutputIndex::new(2)
                    && progress.acknowledged == OutputIndex::new(2)
            })
            .await;
        harness.context.sleep(QUIET).await;
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
        let view = Views::new(&harness.committee).next(
            &harness.committee,
            vec![vec![body(60), body(61)], vec![body(62), body(63)]],
        );
        view.submit(&harness.mailbox(0)).await;
        harness.resolve(0, &view);

        let delivered = harness.wait_updates(0, 3).await;
        assert_delivered(&delivered, 1, &view.horizontal()[..3]);
        harness.context.sleep(QUIET).await;
        assert_eq!(harness.reporter(0).delivered().len(), 3);

        let reporter = harness.reporter(0);
        assert!(reporter.acknowledge(OutputIndex::new(2)));
        assert!(reporter.acknowledge(OutputIndex::new(3)));
        harness.context.sleep(QUIET).await;
        assert_eq!(
            harness.mailbox(0).progress().await.unwrap().acknowledged,
            OutputIndex::zero()
        );
        assert_eq!(reporter.pending(), vec![OutputIndex::new(1)]);

        assert!(reporter.acknowledge(OutputIndex::new(1)));
        harness.wait_acknowledged(0, OutputIndex::new(3)).await;
        let delivered = harness.wait_updates(0, 4).await;
        assert_eq!(delivered[3].index, OutputIndex::new(4));
        assert_eq!(reporter.pending(), vec![OutputIndex::new(4)]);

        assert!(reporter.acknowledge(OutputIndex::new(4)));
        harness.wait_acknowledged(0, OutputIndex::new(4)).await;
        harness.shutdown().await;
    });
}

/// Builds `count` views with four blocks per chain, with bodies numbered from `first`.
fn dense_views(committee: &Committee<MinPk>, count: u64, first: u64) -> Vec<Resolved> {
    let mut views = Views::new(committee);
    (1..=count)
        .map(|view| {
            views.next(
                committee,
                (0..CHAINS as u64)
                    .map(|chain| {
                        (0..4)
                            .map(|offset| body(first + chain * 1_000 + view * 100 + offset))
                            .collect()
                    })
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn sustained_one_output_commits_remain_dense_and_memory_only() {
    runner(120).start(|context| async move {
        let mut harness = Harness::new(context, 120, [true, true]).await;
        harness.max_commit_outputs = NZUsize!(1);
        harness.max_pending_acks = NZUsize!(8);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let views = dense_views(&harness.committee, 4, 3_000);
        for view in &views {
            view.submit(&mailbox).await;
            harness.resolve(0, view);
        }
        let expected = horizontal(&views);

        let delivered = harness.wait_updates(0, expected.len()).await;
        assert_delivered(&delivered, 1, &expected);
        harness
            .wait_acknowledged(0, views.last().unwrap().index())
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
        let mut harness = Harness::new(context, 121, [true, true]).await;
        harness.catalog_mailbox_size = NZUsize!(256);
        harness.max_commit_outputs = NZUsize!(128);
        harness.max_pending_acks = NZUsize!(256);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let views = dense_views(&harness.committee, 20, 5_000);
        for view in &views {
            view.submit(&mailbox).await;
        }

        // Twenty resolutions reported back to back merge into catch-up passes over the staged
        // openings, finalized by the last view's L-QC.
        for view in &views {
            harness.resolve(0, view);
        }
        let last = views.last().unwrap();
        harness.report(0, last.finalization(&harness.committee));
        let expected = horizontal(&views);
        let delivered = harness.wait_updates(0, expected.len()).await;
        assert_delivered(&delivered, 1, &expected);
        harness.wait_acknowledged(0, last.index()).await;

        let metrics = harness.context.encode();
        let outputs = expected.len() as u64;
        for (metric, expected) in [
            ("custody_planned_outputs_total", outputs),
            ("custody_local_outputs_total", outputs),
            ("custody_fetched_outputs_total", 0),
            ("delivery_hot_outputs_total", outputs),
            ("delivery_stored_outputs_total", 0),
            ("runtime_storage_reads_total", 0),
        ] {
            assert_eq!(
                metric_total(&metrics, metric),
                expected,
                "{metric}: {metrics}"
            );
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
        let view = Views::new(&harness.committee).next(
            &harness.committee,
            vec![
                vec![body(80), body(81), body(82), body(83)],
                vec![body(84), body(85), body(86), body(87)],
            ],
        );
        let expected = view.horizontal();
        view.submit(&harness.mailbox(0)).await;
        harness.resolve(0, &view);

        harness.wait_updates(0, 1).await;
        harness
            .wait_progress(0, |progress| progress.committed == view.index())
            .await;
        for (offset, block) in expected.iter().enumerate() {
            let index = OutputIndex::new(offset as u64 + 1);
            let delivered = harness.wait_updates(0, offset + 1).await;
            assert_eq!(delivered[offset].index, index);
            assert_eq!(delivered[offset].block.as_ref(), block.as_ref());
            assert_eq!(harness.reporter(0).acknowledge_next(), Some(index));
            harness.wait_acknowledged(0, index).await;
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
        let view = Views::new(&harness.committee).next(
            &harness.committee,
            vec![
                vec![body(90), body(91), body(92), body(93)],
                vec![body(94), body(95), body(96), body(97)],
            ],
        );
        let expected = view.horizontal();
        let cache_bytes = std::mem::size_of::<StoredRef<Sha256Digest>>()
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

        view.submit(&harness.mailbox(0)).await;
        harness.resolve(0, &view);
        let delivered = harness.wait_updates(0, expected.len()).await;
        assert_delivered(&delivered, 1, &expected);
        harness.wait_acknowledged(0, view.index()).await;

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
        let view = Views::new(&harness.committee).one_each(&harness.committee, 88);
        let expected = view.horizontal();
        let block_bytes = expected[0].encode_size();
        assert_eq!(expected[1].encode_size(), block_bytes);
        let descriptor_bytes = std::mem::size_of::<StoredRef<Sha256Digest>>();
        harness.max_hot_block_bytes = NonZeroUsize::new(block_bytes + descriptor_bytes).unwrap();
        harness.max_pending_acks = NZUsize!(2);
        harness.start(0).await;

        view.submit(&harness.mailbox(0)).await;
        harness.resolve(0, &view);
        let delivered = harness.wait_updates(0, 2).await;
        assert_delivered(&delivered, 1, &expected);
        harness.wait_acknowledged(0, view.index()).await;

        let metrics = harness.context.encode();
        for (metric, expected) in [
            ("custody_local_outputs_total", 2),
            ("custody_fetched_outputs_total", 0),
            ("delivery_stored_outputs_total", 1),
            ("delivery_hot_outputs_total", 1),
        ] {
            assert_eq!(
                metric_total(&metrics, metric),
                expected,
                "{metric}: {metrics}"
            );
        }
        harness.shutdown().await;
    });
}

#[test]
fn canceled_floor_install_still_retires_adopted_requests() {
    runner(133).start(|context| async move {
        let mut harness = Harness::new(context, 133, [true, true]).await;
        let (gate, mut started, release) = VerificationGate::new();
        harness.verification_gate = Some(gate);
        harness.start(0).await;

        // An adopted block below the floor has a body fetch in flight that no peer can serve.
        let view = Views::new(&harness.committee).one_each(&harness.committee, 133);
        harness.accept_header(0, &view.blocks[0][0], true);
        harness
            .wait_metric("resolver_pending_requests", |pending| pending == 1)
            .await;

        let floor = view.lqc_id(&harness.committee);
        let mailbox = harness.mailbox(0);
        let mut installation = Box::pin(mailbox.install_floor(view.floor(&harness.committee)));
        commonware_macros::select! {
            result = &mut started => result.unwrap(),
            result = &mut installation => panic!("floor installation completed before verification paused: {result:?}"),
        }
        drop(installation);
        harness.context.sleep(WAIT_STEP).await;
        release.send(()).unwrap();
        harness
            .wait_progress(0, |progress| {
                progress.floor_generation == 1 && progress.floor == floor
            })
            .await;
        harness
            .wait_metric("resolver_pending_requests", |pending| pending == 0)
            .await;
        harness.shutdown().await;
    });
}

#[test]
fn floor_installation_retires_the_pending_delivery_window() {
    runner(112).start(|context| async move {
        let mut harness = Harness::new(context, 112, [false, true]).await;
        harness.max_pending_acks = NZUsize!(2);
        harness.start(0).await;
        let mailbox = harness.mailbox(0);
        let mut views = Views::new(&harness.committee);
        let [first, floor, continuation] =
            [70, 72, 74].map(|marker| views.one_each(&harness.committee, marker));
        first.submit(&mailbox).await;
        harness.resolve(0, &first);
        harness.wait_updates(0, 2).await;
        harness
            .wait_progress(0, |progress| {
                progress.committed == first.index() && progress.acknowledged.is_zero()
            })
            .await;

        // The floor's tips are at height two on both chains, so its index is four.
        mailbox
            .install_floor(floor.floor(&harness.committee))
            .await
            .unwrap();
        harness
            .wait_progress(0, |progress| {
                progress.floor_generation == 1
                    && progress.committed == OutputIndex::new(4)
                    && progress.acknowledged == OutputIndex::new(4)
            })
            .await;
        harness.reporter(0).discard_pending();

        continuation.submit(&mailbox).await;
        harness.finalize(0, &continuation);
        let delivered = harness.wait_updates(0, 4).await;
        assert_delivered(&delivered[2..], 5, &continuation.horizontal());

        // Pruning at the continuation's floor reclaims both generations' rows below it and their
        // bodies, except each chain's tip at that floor, which its next block builds on.
        let reporter = harness.reporter(0);
        assert!(reporter.acknowledge(OutputIndex::new(5)));
        assert!(reporter.acknowledge(OutputIndex::new(6)));
        harness.wait_acknowledged(0, OutputIndex::new(6)).await;
        mailbox.prune(OutputIndex::new(6)).await.unwrap();
        for block in first.all_blocks() {
            assert!(
                mailbox
                    .get_block(block.reference())
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        for block in continuation.all_blocks() {
            assert!(
                mailbox
                    .get_block(block.reference())
                    .await
                    .unwrap()
                    .is_some()
            );
        }

        harness.restart(0).await;
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
        let mut views = Views::new(&harness.committee);
        let [first, floor, continuation, newest] =
            [80, 82, 84, 86].map(|marker| views.one_each(&harness.committee, marker));
        first.submit(&mailbox).await;
        harness.resolve(0, &first);
        harness.wait_updates(0, 2).await;

        // Each view adds one block per chain, so the first generation holds rows one and two,
        // the second its floor index four and rows five and six, and the third floor index
        // eight.
        for (generation, floor) in [(1, &floor), (2, &newest)] {
            mailbox
                .install_floor(floor.floor(&harness.committee))
                .await
                .unwrap();
            harness
                .wait_progress(0, |progress| {
                    progress.floor_generation == generation && progress.committed == floor.index()
                })
                .await;
            harness.reporter(0).discard_pending();
            if generation == 1 {
                continuation.submit(&mailbox).await;
                harness.resolve(0, &continuation);
                harness.wait_updates(0, 4).await;
            }
        }

        // A read that begins in a gap below a floor index resumes at the next generation's
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

        // Three views each add one block per chain, so their floors end at indices 2, 4, 6.
        let mut views = Views::new(&harness.committee);
        let views = [92, 94, 96].map(|marker| views.one_each(&harness.committee, marker));
        for view in &views {
            view.submit(&source).await;
            harness.finalize(0, view);
            let id = view.lqc_id(&harness.committee);
            harness
                .wait_progress(0, |progress| progress.floor == id)
                .await;
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
            assert_eq!(floor, views[view].floor(&harness.committee));
        }

        // Pruning at index five keeps the floor at or below it, every output after that floor,
        // and each chain's block at the floor, which its next block builds on.
        harness.wait_acknowledged(0, OutputIndex::new(6)).await;
        source.prune(OutputIndex::new(5)).await.unwrap();
        let (found, _) = floor_at(5).await.unwrap();
        assert_eq!(found, OutputIndex::new(4));
        for (position, view) in views.iter().enumerate() {
            for block in view.all_blocks() {
                let local = source.get_block(block.reference()).await.unwrap();
                assert_eq!(local.is_some(), position >= 1);
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
        harness.finalize(1, &views[2]);
        let resumed = harness.wait_updates(1, 2).await;
        assert_delivered(
            &resumed,
            5,
            &delivered[4..]
                .iter()
                .map(|delivered| Arc::clone(&delivered.block))
                .collect::<Vec<_>>(),
        );
        harness.shutdown().await;
    });
}

/// Installs view one's floor, resolves an empty view and a four-block view above it, prunes, and
/// checks across a reopen that each family's retention follows its archive mode.
async fn run_floor_case(
    context: deterministic::Context,
    seed: u64,
    archive_modes: [ArchiveMode; 3],
) {
    let mut harness = Harness::new(context, seed, [true, true]).await;
    harness.archive_modes = archive_modes;
    harness.start(0).await;
    let mut views = Views::new(&harness.committee);
    let floor = views.one_each(&harness.committee, 40);
    let empty = views.next(&harness.committee, vec![Vec::new(), Vec::new()]);
    let continuation = views.next(
        &harness.committee,
        vec![vec![body(42), body(44)], vec![body(43), body(45)]],
    );
    let floor_id = floor.lqc_id(&harness.committee);
    harness
        .mailbox(0)
        .install_floor(floor.floor(&harness.committee))
        .await
        .unwrap();
    let progress = harness
        .wait_progress(0, |progress| {
            progress.floor_generation == 1 && progress.floor == floor_id
        })
        .await;
    // The floor's tips are at height one on both chains, so its index is two.
    assert_eq!(progress.committed, OutputIndex::new(2));
    assert_eq!(progress.acknowledged, OutputIndex::new(2));
    assert!(harness.reporter(0).delivered().is_empty());

    let mailbox = harness.mailbox(0);
    assert_eq!(empty.index(), floor.index());
    harness.resolve(0, &empty);
    let continuation_id = continuation.lqc_id(&harness.committee);
    continuation.submit(&mailbox).await;
    harness.finalize(0, &continuation);
    let delivered = harness.wait_updates(0, 4).await;
    assert_delivered(&delivered, 3, &continuation.horizontal());
    harness
        .wait_progress(0, |progress| {
            progress.floor_generation == 1
                && progress.floor == continuation_id
                && progress.acknowledged == OutputIndex::new(6)
        })
        .await;
    mailbox.prune(OutputIndex::new(6)).await.unwrap();

    harness.restart(0).await;
    let mailbox = harness.mailbox(0);
    let reopened = harness
        .wait_progress(0, |progress| {
            progress.floor_generation == 1
                && progress.floor == continuation_id
                && progress.acknowledged == OutputIndex::new(6)
        })
        .await;
    assert_eq!(reopened.committed, OutputIndex::new(6));
    // A delayed request below the current floor prunes nothing it still needs.
    mailbox.prune(OutputIndex::new(2)).await.unwrap();
    assert_eq!(
        mailbox.get_certificate(floor_id).await.unwrap().is_some(),
        archive_modes[0] == ArchiveMode::Immutable,
        "LQC retention follows its independently selected backend"
    );
    assert_eq!(
        harness
            .catalog(0)
            .history(floor.commitment())
            .await
            .unwrap()
            .is_some(),
        archive_modes[1] == ArchiveMode::Immutable,
        "history retention follows its independently selected backend"
    );
    assert_eq!(
        mailbox
            .get_block(continuation.blocks[0][0].reference())
            .await
            .unwrap()
            .is_some(),
        archive_modes[2] == ArchiveMode::Immutable,
        "block retention follows its independently selected backend"
    );
    for tip in continuation.tips() {
        assert!(
            mailbox.get_block(*tip).await.unwrap().is_some(),
            "the block each chain builds on next survives pruning"
        );
    }
    assert!(
        mailbox
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
