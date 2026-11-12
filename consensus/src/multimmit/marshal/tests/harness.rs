//! Deterministic harness: marshals over a simulated network, fed by a scripted consensus.

use crate::{
    Epochable as _, Reporter,
    multimmit::{
        algebra::FinalTips,
        config::Parameters,
        marshal::{
            Bridge, Config, Floor, Key, Limits, LqcVerifier, Mailbox, MarshalProgress,
            ServiceHandle, Update, open,
        },
        mocks::{
            Bls, Committee,
            cluster::{BOUNDED_QUOTA, link_all, start_network},
        },
        scheme::Generic,
        testing::TestBody,
        types::{
            Activity, Anchor, Artifact, BlockRef, ChainId, ChainProposal, DigestedLeader,
            Extension, FinalityId, LeaderBlock, Lqc, LqcProof, PathLimits, Position, TipRecord,
            TransactionBlock, TransactionBlockHeader, VoteBody, genesis_history,
        },
    },
    types::{Height, OutputIndex, Participant, Round, View},
};
use bytes::Bytes;
use commonware_actor::Feedback;
use commonware_broadcast::buffered;
use commonware_cryptography::{
    Digestible as _, Hasher as _, Sha256, bls12381::primitives::variant::MinPk, ed25519,
    sha256::Digest as Sha256Digest,
};
use commonware_p2p::simulated;
use commonware_parallel::Sequential;
use commonware_resolver::p2p::{self, Producer};
use commonware_runtime::{
    Clock as _, Handle, Spawner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_utils::{
    Acknowledgement as _, NZDuration, NZU16, NZU64, NZUsize, acknowledgement::Exact,
    channel::oneshot, sync::Mutex, test_rng,
};
use std::{collections::VecDeque, sync::Arc, time::Duration};

pub(super) const CHAINS: usize = 2;
pub(super) const PARTICIPANTS: u32 = 6;
const RESOLVER_CHANNEL: u64 = 0;
const BROADCAST_CHANNEL: u64 = 1;
const WAIT_STEPS: usize = 4_000;
const WAIT_STEP: Duration = Duration::from_millis(5);
const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_MARSHAL_V2_TEST";

pub(super) type D = Sha256Digest;
pub(super) type S = Bls<MinPk>;
pub(super) type TestBlock = TransactionBlock<Sha256, TestBody>;
pub(super) type TestMailbox = Mailbox<Sha256, S, TestBody>;

/// Returns a deterministic runner for `seed`.
pub(super) fn runner(seed: u64) -> deterministic::Runner {
    deterministic::Runner::new(
        deterministic::Config::new()
            .with_seed(seed)
            .with_timeout(Some(Duration::from_secs(120))),
    )
}

/// Verifies L-QCs against the test committee.
#[derive(Clone)]
pub(super) struct Verifier(pub(super) Generic<S>);

#[derive(Debug, thiserror::Error)]
#[error("committee rejected the L-QC")]
pub(super) struct Rejected;

impl LqcVerifier<Sha256, S> for Verifier {
    type Error = Rejected;

    fn verify(
        &mut self,
        proof: &Lqc<S, D>,
    ) -> impl std::future::Future<Output = Result<(), Rejected>> + Send {
        let valid = self
            .0
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), proof, &Sequential)
            .is_some();
        async move { valid.then_some(()).ok_or(Rejected) }
    }
}

/// One delivered update.
#[derive(Clone, Debug)]
pub(super) struct Delivered {
    pub(super) index: OutputIndex,
    pub(super) block: Arc<TestBlock>,
}

struct ApplicationState {
    delivered: Vec<Delivered>,
    pending: VecDeque<(OutputIndex, Exact)>,
    /// Final blocks reported ahead of delivery, with the outputs delivered before each report.
    finals: Vec<(usize, Arc<TestBlock>)>,
}

/// Records every update and acknowledges it at once or when the test says so.
#[derive(Clone)]
pub(super) struct Application {
    state: Arc<Mutex<ApplicationState>>,
    auto: Arc<Mutex<bool>>,
}

impl Application {
    pub(super) fn new(auto: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(ApplicationState {
                delivered: Vec::new(),
                pending: VecDeque::new(),
                finals: Vec::new(),
            })),
            auto: Arc::new(Mutex::new(auto)),
        }
    }

    pub(super) fn delivered(&self) -> Vec<Delivered> {
        self.state.lock().delivered.clone()
    }

    /// Returns the final blocks reported ahead of delivery, each with the number of outputs
    /// delivered before it.
    pub(super) fn finals(&self) -> Vec<(usize, Arc<TestBlock>)> {
        self.state.lock().finals.clone()
    }

    pub(super) fn set_auto(&self, auto: bool) {
        *self.auto.lock() = auto;
        if auto {
            let pending = std::mem::take(&mut self.state.lock().pending);
            for (_, acknowledgement) in pending {
                acknowledgement.acknowledge();
            }
        }
    }

    /// Acknowledges the oldest pending update.
    pub(super) fn acknowledge_next(&self) -> Option<OutputIndex> {
        let (index, acknowledgement) = self.state.lock().pending.pop_front()?;
        acknowledgement.acknowledge();
        Some(index)
    }

    /// Forgets pending acknowledgements without acknowledging them (a crashed application).
    pub(super) fn forget_pending(&self) {
        let pending = std::mem::take(&mut self.state.lock().pending);
        std::mem::forget(pending);
    }

    pub(super) fn clear(&self) {
        let mut state = self.state.lock();
        state.delivered.clear();
        state.finals.clear();
    }
}

impl Reporter for Application {
    type Activity = Update<TestBlock>;

    fn report(&mut self, update: Self::Activity) -> Feedback {
        let (index, block, acknowledgement) = match update {
            Update::Block {
                index,
                block,
                acknowledgement,
            } => (index, block, acknowledgement),
            Update::Final(block) => {
                assert_eq!(
                    block.digest(),
                    block.inner().reference().digest(),
                    "final blocks carry their own digest"
                );
                let mut state = self.state.lock();
                let delivered = state.delivered.len();
                state.finals.push((delivered, block.into()));
                return Feedback::Ok;
            }
        };
        let auto = *self.auto.lock();
        let mut state = self.state.lock();
        assert_eq!(
            block.digest(),
            block.inner().reference().digest(),
            "delivered blocks carry their own digest"
        );
        state.delivered.push(Delivered {
            index,
            block: block.into(),
        });
        if auto {
            drop(state);
            acknowledgement.acknowledge();
        } else {
            state.pending.push_back((index, acknowledgement));
        }
        Feedback::Ok
    }
}

/// Serves a node's responses to peers, corrupting one byte of each when the node is adversarial.
#[derive(Clone)]
struct Serving {
    bridge: Bridge<Sha256, S, TestBody>,
    corrupt: Option<Arc<deterministic::Context>>,
}

impl Producer for Serving {
    type Key = Key<D>;

    fn produce(&mut self, key: Key<D>) -> oneshot::Receiver<Bytes> {
        let honest = self.bridge.produce(key);
        let Some(context) = &self.corrupt else {
            return honest;
        };
        let (sender, receiver) = oneshot::channel();
        context.child("corrupt").spawn(move |_| async move {
            let Ok(bytes) = honest.await else {
                return;
            };
            let mut bytes = bytes.to_vec();
            let middle = bytes.len() / 2;
            if let Some(byte) = bytes.get_mut(middle) {
                *byte ^= 0x5a;
            }
            let _ = sender.send(Bytes::from(bytes));
        });
        receiver
    }
}

/// One node's running marshal and the engines it runs over.
pub(super) struct Node {
    pub(super) mailbox: TestMailbox,
    pub(super) buffer: buffered::Mailbox<ed25519::PublicKey, TestBlock>,
    marshal: ServiceHandle,
    resolver: Handle<()>,
    broadcast: Handle<()>,
}

/// One view's certified proposal: its L-QC, the history record its leader commits to, the
/// blocks it proposes on every chain, and which chains are payment chains.
#[derive(Clone)]
pub(super) struct Certified {
    pub(super) lqc: Arc<Lqc<S, D>>,
    pub(super) history: Arc<TipRecord<D>>,
    pub(super) blocks: Vec<Vec<Arc<TestBlock>>>,
    pub(super) payment: Arc<[bool]>,
}

impl Certified {
    /// Returns the tip of every chain after this view.
    pub(super) fn tips(&self, bases: &[BlockRef<D>]) -> Vec<BlockRef<D>> {
        self.blocks
            .iter()
            .zip(bases)
            .map(|(blocks, base)| blocks.last().map_or(*base, |block| block.reference()))
            .collect()
    }

    /// Returns the blocks in the order they are delivered: offset by offset, chain by chain, the
    /// payment chains' first.
    pub(super) fn ordered(&self) -> Vec<Arc<TestBlock>> {
        let depth = self.blocks.iter().map(Vec::len).max().unwrap_or(0);
        [true, false]
            .into_iter()
            .flat_map(|payment| {
                (0..depth).flat_map(move |offset| {
                    self.blocks
                        .iter()
                        .zip(self.payment.iter())
                        .filter(move |(_, is_payment)| **is_payment == payment)
                        .filter_map(move |(chain, _)| chain.get(offset).cloned())
                })
            })
            .collect()
    }

    /// Returns the activity consensus reports when it verifies this L-QC, with `records`.
    pub(super) fn proven(
        &self,
        codec: crate::multimmit::types::CodecConfig,
        records: Vec<Arc<TipRecord<D>>>,
    ) -> Activity<S, D> {
        let lqc = self.lqc.as_ref().clone();
        let id = lqc.id::<Sha256>();
        let tips = FinalTips::from_lqc::<Sha256, S>(&lqc, codec).unwrap();
        let fact = tips
            .fact(
                FinalityId::Lqc(id),
                DigestedLeader::new::<Sha256>(lqc.leader()),
                codec.view_quorum(),
                codec,
            )
            .unwrap();
        Activity::Proven {
            proof: LqcProof::new(id, Arc::new(Artifact::Lqc(lqc))).unwrap(),
            fact,
            records: records.into(),
        }
    }

    /// Returns the floor this view's L-QC anchors once its blocks are emitted.
    pub(super) fn floor(&self, boundary: Vec<BlockRef<D>>) -> Floor<S, D> {
        Floor::new(Arc::clone(&self.lqc), Arc::clone(&self.history), boundary)
    }
}

/// A scripted consensus: a chain of certified views over the genesis tips.
pub(super) struct Script {
    pub(super) committee: Committee<S>,
    /// The epoch parameters marshal orders with.
    pub(super) parameters: Parameters,
    pub(super) views: Vec<Certified>,
    /// Tips after each view, the genesis tips first.
    pub(super) tips: Vec<Vec<BlockRef<D>>>,
}

impl Script {
    pub(super) fn new(seed: u64) -> Self {
        Self::build(seed, false)
    }

    /// Returns a script whose last chain is a payment chain (`d = 0`, `e = 0`, payments on).
    pub(super) fn with_payments(seed: u64) -> Self {
        Self::build(seed, true)
    }

    fn build(seed: u64, payments: bool) -> Self {
        let mut builder = Committee::builder(seed, PARTICIPANTS)
            .namespace(NAMESPACE)
            .producers((0..CHAINS as u32).map(Participant::new).collect())
            .limits(PathLimits::new(4, 1));
        if payments {
            let mut limits = vec![PathLimits::new(4, 1); CHAINS];
            limits[CHAINS - 1] = PathLimits::new(0, 0);
            builder = builder.chain_limits(limits);
        }
        let committee = builder.build();
        let parameters =
            Arc::unwrap_or_clone(Arc::clone(committee.config.parameters())).with_payments(payments);
        let tips = vec![committee.config.genesis().tips().to_vec()];
        Self {
            committee,
            parameters,
            views: Vec::new(),
            tips,
        }
    }

    /// Returns whether each chain is a payment chain.
    fn payment(&self) -> Arc<[bool]> {
        (0..CHAINS as u32)
            .map(|chain| self.parameters.payment_chain(ChainId::new(chain)))
            .collect()
    }

    pub(super) fn codec(&self) -> crate::multimmit::types::CodecConfig {
        self.committee.codec()
    }

    /// Certifies the next view, proposing `counts` blocks on each chain.
    pub(super) fn certify(&mut self, counts: [usize; CHAINS]) -> &Certified {
        let view = self.views.len() as u64 + 1;
        let bases = self.tips.last().unwrap().clone();
        let parent = match self.views.last() {
            Some(previous) => previous.history.commitment::<Sha256>(),
            None => genesis_history::<Sha256>(self.committee.config.genesis()),
        };
        let history = Arc::new(TipRecord::at_tips(parent, bases.clone()).unwrap());
        let certified = certify(
            &self.committee,
            view,
            history,
            &bases,
            counts,
            self.payment(),
        );
        self.tips.push(certified.tips(&bases));
        self.views.push(certified);
        self.views.last().unwrap()
    }

    /// Returns view `view`'s leader certified again by votes supporting only `positions` of
    /// each chain's proposal: a weaker L-QC for the same leader.
    pub(super) fn weaker(&self, view: usize, positions: [u32; CHAINS]) -> Certified {
        let certified = &self.views[view];
        let leader = certified.lqc.leader().clone();
        let vote = VoteBody::for_leader(
            DigestedLeader::new::<Sha256>(&leader),
            positions
                .iter()
                .map(|position| Position::new(*position))
                .collect(),
            vec![Extension::empty(); CHAINS],
            self.codec(),
        )
        .unwrap();
        let votes = (0..self.codec().view_quorum())
            .map(|signer| {
                self.committee.signers[signer]
                    .sign_vote(vote.clone())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let lqc = self
            .committee
            .verifier
            .assemble_lqc::<_, Sha256, _>(&mut test_rng(), leader, &votes, &Sequential)
            .unwrap();
        Certified {
            lqc: Arc::new(lqc),
            history: Arc::clone(&certified.history),
            blocks: certified.blocks.clone(),
            payment: Arc::clone(&certified.payment),
        }
    }

    /// Returns view `view`'s proof with one byte of its certificate changed so that it still
    /// decodes but its signature no longer verifies.
    pub(super) fn forged(&self, view: usize) -> Certified {
        use commonware_codec::{Decode as _, Encode as _};
        let certified = &self.views[view];
        let encoded = certified.lqc.encode().to_vec();
        let verifier = Verifier(self.committee.verifier.clone());
        for offset in (0..encoded.len()).rev() {
            let mut bytes = encoded.clone();
            bytes[offset] ^= 1;
            let Ok(lqc) = Lqc::<S, D>::decode_cfg(Bytes::from(bytes), &self.codec()) else {
                continue;
            };
            if lqc.leader() != certified.lqc.leader()
                || verifier
                    .0
                    .verify_lqc::<_, Sha256, _>(&mut test_rng(), &lqc, &Sequential)
                    .is_some()
            {
                continue;
            }
            return Certified {
                lqc: Arc::new(lqc),
                history: Arc::clone(&certified.history),
                blocks: certified.blocks.clone(),
                payment: Arc::clone(&certified.payment),
            };
        }
        panic!("no single-byte change keeps the certificate decodable");
    }

    /// Reports `certified`'s proof to `mailbox` with its own history record.
    pub(super) fn prove_certified(&self, mailbox: &TestMailbox, certified: &Certified) {
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(certified.proven(self.codec(), vec![Arc::clone(&certified.history)])),
            Feedback::Ok
        );
    }

    /// Returns every block certified so far, in delivery order.
    pub(super) fn ordered(&self) -> Vec<Arc<TestBlock>> {
        self.views.iter().flat_map(Certified::ordered).collect()
    }

    /// Reports view `view`'s proof (zero-based) to `mailbox` with its own history record.
    pub(super) fn prove(&self, mailbox: &TestMailbox, view: usize) {
        let certified = &self.views[view];
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(certified.proven(self.codec(), vec![Arc::clone(&certified.history)])),
            Feedback::Ok
        );
    }

    /// Reports view `view`'s finality to `mailbox` as direct finality, without a proof.
    pub(super) fn finalize(&self, mailbox: &TestMailbox, view: usize) {
        let Activity::Proven { fact, .. } = self.views[view].proven(self.codec(), Vec::new())
        else {
            unreachable!("a certified view proves its finality");
        };
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(Activity::LeaderFinalized { fact }),
            Feedback::Ok
        );
    }

    /// Reports view `view`'s proof without any record.
    pub(super) fn prove_bare(&self, mailbox: &TestMailbox, view: usize) {
        let certified = &self.views[view];
        let mut reporter = mailbox.clone();
        assert_eq!(
            reporter.report(certified.proven(self.codec(), Vec::new())),
            Feedback::Ok
        );
    }

    /// Stages every block of view `view` on `mailbox`.
    pub(super) async fn stage(&self, mailbox: &TestMailbox, view: usize) {
        for block in self.views[view].blocks.iter().flatten() {
            mailbox.put_block(Arc::clone(block)).await.unwrap();
        }
    }
}

fn body(marker: u64) -> TestBody {
    TestBody::new(
        Sha256::hash(&[b"application", &marker.to_be_bytes()]),
        Height::new(marker + 1),
        marker,
    )
}

/// Certifies view `view`: `counts` new blocks above `bases`, every vote supporting all of them.
///
/// A payment chain (`d = 0`) proposes no blocks: its proposal anchors at a DA certificate of its
/// newest block, so its tip jumps there.
fn certify(
    committee: &Committee<S>,
    view: u64,
    history: Arc<TipRecord<D>>,
    bases: &[BlockRef<D>],
    counts: [usize; CHAINS],
    payment: Arc<[bool]>,
) -> Certified {
    let epoch = committee.config.epoch();
    let mut blocks = Vec::with_capacity(CHAINS);
    let mut proposals = Vec::with_capacity(CHAINS);
    for (chain, (base, count)) in bases.iter().zip(counts).enumerate() {
        let id = ChainId::new(chain as u32);
        let mut parent = base.digest();
        let mut chain_blocks = Vec::with_capacity(count);
        let mut payloads = Vec::with_capacity(count);
        for offset in 0..count {
            let height = base.height().get() + offset as u64 + 1;
            let body = body(view * 1_000 + chain as u64 * 100 + height);
            payloads.push(body.digest());
            let header =
                TransactionBlockHeader::new(epoch, id, Height::new(height), parent, body.digest())
                    .unwrap();
            let block = Arc::new(TransactionBlock::new(header, body).unwrap());
            parent = block.reference().digest();
            chain_blocks.push(block);
        }
        let anchor = match chain_blocks.last() {
            Some(tip) if payment[chain] => {
                payloads.clear();
                Anchor::Certificate(committee.da_certificate(tip.header().clone()))
            }
            _ => Anchor::Tip(*base),
        };
        proposals.push(
            ChainProposal::new(id, anchor, payloads, committee.codec().pipeline_depth()).unwrap(),
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
        .zip(payment.iter())
        .map(|(chain, payment)| Position::new(if *payment { 0 } else { chain.len() as u32 }))
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
    let lqc = committee
        .verifier
        .assemble_lqc::<_, Sha256, _>(&mut test_rng(), leader, &votes, &Sequential)
        .unwrap();
    Certified {
        lqc: Arc::new(lqc),
        history,
        blocks,
        payment,
    }
}

/// Marshals over a simulated network.
pub(super) struct Harness {
    pub(super) context: deterministic::Context,
    oracle: simulated::Oracle<ed25519::PublicKey, deterministic::Context>,
    pub(super) script: Script,
    pub(super) applications: Vec<Application>,
    pub(super) nodes: Vec<Option<Node>>,
    launches: Vec<usize>,
    /// Nodes that corrupt every response they serve.
    corrupt: Vec<bool>,
    /// Nodes that order without the epoch's payment chains.
    ordinary: Vec<bool>,
    pub(super) limits: Limits,
}

impl Harness {
    pub(super) async fn new(context: deterministic::Context, seed: u64, nodes: usize) -> Self {
        Self::with_script(context, Script::new(seed), nodes).await
    }

    /// Returns a harness whose script runs a payment chain (see [`Script::with_payments`]).
    pub(super) async fn with_payments(
        context: deterministic::Context,
        seed: u64,
        nodes: usize,
    ) -> Self {
        Self::with_script(context, Script::with_payments(seed), nodes).await
    }

    async fn with_script(context: deterministic::Context, script: Script, nodes: usize) -> Self {
        let identities = script.committee.identities[..nodes].to_vec();
        let oracle = start_network(&context, identities.clone(), 4 * 1024 * 1024).await;
        link_all(&oracle, &identities).await;
        let mut limits = Limits::for_block_bytes(NZUsize!(64 * 1024));
        limits.blocks_per_segment = NZU64!(8);
        limits.proofs_per_segment = NZU64!(8);
        limits.write_buffer = NZUsize!(4096);
        limits.replay_buffer = NZUsize!(4096);
        Self {
            context,
            oracle,
            script,
            applications: (0..nodes).map(|_| Application::new(true)).collect(),
            nodes: (0..nodes).map(|_| None).collect(),
            launches: vec![0; nodes],
            corrupt: vec![false; nodes],
            ordinary: vec![false; nodes],
            limits,
        }
    }

    /// Starts node `index`.
    pub(super) async fn start(&mut self, index: usize) {
        assert!(self.nodes[index].is_none(), "node is running");
        let launch = self.launches[index];
        self.launches[index] += 1;
        let context = self
            .context
            .child("node")
            .with_attribute("index", index)
            .with_attribute("launch", launch);
        let identity = self.script.committee.identities[index].clone();
        let control = self.oracle.control(identity.clone());
        let resolver_network = control
            .register(RESOLVER_CHANNEL, BOUNDED_QUOTA)
            .await
            .unwrap();
        let broadcast_network = control
            .register(BROADCAST_CHANNEL, BOUNDED_QUOTA)
            .await
            .unwrap();
        let (broadcast_engine, buffer) = buffered::Engine::new(
            context.child("broadcast"),
            buffered::Config {
                public_key: identity.clone(),
                mailbox_size: NZUsize!(64),
                deque_size: 16,
                priority: false,
                codec_config: (),
                peer_provider: self.oracle.manager(),
                blocker: control.clone(),
                strategy: Sequential,
            },
        );
        let broadcast = broadcast_engine.start(broadcast_network);
        let mut config = Config::new(
            self.script.committee.config.genesis().clone(),
            format!("marshal_{index}"),
            CacheRef::new(NZU16!(1024), NZUsize!(8)),
            self.script.codec(),
            (),
        )
        .with_limits(self.limits)
        .with_payments(&self.script.parameters);
        if self.ordinary[index] {
            config.payment_chains = Vec::new();
        }
        let (service, bridge) = open::<_, Sha256, S, TestBody, ed25519::PublicKey>(
            context.child("marshal"),
            config,
            buffer.clone(),
        )
        .await
        .unwrap();
        let (resolver_engine, resolver) = p2p::Engine::new(
            context.child("resolver"),
            p2p::Config {
                peer_provider: self.oracle.manager(),
                blocker: control,
                consumer: bridge.clone(),
                producer: Serving {
                    bridge,
                    corrupt: self.corrupt[index].then(|| Arc::new(context.child("serving"))),
                },
                mailbox_size: NZUsize!(256),
                me: Some(identity),
                fetch_timeout: NZDuration!(Duration::from_millis(100)),
                fetch_retry_delay: Duration::from_millis(20),
                priority_requests: false,
                priority_responses: false,
            },
        );
        let resolver_handle = resolver_engine.start(resolver_network);
        let (mailbox, marshal) = service.start(
            resolver,
            Verifier(self.script.committee.verifier.clone()),
            self.applications[index].clone(),
        );
        self.nodes[index] = Some(Node {
            mailbox,
            buffer,
            marshal,
            resolver: resolver_handle,
            broadcast,
        });
    }

    /// Makes node `index` order without the payment chains from its next start, as a node
    /// configured unlike its peers would.
    pub(super) fn order_without_payments(&mut self, index: usize) {
        self.ordinary[index] = true;
    }

    /// Makes node `index` corrupt every response it serves from its next start.
    pub(super) fn corrupt(&mut self, index: usize) {
        self.corrupt[index] = true;
    }

    /// Returns the (blocker, blocked) pairs of peers blocked so far.
    pub(super) async fn blocked(&self) -> Vec<(ed25519::PublicKey, ed25519::PublicKey)> {
        self.oracle.blocked().await.unwrap()
    }

    /// Returns node `index`'s identity.
    pub(super) fn identity(&self, index: usize) -> ed25519::PublicKey {
        self.script.committee.identities[index].clone()
    }

    pub(super) fn mailbox(&self, index: usize) -> TestMailbox {
        self.nodes[index]
            .as_ref()
            .expect("node is running")
            .mailbox
            .clone()
    }

    /// Stops node `index` abruptly, as a crash would.
    pub(super) async fn crash(&mut self, index: usize) {
        let mut node = self.nodes[index].take().expect("node is running");
        node.marshal.abort();
        let _ = node.marshal.join().await;
        node.resolver.abort();
        node.broadcast.abort();
        let _ = node.resolver.await;
        let _ = node.broadcast.await;
        self.applications[index].forget_pending();
    }

    /// Waits until node `index` delivered at least `count` updates and returns them.
    pub(super) async fn wait_delivered(&self, index: usize, count: usize) -> Vec<Delivered> {
        for _ in 0..WAIT_STEPS {
            let delivered = self.applications[index].delivered();
            if delivered.len() >= count {
                return delivered;
            }
            self.context.sleep(WAIT_STEP).await;
        }
        panic!(
            "node {index} delivered {} of {count} updates",
            self.applications[index].delivered().len()
        );
    }

    /// Waits until node `index`'s progress satisfies `predicate`.
    pub(super) async fn wait_progress(
        &self,
        index: usize,
        predicate: impl Fn(&MarshalProgress<D>) -> bool,
    ) -> MarshalProgress<D> {
        let mut last = None;
        for _ in 0..WAIT_STEPS {
            if let Ok(progress) = self.mailbox(index).progress().await {
                if predicate(&progress) {
                    return progress;
                }
                last = Some(progress);
            }
            self.context.sleep(WAIT_STEP).await;
        }
        panic!("node {index} did not reach the expected progress: {last:?}");
    }

    /// Broadcasts `block` from node `index` to every peer.
    pub(super) fn broadcast(&self, index: usize, block: &Arc<TestBlock>) {
        use commonware_broadcast::Broadcaster as _;
        let buffer = self.nodes[index]
            .as_ref()
            .expect("node is running")
            .buffer
            .clone();
        let _ = buffer.broadcast(
            commonware_p2p::Recipients::All,
            commonware_cryptography::Digested::precomputed(
                Arc::clone(block),
                block.reference().digest(),
            ),
        );
    }

    /// Lets the network and marshals run for `duration`.
    pub(super) async fn settle(&self, duration: Duration) {
        self.context.sleep(duration).await;
    }
}

/// Returns the references of `blocks`.
pub(super) fn references(blocks: &[Arc<TestBlock>]) -> Vec<BlockRef<D>> {
    blocks.iter().map(|block| block.reference()).collect()
}

/// Returns the references and indices of `delivered`.
pub(super) fn stream(delivered: &[Delivered]) -> Vec<(u64, BlockRef<D>)> {
    delivered
        .iter()
        .map(|update| (update.index.get(), update.block.reference()))
        .collect()
}

/// Returns `blocks` numbered from `first`.
pub(super) fn numbered(first: u64, blocks: &[Arc<TestBlock>]) -> Vec<(u64, BlockRef<D>)> {
    (first..).zip(references(blocks)).collect()
}
